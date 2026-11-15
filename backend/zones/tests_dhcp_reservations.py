"""DHCP reservations made in the GUI: API, import/export, and the DHCP server using them at once."""
import ipaddress
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .dhcp.v4 import Config, Server, dhcp_settings
from .models import DataVersion, Dhcp6Lease, DhcpLease, DhcpReservation, MacVendor, Setting

NET = dict(DHCP=True, DHCP_SERVER='192.168.1.2', DHCP_NETMASK='255.255.255.0', DHCP_RANGE='192.168.1.100-192.168.1.110')
A = ipaddress.IPv4Address


class ReservationApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff', password='x', is_staff=True))

    def make(self, mac, ip, **kw):
        return self.api.post('/api/dhcp/reservations/', {'mac': mac, 'ip': ip, **kw}, format='json')

    @override_settings(**NET)
    def test_create_normalises_and_checks(self):
        r = self.make('AA-BB-CC-DD-EE-01', '192.168.1.50', hostname='NAS')
        self.assertEqual((r.status_code, r.json()['mac'], r.json()['hostname']), (201, 'aa:bb:cc:dd:ee:01', 'nas'))
        self.assertEqual(self.make('aabb.ccdd.ee01', '192.168.1.51').status_code, 400)  # same MAC
        self.assertEqual(self.make('aa:bb:cc:dd:ee:02', '192.168.1.50').status_code, 400)  # same address
        self.assertEqual(self.make('aa:bb:cc:dd:ee:02', '10.0.0.5').status_code, 400)  # not in a served network
        self.assertEqual(self.make('aa:bb:cc:dd:ee:02', '192.168.1.2').status_code, 400)  # the server itself
        self.assertEqual(self.make('01:bb:cc:dd:ee:02', '192.168.1.60').status_code, 400)  # multicast MAC
        self.assertEqual(self.make('zz', '192.168.1.60').status_code, 400)
        self.assertEqual(self.make('aa:bb:cc:dd:ee:02', '192.168.1.60', hostname='wpad').status_code, 400)
        pk = r.json()['id']
        self.assertEqual(self.api.patch(f'/api/dhcp/reservations/{pk}/', {'ip': '192.168.1.55'}, format='json').json()['ip'], '192.168.1.55')

    def test_export_import_roundtrip_and_all_or_nothing(self):
        self.make('aa:bb:cc:dd:ee:01', '192.168.1.50', hostname='nas', note='a, b')
        self.make('aa:bb:cc:dd:ee:02', '192.168.1.51', enabled=False)
        csv_text = self.api.get('/api/dhcp/reservations/export/').content.decode()
        self.assertTrue(csv_text.startswith('mac,ip,hostname,note,enabled\n'))
        DhcpReservation.objects.all().delete()
        r = self.api.post('/api/dhcp/reservations/import/', {'text': csv_text}, format='json').json()
        self.assertEqual((r['created'], r['errors']), (2, []))
        self.assertEqual(DhcpReservation.objects.get(mac='aa:bb:cc:dd:ee:01').note, 'a, b')
        self.assertFalse(DhcpReservation.objects.get(mac='aa:bb:cc:dd:ee:02').enabled)
        r = self.api.post('/api/dhcp/reservations/import/', {'text': csv_text}, format='json').json()
        self.assertEqual((r['created'], r['updated'], r['skipped']), (0, 0, 2))
        swap = 'aa:bb:cc:dd:ee:01,192.168.1.51\naa:bb:cc:dd:ee:02,192.168.1.50\n'  # two MACs swap addresses
        r = self.api.post('/api/dhcp/reservations/import/', {'text': swap}, format='json').json()
        self.assertEqual((r['updated'], r['errors']), (2, []))
        self.assertEqual(DhcpReservation.objects.get(mac='aa:bb:cc:dd:ee:01').ip, '192.168.1.51')
        bad = 'aa:bb:cc:dd:ee:09,192.168.1.90\nnope,1.2.3.4\naa:bb:cc:dd:ee:08,192.168.1.51\n'
        r = self.api.post('/api/dhcp/reservations/import/', {'text': bad}, format='json').json()
        self.assertEqual(len(r['errors']), 2)
        self.assertFalse(DhcpReservation.objects.filter(mac='aa:bb:cc:dd:ee:09').exists())  # one bad line: nothing changed

    def test_any_column_order_and_delimiter(self):
        post = lambda t: self.api.post('/api/dhcp/reservations/import/', {'text': t}, format='json').json()
        r = post('nas.lan,AA-BB-CC-DD-EE-01,192.168.1.50\ntv,aa:bb:cc:dd:ee:02,192.168.1.51\n')  # hostname, mac, ip, no header
        self.assertEqual((r['created'], r['errors']), (2, []))
        self.assertEqual(DhcpReservation.objects.get(mac='aa:bb:cc:dd:ee:01').hostname, 'nas')
        r = post('IP Address;Host;MAC Address\n192.168.1.60;pc;aa:bb:cc:dd:ee:03\n')  # header, ';'
        self.assertEqual((r['created'], r['errors']), (1, []))
        self.assertEqual(DhcpReservation.objects.get(mac='aa:bb:cc:dd:ee:03').ip, '192.168.1.60')

    def test_replace_needs_the_second_factor(self):
        self.make('aa:bb:cc:dd:ee:01', '192.168.1.50')
        body = {'text': 'aa:bb:cc:dd:ee:07,192.168.1.70', 'replace': True}
        with mock.patch('zones.views.zone.mfa.methods', return_value=['totp']):
            self.assertEqual(self.api.post('/api/dhcp/reservations/import/', body, format='json').status_code, 403)
            self.assertEqual(self.api.post('/api/dhcp/reservations/import/', {**body, 'dry_run': True}, format='json').status_code, 200)
        self.assertEqual(DhcpReservation.objects.count(), 1)
        self.assertEqual(self.api.post('/api/dhcp/reservations/import/', body, format='json').status_code, 200)  # no second factor set up
        self.assertEqual(list(DhcpReservation.objects.values_list('mac', flat=True)), ['aa:bb:cc:dd:ee:07'])


class ReservationServerTests(TestCase):
    def packet(self, mac, kind):
        import struct
        head = struct.pack('!BBBBIHH4s4s4s4s', 1, 1, 6, 0, 7, 0, 0, b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4)
        return head + bytes.fromhex(mac.replace(':', '')).ljust(16, b'\0') + b'\0' * 192 + b'\x63\x82\x53\x63' + bytes([53, 1, kind]) + b'\xff'

    def test_server_uses_gui_reservations_at_once(self):
        cfg = Config(A('192.168.1.2'), ipaddress.IPv4Network('192.168.1.0/24'), A('192.168.1.100'), A('192.168.1.102'), None, [A('192.168.1.2')], 'lan', 3600, {}, b'')
        server = Server(cfg)

        def offer(mac):
            out = server.handle(self.packet(mac, 1))
            return str(A(out.data[16:20]))
        self.assertEqual(offer('aa:aa:aa:aa:aa:01'), '192.168.1.100')
        DhcpReservation.objects.create(mac='aa:aa:aa:aa:aa:01', ip='192.168.1.50', hostname='nas')  # no restart
        self.assertEqual(offer('aa:aa:aa:aa:aa:01'), '192.168.1.50')
        self.assertEqual(DhcpLease.objects.get(client='aa:aa:aa:aa:aa:01').hostname, 'nas')
        self.assertEqual(offer('aa:aa:aa:aa:aa:02'), '192.168.1.100')
        DhcpReservation.objects.filter(mac='aa:aa:aa:aa:aa:01').update(enabled=False)
        DhcpReservation.objects.get().save()  # a save bumps the data counter
        self.assertNotEqual(offer('aa:aa:aa:aa:aa:03'), '192.168.1.50')
        DhcpReservation.objects.all().delete()
        self.assertEqual(server.cfg.reservations, {})


class EnvImportTests(TestCase):
    def test_migration_imports_env_once(self):
        import importlib
        from django.apps import apps
        mig = importlib.import_module('zones.migrations.0034_dhcp_settings_from_env')
        Setting.objects.create(key='dhcp:DHCP_ROUTER', value='10.0.0.1')  # saved in the GUI: stays
        env = {'DHCP': 'True', 'DHCP_ROUTER': '10.9.9.9', 'DHCP6_POOL': 'fd00::100-fd00::1ff', 'DHCP_LEASE': '600'}
        with mock.patch.dict('os.environ', env):
            mig.from_env(apps, None)
        self.assertEqual(Setting.objects.get(key='dhcp:DHCP').value, 'true')
        self.assertEqual(Setting.objects.get(key='dhcp:DHCP_ROUTER').value, '10.0.0.1')
        self.assertEqual(dhcp_settings().DHCP6_POOL, 'fd00::100-fd00::1ff')
        self.assertEqual(dhcp_settings().DHCP_LEASE, 600)


class DnsListTests(TestCase):
    def test_several_dns_servers(self):
        from .dhcp.v4 import scopes
        for text in ('192.168.1.23,192.168.1.254', '192.168.1.23 192.168.1.254', '192.168.1.23, 192.168.1.254;'):
            s = dhcp_settings(overrides={'DHCP': True, 'DHCP_SERVER': '192.168.1.23', 'DHCP_RANGE': '192.168.1.100-192.168.1.200', 'DHCP_DNS': text})
            self.assertEqual([str(x) for x in scopes(s)[0].dns], ['192.168.1.23', '192.168.1.254'])


class Reservation6Tests(TestCase):
    def setUp(self):
        from .dhcp.v6 import Config6, Server6
        cfg = Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                      ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::101'), None, 56, name='t')
        self.s = Server6(cfg)
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff6', password='x', is_staff=True))

    def take(self, duid, iaid=1, only_existing=False):
        from django.utils import timezone
        return self.s._take('na', duid, iaid, [], timezone.now(), 3600, only_existing)

    def test_reserved_address_goes_to_its_client_and_to_nobody_else(self):
        from .models import Dhcp6Reservation
        Dhcp6Reservation.objects.create(duid='aa' * 8, ip='2001:db8:1::100')
        self.assertEqual(self.take('bb' * 8), '2001:db8:1::101')  # ::100 is not free for the others
        self.assertIsNone(self.take('cc' * 8))  # pool exhausted
        self.assertEqual(self.take('aa' * 8), '2001:db8:1::100')  # it takes its own, though the other holds ::101
        Dhcp6Reservation.objects.create(duid='dd' * 8, ip='2001:db8:1::50')  # outside the pool, inside the prefix
        self.assertEqual(self.take('dd' * 8), '2001:db8:1::50')
        Dhcp6Reservation.objects.filter(duid='dd' * 8).update(ip='2001:db8:1::51')
        self.assertIsNone(self.take('dd' * 8, only_existing=True))  # a renewal of the old address: NoBinding, the client asks again
        self.assertEqual(self.take('dd' * 8), '2001:db8:1::51')

    @override_settings(DHCP6_PREFIX='2001:db8:1::/64')
    def test_api(self):
        r = self.api.post('/api/dhcp/reservations6/', {'duid': '00:03:00:01:D8:3A:DD:BE:4E:69', 'ip': '2001:db8:1::77', 'note': 'cam'}, format='json')
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual((r.json()['duid'], r.json()['mac']), ('00030001d83addbe4e69', 'd8:3a:dd:be:4e:69'))
        self.assertEqual(self.api.post('/api/dhcp/reservations6/', {'duid': '00030001d83addbe4e69', 'ip': '2001:db8:1::78'}, format='json').status_code, 400)  # DUID twice
        self.assertEqual(self.api.post('/api/dhcp/reservations6/', {'duid': 'ab' * 8, 'ip': '2001:db8:1::77'}, format='json').status_code, 400)  # address twice
        self.assertEqual(self.api.post('/api/dhcp/reservations6/', {'duid': 'ab' * 8, 'ip': '2001:db9::1'}, format='json').status_code, 400)  # outside the prefix
        self.assertEqual(self.api.post('/api/dhcp/reservations6/', {'duid': 'xyz', 'ip': '2001:db8:1::79'}, format='json').status_code, 400)


class Reservation6CsvTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff6c', password='x', is_staff=True))

    @override_settings(DHCP6_PREFIX='2001:db8:1::/64')
    def test_import_and_export(self):
        from .models import Dhcp6Reservation
        csv = 'duid,ip,note,enabled\n00:03:00:01:d8:3a:dd:be:4e:69,2001:db8:1::10,cam,true\n' + 'ab' * 8 + ',2001:db8:1::11,,false\n'
        r = self.api.post('/api/dhcp/reservations6/import/', {'text': csv, 'dry_run': True}, format='json').json()
        self.assertEqual((r['created'], r['errors']), (2, []))
        self.assertEqual(Dhcp6Reservation.objects.count(), 0)  # a preview changes nothing
        r = self.api.post('/api/dhcp/reservations6/import/', {'text': csv}, format='json').json()
        self.assertEqual(r['created'], 2)
        self.assertFalse(Dhcp6Reservation.objects.get(duid='ab' * 8).enabled)
        again = self.api.post('/api/dhcp/reservations6/import/', {'text': csv}, format='json').json()
        self.assertEqual((again['created'], again['skipped']), (0, 2))
        # no header, columns in any order; one bad line: nothing changes
        bad = self.api.post('/api/dhcp/reservations6/import/', {'text': 'cd' * 8 + ',2001:db8:1::12\n2001:db9::1,' + 'ef' * 8}, format='json').json()
        self.assertEqual(len(bad['errors']), 1)
        self.assertEqual(Dhcp6Reservation.objects.count(), 2)
        out = self.api.get('/api/dhcp/reservations6/export/').content.decode().splitlines()
        self.assertEqual(out[0], 'duid,ip,note,enabled')
        self.assertIn('00030001d83addbe4e69,2001:db8:1::10,cam,true', out)


class Lease6IdentityTests(TestCase):
    def test_mac_and_host_name_kept_with_the_lease(self):
        from django.utils import timezone
        from .dhcp.v6 import Config6, Server6, fqdn_host, peer_mac
        from .models import Dhcp6Lease
        self.assertEqual(peer_mac('fe80::7a6c:84ff:fea9:e428%eth0', 'eth0'), '78:6c:84:a9:e4:28')  # EUI-64: the MAC is in the address
        self.assertEqual(peer_mac('2001:db8::1', 'eth0'), '')  # not link-local (a relay, or a global address)
        self.assertEqual(fqdn_host(b'\x00' + bytes([14]) + b'Home-Assistant' + b'\x00'), 'home-assistant')
        self.assertEqual(fqdn_host(b'\x00'), '')
        cfg = Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                      ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::101'), None, 56, name='t')
        s = Server6(cfg)
        s._peer, s._host = 'fe80::7a6c:84ff:fea9:e428%eth0', 'ha'
        # a DUID-UUID (type 4) holds no MAC: the one of the link-local address is kept
        s._take('na', '0004' + '6a4e9ff7c05012e80bc66101c269be65', 1, [], timezone.now(), 3600, False)
        row = Dhcp6Lease.objects.get()
        self.assertEqual((row.mac, row.hostname), ('78:6c:84:a9:e4:28', 'ha'))


class Dns6NamesTests(TestCase):
    @override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True, DHCP_SERVER='192.168.1.2', DHCP_RANGE='192.168.1.100-192.168.1.200')
    def test_dhcp6_leases_are_answered_by_name_and_by_address(self):
        from django.utils import timezone
        from .dhcp.names import lease_hosts, lease_ptr
        from .models import Dhcp6Lease
        later = timezone.now() + timezone.timedelta(hours=1)
        DhcpLease.objects.create(client='k', ip='192.168.1.101', mac='78:6c:84:a9:e4:28', hostname='ha', expires=later)
        Dhcp6Lease.objects.create(duid='0004aa', iaid=1, kind='na', value='fd00::100', mac='78:6c:84:a9:e4:28', expires=later)  # same MAC: it is "ha"
        Dhcp6Lease.objects.create(duid='0004bb', iaid=1, kind='na', value='fd00::200', hostname='cam', expires=later)  # named itself
        Dhcp6Lease.objects.create(duid='0004cc', iaid=1, kind='pd', value='fd00:1::/56', hostname='ha', expires=later)  # a prefix is not a host
        self.assertEqual(lease_hosts('ha.lan'), [('192.168.1.101', 60), ('fd00::100', 60)])
        self.assertEqual(lease_hosts('cam.lan'), [('fd00::200', 60)])
        ptr = lambda a: __import__('ipaddress').IPv6Address(a).reverse_pointer
        self.assertEqual(lease_ptr(ptr('fd00::100')), 'ha.lan')
        self.assertEqual(lease_ptr(ptr('fd00::200')), 'cam.lan')
        self.assertIsNone(lease_ptr(ptr('fd00::300')))


class Dns6OnlyLeaseTests(TestCase):
    def ask(self, name, qtype):
        from types import SimpleNamespace

        from dnslib import DNSRecord

        from .dnsd.resolver import Resolver
        return Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question(name, qtype), SimpleNamespace(client_address=('127.0.0.1', 0)))

    @override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True, DNS_AUTHORITATIVE=False)
    def test_name_with_only_v6_leases_is_not_answered_empty_for_a(self):
        from django.utils import timezone

        from .dnsd import resolver
        from .models import Dhcp6Lease
        resolver._data = None
        resolver._dhcp_names = (True, 'lan')
        Dhcp6Lease.objects.create(duid='0004aa', iaid=1, kind='na', value='fd00::100', hostname='ha', expires=timezone.now() + timezone.timedelta(hours=1))
        aaaa = self.ask('ha.lan', 'AAAA')
        self.assertEqual((aaaa.header.aa, [str(r.rdata) for r in aaaa.rr]), (1, ['fd00::100']))
        a = self.ask('ha.lan', 'A')  # no IPv4 among its leases: the name goes on to the upstream, which may know it
        self.assertEqual(a.header.rcode, 2)  # SERVFAIL: it was forwarded to the (unreachable) upstream, not answered empty


class Duid6Tests(TestCase):
    def test_mac_from_duid_and_names_from_dhcp4(self):
        from django.utils import timezone
        from .dhcp.v6 import duid_mac
        llt, ll = '00010001' + '2b3c4d5e' + 'd83addbe4e69', '00030001' + 'd83addbe4e69'
        self.assertEqual(duid_mac(llt), 'd8:3a:dd:be:4e:69')
        self.assertEqual(duid_mac(ll), 'd8:3a:dd:be:4e:69')
        self.assertEqual(duid_mac('0002' + '00000000' + 'aabb'), '')  # DUID-EN: no MAC
        self.assertEqual(duid_mac('zz'), '')
        later = timezone.now() + timezone.timedelta(hours=1)
        DhcpLease.objects.create(client='x', ip='192.168.1.101', mac='d8:3a:dd:be:4e:69', hostname='pi', expires=later)
        Dhcp6Lease.objects.create(duid=llt, iaid=1, kind='na', value='fd00::101', expires=later)
        c = APIClient()
        c.force_authenticate(get_user_model().objects.create_user('u6', password='x', is_staff=True))
        row = next(r for r in c.get('/api/dhcp/leases/').json() if r['family'] == 6)
        self.assertEqual((row['mac'], row['hostname']), ('d8:3a:dd:be:4e:69', 'pi'))


class SettingsReloadTests(TestCase):
    def cmd(self):
        from .management.commands.rundhcp import Command
        c = Command()
        c.stdout, c.stderr = mock.Mock(), mock.Mock()
        c.snap, c.seen = c.snapshot(dhcp_settings()), DataVersion.version()
        return c

    @override_settings(**NET)
    def test_saved_settings_restart_the_server_once(self):
        c = self.cmd()
        with mock.patch('zones.management.commands.rundhcp.os.execv') as ex:
            c.reload_if_changed()  # nothing changed
            DataVersion.bump()
            c.reload_if_changed()  # counter moved, settings did not
            self.assertFalse(ex.called)
            Setting.objects.create(key='dhcp:DHCP_DNS', value='192.168.1.2 1.1.1.1')
            DataVersion.bump()
            c.reload_if_changed()
            self.assertEqual(ex.call_count, 1)

    @override_settings(**NET)
    def test_invalid_or_off_settings(self):
        c = self.cmd()
        with mock.patch('zones.management.commands.rundhcp.os.execv') as ex:
            Setting.objects.create(key='dhcp:DHCP_RANGE', value='10.9.9.1-10.9.9.9')  # outside the network
            DataVersion.bump()
            c.reload_if_changed()
            self.assertFalse(ex.called)
            self.assertIn('not applied', c.stderr.write.call_args.args[0])
            Setting.objects.create(key='dhcp:DHCP', value='false')
            DataVersion.bump()
            with self.assertRaises(SystemExit):
                c.reload_if_changed()


class VendorAndPingTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff', password='x', is_staff=True))

    def test_vendor_lookup(self):
        from . import oui
        oui.replace_table([('F4F5D8', 'Google, Inc.'), ('F4F5D8000', 'Google Lab (36-bit)')])
        self.assertEqual(oui.vendor('F4:F5:D8:00:00:01'), 'Google Lab (36-bit)')  # the longest block wins
        self.assertEqual(oui.vendor('f4-f5-d8-aa-bb-cc'), 'Google, Inc.')
        self.assertEqual(oui.vendor('02:00:00:00:00:01'), 'Private (random address)')
        self.assertEqual(oui.vendor('nonsense'), '')
        r = self.api.get('/api/dhcp/vendor/', {'mac': 'F4F5D8000001'}).json()
        self.assertEqual((r['private'], 'Google' in r['vendor']), (False, True))
        DhcpReservation.objects.create(mac='f4:f5:d8:00:00:01', ip='192.168.1.5')
        self.assertIn('Google', self.api.get('/api/dhcp/reservations/').json()[0]['vendor'])

    def test_ping_only_local_addresses(self):
        with mock.patch('zones.netcheck.ping_one', side_effect=lambda ip: (str(ip) == '192.168.1.1', 1.5, 64, 64)) as p:
            r = self.api.post('/api/dhcp/ping/', {'addresses': ['192.168.1.1', '192.168.1.2', '8.8.8.8', 'nas.lan', '-c5', 'fd00::1']}, format='json').json()
        self.assertEqual([(x['address'], x['up'], bool(x['error'])) for x in r],
                         [('192.168.1.1', True, False), ('192.168.1.2', False, False), ('8.8.8.8', False, True), ('nas.lan', False, True), ('-c5', False, True), ('fd00::1', False, False)])
        self.assertEqual(p.call_count, 3)  # the refused ones never reach the ping program
        self.assertEqual(self.api.post('/api/dhcp/ping/', {'addresses': ['10.0.0.1'] * 65}, format='json').status_code, 400)

    def test_update_downloads_and_replaces_the_table_or_keeps_it(self):
        import gzip
        import io

        from django.core.management import call_command
        from django.core.management.base import CommandError
        from . import oui
        oui.replace_table([('AAAAAA', 'Old Vendor')])
        manuf = '# comment\n00:1B:C5:00:10/36\tShort\tOpenRB.com, Direct SIA\nF4:F5:D8\tGoogle\tGoogle, Inc.\nbad line\n'
        reply = lambda data: mock.MagicMock(__enter__=lambda s: io.BytesIO(data), __exit__=lambda *a: False)
        with mock.patch('zones.management.commands.update_oui.urllib.request.urlopen', side_effect=OSError('offline')):
            with self.assertRaises(CommandError):
                call_command('update_oui')
        self.assertEqual(MacVendor.objects.get().name, 'Old Vendor')  # the old table stays
        with mock.patch('zones.management.commands.update_oui.urllib.request.urlopen', return_value=reply(gzip.compress(manuf.encode()))):
            with self.assertRaises(CommandError):  # far too few lines: a broken file
                call_command('update_oui')
            self.assertEqual(MacVendor.objects.get().name, 'Old Vendor')
            with mock.patch('zones.management.commands.update_oui.MIN_ROWS', 2):
                call_command('update_oui', stdout=mock.Mock())
        self.assertEqual(dict(MacVendor.objects.values_list('prefix', 'name')), {'001BC5001': 'OpenRB.com, Direct SIA', 'F4F5D8': 'Google, Inc.'})


class IcmpTests(TestCase):
    def test_packets(self):
        from . import netcheck
        pkt = netcheck.echo_request(4, 0x1234, 7)
        self.assertEqual((pkt[0], pkt[1]), (8, 0))
        self.assertEqual(netcheck.checksum(pkt), 0)  # a packet with a right checksum sums to zero
        self.assertEqual(netcheck.echo_request(6, 1, 1)[0], 128)
        reply = bytes([0, 0, 0, 0]) + pkt[4:]
        self.assertTrue(netcheck.is_reply(4, reply, 7, 0x1234))
        self.assertTrue(netcheck.is_reply(4, bytes([0x45]) + b'\0' * 19 + reply, 7))  # with the IP header of a raw socket
        self.assertFalse(netcheck.is_reply(4, reply, 8))  # another sequence number
        self.assertFalse(netcheck.is_reply(4, pkt, 7))  # a request, not a reply
        self.assertTrue(netcheck.is_reply(6, bytes([129, 0, 0, 0]) + pkt[4:], 7))

    def test_loopback_answers_and_a_closed_door_does_not(self):
        import ipaddress

        from . import netcheck
        up, ms, ttl, size = netcheck.ping_one(ipaddress.ip_address('127.0.0.1'))
        self.assertTrue(up)
        self.assertEqual((ms is not None, size), (True, 64))  # 56 bytes of data + 8 of header, like ping
        self.assertIn(ttl, (None, *range(1, 256)))
        with mock.patch('zones.netcheck._socket', side_effect=netcheck.Unavailable), mock.patch('zones.netcheck.ping_command', return_value=(True, 0.5, 64, 64)) as cmd:
            self.assertEqual(netcheck.ping_one(ipaddress.ip_address('127.0.0.1')), (True, 0.5, 64, 64))  # no socket allowed: the ping program
        self.assertTrue(cmd.called)
