"""DHCP reservations made in the GUI: API, import/export, and the DHCP server using them at once."""
import ipaddress
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .dhcp.v4 import Config, Server, dhcp_settings
from .models import DataVersion, DhcpLease, DhcpReservation, MacVendor, Setting

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
