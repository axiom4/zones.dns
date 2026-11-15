"""DHCP reservations made in the GUI: API, import/export, and the DHCP server using them at once."""
import ipaddress
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .dhcp.v4 import Config, Server
from .models import DhcpLease, DhcpReservation

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
