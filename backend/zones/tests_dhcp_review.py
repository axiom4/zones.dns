"""Regression tests of the DHCP review: host names over DHCPv6, reserved addresses and IA_TA, CSV formula cells, network/broadcast reservations."""
import ipaddress
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from .dhcp import v4, v6
from .models import Dhcp6Lease, Dhcp6Reservation, DhcpLease, DhcpReservation

NET = dict(DHCP=True, DHCP_SERVER='192.168.1.2', DHCP_NETMASK='255.255.255.0', DHCP_RANGE='192.168.1.100-192.168.1.110')


def server6():
    cfg = v6.Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                     ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::101'), None, 56, name='t')
    return v6.Server6(cfg)


class HostNameTests(TestCase):
    def test_dhcp6_client_cannot_take_a_name_of_another_client(self):
        later = timezone.now() + timezone.timedelta(hours=1)
        DhcpLease.objects.create(client='k', ip='192.168.1.101', mac='aa:aa:aa:aa:aa:01', hostname='nas', expires=later)
        s = server6()
        for i, host in enumerate(('nas', 'cam')):  # the pool has two addresses
            s._peer, s._host = None, host
            s._take('na', f'0004{i:02x}', 1, [], timezone.now(), 3600, False)
        self.assertEqual(sorted(Dhcp6Lease.objects.values_list('hostname', flat=True)), ['', 'cam'])
        self.assertTrue(v4.name_taken('wpad', timezone.now(), duid='0004ff'))

    def test_dhcp6_same_card_keeps_the_dhcpv4_name(self):
        later = timezone.now() + timezone.timedelta(hours=1)
        DhcpLease.objects.create(client='k', ip='192.168.1.101', mac='aa:aa:aa:aa:aa:01', hostname='nas', expires=later)
        s = server6()
        s._peer, s._host = None, 'nas'
        s._take('na', '00030001aaaaaaaaaa01', 1, [], timezone.now(), 3600, False)  # DUID-LL with the same MAC
        self.assertEqual(Dhcp6Lease.objects.get().hostname, 'nas')

    def test_dhcpv4_client_cannot_take_a_reserved_or_dhcp6_name(self):
        DhcpReservation.objects.create(mac='aa:aa:aa:aa:aa:01', ip='192.168.1.50', hostname='nas')
        Dhcp6Lease.objects.create(duid='0004aa', iaid=1, kind='na', value='2001:db8:1::5', hostname='cam', expires=timezone.now() + timezone.timedelta(hours=1))
        now = timezone.now()
        self.assertTrue(v4.name_taken('nas', now, mac='aa:aa:aa:aa:aa:02', client='x'))
        self.assertFalse(v4.name_taken('nas', now, mac='aa:aa:aa:aa:aa:01', client='y'))  # the reserved card itself
        self.assertTrue(v4.name_taken('cam', now, mac='aa:aa:aa:aa:aa:02', client='x'))

    def test_peer_mac_asked_once_per_message(self):
        s = server6()
        s._peer, s._host, s._pmac = 'fe80::1%eth0', '', None
        with mock.patch.object(v6, 'peer_mac', return_value='') as pm:
            for iaid in range(2):  # two IAs of one message
                s._take('na', '0004ff', iaid, [], timezone.now(), 60, False)
        self.assertEqual(pm.call_count, 1)


class TemporaryAddressReservationTests(TestCase):
    def test_ia_ta_never_gets_an_address_reserved_for_another(self):
        Dhcp6Reservation.objects.create(duid='0004aa', ip='2001:db8:1::100')
        s = server6()
        s._peer, s._host = None, ''
        self.assertEqual(s._take('ta', '0004bb', 1, [], timezone.now(), 3600, False), '2001:db8:1::101')


class CsvTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff', password='x', is_staff=True))

    def test_formula_note_is_quoted_in_export_and_round_trips(self):
        DhcpReservation.objects.create(mac='aa:aa:aa:aa:aa:01', ip='192.168.1.50', note='=HYPERLINK("http://x")')
        out = self.api.get('/api/dhcp/reservations/export/').content.decode()
        self.assertIn(',"\'=HYPERLINK(""http://x"")",', out)
        DhcpReservation.objects.all().delete()
        r = self.api.post('/api/dhcp/reservations/import/', {'text': out}, format='json').json()
        self.assertEqual(r['errors'], [])
        self.assertEqual(DhcpReservation.objects.get().note, '=HYPERLINK("http://x")')
        Dhcp6Reservation.objects.create(duid='0004aa', ip='2001:db8:1::5', note='@SUM(1)')
        self.assertIn("'@SUM(1)", self.api.get('/api/dhcp/reservations6/export/').content.decode())

    @override_settings(**NET)
    def test_network_and_broadcast_address_cannot_be_reserved(self):
        for ip in ('192.168.1.0', '192.168.1.255'):
            r = self.api.post('/api/dhcp/reservations/', {'mac': 'aa:aa:aa:aa:aa:01', 'ip': ip}, format='json')
            self.assertEqual(r.status_code, 400, ip)
        self.assertEqual(self.api.post('/api/dhcp/reservations/', {'mac': 'aa:aa:aa:aa:aa:01', 'ip': '192.168.1.50'}, format='json').status_code, 201)
