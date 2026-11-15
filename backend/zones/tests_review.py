"""Regression tests for the fixes of the code review (DoH negotiation, daemon housekeeping, TCP connections, step-up gaps, input checks)."""
import base64
import socket
import struct
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client, SimpleTestCase, TestCase, override_settings
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import DNSServer
from rest_framework.test import APIClient

from .dnsd import ddns, resolver, suspicious
from .dnsd.dnsserver import Handler, PooledTCPServer, logger
from .management.commands.rundns import Command as RunDns
from .models import Record, TotpDevice, Zone


class DohAcceptTests(TestCase):
    def test_browsers_accept_header_is_answered(self):
        wire = bytes(DNSRecord.question('example.com', 'A').pack())
        q = base64.urlsafe_b64encode(wire).rstrip(b'=').decode()
        c = Client()
        with override_settings(DNS_DOH=True), mock.patch('zones.views.doh._exchange', return_value=wire):
            self.assertEqual(c.get('/dns-query', {'dns': q}, HTTP_ACCEPT='application/dns-message').status_code, 200)
            self.assertEqual(c.post('/dns-query', wire, content_type='application/dns-message', HTTP_ACCEPT='application/dns-message').status_code, 200)
            self.assertEqual(c.put('/dns-query', wire, content_type='application/dns-message').status_code, 405)

    def test_client_address_is_passed_to_the_daemon(self):
        wire = bytes(DNSRecord.question('example.com', 'A').pack())
        c = Client(REMOTE_ADDR='192.168.1.7')
        with override_settings(DNS_DOH=True), mock.patch('zones.views.doh._exchange', return_value=wire) as ex:
            c.post('/dns-query', wire, content_type='application/dns-message')
        self.assertEqual(ex.call_args.args[1], '192.168.1.7')
        from .views.doh import _proxy_line
        with override_settings(DNS_PROXY_PROTOCOL=True):
            self.assertEqual(_proxy_line('192.168.1.7'), b'PROXY TCP4 192.168.1.7 127.0.0.1 0 53\r\n')
            self.assertEqual(_proxy_line('not an address'), b'')
        self.assertEqual(_proxy_line('192.168.1.7'), b'')  # off by default


class HousekeepingTests(TestCase):
    def test_a_database_error_does_not_end_the_daemon(self):
        cmd = RunDns()
        with mock.patch('zones.management.commands.rundns.QueryLog.objects') as objects, mock.patch.object(cmd.stderr, 'write') as err:
            objects.filter.side_effect = DatabaseError('gone away')
            cmd.housekeeping()  # must not raise
        self.assertIn('Log purge', err.call_args.args[0])


class SuspiciousBoundTests(SimpleTestCase):
    def test_a_flood_of_subdomains_does_not_grow_the_table(self):
        suspicious._seen.clear()
        with override_settings(SUSPICIOUS_MODE='block', SUSPICIOUS_MAX_UNIQUE=40, SUSPICIOUS_ALLOW=set()):
            why = [suspicious.check(f'x{i}.flood.example', 'A', '10.0.0.9') for i in range(500)]
        self.assertIsNone(why[39])
        self.assertIn('distinct subdomains', why[-1])
        self.assertLessEqual(len(suspicious._seen[('10.0.0.9', 'flood.example')]), 41)
        suspicious._seen.clear()


class ResolverFailOpenTests(TestCase):
    def test_blacklist_lookup_without_database_does_not_block_or_fail(self):
        broken = mock.MagicMock()
        broken.exclude.return_value = broken
        broken.__iter__.side_effect = DatabaseError('gone away')
        with mock.patch.object(resolver, '_live', return_value=broken):
            self.assertIsNone(resolver.blocked_entry('never-asked.example'))
        self.assertNotIn('never-asked.example', resolver._blocked)  # asked again when the database is back

    def test_an_answer_from_replaced_data_is_not_remembered(self):
        resolver._snapshot()
        resolver._remember_blocked('stale.example', ('stale.example', 'personal'), gen=resolver._data_at - 1)
        self.assertNotIn('stale.example', resolver._blocked)


class _Echo:
    def __init__(self):
        self.clients = []

    def resolve(self, request, handler):
        self.clients.append(handler.client_address[0])
        return request.reply()


def _framed(name):
    wire = bytes(DNSRecord.question(name).pack())
    return struct.pack('!H', len(wire)) + wire


def _read_answer(s):
    head = s.recv(2, socket.MSG_WAITALL)
    return DNSRecord.parse(s.recv(struct.unpack('!H', head)[0], socket.MSG_WAITALL)) if len(head) == 2 else None


class TcpConnectionTests(SimpleTestCase):
    def setUp(self):
        self.echo = _Echo()
        self.srv = DNSServer(self.echo, port=0, address='127.0.0.1', tcp=True, logger=logger(), handler=Handler, server=PooledTCPServer)
        self.srv.start_thread()
        self.addr = self.srv.server.server_address
        self.addCleanup(self.srv.stop)
        self.addCleanup(self.srv.server.server_close)

    def test_every_query_of_a_connection_is_answered(self):
        with socket.create_connection(self.addr, timeout=5) as s:
            s.sendall(_framed('a.example') + _framed('b.example'))  # two in one segment: the second was dropped
            self.assertEqual(str(_read_answer(s).q.qname), 'a.example.')
            self.assertEqual(str(_read_answer(s).q.qname), 'b.example.')
            s.sendall(_framed('c.example'))  # and the connection stays open for more
            self.assertEqual(str(_read_answer(s).q.qname), 'c.example.')

    def test_proxy_line_gives_the_real_client(self):
        with override_settings(DNS_PROXY_PROTOCOL=True), socket.create_connection(self.addr, timeout=5) as s:
            s.sendall(b'PROXY TCP4 192.168.1.7 127.0.0.1 51000 853\r\n' + _framed('a.example'))
            self.assertIsNotNone(_read_answer(s))
        with override_settings(DNS_PROXY_PROTOCOL=True), socket.create_connection(self.addr, timeout=5) as s:
            s.sendall(_framed('b.example'))  # a local client without the line still works
            self.assertIsNotNone(_read_answer(s))
        with socket.create_connection(self.addr, timeout=5) as s:  # switched off: the line is not a DNS message, nothing is believed
            s.sendall(b'PROXY TCP4 192.168.1.8 127.0.0.1 51000 853\r\n' + _framed('c.example'))
            s.settimeout(5)
            try:
                s.recv(2)
            except OSError:
                pass
        self.assertEqual(self.echo.clients, ['192.168.1.7', '127.0.0.1'])

    def test_a_client_outside_allow_query_is_closed_at_once(self):
        with override_settings(DNS_ALLOW_QUERY='10.0.0.0/8'), socket.create_connection(self.addr, timeout=5) as s:
            try:
                s.sendall(_framed('a.example'))
                self.assertEqual(s.recv(2), b'')
            except OSError:
                pass  # reset by the server: closed as well
        self.assertEqual(self.echo.clients, [])


class DdnsValidationTests(TestCase):
    def setUp(self):
        self.zone = Zone.objects.create(name='corp.lan')

    def _update(self, rr):
        req = DNSRecord.question('corp.lan', 'SOA')
        req.add_auth(rr)
        return req

    def test_ttl_zero_and_bad_names(self):
        ddns._apply(self._update(RR('host.corp.lan', QTYPE.A, rdata=A('10.0.0.5'), ttl=0)), self.zone)
        self.assertEqual(Record.objects.get(name='host').ttl, 300)
        with self.assertRaises(ddns._Abort) as bad:
            ddns._apply(self._update(RR('.'.join(['a' * 60] * 4) + '.' + 'b' * 40 + '.corp.lan', QTYPE.A, rdata=A('10.0.0.6'), ttl=60)), self.zone)
        self.assertEqual(bad.exception.rcode, RCODE.FORMERR)


class StepUpGapTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()  # a grant is one-use, and two made in the same second for the same scope are the same text
        self.user = get_user_model().objects.create_superuser('root', password='x')
        TotpDevice.objects.create(user=self.user, secret='JBSWY3DPEHPK3PXP', confirmed=True)
        self.api = APIClient()
        self.api.force_authenticate(self.user)
        self.zone = Zone.objects.create(name='corp.lan')
        self.recs = [Record.objects.create(zone=self.zone, name=n, type='A', value='10.0.0.1') for n in ('a', 'b')]

    def _grant(self, scope):
        from .security import mfa
        return {'HTTP_X_MFA_GRANT': mfa.make_grant(self.user, scope)}

    def test_import_replace_needs_the_zone_grant(self):
        url, body = f'/api/zones/{self.zone.pk}/import/', {'text': 'c 300 IN A 10.0.0.3', 'replace': True}
        self.assertEqual(self.api.post(url, body, format='json').status_code, 403)
        self.assertEqual(self.zone.records.count(), 2)
        self.assertEqual(self.api.post(url, {**body, 'dry_run': True}, format='json').status_code, 200)  # nothing deleted: no proof needed
        self.assertEqual(self.api.post(url, {**body, 'replace': False}, format='json').status_code, 200)
        self.assertEqual(self.api.post(url, body, format='json', **self._grant(f'zone-delete:{self.zone.pk}')).status_code, 200)
        self.assertEqual(list(self.zone.records.values_list('name', flat=True)), ['c'])

    def test_bulk_delete_of_a_whole_zone_needs_the_zone_grant(self):
        ids = [r.pk for r in self.recs]
        self.assertEqual(self.api.post('/api/records/bulk/', {'ids': ids, 'action': 'delete'}, format='json').status_code, 403)
        self.assertEqual(self.zone.records.count(), 2)
        self.assertEqual(self.api.post('/api/records/bulk/', {'ids': ids[:1], 'action': 'delete'}, format='json').status_code, 200)  # one record left
        self.assertEqual(self.api.post('/api/records/bulk/', {'ids': ids[1:], 'action': 'delete'}, format='json', **self._grant(f'zone-delete:{self.zone.pk}')).status_code, 200)
        self.assertEqual(self.zone.records.count(), 0)

    def test_admin_ticket_needs_the_admin_grant(self):
        self.assertEqual(self.api.post('/api/admin-ticket/').status_code, 403)
        self.assertEqual(self.api.post('/api/admin-ticket/', **self._grant('mfa-change')).status_code, 403)  # a grant for something else
        self.assertIn('ticket', self.api.post('/api/admin-ticket/', **self._grant('admin')).json())


class InputCheckTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('staff', password='x', is_staff=True))

    def test_hours_out_of_range_is_not_an_error(self):
        for hours in ('99999999999999999999', '²', '0', '24'):
            for url in ('/api/logs/', '/api/logs/grouped/', '/api/logs/clients/'):
                self.assertEqual(self.api.get(url, {'hours': hours}).status_code, 200, (url, hours))

    def test_cname_shares_its_name_with_nothing(self):
        zone = Zone.objects.create(name='corp.lan')
        rec = lambda **kw: self.api.post('/api/records/', {'zone': zone.pk, 'ttl': 300, **kw}, format='json')
        self.assertEqual(rec(name='www', type='A', value='10.0.0.1').status_code, 201)
        self.assertEqual(rec(name='www', type='A', value='10.0.0.1').status_code, 400)  # the same record twice
        self.assertEqual(rec(name='www', type='A', value='10.0.0.2').status_code, 201)
        self.assertEqual(rec(name='www', type='CNAME', value='other.corp.lan.').status_code, 400)
        self.assertEqual(rec(name='alias', type='CNAME', value='www.corp.lan.').status_code, 201)
        self.assertEqual(rec(name='alias', type='TXT', value='"x"').status_code, 400)
        www = Record.objects.filter(name='www').first()
        self.assertEqual(self.api.patch(f'/api/records/{www.pk}/', {'note': 'kept'}, format='json').status_code, 200)  # editing a record is not a duplicate of itself
