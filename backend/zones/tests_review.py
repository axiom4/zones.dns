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

from .dnsd import ddns, ratelimit, resolver, suspicious, zonefile
from .dnsd.dnsserver import Handler, PooledTCPServer, logger
from .management.commands.rundns import Command as RunDns
from .models import ProxyLog, QueryLog, Record, TotpDevice, Zone


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
            self.assertEqual(sorted(str(_read_answer(s).q.qname) for _ in range(2)), ['a.example.', 'b.example.'])  # in any order (RFC 7766 §7)
            s.sendall(_framed('c.example'))  # and the connection stays open for more
            self.assertEqual(str(_read_answer(s).q.qname), 'c.example.')

    def test_proxy_line_gives_the_real_client(self):
        with override_settings(DNS_PROXY_PROTOCOL=True), socket.create_connection(self.addr, timeout=5) as s:
            s.sendall(b'PROXY TCP4 192.168.1.7 127.0.0.1 51000 853\r\n' + _framed('a.example'))
            self.assertIsNotNone(_read_answer(s))
        with override_settings(DNS_PROXY_PROTOCOL=True), socket.create_connection(self.addr, timeout=5) as s:
            s.sendall(_framed('b.example'))  # a local client without the line still works
            self.assertIsNotNone(_read_answer(s))
        with mock.patch('zones.dnsd.dnsserver.TCP_IDLE', 0.3), socket.create_connection(self.addr, timeout=5) as s:  # switched off: the line is not a DNS message, nothing is believed
            s.sendall(b'PROXY TCP4 192.168.1.8 127.0.0.1 51000 853\r\n' + _framed('c.example'))
            s.settimeout(5)
            try:
                s.recv(2)
            except OSError:
                pass
        self.assertEqual(self.echo.clients, ['192.168.1.7', '127.0.0.1'])

    def test_silent_connections_hold_no_worker(self):
        idle = [socket.create_connection(self.addr, timeout=5) for _ in range(PooledTCPServer.workers * 3)]
        self.addCleanup(lambda: [s.close() for s in idle])
        idle[0].sendall(b'\x00')  # half a length: a query that never comes
        with socket.create_connection(self.addr, timeout=2) as s:
            s.sendall(_framed('a.example'))
            self.assertEqual(str(_read_answer(s).q.qname), 'a.example.')
        with mock.patch('zones.dnsd.dnsserver.TCP_IDLE', 0.2):
            idle[1].settimeout(5)
            self.assertEqual(idle[1].recv(1), b'')  # closed by the server after the idle time

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
        cache.clear()
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


class CnameEverywhereTests(TestCase):
    """The CNAME rule of the API also holds for the other ways a record gets in."""
    def setUp(self):
        self.zone = Zone.objects.create(name='corp.lan')
        Record.objects.create(zone=self.zone, name='www', type='A', value='10.0.0.1')
        Record.objects.create(zone=self.zone, name='alias', type='CNAME', value='www.corp.lan.')

    def test_zone_file_import(self):
        out = zonefile.import_zone(self.zone, 'www 300 IN CNAME other.corp.lan.\nalias 300 IN TXT "x"\nnew 300 IN CNAME www.corp.lan.\nnew 300 IN A 10.0.0.9\nok 300 IN A 10.0.0.2\n')
        self.assertEqual((out['created'], len(out['errors'])), (2, 3))
        self.assertEqual(sorted(self.zone.records.values_list('name', 'type')), [('alias', 'CNAME'), ('new', 'CNAME'), ('ok', 'A'), ('www', 'A')])

    def test_dns_update_ignores_the_conflict(self):
        req = DNSRecord.question('corp.lan', 'SOA')
        req.add_auth(RR('alias.corp.lan', QTYPE.A, rdata=A('10.0.0.5'), ttl=60))
        ddns._apply(req, self.zone)
        self.assertEqual(list(Record.objects.filter(name='alias').values_list('type', flat=True)), ['CNAME'])

    def test_django_admin(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            Record(zone=self.zone, name='www', type='CNAME', value='other.corp.lan.').clean()
        Record.objects.get(name='www').clean()  # a record is not in conflict with itself


class MoreStepUpTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.user = get_user_model().objects.create_user('staff', password='x', is_staff=True)
        TotpDevice.objects.create(user=self.user, secret='JBSWY3DPEHPK3PXP', confirmed=True)
        self.api = APIClient()
        self.api.force_authenticate(self.user)
        self.zone = Zone.objects.create(name='corp.lan')

    def _grant(self, scope):
        from .security import mfa
        return {'HTTP_X_MFA_GRANT': mfa.make_grant(self.user, scope)}

    def test_two_grants_of_the_same_second_both_work(self):
        url = f'/api/zones/{self.zone.pk}/'
        for _ in range(2):
            self.assertEqual(self.api.patch(url, {'enabled': False}, format='json', **self._grant(f'zone-delete:{self.zone.pk}')).status_code, 200)
            self.assertEqual(self.api.patch(url, {'enabled': True}, format='json').status_code, 200)  # switching on needs no proof

    def test_switching_a_zone_off_needs_the_zone_grant(self):
        url = f'/api/zones/{self.zone.pk}/'
        self.assertEqual(self.api.patch(url, {'enabled': False}, format='json').status_code, 403)
        self.assertEqual(self.api.put(url, {'name': 'corp.lan', 'enabled': False}, format='json').status_code, 403)
        self.assertTrue(Zone.objects.get(pk=self.zone.pk).enabled)

    def test_purging_the_log_needs_its_grant(self):
        QueryLog.objects.create(name='a.example', type='A', outcome='forwarded', client='10.0.0.1', ms=1)
        body = {'older_than_hours': 0}
        self.assertEqual(self.api.post('/api/logs/purge/', {**body, 'dry_run': True}, format='json').json()['count'], 1)
        self.assertEqual(self.api.post('/api/logs/purge/', body, format='json').status_code, 403)
        self.assertEqual(QueryLog.objects.count(), 1)
        self.assertEqual(self.api.post('/api/logs/purge/', body, format='json', **self._grant('log-purge')).status_code, 200)
        self.assertEqual(QueryLog.objects.count(), 0)

    def test_purging_the_proxy_log_needs_its_grant(self):
        ProxyLog.objects.create(client='10.0.0.1', method='GET', host='a.example', url='http://a.example/', outcome='allowed')
        body = {'older_than_hours': 0}
        self.assertEqual(self.api.post('/api/proxy/logs/purge/', {**body, 'dry_run': True}, format='json').json()['deleted'], 1)
        self.assertEqual(self.api.post('/api/proxy/logs/purge/', body, format='json').status_code, 403)
        self.assertEqual(ProxyLog.objects.count(), 1)
        self.assertEqual(self.api.post('/api/proxy/logs/purge/', body, format='json', **self._grant('log-purge')).status_code, 200)
        self.assertEqual(ProxyLog.objects.count(), 0)

    def test_proxy_changes_that_move_traffic_need_their_grant(self):
        patch = lambda body, **kw: self.api.patch('/api/proxy/settings/', body, format='json', **kw).status_code
        self.assertEqual(patch({'PROXY_HTTPS_MITM': True}), 403)
        self.assertEqual(patch({'DHCP_WPAD_URL': 'http://10.9.9.9/wpad.dat'}), 403)
        self.assertEqual(patch({'PROXY_BLOCK_ADS': False}), 200)  # filtering options need no proof
        self.assertEqual(patch({'PROXY_HTTPS_MITM': True}, **self._grant('proxy-change')), 200)
        self.assertEqual(patch({'PROXY_HTTPS_MITM': True}), 200)  # unchanged value: nothing to prove
        self.assertEqual(self.api.post('/api/proxy/info/').status_code, 403)  # a new Root CA
        self.assertEqual(self.api.post('/api/proxy/info/', **self._grant('proxy-change')).status_code, 200)

    def test_dhcp_changes_that_move_traffic_need_their_grant(self):
        patch = lambda body, **kw: self.api.patch('/api/dhcp/settings/', body, format='json', **kw).status_code
        self.assertEqual(patch({'DHCP_DNS': '10.9.9.9'}), 403)
        self.assertEqual(patch({'DHCP_LEASEQUERY': '10.0.0.0/8'}), 403)  # who may read the leases
        self.assertEqual(patch({'DHCP_LEASE': 7200}), 200)  # other options need no proof
        self.assertEqual(patch({'DHCP_DNS': '10.9.9.9'}, **self._grant('dhcp-change')), 200)
        self.assertEqual(patch({'DHCP_DNS': '10.9.9.9'}), 200)  # unchanged value: nothing to prove
        self.assertEqual(patch({'DHCP_LEASEQUERY': 'not-an-ip'}, **self._grant('dhcp-change')), 400)

    def test_bulk_disable_of_most_of_a_zone_needs_the_zone_grant(self):
        ids = [Record.objects.create(zone=self.zone, name=f'h{i}', type='A', value=f'10.0.0.{i}').pk for i in range(1, 21)]
        post = lambda some, **kw: self.api.post('/api/records/bulk/', {'ids': some, 'action': 'disable'}, format='json', **kw).status_code
        self.assertEqual(post(ids[:11]), 403)  # 11 of 20: over half
        self.assertEqual(Record.objects.filter(enabled=False).count(), 0)
        self.assertEqual(post(ids[:3]), 200)  # a few: no proof
        self.assertEqual(post(ids, **self._grant(f'zone-delete:{self.zone.pk}')), 200)
        self.assertEqual(Record.objects.filter(enabled=False).count(), 20)
        self.assertEqual(self.api.post('/api/records/bulk/', {'ids': ids, 'action': 'enable'}, format='json').status_code, 200)

    def test_bulk_delete_of_most_of_a_zone_needs_the_zone_grant(self):
        ids = [Record.objects.create(zone=self.zone, name=f'h{i}', type='A', value=f'10.0.0.{i}').pk for i in range(1, 21)]
        post = lambda some, **kw: self.api.post('/api/records/bulk/', {'ids': some, 'action': 'delete'}, format='json', **kw).status_code
        self.assertEqual(post(ids[:11]), 403)  # 11 of 20: over half
        self.assertEqual(post(ids[:9]), 200)  # under BULK_MIN
        self.assertEqual(post(ids[9:], **self._grant(f'zone-delete:{self.zone.pk}')), 200)


class DegradedTests(TestCase):
    def test_dhcp_names_without_database(self):
        def gone(qname, cfg):
            raise DatabaseError('gone away')
        with self.assertLogs('zones.dnsd.resolver', 'WARNING'):
            resolver._db_warned = 0.0
            self.assertIsNone(resolver._lease(gone, 'pc.corp.lan'))

    def test_only_the_upstream_asked_and_the_right_id_are_taken(self):
        import threading
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('127.0.0.1', 0))
        self.addCleanup(srv.close)
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(stranger.close)

        def serve():
            data, who = srv.recvfrom(512)
            stranger.sendto(data, who)  # the right id from another port: dropped by the connected socket
            srv.sendto(b'\x00\x00' + data[2:], who)  # the right server, another id: skipped
            srv.sendto(data + b'ok', who)
        threading.Thread(target=serve, daemon=True).start()
        self.assertEqual(resolver._udp_exchange(b'\x12\x34question', '127.0.0.1', srv.getsockname()[1], False, 3), b'\x12\x34questionok')
        with self.assertRaises(OSError):
            resolver._udp_exchange(b'\x12\x34question', '127.0.0.1', srv.getsockname()[1], False, 0.2)  # nobody answers


class RateLimitTests(TestCase):
    def tearDown(self):
        ratelimit.reset()

    def test_ipv6_is_counted_per_64_and_refusals_are_numbered(self):
        ratelimit.reset()
        with override_settings(DNS_RATE_LIMIT=2, DNS_RATE_WINDOW=60):
            self.assertEqual([ratelimit.exceeded(f'2001:db8:1:2::{i}') for i in range(1, 5)], [0, 0, 1, 2])  # one host, four addresses
            self.assertEqual(ratelimit.exceeded('2001:db8:1:3::1'), 0)  # another network
            self.assertEqual(ratelimit.exceeded('::ffff:10.0.0.1'), 0)
            self.assertEqual([ratelimit.exceeded('10.0.0.1') for _ in range(2)], [0, 1])  # the same client as the mapped address

    def test_a_flood_is_logged_once(self):
        from types import SimpleNamespace
        ratelimit.reset()
        resolver._data = None
        Zone.objects.create(name='corp.lan')
        h = SimpleNamespace(client_address=('10.9.9.9', 0))
        r = resolver.Resolver('1.1.1.1')
        with override_settings(DNS_RATE_LIMIT=1, DNS_RATE_WINDOW=60, DNS_AUTHORITATIVE=True):
            codes = [r.resolve(DNSRecord.question('x.corp.lan', 'A'), h).header.rcode for _ in range(6)]
        self.assertEqual(codes, [RCODE.NXDOMAIN] + [RCODE.REFUSED] * 5)
        self.assertEqual(QueryLog.objects.filter(via='rate limit').count(), 1)


class SlowPatternTests(SimpleTestCase):
    def test_a_pattern_that_is_slow_without_nested_repeats_is_refused(self):
        from .serializers.blocked_domain import _has_redos, pattern_error
        slow = 'a*a*a*a*a*a*b'
        self.assertFalse(_has_redos(slow))  # nothing the reading of the pattern objects to
        self.assertIsNotNone(pattern_error(slow))
        for fine in (r'^ads?\d+\.', r'(^|\.)track(er|ing)?\.', r'^[a-z0-9-]{20,}\.example\.com$'):
            self.assertIsNone(pattern_error(fine), fine)


class DhcpReviewTests(TestCase):
    def _cfg(self, failover):
        import ipaddress
        from .dhcp.v4 import Config
        ip = ipaddress.IPv4Address
        return Config(ip('192.168.1.2'), ipaddress.IPv4Network('192.168.1.0/24'), ip('192.168.1.100'), ip('192.168.1.102'), ip('192.168.1.1'), [ip('192.168.1.2')],
                      'lan', 3600, {}, b'', failover_secs=failover)

    def test_a_standby_server_does_not_refuse_the_address_the_primary_gave(self):
        from .dhcp.v4 import Server
        from .tests import DhcpTests
        req = DhcpTests().packet('aa:aa:aa:aa:aa:70', 3, o50=bytes([192, 168, 1, 20]))  # INIT-REBOOT: an address of the primary's range, no server id
        self.assertIsNone(Server(self._cfg(failover=5)).handle(req))
        self.assertEqual(Server(self._cfg(failover=0)).handle(req).data[240:243], bytes([53, 1, 6]))  # the only server on the network says NAK

    def test_a_release_with_thousands_of_ias_is_bounded(self):
        import ipaddress
        from .dhcp.v6 import IA_NA, MAX_IA, Config6, Server6
        from .tests import Dhcp6Tests
        s6 = Server6(Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                             ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::1ff'), name='test6'))
        h6 = Dhcp6Tests()
        msg = h6.msg(8, cid=b'\x00\x03flood', sid=s6.duid, ias=[h6.ia(IA_NA, i, b'') for i in range(2000)])
        with self.assertNumQueries(MAX_IA):  # one DELETE per IA looked at, not 2000
            self.assertIsNotNone(s6.handle(msg))


class AuditReviewTests(SimpleTestCase):
    def test_upstream_with_a_port_is_asked_on_that_port(self):
        from .stats import audit
        reply = DNSRecord.question('example.com').reply()
        for upstream, want in (('127.0.0.1:5335', ('127.0.0.1', 5335, False)), ('[::1]:5335', ('::1', 5335, True)), ('9.9.9.9', ('9.9.9.9', 53, False))):
            with override_settings(UPSTREAMS=[upstream]), mock.patch.object(DNSRecord, 'send', return_value=reply.pack()) as send:
                self.assertIsNotNone(audit.dns_query('example.com', 'A'))
            self.assertEqual((send.call_args.args[0], send.call_args.args[1], send.call_args.kwargs['ipv6']), want)

    def test_a_dripping_server_does_not_hold_the_request(self):
        from .stats import audit

        class Drip:
            def recv(self, n):
                return b'x'
        with mock.patch.object(audit, 'TIMEOUT', 0.05):
            status, headers, cookies, body = audit._read_response(Drip(), body_limit=10 ** 9)
        self.assertIsNone(status)  # it returned
