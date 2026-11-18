from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from .stats import audit, tracker_scan


class AuditHardeningTests(SimpleTestCase):
    def test_nat64_and_ipv4_compatible_addresses_are_judged_by_the_ipv4_inside(self):
        for ip in ('64:ff9b::a00:1', '::127.0.0.1', '64:ff9b::a9fe:a9fe', '::ffff:10.0.0.1'):
            self.assertFalse(audit.is_public(ip), ip)
        for ip in ('64:ff9b::808:808', '8.8.8.8', '2606:4700::1111'):
            self.assertTrue(audit.is_public(ip), ip)

    def test_tcp_answer_cut_short_does_not_loop(self):
        class Sock:
            def __init__(self):
                self.parts = [b'\xff\xff', b'abc']  # announces 65535 bytes, sends 3, closes

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def sendall(self, data):
                pass

            def settimeout(self, t):
                pass

            def recv(self, n):
                return self.parts.pop(0) if self.parts else b''
        with mock.patch('socket.create_connection', return_value=Sock()):
            self.assertIsNone(audit.dns_query('example.com', 'AXFR', server='192.0.2.1', tcp=True))

    def test_bad_location_ends_the_chain_instead_of_failing(self):
        for loc in ('http://example.org:abc/', 'http://[::1/', 'http://example.org:99999/'):
            with mock.patch.object(audit, 'public_ips', return_value=['93.184.216.34']), \
                    mock.patch.object(audit, 'fetch', return_value=(301, {'location': loc}, [], b'')):
                hops = audit.redirect_chain('example.com')
            self.assertEqual([h['location'] for h in hops], [loc])
            with mock.patch.object(tracker_scan, 'public_ips', return_value=['93.184.216.34']), \
                    mock.patch.object(tracker_scan, 'fetch', return_value=(301, {'location': loc}, [], b'')), \
                    mock.patch.object(tracker_scan, 'main_domain', side_effect=lambda h: h):
                tracker_scan.probe('example.com')  # returned

    def test_rdap_dates_and_vcards_from_odd_registries(self):
        self.assertEqual(audit._iso('2030-01-01T00:00:00').tzinfo is not None, True)  # no zone: UTC, not a TypeError
        self.assertIsNone(audit._iso('soon'))
        self.assertIsNone(audit._iso(None))
        self.assertIsNone(audit._vcard({'vcardArray': ['vcard']}, 'fn'))
        self.assertIsNone(audit._vcard({'vcardArray': ['vcard', [['fn']]]}, 'fn'))
        self.assertEqual(audit._vcard({'vcardArray': ['vcard', [['fn', {}, 'text', 'Reg']]]}, 'fn'), 'Reg')


class StatsViewReviewTests(TestCase):
    def setUp(self):
        cache.clear()
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('adm', is_staff=True))

    def test_proxy_timeouts_are_counted_apart(self):
        from .models import ProxyLog
        for outcome, ms in (('allowed', 100), ('allowed', 300), ('error', 200), ('timeout', 120000), ('timeout', 120000)):
            ProxyLog.objects.create(client='10.0.0.1', method='GET', host='slow.example' if outcome == 'timeout' else 'ok.example', outcome=outcome, ms=ms)
        d = self.api.get('/api/stats/?source=proxy').json()
        self.assertEqual((d['total'], d['avg_ms'], d['timeouts']), (3, 200, 2))  # the two waits that ran out change neither the total nor the average
        self.assertNotIn('timeout', [c['name'] for c in d['by_outcome']])
        self.assertEqual(d['top_timeouts'], [{'name': 'slow.example', 'count': 2}])
        self.assertEqual(self.api.get('/api/stats/?source=dns').json()['timeouts'], 0)
        self.assertEqual(self.api.get('/api/stats/').json()['timeouts'], 2)
        self.assertEqual(self.api.get('/api/proxy/logs/?outcome=timeout').json()['count'], 2)  # the log still lists them

    def test_since_that_is_not_a_date_is_ignored(self):
        self.assertEqual(self.api.get('/api/stats/?since=2024-13-45T00:00:00Z').status_code, 200)

    def test_odd_numbers_in_query_log_params(self):
        self.assertEqual(self.api.get('/api/logs/answers/?ids=1,²').status_code, 200)
        self.assertEqual(self.api.get('/api/logs/?before=²').status_code, 200)
        r = self.api.post('/api/logs/purge/', {'older_than_hours': 10 ** 12, 'dry_run': True}, format='json')
        self.assertEqual(r.status_code, 200)

    def test_grouped_count_is_the_number_of_groups(self):
        from .models import QueryLog
        from .stats import rollup
        rows = [QueryLog.objects.create(name=f'{i}.example.com', domain='example.com', type='A', outcome='forwarded', client='10.0.0.1', ms=1) for i in range(3)]
        rollup.add(rows)  # LogTotal exists: the fast count path is on
        r = self.api.get('/api/logs/grouped/?by=name').json()
        self.assertEqual((r['count'], len(r['results'])), (3, 3))
        r = self.api.get('/api/logs/grouped/').json()
        self.assertEqual((r['count'], len(r['results'])), (1, 1))  # one domain, not 3 queries
