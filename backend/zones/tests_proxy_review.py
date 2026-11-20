"""Regression tests for the proxy review: SSRF through IPv4-mapped addresses, truncated compressed pages, CSS injected by rule lists,
a Root CA made anew by another process, and HTTP/2 flow control and stream resets."""
import asyncio
import gzip

import h2.config
import h2.connection
import h2.events
from django.test import TestCase

from .models import Setting
from .proxy import ca, filter as pfilter, rules, server as ps
from .proxy.h2conn import H2Connection


class SsrfMappedTests(TestCase):
    def test_ipv4_mapped_address_of_the_server_is_its_own(self):
        own = frozenset({'192.168.1.23'})
        with self.assertRaises(PermissionError):
            ps._resolve_target('[::ffff:192.168.1.23]', 5432, own_ips=own)
        with self.assertRaises(PermissionError):  # the address the client reached, as a dual-stack socket names it
            ps._resolve_target('192.168.1.23', 5432, own_ips=frozenset({'::ffff:192.168.1.23'}))
        self.assertEqual(ps._resolve_target('[::ffff:192.168.1.23]', 443, own_ips=own)[0][1][1], 443)


class DecompressTests(TestCase):
    def test_truncated_or_multi_member_gzip_is_not_filtered(self):
        gz = gzip.compress(b'<p>' + b'x' * 5000 + b'</p>')
        with self.assertRaises(ValueError):
            ps._decompress(gz[:-12], 'gzip')
        with self.assertRaises(ValueError):
            ps._decompress(gz + gzip.compress(b'<p>more</p>'), 'gzip')
        self.assertEqual(ps._decompress(gz, 'gzip')[:3], b'<p>')


class CssInjectionTests(TestCase):
    def test_selectors_with_blocks_or_comments_are_dropped(self):
        bad = ['##a{} input[value^="a"]{background:url(https://x.example/a)}', '##div /* x', 'example.com##b}c{']
        text, counts = rules.reduce('\n'.join(bad + ['##.ad-slot']))
        self.assertEqual(text, '##.ad-slot')
        self.assertEqual(counts['cosmetic'], 1)
        _, _, global_css, domain_css = pfilter.parse_custom_rules('\n'.join(bad + ['##.ok']))
        self.assertEqual((global_css, domain_css), (['.ok'], {}))


class CaRefreshTests(TestCase):
    def test_a_ca_made_by_another_process_is_picked_up(self):
        first = ca.ensure_ca()
        ca.leaf_context('a.example')
        cert_pem, key_pem, _, _ = ca._generate_ca()  # what the GUI's "new Root CA" stores
        Setting.objects.update_or_create(key=ca.CA_CERT_KEY, defaults={'value': cert_pem})
        Setting.objects.update_or_create(key=ca.CA_PRIV_KEY, defaults={'value': key_pem})
        self.assertEqual(ca.ensure_ca()[0], first[0])  # the hot path keeps its cache
        self.assertEqual(ca.ensure_ca(refresh=True)[0], cert_pem)
        self.assertNotIn('a.example', ca._leaf_contexts)


    def test_a_database_error_with_no_cached_ca_is_not_a_new_ca(self):
        from unittest import mock
        from django.db import DatabaseError
        ca.ensure_ca()
        Setting.objects.filter(key__in=(ca.CA_CERT_KEY, ca.CA_PRIV_KEY)).delete()
        with mock.patch.object(ca, '_cached_ca', None), mock.patch.object(ca.Setting.objects, 'filter', side_effect=DatabaseError('away')), \
                mock.patch.object(ca, '_generate_ca') as gen:
            with self.assertRaises(DatabaseError):
                ca.ensure_ca()
        gen.assert_not_called()


class _Pipe:
    """The server side of an in-memory connection: what the client h2 writes is read here, what the server writes goes to `out`."""

    def __init__(self):
        self.inbox = asyncio.Queue()
        self.out = bytearray()

    async def read(self, n=65536, timeout=None):
        return await asyncio.wait_for(self.inbox.get(), timeout)

    async def write(self, data):
        self.out += data


def _client():
    c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
    c.initiate_connection()
    return c


_REQ = [(':method', 'POST'), (':path', '/up'), (':scheme', 'https'), (':authority', 'a.example')]


class H2Tests(TestCase):
    def test_unread_body_is_given_back_to_the_connection_window(self):
        async def main():
            pipe, client = _Pipe(), _client()
            done = asyncio.Event()

            async def handle(ex):
                done.set()  # answers without reading the body (a blocked upload)
                await ex.respond(403, '', [], b'no')

            conn = H2Connection(pipe, handle)
            runner = asyncio.create_task(conn.run())
            client.send_headers(1, _REQ)
            client.send_data(1, b'x' * 16000)
            client.send_data(1, b'x' * 16000)
            client.send_data(1, b'x' * 16000)
            await pipe.inbox.put(client.data_to_send())
            await asyncio.wait_for(done.wait(), 5)
            for _ in range(50):
                await asyncio.sleep(0.01)
                events = client.receive_data(bytes(pipe.out))
                pipe.out.clear()
                if any(isinstance(e, h2.events.WindowUpdated) and e.stream_id == 0 for e in events):
                    break
            else:
                self.fail('the connection window was never given back')
            await pipe.inbox.put(b'')
            await asyncio.wait_for(runner, 5)
        asyncio.run(main())

    def test_a_reset_stream_stops_its_handler(self):
        async def main():
            pipe, client = _Pipe(), _client()
            started, cancelled = asyncio.Event(), asyncio.Event()

            async def handle(ex):
                started.set()
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    cancelled.set()
                    raise

            conn = H2Connection(pipe, handle)
            runner = asyncio.create_task(conn.run())
            client.send_headers(1, _REQ, end_stream=True)
            await pipe.inbox.put(client.data_to_send())
            await asyncio.wait_for(started.wait(), 5)
            client.reset_stream(1)
            await pipe.inbox.put(client.data_to_send())
            await asyncio.wait_for(cancelled.wait(), 5)
            await pipe.inbox.put(b'')
            await asyncio.wait_for(runner, 5)
        asyncio.run(main())

    def test_a_silent_request_body_times_out(self):
        async def main():
            pipe, client = _Pipe(), _client()
            got = asyncio.get_running_loop().create_future()

            async def handle(ex):
                try:
                    async for _ in ex.body_chunks(0.05):
                        pass
                except TimeoutError:
                    got.set_result('timeout')

            conn = H2Connection(pipe, handle)
            runner = asyncio.create_task(conn.run())
            client.send_headers(1, _REQ)
            await pipe.inbox.put(client.data_to_send())
            self.assertEqual(await asyncio.wait_for(got, 5), 'timeout')
            await pipe.inbox.put(b'')
            await asyncio.wait_for(runner, 5)
        asyncio.run(main())


class DbPoolTimeoutTests(TestCase):
    """A database that does not answer: a DatabaseError (not TimeoutError, which drops the client's request unanswered), the blacklist lets through."""
    def test_timeout_is_a_database_error_and_the_blacklist_fails_open(self):
        from concurrent.futures import Future
        from unittest import mock
        from django.db import DatabaseError
        from .dnsd import resolver
        pending = []

        def submit(*a, **k):
            pending.append(Future())
            return pending[-1]
        with mock.patch.object(pfilter._db_pool, 'submit', side_effect=submit), \
                mock.patch.object(type(pfilter.connection), 'in_atomic_block', False, create=True), \
                mock.patch.object(resolver, '_data', None):
            with self.assertRaises(DatabaseError):
                pfilter.run_on_db_pool(len, 'x', timeout=0.01)
            self.assertTrue(pending[-1].cancelled())  # not left in the queue
            with mock.patch('zones.proxy.filter.run_on_db_pool', side_effect=DatabaseError('slow')):
                self.assertIsNone(pfilter._check_domain_blocked('ads.example'))
                self.assertEqual(rules.loaded(), rules._cache['data'])


class TlsOnPlainPortTests(TestCase):
    def test_the_server_name_of_a_client_hello(self):
        import ssl
        ctx = ssl.create_default_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(inc, out, server_hostname='www.example.org')
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()
        hello = out.read()
        self.assertEqual(ps._tls_sni(hello), 'www.example.org')
        self.assertIsNone(ps._tls_sni(b'GET / HTTP/1.1\r\n'))
        self.assertIsNone(ps._tls_sni(hello[:20]))  # cut short

    def test_the_fingerprint_of_a_client_hello_names_its_family_without_a_server_name(self):
        import ssl
        import re

        def hello(name):
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = ctx.wrap_bio(inc, out, server_hostname=name)
            with self.assertRaises(ssl.SSLWantReadError):
                tls.do_handshake()
            return out.read()
        a, b = ps._tls_fingerprint(hello('www.example.org')), ps._tls_fingerprint(hello('192.168.1.23'))
        self.assertRegex(a, r'^alpn=h2,http/1\.1 ciphers=\d+ ja3=[0-9a-f]{12}$')
        self.assertEqual(re.sub(r'ja3=\w+', '', a), re.sub(r'ja3=\w+', '', b))
        self.assertEqual(ps._tls_fingerprint(hello('www.example.org')), a)  # the random and the session do not count
        self.assertEqual(ps._tls_fingerprint(b'GET / HTTP/1.1\r\n'), '')
        self.assertEqual(ps._tls_fingerprint(hello('x.example')[:50]), '')  # cut short


class FilterLinearTests(TestCase):
    def test_unclosed_tags_are_filtered_in_linear_time(self):
        import time
        for tag in ('<script>', '<iframe ', '<meta ', '<head '):
            t0 = time.monotonic()
            pfilter.filter_html((tag * 40000).encode())
            self.assertLess(time.monotonic() - t0, 1, tag)

    def test_blocked_script_still_replaced(self):
        class S:
            PROXY_CUSTOM_RULES = '||evil.test^'
        out = pfilter.filter_html(b'<head></head><script src="http://evil.test/a.js"></script><p>x</p>', s=S).decode()
        self.assertIn('<!-- blocked script -->', out)
        self.assertIn('<p>x</p>', out)

    def test_long_url_is_capped_for_rules(self):
        class S:
            PROXY_CUSTOM_RULES = 'a*a*a*a*a*a*b'
        t0 = __import__('time').monotonic()
        pfilter.check_request('example.com', 'http://example.com/' + 'a' * 60000, s=S, dns=False)
        self.assertLess(__import__('time').monotonic() - t0, 1)


class ProxyHardeningTests(TestCase):
    def test_redact_url_drops_userinfo(self):
        self.assertEqual(ps._redact_url('http://u:pw@h/p?a=1'), 'http://h/p?a=…')

    def test_a_timeout_is_its_own_outcome(self):
        import httpcore
        self.assertEqual(ps._gateway(TimeoutError()), ('timeout', 504))
        self.assertEqual(ps._gateway(httpcore.ReadTimeout('x')), ('timeout', 504))
        self.assertEqual(ps._gateway(ConnectionRefusedError()), ('error', 502))

    def test_header_outside_latin1_is_escaped(self):
        self.assertEqual(ps.H1Exchange._encode([('X-Blocked-By', 'a中')]), [(b'X-Blocked-By', b'a\\u4e2d')])

    def test_nested_quantifier_regex_rules_are_ignored(self):
        import time
        raw = '/(a+)+/\n/(a*)*b/\n/(.+)*x/\n/ads\\d+/'
        t0 = time.monotonic()
        _, pats, _, _ = pfilter.parse_custom_rules(raw)
        self.assertEqual([p for p, _ in pats], ['/ads\\d+/'])  # the safe one stays
        self.assertIsNone(pfilter.check_request('a.test', 'http://a.test/' + 'a' * 2000 + '!', s=type('S', (), {'PROXY_CUSTOM_RULES': raw}), dns=False))
        self.assertLess(time.monotonic() - t0, 1)

    def test_sensitive_ports_are_refused_for_plain_http_even_when_high_or_allowed(self):
        from django.test import override_settings
        from .tests_proxy import RfcAndSecurityTests
        self.assertTrue({22, 25, 3306, 5432, 6379, 11211, 27017} <= ps.SENSITIVE_PORTS)
        with override_settings(PROXY_CONNECT_PORTS='*'):
            for port in (3306, 6379, 22):
                resp, seen = RfcAndSecurityTests._session(self, f'GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode())
                self.assertIn(b'403', resp.split(b'\r\n', 1)[0])
                self.assertEqual(seen, {})
            resp, _ = RfcAndSecurityTests._session(self, b'GET http://127.0.0.1:8080/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
            self.assertIn(b'200 OK', resp)

    def test_pipe_half_close_passes_eof_and_the_late_answer(self):
        class End:
            def __init__(self, chunks):
                self.q, self.got, self.eof = asyncio.Queue(), bytearray(), False
                for c in chunks:
                    self.q.put_nowait(c)

            async def read(self, n=65536, timeout=None):
                return await self.q.get()

            async def write(self, data):
                self.got += data

            def write_eof(self):
                self.eof = True

        async def go():
            a, b = End([b'req', b'']), End([])
            async def late():  # the server answers after the client's half-close
                while not b.eof:
                    await asyncio.sleep(0.01)
                b.q.put_nowait(b'resp')
                b.q.put_nowait(b'')
            t = asyncio.create_task(late())
            await asyncio.wait_for(ps._pipe(a, b), 5)
            await t
            return a, b
        a, b = asyncio.run(go())
        self.assertEqual(bytes(b.got), b'req')
        self.assertEqual(bytes(a.got), b'resp')
