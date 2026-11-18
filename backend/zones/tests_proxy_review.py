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
