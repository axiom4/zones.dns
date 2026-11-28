"""Tests for the HTTP/HTTPS ad-blocking & popup-blocking proxy, DHCP WPAD (option 252 + DNS wpad.<domain>), PAC generation, and HTTPS MITM."""
import asyncio
import gzip
import socket
import ssl
import threading
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from dnslib import DNSRecord
from rest_framework.test import APIClient

from .dhcp import names, v4 as dhcp
from .dnsd import resolver
from .dnsd.resolver import Resolver
from .models import BlockedDomain, DataVersion, ProxyLog, Setting
from .proxy import ca, filter as pfilter
from .proxy.server import _mitm_failed, cached_proxy_settings, is_mitm_failed, serve_connection


def _fake_fetcher(scheme, host, port, method, path, body, headers):
    if path == '/br-page':
        # Verify lowercase accept-encoding was stripped and replaced with gzip, deflate
        ae_keys = [k for k in headers if k.lower() == 'accept-encoding']
        assert ae_keys == ['Accept-Encoding'] and headers['Accept-Encoding'] == 'gzip, deflate'
        fake_brotli = b'\x8b\x13\x80\xff\xfe\xfd\x00\x99\xa0\xb1\xc2\xd3\xe4\xf5'
        return 200, 'OK', [('Content-Type', 'text/html; charset=utf-8'), ('Content-Encoding', 'br')], fake_brotli
    if path == '/gzip-page':
        raw = (
            b'<!doctype html><html><head><title>News</title>'
            b'<script src="https://ads.badtracker.example/ad.js"></script>'
            b'<script>window.PopAds = 1; openPopunder();</script>'
            b'</head><body><h1>Hello</h1>'
            b'<iframe src="https://ads.badtracker.example/frame.html"></iframe>'
            b'<div class="adsbox">Ad</div></body></html>'
        )
        gz = gzip.compress(raw)
        return 200, 'OK', [('Content-Type', 'text/html; charset=utf-8'), ('Content-Encoding', 'gzip')], gz
    raw = (
        b'<!doctype html><html><head><title>Test Page</title>'
        b'<script src="http://ads.badtracker.example/banner.js"></script>'
        b'<script src="/pagead/show_ads.js"></script>'
        b'<script>function init(){ aclib.runPop(); }</script>'
        b'<script>console.log("legit script");</script>'
        b'</head><body>'
        b'<iframe src="http://ads.badtracker.example/iframe.html"></iframe>'
        b'<iframe src="/content/frame.html"></iframe>'
        b'<p>Real article content</p>'
        b'</body></html>'
    )
    return 200, 'OK', [('Content-Type', 'text/html; charset=utf-8')], raw


def _dechunk(body):
    out = b''
    while True:
        size_line, _, body = body.partition(b'\r\n')
        n = int(size_line, 16)
        if n == 0:
            return out
        out, body = out + body[:n], body[n + 2:]


def _run_proxy_session(raw_bytes, server_ns):
    """Run one proxy connection over a socketpair and return the raw response bytes."""
    client_sock, server_sock = socket.socketpair()
    t = threading.Thread(target=lambda: (serve_connection(server_sock, ('127.0.0.1', 54321), server_ns), server_sock.close()), daemon=True)
    t.start()
    try:
        client_sock.sendall(raw_bytes)
        chunks = []
        while True:
            data = client_sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b''.join(chunks)
    finally:
        client_sock.close()
        t.join(timeout=5)


class ProxyAndWpadTests(TestCase):
    def setUp(self):
        BlockedDomain.objects.create(name='badtracker.example', source='manual', enabled=True)
        resolver._data = None

    def test_dhcp_option_252_and_dns_wpad_resolution(self):
        with override_settings(
            DHCP=True,
            DHCP_SERVER='192.168.1.2',
            DHCP_NETMASK='255.255.255.0',
            DHCP_RANGE='192.168.1.100-192.168.1.150',
            DHCP_DOMAIN='home.lan',
            DHCP_NAMES=True,
            DHCP_WPAD=True,
            PROXY=True,
            PROXY_PORT=8080,
            DHCP_PROBE=False,
        ):
            cfgs = dhcp.scopes(dhcp.dhcp_settings())
            self.assertEqual(cfgs[0].wpad_url, 'http://192.168.1.2:8080/wpad.dat')
            srv = dhcp.Server(cfgs, probe=lambda ip: False)
            req = {'xid': 123, 'flags': 0, 'giaddr': dhcp.ZERO, 'chaddr': bytes.fromhex('aabbccddeeff')}
            pkt = dhcp.build(req, dhcp.ZERO, [(53, bytes([dhcp.DISCOVER])), (55, bytes([1, 3, 6, 15, 252]))])
            out = srv.handle(b'\x01' + pkt[1:])
            parsed = dhcp.parse(b'\x01' + out.data[1:])
            self.assertEqual(parsed['opts'].get(252), b'http://192.168.1.2:8080/wpad.dat')

            resolver._data = None
            res = Resolver('127.0.0.1:9', log=None)
            ans = res.resolve(DNSRecord.question('wpad.home.lan', 'A'), SimpleNamespace(client_address=('127.0.0.1', 0)))
            self.assertEqual([str(rr.rdata) for rr in ans.rr], ['192.168.1.2'])
            self.assertIsNone(names.lease_hosts('wpad.home.lan', (True, 'home.lan')))

    def test_pac_file_generation_and_public_endpoints(self):
        import plistlib
        with override_settings(
            ALLOWED_HOSTS=['dns.axiom4.net'],
            SECURE_SSL_REDIRECT=True,
            SECURE_REDIRECT_EXEMPT=[r'^(wpad\.dat|proxy\.pac|proxy-ca\.crt|proxy\.mobileconfig)$'],
            DHCP_SERVER='192.168.1.2',
            DHCP_DOMAIN='corp.lan',
            DEFAULT_ZONE='axiom4.net',
            PROXY=True,
            PROXY_PORT=8888,
            DHCP_WPAD=True,
            PROXY_CUSTOM_RULES='@@intranet.corp.lan',
        ):
            # Works over plain HTTP even with Host: wpad.axiom4.net (not in ALLOWED_HOSTS) and SECURE_SSL_REDIRECT=True
            r = self.client.get('/wpad.dat', HTTP_HOST='wpad.axiom4.net')
            self.assertEqual(r.status_code, 200)
            self.assertIn('application/x-ns-proxy-autoconfig', r['Content-Type'])
            text = r.content.decode()
            self.assertIn('PROXY 192.168.1.2:8888', text)
            self.assertIn('wss:', text)
            self.assertIn('.corp.lan', text)
            self.assertIn('.axiom4.net', text)
            self.assertIn('.intranet.corp.lan', text)

            ca_resp = self.client.get('/proxy-ca.crt', HTTP_HOST='wpad.axiom4.net')
            self.assertEqual(ca_resp.status_code, 200)
            self.assertIn(b'BEGIN CERTIFICATE', ca_resp.content)

            mc_resp = self.client.get('/proxy.mobileconfig', HTTP_HOST='wpad.axiom4.net')
            self.assertEqual(mc_resp.status_code, 200)
            self.assertEqual(mc_resp['Content-Type'], 'application/x-apple-aspen-config')
            plist = plistlib.loads(mc_resp.content)
            self.assertEqual(plist['PayloadContent'][0]['ProxyAutoConfigURLString'], 'http://192.168.1.2:8888/wpad.dat')

            # wpad.axiom4.net (from DEFAULT_ZONE) also resolves in DNS
            resolver._data = None
            res = Resolver('127.0.0.1:9', log=None)
            ans = res.resolve(DNSRecord.question('wpad.axiom4.net', 'A'), SimpleNamespace(client_address=('127.0.0.1', 0)))
            self.assertEqual([str(rr.rdata) for rr in ans.rr], ['192.168.1.2'])

    def test_filter_rules_and_html_cleaning(self):
        s = dhcp.dhcp_settings(overrides={
            'PROXY': True,
            'PROXY_BLOCK_ADS': True,
            'PROXY_BLOCK_POPUPS': True,
            'PROXY_CUSTOM_RULES': '##.custom-ad-slot\nnews.example##.paywall-banner\n/evil-tracker/\n@@trusted.badtracker.example',
        })
        self.assertEqual(pfilter.check_request('ads.badtracker.example', 'https://ads.badtracker.example/x.js', s=s)[0], 'blacklist')
        self.assertIsNone(pfilter.check_request('trusted.badtracker.example', 'https://trusted.badtracker.example/x.js', s=s))
        self.assertEqual(pfilter.check_request('news.example', 'https://news.example/pagead/show_ads.js', s=s)[0], 'ad-url')
        self.assertEqual(pfilter.check_request('news.example', 'https://news.example/js/popunder.min.js', s=s)[0], 'popup-url')
        self.assertEqual(pfilter.check_request('news.example', 'https://news.example/evil-tracker/pixel', s=s)[0], 'custom-rule')
        self.assertIsNone(pfilter.check_request('news.example', 'https://news.example/articles/1', s=s))

        raw_html = (
            b'<html><head><title>Article</title>'
            b'<script src="https://ads.badtracker.example/ad.js"></script>'
            b'<script>aclib.runPop();</script>'
            b'<script src="/app.js"></script>'
            b'</head><body>'
            b'<iframe src="https://ads.badtracker.example/frame.html"></iframe>'
            b'<p>Hello world</p></body></html>'
        )
        cleaned = pfilter.filter_html(raw_html, 'text/html; charset=utf-8', host='news.example', s=s).decode()
        self.assertNotIn('ads.badtracker.example/ad.js', cleaned)
        self.assertNotIn('aclib.runPop', cleaned)
        self.assertNotIn('ads.badtracker.example/frame.html', cleaned)
        self.assertIn('src="/app.js"', cleaned)
        self.assertIn('id="zones-popup-blocker"', cleaned)
        self.assertIn('id="zones-adblock-css"', cleaned)
        self.assertIn('.custom-ad-slot', cleaned)
        self.assertIn('.paywall-banner', cleaned)

    def test_http_proxy_and_https_connect_and_mitm(self):
        ca_pem, _, _, _ = ca.ensure_ca()
        ca.leaf_context('127.0.0.1')
        resolver.blocked_entry('ads.badtracker.example')
        resolver.blocked_entry('127.0.0.1')
        client_ssl_ctx = ssl.create_default_context(cadata=ca_pem)
        mitm_enabled = {'on': False}

        def make_server_ns(tunnel_factory=None):
            return SimpleNamespace(
                settings_getter=lambda: SimpleNamespace(
                    DHCP_SERVER='192.168.1.2',
                    DHCP_DOMAIN='home.lan',
                    DHCP_WPAD=True,
                    DHCP_WPAD_URL='',
                    PROXY=True,
                    PROXY_PORT=8080,
                    PROXY_BLOCK_ADS=True,
                    PROXY_BLOCK_POPUPS=True,
                    PROXY_HTTPS_MITM=mitm_enabled['on'],
                    PROXY_CUSTOM_RULES='',
                ),
                allow_loopback=True,
                http_fetcher=_fake_fetcher,
                tunnel_factory=tunnel_factory,
                upstream_ssl_context=client_ssl_ctx,
            )

        # 1. Local /wpad.dat directly from proxy handler
        resp = _run_proxy_session(b'GET /wpad.dat HTTP/1.1\r\nHost: 192.168.1.2:8080\r\n\r\n', make_server_ns())
        self.assertIn(b'200 OK', resp)
        self.assertIn(b'FindProxyForURL', resp)

        # 2. HTTP request to blocked domain is rejected with 403
        resp = _run_proxy_session(b'GET http://ads.badtracker.example/page.html HTTP/1.1\r\nHost: ads.badtracker.example\r\nConnection: close\r\n\r\n', make_server_ns())
        self.assertIn(b'403 Forbidden', resp)
        self.assertIn(b'X-Blocked-By: Zones.dns (blacklist:', resp)

        # 3. HTTP request to allowed page decompresses gzip, strips ads/popups, and injects CSS & popup blocker
        resp = _run_proxy_session(b'GET http://127.0.0.1/gzip-page HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n', make_server_ns())
        text = resp.decode()
        self.assertIn('200 OK', text)
        self.assertNotIn('ads.badtracker.example', text)
        self.assertNotIn('openPopunder', text)
        self.assertIn('id="zones-popup-blocker"', text)
        self.assertIn('id="zones-adblock-css"', text)
        self.assertIn('<h1>Hello</h1>', text)

        # 3b. Upstream Brotli/Zstd response or lowercase accept-encoding is never corrupted into replacement chars
        resp_br = _run_proxy_session(
            b'GET http://127.0.0.1/br-page HTTP/1.1\r\nHost: 127.0.0.1\r\naccept-encoding: gzip, deflate, br, zstd\r\nConnection: close\r\n\r\n',
            make_server_ns(),
        )
        self.assertIn(b'Content-Encoding: br\r\n', resp_br)
        self.assertTrue(resp_br.endswith(b'\x8b\x13\x80\xff\xfe\xfd\x00\x99\xa0\xb1\xc2\xd3\xe4\xf5'))

        # 4. HTTPS CONNECT to blocked domain is rejected with 403 without needing MITM
        resp = _run_proxy_session(b'CONNECT ads.badtracker.example:443 HTTP/1.1\r\nHost: ads.badtracker.example:443\r\n\r\n', make_server_ns())
        self.assertIn(b'403 Forbidden', resp)

        # 5. HTTPS CONNECT with MITM=False tunnels raw bytes end-to-end
        up_a, up_b = socket.socketpair()
        def _echo_upstream():
            data = up_b.recv(1024)
            up_b.sendall(b'TUNNELED:' + data)
            up_b.close()
        threading.Thread(target=_echo_upstream, daemon=True).start()
        c_sock, s_sock = socket.socketpair()
        srv_ns = make_server_ns(tunnel_factory=lambda h, p: up_a)
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 54321), srv_ns), s_sock.close()), daemon=True)
        t.start()
        c_sock.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner = c_sock.recv(1024)
        self.assertIn(b'200 Connection Established', banner)
        c_sock.sendall(b'hello-tls')
        echoed = c_sock.recv(1024)
        self.assertEqual(echoed, b'TUNNELED:hello-tls')
        c_sock.close()
        t.join(timeout=5)

        # 6. HTTPS CONNECT with MITM=True performs TLS handshake with dynamically signed cert and filters HTTPS HTML
        _mitm_failed.clear()
        mitm_enabled['on'] = True
        c_sock, s_sock = socket.socketpair()
        srv_ns = make_server_ns()
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 54321), srv_ns), s_sock.close()), daemon=True)
        t.start()
        c_sock.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner = b''
        while b'\r\n\r\n' not in banner:
            banner += c_sock.recv(1024)
        self.assertIn(b'200 Connection Established', banner)
        with client_ssl_ctx.wrap_socket(c_sock, server_hostname='127.0.0.1') as tls_sock:
            tls_sock.sendall(b'GET /article HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
            chunks = []
            while True:
                try:
                    d = tls_sock.recv(65536)
                except (ssl.SSLZeroReturnError, BrokenPipeError, ConnectionResetError):
                    break
                if not d:
                    break
                chunks.append(d)
            mitm_resp = b''.join(chunks).decode()
        t.join(timeout=5)
        self.assertIn('200 OK', mitm_resp)
        self.assertNotIn('ads.badtracker.example/banner.js', mitm_resp)
        self.assertNotIn('/pagead/show_ads.js', mitm_resp)
        self.assertNotIn('aclib.runPop', mitm_resp)
        self.assertIn('id="zones-popup-blocker"', mitm_resp)
        self.assertIn('id="zones-adblock-css"', mitm_resp)
        self.assertIn('Real article content', mitm_resp)
        self.assertFalse(is_mitm_failed('127.0.0.1', '127.0.0.1'))

        # 7. Dynamic adaptive MITM fallback: if a client/app rejects the MITM TLS handshake (pinning or missing CA),
        #    the proxy automatically remembers (client_ip, host) and switches the next connection to direct CONNECT passthrough
        c_sock2, s_sock2 = socket.socketpair()
        t2 = threading.Thread(target=lambda: (serve_connection(s_sock2, ('10.0.0.99', 54322), srv_ns), s_sock2.close()), daemon=True)
        t2.start()
        c_sock2.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner2 = b''
        while b'\r\n\r\n' not in banner2:
            banner2 += c_sock2.recv(1024)
        self.assertIn(b'200 Connection Established', banner2)
        c_sock2.close()  # simulate client aborting TLS handshake immediately upon seeing MITM certificate
        t2.join(timeout=5)
        self.assertTrue(is_mitm_failed('10.0.0.99', '127.0.0.1'))

        # Next connection from 10.0.0.99 to 127.0.0.1 automatically uses direct CONNECT tunnel even with MITM=True
        up2_a, up2_b = socket.socketpair()
        def _echo_up2():
            data = up2_b.recv(1024)
            up2_b.sendall(b'AUTO-BYPASS:' + data)
            up2_b.close()
        threading.Thread(target=_echo_up2, daemon=True).start()
        c_sock3, s_sock3 = socket.socketpair()
        srv_ns2 = make_server_ns(tunnel_factory=lambda h, p: up2_a)
        t3 = threading.Thread(target=lambda: (serve_connection(s_sock3, ('10.0.0.99', 54323), srv_ns2), s_sock3.close()), daemon=True)
        t3.start()
        c_sock3.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner3 = c_sock3.recv(1024)
        self.assertIn(b'200 Connection Established', banner3)
        c_sock3.sendall(b'pinned-client')
        self.assertEqual(c_sock3.recv(1024), b'AUTO-BYPASS:pinned-client')
        c_sock3.close()
        t3.join(timeout=5)
        _mitm_failed.clear()

    def test_proxy_api_endpoints(self):
        user = get_user_model().objects.create_user('admin_p', password='x', is_staff=True)
        api = APIClient()
        api.force_authenticate(user)

        res = api.patch('/api/proxy/settings/', {
            'DHCP_WPAD': True,
            'PROXY': True,
            'PROXY_PORT': 8123,
            'PROXY_BLOCK_ADS': True,
            'PROXY_BLOCK_POPUPS': True,
            'PROXY_HTTPS_MITM': True,
        }, format='json')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()['PROXY'])
        self.assertEqual(res.json()['PROXY_PORT'], 8123)

        info = api.get('/api/proxy/info/').json()
        self.assertIn('BEGIN CERTIFICATE', info['pem'])
        self.assertIn('8123', info['pac'])

        t1 = api.post('/api/proxy/test/', {'url': 'https://sub.badtracker.example/script.js'}, format='json').json()
        self.assertTrue(t1['blocked'])
        self.assertEqual(t1['reason'], 'blacklist')

        t2 = api.post('/api/proxy/test/', {'url': 'https://example.org/index.html'}, format='json').json()
        self.assertFalse(t2['blocked'])

        ProxyLog.objects.create(
            client='192.168.1.50',
            method='CONNECT',
            host='ads.badtracker.example',
            url='https://ads.badtracker.example/',
            outcome='blocked',
            status=403,
            reason='blacklist: badtracker.example (personal)',
            ms=2,
        )
        ProxyLog.objects.create(
            client='192.168.1.50',
            method='MITM GET',
            host='news.example',
            url='https://news.example/index.html',
            outcome='filtered',
            status=200,
            reason='HTML filtered',
            ms=14,
        )
        logs_res = api.get('/api/proxy/logs/?outcome=blocked').json()
        self.assertEqual(logs_res['count'], 1)
        self.assertEqual(logs_res['blocked_count'], 1)
        self.assertEqual(logs_res['results'][0]['host'], 'ads.badtracker.example')
        self.assertIn('192.168.1.50', logs_res['clients'])

        purge_res = api.post('/api/proxy/logs/purge/', {'older_than_hours': 0}, format='json').json()
        self.assertEqual(purge_res['deleted'], 2)
        self.assertEqual(ProxyLog.objects.count(), 0)

    def test_cached_proxy_settings_avoids_per_request_db_queries(self):
        Setting.objects.update_or_create(key='dhcp:PROXY_PORT', defaults={'value': '8999'})
        DataVersion.bump()
        s1 = cached_proxy_settings(force=True)
        self.assertEqual(s1.PROXY_PORT, 8999)
        with self.assertNumQueries(0):
            s2 = cached_proxy_settings()
            self.assertIs(s1, s2)


class RuleListTests(TestCase):
    """External ad-block lists: reduced to domain and cosmetic rules, stored, applied by the filter."""
    LIST = '\n'.join([
        '[Adblock Plus 2.0]', '! comment', '||ads.example^', '||tracker.example^$third-party', '||only.example^$domain=a.com', '||cdn.example^$subdocument,third-party',
        '||pop.example^$popup', '@@||lib.example^$script', '||x.example/path^',
        '/banner/ad-*.gif', '@@||good.ads.example^', '##.ad-box', 'news.example##.promo', 'a.example#@#.ad-box', '##+js(abort)',
    ])

    def setUp(self):
        from .proxy import rules
        self.rules = rules
        rules.reset()
        self.addCleanup(rules.reset)

    def test_reduce_keeps_only_what_the_proxy_applies(self):
        text, counts = self.rules.reduce(self.LIST)
        self.assertEqual(text.splitlines(), ['||ads.example^', '||tracker.example^', '||pop.example^', '@@||lib.example^', '@@||good.ads.example^', '##.ad-box', 'news.example##.promo'])
        self.assertEqual(counts, {'blocks': 3, 'allow': 2, 'cosmetic': 2})  # cdn.example: only its frames, which the proxy cannot tell apart

    def test_sync_stores_and_filter_applies(self):
        self.rules.sync_all('easy=https://lists.example/easy.txt', fetcher=lambda url: self.LIST)
        self.assertEqual(Setting.objects.get(key='prl:easy').value.splitlines()[0], '||ads.example^')
        from .proxy import filter as pf
        self.assertEqual(pf.check_request('cdn.ads.example', 'http://cdn.ads.example/a.js')[0], 'rule-list')
        self.assertIsNone(pf.check_request('good.ads.example', 'http://good.ads.example/a.js'))
        self.assertIsNone(pf.check_request('fine.example', 'http://fine.example/'))
        html = pf.filter_html(b'<html><head></head><body></body></html>', 'text/html', host='news.example').decode()
        self.assertIn('.ad-box', html)
        self.assertIn('.promo', html)

    def test_failed_list_keeps_old_rules_and_removed_list_goes(self):
        self.rules.sync_all('a=https://l.example/a.txt b=https://l.example/b.txt', fetcher=lambda url: '||one.example^')

        def boom(url):
            raise OSError('down')
        out = self.rules.sync_all('a=https://l.example/a.txt', fetcher=boom)
        self.assertEqual(out[0]['error'], 'down')
        self.assertEqual(out[0]['blocks'], 1)
        self.assertTrue(Setting.objects.filter(key='prl:a').exists())
        self.assertFalse(Setting.objects.filter(key__in=('prl:b', 'prm:b')).exists())

    def test_entries(self):
        self.assertEqual(self.rules.split_entries('https://easylist.to/easylist/easylist.txt'), [('easylist.txt', 'https://easylist.to/easylist/easylist.txt')])
        with self.assertRaises(ValueError):
            self.rules.split_entries('ftp://x/y')

    def test_api(self):
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('admin_r', password='x', is_staff=True))
        self.assertEqual(api.patch('/api/proxy/settings/', {'PROXY_RULE_LISTS': 'ftp://x'}, format='json').status_code, 400)
        self.assertEqual(api.patch('/api/proxy/settings/', {'PROXY_RULE_LISTS': 'e=https://l.example/e.txt'}, format='json').status_code, 200)
        self.assertEqual(api.get('/api/proxy/rules/').json()[0]['updated'], None)
        from unittest import mock
        with mock.patch.object(self.rules, 'fetch', return_value='||ads.example^'):
            res = api.post('/api/proxy/rules/').json()
        self.assertEqual(res[0]['blocks'], 1)

    def test_import_blocklist_downloads_the_rule_lists(self):
        from unittest import mock
        from django.core.management import call_command
        Setting.objects.update_or_create(key='dhcp:PROXY_RULE_LISTS', defaults={'value': 'e=https://l.example/e.txt'})
        with mock.patch.object(self.rules, 'fetch', return_value='||ads.example^'), mock.patch('zones.management.commands.import_blocklist.settings') as st:
            st.BLOCKLISTS = []
            call_command('import_blocklist', stdout=__import__('io').StringIO())
        self.assertEqual(Setting.objects.get(key='prl:e').value, '||ads.example^')


class ProxyStatsTests(TestCase):
    def test_stats_join_dns_and_proxy(self):
        from .models import QueryLog
        for host, outcome, reason in [('ads.example', 'blocked', 'blacklist: ads.example (x)'), ('ads.example', 'blocked', 'rule-list: ads.example (easy)'),
                                      ('ok.example', 'allowed', 'text/html'), ('pg.example', 'filtered', 'html')]:
            ProxyLog.objects.create(client='192.168.1.9', method='GET', host=host, outcome=outcome, reason=reason)
        QueryLog.objects.create(client='192.168.1.9', name='ads.example', type='A', outcome='blocked', rcode='NOERROR', answers=[], ms=2)
        QueryLog.objects.create(client='192.168.1.8', name='x.example', type='A', outcome='forwarded', rcode='NOERROR', answers=[], ms=4)
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('admin_s', password='x', is_staff=True))
        both = api.get('/api/stats/?hours=1').json()
        self.assertEqual(both['total'], 6)
        self.assertEqual({c['name']: c['count'] for c in both['by_outcome']}, {'blocked': 3, 'forwarded': 1, 'proxied': 1, 'filtered': 1})
        self.assertEqual(both['top_blocked'][0], {'name': 'ads.example', 'count': 3})
        self.assertEqual(sum(b['count'] for b in both['series']), 6)
        self.assertEqual((sum(b['blocked'] for b in both['series']), sum(b['proxy_blocked'] for b in both['series'])), (1, 2))
        self.assertEqual(sum(b['proxy_count'] for b in both['series']), 4)
        dns = api.get('/api/stats/?hours=1&source=dns').json()
        self.assertEqual(dns['total'], 2)
        prx = api.get('/api/stats/?hours=1&source=proxy').json()
        self.assertEqual((prx['total'], {c['name']: c['count'] for c in prx['by_answer']}), (4, {'blocked': 2, 'proxied': 2}))
        self.assertEqual(api.get('/api/stats/?hours=1&source=zzz').json()['total'], 6)


class UpstreamPoolTests(TestCase):
    def test_a_kept_alive_upstream_connection_is_reused(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        seen = []

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                seen.append(self.client_address)
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=False, PROXY_BLOCK_POPUPS=False, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None,
        )
        req = f'GET http://127.0.0.1:{srv.server_port}/ HTTP/1.1\r\nHost: x\r\n\r\n'.encode()
        resp = _run_proxy_session(req + req[:-2] + b'Connection: close\r\n\r\n', ns)  # two requests on one client connection
        self.assertEqual(resp.count(b'200 OK'), 2)
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], seen[1])  # the same upstream connection: no second handshake


class UploadBodyTests(TestCase):
    def _post(self, raw):
        seen = {}

        def fetcher(scheme, host, port, method, path, body, headers):
            seen.update(body=body, headers=headers)
            return 200, 'OK', [('Content-Type', 'text/plain')], b'ok'

        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=True, PROXY_BLOCK_POPUPS=True, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, http_fetcher=fetcher, upstream_ssl_context=None,
        )
        return _run_proxy_session(raw, ns), seen

    def test_a_chunked_post_is_forwarded_whole(self):
        resp, seen = self._post(b'POST http://127.0.0.1/ews HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6;x=1\r\n world\r\n0\r\n\r\n')
        self.assertIn(b'200 OK', resp)
        self.assertEqual(seen['body'], b'hello world')

    def test_expect_100_continue_is_answered_and_not_forwarded(self):
        resp, seen = self._post(b'POST http://127.0.0.1/ews HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc')
        self.assertTrue(resp.startswith(b'HTTP/1.0 100') or resp.startswith(b'HTTP/1.1 100'))
        self.assertEqual(seen['body'], b'abc')
        self.assertNotIn('expect', {k.lower() for k in seen['headers']})


class StreamingTests(TestCase):
    def test_a_chunked_json_response_is_relayed_without_buffering_the_whole_body(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                for part in (b'{"a":', b'1}'):
                    self.wfile.write(f'{len(part):x}\r\n'.encode() + part + b'\r\n')
                self.wfile.write(b'0\r\n\r\n')

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=False, PROXY_BLOCK_POPUPS=False, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None,
        )
        resp = _run_proxy_session(f'GET http://127.0.0.1:{srv.server_port}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'.encode(), ns)
        self.assertIn(b'200 OK', resp)
        head, _, body = resp.partition(b'\r\n\r\n')
        self.assertIn(b'Transfer-Encoding: chunked', head)  # no Content-Length from the server: chunked to an HTTP/1.1 client
        self.assertEqual(_dechunk(body), b'{"a":1}')


class RfcAndSecurityTests(TestCase):
    """Request smuggling, framing, CONNECT ports, headers a proxy must add or drop, logs without secrets, bounded decompression, the CA key."""

    def _session(self, raw, response=None, cfg=None):
        seen = {}

        def fetcher(scheme, host, port, method, path, body, headers):
            seen.update(body=body, headers=headers)
            return response or (200, 'OK', [('Content-Type', 'text/plain'), ('Date', 'Tue, 17 Nov 2026 10:00:00 GMT')], b'ok')

        ns = SimpleNamespace(
            settings_getter=lambda: cfg or SimpleNamespace(PROXY_BLOCK_ADS=True, PROXY_BLOCK_POPUPS=True, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, http_fetcher=fetcher, upstream_ssl_context=None, tunnel_factory=None,
        )
        return _run_proxy_session(raw, ns), seen

    def test_chunked_body_with_a_content_length_is_not_smuggled(self):
        data = b'x=1GET /smuggled HTTP/1.1\r\nHost: victim\r\n\r\n'
        resp, seen = self._session(b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\nConnection: close\r\n\r\n'
                                   + f'{len(data):x}'.encode() + b'\r\n' + data + b'\r\n0\r\n\r\n')
        self.assertIn(b'200 OK', resp)
        self.assertEqual(seen['body'], data)
        self.assertEqual(seen['headers']['Content-Length'], str(len(data)))  # the length of what is sent, not the client's 3

    def test_bad_framing_is_refused(self):
        for raw in (
            b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n-1\r\nabc\r\n0\r\n\r\n',
            b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0x3\r\nabc\r\n0\r\n\r\n',
            b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n0\r\n\r\n',
            b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd',
            b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nContent-Length: -3\r\nConnection: close\r\n\r\n',
        ):
            resp, seen = self._session(raw)
            self.assertRegex(resp.split(b'\r\n', 1)[0], rb' (400|501) ', raw)  # 501: a transfer coding it does not know (RFC 9112 6.1)
            self.assertEqual(seen, {})

    def test_a_large_body_is_streamed_not_held(self):
        from unittest import mock
        from .proxy import server as ps
        with mock.patch.object(ps, 'MAX_BUFFERED_BODY', 4):
            resp, seen = self._session(b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789')
            self.assertEqual(seen['body'], b'0123456789')
            self.assertEqual(seen['headers']['Content-Length'], '10')
            resp, seen = self._session(b'POST http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n')
            self.assertEqual(seen['body'], b'abcdef')
            self.assertNotIn('Content-Length', seen['headers'])
            self.assertEqual(seen['headers']['Transfer-Encoding'], 'chunked')

    def test_headers_a_proxy_adds_and_drops(self):
        resp, seen = self._session(b'GET http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nConnection: close, X-Hop\r\nX-Hop: secret\r\nX-Keep: 1\r\n\r\n')
        self.assertNotIn('X-Hop', seen['headers'])  # listed in Connection: hop-by-hop (RFC 9110 7.6.1)
        self.assertEqual(seen['headers']['X-Keep'], '1')
        self.assertEqual(seen['headers']['Via'], '1.1 zones-dns')
        head = resp.split(b'\r\n\r\n', 1)[0]
        self.assertEqual(head.count(b'\r\nDate:'), 1)  # the upstream's, not a second one of ours
        self.assertNotIn(b'BaseHTTP', head)
        self.assertIn(b'\r\nVia: 1.1 zones-dns', head)

    def test_options_with_max_forwards_zero_is_answered_by_the_proxy(self):
        resp, seen = self._session(b'OPTIONS http://127.0.0.1/a HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\nConnection: close\r\n\r\n')
        self.assertIn(b'200 OK', resp)
        self.assertIn(b'Allow:', resp)
        self.assertEqual(seen, {})

    def test_connect_only_to_allowed_ports(self):
        with override_settings(PROXY_CONNECT_PORTS='443'):
            resp, _ = self._session(b'CONNECT mail.example:25 HTTP/1.1\r\nHost: mail.example:25\r\n\r\n')
        self.assertIn(b'403', resp.split(b'\r\n', 1)[0])

    def test_the_server_itself_only_on_web_ports(self):
        from .proxy import server as ps
        with self.assertRaises(PermissionError):
            ps._resolve_target('192.168.1.23', 5432, own_ips=frozenset({'192.168.1.23'}))
        self.assertEqual(ps._resolve_target('192.168.1.23', 443, own_ips=frozenset({'192.168.1.23'}))[0][1], ('192.168.1.23', 443))

    def test_the_log_keeps_no_query_values(self):
        from .proxy.server import _redact_url
        self.assertEqual(_redact_url('https://a.example/cb?code=SECRET&state=x&flag'), 'https://a.example/cb?code=…&state=…&flag=…')
        self.assertEqual(_redact_url('https://a.example/p'), 'https://a.example/p')

    def test_decompression_is_bounded(self):
        from .proxy import server as ps
        bomb = gzip.compress(b'\0' * (ps.MAX_HTML_BYTES + 10))
        with self.assertRaises(ValueError):
            ps._decompress(bomb, 'gzip')
        self.assertEqual(ps._decompress(gzip.compress(b'<p>x</p>'), 'gzip'), b'<p>x</p>')

    def test_content_security_policy_is_respected(self):
        self.assertTrue(pfilter.csp_allows_inline('', 'script-src'))
        self.assertTrue(pfilter.csp_allows_inline("img-src 'self'", 'script-src'))
        self.assertTrue(pfilter.csp_allows_inline("script-src 'self' 'unsafe-inline'", 'script-src'))
        self.assertFalse(pfilter.csp_allows_inline("default-src 'self'", 'script-src'))
        self.assertFalse(pfilter.csp_allows_inline("script-src 'unsafe-inline' 'nonce-abc'", 'script-src'))
        self.assertFalse(pfilter.csp_allows_inline("script-src *, script-src 'self'", 'script-src'))
        html = pfilter.filter_html(b'<html><head></head><body></body></html>', 'text/html', host='news.example', csp="script-src 'self'").decode()
        self.assertNotIn('zones-popup-blocker', html)
        self.assertIn('zones-adblock-css', html)

    def test_a_page_in_another_charset_is_not_damaged(self):
        raw = '<html><head><meta charset="windows-1252"></head><body>caffè perché</body></html>'.encode('cp1252')
        out = pfilter.filter_html(raw, 'text/html', host='news.example')
        self.assertIn('caffè perché'.encode('cp1252'), out)

    def test_two_empty_mitm_sessions_switch_to_a_tunnel(self):
        from .proxy import server as ps
        ps._mitm_strikes.clear()
        _mitm_failed.clear()
        self.assertFalse(ps.note_empty_mitm_session('10.0.0.5', 'app.example'))  # a preconnect that was never used
        self.assertFalse(is_mitm_failed('10.0.0.5', 'app.example'))
        self.assertTrue(ps.note_empty_mitm_session('10.0.0.5', 'app.example'))
        self.assertTrue(is_mitm_failed('10.0.0.5', 'app.example'))
        _mitm_failed.clear()

    def test_a_data_change_keeps_the_tunnel_fallback_a_new_root_ca_forgets_it(self):
        from .proxy import server as ps
        ca.ensure_ca()
        ps._mitm_gen()
        ps.record_mitm_failure('10.0.0.8', 'pinned.example')
        DataVersion.bump()  # a DNS record, a blocklist import...
        cached_proxy_settings(force=True)
        self.assertTrue(is_mitm_failed('10.0.0.8', 'pinned.example'))
        ca.ensure_ca(regenerate=True)  # devices may trust the new one: try inspecting again
        self.assertFalse(is_mitm_failed('10.0.0.8', 'pinned.example'))

    @override_settings(REDIS_URL='redis://unused')
    def test_with_redis_the_worker_processes_share_the_tunnel_fallback(self):
        from django.core.cache import cache
        from .proxy import server as ps
        cache.clear()
        ps._mitm_strikes.clear()
        _mitm_failed.clear()
        self.assertFalse(ps.note_empty_mitm_session('10.0.0.6', 'citrix.example'))  # one launch, on one worker
        ps._mitm_strikes.clear()  # the next launch lands on another worker: nothing of the first in its memory
        self.assertTrue(ps.note_empty_mitm_session('10.0.0.6', 'citrix.example'))
        _mitm_failed.clear()  # a third worker
        self.assertTrue(is_mitm_failed('10.0.0.6', 'citrix.example'))
        self.assertFalse(is_mitm_failed('10.0.0.7', 'citrix.example'))  # per device
        _mitm_failed.clear()
        cache.clear()

    def test_the_ca_key_is_stored_encrypted_and_never_shown(self):
        from cryptography.hazmat.primitives import serialization
        ca.ensure_ca(regenerate=True)
        stored = Setting.objects.get(key=ca.CA_PRIV_KEY).value
        self.assertIn('ENCRYPTED', stored)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(stored.encode(), password=None)
        # a key stored in clear by an older version is read and encrypted
        key = ca._cached_ca[3]
        Setting.objects.filter(key=ca.CA_PRIV_KEY).update(value=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        ca._cached_ca = None
        fp = ca.ca_info()['fingerprint']
        self.assertIn('ENCRYPTED', Setting.objects.get(key=ca.CA_PRIV_KEY).value)
        self.assertEqual(ca.ca_info()['fingerprint'], fp)
        admin_user = get_user_model().objects.create_superuser('root', password='x')
        from .admin.setting import SettingAdmin
        from django.contrib import admin as dj_admin
        from django.test import RequestFactory
        req = RequestFactory().get('/')
        req.user = admin_user
        qs = SettingAdmin(Setting, dj_admin.site).get_queryset(req)
        self.assertFalse(qs.filter(key=ca.CA_PRIV_KEY).exists())

    def test_root_ca_and_profile_only_over_https(self):
        with override_settings(GUI_URL='https://dns.example/'):
            r = self.client.get('/proxy-ca.crt', HTTP_HOST='wpad.example')
            self.assertEqual((r.status_code, r['Location']), (302, 'https://dns.example/proxy-ca.crt'))
            r = self.client.get('/proxy.mobileconfig', HTTP_HOST='wpad.example')
            self.assertEqual(r['Location'], 'https://dns.example/proxy.mobileconfig')
            self.assertEqual(self.client.get('/wpad.dat', HTTP_HOST='wpad.example').status_code, 200)  # OS WPAD clients: plain http


class ProxyWorkersTests(TestCase):
    def test_workers_listen_on_one_port(self):
        import asyncio
        from .proxy.server import ProxyServer

        async def run():
            a = await ProxyServer(('127.0.0.1', 0), reuse_port=True).start()
            port = a._srv.sockets[0].getsockname()[1]
            b = await ProxyServer(('127.0.0.1', port), reuse_port=True).start()  # the second worker binds the same port
            a.close()
            b.close()
        asyncio.run(run())

    def test_the_supervisor_starts_a_crashed_worker_again_and_stops_with_the_first_clean_exit(self):
        from unittest import mock
        from .management.commands import runproxy

        class Proc:
            def __init__(self, rcs):
                self.rcs, self.terminated = list(rcs), False

            def poll(self):
                return self.rcs.pop(0) if len(self.rcs) > 1 else self.rcs[0]

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                pass
        procs = [Proc([None]), Proc([1]), Proc([None, 0]), Proc([None])]  # worker 1 crashes, comes back, and then exits with 0
        cmd = runproxy.Command()
        with mock.patch.object(runproxy.subprocess, 'Popen', side_effect=procs) as popen, \
                mock.patch.object(runproxy.signal, 'signal'), mock.patch.object(runproxy.time, 'sleep'), \
                mock.patch.object(runproxy.sys, 'argv', ['manage.py', 'runproxy']):
            with self.assertRaises(SystemExit) as stop:
                cmd.supervise(2)
        self.assertEqual(stop.exception.code, 0)
        self.assertEqual(popen.call_count, 3)  # two workers and one start again
        self.assertEqual(popen.call_args_list[1].args[0][-2:], ['--worker', '1'])
        self.assertTrue(procs[0].terminated)  # the others stop with it


class NoPostRetryTests(TestCase):
    def test_a_post_is_never_sent_twice(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        posts = []

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):
                posts.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.close_connection = True  # the server dies before it answers: the mail may have been sent

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=False, PROXY_BLOCK_POPUPS=False, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None,
        )
        resp = _run_proxy_session(f'POST http://127.0.0.1:{srv.server_port}/send HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc'.encode(), ns)
        self.assertIn(b'502', resp.split(b'\r\n', 1)[0])
        self.assertEqual(posts, [b'abc'])  # once: a proxy must not repeat a POST (RFC 9110 9.2.2)

    def test_a_stream_that_breaks_says_who_it_was_waiting_for(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('Content-Length', '100000')
                self.end_headers()
                self.wfile.write(b'x' * 1000)
                self.wfile.flush()
                self.close_connection = True  # the server goes away in the middle of the body

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        entries = []
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=False, PROXY_BLOCK_POPUPS=False, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None, log=SimpleNamespace(add=entries.append),
        )
        _run_proxy_session(f'GET http://127.0.0.1:{srv.server_port}/p.jpg HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode(), ns)
        failed = [e for e in entries if e.outcome == 'error']
        self.assertEqual(len(failed), 1)
        self.assertIn('Upstream failed while streaming', failed[0].reason)
        self.assertIn('(after 1000 bytes, waiting for the server)', failed[0].reason)

    def test_a_full_http2_connection_makes_the_request_wait_not_fail(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest import mock
        import httpcore

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=False, PROXY_BLOCK_POPUPS=False, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None,
        )
        real, calls = httpcore.AsyncConnectionPool.stream, []

        def full_twice(self, *a, **k):
            calls.append(1)
            if len(calls) < 3:
                raise httpcore.LocalProtocolError('Max outbound streams is 100, 100 open')  # h2 refuses before sending anything
            return real(self, *a, **k)

        with mock.patch.object(httpcore.AsyncConnectionPool, 'stream', full_twice):
            resp = _run_proxy_session(f'POST http://127.0.0.1:{srv.server_port}/x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc'.encode(), ns)
        self.assertIn(b'200', resp.split(b'\r\n', 1)[0])
        self.assertEqual(len(calls), 3)

    def test_a_real_html_page_is_filtered_and_framed(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        page = b'<html><head><title>t</title></head><body>' + b'x' * 5000 + b'</body></html>'

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                assert self.headers['Accept-Encoding'] == 'gzip, deflate' and self.headers['Via'] == '1.1 zones-dns'
                body = gzip.compress(page)
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        ns = SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=True, PROXY_BLOCK_POPUPS=True, PROXY_HTTPS_MITM=False, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=None,
        )
        resp = _run_proxy_session(f'GET http://127.0.0.1:{srv.server_port}/ HTTP/1.1\r\nHost: x\r\nAccept-Encoding: br\r\nConnection: close\r\n\r\n'.encode(), ns)
        head, _, body = resp.partition(b'\r\n\r\n')
        self.assertIn(b'zones-popup-blocker', body)
        self.assertIn(f'Content-Length: {len(body)}'.encode(), head)
        self.assertNotIn(b'Content-Encoding', head)


class RevocationAndProfileTests(TestCase):
    """Upstream certificates checked for revocation (CRL, OCSP), the signed Apple profile, a CSP in <meta>, bounded br."""

    def setUp(self):
        from .proxy import revocation
        self.rv = revocation
        revocation.reset()
        self.addCleanup(revocation.reset)

    def _pki(self, crl_url=None, ocsp_url=None):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
        now = datetime.now(timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')])
        ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
                   .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'site.example')])).issuer_name(ca_name)
             .public_key(ec.generate_private_key(ec.SECP256R1()).public_key()).serial_number(4242)
             .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30)))
        if crl_url:
            b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]), critical=False)
        if ocsp_url:
            b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))]), critical=False)
        return ca_key, ca_cert, b.sign(ca_key, hashes.SHA256())

    def _crl(self, ca_key, ca_cert, serials):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        now = datetime.now(timezone.utc)
        b = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(now).next_update(now + timedelta(days=1))
        for sn in serials:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(sn).revocation_date(now).build())
        return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_a_certificate_on_the_crl_is_refused_from_the_next_connection(self):
        from unittest import mock
        from cryptography.hazmat.primitives import serialization
        ca_key, ca_cert, leaf = self._pki(crl_url='http://crl.test/ca.crl')
        chain = [c.public_bytes(serialization.Encoding.DER) for c in (leaf, ca_cert)]
        with mock.patch.object(self.rv, 'fetch', return_value=self._crl(ca_key, ca_cert, [4242])) as f, \
                mock.patch.object(self.rv._pool, 'submit', side_effect=lambda fn, *a: fn(*a)):
            self.assertFalse(self.rv.is_revoked(chain))  # the first connection does not wait
            self.assertTrue(self.rv.is_revoked(chain))
            self.assertEqual(f.call_count, 1)  # the CRL is kept until its nextUpdate

    @override_settings(REDIS_URL='redis://unused')
    def test_with_redis_one_answer_serves_every_worker(self):
        from unittest import mock
        from django.core.cache import cache
        cache.clear()
        self.addCleanup(cache.clear)
        ca_key, ca_cert, leaf = self._pki(crl_url='http://crl.test/ca.crl')
        with mock.patch.object(self.rv, 'fetch', return_value=self._crl(ca_key, ca_cert, [4242])) as f:
            self.assertTrue(self.rv.lookup(leaf, ca_cert))
            self.rv.reset()  # another worker process: no CRL and no answer in its memory
            self.assertTrue(self.rv.lookup(leaf, ca_cert))
            self.assertEqual(f.call_count, 1)

    def test_a_good_certificate_and_a_crl_signed_by_someone_else(self):
        from unittest import mock
        ca_key, ca_cert, leaf = self._pki(crl_url='http://crl.test/ca.crl')
        with mock.patch.object(self.rv, 'fetch', return_value=self._crl(ca_key, ca_cert, [1])):
            self.assertFalse(self.rv.lookup(leaf, ca_cert))
        self.rv.reset()
        other_key, _, _ = self._pki()
        with mock.patch.object(self.rv, 'fetch', return_value=self._crl(other_key, ca_cert, [4242])):
            self.assertIsNone(self.rv.lookup(leaf, ca_cert))  # forged list: ignored, soft-fail

    def test_ocsp_when_there_is_no_crl(self):
        from datetime import datetime, timedelta, timezone
        from unittest import mock
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp
        ca_key, ca_cert, leaf = self._pki(ocsp_url='http://ocsp.test/')
        now = datetime.now(timezone.utc)
        resp = (ocsp.OCSPResponseBuilder()
                .add_response(cert=leaf, issuer=ca_cert, algorithm=hashes.SHA1(), cert_status=ocsp.OCSPCertStatus.REVOKED, this_update=now,
                              next_update=now + timedelta(hours=1), revocation_time=now, revocation_reason=None)
                .responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert).sign(ca_key, hashes.SHA256()))
        with mock.patch.object(self.rv, 'fetch', return_value=resp.public_bytes(serialization.Encoding.DER)):
            self.assertTrue(self.rv.lookup(leaf, ca_cert))
        self.rv.reset()
        with mock.patch.object(self.rv, 'fetch', side_effect=OSError('down')):
            self.assertIsNone(self.rv.lookup(leaf, ca_cert))

    def test_the_profile_is_signed_when_a_certificate_is_given(self):
        import os
        import tempfile
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs7
        from .proxy import pac
        ca_key, ca_cert, _ = self._pki()
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.remove(os.path.join(d, n)) for n in os.listdir(d)] and os.rmdir(d))
        cert_path, key_path = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
        with open(cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as f:
            f.write(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        s = SimpleNamespace(DHCP_SERVER='192.168.1.2', PROXY_PORT=8080, DHCP_WPAD_URL='')
        with override_settings(PROFILE_SIGN_CERT=cert_path, PROFILE_SIGN_KEY=key_path):
            signed = pac.build_mobileconfig(s)
        self.assertEqual(pkcs7.load_der_pkcs7_certificates(signed)[0], ca_cert)
        self.assertIn(b'ProxyAutoConfigURLString', signed)  # the profile is inside the signature
        with override_settings(PROFILE_SIGN_CERT=cert_path, PROFILE_SIGN_KEY=os.path.join(d, 'missing')):
            self.assertTrue(pac.build_mobileconfig(s).startswith(b'<?xml'))  # unsigned rather than no profile

    def test_a_csp_in_a_meta_tag_is_respected(self):
        page = b'<html><head><meta http-equiv="Content-Security-Policy" content="script-src &#39;self&#39;"></head><body></body></html>'
        html = pfilter.filter_html(page, 'text/html', host='news.example').decode()
        self.assertNotIn('zones-popup-blocker', html)
        self.assertIn('zones-adblock-css', html)

    def test_br_is_decompressed_with_a_limit(self):
        import brotli
        from .proxy import server as ps
        self.assertEqual(ps._decompress(brotli.compress(b'<p>x</p>'), 'br'), b'<p>x</p>')
        with self.assertRaises(ValueError):
            ps._decompress(brotli.compress(b'\0' * (ps.MAX_HTML_BYTES + 10)), 'br')


class Http2Tests(TestCase):
    """HTTP/2 both ways: a browser that chooses h2 inside a MITM session, and an upstream server that speaks h2."""

    def setUp(self):
        # nothing written in the test's transaction to the tables the proxy's threads read (SQLite in memory locks them)
        if ca._cached_ca is None:
            ca._cached_ca = ca._generate_ca()
            ca._leaf_contexts.clear()
        _mitm_failed.clear()

    def _ns(self, mitm=True, fetcher=_fake_fetcher, ctx=None):
        return SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=True, PROXY_BLOCK_POPUPS=True, PROXY_HTTPS_MITM=mitm, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, http_fetcher=fetcher, upstream_ssl_context=ctx, tunnel_factory=None,
        )

    def test_a_browser_speaking_h2_inside_mitm(self):
        import h2.config
        import h2.connection
        import h2.events
        ca_pem = ca.ensure_ca()[0]
        ctx = ssl.create_default_context(cadata=ca_pem)
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        c_sock, s_sock = socket.socketpair()
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 50001), self._ns()), s_sock.close()), daemon=True)
        t.start()
        c_sock.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner = b''
        while b'\r\n\r\n' not in banner:
            banner += c_sock.recv(1024)
        self.assertIn(b'200 Connection Established', banner)
        tls = ctx.wrap_socket(c_sock, server_hostname='127.0.0.1')
        self.assertEqual(tls.selected_alpn_protocol(), 'h2')
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
        conn.initiate_connection()
        req = [(':method', 'GET'), (':scheme', 'https'), (':authority', '127.0.0.1'), (':path', '/article')]
        conn.send_headers(1, req, end_stream=True)
        conn.send_headers(3, [*req[:3], (':path', '/gzip-page')], end_stream=True)  # two streams on one connection
        conn.send_headers(5, [(':method', 'GET'), (':scheme', 'https'), (':authority', '127.0.0.1'), (':path', '/x.js'),
                              ('sec-fetch-dest', 'script')], end_stream=True)
        tls.sendall(conn.data_to_send())
        status, bodies, ended = {}, {1: b'', 3: b'', 5: b''}, set()
        tls.settimeout(10)
        while len(ended) < 3:
            data = tls.recv(65536)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    status[ev.stream_id] = dict(ev.headers)
                elif isinstance(ev, h2.events.DataReceived):
                    bodies[ev.stream_id] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    ended.add(ev.stream_id)
            tls.sendall(conn.data_to_send())
        tls.close()
        t.join(timeout=5)
        self.assertEqual(status[1][':status'], '200')
        self.assertNotIn('connection', status[1])  # connection-specific fields are not allowed in HTTP/2
        self.assertIn(b'Real article content', bodies[1])
        self.assertIn(b'zones-popup-blocker', bodies[1])
        self.assertNotIn(b'aclib.runPop', bodies[1])
        self.assertIn(b'<h1>Hello</h1>', bodies[3])
        self.assertEqual(int(status[3]['content-length']), len(bodies[3]))
        self.assertFalse(is_mitm_failed('127.0.0.1', '127.0.0.1'))

    def test_an_upstream_server_speaking_h2(self):
        import h2.config
        import h2.connection
        import h2.events
        ca_pem = ca.ensure_ca()[0]
        server_ctx = ca.leaf_context('localhost')  # a certificate of the proxy CA, offering h2
        lst = socket.socket()
        lst.bind(('127.0.0.1', 0))
        lst.listen()
        port = lst.getsockname()[1]
        seen = {}

        def h2_server():
            raw, _ = lst.accept()
            tls = server_ctx.wrap_socket(raw, server_side=True)
            seen['alpn'] = tls.selected_alpn_protocol()
            conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding='utf-8'))
            conn.initiate_connection()
            tls.sendall(conn.data_to_send())
            done = False
            while not done:
                data = tls.recv(65536)
                if not data:
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        seen['headers'] = dict(ev.headers)
                        conn.send_headers(ev.stream_id, [(':status', '200'), ('content-type', 'application/json')])
                        conn.send_data(ev.stream_id, b'{"h2":true}', end_stream=True)
                        done = True
                tls.sendall(conn.data_to_send())
            tls.close()
            lst.close()

        threading.Thread(target=h2_server, daemon=True).start()
        ns = self._ns(mitm=False, fetcher=None, ctx=ssl.create_default_context(cadata=ca_pem))
        del ns.http_fetcher
        resp = _run_proxy_session(f'GET https://localhost:{port}/api HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n'.encode(), ns)
        self.assertEqual(seen['alpn'], 'h2')
        self.assertEqual(seen['headers'][':authority'], f'localhost:{port}')
        self.assertEqual(seen['headers']['via'], '1.1 zones-dns')
        head, _, body = resp.partition(b'\r\n\r\n')
        self.assertIn(b'HTTP/1.1 200 OK', head)  # an h2 answer has no reason phrase: the standard one is used
        self.assertIn(b'{"h2":true}', body)

    def test_h2_flow_control_both_ways(self):
        import h2.config
        import h2.connection
        import h2.events
        upload, answer = b'u' * 200_000, b'a' * 300_000  # both larger than the 64 KB initial window
        seen = {}

        def fetcher(scheme, host, port, method, path, body, headers):
            seen['body'] = body
            return 200, 'OK', [('Content-Type', 'application/octet-stream')], answer

        ctx = ssl.create_default_context(cadata=ca.ensure_ca()[0])
        ctx.set_alpn_protocols(['h2'])
        c_sock, s_sock = socket.socketpair()
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 50002), self._ns(fetcher=fetcher)), s_sock.close()), daemon=True)
        t.start()
        c_sock.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
        banner = b''
        while b'\r\n\r\n' not in banner:
            banner += c_sock.recv(1024)
        tls = ctx.wrap_socket(c_sock, server_hostname='127.0.0.1')
        tls.settimeout(10)
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
        conn.initiate_connection()
        conn.send_headers(1, [(':method', 'POST'), (':scheme', 'https'), (':authority', '127.0.0.1'), (':path', '/up'),
                              ('content-length', str(len(upload)))])
        tls.sendall(conn.data_to_send())
        left, got, ended = memoryview(upload), b'', False
        while not ended:
            while left and (w := min(conn.local_flow_control_window(1), conn.max_outbound_frame_size)) > 0:
                n = min(w, len(left))
                conn.send_data(1, bytes(left[:n]), end_stream=n == len(left))
                left = left[n:]
            tls.sendall(conn.data_to_send())
            data = tls.recv(65536)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.DataReceived):
                    got += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    ended = True
            tls.sendall(conn.data_to_send())
        tls.close()
        t.join(timeout=5)
        self.assertEqual(seen['body'], upload)
        self.assertEqual(got, answer)


class UploadAndWebSocketTests(TestCase):
    """A refused large upload reaches the client as the server's answer; WebSockets through the inspected session, HTTP/1.1 and HTTP/2."""

    def setUp(self):
        if ca._cached_ca is None:
            ca._cached_ca = ca._generate_ca()
            ca._leaf_contexts.clear()
        _mitm_failed.clear()

    def _ns(self, mitm=False, ctx=None):
        return SimpleNamespace(
            settings_getter=lambda: SimpleNamespace(PROXY_BLOCK_ADS=True, PROXY_BLOCK_POPUPS=True, PROXY_HTTPS_MITM=mitm, PROXY_CUSTOM_RULES='', DHCP_SERVER='', DHCP_WPAD=False),
            allow_loopback=True, upstream_ssl_context=ctx, tunnel_factory=None,
        )

    def _server(self, handle, tls=False):
        lst = socket.socket()
        lst.bind(('127.0.0.1', 0))
        lst.listen()
        self.addCleanup(lst.close)

        def run():
            while True:
                try:
                    raw, _ = lst.accept()
                except OSError:
                    return
                sock = ca.leaf_context('localhost').wrap_socket(raw, server_side=True) if tls else raw
                threading.Thread(target=handle, args=(sock,), daemon=True).start()
        threading.Thread(target=run, daemon=True).start()
        return lst.getsockname()[1]

    def test_a_refused_upload_gets_the_servers_answer(self):
        got = {}

        def handle(sock):
            head = b''
            while b'\r\n\r\n' not in head:
                head += sock.recv(4096)
            got['head'] = head
            sock.sendall(b'HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo big!')
            sock.close()  # without reading the body

        port = self._server(handle)
        body = b'x' * 5_000_000
        c_sock, s_sock = socket.socketpair()
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 50004), self._ns()), s_sock.close()), daemon=True)
        t.start()

        def send():  # like a real client: it goes on sending while the answer arrives
            try:
                c_sock.sendall(f'POST http://127.0.0.1:{port}/up HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
            except OSError:
                pass
        threading.Thread(target=send, daemon=True).start()
        c_sock.settimeout(10)
        resp = b''
        while b'too big!' not in resp:
            data = c_sock.recv(65536)
            if not data:
                break
            resp += data
        c_sock.close()
        t.join(timeout=10)
        self.assertIn(b'413 Payload Too Large', resp.split(b'\r\n', 1)[0])
        self.assertTrue(resp.endswith(b'too big!'))
        self.assertIn(b'expect: 100-continue', got['head'].lower())

    def test_a_large_upload_goes_whole_after_100_continue(self):
        import hashlib
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):  # BaseHTTPRequestHandler answers 100 Continue by itself
                digest = hashlib.sha256(self.rfile.read(int(self.headers['Content-Length']))).hexdigest().encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(digest)))
                self.end_headers()
                self.wfile.write(digest)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        body = os_urandom(3_000_000)
        resp = _run_proxy_session(f'POST http://127.0.0.1:{srv.server_port}/up HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body, self._ns())
        self.assertTrue(resp.endswith(hashlib.sha256(body).hexdigest().encode()))

    def _ws_server(self):
        import base64
        import hashlib

        def handle(sock):
            head = b''
            while b'\r\n\r\n' not in head:
                head += sock.recv(4096)
            lines = head.decode().split('\r\n')
            hdrs = {k.lower(): v for k, _, v in (ln.partition(': ') for ln in lines[1:] if ln)}
            assert hdrs['upgrade'].lower() == 'websocket', hdrs
            accept = base64.b64encode(hashlib.sha1((hdrs['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            sock.sendall(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n'.encode())
            while data := sock.recv(4096):
                sock.sendall(b'echo:' + data)
            sock.close()
        return self._server(handle, tls=True)

    def _mitm(self, port, alpn):
        ctx = ssl.create_default_context(cadata=ca.ensure_ca()[0])
        ctx.set_alpn_protocols(alpn)
        c_sock, s_sock = socket.socketpair()
        ns = self._ns(mitm=True, ctx=ssl.create_default_context(cadata=ca.ensure_ca()[0]))
        t = threading.Thread(target=lambda: (serve_connection(s_sock, ('127.0.0.1', 50003), ns), s_sock.close()), daemon=True)
        t.start()
        c_sock.sendall(f'CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n'.encode())
        banner = b''
        while b'\r\n\r\n' not in banner:
            banner += c_sock.recv(1024)
        self.assertIn(b'200 Connection Established', banner)
        tls = ctx.wrap_socket(c_sock, server_hostname='localhost')
        tls.settimeout(10)
        return tls, t

    @override_settings(PROXY_CONNECT_PORTS='*')
    def test_a_websocket_inside_mitm_over_http1(self):
        port = self._ws_server()
        tls, t = self._mitm(port, ['http/1.1'])
        tls.sendall(f'GET /ws HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
        head = b''
        while b'\r\n\r\n' not in head:
            head += tls.recv(4096)
        self.assertIn(b'101 Switching Protocols', head)
        self.assertIn(b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=', head)  # the client's own key reached the server
        tls.sendall(b'ping')
        self.assertEqual(tls.recv(4096), b'echo:ping')
        tls.close()
        t.join(timeout=5)
        self.assertFalse(is_mitm_failed('127.0.0.1', 'localhost'))  # no fallback to a plain tunnel any more

    @override_settings(PROXY_CONNECT_PORTS='*')
    def test_a_websocket_over_http2_rfc8441(self):
        import h2.config
        import h2.connection
        import h2.events
        import h2.settings
        port = self._ws_server()
        tls, t = self._mitm(port, ['h2'])
        self.assertEqual(tls.selected_alpn_protocol(), 'h2')
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
        conn.initiate_connection()
        tls.sendall(conn.data_to_send())
        enabled = False
        while not enabled:
            for ev in conn.receive_data(tls.recv(65536)):
                if isinstance(ev, h2.events.RemoteSettingsChanged) and h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL in ev.changed_settings:
                    enabled = ev.changed_settings[h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL].new_value == 1
            tls.sendall(conn.data_to_send())
        conn.send_headers(1, [(':method', 'CONNECT'), (':protocol', 'websocket'), (':scheme', 'https'), (':path', '/ws'),
                              (':authority', f'localhost:{port}'), ('sec-websocket-version', '13')])
        tls.sendall(conn.data_to_send())
        status, echoed = None, b''
        while not echoed:
            for ev in conn.receive_data(tls.recv(65536)):
                if isinstance(ev, h2.events.ResponseReceived):
                    status = dict(ev.headers)[':status']
                    conn.send_data(1, b'ping')
                elif isinstance(ev, h2.events.DataReceived):
                    echoed += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, 1)
            tls.sendall(conn.data_to_send())
        self.assertEqual(status, '200')
        self.assertEqual(echoed, b'echo:ping')
        tls.close()
        t.join(timeout=5)

    def test_worker_threads_hold_no_database_connection(self):
        from django.db import connection
        from .proxy import server as ps
        BlockedDomain.objects.create(name='ads.example', source='manual', enabled=True)

        def work():
            pfilter.check_request('www.ads.example', 'https://www.ads.example/x.js')
            pfilter.filter_html(b'<html><head></head></html>', 'text/html', host='news.example')
            return connection.connection is None  # this thread never opened its own

        self.assertTrue(ps._WORK.submit(work).result(timeout=10))


def os_urandom(n):
    import os
    return os.urandom(n)


class LingerTests(TestCase):
    def test_nothing_is_written_after_the_sending_side_is_closed(self):
        import asyncio
        from .proxy.streams import RawStream

        async def main():
            a, b = socket.socketpair()
            r, w = await asyncio.open_connection(sock=a)
            stream = RawStream(r, w)
            stream.write_eof()
            await stream.write(b'close_notify')  # was: RuntimeError: Cannot call write() after write_eof()
            await stream.aclose()
            b.close()
        asyncio.run(main())


class CancelOpenStreamTests(TestCase):
    def test_a_response_given_up_resets_its_http2_stream_so_it_stops_counting(self):
        import h2.config, h2.connection
        from types import SimpleNamespace
        from .proxy import upstream
        h2c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        h2c.initiate_connection()
        h2c.send_headers(1, [(':method', 'GET'), (':scheme', 'https'), (':authority', 'x'), (':path', '/')], end_stream=True)
        h2c.data_to_send()
        sent = []

        async def write(request):
            sent.append(h2c.data_to_send())
        conn = SimpleNamespace(_h2_state=h2c, _write_outgoing_data=write)
        resp = SimpleNamespace(stream=SimpleNamespace(_connection=conn, _stream_id=1, _request=None))
        self.assertTrue(h2c.streams[1].open)
        asyncio.run(upstream.cancel_open_stream(resp))
        self.assertFalse(h2c.streams[1].open)
        self.assertEqual(h2c.open_outbound_streams, 0)
        self.assertTrue(sent and sent[0])  # the RST_STREAM went out
        asyncio.run(upstream.cancel_open_stream(resp))  # again, or not HTTP/2 at all: nothing happens
        asyncio.run(upstream.cancel_open_stream(SimpleNamespace(stream=object())))

    def test_unread_data_of_a_given_up_response_goes_back_to_the_connection_window(self):
        import h2.config, h2.connection, h2.events
        from types import SimpleNamespace
        from .proxy import upstream
        cli = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        srv = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        cli.initiate_connection()
        srv.initiate_connection()
        got = []

        def pump():
            for _ in range(4):
                if a := cli.data_to_send():
                    srv.receive_data(a)
                if b := srv.data_to_send():
                    got.extend(cli.receive_data(b))
        pump()
        for sid in (1, 3):  # 3: the server already ended it, nobody read it
            cli.send_headers(sid, [(':method', 'GET'), (':scheme', 'https'), (':authority', 'x'), (':path', '/')], end_stream=True)
        pump()
        srv.send_headers(1, [(':status', '200')])
        srv.send_headers(3, [(':status', '200')])
        srv.send_data(1, b'v' * 16000)
        srv.send_data(1, b'v' * 16000)
        srv.send_data(3, b'i' * 16000, end_stream=True)
        pump()
        self.assertEqual(srv.outbound_flow_control_window, 65535 - 48000)
        events = {sid: [e for e in got if getattr(e, 'stream_id', None) == sid] for sid in (1, 3)}

        async def write(request):
            srv.receive_data(cli.data_to_send())
        conn = SimpleNamespace(_h2_state=cli, _write_outgoing_data=write, _events=events)
        for sid in (1, 3):
            asyncio.run(upstream.cancel_open_stream(SimpleNamespace(stream=SimpleNamespace(_connection=conn, _stream_id=sid, _request=None))))
        self.assertEqual(srv.outbound_flow_control_window, 65535)  # was: 17535 for good, until every stream of the connection stalled
        self.assertEqual(events, {1: [], 3: []})

    def test_a_paused_response_leaves_room_on_the_connection_for_the_others(self):
        import h2.config, h2.connection
        import httpcore
        from httpcore._async.http2 import AsyncHTTP2Connection
        from .proxy import upstream  # noqa: F401 -- importing it patches the windows of AsyncHTTP2Connection

        class Net(httpcore.AsyncNetworkStream):
            async def write(self, data, timeout=None):
                srv.receive_data(data)

            async def read(self, n, timeout=None):
                return srv.data_to_send()
        srv = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        srv.initiate_connection()
        conn = AsyncHTTP2Connection(httpcore.Origin(b'https', b'x', 443), Net())

        async def main():
            req = httpcore.Request('GET', 'https://x/', headers=[(b'Host', b'x')])
            await conn._send_connection_init(req)
            for sid in (1, 3):
                conn._h2_state.get_next_available_stream_id()
                await conn._send_request_headers(req, sid)
        asyncio.run(main())
        srv.send_headers(1, [(':status', '200')])
        while srv.local_flow_control_window(1) > 0:  # stream 1: a video nobody reads any more
            srv.send_data(1, b'v' * min(16384, srv.local_flow_control_window(1)))
        self.assertEqual(srv.local_flow_control_window(1), 0)
        self.assertGreater(srv.outbound_flow_control_window, 2**27)  # the connection: plenty left
        self.assertGreater(srv.local_flow_control_window(3), 2**20)  # stream 3 can still be sent: was 0, the 16 MB were gone


class PopupGuardTests(TestCase):
    """The injected popup guard, run in Node with a stand-in window: a blank window and sign-in popups open, ad URLs do not."""

    def test_blank_and_sign_in_windows_open_ad_urls_do_not(self):
        import json
        import re
        import shutil
        import subprocess
        import unittest
        node = shutil.which('node')
        if not node:
            raise unittest.SkipTest('node is not installed')
        js = re.search(r'<script id="zones-popup-blocker">(.*)</script>', pfilter.POPUP_BLOCKER_JS, re.S)[1]
        harness = (
            'var opened=[];var window={open:function(u){opened.push(String(u||""));return {};},addEventListener:function(){}};'
            'var document={currentScript:null,addEventListener:function(){}};var console={debug:function(){}};'
            + js +
            ';var r=["","about:blank","https://www.facebook.com/dialog/oauth?display=popup","https://pop.example/popunder.php"]'
            '.map(function(u){return window.open(u)!==null;});'
            'process.stdout.write(JSON.stringify({r:r,intercom:typeof window.Intercom,gtm:typeof window.google_tag_manager}));'
        )
        out = json.loads(subprocess.run([node, '-e', harness], capture_output=True, text=True, timeout=20, check=True).stdout)
        self.assertEqual(out['r'], [True, True, True, False])
        self.assertEqual((out['intercom'], out['gtm']), ('undefined', 'undefined'))  # a site's own Intercom or GTM still loads


class MemoryWatchTests(TestCase):
    """The worker's memory line, and the exit once it is over the limit (the Pi's kernel has no memory cgroup for MemoryMax)."""

    def watch(self, server, readings):
        """Run memwatch.watch over `readings`, (loop time, RSS) pairs ending over the limit: the lines and the exit code."""
        import tracemalloc
        from unittest import mock
        from .proxy import memwatch
        lines, readings, clock = [], iter(readings), {'t': 0.0}

        class Exited(Exception):
            pass

        def exit_(code):
            raise Exited(code)

        def rss():
            clock['t'], r = next(readings)
            return r

        async def run():
            asyncio.get_running_loop().time = lambda: clock['t']
            with mock.patch.object(memwatch, 'EVERY', 0), mock.patch.object(memwatch, 'rss', rss), \
                    mock.patch.object(memwatch.os, '_exit', exit_):
                await memwatch.watch(server, lines.append)
        try:
            with self.assertRaises(Exited) as e:
                asyncio.run(run())
        finally:
            tracemalloc.stop()
        return lines, e.exception.args[0]

    def test_the_report_counts_clients_upstream_connections_and_unread_data(self):
        import h2.events
        from .proxy import memwatch
        data = h2.events.DataReceived(stream_id=1)
        data.data = b'x' * 2**20
        h2conn = SimpleNamespace(_events={1: [data, h2.events.StreamEnded(stream_id=1)], 3: []})  # only the data counts
        server = SimpleNamespace(_total=3, _per_client={'10.0.0.2': 1, '10.0.0.1': 2},
                                 _upstream_pool=SimpleNamespace(connections=[SimpleNamespace(_connection=h2conn), SimpleNamespace()]))

        async def run():
            return memwatch.report(server, 300 * 2**20)
        line = asyncio.run(run())
        self.assertIn(': 300 MB, 3 client connections (10.0.0.1 2, 10.0.0.2 1), 2 upstream connections, 2 HTTP/2 streams holding 1.0 MB unread', line)

    def test_lines_come_every_15_minutes_then_every_minute_or_100_mb_and_the_worker_exits_over_the_limit(self):
        from .proxy import memwatch
        MB, BIG = 2**20, memwatch.BIG
        server = SimpleNamespace(_total=0, _per_client={}, _upstream_pool=None)
        lines, code = self.watch(server, [
            (0, 100 * MB),              # first reading: a line
            (10, 100 * MB),             # small, 10 s later: none
            (900, 100 * MB),            # 15 minutes later: a line
            (910, BIG),                 # big: tracing starts, a line without allocations yet
            (920, BIG + 10 * MB),       # 10 s and 10 MB later: none
            (930, BIG + memwatch.STEP), # 100 MB more: a line
            (995, BIG + memwatch.STEP), # a minute later: a line
            (1000, 100 * MB),           # small again: tracing stops, no line
            (1010, memwatch.LIMIT),     # over the limit: tracing starts anew, a line, the exit
        ])
        self.assertEqual([line.split(': ', 1)[1].split(' MB')[0] for line in lines[:-1]],
                         ['100', '100', str(BIG // MB), str((BIG + memwatch.STEP) // MB), str((BIG + memwatch.STEP) // MB), str(memwatch.LIMIT // MB)])
        held = ['held since tracing started: ' in line for line in lines[:-1]]
        self.assertEqual(held, [False, False, False, True, True, False])  # the last: tracing was stopped below BIG and started again
        self.assertIn('MB limit: exiting', lines[-1])
        self.assertNotEqual(code, 0)  # 0 would tell the supervisor the proxy was switched off: it would stop every worker

    def test_a_report_that_fails_does_not_stop_the_watch(self):
        from .proxy import memwatch
        lines, code = self.watch(SimpleNamespace(), [(0, 100 * 2**20), (10, memwatch.LIMIT)])  # no _per_client: report() raises
        self.assertIn('memory report failed', lines[0])
        self.assertIn('MB limit: exiting', lines[-1])
