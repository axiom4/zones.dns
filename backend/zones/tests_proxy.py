"""Tests for the HTTP/HTTPS ad-blocking & popup-blocking proxy, DHCP WPAD (option 252 + DNS wpad.<domain>), PAC generation, and HTTPS MITM."""
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
from .proxy.server import ProxyHandler, _mitm_failed, cached_proxy_settings, is_mitm_failed


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


def _run_proxy_session(raw_bytes, server_ns):
    """Run one ProxyHandler connection over a socketpair and return the raw response bytes."""
    client_sock, server_sock = socket.socketpair()
    t = threading.Thread(target=lambda: (ProxyHandler(server_sock, ('127.0.0.1', 54321), server_ns), server_sock.close()), daemon=True)
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
        resp = _run_proxy_session(b'GET http://ads.badtracker.example/page.html HTTP/1.1\r\nHost: ads.badtracker.example\r\n\r\n', make_server_ns())
        self.assertIn(b'403 Forbidden', resp)
        self.assertIn(b'X-Blocked-By: Zones.dns (blacklist:', resp)

        # 3. HTTP request to allowed page decompresses gzip, strips ads/popups, and injects CSS & popup blocker
        resp = _run_proxy_session(b'GET http://127.0.0.1/gzip-page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n', make_server_ns())
        text = resp.decode()
        self.assertIn('200 OK', text)
        self.assertNotIn('ads.badtracker.example', text)
        self.assertNotIn('openPopunder', text)
        self.assertIn('id="zones-popup-blocker"', text)
        self.assertIn('id="zones-adblock-css"', text)
        self.assertIn('<h1>Hello</h1>', text)

        # 3b. Upstream Brotli/Zstd response or lowercase accept-encoding is never corrupted into replacement chars
        resp_br = _run_proxy_session(
            b'GET http://127.0.0.1/br-page HTTP/1.1\r\nHost: 127.0.0.1\r\naccept-encoding: gzip, deflate, br, zstd\r\n\r\n',
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
        t = threading.Thread(target=lambda: (ProxyHandler(s_sock, ('127.0.0.1', 54321), srv_ns), s_sock.close()), daemon=True)
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
        t = threading.Thread(target=lambda: (ProxyHandler(s_sock, ('127.0.0.1', 54321), srv_ns), s_sock.close()), daemon=True)
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
        t2 = threading.Thread(target=lambda: (ProxyHandler(s_sock2, ('10.0.0.99', 54322), srv_ns), s_sock2.close()), daemon=True)
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
        t3 = threading.Thread(target=lambda: (ProxyHandler(s_sock3, ('10.0.0.99', 54323), srv_ns2), s_sock3.close()), daemon=True)
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
        '[Adblock Plus 2.0]', '! comment', '||ads.example^', '||tracker.example^$third-party', '||only.example^$domain=a.com', '||x.example/path^',
        '/banner/ad-*.gif', '@@||good.ads.example^', '##.ad-box', 'news.example##.promo', 'a.example#@#.ad-box', '##+js(abort)',
    ])

    def setUp(self):
        from .proxy import rules
        self.rules = rules
        rules.reset()
        self.addCleanup(rules.reset)

    def test_reduce_keeps_only_what_the_proxy_applies(self):
        text, counts = self.rules.reduce(self.LIST)
        self.assertEqual(text.splitlines(), ['||ads.example^', '||tracker.example^', '@@||good.ads.example^', '##.ad-box', 'news.example##.promo'])
        self.assertEqual(counts, {'blocks': 2, 'allow': 1, 'cosmetic': 2})

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
    def test_a_kept_alive_connection_is_reused_and_a_stale_one_is_dropped(self):
        from http.client import HTTPConnection
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from .proxy import server as ps

        class H(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *a):
                pass

        srv = HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        key = ('http', 'x', srv.server_port, '127.0.0.1')
        conn = HTTPConnection('127.0.0.1', srv.server_port)
        conn.request('GET', '/')
        resp = conn.getresponse()
        resp.read()
        ps._pool_give(key, conn)
        self.assertIs(ps._pool_take(key), conn)  # same connection, no new handshake
        self.assertIsNone(ps._pool_take(key))
        ps._pool_give(key, conn)
        with ps._pool_lock:
            ps._pool[key][0] = (conn, 0)  # idle for longer than _POOL_IDLE
        self.assertIsNone(ps._pool_take(key))


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
        self.assertTrue(resp.endswith(b'{"a":1}'))  # no Content-Length: the body ends with the connection
        self.assertNotIn(b'Transfer-Encoding', resp)
