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
from .models import BlockedDomain, DataVersion, Setting
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
            self.assertIn('PROXY 192.168.1.2:8888; DIRECT', text)
            self.assertIn('.corp.lan', text)
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

        res = api.patch('/api/dhcp/settings/', {
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

        info = api.get('/api/dhcp/proxy/info/').json()
        self.assertIn('BEGIN CERTIFICATE', info['pem'])
        self.assertIn('8123', info['pac'])

        t1 = api.post('/api/dhcp/proxy/test/', {'url': 'https://sub.badtracker.example/script.js'}, format='json').json()
        self.assertTrue(t1['blocked'])
        self.assertEqual(t1['reason'], 'blacklist')

        t2 = api.post('/api/dhcp/proxy/test/', {'url': 'https://example.org/index.html'}, format='json').json()
        self.assertFalse(t2['blocked'])

    def test_cached_proxy_settings_avoids_per_request_db_queries(self):
        Setting.objects.update_or_create(key='dhcp:PROXY_PORT', defaults={'value': '8999'})
        DataVersion.bump()
        s1 = cached_proxy_settings(force=True)
        self.assertEqual(s1.PROXY_PORT, 8999)
        with self.assertNumQueries(0):
            s2 = cached_proxy_settings()
            self.assertIs(s1, s2)
