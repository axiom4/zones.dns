"""Multi-threaded HTTP and HTTPS ad/popup-filtering forward proxy server."""
import gzip
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import select
import socket
from socketserver import ThreadingMixIn
import ssl
import threading
import time
from urllib.parse import urlsplit
import zlib

from django.conf import settings
from django.db import DatabaseError, connections

from ..dhcp import v4 as dhcp
from ..dnsd import ratelimit
from ..models import DataVersion
from . import ca, filter as pfilter, pac

_cfg_lock = threading.Lock()
_cfg_data = None
_cfg_checked = 0.0
_cfg_version = None
_CFG_CHECK_INTERVAL = 1.0


def cached_proxy_settings(base=None, force=False):
    """Return cached `dhcp_settings` in memory, checking `DataVersion` at most once per second so proxy worker threads do not query the DB per request."""
    global _cfg_data, _cfg_checked, _cfg_version
    now = time.monotonic()
    if not force and _cfg_data is not None and (now - _cfg_checked) < _CFG_CHECK_INTERVAL:
        return _cfg_data
    if _cfg_lock.acquire(blocking=(_cfg_data is None or force)):
        try:
            now = time.monotonic()
            if not force and _cfg_data is not None and (now - _cfg_checked) < _CFG_CHECK_INTERVAL:
                return _cfg_data
            _cfg_checked = now
            try:
                ver = DataVersion.version()
                if force or _cfg_data is None or ver != _cfg_version:
                    _cfg_data = dhcp.dhcp_settings(base or settings)
                    _cfg_version = ver
            except DatabaseError:
                if _cfg_data is None:
                    b = base or settings
                    ns = type('DhcpSettings', (), {'DNS_DDR': getattr(b, 'DNS_DDR', '')})()
                    for name, _ in dhcp.DHCP_SETTING_SPEC:
                        setattr(ns, name, getattr(b, name))
                    _cfg_data = ns
        finally:
            _cfg_lock.release()
    return _cfg_data

HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailers', 'transfer-encoding', 'upgrade',
})

TRANSPARENT_GIF = (
    b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!'
    b'\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
)
MAX_HTML_BYTES = 8 * 1024 * 1024  # 8 MB cap for in-memory HTML filtering


def _is_forbidden_target_ip(ip_str, allow_loopback=False):
    """Prevent SSRF to loopback, link-local, multicast or unspecified addresses through the proxy."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.is_Loopback if hasattr(ip, 'is_Loopback') else ip.is_loopback:
        return not allow_loopback
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified


def _resolve_target(host, port, allow_loopback=False):
    """Resolve `host` and verify none of its addresses are forbidden internal/loopback targets."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f'Cannot resolve {host}')
    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        if _is_forbidden_target_ip(ip_str, allow_loopback=allow_loopback):
            raise PermissionError(f'Target address {ip_str} is not allowed through the proxy')
    return infos[0][0], infos[0][4][:2]


def _decompress(data, encoding):
    enc = (encoding or '').strip().lower()
    if enc == 'gzip' or enc == 'x-gzip':
        return gzip.decompress(data)
    if enc == 'deflate':
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -zlib.MAX_WBITS)
    return data


class ProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_threads = 256

    def __init__(self, server_address, RequestHandlerClass=None, settings_getter=None, allow_loopback=False, upstream_ssl_context=None):
        if ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        self.settings_getter = settings_getter or cached_proxy_settings
        self.allow_loopback = allow_loopback
        self.upstream_ssl_context = upstream_ssl_context
        self._thread_sem = threading.BoundedSemaphore(self.max_threads)
        super().__init__(server_address, RequestHandlerClass or ProxyHandler)

    def process_request(self, request, client_address):
        if not self._thread_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._thread_sem.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            connections.close_all()
            self._thread_sem.release()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 30

    def log_message(self, fmt, *args):
        pass  # keep stdout quiet per request unless debugging

    def _cfg(self):
        return self.server.settings_getter()

    def _client_allowed(self):
        client_ip = self.client_address[0]
        return ratelimit.allowed(client_ip)

    def _send_bytes(self, status_code, content_type, body, extra_headers=None):
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD' and body:
            self.wfile.write(body)
        self.close_connection = True

    def _send_blocked(self, reason, detail, path=''):
        header_val = f'Zones.dns ({reason}: {detail})'
        low_path = (path or '').lower().partition('?')[0]
        accept = (self.headers.get('Accept') or '').lower()
        if low_path.endswith('.js') or 'javascript' in accept:
            self._send_bytes(200, 'application/javascript; charset=utf-8', b'/* blocked by Zones.dns */\n', {'X-Blocked-By': header_val})
        elif low_path.endswith(('.gif', '.png', '.jpg', '.jpeg', '.webp', '.ico')) or accept.startswith('image/'):
            self._send_bytes(200, 'image/gif', TRANSPARENT_GIF, {'X-Blocked-By': header_val})
        else:
            body = f'<!doctype html><title>Blocked</title><!-- blocked by {header_val} -->'.encode()
            self._send_bytes(403, 'text/html; charset=utf-8', body, {'X-Blocked-By': header_val})

    def _handle_local(self, s):
        """Serve /wpad.dat, /proxy.pac, /ca.crt (/ca.pem) and /proxy.mobileconfig when requested directly from the proxy port."""
        path = self.path.partition('?')[0]
        if path in ('/wpad.dat', '/proxy.pac'):
            body = pac.build_pac(s, request_host=self.headers.get('Host', '')).encode('utf-8')
            self._send_bytes(200, 'application/x-ns-proxy-autoconfig; charset=utf-8', body, {'Cache-Control': 'no-cache'})
            return True
        if path in ('/ca.crt', '/ca.pem'):
            cert_pem, _, _, _ = ca.ensure_ca()
            self._send_bytes(
                200,
                'application/x-x509-ca-cert',
                cert_pem.encode('utf-8'),
                {'Content-Disposition': 'attachment; filename="zones-proxy-ca.crt"'},
            )
            return True
        if path == '/proxy.mobileconfig':
            cert_pem, _, _, _ = ca.ensure_ca()
            body = pac.build_mobileconfig(s, ca_cert_pem=cert_pem, request_host=self.headers.get('Host', ''))
            self._send_bytes(
                200,
                'application/x-apple-aspen-config',
                body,
                {'Content-Disposition': 'attachment; filename="zones-proxy.mobileconfig"'},
            )
            return True
        return False

    def _proxy_http(self, scheme=None, default_host=None, default_port=None):
        if not self._client_allowed():
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden')
            return
        s = self._cfg()
        if self.path.startswith('/') and scheme is None:
            if self._handle_local(s):
                return
            host_hdr = self.headers.get('Host', '')
            if not host_hdr:
                self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad Request')
                return
            full_url = f'http://{host_hdr}{self.path}'
        elif self.path.startswith(('http://', 'https://')):
            full_url = self.path
        elif scheme and default_host:
            port_part = f':{default_port}' if default_port and default_port not in (80, 443) else ''
            full_url = f'{scheme}://{default_host}{port_part}{self.path}'
        else:
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad Request')
            return

        parts = urlsplit(full_url)
        target_scheme = (parts.scheme or scheme or 'http').lower()
        host = (parts.hostname or default_host or '').lower()
        port = parts.port or default_port or (443 if target_scheme == 'https' else 80)
        path_query = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')

        if not host:
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Missing target host')
            return

        try:
            hit = pfilter.check_request(host, full_url, s=s)
        finally:
            connections.close_all()
        if hit:
            self._send_blocked(hit[0], hit[1], path=parts.path)
            return

        try:
            _resolve_target(host, port, allow_loopback=self.server.allow_loopback)
        except PermissionError:
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden target address')
            return
        except OSError:
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway: DNS lookup failed')
            return

        content_len = int(self.headers.get('Content-Length', '0') or 0)
        req_body = self.rfile.read(content_len) if content_len > 0 else None

        fwd_headers = {}
        for k, v in self.headers.items():
            if k.lower() not in HOP_BY_HOP:
                fwd_headers[k] = v
        fwd_headers['Host'] = f'{host}:{port}' if port not in (80, 443) else host
        if getattr(s, 'PROXY_BLOCK_ADS', True) or getattr(s, 'PROXY_BLOCK_POPUPS', True):
            fwd_headers['Accept-Encoding'] = 'gzip, deflate'

        conn = None
        try:
            fetcher = getattr(self.server, 'http_fetcher', None)
            if fetcher is not None:
                status_code, reason, resp_headers, raw_body = fetcher(target_scheme, host, port, self.command, path_query, req_body, fwd_headers)
                ctype = dict((k.lower(), v) for k, v in resp_headers).get('content-type', '')
                cenc = dict((k.lower(), v) for k, v in resp_headers).get('content-encoding', '')
                out_headers = [
                    (k, v) for k, v in resp_headers
                    if k.lower() not in HOP_BY_HOP and k.lower() not in ('content-length', 'content-encoding')
                ]
            else:
                if target_scheme == 'https':
                    ctx = self.server.upstream_ssl_context or ssl.create_default_context()
                    conn = HTTPSConnection(host, port, timeout=20, context=ctx)
                else:
                    conn = HTTPConnection(host, port, timeout=20)
                conn.request(self.command, path_query, body=req_body, headers=fwd_headers)
                resp = conn.getresponse()
                raw_body = resp.read()
                status_code, reason = resp.status, resp.reason
                ctype = resp.getheader('Content-Type', '') or ''
                cenc = resp.getheader('Content-Encoding', '') or ''
                out_headers = [
                    (k, v) for k, v in resp.getheaders()
                    if k.lower() not in HOP_BY_HOP and k.lower() not in ('content-length', 'content-encoding')
                ]
        except Exception:
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway')
            return
        finally:
            if conn:
                conn.close()

        if self.command != 'HEAD' and 'text/html' in ctype.lower() and len(raw_body) <= MAX_HTML_BYTES:
            try:
                plain = _decompress(raw_body, cenc)
                raw_body = pfilter.filter_html(plain, content_type=ctype, host=host, s=s)
                cenc = ''
            except Exception:
                pass
            finally:
                connections.close_all()

        self.send_response(status_code, reason)
        for k, v in out_headers:
            self.send_header(k, v)
        if cenc:
            self.send_header('Content-Encoding', cenc)
        self.send_header('Content-Length', str(len(raw_body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and raw_body:
            self.wfile.write(raw_body)
        self.close_connection = True

    def do_GET(self):
        self._proxy_http()

    def do_POST(self):
        self._proxy_http()

    def do_PUT(self):
        self._proxy_http()

    def do_DELETE(self):
        self._proxy_http()

    def do_HEAD(self):
        self._proxy_http()

    def do_OPTIONS(self):
        self._proxy_http()

    def do_PATCH(self):
        self._proxy_http()

    def do_CONNECT(self):
        if not self._client_allowed():
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden')
            return
        s = self._cfg()
        host_port = self.path.strip()
        if host_port.startswith('[') and ']' in host_port:
            host = host_port[1:host_port.index(']')].lower()
            rest = host_port[host_port.index(']') + 1:]
            port = int(rest[1:]) if rest.startswith(':') and rest[1:].isdigit() else 443
        else:
            h, _, p = host_port.rpartition(':')
            if h and p.isdigit():
                host, port = h.lower(), int(p)
            else:
                host, port = host_port.lower(), 443

        try:
            hit = pfilter.check_request(host, f'https://{host}:{port}/', s=s)
        finally:
            connections.close_all()
        if hit:
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Blocked by Zones.dns', {'X-Blocked-By': f'Zones.dns ({hit[0]}: {hit[1]})'})
            return

        try:
            family, addr = _resolve_target(host, port, allow_loopback=self.server.allow_loopback)
        except PermissionError:
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden target address')
            return
        except OSError:
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway: DNS lookup failed')
            return

        allow_domains, _, _, _ = pfilter.parse_custom_rules(getattr(s, 'PROXY_CUSTOM_RULES', ''))
        use_mitm = bool(getattr(s, 'PROXY_HTTPS_MITM', False)) and not pfilter.is_domain_allowed(host, allow_domains)

        if use_mitm:
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self.wfile.flush()
            try:
                ctx = ca.leaf_context(host)
                with ctx.wrap_socket(self.connection, server_side=True) as tls_client:
                    mitm_handler = _MitmHandler(tls_client, self.client_address, self.server, host=host, port=port)
                    mitm_handler.handle_one_request()
                    try:
                        tls_client.unwrap()
                    except Exception:
                        pass
            except Exception:
                pass
            self.close_connection = True
            return

        try:
            tunnel_factory = getattr(self.server, 'tunnel_factory', None)
            if tunnel_factory is not None:
                upstream = tunnel_factory(host, port)
            else:
                upstream = socket.socket(family, socket.SOCK_STREAM)
                upstream.settimeout(15)
                upstream.connect(addr)
        except OSError:
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway')
            return

        try:
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self.wfile.flush()
            self._tunnel(self.connection, upstream)
        finally:
            upstream.close()
            self.close_connection = True

    @staticmethod
    def _tunnel(client_sock, upstream_sock):
        sockets = [client_sock, upstream_sock]
        client_sock.setblocking(False)
        upstream_sock.setblocking(False)
        while True:
            r, _, e = select.select(sockets, [], sockets, 30)
            if e or not r:
                break
            for sock in r:
                other = upstream_sock if sock is client_sock else client_sock
                try:
                    data = sock.recv(32768)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return


class _MitmHandler(ProxyHandler):
    """Handles decrypted HTTP/1.1 requests inside an HTTPS MITM tunnel."""

    def __init__(self, connection, client_address, server, host, port):
        self._mitm_host = host
        self._mitm_port = port
        self.request = connection
        self.connection = connection
        self.client_address = client_address
        self.server = server
        self.setup()

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline or len(self.raw_requestline) > 65536:
                return
            if not self.parse_request():
                return
            self._proxy_http(scheme='https', default_host=self._mitm_host, default_port=self._mitm_port)
            self.wfile.flush()
        except Exception:
            pass
        finally:
            self.finish()
