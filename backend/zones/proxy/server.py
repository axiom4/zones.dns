"""Multi-threaded HTTP and HTTPS ad/popup-filtering forward proxy server."""
from collections import OrderedDict
import gzip
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import queue
import select
import socket
from socketserver import ThreadingMixIn
import ssl
import threading
import time
from urllib.parse import urlsplit
import zlib

from django.conf import settings
from django.db import DatabaseError, close_old_connections, connections
from dnslib import DNSRecord, QTYPE

from ..dhcp import v4 as dhcp
from ..dnsd import ratelimit, resolver
from ..models import DataVersion, ProxyLog
from . import ca, filter as pfilter, pac

_cfg_lock = threading.Lock()
_cfg_data = None
_cfg_checked = 0.0
_cfg_version = None
_CFG_CHECK_INTERVAL = 1.0

_dns_lock = threading.Lock()
_dns_cache = OrderedDict()  # (host, allow_loopback) -> (expires_at, family, ip_str) or (expires_at, None, None) for negative cache
_dns_inflight = {}  # (host, allow_loopback) -> threading.Lock (singleflight deduplication for concurrent lookups of the same host)
_DNS_TTL = 600.0
_DNS_NEG_TTL = 120.0
_DNS_MAX = 8192

_proxy_resolver = None
_proxy_resolver_lock = threading.Lock()


def _get_proxy_resolver():
    global _proxy_resolver
    if _proxy_resolver is None:
        with _proxy_resolver_lock:
            if _proxy_resolver is None:
                _proxy_resolver = resolver.Resolver(settings.UPSTREAM_DNS, log=None)
    return _proxy_resolver


def _resolve_hostname_direct(clean_host):
    """Resolve `clean_host` in-process via `zones.dnsd.resolver` (internal zones, static hosts, shared Redis cache, and UPSTREAM_DNS)
    without calling `socket.getaddrinfo()`, so the proxy never sends loopback DNS queries from 127.0.0.1 to rundns."""
    if clean_host == 'localhost':
        return [(socket.AF_INET, '127.0.0.1')]
    try:
        if resolver._data is None or (time.monotonic() - resolver._data_checked) >= 1.0:
            pfilter.run_on_db_pool(resolver._snapshot)
        sh = resolver.static_hosts(clean_host)
        if sh:
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip) for ip, _ in sh]
        loc = resolver.lookup(clean_host, 'A')
        if loc:
            recs, _ = loc
            ips = [(socket.AF_INET, r.value) for r in recs if r.type == 'A']
            if ips:
                return ips
    except Exception:
        pass
    res = _get_proxy_resolver()
    for qtype, fam, rtype in (('A', socket.AF_INET, QTYPE.A), ('AAAA', socket.AF_INET6, QTYPE.AAAA)):
        reply, _ = res.forward(DNSRecord.question(clean_host, qtype))
        ips = [(fam, str(rr.rdata)) for rr in reply.rr if rr.rtype == rtype]
        if ips:
            return ips
    return []

_mitm_lock = threading.Lock()
_mitm_failed = OrderedDict()  # (client_ip, host) -> expires_at (auto-fallback to CONNECT tunnel when a client/app rejects MITM TLS)
_MITM_FAIL_TTL = 1800.0
_MITM_FAIL_MAX = 8192


def is_mitm_failed(client_ip, host):
    """True when `(client_ip, host)` recently failed a MITM TLS handshake (e.g. certificate pinning or missing CA on client)."""
    key = (client_ip, host)
    now = time.monotonic()
    with _mitm_lock:
        exp = _mitm_failed.get(key)
        if exp is None:
            return False
        if exp > now:
            _mitm_failed.move_to_end(key)
            return True
        del _mitm_failed[key]
        return False


def record_mitm_failure(client_ip, host):
    """Remember that `(client_ip, host)` rejected the MITM certificate so subsequent connections use direct CONNECT passthrough."""
    key = (client_ip, host)
    with _mitm_lock:
        _mitm_failed[key] = time.monotonic() + _MITM_FAIL_TTL
        if len(_mitm_failed) > _MITM_FAIL_MAX:
            _mitm_failed.popitem(last=False)


class _ResolvedHTTPSConnection(HTTPSConnection):
    """HTTPSConnection that connects to an already-resolved IP address (avoiding a second getaddrinfo call) while preserving SNI/hostname verification."""

    def __init__(self, host, port, resolved_addr, family=socket.AF_INET, **kwargs):
        super().__init__(host, port, **kwargs)
        self._resolved_addr = resolved_addr
        self._family = family

    def connect(self):
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        _set_nodelay(sock)
        sock.settimeout(self.timeout)
        sock.connect(self._resolved_addr)
        server_hostname = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


_default_ssl_context = ssl.create_default_context()  # building one loads the CA store (tens of ms): once, not per request

_pool_lock = threading.Lock()
_pool = {}  # (scheme, host, port, ip) -> [(conn, idle_since)]: kept-alive upstream connections, the TCP+TLS handshake is most of a request's time
_POOL_IDLE = 20.0  # most servers close an idle connection after 30-60 s; a stale one is retried on a new connection anyway
_POOL_PER_KEY = 4


def _pool_take(key):
    now = time.monotonic()
    with _pool_lock:
        lst = _pool.get(key)
        while lst:
            conn, since = lst.pop()
            if now - since < _POOL_IDLE:
                return conn
            conn.close()
    return None


def _pool_give(key, conn):
    with _pool_lock:
        lst = _pool.setdefault(key, [])
        if len(lst) < _POOL_PER_KEY:
            lst.append((conn, time.monotonic()))
            return
    conn.close()
    # shortcut: idle connections are dropped only when the same key is used again, no sweeper; add one if the number of hosts grows


def _open_upstream(scheme, host, port, family, addr, ctx):
    if scheme == 'https':
        return _ResolvedHTTPSConnection(host, port, resolved_addr=addr, family=family, timeout=20, context=ctx)
    return HTTPConnection(addr[0], addr[1], timeout=20)


def _set_nodelay(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def _load_cfg_from_db(base, force, prev_ver):
    ver = DataVersion.version()
    if force or prev_ver is None or ver != prev_ver:
        return ver, dhcp.dhcp_settings(base)
    return ver, None


def cached_proxy_settings(base=None, force=False):
    """Return cached `dhcp_settings` in memory, checking `DataVersion` at most once per second on the persistent DB worker pool."""
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
                ver, fresh = pfilter.run_on_db_pool(_load_cfg_from_db, base or settings, force or _cfg_data is None, _cfg_version)
                if fresh is not None:
                    _cfg_data = fresh
                    with _mitm_lock:
                        _mitm_failed.clear()
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
SURROGATE_JS = (
    b'/* blocked by Zones.dns */\n'
    b'(function(w){'
    b'var noop=function(){};'
    b'w.adsbygoogle=w.adsbygoogle||{loaded:true,push:noop};'
    b'w.ga=w.ga||noop;w.gtag=w.gtag||noop;w.dataLayer=w.dataLayer||[];'
    b'w.google_tag_manager=w.google_tag_manager||{};'
    b'w.Intercom=w.Intercom||function(){(w.Intercom.q=w.Intercom.q||[]).push(arguments);};'
    b'w.Intercom.booted=true;'
    b'w.Appcues=w.Appcues||{identify:noop,page:noop,track:noop,on:noop,anonymous:noop,reset:noop,debug:noop};'
    b'w._hsq=w._hsq||[];w.fbq=w.fbq||noop;w.lintrk=w.lintrk||noop;'
    b'})(typeof window!=="undefined"?window:this);\n'
)
SURROGATE_JSON = b'{"integrations":{"Segment.io":{}},"plan":{},"status":"ok"}'
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
    """Resolve `host` (with a 5-minute in-memory cache, IPv4-first to avoid duplicate A+AAAA queries) and check SSRF rules."""
    clean_host = host.strip('[]')
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        ip_str = str(ip_obj)
        if _is_forbidden_target_ip(ip_str, allow_loopback=allow_loopback):
            raise PermissionError(f'Target address {ip_str} is not allowed through the proxy')
        fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        return fam, (ip_str, int(port))
    except ValueError:
        pass

    key = (clean_host, bool(allow_loopback))
    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache.get(key)
        if cached is not None:
            if cached[0] > now:
                _dns_cache.move_to_end(key)
                if cached[1] is None:
                    raise OSError(f'Cannot resolve {host} (cached negative)')
                return cached[1], (cached[2], int(port))
            del _dns_cache[key]
        host_lock = _dns_inflight.get(key)
        if host_lock is None:
            host_lock = threading.Lock()
            _dns_inflight[key] = host_lock

    with host_lock:
        now = time.monotonic()
        with _dns_lock:
            cached = _dns_cache.get(key)
            if cached is not None and cached[0] > now:
                _dns_cache.move_to_end(key)
                if cached[1] is None:
                    raise OSError(f'Cannot resolve {host} (cached negative)')
                return cached[1], (cached[2], int(port))
        try:
            addrs = _resolve_hostname_direct(clean_host)
            if not addrs:
                with _dns_lock:
                    _dns_cache[key] = (time.monotonic() + _DNS_NEG_TTL, None, None)
                raise OSError(f'Cannot resolve {host}')
            for _, ip_str in addrs:
                if _is_forbidden_target_ip(ip_str, allow_loopback=allow_loopback):
                    raise PermissionError(f'Target address {ip_str} is not allowed through the proxy')
            res_family, res_ip = addrs[0]
            with _dns_lock:
                _dns_cache[key] = (time.monotonic() + _DNS_TTL, res_family, res_ip)
                if len(_dns_cache) > _DNS_MAX:
                    _dns_cache.popitem(last=False)
            return res_family, (res_ip, int(port))
        finally:
            with _dns_lock:
                _dns_inflight.pop(key, None)


try:
    import brotli as _brotli
except ImportError:
    try:
        import brotlicffi as _brotli
    except ImportError:
        _brotli = None

try:
    from compression import zstd as _zstd_stdlib
except ImportError:
    _zstd_stdlib = None

try:
    import zstandard as _zstandard
except ImportError:
    _zstandard = None


def _decompress_single(data, enc):
    if enc in ('', 'identity'):
        return data
    if enc in ('gzip', 'x-gzip'):
        return gzip.decompress(data)
    if enc == 'deflate':
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -zlib.MAX_WBITS)
    if enc == 'br' and _brotli is not None:
        return _brotli.decompress(data)
    if enc == 'zstd':
        if _zstd_stdlib is not None:
            return _zstd_stdlib.decompress(data)
        if _zstandard is not None:
            return _zstandard.ZstdDecompressor().decompress(data, max_output_size=MAX_HTML_BYTES)
    raise ValueError(f'Unsupported Content-Encoding: {enc}')


def _decompress(data, encoding):
    raw_enc = (encoding or '').strip().lower()
    if not raw_enc or raw_enc == 'identity':
        if data.startswith(b'\x1f\x8b'):
            return gzip.decompress(data)
        return data
    for enc in reversed([ p.strip() for p in raw_enc.split(',') if p.strip() ]):
        data = _decompress_single(data, enc)
    return data


class ProxyLogWriter:
    """Writes ProxyLog entries in batches on a background thread so logging never slows down proxy requests or opens per-request DB connections."""

    def __init__(self, interval=1.0, queue_max=20000, batch_max=500):
        self.interval = interval
        self.queue_max = queue_max
        self.batch_max = batch_max
        self.queue = queue.Queue(maxsize=queue_max)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name='proxy-logwriter', daemon=True)

    def start(self):
        self._thread.start()

    def add(self, entry):
        try:
            self.queue.put_nowait(entry)
        except queue.Full:
            pass

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self):
        while not self._stop.wait(self.interval):
            self._flush()
        self._flush()

    def _flush(self):
        rows = []
        try:
            while True:
                rows.append(self.queue.get_nowait())
        except queue.Empty:
            pass
        if not rows:
            return
        try:
            close_old_connections()
            for i in range(0, len(rows), self.batch_max):
                ProxyLog.objects.bulk_create(rows[i:i + self.batch_max])
        except Exception:
            pass


class ProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256
    max_threads = 512

    def __init__(self, server_address, RequestHandlerClass=None, settings_getter=None, allow_loopback=False, upstream_ssl_context=None, log=None):
        if ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        self.settings_getter = settings_getter or cached_proxy_settings
        self.allow_loopback = allow_loopback
        self.upstream_ssl_context = upstream_ssl_context
        self.log = log
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

    def setup(self):
        _set_nodelay(self.request)
        super().setup()

    def log_message(self, fmt, *args):
        pass  # keep stdout quiet per request unless debugging

    def _cfg(self):
        return self.server.settings_getter()

    def _client_allowed(self):
        client_ip = self.client_address[0]
        return ratelimit.allowed(client_ip)

    def _log(self, method, host, url, outcome, status_code=200, reason='', t0=None):
        logger = getattr(self.server, 'log', None)
        if not logger:
            return
        ms = max(0, int((time.monotonic() - t0) * 1000)) if t0 is not None else 0
        entry = ProxyLog(
            client=str(self.client_address[0] or '')[:45],
            method=str(method or '')[:12],
            host=str(host or '').lower()[:253],
            url=str(url or '')[:500],
            outcome=outcome,
            status=int(status_code or 0),
            reason=str(reason or '')[:255],
            ms=ms,
        )
        if hasattr(logger, 'add'):
            logger.add(entry)
        elif logger is True:
            try:
                pfilter.run_on_db_pool(entry.save)
            except Exception:
                pass

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
        origin = self.headers.get('Origin') or '*'
        hdrs = {
            'X-Blocked-By': header_val,
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, HEAD',
            'Access-Control-Allow-Headers': '*',
            'Cache-Control': 'no-store',
        }
        if self.command == 'OPTIONS':
            self._send_bytes(204, 'text/plain; charset=utf-8', b'', hdrs)
            return
        low_path = (path or '').lower().partition('?')[0]
        accept = (self.headers.get('Accept') or '').lower()
        sec_dest = (self.headers.get('Sec-Fetch-Dest') or '').strip().lower()
        sec_mode = (self.headers.get('Sec-Fetch-Mode') or '').strip().lower()
        if (
            low_path.endswith('.js')
            or low_path.endswith('/gtag/js')
            or '/widget/' in low_path
            or 'javascript' in accept
            or sec_dest == 'script'
        ):
            self._send_bytes(200, 'application/javascript; charset=utf-8', SURROGATE_JS, hdrs)
        elif low_path.endswith('.css') or 'text/css' in accept or sec_dest == 'style':
            self._send_bytes(200, 'text/css; charset=utf-8', b'/* blocked by Zones.dns */\n', hdrs)
        elif low_path.endswith('.map'):
            self._send_bytes(200, 'application/json; charset=utf-8', b'{"version":3,"sources":[],"mappings":""}', hdrs)
        elif low_path.endswith(('.gif', '.png', '.jpg', '.jpeg', '.webp', '.ico', '.svg')) or accept.startswith('image/') or sec_dest == 'image':
            self._send_bytes(200, 'image/gif', TRANSPARENT_GIF, hdrs)
        elif (
            low_path.endswith(('.html', '.htm'))
            or sec_dest in ('document', 'iframe')
            or ('text/html' in accept and sec_mode in ('', 'navigate'))
            or (not accept and sec_dest == '' and self.command == 'GET' and not low_path.endswith('.json') and '/settings' not in low_path)
        ):
            body = f'<!doctype html><title>Blocked</title><!-- blocked by {header_val} -->'.encode()
            self._send_bytes(403, 'text/html; charset=utf-8', body, hdrs)
        else:
            self._send_bytes(200, 'application/json; charset=utf-8', SURROGATE_JSON, hdrs)

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

    def _proxy_http(self, scheme=None, default_host=None, default_port=None, keep_alive=False):
        t0 = time.monotonic()
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
        log_method = f'MITM {self.command}' if scheme == 'https' else self.command

        if not host:
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Missing target host')
            return

        if hit := pfilter.check_request(host, full_url, s=s):
            self._log(log_method, host, full_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            self._send_blocked(hit[0], hit[1], path=parts.path)
            return

        try:
            resolved_family, resolved_addr = _resolve_target(host, port, allow_loopback=self.server.allow_loopback)
        except PermissionError:
            self._log(log_method, host, full_url, 'error', 403, 'Forbidden target address', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden target address')
            return
        except OSError:
            self._log(log_method, host, full_url, 'error', 502, 'DNS lookup failed', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway: DNS lookup failed')
            return

        content_len = int(self.headers.get('Content-Length', '0') or 0)
        req_body = self.rfile.read(content_len) if content_len > 0 else None

        filter_enabled = bool(getattr(s, 'PROXY_BLOCK_ADS', True) or getattr(s, 'PROXY_BLOCK_POPUPS', True))
        fwd_headers = {}
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in HOP_BY_HOP or kl == 'host':
                continue
            if kl == 'accept-encoding' and filter_enabled:
                continue
            fwd_headers[k] = v
        fwd_headers['Host'] = f'{host}:{port}' if port not in (80, 443) else host
        if filter_enabled:
            fwd_headers['Accept-Encoding'] = 'gzip, deflate'

        conn_header_val = 'keep-alive' if keep_alive else 'close'
        conn = pool_key = None
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
                ctx = self.server.upstream_ssl_context or _default_ssl_context
                key = (target_scheme, host, port, resolved_addr[0])
                conn = _pool_take(key)
                reused = conn is not None
                if conn is None:
                    conn = _open_upstream(target_scheme, host, port, resolved_family, resolved_addr, ctx)
                try:
                    conn.request(self.command, path_query, body=req_body, headers=fwd_headers)
                    if conn.sock is not None:
                        _set_nodelay(conn.sock)
                    resp = conn.getresponse()
                except (OSError, HTTPException):
                    conn.close()
                    if not reused:
                        raise
                    # the server closed the idle connection: one retry on a new one (the request was not answered)
                    conn = _open_upstream(target_scheme, host, port, resolved_family, resolved_addr, ctx)
                    conn.request(self.command, path_query, body=req_body, headers=fwd_headers)
                    if conn.sock is not None:
                        _set_nodelay(conn.sock)
                    resp = conn.getresponse()
                status_code, reason = resp.status, resp.reason
                ctype = resp.getheader('Content-Type', '') or ''
                cenc = resp.getheader('Content-Encoding', '') or ''
                clen_hdr = resp.getheader('Content-Length')
                low_ctype = ctype.lower()
                if 'text/html' not in low_ctype and (
                    (clen_hdr and clen_hdr.isdigit()) or 'text/event-stream' in low_ctype
                ):
                    # Stream non-HTML responses with known Content-Length and real-time SSE streams directly
                    stream_keep_alive = keep_alive and bool(clen_hdr and clen_hdr.isdigit())
                    self.send_response(status_code, reason)
                    for k, v in resp.getheaders():
                        if k.lower() not in HOP_BY_HOP:
                            self.send_header(k, v)
                    self.send_header('Connection', 'keep-alive' if stream_keep_alive else 'close')
                    self.end_headers()
                    if self.command != 'HEAD':
                        read_fn = getattr(resp, 'read1', None) or resp.read
                        while chunk := read_fn(65536):
                            self.wfile.write(chunk)
                            if 'text/event-stream' in low_ctype:
                                self.wfile.flush()
                    pool_key = key if resp.isclosed() and not resp.will_close else None  # body read to its end: the connection is reusable
                    self._log(log_method, host, full_url, 'allowed', status_code, ctype.partition(';')[0] or 'stream', t0)
                    self.close_connection = not stream_keep_alive
                    return
                raw_body = resp.read()
                pool_key = key if resp.isclosed() and not resp.will_close else None
                out_headers = [
                    (k, v) for k, v in resp.getheaders()
                    if k.lower() not in HOP_BY_HOP and k.lower() not in ('content-length', 'content-encoding')
                ]
        except Exception:
            self._log(log_method, host, full_url, 'error', 502, 'Bad Gateway', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway')
            return
        finally:
            if conn:
                _pool_give(pool_key, conn) if pool_key and conn.sock else conn.close()

        html_filtered = False
        sec_dest = (self.headers.get('Sec-Fetch-Dest') or '').strip().lower()
        is_bg_fetch = (sec_dest and sec_dest != 'document') or (
            (self.headers.get('X-Requested-With') or '').strip().lower() == 'xmlhttprequest'
        )
        if (
            self.command != 'HEAD'
            and not is_bg_fetch
            and '/cdn-cgi/' not in path_query
            and 'text/html' in ctype.lower()
            and len(raw_body) <= MAX_HTML_BYTES
        ):
            try:
                plain = _decompress(raw_body, cenc)
                filtered_body = pfilter.filter_html(plain, content_type=ctype, host=host, s=s)
                html_filtered = filtered_body != plain
                raw_body = filtered_body
                cenc = ''
                out_headers = [(k, v) for k, v in out_headers if k.lower() != 'etag']
            except Exception:
                pass

        self._log(
            log_method,
            host,
            full_url,
            'filtered' if html_filtered else 'allowed',
            status_code,
            'HTML filtered' if html_filtered else (ctype.partition(';')[0] or 'HTTP'),
            t0,
        )

        self.send_response(status_code, reason)
        for k, v in out_headers:
            self.send_header(k, v)
        if cenc:
            self.send_header('Content-Encoding', cenc)
        self.send_header('Content-Length', str(len(raw_body)))
        self.send_header('Connection', conn_header_val)
        self.end_headers()
        if self.command != 'HEAD' and raw_body:
            self.wfile.write(raw_body)
        self.close_connection = not keep_alive

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
        t0 = time.monotonic()
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

        target_url = f'https://{host}:{port}/' if port != 443 else f'https://{host}/'
        client_ip = self.client_address[0]
        allow_domains, _, _, _ = pfilter.parse_custom_rules(getattr(s, 'PROXY_CUSTOM_RULES', ''))
        mitm_bypassed_for_client = is_mitm_failed(client_ip, host)
        use_mitm = (
            bool(getattr(s, 'PROXY_HTTPS_MITM', False))
            and not pfilter.is_domain_allowed(host, allow_domains)
            and not mitm_bypassed_for_client
        )

        if use_mitm:
            # With MITM enabled, accept CONNECT locally (without contacting or resolving the remote host yet)
            # so blocked tracker scripts/fetches inside the tunnel receive a stealth 200 OK surrogate from _send_blocked()
            # instead of a hard CONNECT 403 network error that triggers "Ad Blocker Detected" walls.
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self.wfile.flush()
            try:
                ctx = ca.leaf_context(host)
                with ctx.wrap_socket(self.connection, server_side=True) as tls_client:
                    mitm_handler = _MitmHandler(tls_client, self.client_address, self.server, host=host, port=port)
                    mitm_handler.handle_requests()
                    if mitm_handler.tls_handshake_failed:
                        record_mitm_failure(client_ip, host)
                        self._log('MITM', host, target_url, 'allowed', 200, 'TLS pin/CA fallback -> CONNECT', t0)
                    try:
                        tls_client.unwrap()
                    except Exception:
                        pass
            except (ssl.SSLError, OSError):
                record_mitm_failure(client_ip, host)
                self._log('MITM', host, target_url, 'allowed', 200, 'TLS pin/CA fallback -> CONNECT', t0)
            except Exception:
                pass
            self.close_connection = True
            return

        if hit := pfilter.check_request(host, target_url, s=s):
            self._log('CONNECT', host, target_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Blocked by Zones.dns', {'X-Blocked-By': f'Zones.dns ({hit[0]}: {hit[1]})'})
            return

        try:
            family, addr = _resolve_target(host, port, allow_loopback=self.server.allow_loopback)
        except PermissionError:
            self._log('CONNECT', host, target_url, 'error', 403, 'Forbidden target address', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden target address')
            return
        except OSError:
            self._log('CONNECT', host, target_url, 'error', 502, 'DNS lookup failed', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway: DNS lookup failed')
            return

        try:
            tunnel_factory = getattr(self.server, 'tunnel_factory', None)
            if tunnel_factory is not None:
                upstream = tunnel_factory(host, port)
            else:
                upstream = socket.socket(family, socket.SOCK_STREAM)
                _set_nodelay(upstream)
                upstream.settimeout(15)
                upstream.connect(addr)
        except OSError:
            self._log('CONNECT', host, target_url, 'error', 502, 'Bad Gateway', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway')
            return

        self._log(
            'CONNECT',
            host,
            target_url,
            'allowed',
            200,
            'CONNECT tunnel (MITM auto-bypass)' if mitm_bypassed_for_client else 'CONNECT tunnel',
            t0,
        )
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
        _set_nodelay(client_sock)
        _set_nodelay(upstream_sock)
        client_sock.settimeout(60)
        upstream_sock.settimeout(60)
        sockets = [client_sock, upstream_sock]
        while True:
            try:
                r, _, e = select.select(sockets, [], sockets, 120)
            except OSError:
                break
            if e or not r:
                break
            for sock in r:
                other = upstream_sock if sock is client_sock else client_sock
                try:
                    data = sock.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except OSError:
                    return


class _MitmHandler(ProxyHandler):
    """Handles decrypted HTTP/1.1 requests (with Keep-Alive) inside an HTTPS MITM tunnel."""

    def __init__(self, connection, client_address, server, host, port):
        self._mitm_host = host
        self._mitm_port = port
        self.handled_requests = 0
        self.tls_handshake_failed = False
        self.request = connection
        self.connection = connection
        self.client_address = client_address
        self.server = server
        self.setup()

    def handle_requests(self):
        self.close_connection = False
        try:
            while not self.close_connection and self.handled_requests < 64:
                if self.handled_requests > 0:
                    self.connection.settimeout(15)
                self.raw_requestline = self.rfile.readline(65537)
                if not self.raw_requestline:
                    return
                if len(self.raw_requestline) > 65536 or not self.parse_request():
                    return
                if (self.headers.get('Upgrade') or '').lower() == 'websocket':
                    # WebSockets inside MITM should fall back to direct CONNECT tunnel on next attempt
                    self.tls_handshake_failed = True
                    return
                self.handled_requests += 1
                conn_hdr = (self.headers.get('Connection') or '').lower()
                keep_alive = conn_hdr != 'close' and self.request_version >= 'HTTP/1.1'
                self._proxy_http(
                    scheme='https',
                    default_host=self._mitm_host,
                    default_port=self._mitm_port,
                    keep_alive=keep_alive,
                )
                self.wfile.flush()
        except Exception:
            pass
        finally:
            if self.handled_requests == 0:
                self.tls_handshake_failed = True
            self.finish()
