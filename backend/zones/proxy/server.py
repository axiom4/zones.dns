"""Multi-threaded HTTP and HTTPS ad/popup-filtering forward proxy server."""
from collections import OrderedDict
from functools import lru_cache
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import itertools
import queue
import re
import select
import socket
from socketserver import ThreadingMixIn
import ssl
import sys
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
_dns_cache = OrderedDict()  # (host, allow_loopback) -> (expires_at, [(family, ip_str)]); an empty list is a negative entry
_dns_inflight = {}  # (host, allow_loopback) -> threading.Lock (singleflight deduplication for concurrent lookups of the same host)
_DNS_TTL = 600.0  # upper bound: the record's own TTL is used when shorter (a CDN moving a name must not wait 10 minutes)
_DNS_MIN_TTL = 30.0
_DNS_LOCAL_TTL = 60.0  # internal zones and static hosts
_DNS_NEG_TTL = 30.0  # a failed lookup may be a hiccup of the upstream: retried soon
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
    without calling `socket.getaddrinfo()`, so the proxy never sends loopback DNS queries from 127.0.0.1 to rundns.
    Returns ([(family, ip)], ttl seconds)."""
    if clean_host == 'localhost':
        return [(socket.AF_INET, '127.0.0.1')], _DNS_TTL
    try:
        if resolver._data is None or (time.monotonic() - resolver._data_checked) >= 1.0:
            pfilter.run_on_db_pool(resolver._snapshot)
        sh = resolver.static_hosts(clean_host)
        if sh:
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip) for ip, _ in sh], _DNS_LOCAL_TTL
        loc = resolver.lookup(clean_host, 'A')
        if loc:
            recs, _ = loc
            ips = [(socket.AF_INET, r.value) for r in recs if r.type == 'A']
            if ips:
                return ips, _DNS_LOCAL_TTL
    except Exception:
        pass
    res = _get_proxy_resolver()
    for qtype, fam, rtype in (('A', socket.AF_INET, QTYPE.A), ('AAAA', socket.AF_INET6, QTYPE.AAAA)):
        reply, _ = res.forward(DNSRecord.question(clean_host, qtype))
        rrs = [rr for rr in reply.rr if rr.rtype == rtype]
        if rrs:
            return [(fam, str(rr.rdata)) for rr in rrs], min(rr.ttl for rr in rrs)
    return [], _DNS_NEG_TTL

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
        _mitm_strikes.pop(key, None)
        _mitm_failed[key] = time.monotonic() + _MITM_FAIL_TTL
        if len(_mitm_failed) > _MITM_FAIL_MAX:
            _mitm_failed.popitem(last=False)


_mitm_strikes = OrderedDict()  # (client_ip, host) -> (count, first_at): TLS sessions that ended without a request
_MITM_STRIKE_WINDOW = 600.0


def note_empty_mitm_session(client_ip, host):
    """A MITM TLS session closed before any request. An app that pins its certificate does this, but so does a browser preconnect
    that is never used: only the second one within 10 minutes switches the host to a plain tunnel."""
    key = (client_ip, host)
    now = time.monotonic()
    with _mitm_lock:
        n, since = _mitm_strikes.get(key, (0, now))
        if now - since > _MITM_STRIKE_WINDOW:
            n, since = 0, now
        _mitm_strikes[key] = (n + 1, since)
        _mitm_strikes.move_to_end(key)
        if len(_mitm_strikes) > _MITM_FAIL_MAX:
            _mitm_strikes.popitem(last=False)
    if n + 1 >= 2:
        record_mitm_failure(client_ip, host)
        return True
    return False


def _connect_any(addrs, timeout):
    """A TCP socket to the first address of `addrs` [(family, (ip, port))] that answers: one dead address of a name must not fail the request."""
    err = None
    for family, addr in addrs:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            _set_nodelay(sock)
            sock.settimeout(timeout if len(addrs) == 1 else min(timeout, 5))
            sock.connect(addr)
            sock.settimeout(timeout)
            return sock
        except OSError as e:
            sock.close()
            err = e
    raise err or OSError('no address to connect to')


class _ResolvedHTTPConnection(HTTPConnection):
    """HTTPConnection to already-resolved addresses (no second getaddrinfo), trying the next one when an address does not answer."""

    def __init__(self, host, port, addrs, **kwargs):
        super().__init__(host, port, **kwargs)
        self._addrs = addrs

    def connect(self):
        self.sock = _connect_any(self._addrs, self.timeout)


class _ResolvedHTTPSConnection(HTTPSConnection):
    """HTTPSConnection to already-resolved addresses (avoiding a second getaddrinfo call) while preserving SNI/hostname verification."""

    def __init__(self, host, port, addrs, **kwargs):
        super().__init__(host, port, **kwargs)
        self._addrs = addrs

    def connect(self):
        sock = _connect_any(self._addrs, self.timeout)
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


def _open_upstream(scheme, host, port, addrs, ctx):
    if scheme == 'https':
        return _ResolvedHTTPSConnection(host, port, addrs, timeout=20, context=ctx)
    return _ResolvedHTTPConnection(host, port, addrs, timeout=20)


@lru_cache(maxsize=4)
def _connect_ports(raw):
    raw = str(raw or '').strip()
    return None if raw in ('', '*') else frozenset(int(p) for p in raw.replace(' ', ',').split(',') if p.strip().isdigit())


def _connect_port_allowed(port):
    """PROXY_CONNECT_PORTS: the ports a CONNECT tunnel may reach ('*' = any)."""
    ports = _connect_ports(getattr(settings, 'PROXY_CONNECT_PORTS', '*'))
    return ports is None or port in ports


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

MAX_REQUEST_BYTES = 150 * 1024 * 1024  # Exchange accepts messages up to 150 MB
MAX_BUFFERED_BODY = 1024 * 1024  # request bodies up to this size are kept in memory (and can be sent again on a new connection); larger ones are streamed
IDEMPOTENT = frozenset({'GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'TRACE'})  # RFC 9110 9.2.2: only these may be retried by a proxy
VIA = '1.1 zones-dns'  # RFC 9110 7.6.3
TUNNEL_IDLE = 1800  # seconds a CONNECT tunnel may stay silent: IMAP IDLE, push channels and WebSockets are quiet for many minutes
PER_CLIENT_MAX = 256  # connections (threads) one client address may hold: one device cannot take all of max_threads
_HEX_RX = re.compile(rb'^[0-9A-Fa-f]{1,16}$')
_CL_RX = re.compile(r'^\d{1,19}$')

HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailers', 'transfer-encoding', 'upgrade',
})


class BodyTooLarge(ValueError):
    pass


def _hop_headers(headers):
    """The hop-by-hop fields of a message: the fixed ones plus every name listed in its Connection header (RFC 9110 7.6.1)."""
    out = set(HOP_BY_HOP)
    for v in headers.get_all('Connection') or ():
        out.update(t.strip().lower() for t in v.split(',') if t.strip())
    return out


def _with_via(prev):
    return f'{prev}, {VIA}' if prev else VIA


def _redact_url(url):
    """The URL for the log without the values of its query: they carry sign-in codes, tokens and keys. The parameter names stay."""
    base, sep, query = str(url or '').partition('?')
    if not sep:
        return base
    names = [p.partition('=')[0] for p in query.split('&') if p]
    return base + '?' + '&'.join(f'{n}=…' for n in names)

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


def _with_port(addrs, port):
    return [(fam, (ip, int(port))) for fam, ip in addrs]


def _resolve_target(host, port, allow_loopback=False, own_ips=frozenset()):
    """Resolve `host` (in-memory cache for the record's TTL, IPv4-first to avoid duplicate A+AAAA queries) and check SSRF rules.
    Returns every address [(family, (ip, port))], the first one first. `own_ips`: this server's addresses, reachable only on ports 80 and 443
    (the GUI behind nginx), never on the ports of its databases and daemons."""
    clean_host = host.strip('[]')

    def check(ip_str):
        if _is_forbidden_target_ip(ip_str, allow_loopback=allow_loopback) or (ip_str in own_ips and int(port) not in (80, 443)):
            raise PermissionError(f'Target address {ip_str} is not allowed through the proxy')

    try:
        ip_obj = ipaddress.ip_address(clean_host)
    except ValueError:
        pass
    else:
        check(str(ip_obj))
        return [(socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET, (str(ip_obj), int(port)))]

    key = (clean_host, bool(allow_loopback))

    def cached_answer():
        cached = _dns_cache.get(key)
        if cached is None:
            return None
        if cached[0] <= time.monotonic():
            del _dns_cache[key]
            return None
        _dns_cache.move_to_end(key)
        if not cached[1]:
            raise OSError(f'Cannot resolve {host} (cached negative)')
        for _, ip_str in cached[1]:
            check(ip_str)
        return _with_port(cached[1], port)

    with _dns_lock:
        if (hit := cached_answer()) is not None:
            return hit
        host_lock = _dns_inflight.get(key)
        if host_lock is None:
            host_lock = threading.Lock()
            _dns_inflight[key] = host_lock

    with host_lock:
        with _dns_lock:
            if (hit := cached_answer()) is not None:
                return hit
        try:
            addrs, ttl = _resolve_hostname_direct(clean_host)
            if not addrs:
                with _dns_lock:
                    _dns_cache[key] = (time.monotonic() + _DNS_NEG_TTL, [])
                raise OSError(f'Cannot resolve {host}')
            for _, ip_str in addrs:
                check(ip_str)  # every address: a name must not smuggle a forbidden one in second place
            with _dns_lock:
                _dns_cache[key] = (time.monotonic() + max(_DNS_MIN_TTL, min(float(ttl), _DNS_TTL)), addrs)
                if len(_dns_cache) > _DNS_MAX:
                    _dns_cache.popitem(last=False)
            return _with_port(addrs, port)
        finally:
            with _dns_lock:
                _dns_inflight.pop(key, None)


try:
    from compression import zstd as _zstd_stdlib
except ImportError:
    _zstd_stdlib = None

try:
    import zstandard as _zstandard
except ImportError:
    _zstandard = None


def _bounded(d, data):
    """Decompress with a zlib-style decompressor, at most MAX_HTML_BYTES: a few MB of gzip can expand to gigabytes (a decompression bomb)."""
    out = d.decompress(data, MAX_HTML_BYTES + 1)
    if len(out) > MAX_HTML_BYTES:
        raise ValueError('Decompressed HTML is too large to filter')
    return out


def _decompress_single(data, enc):
    if enc in ('', 'identity'):
        return data
    if enc in ('gzip', 'x-gzip'):
        return _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), data)
    if enc == 'deflate':
        try:
            return _bounded(zlib.decompressobj(), data)
        except zlib.error:
            return _bounded(zlib.decompressobj(-zlib.MAX_WBITS), data)
    if enc == 'zstd':
        if _zstd_stdlib is not None:
            return _bounded(_zstd_stdlib.ZstdDecompressor(), data)
        if _zstandard is not None:
            return _zstandard.ZstdDecompressor().decompress(data, max_output_size=MAX_HTML_BYTES)
    # br: the brotli module has no output limit, so it is not decompressed (the page passes unfiltered); documents are asked for as gzip anyway
    raise ValueError(f'Unsupported Content-Encoding: {enc}')


def _decompress(data, encoding):
    raw_enc = (encoding or '').strip().lower()
    if not raw_enc or raw_enc == 'identity':
        if data.startswith(b'\x1f\x8b'):
            return _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), data)
        return data
    for enc in reversed([ p.strip() for p in raw_enc.split(',') if p.strip() ]):
        data = _decompress_single(data, enc)
    return data


def _why(e):
    """One line for the log and stderr: the exception class and its text."""
    return f'{type(e).__name__}: {e}'[:200]


def _warn(msg):
    print(f'Proxy: {msg}', file=sys.stderr, flush=True)


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
            _warn('log queue full, an entry was dropped')

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
        except Exception as e:
            _warn(f'cannot save {len(rows)} log entries: {_why(e)}')


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
        self._per_client = {}
        self._per_client_lock = threading.Lock()
        super().__init__(server_address, RequestHandlerClass or ProxyHandler)

    def _client_done(self, ip):
        with self._per_client_lock:
            n = self._per_client.get(ip, 1) - 1
            if n > 0:
                self._per_client[ip] = n
            else:
                self._per_client.pop(ip, None)

    def process_request(self, request, client_address):
        ip = client_address[0]
        with self._per_client_lock:
            if self._per_client.get(ip, 0) >= PER_CLIENT_MAX:
                self.shutdown_request(request)
                return
            self._per_client[ip] = self._per_client.get(ip, 0) + 1
        if not self._thread_sem.acquire(blocking=False):
            self._client_done(ip)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._thread_sem.release()
            self._client_done(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            connections.close_all()
            self._thread_sem.release()
            self._client_done(client_address[0])


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
            url=_redact_url(url)[:500],
            outcome=outcome,
            status=int(status_code or 0),
            reason=str(reason or '')[:255],
            ms=ms,
        )
        print(f'{entry.client} {entry.method} {entry.status} {entry.outcome} {entry.ms}ms {entry.url} {entry.reason}'.rstrip(), flush=True)  # the supervisor log of runproxy: one line per request
        if hasattr(logger, 'add'):
            logger.add(entry)
        elif logger is True:
            try:
                pfilter.run_on_db_pool(entry.save)
            except Exception as e:
                _warn(f'cannot save a log entry: {_why(e)}')

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
        if path in ('/ca.crt', '/ca.pem', '/proxy.mobileconfig') and str(settings.GUI_URL).startswith('https://'):
            # plain HTTP lets anyone on the path swap the certificate for their own: the GUI serves both over https
            target = settings.GUI_URL.rstrip('/') + ('/proxy.mobileconfig' if path == '/proxy.mobileconfig' else '/proxy-ca.crt')
            self._send_bytes(302, 'text/plain; charset=utf-8', b'', {'Location': target})
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

    def _read_exact(self, n):
        data = self.rfile.read(n)
        if len(data) != n:
            raise ValueError('the client closed the connection before the end of the body')
        return data

    def _chunks(self):
        """The data of a chunked body (RFC 9112 7.1), piece by piece. Raises ValueError on bad framing, BodyTooLarge over MAX_REQUEST_BYTES."""
        total = 0
        while True:
            line = self.rfile.readline(1025)
            size_txt = line.split(b';', 1)[0].strip()
            if not line.endswith(b'\n') or not _HEX_RX.match(size_txt):
                raise ValueError('bad chunk size')  # only hex digits: int(x, 16) also takes "-1", "0x10" and "1_0"
            size = int(size_txt, 16)
            if size == 0:
                for _ in range(64):  # trailers, up to the blank line
                    if not self.rfile.readline(8193).strip():
                        return
                raise ValueError('too many trailer lines')
            total += size
            if total > MAX_REQUEST_BYTES:
                raise BodyTooLarge('request body too large')
            while size:
                part = self._read_exact(min(size, 65536))
                size -= len(part)
                yield part
            if self.rfile.readline(3) not in (b'\r\n', b'\n'):
                raise ValueError('missing CRLF after a chunk')

    def _request_body(self):
        """(body, length): body None, bytes (small: can be sent again) or an iterator that streams a large body without holding it in memory;
        length is the Content-Length to forward for a streamed sized body, else None (http.client then frames the body itself).
        Raises ValueError on a message whose length is ambiguous (request smuggling, RFC 9112 6.1 and 6.3), BodyTooLarge over MAX_REQUEST_BYTES."""
        te = [c.strip().lower() for v in self.headers.get_all('Transfer-Encoding') or () for c in v.split(',') if c.strip()]
        if te:
            if te != ['chunked']:
                raise ValueError('unsupported Transfer-Encoding')
            chunks = self._chunks()
            head, size = [], 0
            for part in chunks:
                head.append(part)
                size += len(part)
                if size > MAX_BUFFERED_BODY:
                    return itertools.chain(head, chunks), None
            return b''.join(head) or None, None
        lengths = {v.strip() for v in self.headers.get_all('Content-Length') or ()}
        if len(lengths) > 1 or (lengths and not _CL_RX.match(next(iter(lengths)))):
            raise ValueError('bad Content-Length')
        n = int(lengths.pop()) if lengths else 0
        if n > MAX_REQUEST_BYTES:
            raise BodyTooLarge('request body too large')
        if n <= MAX_BUFFERED_BODY:
            return (self._read_exact(n) if n else None), None

        def stream(left=n):
            while left:
                part = self._read_exact(min(left, 65536))
                left -= len(part)
                yield part
        return stream(), n

    def _proxy_http(self, scheme=None, default_host=None, default_port=None, keep_alive=False):
        t0 = time.monotonic()
        if not self._client_allowed():
            self._log(self.command, '', self.path, 'error', 403, 'Client refused (DNS_ALLOW_QUERY or rate limit)', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden')
            return
        s = self._cfg()
        if self.path.startswith('/') and scheme is None:
            if self._handle_local(s):
                return
            host_hdr = self.headers.get('Host', '')
            if not host_hdr:
                self._log(self.command, '', self.path, 'error', 400, 'No Host header', t0)
                self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad Request')
                return
            full_url = f'http://{host_hdr}{self.path}'
        elif self.path.startswith(('http://', 'https://')):
            full_url = self.path
        elif scheme and default_host:
            port_part = f':{default_port}' if default_port and default_port not in (80, 443) else ''
            full_url = f'{scheme}://{default_host}{port_part}{self.path}'
        else:
            self._log(self.command, '', self.path, 'error', 400, 'Unusable request target', t0)
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad Request')
            return

        parts = urlsplit(full_url)
        target_scheme = (parts.scheme or scheme or 'http').lower()
        host = (parts.hostname or default_host or '').lower()
        try:
            port = parts.port or default_port or (443 if target_scheme == 'https' else 80)
        except ValueError:  # a port that is not a number or out of range
            self._log(self.command, '', full_url, 'error', 400, 'Bad port in the request target', t0)
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad Request')
            return
        path_query = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')
        log_method = f'MITM {self.command}' if scheme == 'https' else self.command

        if not host:
            self._log(log_method, '', full_url, 'error', 400, 'Missing target host', t0)
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Missing target host')
            return

        if hit := pfilter.check_request(host, full_url, s=s):
            self._log(log_method, host, full_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            self._send_blocked(hit[0], hit[1], path=parts.path)
            return

        if self.command == 'OPTIONS' and (self.headers.get('Max-Forwards') or '').strip() == '0':
            # RFC 9110 7.6.2: Max-Forwards 0 means the request is for this proxy, it goes no further
            self._send_bytes(200, 'text/plain; charset=utf-8', b'', {'Allow': 'GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH, CONNECT'})
            return

        try:
            addrs = _resolve_target(host, port, allow_loopback=self.server.allow_loopback, own_ips=self._own_ips(s))
        except PermissionError:
            self._log(log_method, host, full_url, 'error', 403, 'Forbidden target address', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden target address')
            return
        except OSError:
            self._log(log_method, host, full_url, 'error', 502, 'DNS lookup failed', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway: DNS lookup failed')
            return

        if self.request_version >= 'HTTP/1.1' and (self.headers.get('Expect') or '').lower() == '100-continue':
            self.send_response_only(100)  # the client holds back the body until it hears this (mail clients upload attachments this way); never to HTTP/1.0 (RFC 9110 10.1.1)
            self.end_headers()
        try:
            req_body, stream_len = self._request_body()
        except BodyTooLarge:
            self._log(log_method, host, full_url, 'error', 413, 'Request body too large', t0)
            self._send_bytes(413, 'text/plain; charset=utf-8', b'Request body too large')
            return
        except (ValueError, OSError) as e:
            self._log(log_method, host, full_url, 'error', 400, f'Bad request body: {_why(e)}', t0)
            self._send_bytes(400, 'text/plain; charset=utf-8', b'Bad request body')
            return
        resendable = req_body is None or isinstance(req_body, bytes)

        sec_dest = (self.headers.get('Sec-Fetch-Dest') or '').strip().lower()
        is_bg_fetch = (sec_dest and sec_dest != 'document') or (
            (self.headers.get('X-Requested-With') or '').strip().lower() == 'xmlhttprequest'
        )
        filter_enabled = bool(getattr(s, 'PROXY_BLOCK_ADS', True) or getattr(s, 'PROXY_BLOCK_POPUPS', True))
        may_filter = filter_enabled and not is_bg_fetch and self.command != 'HEAD'  # only a page itself is filtered, never what it fetches
        hop = _hop_headers(self.headers)
        fwd_headers = {}
        for k, v in self.headers.items():
            kl = k.lower()
            # content-length: http.client frames the body it is given; forwarding the client's own next to a chunked body is request smuggling
            if kl in hop or kl in ('host', 'expect', 'content-length', 'via', 'max-forwards'):
                continue
            if kl == 'accept-encoding' and may_filter:
                continue
            fwd_headers[k] = v
        fwd_headers['Host'] = f'{host}:{port}' if port not in (80, 443) else host
        fwd_headers['Via'] = _with_via(self.headers.get('Via'))
        if (mf := (self.headers.get('Max-Forwards') or '').strip()).isdigit():
            fwd_headers['Max-Forwards'] = str(int(mf) - 1) if self.command == 'OPTIONS' else mf
        if stream_len is not None:
            fwd_headers['Content-Length'] = str(stream_len)
        if may_filter:
            fwd_headers['Accept-Encoding'] = 'gzip, deflate'

        conn_header_val = 'keep-alive' if keep_alive else 'close'
        conn = pool_key = None
        raw_body = b''
        try:
            fetcher = getattr(self.server, 'http_fetcher', None)
            if fetcher is not None:
                body = req_body if resendable else b''.join(req_body)
                status_code, reason, resp_headers, raw_body = fetcher(target_scheme, host, port, self.command, path_query, body, fwd_headers)
                rh = {k.lower(): v for k, v in resp_headers}
                ctype, cenc = rh.get('content-type', ''), rh.get('content-encoding', '')
                cache_control, csp = rh.get('cache-control', ''), rh.get('content-security-policy', '')
                out_headers = [
                    (k, v) for k, v in resp_headers
                    if k.lower() not in HOP_BY_HOP and k.lower() not in ('content-length', 'content-encoding', 'via')
                ]
                resp_via = rh.get('via')
            else:
                ctx = self.server.upstream_ssl_context or _default_ssl_context
                key = (target_scheme, host, port, addrs[0][1][0])
                idempotent = self.command in IDEMPOTENT and resendable
                conn = _pool_take(key) if idempotent else None  # anything else goes on a fresh connection: it may not be sent twice (RFC 9110 9.2.2)
                reused = conn is not None
                if conn is None:
                    conn = _open_upstream(target_scheme, host, port, addrs, ctx)
                try:
                    resp = self._send_upstream(conn, path_query, req_body, fwd_headers)
                except (OSError, HTTPException) as e:
                    conn.close()
                    if not reused or isinstance(e, TimeoutError):  # a timeout is an answer too slow, not a closed connection: retrying doubled the wait
                        raise
                    # the server closed the idle connection: one retry on a new one (an idempotent request that was not answered)
                    conn = _open_upstream(target_scheme, host, port, addrs, ctx)
                    resp = self._send_upstream(conn, path_query, req_body, fwd_headers)
                status_code, reason = resp.status, resp.reason
                hop_resp = _hop_headers(resp.msg)
                ctype = resp.getheader('Content-Type', '') or ''
                cenc = resp.getheader('Content-Encoding', '') or ''
                cache_control = resp.getheader('Cache-Control', '') or ''
                csp = ', '.join(resp.msg.get_all('Content-Security-Policy') or ())
                resp_via = resp.getheader('Via')
                clen_hdr = resp.getheader('Content-Length')
                chunked_up = bool(getattr(resp, 'chunked', False))  # with both, Transfer-Encoding wins and Content-Length is not forwarded (RFC 9112 6.3)
                low_ctype = ctype.lower()
                no_body = self.command == 'HEAD' or status_code in (204, 304)
                prefix = b''
                buffer_html = (
                    may_filter and not no_body and 'text/html' in low_ctype and '/cdn-cgi/' not in path_query
                    and 'no-transform' not in cache_control.lower()  # RFC 9110 7.7: a proxy must not transform it
                    and not (clen_hdr and clen_hdr.isdigit() and not chunked_up and int(clen_hdr) > MAX_HTML_BYTES)
                )
                if buffer_html:
                    raw_body = resp.read(MAX_HTML_BYTES + 1)
                    if len(raw_body) > MAX_HTML_BYTES:
                        prefix, raw_body, buffer_html = raw_body, b'', False  # too big to filter: relayed as it comes, starting with what was read
                if not buffer_html:
                    # Relayed as it arrives: long polls and streams (Exchange EWS streaming notifications, Teams trouter, SSE) never end,
                    # and a buffered copy made the client wait until its own timeout
                    framed = (bool(clen_hdr and clen_hdr.isdigit()) and not chunked_up) or no_body  # the client can tell where the body ends
                    chunk_out = not framed and keep_alive  # otherwise the end of the body is the end of the connection
                    self.send_response_only(status_code, reason)  # not send_response: it adds a second Date and Server
                    for k, v in resp.getheaders():
                        kl = k.lower()
                        if kl in hop_resp or kl == 'via' or (kl == 'content-length' and chunked_up):
                            continue
                        self.send_header(k, v)
                    self.send_header('Via', _with_via(resp_via))
                    if chunk_out:
                        self.send_header('Transfer-Encoding', 'chunked')
                    self.send_header('Connection', 'keep-alive' if (framed or chunk_out) and keep_alive else 'close')
                    self.end_headers()
                    if not framed and conn.sock is not None:
                        conn.sock.settimeout(120)  # a long poll is silent for tens of seconds
                    client_gone = False
                    if not no_body:
                        read_fn = getattr(resp, 'read1', None) or resp.read
                        pieces = itertools.chain([prefix] if prefix else [], iter(lambda: read_fn(65536), b''))
                        try:
                            for chunk in pieces:
                                try:
                                    self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n' if chunk_out else chunk)
                                    if chunk_out or 'text/event-stream' in low_ctype:
                                        self.wfile.flush()
                                except OSError:
                                    client_gone = True  # the client gave up (a video seek, a closed tab): not an error of ours
                                    break
                            if chunk_out and not client_gone:
                                self.wfile.write(b'0\r\n\r\n')
                        except Exception as e:
                            # the headers are gone: all we can do is cut the connection
                            self._log(log_method, host, full_url, 'error', status_code, f'Upstream failed while streaming: {_why(e)}', t0)
                            self.close_connection = True
                            return
                    if client_gone:
                        self._log(log_method, host, full_url, 'allowed', status_code, 'client closed the connection', t0)
                        self.close_connection = True
                        return
                    pool_key = key if resp.isclosed() and not resp.will_close else None  # body read to its end: the connection is reusable
                    self._log(log_method, host, full_url, 'allowed', status_code, ctype.partition(';')[0] or 'stream', t0)
                    self.close_connection = not keep_alive
                    return
                pool_key = key if resp.isclosed() and not resp.will_close else None
                out_headers = [
                    (k, v) for k, v in resp.getheaders()
                    if k.lower() not in hop_resp and k.lower() not in ('content-length', 'content-encoding', 'via')
                ]
        except BodyTooLarge:
            self._log(log_method, host, full_url, 'error', 413, 'Request body too large', t0)
            self._send_bytes(413, 'text/plain; charset=utf-8', b'Request body too large')
            return
        except Exception as e:
            self._log(log_method, host, full_url, 'error', 502, f'Bad Gateway: {_why(e)}', t0)
            self._send_bytes(502, 'text/plain; charset=utf-8', b'Bad Gateway')
            return
        finally:
            if conn:
                _pool_give(pool_key, conn) if pool_key and conn.sock else conn.close()

        html_filtered = False
        if (
            may_filter
            and '/cdn-cgi/' not in path_query
            and 'text/html' in ctype.lower()
            and 'no-transform' not in cache_control.lower()
            and len(raw_body) <= MAX_HTML_BYTES
        ):
            try:
                plain = _decompress(raw_body, cenc)
                filtered_body = pfilter.filter_html(plain, content_type=ctype, host=host, s=s, csp=csp)
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

        self.send_response_only(status_code, reason)
        for k, v in out_headers:
            self.send_header(k, v)
        if cenc:
            self.send_header('Content-Encoding', cenc)
        self.send_header('Content-Length', str(len(raw_body)))
        self.send_header('Via', _with_via(resp_via))
        self.send_header('Connection', conn_header_val)
        self.end_headers()
        if self.command != 'HEAD' and raw_body:
            self.wfile.write(raw_body)
        self.close_connection = not keep_alive

    def _send_upstream(self, conn, path_query, body, headers):
        conn.request(self.command, path_query, body=body, headers=headers)
        if conn.sock is not None:
            _set_nodelay(conn.sock)
        return conn.getresponse()

    def _own_ips(self, s):
        """This server's addresses: the one the client reached and the configured ones (none in the tests, that allow loopback)."""
        if self.server.allow_loopback:
            return frozenset()
        out = set()
        try:
            local = self.connection.getsockname()
            if isinstance(local, tuple):
                out.add(local[0])
        except OSError:
            pass
        for v in (getattr(s, 'DHCP_SERVER', ''), getattr(s, 'PROXY_ADDRESS', '')):
            if v and str(v) not in ('0.0.0.0', '::'):
                out.add(str(v))
        return frozenset(out)

    def _plain(self):
        self._proxy_http(keep_alive=not self.close_connection)  # parse_request decided it from the version and the Connection header

    def do_GET(self):
        self._plain()

    def do_POST(self):
        self._plain()

    def do_PUT(self):
        self._plain()

    def do_DELETE(self):
        self._plain()

    def do_HEAD(self):
        self._plain()

    def do_OPTIONS(self):
        self._plain()

    def do_PATCH(self):
        self._plain()

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
        if not _connect_port_allowed(port):
            # RFC 9110 9.3.6: a tunnel to any port would let clients reach mail relays and internal services through the proxy
            self._log('CONNECT', host, target_url, 'error', 403, f'Port {port} is not allowed for CONNECT (PROXY_CONNECT_PORTS)', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Forbidden port')
            return
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
                    elif mitm_handler.handled_requests == 0 and note_empty_mitm_session(client_ip, host):
                        self._log('MITM', host, target_url, 'allowed', 200, 'TLS sessions without requests (pinning?) -> CONNECT', t0)
                    try:
                        tls_client.unwrap()
                    except Exception:
                        pass
            except (ssl.SSLError, OSError) as e:
                record_mitm_failure(client_ip, host)
                self._log('MITM', host, target_url, 'allowed', 200, f'TLS pin/CA fallback -> CONNECT ({_why(e)})', t0)
            except Exception as e:
                _warn(f'MITM {host}: {_why(e)}')
                self._log('MITM', host, target_url, 'error', 500, f'Internal error: {_why(e)}', t0)
            self.close_connection = True
            return

        if hit := pfilter.check_request(host, target_url, s=s):
            self._log('CONNECT', host, target_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            self._send_bytes(403, 'text/plain; charset=utf-8', b'Blocked by Zones.dns', {'X-Blocked-By': f'Zones.dns ({hit[0]}: {hit[1]})'})
            return

        try:
            addrs = _resolve_target(host, port, allow_loopback=self.server.allow_loopback, own_ips=self._own_ips(s))
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
            upstream = tunnel_factory(host, port) if tunnel_factory is not None else _connect_any(addrs, 15)
        except OSError as e:
            self._log('CONNECT', host, target_url, 'error', 502, f'Bad Gateway: {_why(e)}', t0)
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
    def _keepalive(sock):
        """TCP keep-alive: a tunnel may stay silent for a long time, a peer that vanished is still noticed."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
        except OSError:
            pass

    @staticmethod
    def _tunnel(client_sock, upstream_sock):
        for sock in (client_sock, upstream_sock):
            _set_nodelay(sock)
            ProxyHandler._keepalive(sock)
            sock.settimeout(60)  # for a send that does not progress; silence is measured by select
        sockets = [client_sock, upstream_sock]
        while True:
            try:
                r, _, e = select.select(sockets, [], sockets, TUNNEL_IDLE)
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
        except (OSError, ssl.SSLError):
            pass  # the client went away or timed out: normal at the end of a keep-alive connection
        except Exception as e:
            _warn(f'MITM {self._mitm_host}: {_why(e)}')
            self._log('MITM', self._mitm_host, f'https://{self._mitm_host}/', 'error', 500, f'Internal error: {_why(e)}')
        finally:
            self.finish()
