"""Asynchronous HTTP/1.1 and HTTP/2 ad/popup-filtering forward proxy.

asyncio, one event loop: a connection costs a few kilobytes, not a thread. Towards the client HTTP/1.1 (h11: framing, chunked bodies,
100 Continue and request smuggling handled by the library) and, inside an HTTPS MITM session, HTTP/2 when the client offers it (h2).
Towards the servers httpcore: HTTP/1.1 or HTTP/2 as the server chooses, one pool of kept-alive connections. Whatever touches the
database or burns CPU (settings, filters, the CA, HTML filtering) runs on a small thread pool, DNS lookups on another.
"""
import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache, partial
from http import HTTPStatus
import ipaddress
import queue
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit
import zlib

from django.conf import settings
from django.db import DatabaseError, close_old_connections
from dnslib import DNSRecord, QTYPE
import h11
import httpcore

from ..dhcp import v4 as dhcp
from ..dnsd import ratelimit, resolver
from ..models import DataVersion, ProxyLog
from . import ca, filter as pfilter, pac, upload, upstream
from .h2conn import H2Connection, StreamGone
from .streams import RawStream, TLSStream, keepalive
from .upload import Prefixed

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


@lru_cache(maxsize=4)
def _connect_ports(raw):
    raw = str(raw or '').strip()
    return None if raw in ('', '*') else frozenset(int(p) for p in raw.replace(' ', ',').split(',') if p.strip().isdigit())


def _connect_port_allowed(port):
    """PROXY_CONNECT_PORTS: the ports a CONNECT tunnel may reach ('*' = any)."""
    ports = _connect_ports(getattr(settings, 'PROXY_CONNECT_PORTS', '*'))
    return ports is None or port in ports


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
PER_CLIENT_MAX = 256  # connections one client address may hold: one device cannot take all of MAX_CLIENT_CONNECTIONS
MAX_CLIENT_CONNECTIONS = 8192

HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailers', 'transfer-encoding', 'upgrade',
})


class BodyTooLarge(ValueError):
    pass


def _hop_headers(connection_values):
    """The hop-by-hop fields of a message: the fixed ones plus every name listed in its Connection header (RFC 9110 7.6.1)."""
    out = set(HOP_BY_HOP)
    for v in connection_values:
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
    if ip.is_loopback:
        return not allow_loopback
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified


def _plain_ip(ip_str):
    """The address as compared with this server's own: an IPv4-mapped IPv6 one (::ffff:a.b.c.d) is the IPv4 address it reaches."""
    try:
        ip = ipaddress.ip_address(str(ip_str).partition('%')[0])
    except ValueError:
        return str(ip_str)
    return str(getattr(ip, 'ipv4_mapped', None) or ip)


def _with_port(addrs, port):
    return [(fam, (ip, int(port))) for fam, ip in addrs]


def _resolve_target(host, port, allow_loopback=False, own_ips=frozenset()):
    """Resolve `host` (in-memory cache for the record's TTL, IPv4-first to avoid duplicate A+AAAA queries) and check SSRF rules.
    Returns every address [(family, (ip, port))], the first one first. `own_ips`: this server's addresses, reachable only on ports 80 and 443
    (the GUI behind nginx), never on the ports of its databases and daemons."""
    clean_host = host.strip('[]')
    own_ips = {_plain_ip(i) for i in own_ips}

    def check(ip_str):
        if _is_forbidden_target_ip(ip_str, allow_loopback=allow_loopback) or (_plain_ip(ip_str) in own_ips and int(port) not in (80, 443)):
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

try:
    import brotli as _brotli
    if not hasattr(_brotli.Decompressor(), 'can_accept_more_data'):
        _brotli = None  # before 1.2 there is no output limit (CVE-2025-6176): br pages pass unfiltered
except ImportError:
    _brotli = None


def _bounded(d, data):
    """Decompress with a zlib-style decompressor, at most MAX_HTML_BYTES: a few MB of gzip can expand to gigabytes (a decompression bomb)."""
    out = d.decompress(data, MAX_HTML_BYTES + 1)
    if len(out) > MAX_HTML_BYTES:
        raise ValueError('Decompressed HTML is too large to filter')
    if not d.eof or d.unused_data:
        # cut short, or more than one member: what was read is not the whole page, and would be sent as if it were
        raise ValueError('Truncated or multi-part compressed body')
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
    if enc == 'br' and _brotli is not None:
        d = _brotli.Decompressor()
        out = d.process(data, output_buffer_limit=MAX_HTML_BYTES + 1)
        if len(out) > MAX_HTML_BYTES:
            raise ValueError('Decompressed HTML is too large to filter')
        if not d.is_finished():
            raise ValueError('Truncated br body')
        return out
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




_WORK = ThreadPoolExecutor(max_workers=16, thread_name_prefix='proxy-work')  # settings, filters, CA, HTML: database and CPU (each thread may hold a DB connection)
_DNS = ThreadPoolExecutor(max_workers=32, thread_name_prefix='proxy-dns')  # name lookups wait on the network, not on the database
FIRST_REQUEST_TIMEOUT = 30  # seconds a new connection may take to send its first request
KEEPALIVE_TIMEOUT = 30  # ... and to send the next one (15 inside a MITM session, like browsers' own idle timeout)
UPSTREAM_TIMEOUTS = {'connect': 15.0, 'read': 120.0, 'write': 60.0, 'pool': 30.0}  # read: a long poll is silent for tens of seconds
_RETRYABLE = (httpcore.RemoteProtocolError, httpcore.ReadError, httpcore.WriteError)


async def _run(pool, fn, *args, **kwargs):
    return await asyncio.get_running_loop().run_in_executor(pool, partial(fn, *args, **kwargs))


def _phrase(status):
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ''


def _filter_page(raw_body, cenc, ctype, host, s, csp):
    """(body, changed): the page decompressed and filtered; raises when it cannot be (it is then relayed as it came)."""
    plain = _decompress(raw_body, cenc)
    out = pfilter.filter_html(plain, content_type=ctype, host=host, s=s, csp=csp)
    return out, out != plain


class H1Exchange:
    """One HTTP/1.1 (or 1.0) request on an h11 connection."""

    def __init__(self, conn, req):
        self.conn = conn
        self.method = req.method.decode('latin-1')
        self.target = req.target.decode('latin-1')
        self.version = 'HTTP/' + req.http_version.decode('latin-1')
        self.headers = [(k.decode('latin-1'), v.decode('latin-1')) for k, v in req.headers.raw_items()]
        tokens = {t.strip().lower() for v in self.get_all('connection') for t in v.split(',')}
        self.keep_alive = req.http_version >= b'1.1' and 'close' not in tokens
        self.started = False

    def header(self, name):
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), '')

    def get_all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def content_length(self):
        if self.get_all('transfer-encoding'):
            return None
        v = self.header('content-length').strip()
        return int(v) if v.isdigit() else None

    async def wait_continue(self):
        if self.conn.h11.they_are_waiting_for_100_continue:  # only HTTP/1.1 clients (RFC 9110 10.1.1): h11 knows
            await self.conn.send(h11.InformationalResponse(status_code=100, headers=[]))

    async def body_chunks(self):
        while True:
            try:
                ev = await self.conn.next_event(KEEPALIVE_TIMEOUT)
            except h11.RemoteProtocolError as e:
                raise ValueError(str(e)) from e
            if isinstance(ev, h11.Data):
                yield bytes(ev.data)
            elif isinstance(ev, h11.EndOfMessage):
                return
            else:
                raise ValueError('the client closed the connection before the end of the body')

    @staticmethod
    def _encode(headers):
        return [(k.encode('latin-1'), str(v).encode('latin-1')) for k, v in headers if k.lower() != 'connection']

    async def start(self, status, reason, headers, end=False, close=False):
        self.started = True
        hdrs = self._encode(headers)
        if close or not self.keep_alive:
            hdrs.append((b'connection', b'close'))
        await self.conn.send(h11.Response(status_code=status, headers=hdrs, reason=(reason or _phrase(status)).encode('latin-1')))

    async def send(self, data):
        if data:
            await self.conn.send(h11.Data(data=data))

    async def finish(self):
        await self.conn.send(h11.EndOfMessage())

    async def respond(self, status, reason, headers, body=b'', close=False):
        if self.started:
            return
        try:
            await self.start(status, reason, [*headers, ('Content-Length', str(len(body)))], close=close)
            if body and self.method != 'HEAD':
                await self.send(body)
            await self.finish()
        except h11.LocalProtocolError:
            # the client broke the protocol (h11 refuses to go on): answered by hand, then the connection is closed
            head = f'HTTP/1.1 {status} {reason or _phrase(status)}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n'
            head += ''.join(f'{k}: {v}\r\n' for k, v in headers)
            await self.conn.stream.write(head.encode('latin-1') + b'\r\n' + (body if self.method != 'HEAD' else b''))
            self.conn.broken = True

    async def establish(self):
        """Answer a CONNECT with 200 and hand over the raw connection, with what the client already sent behind its request."""
        while self.conn.h11.their_state is h11.SEND_BODY:
            await self.conn.next_event(KEEPALIVE_TIMEOUT)
        await self.conn.send(h11.Response(status_code=200, headers=[], reason=b'Connection Established'))
        self.conn.taken = True
        data, _ = self.conn.h11.trailing_data
        stream = self.conn.stream
        return RawStream(stream.reader, stream.writer, prefix=bytes(data) + stream.take_prefix())


class H1Connection:
    def __init__(self, client, stream, mitm=None):
        self.client = client
        self.stream = stream
        self.mitm = mitm
        self.h11 = h11.Connection(h11.SERVER, max_incomplete_event_size=65536)
        self.handled = 0
        self.taken = False
        self.broken = False

    async def next_event(self, timeout):
        while True:
            ev = self.h11.next_event()
            if ev is h11.NEED_DATA:
                self.h11.receive_data(await self.stream.read(65536, timeout))
                continue
            return ev

    async def send(self, ev):
        data = self.h11.send(ev)
        if data:
            await self.stream.write(data)

    async def run(self):
        try:
            while True:
                timeout = FIRST_REQUEST_TIMEOUT if not self.handled else (15 if self.mitm else KEEPALIVE_TIMEOUT)
                try:
                    ev = await self.next_event(timeout)
                except h11.RemoteProtocolError as e:
                    status = e.error_status_hint or 400
                    self.client.log('', '', '', 'error', status, f'Bad request: {e}'[:255], None)
                    body = f'{_phrase(status)}\n'.encode()
                    await self.stream.write(f'HTTP/1.1 {status} {_phrase(status)}\r\nContent-Type: text/plain; charset=utf-8\r\n'
                                            f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
                    return
                if not isinstance(ev, h11.Request):
                    return  # the client closed the connection
                ex = H1Exchange(self, ev)
                self.handled += 1
                await self.client.handle(ex, self.mitm)
                if self.taken or self.broken:
                    return
                if self.h11.our_state is h11.DONE and self.h11.their_state is h11.DONE:
                    self.h11.start_next_cycle()
                else:
                    if self.h11.our_state in (h11.DONE, h11.MUST_CLOSE) and self.h11.their_state is h11.SEND_BODY:
                        await _linger(self.stream)  # answered before the end of the body (413, blocked): let the client read it
                    return  # a body not read to its end, or "Connection: close": the connection ends here
        except (OSError, TimeoutError, h11.LocalProtocolError, StreamGone, ssl.SSLError):
            return


LINGER_SECONDS = 5
LINGER_BYTES = 64 * 1024 * 1024


async def _linger(stream):
    """Close the sending side and throw away what the client still sends for a while, then close (RFC 9112 9.6). Closing at once,
    with its body still arriving, makes the kernel reset the connection, and the client may lose the answer it was sent."""
    raw = getattr(stream, 'raw', stream)
    try:
        raw.write_eof()
        loop = asyncio.get_running_loop()
        end, total = loop.time() + LINGER_SECONDS, 0
        while total < LINGER_BYTES and (left := end - loop.time()) > 0:
            data = await raw.read(65536, left)
            if not data:
                return
            total += len(data)
    except (OSError, TimeoutError, ssl.SSLError):
        pass


class Client:
    """One accepted client connection: who it is, and the handling of its requests (HTTP/1.1 or HTTP/2 exchanges alike)."""

    def __init__(self, server, client_address, sockname):
        self.server = server
        self.client_address = client_address
        self.client_ip = str(client_address[0] or '')
        self.sockname = sockname

    def log(self, method, host, url, outcome, status_code=200, reason='', t0=None):
        logger = getattr(self.server, 'log', None)
        if not logger:
            return
        ms = max(0, int((time.monotonic() - t0) * 1000)) if t0 is not None else 0
        entry = ProxyLog(
            client=self.client_ip[:45],
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

    def own_ips(self, s):
        """This server's addresses: the one the client reached and the configured ones (none in the tests, that allow loopback)."""
        if getattr(self.server, 'allow_loopback', False):
            return frozenset()
        out = set()
        if isinstance(self.sockname, tuple):
            out.add(self.sockname[0])
        for v in (getattr(s, 'DHCP_SERVER', ''), getattr(s, 'PROXY_ADDRESS', '')):
            if v and str(v) not in ('0.0.0.0', '::'):
                out.add(str(v))
        return frozenset(out)

    @staticmethod
    async def text(ex, status, text, close=True, extra=None):
        await ex.respond(status, '', [('Content-Type', 'text/plain; charset=utf-8'), *(extra or {}).items()], text if isinstance(text, bytes) else text.encode(), close=close)

    async def handle(self, ex, mitm=None):
        try:
            if ex.method == 'CONNECT':
                if mitm and getattr(ex, 'protocol', '') == 'websocket':
                    await self.http(ex, scheme='https', default_host=mitm[0], default_port=mitm[1])  # RFC 8441: a WebSocket on an h2 stream
                elif mitm:
                    await self.text(ex, 405, 'CONNECT inside a tunnel is not supported')
                else:
                    await self.connect(ex)
            elif mitm:
                await self.http(ex, scheme='https', default_host=mitm[0], default_port=mitm[1])
            else:
                await self.http(ex)
        except (OSError, StreamGone, h11.LocalProtocolError, ssl.SSLError, TimeoutError):
            raise  # the client's connection: the caller ends it
        except Exception as e:
            # a bug or the database gone: the client gets an answer, the log the reason
            _warn(f'{ex.method} {ex.target}: {_why(e)}')
            self.log(ex.method, mitm[0] if mitm else '', ex.target, 'error', 500, f'Internal error: {_why(e)}', None)
            if ex.started:
                await self.abort(ex)
            else:
                await self.text(ex, 500, 'Internal error')

    async def blocked(self, ex, reason, detail, path=''):
        """A blocked request gets what the page expects (an empty script, style, image or JSON) so it does not show an "ad blocker" wall."""
        header_val = f'Zones.dns ({reason}: {detail})'
        hdrs = [
            ('X-Blocked-By', header_val),
            ('Access-Control-Allow-Origin', ex.header('origin') or '*'),
            ('Access-Control-Allow-Credentials', 'true'),
            ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD'),
            ('Access-Control-Allow-Headers', '*'),
            ('Cache-Control', 'no-store'),
        ]

        async def send(status, ctype, body):
            await ex.respond(status, '', [('Content-Type', ctype), *hdrs], body)

        if ex.method == 'OPTIONS':
            return await send(204, 'text/plain; charset=utf-8', b'')
        low_path = (path or '').lower().partition('?')[0]
        accept = ex.header('accept').lower()
        sec_dest = ex.header('sec-fetch-dest').strip().lower()
        sec_mode = ex.header('sec-fetch-mode').strip().lower()
        if low_path.endswith('.js') or low_path.endswith('/gtag/js') or '/widget/' in low_path or 'javascript' in accept or sec_dest == 'script':
            await send(200, 'application/javascript; charset=utf-8', SURROGATE_JS)
        elif low_path.endswith('.css') or 'text/css' in accept or sec_dest == 'style':
            await send(200, 'text/css; charset=utf-8', b'/* blocked by Zones.dns */\n')
        elif low_path.endswith('.map'):
            await send(200, 'application/json; charset=utf-8', b'{"version":3,"sources":[],"mappings":""}')
        elif low_path.endswith(('.gif', '.png', '.jpg', '.jpeg', '.webp', '.ico', '.svg')) or accept.startswith('image/') or sec_dest == 'image':
            await send(200, 'image/gif', TRANSPARENT_GIF)
        elif (
            low_path.endswith(('.html', '.htm'))
            or sec_dest in ('document', 'iframe')
            or ('text/html' in accept and sec_mode in ('', 'navigate'))
            or (not accept and sec_dest == '' and ex.method == 'GET' and not low_path.endswith('.json') and '/settings' not in low_path)
        ):
            await send(403, 'text/html; charset=utf-8', f'<!doctype html><title>Blocked</title><!-- blocked by {header_val} -->'.encode())
        else:
            await send(200, 'application/json; charset=utf-8', SURROGATE_JSON)

    async def local(self, ex, s):
        """/wpad.dat, /proxy.pac, /ca.crt (/ca.pem) and /proxy.mobileconfig asked directly of the proxy port. True when answered."""
        path = ex.target.partition('?')[0]
        if path in ('/wpad.dat', '/proxy.pac'):
            body = (await _run(_WORK, pac.build_pac, s, request_host=ex.header('host'))).encode('utf-8')
            await ex.respond(200, '', [('Content-Type', 'application/x-ns-proxy-autoconfig; charset=utf-8'), ('Cache-Control', 'no-cache')], body, close=True)
            return True
        if path in ('/ca.crt', '/ca.pem', '/proxy.mobileconfig') and str(settings.GUI_URL).startswith('https://'):
            # plain HTTP lets anyone on the path swap the certificate for their own: the GUI serves both over https
            target = settings.GUI_URL.rstrip('/') + ('/proxy.mobileconfig' if path == '/proxy.mobileconfig' else '/proxy-ca.crt')
            await ex.respond(302, '', [('Location', target)], b'', close=True)
            return True
        if path in ('/ca.crt', '/ca.pem'):
            cert_pem = (await _run(_WORK, pfilter.run_on_db_pool, ca.ensure_ca, refresh=True))[0]
            await ex.respond(200, '', [('Content-Type', 'application/x-x509-ca-cert'), ('Content-Disposition', 'attachment; filename="zones-proxy-ca.crt"')],
                             cert_pem.encode('utf-8'), close=True)
            return True
        if path == '/proxy.mobileconfig':
            cert_pem = (await _run(_WORK, pfilter.run_on_db_pool, ca.ensure_ca, refresh=True))[0]
            body = await _run(_WORK, pac.build_mobileconfig, s, ca_cert_pem=cert_pem, request_host=ex.header('host'))
            await ex.respond(200, '', [('Content-Type', 'application/x-apple-aspen-config'), ('Content-Disposition', 'attachment; filename="zones-proxy.mobileconfig"')],
                             body, close=True)
            return True
        return False

    async def read_body(self, ex):
        """(body, length): None, bytes (small: can be sent again) or an async iterator that streams a large body without holding it;
        length: the Content-Length to forward for a streamed body, when the client gave one. Raises BodyTooLarge, ValueError (bad framing)."""
        n = ex.content_length()
        if n is not None and n > MAX_REQUEST_BYTES:
            raise BodyTooLarge('request body too large')
        chunks = ex.body_chunks()
        head, size = [], 0
        while True:
            try:
                part = await chunks.__anext__()
            except StopAsyncIteration:
                return b''.join(head) or None, None
            size += len(part)
            if size > MAX_REQUEST_BYTES:
                raise BodyTooLarge('request body too large')
            head.append(part)
            if size > MAX_BUFFERED_BODY:
                break

        async def rest(total=size):
            for p in head:
                yield p
            async for p in chunks:
                total += len(p)
                if total > MAX_REQUEST_BYTES:
                    raise BodyTooLarge('request body too large')
                yield p
        return rest(), n

    async def http(self, ex, scheme=None, default_host=None, default_port=None):
        t0 = time.monotonic()
        if not ratelimit.allowed(self.client_ip):
            self.log(ex.method, '', ex.target, 'error', 403, 'Client refused (DNS_ALLOW_QUERY or rate limit)', t0)
            return await self.text(ex, 403, 'Forbidden')
        s = await _run(_WORK, self.server.settings_getter)
        target = ex.target
        if target.startswith('/') and scheme is None:
            if await self.local(ex, s):
                return
            host_hdr = ex.header('host')
            if not host_hdr:
                self.log(ex.method, '', target, 'error', 400, 'No Host header', t0)
                return await self.text(ex, 400, 'Bad Request')
            full_url = f'http://{host_hdr}{target}'
        elif target.startswith(('http://', 'https://')):
            full_url = target
        elif scheme and default_host:
            port_part = f':{default_port}' if default_port and default_port not in (80, 443) else ''
            full_url = f'{scheme}://{default_host}{port_part}{target}'
        else:
            self.log(ex.method, '', target, 'error', 400, 'Unusable request target', t0)
            return await self.text(ex, 400, 'Bad Request')

        parts = urlsplit(full_url)
        target_scheme = (parts.scheme or scheme or 'http').lower()
        host = (parts.hostname or default_host or '').lower()
        try:
            port = parts.port or default_port or (443 if target_scheme == 'https' else 80)
        except ValueError:  # a port that is not a number or out of range
            self.log(ex.method, '', full_url, 'error', 400, 'Bad port in the request target', t0)
            return await self.text(ex, 400, 'Bad Request')
        path_query = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')
        log_method = f'MITM {ex.method}' if scheme == 'https' else ex.method

        if not host:
            self.log(log_method, '', full_url, 'error', 400, 'Missing target host', t0)
            return await self.text(ex, 400, 'Missing target host')

        if hit := await _run(_WORK, pfilter.check_request, host, full_url, s=s):
            self.log(log_method, host, full_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            return await self.blocked(ex, hit[0], hit[1], path=parts.path)

        if ex.method == 'OPTIONS' and ex.header('max-forwards').strip() == '0':
            # RFC 9110 7.6.2: Max-Forwards 0 means the request is for this proxy, it goes no further
            return await ex.respond(200, '', [('Allow', 'GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH, CONNECT')], b'')

        own_ips = self.own_ips(s)
        allow_loopback = bool(getattr(self.server, 'allow_loopback', False))
        try:
            addrs = await _run(_DNS, _resolve_target, host, port, allow_loopback=allow_loopback, own_ips=own_ips)
        except PermissionError:
            self.log(log_method, host, full_url, 'error', 403, 'Forbidden target address', t0)
            return await self.text(ex, 403, 'Forbidden target address')
        except OSError:
            self.log(log_method, host, full_url, 'error', 502, 'DNS lookup failed', t0)
            return await self.text(ex, 502, 'Bad Gateway: DNS lookup failed')

        ws_tokens = {t.strip().lower() for v in ex.get_all('connection') for t in v.split(',')}
        if (ex.method == 'GET' and ex.header('upgrade').lower() == 'websocket' and 'upgrade' in ws_tokens) or getattr(ex, 'protocol', '') == 'websocket':
            return await self.websocket(ex, target_scheme, host, port, addrs, path_query, s, SimpleCtx(
                ex=ex, s=s, host=host, full_url=full_url, path_query=path_query, log_method=log_method, t0=t0, may_filter=False))

        try:
            await ex.wait_continue()
            req_body, stream_len = await self.read_body(ex)
        except BodyTooLarge:
            self.log(log_method, host, full_url, 'error', 413, 'Request body too large', t0)
            return await self.text(ex, 413, 'Request body too large')
        except (ValueError, OSError, StreamGone) as e:
            self.log(log_method, host, full_url, 'error', 400, f'Bad request body: {_why(e)}', t0)
            return await self.text(ex, 400, 'Bad request body')
        resendable = req_body is None or isinstance(req_body, bytes)

        sec_dest = ex.header('sec-fetch-dest').strip().lower()
        is_bg_fetch = (sec_dest and sec_dest != 'document') or ex.header('x-requested-with').strip().lower() == 'xmlhttprequest'
        filter_enabled = bool(getattr(s, 'PROXY_BLOCK_ADS', True) or getattr(s, 'PROXY_BLOCK_POPUPS', True))
        may_filter = filter_enabled and not is_bg_fetch and ex.method != 'HEAD'  # only a page itself is filtered, never what it fetches
        hop = _hop_headers(ex.get_all('connection'))
        fwd = {}
        for k, v in ex.headers:
            kl = k.lower()
            # content-length: the proxy frames the body it sends; the client's own next to a chunked body is request smuggling
            if kl in hop or kl in ('host', 'expect', 'content-length', 'via', 'max-forwards'):
                continue
            if kl == 'accept-encoding' and may_filter:
                continue
            # a field sent twice is one list (RFC 9110 5.3), not the last of them; Cookie lines are joined with "; " (RFC 6265 5.4)
            fwd[k] = f'{fwd[k]}{"; " if kl == "cookie" else ", "}{v}' if k in fwd else v
        host_url = f'[{host}]' if ':' in host else host
        fwd['Host'] = f'{host_url}:{port}' if port not in (80, 443) else host_url
        fwd['Via'] = _with_via(', '.join(ex.get_all('via')))
        if (mf := ex.header('max-forwards').strip()).isdigit():
            fwd['Max-Forwards'] = str(int(mf) - 1) if ex.method == 'OPTIONS' else mf
        if isinstance(req_body, bytes):
            fwd['Content-Length'] = str(len(req_body))
        elif req_body is None:
            if ex.method in ('POST', 'PUT', 'PATCH'):
                fwd['Content-Length'] = '0'
        elif stream_len is not None:
            fwd['Content-Length'] = str(stream_len)
        else:
            fwd['Transfer-Encoding'] = 'chunked'  # dropped again if the server speaks HTTP/2
        if may_filter:
            fwd['Accept-Encoding'] = 'gzip, deflate'

        info = SimpleCtx(ex=ex, s=s, host=host, full_url=full_url, path_query=path_query, log_method=log_method, t0=t0, may_filter=may_filter)
        fetcher = getattr(self.server, 'http_fetcher', None)
        if fetcher is not None:  # the tests' stand-in for the network
            body = req_body if resendable else b''.join([p async for p in req_body])
            try:
                status, reason, resp_headers, raw_body = await _run(_WORK, fetcher, target_scheme, host, port, ex.method, path_query, body, fwd)
            except Exception as e:
                self.log(log_method, host, full_url, 'error', 502, f'Bad Gateway: {_why(e)}', t0)
                return await self.text(ex, 502, 'Bad Gateway')
            return await self.page(info, status, reason, list(resp_headers), raw_body)

        pool = upstream.pool_for(self.server, _resolve_target, _DNS)
        url = f'{target_scheme}://{host_url}:{port}{path_query}'
        token = upstream.target_rules.set((allow_loopback, own_ips))
        idempotent = ex.method in IDEMPOTENT and resendable
        try:
            if not resendable:
                # a large upload: Expect: 100-continue and the answer read while it goes out, so a refusal (413) reaches the client
                ctx = getattr(self.server, 'upstream_ssl_context', None) or upload.h1_ssl_context
                stream = await upload.open_h1(target_scheme, host, port, addrs, ctx, UPSTREAM_TIMEOUTS['connect'])
                try:
                    resp = await upload.upload(stream, ex.method, path_query, list(fwd.items()), req_body, UPSTREAM_TIMEOUTS['read'])
                    info.responded = True
                    await self.relay(info, resp)
                finally:
                    await stream.aclose()
                return
            for attempt in (0, 1):
                info.responded = False
                try:
                    async with pool.stream(ex.method, url, headers=list(fwd.items()), content=req_body,
                                           extensions={'timeout': UPSTREAM_TIMEOUTS}) as resp:
                        info.responded = True
                        await self.relay(info, resp)
                    return
                except _RETRYABLE:
                    # a kept-alive connection the server had closed: once more on a new one, only for a request that may be sent twice
                    if info.responded or attempt or not idempotent:
                        raise
        except BodyTooLarge:
            self.log(log_method, host, full_url, 'error', 413, 'Request body too large', t0)
            await self.text(ex, 413, 'Request body too large')
        except StreamGone:
            pass  # HTTP/2: the client reset the stream
        except Exception as e:
            if ex.started:
                self.log(log_method, host, full_url, 'error', info.status, f'Upstream failed while streaming: {_why(e)}', t0)
                await self.abort(ex)
            else:
                self.log(log_method, host, full_url, 'error', 502, f'Bad Gateway: {_why(e)}', t0)
                await self.text(ex, 502, 'Bad Gateway')
        finally:
            upstream.target_rules.reset(token)

    async def websocket(self, ex, scheme, host, port, addrs, path_query, s, info):
        """A WebSocket (RFC 6455) through the proxy, also inside HTTPS inspection: the handshake goes to the server over HTTP/1.1,
        then the frames pass unchanged both ways. From an HTTP/2 client (RFC 8441, extended CONNECT) the stream carries the frames."""
        hop = _hop_headers(ex.get_all('connection'))
        h2_client = ex.version == 'HTTP/2'
        fwd = [(k, v) for k, v in ex.headers if k.lower() not in hop and k.lower() not in ('host', 'via', 'sec-websocket-key', 'content-length')]
        host_url = f'[{host}]' if ':' in host else host
        fwd = [('Host', f'{host_url}:{port}' if port not in (80, 443) else host_url), *fwd, ('Via', _with_via(', '.join(ex.get_all('via'))))]
        if not any(k.lower() == 'sec-websocket-version' for k, _ in fwd):
            fwd.append(('Sec-WebSocket-Version', '13'))
        # an HTTP/1.1 client's key goes on (its browser checks the server's accept against it); an HTTP/2 client has none
        fwd.append(('Sec-WebSocket-Key', ex.header('sec-websocket-key') or upload.websocket_key()))
        ctx = getattr(self.server, 'upstream_ssl_context', None) or upload.h1_ssl_context
        if not h2_client:
            while ex.conn.h11.their_state is h11.SEND_BODY:  # the end of the client's request, before h11 lets it switch protocol
                await ex.conn.next_event(KEEPALIVE_TIMEOUT)
        try:
            stream = await upload.open_h1(scheme, host, port, addrs, ctx, UPSTREAM_TIMEOUTS['connect'])
        except (OSError, TimeoutError, ssl.SSLError) as e:
            self.log(info.log_method, host, info.full_url, 'error', 502, f'Bad Gateway: {_why(e)}', info.t0)
            return await self.text(ex, 502, 'Bad Gateway')
        try:
            conn, ev = await upload.websocket_handshake(stream, path_query, fwd, UPSTREAM_TIMEOUTS['read'])
            if not (isinstance(ev, h11.InformationalResponse) and ev.status_code == 101):
                if isinstance(ev, h11.Response):  # refused (403, 404...): that answer goes to the client
                    info.responded = True
                    return await self.relay(info, upload.H1Response(conn, stream, ev, UPSTREAM_TIMEOUTS['read']))
                raise ConnectionError('no answer to the WebSocket handshake')
            rh = [(k.decode('latin-1'), v.decode('latin-1')) for k, v in ev.headers.raw_items()]
            up = Prefixed(stream, bytes(conn.trailing_data[0]))
            self.log(info.log_method, host, info.full_url, 'allowed', 101, 'WebSocket', info.t0)
            if h2_client:
                keep = [(k, v) for k, v in rh if k.lower() in ('sec-websocket-protocol', 'sec-websocket-extensions')]
                await ex.start(200, '', keep)
                await _pipe_h2(ex, up)
            else:
                await ex.conn.send(h11.InformationalResponse(status_code=101, headers=H1Exchange._encode(rh) + [(b'connection', b'Upgrade')],
                                                             reason=b'Switching Protocols'))
                ex.conn.taken = True
                client = Prefixed(ex.conn.stream, bytes(ex.conn.h11.trailing_data[0]))
                await _pipe(client, up)
        except (OSError, TimeoutError, ssl.SSLError, h11.ProtocolError, ConnectionError) as e:
            if not ex.started and not getattr(ex.conn, 'taken', False):
                self.log(info.log_method, host, info.full_url, 'error', 502, f'Bad Gateway: {_why(e)}', info.t0)
                await self.text(ex, 502, 'Bad Gateway')
        finally:
            await stream.aclose()

    @staticmethod
    async def abort(ex):
        """The answer has started and cannot be completed: the client must see a broken message, not a short one that looks whole."""
        conn = getattr(ex, 'conn', None)
        if isinstance(conn, H1Connection):
            conn.broken = True  # HTTP/1.1: the connection is closed; HTTP/2: the stream is reset when the handler returns

    async def relay(self, info, resp):
        ex = info.ex
        status = resp.status
        info.status = status
        reason = (resp.extensions.get('reason_phrase') or b'').decode('latin-1') or _phrase(status)
        rh = [(k.decode('latin-1'), v.decode('latin-1')) for k, v in resp.headers]

        def get(name):
            return next((v for k, v in rh if k.lower() == name), '')
        ctype, cache_control = get('content-type'), get('cache-control')
        clen_hdr = get('content-length').strip()
        chunked_up = 'chunked' in get('transfer-encoding').lower()
        low_ctype = ctype.lower()
        no_body = ex.method == 'HEAD' or status in (204, 304)
        buffer_html = (
            info.may_filter and not no_body and 'text/html' in low_ctype and '/cdn-cgi/' not in info.path_query
            and 'no-transform' not in cache_control.lower()  # RFC 9110 7.7: a proxy must not transform it
            and not (clen_hdr.isdigit() and not chunked_up and int(clen_hdr) > MAX_HTML_BYTES)
        )
        chunks = resp.aiter_stream()
        prefix = b''
        if buffer_html:
            buf = bytearray()
            async for chunk in chunks:
                buf += chunk
                if len(buf) > MAX_HTML_BYTES:
                    break
            if len(buf) > MAX_HTML_BYTES:
                prefix, buffer_html = bytes(buf), False  # too big to filter: relayed as it comes, starting with what was read
            else:
                return await self.page(info, status, reason, rh, bytes(buf))

        # Relayed as it arrives: long polls and streams (Exchange EWS streaming notifications, Teams trouter, SSE) never end
        hop_resp = _hop_headers([v for k, v in rh if k.lower() == 'connection'])
        headers = [(k, v) for k, v in rh if k.lower() not in hop_resp and k.lower() != 'via' and not (k.lower() == 'content-length' and chunked_up)]
        headers.append(('Via', _with_via(get('via'))))
        await ex.start(status, reason, headers, end=no_body and ex.version == 'HTTP/2')
        if no_body:
            if ex.version != 'HTTP/2':
                await ex.finish()
            self.log(info.log_method, info.host, info.full_url, 'allowed', status, ctype.partition(';')[0] or 'stream', info.t0)
            return
        try:
            if prefix:
                await ex.send(prefix)
            async for chunk in chunks:
                await ex.send(chunk)
            await ex.finish()
        except (OSError, StreamGone, h11.LocalProtocolError) as e:
            if isinstance(e, h11.LocalProtocolError):
                raise  # the server sent less than its Content-Length
            # the client gave up (a video seek, a closed tab): not an error of ours
            self.log(info.log_method, info.host, info.full_url, 'allowed', status, 'client closed the connection', info.t0)
            await self.abort(ex)
            return
        self.log(info.log_method, info.host, info.full_url, 'allowed', status, ctype.partition(';')[0] or 'stream', info.t0)

    async def page(self, info, status, reason, rh, raw_body):
        """A whole answer in hand (an HTML page to filter, or the tests' stand-in): filtered when it is a page, then sent with its length."""
        ex = info.ex

        def get(name):
            return next((v for k, v in rh if k.lower() == name), '')
        ctype, cenc, cache_control = get('content-type'), get('content-encoding'), get('cache-control')
        csp = ', '.join(v for k, v in rh if k.lower() == 'content-security-policy')
        hop_resp = _hop_headers([v for k, v in rh if k.lower() == 'connection'])
        out_headers = [(k, v) for k, v in rh if k.lower() not in hop_resp and k.lower() not in ('content-length', 'content-encoding', 'via')]
        html_filtered = False
        if (
            info.may_filter and '/cdn-cgi/' not in info.path_query and 'text/html' in ctype.lower()
            and 'no-transform' not in cache_control.lower() and len(raw_body) <= MAX_HTML_BYTES
        ):
            try:
                raw_body, html_filtered = await _run(_WORK, _filter_page, raw_body, cenc, ctype, info.host, info.s, csp)
                cenc = ''
                out_headers = [(k, v) for k, v in out_headers if k.lower() != 'etag']
            except Exception:
                pass
        self.log(info.log_method, info.host, info.full_url, 'filtered' if html_filtered else 'allowed', status,
                 'HTML filtered' if html_filtered else (ctype.partition(';')[0] or 'HTTP'), info.t0)
        if cenc:
            out_headers.append(('Content-Encoding', cenc))
        out_headers.append(('Via', _with_via(get('via'))))
        await ex.respond(status, reason, out_headers, raw_body)

    async def connect(self, ex):
        t0 = time.monotonic()
        if not ratelimit.allowed(self.client_ip):
            return await self.text(ex, 403, 'Forbidden')
        s = await _run(_WORK, self.server.settings_getter)
        host_port = ex.target.strip()
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
            self.log('CONNECT', host, target_url, 'error', 403, f'Port {port} is not allowed for CONNECT (PROXY_CONNECT_PORTS)', t0)
            return await self.text(ex, 403, 'Forbidden port')
        allow_domains, _, _, _ = pfilter.parse_custom_rules(getattr(s, 'PROXY_CUSTOM_RULES', ''))
        bypassed = is_mitm_failed(self.client_ip, host)
        if bool(getattr(s, 'PROXY_HTTPS_MITM', False)) and not pfilter.is_domain_allowed(host, allow_domains) and not bypassed:
            # accepted locally without contacting the server yet: blocked trackers inside the tunnel get a stealth surrogate from blocked()
            # instead of a CONNECT 403 network error that triggers "Ad Blocker Detected" walls
            return await self.mitm(ex, host, port, target_url, t0)

        if hit := await _run(_WORK, pfilter.check_request, host, target_url, s=s):
            self.log('CONNECT', host, target_url, 'blocked', 403, f'{hit[0]}: {hit[1]}', t0)
            return await self.text(ex, 403, 'Blocked by Zones.dns', extra={'X-Blocked-By': f'Zones.dns ({hit[0]}: {hit[1]})'})
        try:
            addrs = await _run(_DNS, _resolve_target, host, port, allow_loopback=bool(getattr(self.server, 'allow_loopback', False)), own_ips=self.own_ips(s))
        except PermissionError:
            self.log('CONNECT', host, target_url, 'error', 403, 'Forbidden target address', t0)
            return await self.text(ex, 403, 'Forbidden target address')
        except OSError:
            self.log('CONNECT', host, target_url, 'error', 502, 'DNS lookup failed', t0)
            return await self.text(ex, 502, 'Bad Gateway: DNS lookup failed')
        try:
            up = await self.open_tunnel(host, port, addrs)
        except (OSError, TimeoutError) as e:
            self.log('CONNECT', host, target_url, 'error', 502, f'Bad Gateway: {_why(e)}', t0)
            return await self.text(ex, 502, 'Bad Gateway')
        self.log('CONNECT', host, target_url, 'allowed', 200, 'CONNECT tunnel (MITM auto-bypass)' if bypassed else 'CONNECT tunnel', t0)
        try:
            client = await ex.establish()
            await _pipe(client, up)
        finally:
            await up.aclose()

    async def open_tunnel(self, host, port, addrs):
        factory = getattr(self.server, 'tunnel_factory', None)
        if factory is not None:  # the tests' stand-in: a connected socket
            r, w = await asyncio.open_connection(sock=factory(host, port))
            return RawStream(r, w)
        err = None
        for _, (ip, p) in addrs:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), 15 if len(addrs) == 1 else 5)
                keepalive(w)
                return RawStream(r, w)
            except (OSError, TimeoutError) as e:
                err = e
        raise err or OSError('no address to connect to')

    async def mitm(self, ex, host, port, target_url, t0):
        raw = await ex.establish()
        try:
            ctx = await _run(_WORK, pfilter.run_on_db_pool, ca.leaf_context, host)
        except Exception as e:
            _warn(f'MITM {host}: {_why(e)}')
            self.log('MITM', host, target_url, 'error', 500, f'Internal error: {_why(e)}', t0)
            return
        tls = TLSStream(raw, ctx)
        try:
            await tls.handshake()
        except (ssl.SSLError, OSError, TimeoutError) as e:
            record_mitm_failure(self.client_ip, host)
            self.log('MITM', host, target_url, 'allowed', 200, f'TLS pin/CA fallback -> CONNECT ({_why(e)})', t0)
            return
        try:
            if tls.alpn() == 'h2':
                conn = H2Connection(tls, lambda x: self.handle(x, (host, port)))
            else:
                conn = H1Connection(self, tls, mitm=(host, port))
            await conn.run()
            if conn.handled == 0 and note_empty_mitm_session(self.client_ip, host):
                self.log('MITM', host, target_url, 'allowed', 200, 'TLS sessions without requests (pinning?) -> CONNECT', t0)
        except Exception as e:
            _warn(f'MITM {host}: {_why(e)}')
            self.log('MITM', host, target_url, 'error', 500, f'Internal error: {_why(e)}', t0)
        finally:
            await tls.aclose()


class SimpleCtx:
    """What relay() and page() need to know about the request they answer."""

    def __init__(self, **kw):
        self.status = 0
        self.responded = False
        self.__dict__.update(kw)


async def _pipe(a, b):
    """Copy both ways until one side closes, or both have been silent for TUNNEL_IDLE seconds."""
    last = [time.monotonic()]

    async def copy(src, dst):
        while True:
            try:
                data = await src.read(65536, TUNNEL_IDLE)
            except TimeoutError:
                if time.monotonic() - last[0] < TUNNEL_IDLE:
                    continue  # the other direction is busy (a download): not idle
                return
            if not data:
                return
            last[0] = time.monotonic()
            await dst.write(data)

    tasks = [asyncio.create_task(copy(a, b)), asyncio.create_task(copy(b, a))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _pipe_h2(ex, up):
    """A WebSocket on an HTTP/2 stream (RFC 8441): the stream's DATA to the server, the server's bytes back as DATA."""
    async def to_server():
        async for chunk in ex.body_chunks(TUNNEL_IDLE):
            await up.write(chunk)

    async def to_client():
        while True:
            data = await up.read(65536, TUNNEL_IDLE)
            if not data:
                await ex.finish()
                return
            await ex.send(data)

    tasks = [asyncio.create_task(to_server()), asyncio.create_task(to_client())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def handle_client(server, reader, writer, client_address):
    keepalive(writer)
    stream = RawStream(reader, writer)
    client = Client(server, client_address, writer.get_extra_info('sockname'))
    try:
        await H1Connection(client, stream).run()
    finally:
        await stream.aclose()


def serve_connection(sock, client_address, server):
    """Serve one already-connected socket until it closes, on an event loop of its own (the tests drive the proxy this way)."""
    async def main():
        reader, writer = await asyncio.open_connection(sock=sock)
        try:
            await handle_client(server, reader, writer, client_address)
        finally:
            pool = getattr(server, '_upstream_pool', None)
            if pool is not None and getattr(server, '_upstream_loop', None) is asyncio.get_running_loop():
                await pool.aclose()
                server._upstream_pool = None
    asyncio.run(main())


class ProxyServer:
    """The listening proxy: `await start()`, then it serves on the running loop until `close()`."""

    def __init__(self, server_address, settings_getter=None, allow_loopback=False, upstream_ssl_context=None, log=None):
        self.server_address = server_address
        self.settings_getter = settings_getter or cached_proxy_settings
        self.allow_loopback = allow_loopback
        self.upstream_ssl_context = upstream_ssl_context
        self.log = log
        self._per_client = {}
        self._total = 0
        self._srv = None

    async def start(self):
        host, port = self.server_address
        self._srv = await asyncio.start_server(self._accept, host, port, backlog=1024, reuse_address=True, limit=65536)
        return self

    async def _accept(self, reader, writer):
        peer = writer.get_extra_info('peername') or ('', 0)
        ip = peer[0]
        if self._per_client.get(ip, 0) >= PER_CLIENT_MAX or self._total >= MAX_CLIENT_CONNECTIONS:
            writer.close()
            return
        self._per_client[ip] = self._per_client.get(ip, 0) + 1
        self._total += 1
        try:
            await handle_client(self, reader, writer, peer)
        except Exception as e:
            _warn(f'connection from {ip}: {_why(e)}')
        finally:
            self._total -= 1
            n = self._per_client.get(ip, 1) - 1
            if n > 0:
                self._per_client[ip] = n
            else:
                self._per_client.pop(ip, None)

    def close(self):
        if self._srv is not None:
            self._srv.close()
