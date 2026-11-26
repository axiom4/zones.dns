"""Upstream connections of the proxy: one httpcore pool (HTTP/1.1 and HTTP/2, kept-alive connections) per proxy server and event loop.

httpcore opens every connection through _Backend: the name is resolved by the proxy's own resolver and checked against the SSRF rules
(the same _resolve_target as the request), the next address is tried when one does not answer, and after the TLS handshake the
certificate is checked for revocation.
"""
import asyncio
import contextvars
import socket
import ssl

import h2.errors
import h2.events
import httpcore
import httpcore._async.http2

from . import revocation

target_rules = contextvars.ContextVar('target_rules', default=(False, frozenset()))  # (allow_loopback, own_ips) of the request being served

_default_ssl_context = ssl.create_default_context()  # building one loads the CA store (tens of ms): once
KEEPALIVE_EXPIRY = 20.0
MAX_CONNECTIONS = 1024


class _Stream(httpcore.AsyncNetworkStream):
    def __init__(self, inner):
        self._inner = inner

    async def read(self, max_bytes, timeout=None):
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer, timeout=None):
        await self._inner.write(buffer, timeout)

    async def aclose(self):
        await self._inner.aclose()

    def get_extra_info(self, info):
        return self._inner.get_extra_info(info)

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        tls = await self._inner.start_tls(ssl_context, server_hostname=server_hostname, timeout=timeout)
        obj = tls.get_extra_info('ssl_object')
        if obj is not None and revocation.is_revoked(obj.get_verified_chain()):
            await tls.aclose()
            raise httpcore.ConnectError(f'the certificate of {server_hostname} is revoked')
        return _Stream(tls)


class _Backend(httpcore.AsyncNetworkBackend):
    def __init__(self, resolve, executor):
        self._inner = httpcore.AnyIOBackend()
        self._resolve = resolve
        self._executor = executor

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        allow_loopback, own_ips = target_rules.get()
        addrs = await asyncio.get_running_loop().run_in_executor(self._executor, lambda: self._resolve(host, port, allow_loopback, own_ips))
        opts = [*(socket_options or ()), (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
        err = None
        for _, (ip, p) in addrs:
            try:
                each = timeout if len(addrs) == 1 or timeout is None else min(timeout, 5.0)  # one dead address must not use up the whole timeout
                return _Stream(await self._inner.connect_tcp(ip, p, timeout=each, socket_options=opts))
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                err = e
        raise err or httpcore.ConnectError(f'no address for {host}')

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError('unix sockets are not used by the proxy')

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


STREAM_WINDOW = 2**21      # what one response may receive before it is read (httpcore: 16 MB, as much as the whole connection)
CONNECTION_WINDOW = 2**28  # what all the responses of a connection may (httpcore: 16 MB)
_h2_init = httpcore._async.http2.AsyncHTTP2Connection._send_connection_init


async def _send_connection_init(self, request):
    """httpcore's HTTP/2 setup with other flow-control windows. With httpcore's, one response the browser stops reading (a video it has
    buffered enough of) takes the whole window of the connection: every other stream of it, the pictures and the next videos, waited at
    0 bytes until the server gave up. Here a paused response holds at most STREAM_WINDOW and the connection has room for many of them."""
    h2s = self._h2_state
    inc = h2s.increment_flow_control_window
    h2s.increment_flow_control_window = lambda n, stream_id=None: inc(STREAM_WINDOW if stream_id else CONNECTION_WINDOW, stream_id)
    await _h2_init(self, request)


httpcore._async.http2.AsyncHTTP2Connection._send_connection_init = _send_connection_init


async def cancel_open_stream(resp):
    """Tell the server to stop an HTTP/2 response the proxy gives up on (the client went away, the stream broke). httpcore frees its own
    slot but never resets the stream: it stays open in h2 and counts against the server's 100, the server keeps sending data nobody
    reads, and enough of them fill the connection ('Max outbound streams is 100, 100 open', bodies that stall). The data httpcore
    received for the stream but nobody read is acknowledged too: httpcore credits the connection's flow-control window only for what is
    read, so each abandoned body kept part of it; a few cancelled videos used up its 16 MB and every stream of the connection stalled at
    0 bytes. Relies on httpcore's private HTTP2ConnectionByteStream (_connection, _stream_id, _request) and _events: anything else is left alone."""
    body = resp.stream
    conn, sid, request = (getattr(body, name, None) for name in ('_connection', '_stream_id', '_request'))
    try:
        h2s = conn._h2_state
        events = getattr(conn, '_events', {}).get(sid) or []
        unread = sum(e.flow_controlled_length or 0 for e in events if isinstance(e, h2.events.DataReceived))
        events.clear()
        stream = h2s.streams.get(sid)
        reset = stream is not None and stream.open
        if reset:
            h2s.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
        if unread:
            h2s.acknowledge_received_data(unread, sid)  # a closed stream: the connection's window only
        if reset or unread:
            await conn._write_outgoing_data(request)
    except Exception:  # not an HTTP/2 stream, or the connection is already gone
        pass


def pool_for(server, resolve, executor):
    """The pool of `server` for the running event loop (the tests run one loop per connection)."""
    loop = asyncio.get_running_loop()
    pool = getattr(server, '_upstream_pool', None)
    if pool is None or getattr(server, '_upstream_loop', None) is not loop:
        pool = httpcore.AsyncConnectionPool(
            ssl_context=getattr(server, 'upstream_ssl_context', None) or _default_ssl_context,
            http1=True,
            http2=True,
            max_connections=MAX_CONNECTIONS,
            max_keepalive_connections=256,
            keepalive_expiry=KEEPALIVE_EXPIRY,
            network_backend=_Backend(resolve, executor),
        )
        server._upstream_pool, server._upstream_loop = pool, loop
    return pool
