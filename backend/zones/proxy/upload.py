"""HTTP/1.1 exchanges with a server that the connection pool cannot do.

- A large streamed upload: sent with "Expect: 100-continue", and the server's answer is read while the body is still going out.
  A server that refuses it (413 too large, 401) answers before it has it all; the pool only read the answer after the whole body
  and, the server having closed the connection, gave the client a 502 instead of that answer.
- The WebSocket handshake (RFC 6455): after a 101 the connection is a tunnel of WebSocket frames.
"""
import asyncio
import base64
import os
import ssl

import h11

from . import revocation
from .streams import RawStream, keepalive

CONTINUE_WAIT = 1.0  # seconds to wait for "100 Continue" before sending the body anyway (RFC 9110 10.1.1)

h1_ssl_context = ssl.create_default_context()  # apart from the pool's: this one offers only http/1.1 (ALPN)
h1_ssl_context.set_alpn_protocols(['http/1.1'])


class Prefixed:
    """A stream that first hands out bytes already read from it (what came behind a handshake)."""

    def __init__(self, stream, prefix):
        self.stream = stream
        self.prefix = prefix

    async def read(self, n=65536, timeout=None):
        if self.prefix:
            data, self.prefix = self.prefix[:n], self.prefix[n:]
            return data
        return await self.stream.read(n, timeout)

    async def write(self, data):
        await self.stream.write(data)

    async def aclose(self):
        await self.stream.aclose()


async def open_h1(scheme, host, port, addrs, ctx, timeout):
    """A connection to the server for HTTP/1.1: TLS checked (name, revocation) for https."""
    err = None
    for _, (ip, p) in addrs:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, p, ssl=ctx if scheme == 'https' else None, server_hostname=host if scheme == 'https' else None),
                timeout if len(addrs) == 1 else min(timeout, 5),
            )
        except (OSError, TimeoutError, ssl.SSLError) as e:
            err = e
            continue
        if scheme == 'https':
            obj = w.get_extra_info('ssl_object')
            if obj.selected_alpn_protocol() not in (None, 'http/1.1'):
                w.close()
                raise OSError(f'{host} chose {obj.selected_alpn_protocol()}, not HTTP/1.1')
            if revocation.is_revoked(obj.get_verified_chain()):
                w.close()
                raise ssl.SSLCertVerificationError(f'the certificate of {host} is revoked')
        keepalive(w)
        return RawStream(r, w)
    raise err or OSError(f'no address for {host}')


async def next_event(conn, stream, timeout):
    while True:
        ev = conn.next_event()
        if ev is h11.NEED_DATA:
            conn.receive_data(await stream.read(65536, timeout))
            continue
        return ev


class H1Response:
    """An answer read with h11, with what relay() expects of an httpcore one."""

    def __init__(self, conn, stream, resp, read_timeout):
        self.status = resp.status_code
        self.headers = list(resp.headers.raw_items())
        self.extensions = {'reason_phrase': bytes(resp.reason), 'http_version': b'HTTP/1.1'}
        self._conn = conn
        self._stream = stream
        self._timeout = read_timeout

    async def aiter_stream(self):
        while True:
            ev = await next_event(self._conn, self._stream, self._timeout)
            if isinstance(ev, h11.Data):
                yield bytes(ev.data)
            else:
                return  # EndOfMessage, or the end of a body that ends with the connection


async def upload(stream, method, target, headers, body, read_timeout):
    """Send a request with a streamed body; the answer (H1Response), possibly before the body is all sent."""
    conn = h11.Connection(h11.CLIENT)
    hdrs = [(k, v) for k, v in headers if k.lower() not in ('expect', 'connection')]
    hdrs += [('Expect', '100-continue'), ('Connection', 'close')]
    await stream.write(conn.send(h11.Request(method=method, target=target, headers=hdrs)))
    final = asyncio.get_running_loop().create_future()
    go_on = asyncio.Event()

    async def read_answer():
        try:
            while True:
                ev = await next_event(conn, stream, read_timeout)
                if isinstance(ev, h11.InformationalResponse):
                    if ev.status_code == 100:
                        go_on.set()
                    continue
                final.set_result(ev)
                return
        except BaseException as e:  # noqa: BLE001 - handed to the waiting side
            if not final.done():
                final.set_exception(e)

    reader = asyncio.create_task(read_answer())
    waiter = asyncio.create_task(go_on.wait())
    try:
        await asyncio.wait([waiter, final], timeout=CONTINUE_WAIT, return_when=asyncio.FIRST_COMPLETED)
        if not final.done():
            try:
                async for chunk in body:
                    if final.done():
                        break  # answered already: the rest is not sent
                    await stream.write(conn.send(h11.Data(data=chunk)))
                else:
                    if not final.done():
                        await stream.write(conn.send(h11.EndOfMessage()))
            except (OSError, h11.LocalProtocolError):
                pass  # the server stopped reading: its answer, if it sent one, is still there to read
        ev = await asyncio.wait_for(asyncio.shield(final), read_timeout)
    finally:
        waiter.cancel()
        if not final.done():
            reader.cancel()
    if not isinstance(ev, h11.Response):
        raise ConnectionError('the server closed the connection without an answer')
    return H1Response(conn, stream, ev, read_timeout)


def websocket_key():
    return base64.b64encode(os.urandom(16)).decode()


async def websocket_handshake(stream, target, headers, read_timeout):
    """(h11 connection, event): the server's 101 (InformationalResponse) or its refusal (Response)."""
    conn = h11.Connection(h11.CLIENT)
    hdrs = [(k, v) for k, v in headers if k.lower() not in ('connection', 'upgrade')] + [('Connection', 'Upgrade'), ('Upgrade', 'websocket')]
    await stream.write(conn.send(h11.Request(method='GET', target=target, headers=hdrs)) + conn.send(h11.EndOfMessage()))
    ev = await next_event(conn, stream, read_timeout)
    if isinstance(ev, h11.InformationalResponse) and ev.status_code != 101:
        ev = await next_event(conn, stream, read_timeout)  # a stray 100
    return conn, ev
