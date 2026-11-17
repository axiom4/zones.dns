"""Upstream connections of the proxy: one httpcore pool (HTTP/1.1 and HTTP/2, kept-alive connections) per proxy server and event loop.

httpcore opens every connection through _Backend: the name is resolved by the proxy's own resolver and checked against the SSRF rules
(the same _resolve_target as the request), the next address is tried when one does not answer, and after the TLS handshake the
certificate is checked for revocation.
"""
import asyncio
import contextvars
import socket
import ssl

import httpcore

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
