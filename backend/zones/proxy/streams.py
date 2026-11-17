"""Byte streams of the asyncio proxy: a TCP connection, and TLS on top of it done with ssl.MemoryBIO.

The proxy terminates TLS itself (MITM) on a connection whose first bytes it has already read: the CONNECT request, and often the
client's ClientHello right behind it. MemoryBIO starts the handshake from those buffered bytes, which loop.start_tls() would lose.
"""
import asyncio
import socket
import ssl

READ_SIZE = 65536


def keepalive(writer):
    """TCP keep-alive and no Nagle on the socket of a stream: a silent connection still notices a peer that vanished."""
    sock = writer.get_extra_info('socket')
    if sock is None:
        return
    for level, opt, val in ((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1), (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                            (socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', None), 60),
                            (socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', None), 30),
                            (socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', None), 4)):
        if opt is None:
            continue
        try:
            sock.setsockopt(level, opt, val)
        except OSError:
            pass  # not a TCP socket (the tests use socketpair)


class RawStream:
    """A TCP connection (asyncio reader and writer); `prefix`: bytes already read from it, handed out first."""

    def __init__(self, reader, writer, prefix=b''):
        self.reader = reader
        self.writer = writer
        self._prefix = prefix
        self.eof_sent = False

    async def read(self, n=READ_SIZE, timeout=None):
        """Up to n bytes; b'' at the end of the stream. TimeoutError after `timeout` seconds without data."""
        if self._prefix:
            data, self._prefix = self._prefix[:n], self._prefix[n:]
            return data
        if timeout is None:
            return await self.reader.read(n)
        return await asyncio.wait_for(self.reader.read(n), timeout)

    async def write(self, data):
        if data and not self.eof_sent:  # after write_eof() nothing more may go out (a TLS close_notify, say)
            self.writer.write(data)
            await self.writer.drain()

    def write_eof(self):
        if not self.eof_sent and self.writer.can_write_eof():
            self.writer.write_eof()
            self.eof_sent = True

    def take_prefix(self):
        data, self._prefix = self._prefix, b''
        return data

    def sockname(self):
        return self.writer.get_extra_info('sockname')

    async def aclose(self):
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 5)
        except (OSError, TimeoutError, ssl.SSLError):
            pass


class TLSStream:
    """Server-side TLS over a RawStream."""

    def __init__(self, raw, ctx):
        self.raw = raw
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_side=True)

    async def _flush(self):
        data = self._out.read()
        if data:
            await self.raw.write(data)

    async def _fill(self, timeout):
        data = await self.raw.read(READ_SIZE, timeout)
        if data:
            self._in.write(data)
        else:
            self._in.write_eof()

    async def handshake(self, timeout=15):
        """Raises ssl.SSLError (the client refused the certificate, or spoke no TLS), OSError or TimeoutError."""
        while True:
            try:
                self._obj.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                await self._flush()
                if self._in.eof:
                    raise ssl.SSLEOFError('the client closed the connection during the TLS handshake')
                await self._fill(timeout)

    def alpn(self):
        return self._obj.selected_alpn_protocol()

    async def read(self, n=READ_SIZE, timeout=None):
        while True:
            try:
                return self._obj.read(n)
            except ssl.SSLWantReadError:
                await self._flush()
                if self._in.eof:
                    return b''
                await self._fill(timeout)
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b''

    async def write(self, data):
        if data:
            self._obj.write(data)  # a memory BIO never asks to wait
            await self._flush()

    def sockname(self):
        return self.raw.sockname()

    async def aclose(self):
        try:
            self._obj.unwrap()  # close_notify: the client sees a clean end of the TLS session
        except (ssl.SSLError, OSError):
            pass
        try:
            await self._flush()
        except OSError:
            pass
        await self.raw.aclose()
