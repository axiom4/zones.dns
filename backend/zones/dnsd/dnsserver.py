"""DNS servers that answer queries on a fixed set of worker threads instead of one new thread per query.

A thread keeps its database connection open between queries (CONN_MAX_AGE), so the workers are the connection pool:
at most DNS_WORKERS connections per protocol, opened once and reused. A thread per query would open a database connection for each one.
"""
import ipaddress
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from dnslib import DNSError, DNSRecord
from dnslib.server import DNSHandler, DNSLogger, TCPServer, UDPServer

from . import ratelimit

TCP_IDLE = 2.0  # seconds a connection may stay silent (before a query, between two, inside one)
TCP_MAX_SECONDS = 30.0  # a connection is closed after this long, whatever it does: a client that sends a byte now and then cannot keep a worker
TCP_MAX_QUERIES = 100  # per connection; the client opens another one


class Handler(DNSHandler):
    """dnslib's handler, minus a second pack(): resolver.finish() already packed (and cut) the UDP answer to measure it."""

    def handle(self):
        """TCP: every query of the connection is answered (RFC 7766 §6.2.1), not only the first: DNS over TLS clients keep one connection and
        send several queries on it; dnslib answered one, dropped what else had arrived and closed.
        shortcut: a connection holds its worker while it is open (at most TCP_IDLE silent, TCP_MAX_SECONDS in all); an event loop if DoT clients outnumber DNS_WORKERS."""
        if self.server.socket_type != socket.SOCK_STREAM:
            return super().handle()
        self.protocol, self._buf, deadline = 'tcp', b'', time.monotonic() + TCP_MAX_SECONDS
        if not self._proxy_header(deadline):
            return
        for _ in range(TCP_MAX_QUERIES):
            head = self._take(2, deadline)
            data = head and self._take(struct.unpack('!H', head)[0], deadline)
            if not data:
                return
            self.server.logger.log_recv(self, data)
            try:
                rdata = self.get_reply(data)
                self.server.logger.log_send(self, rdata)
                self.request.sendall(struct.pack('!H', len(rdata)) + rdata)
            except DNSError as e:
                self.server.logger.log_error(self, e)
                return
            except OSError:
                return  # the client went away

    def _take(self, n, deadline):
        """The next n bytes of the connection, or None when it ends, stays silent for TCP_IDLE or passes its deadline first."""
        while len(self._buf) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                self.request.settimeout(min(TCP_IDLE, left))
                chunk = self.request.recv(8192)
            except OSError:
                return None
            if not chunk:
                return None
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _proxy_header(self, deadline):
        """DNS_PROXY_PROTOCOL: a connection from this machine (nginx for DNS over TLS, the DoH view) may start with a PROXY protocol v1 line that
        carries the address of the real client; it replaces 127.0.0.1 for DNS_ALLOW_QUERY, the rate limit, the suspicious-query count and the log.
        Never read from another machine: anybody could claim any address. False = close the connection."""
        if not settings.DNS_PROXY_PROTOCOL or not _loopback(self.client_address[0]):
            return True
        while len(self._buf) < 6 or (self._buf.startswith(b'PROXY ') and b'\r\n' not in self._buf):
            if len(self._buf) > 107:  # the longest v1 line
                return False
            more = self._take(len(self._buf) + 1, deadline)  # at least one byte more
            if more is None:
                return False
            self._buf = more + self._buf
        if self._buf.startswith(b'PROXY '):
            line, _, self._buf = self._buf.partition(b'\r\n')
            parts = line.decode('ascii', 'replace').split()
            if len(parts) >= 3 and parts[1] in ('TCP4', 'TCP6'):
                try:
                    self.client_address = (str(ipaddress.ip_address(parts[2])), 0)
                except ValueError:
                    return False
        return True

    def get_reply(self, data):
        self.wire = data  # the bytes received: a TSIG signature (DNS UPDATE) is checked over them
        request = DNSRecord.parse(data)
        self.server.logger.log_request(self, request)
        reply = self.server.resolver.resolve(request, self)
        self.server.logger.log_reply(self, reply)
        wire = getattr(reply, 'wire', None)
        return wire if wire is not None else reply.pack()


def _loopback(ip):
    try:
        addr = ipaddress.ip_address(ip.split('%')[0])
    except ValueError:
        return False
    return addr.is_loopback or bool(getattr(addr, 'ipv4_mapped', None) and addr.ipv4_mapped.is_loopback)


def logger():
    """Only truncated answers and errors on stdout: dnslib's default printed two lines per query (the query log already has them)."""
    return DNSLogger('truncated,error')


class _Pooled:
    def _start_pool(self, workers):
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='dns-worker')
        self._room = threading.BoundedSemaphore(workers * 8)  # queries waiting for a worker; more than that are dropped (flood protection)

    def process_request(self, request, client_address):
        if isinstance(request, tuple) and (len(request[0]) < 12 or request[0][2] & 0x80):
            return  # RFC 5625 §4.1: silently drop UDP responses (QR=1) and truncated headers to prevent port-53 ping-pong loops
        if not self._room.acquire(blocking=False):
            self.shutdown_request(request)  # UDP: the client retries; TCP: the connection is closed
            return
        self._pool.submit(self._work, request, client_address)

    def _work(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._room.release()

    def warm(self, count):
        """Make `count` workers open their database connection now (they wait for each other, so each one is a different thread)."""
        from django.db import connection
        barrier = threading.Barrier(count)

        def open_connection():
            connection.ensure_connection()
            barrier.wait(timeout=10)
        for f in [self._pool.submit(open_connection) for _ in range(count)]:
            f.result()

    def server_close(self):
        super().server_close()
        self._pool.shutdown(wait=False)


class PooledUDPServer(_Pooled, UDPServer):
    workers = 16

    def __init__(self, server_address, handler):
        super().__init__(server_address, handler)
        self._start_pool(self.workers)


class PooledTCPServer(_Pooled, TCPServer):
    workers = 16

    def __init__(self, server_address, handler):
        super().__init__(server_address, handler)
        self._start_pool(self.workers)

    def verify_request(self, request, client_address):
        return ratelimit.allowed(client_address[0])  # DNS_ALLOW_QUERY before a worker reads anything: a stranger cannot hold one with a silent connection

    def finish_request(self, request, client_address):
        request.settimeout(TCP_IDLE)
        super().finish_request(request, client_address)
