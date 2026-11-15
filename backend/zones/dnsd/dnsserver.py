"""DNS servers that answer queries on a fixed set of worker threads instead of one new thread per query.

A thread keeps its database connection open between queries (CONN_MAX_AGE), so the workers are the connection pool:
at most DNS_WORKERS connections per protocol, opened once and reused. A thread per query would open a database connection for each one.
"""
import collections
import ipaddress
import selectors
import socket
import struct
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from django.conf import settings
from dnslib import DNSError, DNSRecord
from dnslib.server import DNSHandler, DNSLogger, TCPServer, UDPServer

from . import ratelimit

TCP_IDLE = 10.0  # seconds a connection may stay silent before it is closed (RFC 7766 §6.2.3: the server decides)
TCP_MAX_SECONDS = 300.0  # ...and how long it may live in all; the client opens another one
TCP_MAX_CONNS = 1000  # open connections; one more closes the one that has been silent the longest
TCP_SEND = 5.0  # seconds a worker waits for a client that does not read its answers, then the connection is dropped


def _reply(server, handler, data):
    """The bytes that answer one query. handler: who asked (client_address, protocol) and the bytes received (wire: a TSIG signature is checked
    over them). resolver.finish() already packed (and cut) a UDP answer to measure it: those bytes are sent, not packed a second time."""
    handler.wire = data
    request = DNSRecord.parse(data)
    server.logger.log_request(handler, request)
    reply = server.resolver.resolve(request, handler)
    server.logger.log_reply(handler, reply)
    wire = getattr(reply, 'wire', None)
    return wire if wire is not None else reply.pack()


class Handler(DNSHandler):
    """dnslib's handler for UDP. TCP connections do not come through here: see PooledTCPServer."""

    def get_reply(self, data):
        return _reply(self.server, self, data)


class _Conn:
    """One TCP connection, read by the reader thread; its queries are answered by the workers."""

    def __init__(self, sock, addr, proxy):
        self.sock, self.addr, self.proxy = sock, addr, proxy  # proxy: a PROXY protocol line may still come first
        self.buf, self.dead, self.lock = b'', False, threading.Lock()  # lock: one answer at a time on the socket
        self.opened = self.seen = time.monotonic()

    def kill(self):
        """From a worker: the reader sees the end of the stream and forgets the connection (only that thread closes sockets)."""
        self.dead = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


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
    """DNS over TCP (and, behind nginx, over TLS). One thread reads every connection and hands each complete query to the workers, so a
    connection costs a worker only while a query of its own is being answered: clients keep theirs open and send several queries on it
    (RFC 7766 §6.2.1; DNS over TLS clients do), in any number, and one that sends nothing or a byte now and then holds no worker.
    Answers of one connection may leave in another order than the queries came (RFC 7766 §7: the client matches them by id)."""
    workers = 16

    def __init__(self, server_address, handler):
        super().__init__(server_address, handler)
        self._start_pool(self.workers)
        self._sel, self._conns, self._new, self._stop = selectors.DefaultSelector(), set(), collections.deque(), False
        self._wake_r, self._wake_w = socket.socketpair()  # ends the reader's wait when a connection arrives
        self._wake_r.setblocking(False)
        self._sel.register(self._wake_r, selectors.EVENT_READ, None)
        self._reader = threading.Thread(target=self._read_loop, name='dns-tcp-reader', daemon=True)
        self._reader.start()

    def verify_request(self, request, client_address):
        return ratelimit.allowed(client_address[0])  # DNS_ALLOW_QUERY before anything is read: a stranger's connection is closed at once

    def process_request(self, request, client_address):
        request.settimeout(TCP_SEND)
        self._new.append(_Conn(request, client_address, settings.DNS_PROXY_PROTOCOL and _loopback(client_address[0])))
        self._wake()

    def _wake(self):
        try:
            self._wake_w.send(b'x')
        except OSError:
            pass

    def _read_loop(self):
        reaped = time.monotonic()
        while not self._stop:
            try:
                events = self._sel.select(timeout=1.0)
            except OSError:
                continue
            for key, _ in events:
                if key.data is None:
                    try:
                        self._wake_r.recv(4096)
                    except OSError:
                        pass
                elif key.data in self._conns:  # not one dropped earlier in this round
                    self._readable(key.data)
            while self._new:
                conn = self._new.popleft()
                if len(self._conns) >= TCP_MAX_CONNS:
                    self._drop(min(self._conns, key=lambda c: c.seen))
                try:
                    self._sel.register(conn.sock, selectors.EVENT_READ, conn)
                    self._conns.add(conn)
                except (OSError, ValueError):
                    conn.sock.close()
            now = time.monotonic()
            if now - reaped >= min(1.0, TCP_IDLE):
                reaped = now
                for conn in [c for c in self._conns if now - c.seen > TCP_IDLE or now - c.opened > TCP_MAX_SECONDS]:
                    self._drop(conn)
        for conn in list(self._conns):
            self._drop(conn)
        self._sel.close()
        self._wake_r.close()
        self._wake_w.close()

    def _drop(self, conn):
        conn.dead = True
        self._conns.discard(conn)
        try:
            self._sel.unregister(conn.sock)
        except (KeyError, ValueError, OSError):
            pass
        conn.sock.close()

    def _readable(self, conn):
        try:
            data = conn.sock.recv(65536)
        except (BlockingIOError, InterruptedError, TimeoutError):
            return
        except OSError:
            data = b''
        if not data:
            return self._drop(conn)
        conn.buf, conn.seen = conn.buf + data, time.monotonic()
        if conn.proxy and not self._proxy_header(conn):
            return
        while len(conn.buf) >= 2:
            n = struct.unpack('!H', conn.buf[:2])[0]
            if len(conn.buf) < 2 + n:
                break
            query, conn.buf = conn.buf[2:2 + n], conn.buf[2 + n:]
            if not self._room.acquire(blocking=False):
                return self._drop(conn)  # more queries waiting than the workers can take (flood protection): the client retries
            self._pool.submit(self._answer, conn, query)

    def _proxy_header(self, conn):
        """DNS_PROXY_PROTOCOL: a connection from this machine (nginx for DNS over TLS, the DoH view) may start with a PROXY protocol v1 line that
        carries the address of the real client; it replaces 127.0.0.1 for DNS_ALLOW_QUERY, the rate limit, the suspicious-query count and the log.
        Never read from another machine: anybody could claim any address. False = wait for more bytes (or the connection was dropped)."""
        if len(conn.buf) < 6:
            return False
        if conn.buf.startswith(b'PROXY '):
            if b'\r\n' not in conn.buf:
                if len(conn.buf) > 107:  # the longest v1 line
                    self._drop(conn)
                return False
            line, _, conn.buf = conn.buf.partition(b'\r\n')
            parts = line.decode('ascii', 'replace').split()
            if len(parts) >= 3 and parts[1] in ('TCP4', 'TCP6'):
                try:
                    conn.addr = (str(ipaddress.ip_address(parts[2])), 0)
                except ValueError:
                    self._drop(conn)
                    return False
        conn.proxy = False
        return True

    def _answer(self, conn, data):
        who = SimpleNamespace(client_address=conn.addr, protocol='tcp', server=self)  # per query: two of one connection may be answered at once
        try:
            if conn.dead:
                return
            self.logger.log_recv(who, data)
            rdata = _reply(self, who, data)
            self.logger.log_send(who, rdata)
            with conn.lock:
                if not conn.dead:
                    conn.sock.sendall(struct.pack('!H', len(rdata)) + rdata)
            conn.seen = time.monotonic()
        except DNSError as e:
            self.logger.log_error(who, e)
            conn.kill()
        except OSError:
            conn.kill()  # the client went away, or does not read its answers
        except Exception:
            traceback.print_exc()  # a future would keep it to itself
            conn.kill()
        finally:
            self._room.release()

    def server_close(self):
        self._stop = True
        self._wake()
        self._reader.join(timeout=3)
        super().server_close()
