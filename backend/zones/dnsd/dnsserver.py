"""DNS servers that answer queries on a fixed set of worker threads instead of one new thread per query.

A thread keeps its database connection open between queries (CONN_MAX_AGE), so the workers are the connection pool:
at most DNS_WORKERS connections per protocol, opened once and reused. A thread per query would open a database connection for each one.
"""
import threading
from concurrent.futures import ThreadPoolExecutor

from dnslib.server import TCPServer, UDPServer


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

    def finish_request(self, request, client_address):
        request.settimeout(5.0)
        super().finish_request(request, client_address)
