"""One Redis connection pool for the whole process.

Django builds a cache client per thread, and each client opens its own pool: the DNS daemon runs a thread per query, so
that meant a new TCP connection to Redis for almost every query. Here every client gets the same pool, whose connections stay open
and are reused (CACHES -> OPTIONS -> pool_class).
"""
import threading

import redis

_lock = threading.Lock()
_pools = {}


class SharedPool(redis.BlockingConnectionPool):
    @classmethod
    def from_url(cls, url, **options):
        with _lock:
            if url not in _pools:
                _pools[url] = super().from_url(url, **options)
            return _pools[url]


def warm(count):
    """Open `count` connections now and leave them in the pool, so the first queries do not pay for the connect."""
    with _lock:
        pools = list(_pools.values())
    for pool in pools:
        conns = [pool.get_connection() for _ in range(count)]
        for c in conns:
            c.connect()
        for c in conns:
            pool.release(c)
