"""Per-client DNS query rate limiting (DNS_RATE_LIMIT queries per DNS_RATE_WINDOW seconds).

Disabled when DNS_RATE_LIMIT <= 0. Keeps a bounded in-memory table of (window_id, count) per client IP.
"""
import threading
import time

from django.conf import settings

_lock = threading.Lock()
_clients = {}  # ip -> [window_id, count]
_MAX_CLIENTS = 10000


def reset():
    with _lock:
        _clients.clear()


def exceeded(client_ip):
    """True if client_ip has sent more than DNS_RATE_LIMIT queries in the current DNS_RATE_WINDOW."""
    limit = getattr(settings, 'DNS_RATE_LIMIT', 0)
    if limit <= 0 or not client_ip:
        return False
    window = max(int(getattr(settings, 'DNS_RATE_WINDOW', 1)), 1)
    win_id = int(time.monotonic() // window)
    with _lock:
        if len(_clients) > _MAX_CLIENTS:
            _clients.clear()
        slot = _clients.get(client_ip)
        if slot is None or slot[0] != win_id:
            _clients[client_ip] = [win_id, 1]
            return False
        slot[1] += 1
        return slot[1] > limit
