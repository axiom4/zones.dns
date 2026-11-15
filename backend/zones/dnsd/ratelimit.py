"""Who may ask (DNS_ALLOW_QUERY) and per-client DNS query rate limiting (DNS_RATE_LIMIT queries per DNS_RATE_WINDOW seconds).

The rate limit is disabled when DNS_RATE_LIMIT <= 0. Keeps a bounded in-memory table of (window_id, count) per client IP: when it is full the
least recently seen client goes, so a flood of forged addresses cannot empty it and reset everybody's counter.
"""
import ipaddress
import threading
import time
from collections import OrderedDict
from functools import lru_cache

from django.conf import settings

_lock = threading.Lock()
_clients = OrderedDict()  # ip -> [window_id, count], least recently seen first
_MAX_CLIENTS = 10000


def reset():
    with _lock:
        _clients.clear()


@lru_cache(maxsize=8)
def _networks(raw):
    """The networks of a DNS_ALLOW_QUERY value; None = anyone ('*'). Entries that do not parse are ignored."""
    if raw.strip() == '*':
        return None
    out = []
    for entry in raw.split(','):
        try:
            if entry.strip():
                out.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            continue
    return tuple(out)


@lru_cache(maxsize=4096)
def _allowed(raw, client_ip):
    nets = _networks(raw)
    if nets is None:
        return True
    try:
        addr = ipaddress.ip_address(client_ip.split('%')[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in n for n in nets if n.version == addr.version)


def allowed(client_ip):
    """True if client_ip may use this resolver (DNS_ALLOW_QUERY): the daemon is never an open resolver by mistake."""
    return _allowed(getattr(settings, 'DNS_ALLOW_QUERY', '*'), client_ip or '')


@lru_cache(maxsize=4096)
def _bucket(client_ip):
    """What is counted: an IPv4 address, or the /64 of an IPv6 one (a host picks any address inside its own /64, so each would start from zero)."""
    try:
        addr = ipaddress.ip_address(client_ip.split('%')[0])
    except ValueError:
        return client_ip
    if addr.version == 6 and not addr.ipv4_mapped:
        return str(ipaddress.ip_network((int(addr) >> 64 << 64, 64)))
    return str(addr.ipv4_mapped or addr) if addr.version == 6 else client_ip


def exceeded(client_ip):
    """How many queries client_ip has sent beyond DNS_RATE_LIMIT in the current DNS_RATE_WINDOW: 0 = within the limit, 1 = the first one refused."""
    limit = getattr(settings, 'DNS_RATE_LIMIT', 0)
    if limit <= 0 or not client_ip:
        return 0
    client_ip = _bucket(client_ip)
    window = max(int(getattr(settings, 'DNS_RATE_WINDOW', 1)), 1)
    win_id = int(time.monotonic() // window)
    with _lock:
        slot = _clients.get(client_ip)
        if slot is None or slot[0] != win_id:
            _clients[client_ip] = slot = [win_id, 0]
            if len(_clients) > _MAX_CLIENTS:
                _clients.popitem(last=False)
        _clients.move_to_end(client_ip)
        slot[1] += 1
        return max(slot[1] - limit, 0)
