import math
import threading
import time
from collections import Counter, defaultdict

from django.conf import settings

from .domains import main_domain

BAD_TYPES = {'ANY', 'AXFR', 'IXFR'}
_seen = defaultdict(dict)  # (client, main domain) -> {name: last seen}; per process
_lock = threading.Lock()


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def check(qname, qtype, client):
    """Reason string if the query looks malicious (tunnelling, DGA, recon), else None."""
    mode = settings.SUSPICIOUS_MODE
    if mode == 'off':
        return None
    domain = main_domain(qname)
    if domain in settings.SUSPICIOUS_ALLOW:
        return None
    if qtype in BAD_TYPES:
        return f'type {qtype}'
    labels = qname.split('.')
    if len(qname) > settings.SUSPICIOUS_MAX_NAME or max(map(len, labels)) > settings.SUSPICIOUS_MAX_LABEL:
        return 'name too long'
    sub = labels[: -len(domain.split('.'))] or []
    for lab in sub:
        if len(lab) >= settings.SUSPICIOUS_ENTROPY_MIN_LEN and entropy(lab) >= settings.SUSPICIOUS_ENTROPY:
            return 'random-looking label (tunnelling/DGA)'
    if sub:  # many distinct subdomains of one domain from one client in a short time
        now, win = time.monotonic(), settings.SUSPICIOUS_WINDOW
        with _lock:
            seen = _seen[(client, domain)]
            seen[qname] = now
            for k in [k for k, t in seen.items() if now - t > win]:
                del seen[k]
            if len(seen) > settings.SUSPICIOUS_MAX_UNIQUE:
                return f'{len(seen)} distinct subdomains in {win}s'
    return None
