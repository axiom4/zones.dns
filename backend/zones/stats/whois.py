"""WHOIS of an IP address (RFC 3912): IANA says which regional registry holds it, then that registry is asked."""
import re
import socket

from django.core.cache import cache

IANA = 'whois.iana.org'
REGISTRIES = {'whois.arin.net', 'whois.ripe.net', 'whois.apnic.net', 'whois.lacnic.net', 'whois.afrinic.net'}  # the referral comes from the network: only these are followed
MAX_BYTES = 30000
TTL = 86400  # registry data changes rarely


def _ask(server, query):
    with socket.create_connection((server, 43), timeout=5) as s:
        s.settimeout(5)
        s.sendall(query.encode() + b'\r\n')
        out = b''
        while len(out) < MAX_BYTES and (chunk := s.recv(4096)):
            out += chunk
    return out.decode('utf-8', 'replace')


def lookup(ip):
    """(server, text) for a public address; OSError if a server cannot be reached. Cached for a day."""
    try:
        hit = cache.get(f'whois:{ip}')
        if hit:
            return hit
    except Exception:
        pass
    text = _ask(IANA, ip)
    refer = re.search(r'^refer:\s*(\S+)', text, re.M | re.I)
    server = refer.group(1).lower() if refer else ''
    result = (server, _ask(server, ip)) if server in REGISTRIES else (IANA, text)
    try:
        cache.set(f'whois:{ip}', result, TTL)
    except Exception:
        pass
    return result
