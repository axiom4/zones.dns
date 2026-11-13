"""RFC 9462 (DDR): tell a client which encrypted resolvers this server is, in the SVCB answer for _dns.resolver.arpa.

DNS_DDR lists them, space separated: `dot:host[:port]` (DNS over TLS, default port 853) and `doh:host[:port]/path{?dns}` (DNS over HTTPS),
each with optional address hints `@ip,ip` (the addresses of the host: the client does not need to look them up first).
The daemon itself only speaks plain DNS: DoT needs a TLS proxy in front (deploy/nginx/dns-dot.conf), DoH is served by views/doh.py behind nginx.
"""
from dnslib import RR
from dnslib.dns import RD

NAME = '_dns.resolver.arpa'
SVCB = 64
import ipaddress

ALPN, PORT, IPV4HINT, IPV6HINT, DOHPATH = 1, 3, 4, 6, 7


def parse(text):
    """[(priority, host, {param key: value bytes})] from DNS_DDR; an entry that makes no sense is an error (it would be announced to every client)."""
    out = []
    for i, e in enumerate(text.split(), 1):
        e, _, hints = e.partition('@')
        kind, _, rest = e.partition(':')
        host, _, path = rest.partition('/')
        host, _, port = host.partition(':')
        host = host.rstrip('.').lower()
        if (kind not in ('dot', 'doh') or not host or len(host) > 253 or any(not (1 <= len(x) <= 63) for x in host.split('.'))
                or (port and (not port.isdigit() or not (1 <= int(port) <= 65535))) or (kind == 'dot' and path) or (kind == 'doh' and '{?dns}' not in path)):
            raise ValueError(f'DNS_DDR: bad entry {e!r} (dot:host[:port] or doh:host[:port]/path{{?dns}})')
        alpn = b'dot' if kind == 'dot' else b'h2'
        params = {ALPN: bytes([len(alpn)]) + alpn}
        if port or kind == 'dot':
            params[PORT] = int(port or 853).to_bytes(2, 'big')
        if kind == 'doh':
            params[DOHPATH] = ('/' + path).encode()
        try:
            ips = [ipaddress.ip_address(h) for h in hints.split(',') if h]
        except ValueError:
            raise ValueError(f'DNS_DDR: bad address in {e!r}')
        if any(a.is_multicast or a.is_loopback or a.is_unspecified for a in ips):  # clients silently discard these (RFC 9463): announcing them is a mistake
            raise ValueError(f'DNS_DDR: multicast, loopback and unspecified addresses are not allowed in {e!r}')
        for key, version in ((IPV4HINT, 4), (IPV6HINT, 6)):
            if packed := b''.join(a.packed for a in ips if a.version == version):
                params[key] = packed
        out.append((i, host, params))
    return out


class SvcbRD(RD):
    """SVCB rdata (RFC 9460): priority, target name (not compressed), parameters in key order."""
    def __init__(self, priority, target, params):
        self.priority, self.target, self.params = priority, target, params

    def pack(self, buffer):
        buffer.pack('!H', self.priority)
        buffer.encode_name_nocompress(self.target)
        for k in sorted(self.params):
            buffer.pack('!HH', k, len(self.params[k]))
            buffer.append(self.params[k])

    def toZone(self):
        return f'{self.priority} {self.target}. ' + ' '.join(f'key{k}={v.hex()}' for k, v in sorted(self.params.items()))

    __str__ = toZone


def answers(text, qname=NAME, ttl=300):
    """The SVCB records for qname: _dns.resolver.arpa (all resolvers) or _dns.<adn> (the ones of that host, asked by clients that got only the name from DNR)."""
    return [RR(qname, SVCB, rdata=SvcbRD(p, h, params), ttl=ttl) for p, h, params in parse(text) if qname == NAME or qname == f'_dns.{h}']


def is_ours(text, qname):
    return qname == NAME or any(qname == f'_dns.{h}' for _, h, _ in parse(text))


def adn(host):
    """The authentication domain name as labels, each with its length, ending in a zero (the encoding of RFC 8415 section 10)."""
    return b''.join(bytes([len(x)]) + x.encode() for x in host.rstrip('.').split('.')) + b'\x00'


def _svcparams(params):
    """SvcParams in key order, without the address hints: RFC 9463 forbids them in DNR, the addresses of the option replace them."""
    return b''.join(k.to_bytes(2, 'big') + len(v).to_bytes(2, 'big') + v for k, v in sorted(params.items()) if k not in (IPV4HINT, IPV6HINT))


def _body(host, params, hint, addr_len, with_params=True):
    """(adn, addresses, svcparams) of one resolver for one address family, or None if it has addresses only of the other family.
    No hints at all = ADN-only mode: no addresses and no SvcParams, the client asks the SVCB record of _dns.<adn> itself."""
    if IPV4HINT not in params and IPV6HINT not in params:
        return adn(host), None, b''
    addrs = params.get(hint)
    return (adn(host), addrs, _svcparams(params)) if addrs else None


def dnr_v4(entries):
    """Body of DHCPv4 option 162 (RFC 9463 section 5): the instances of all resolvers one after the other. Over 255 octets it is split (RFC 3396)."""
    out = b''
    for prio, host, params in entries:
        b = _body(host, params, IPV4HINT, 1)
        if b is None:
            continue
        name, addrs, sp = b
        data = prio.to_bytes(2, 'big') + bytes([len(name)]) + name
        if addrs:
            data += bytes([len(addrs)]) + addrs + sp
        out += len(data).to_bytes(2, 'big') + data
    return out


def dnr_v6(entries):
    """[body of one DHCPv6 option 144 (RFC 9463 section 4)] per resolver."""
    out = []
    for prio, host, params in entries:
        b = _body(host, params, IPV6HINT, 2)
        if b is None:
            continue
        name, addrs, sp = b
        data = prio.to_bytes(2, 'big') + len(name).to_bytes(2, 'big') + name
        if addrs:
            data += len(addrs).to_bytes(2, 'big') + addrs + sp
        out.append(data)
    return out


def dnr_ra(entries, lifetime=1800):
    """[complete IPv6 RA option 144 (RFC 9463 section 6)] per resolver. Without any hint it is the ADN-only form: nothing after the name (the RFC lists Addr Length,
    the addresses and the SvcParams as absent); a resolver with only IPv4 hints is left out."""
    out = []
    for prio, host, params in entries:
        name = adn(host)
        data = prio.to_bytes(2, 'big') + lifetime.to_bytes(4, 'big') + len(name).to_bytes(2, 'big') + name
        if IPV4HINT in params or IPV6HINT in params:
            if IPV6HINT not in params:
                continue
            addrs, sp = params[IPV6HINT], _svcparams(params)
            data += len(addrs).to_bytes(2, 'big') + addrs + len(sp).to_bytes(2, 'big') + sp
        data += b'\x00' * (-(len(data) + 2) % 8)  # type and length count too: the whole option is a multiple of 8 octets
        out.append(bytes([144, (len(data) + 2) // 8]) + data)
    return out
