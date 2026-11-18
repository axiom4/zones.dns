"""Download a list over https only, at every redirect hop, and only from public addresses (no SSRF to the LAN or this host)."""
import http.client
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit

MAX_HOPS = 5


class _Conn(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):  # connects to the address that was checked, so a second DNS answer cannot change it
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _public_ip(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise OSError('host not found') from None
    ips = [i[4][0].partition('%')[0] for i in infos]
    # the message never says which address answered
    if not ips or not all(ipaddress.ip_address(i).is_global and not getattr(ipaddress.ip_address(i), 'ipv4_mapped', None) for i in ips):
        raise OSError('address not allowed')
    return ips[0]


def fetch(url, max_bytes=50_000_000, deadline=60):
    """The body of url as text. OSError with a generic message on any refusal or failure."""
    end = time.monotonic() + deadline
    for _ in range(MAX_HOPS + 1):
        u = urlsplit(url)
        if u.scheme != 'https' or not u.hostname:
            raise OSError('only https addresses are allowed')
        left = end - time.monotonic()
        if left <= 0:
            raise OSError('download took too long')
        try:
            port = u.port or 443
            conn = _Conn(u.hostname, port, _public_ip(u.hostname, port), left)
            try:
                conn.request('GET', (u.path or '/') + ('?' + u.query if u.query else ''), headers={'User-Agent': 'zones-dns/1.0'})
                r = conn.getresponse()
                if r.status in (301, 302, 303, 307, 308) and r.getheader('Location'):
                    url = urljoin(url, r.getheader('Location'))
                    continue
                if r.status != 200:
                    raise OSError(f'HTTP status {r.status}')
                raw = bytearray()
                while len(raw) <= max_bytes:
                    if time.monotonic() > end:
                        raise OSError('download took too long')
                    chunk = r.read1(65536)
                    if not chunk:
                        break
                    raw += chunk
            finally:
                conn.close()
        except (OSError, http.client.HTTPException, ValueError) as e:
            raise OSError(str(e) if str(e) in _OK or str(e).startswith('HTTP status ') else 'download failed') from None
        if len(raw) > max_bytes:
            raise OSError(f'response exceeds {max_bytes // 1_000_000} MB limit')
        return raw.decode('utf-8', 'replace')
    raise OSError('too many redirects')


_OK = {'host not found', 'address not allowed', 'only https addresses are allowed', 'download took too long'}
