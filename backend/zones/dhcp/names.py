"""The names the DNS server answers from the DHCP leases (DHCP_NAMES): <host name>.<DHCP_DOMAIN> gives the A of a DHCPv4 lease and the AAAA of the DHCPv6 leases
of the same client, and the reverse names (in-addr.arpa, ip6.arpa) give the PTR. Used by dnsd/resolver.py."""
import ipaddress

from django.utils import timezone

from ..models import Dhcp6Lease, DhcpLease
from .v4 import RESERVED_NAMES, dhcp_settings


def _name_cfg():
    s = dhcp_settings()
    return bool(s.DHCP and s.DHCP_NAMES and s.DHCP_DOMAIN.strip('.')), s.DHCP_DOMAIN.strip('.').lower()


def _wpad_cfg():
    s = dhcp_settings()
    domain = s.DHCP_DOMAIN.strip('.').lower()
    server = s.DHCP_SERVER.strip()
    on = bool((s.DHCP_WPAD or s.PROXY) and domain and server)
    return on, domain, server


def wpad_hosts(qname, cfg=None):
    """[(DHCP_SERVER, 60)] when qname is wpad.<DHCP_DOMAIN> and WPAD / Proxy is enabled, else None."""
    on, domain, server = cfg or _wpad_cfg()
    if on and qname.rstrip('.').lower() == f'wpad.{domain}':
        return [(server, 60)]
    return None


def lease_hosts(qname, cfg=None):
    """[(address, ttl)] of the client that called itself <label>.<DHCP_DOMAIN> and has a live lease, or None (the DNS server answers these names).
    cfg: _name_cfg() already read (the DNS daemon keeps it with its data copy), else read now."""
    on, domain = cfg or _name_cfg()
    if not (on and qname.endswith('.' + domain)):
        return None
    label = qname[:-len(domain) - 1]
    if not label or '.' in label:
        return None
    if label in RESERVED_NAMES:
        return None  # also for leases saved before the names were reserved
    now = timezone.now()
    row = DhcpLease.objects.filter(hostname=label, expires__gt=now).order_by('updated').first()  # the oldest holder, not the latest claimant
    v6 = Dhcp6Lease.objects.filter(kind__in=('na', 'ta'), expires__gt=now)  # the same client over DHCPv6: by its own name (Client FQDN) or by the MAC it has in DHCPv4
    v6 = v6.filter(hostname=label) | (v6.filter(mac=row.mac) if row and row.mac else v6.none())
    found = ([(row.ip, 60)] if row else []) + [(r.value, 60) for r in v6.order_by('updated')]
    return found or None


def _v6_name(row):
    """The host name of a DHCPv6 lease: the one it gave, else the one its MAC has in DHCPv4."""
    if row.hostname or not row.mac:
        return row.hostname
    return DhcpLease.objects.filter(mac=row.mac).exclude(hostname='').order_by('-updated').values_list('hostname', flat=True).first() or ''


def lease_ptr(qname, cfg=None):
    """The name of the client that holds the address in a reverse name (d.c.b.a.in-addr.arpa, or the 32 nibbles of ip6.arpa), or None."""
    on, domain = cfg or _name_cfg()
    if not on:
        return None
    if qname.endswith('.ip6.arpa'):
        nibbles = qname[:-len('.ip6.arpa')].split('.')
        if len(nibbles) != 32 or not all(len(n) == 1 and n in '0123456789abcdef' for n in nibbles):
            return None
        value = str(ipaddress.IPv6Address(int(''.join(reversed(nibbles)), 16)))
        row = Dhcp6Lease.objects.filter(value=value, kind__in=('na', 'ta'), expires__gt=timezone.now()).first()
        name = _v6_name(row) if row else ''
        return f'{name}.{domain}' if name else None
    if not qname.endswith('.in-addr.arpa'):
        return None
    parts = qname[:-len('.in-addr.arpa')].split('.')
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    row = DhcpLease.objects.filter(ip='.'.join(reversed(parts)), expires__gt=timezone.now()).exclude(hostname='').first()
    return f'{row.hostname}.{domain}' if row else None
