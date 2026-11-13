"""IPv6 Router Advertisements (RFC 4861) with the DNS servers (RDNSS, RFC 8106), the search list (DNSSL) and the encrypted resolvers (RFC 9463 option 144).

By default this host announces itself as NOT a default router (router lifetime 0): it only adds what the real router does not say. Used by `manage.py rundhcp`
when DHCP_RA=true; needs a raw ICMPv6 socket (root or CAP_NET_RAW) and DHCP_INTERFACE."""
import ipaddress
import struct
from dataclasses import dataclass, field

from ..dnsd import ddr

RS, RA = 133, 134


@dataclass
class RaConfig:
    dns: list
    search: list
    dns_ddr: list  # ddr.parse() entries
    prefix: ipaddress.IPv6Network | None = None
    slaac: bool = True  # the A flag of the prefix: clients build their own address
    managed: bool = False  # the M flag: addresses come from DHCPv6
    other: bool = True  # the O flag: the rest (DNS...) comes from DHCPv6
    router_lifetime: int = 0
    interval: int = 600

    @classmethod
    def from_settings(cls, s, search, managed):
        try:
            dns = [ipaddress.IPv6Address(x) for x in s.DHCP6_DNS.replace(',', ' ').split()]
            prefix = ipaddress.IPv6Network(s.DHCP6_PREFIX) if s.DHCP6_PREFIX else None
        except ValueError as e:
            raise ValueError(f'RA settings: {e}')
        if not 4 <= s.DHCP_RA_INTERVAL <= 1800 or not 0 <= s.DHCP_RA_ROUTER_LIFETIME <= 9000:
            raise ValueError('RA settings: DHCP_RA_INTERVAL is 4-1800 seconds, DHCP_RA_ROUTER_LIFETIME 0-9000 (RFC 4861)')
        if prefix and prefix.prefixlen != 64 and s.DHCP_RA_SLAAC:
            raise ValueError('RA settings: SLAAC needs a /64 prefix (DHCP6_PREFIX); set DHCP_RA_SLAAC=false for another length')
        return cls(dns, search, ddr.parse(s.DNS_DDR) if s.DHCP_DNR and s.DNS_DDR else [], prefix, s.DHCP_RA_SLAAC, managed, True, s.DHCP_RA_ROUTER_LIFETIME, s.DHCP_RA_INTERVAL)

    @property
    def lifetime(self):
        return 3 * self.interval  # RFC 8106: at least MaxRtrAdvInterval, 3 times is the suggested value


def _pad(b):
    return b + b'\0' * (-len(b) % 8)


def build(cfg, mac=None):
    """The ICMPv6 Router Advertisement (the kernel adds the checksum on a raw ICMPv6 socket)."""
    flags = (0x80 if cfg.managed else 0) | (0x40 if cfg.other else 0)
    out = struct.pack('!BBHBBHII', RA, 0, 0, 64, flags, cfg.router_lifetime, 0, 0)
    if mac:
        out += bytes([1, 1]) + mac
    if cfg.prefix:
        out += struct.pack('!BBBBIII', 3, 4, cfg.prefix.prefixlen, 0x80 | (0x40 if cfg.slaac else 0), 2592000, 604800, 0) + cfg.prefix.network_address.packed
    if cfg.dns:
        out += struct.pack('!BBHI', 25, 1 + 2 * len(cfg.dns), 0, cfg.lifetime) + b''.join(d.packed for d in cfg.dns)
    if cfg.search:
        names = _pad(b''.join(ddr.adn(n) for n in cfg.search))
        out += struct.pack('!BBHI', 31, 1 + len(names) // 8, 0, cfg.lifetime) + names
    for opt in ddr.dnr_ra(cfg.dns_ddr, cfg.lifetime):
        out += opt
    return out
