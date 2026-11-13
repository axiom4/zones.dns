"""Reverse (PTR) zone helpers: CIDR <-> zone name, and PTR generation from A/AAAA records."""
import ipaddress

from rest_framework import serializers

from ..models import Record, Zone


def cidr_to_zone(cidr):
    """'10.0.0.0/24' -> '0.0.10.in-addr.arpa'. Only octet (IPv4) or nibble (IPv6) boundaries have a reverse zone."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=True)
    except ValueError:
        raise serializers.ValidationError({'cidr': 'Invalid network: use the address/prefix format, e.g. 10.0.0.0/24.'})
    unit, suffix = (8, 'in-addr.arpa') if net.version == 4 else (4, 'ip6.arpa')
    if net.prefixlen % unit or net.prefixlen == 0 or net.prefixlen == net.max_prefixlen:
        raise serializers.ValidationError({'cidr': 'IPv4: /8, /16 and /24 are supported. IPv6: prefixes that are multiples of 4 (e.g. /48, /64).'})
    labels = net.network_address.reverse_pointer.split('.')
    return '.'.join(labels[(net.max_prefixlen - net.prefixlen) // unit:])


def zone_to_cidr(name):
    """Inverse of cidr_to_zone; None if the zone is not a reverse zone."""
    labels = name.split('.')
    if name.endswith('.in-addr.arpa'):
        octets = labels[:-2][::-1]
        if not octets or len(octets) > 3 or not all(o.isdigit() and int(o) <= 255 for o in octets):
            return None
        return '.'.join(octets + ['0'] * (4 - len(octets))) + f'/{8 * len(octets)}'
    if name.endswith('.ip6.arpa'):
        nibbles = labels[:-2][::-1]
        if not nibbles or len(nibbles) > 31 or not all(len(n) == 1 and n.lower() in '0123456789abcdef' for n in nibbles):
            return None
        padded = ''.join(nibbles).ljust(32, '0')
        try:
            addr = ipaddress.IPv6Address(int(padded, 16))
        except ValueError:
            return None
        return f'{addr}/{4 * len(nibbles)}'
    return None


def find_reverse_zone(pointer, zones=None):
    """Longest existing zone that contains this reverse pointer name."""
    all_zones = Zone.objects.all() if zones is None else zones
    matched = [z for z in all_zones if pointer.endswith('.' + z.name)]
    return max(matched, key=lambda z: len(z.name), default=None)


def sync_ptrs(zone):
    """Create the PTR for every enabled A/AAAA record (in any zone) whose address falls inside this reverse zone."""
    created = skipped = 0
    all_zones = list(Zone.objects.all())
    for r in Record.objects.filter(type__in=['A', 'AAAA'], enabled=True).select_related('zone'):
        try:
            ptr = ipaddress.ip_address(r.value.strip()).reverse_pointer
        except ValueError:
            continue
        if find_reverse_zone(ptr, zones=all_zones) != zone:
            continue
        name = ptr[: -len(zone.name) - 1]
        value = f'{r.fqdn}.'
        _, new = Record.objects.get_or_create(zone=zone, name=name, type='PTR', value=value, defaults={'ttl': r.ttl})
        created, skipped = created + new, skipped + (not new)
    return {'created': created, 'skipped': skipped}
