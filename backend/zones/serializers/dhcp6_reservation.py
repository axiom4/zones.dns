import ipaddress
import re

from rest_framework import serializers

from .. import oui
from ..dhcp import v4 as dhcp, v6
from ..models import Dhcp6Reservation
from .dhcp_reservation import DhcpReservationImportSerializer


def normalize_duid(v):
    """The DUID as lower case hex without separators (accepts 00:01:..., 00-01-... and spaces); ValueError otherwise."""
    h = re.sub(r'[:\-\s]', '', str(v).lower())
    if not re.fullmatch(r'[0-9a-f]{6,260}', h) or len(h) % 2:
        raise ValueError('Not a DUID: hexadecimal bytes, e.g. 00:01:00:01:2b:3c:4d:5e:d8:3a:dd:be:4e:69.')
    return h


def check_row(duid, ip):
    """(duid, ip) in canonical form, or ValueError. The address must be inside DHCP6_PREFIX when that is set."""
    duid = normalize_duid(duid)
    try:
        addr = ipaddress.IPv6Address(str(ip).strip())
    except ValueError:
        raise ValueError('Not an IPv6 address.')
    prefix = dhcp.dhcp_settings().DHCP6_PREFIX
    try:
        net = ipaddress.IPv6Network(prefix) if prefix else None
    except ValueError:
        net = None
    if net and addr not in net:
        raise ValueError(f'{addr} is not in the DHCPv6 prefix {net}.')
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        raise ValueError('Not a usable unicast address.')
    return duid, str(addr)


class Dhcp6ReservationSerializer(serializers.ModelSerializer):
    mac = serializers.SerializerMethodField(help_text='MAC address inside the DUID (types 1 and 3), empty for the others')
    vendor = serializers.SerializerMethodField(help_text='Maker of the network card, empty if unknown')

    class Meta:
        model = Dhcp6Reservation
        fields = ['id', 'duid', 'ip', 'note', 'enabled', 'created', 'mac', 'vendor']
        read_only_fields = ['mac', 'vendor']
        validators = []  # uniqueness is checked in validate() with a readable message
        extra_kwargs = {'note': {'required': False}}

    def get_mac(self, r) -> str:
        return v6.duid_mac(r.duid)

    def get_vendor(self, r) -> str:
        return oui.vendor(v6.duid_mac(r.duid))

    def validate(self, d):
        cur = self.instance
        try:
            d['duid'], d['ip'] = check_row(d.get('duid', cur and cur.duid), d.get('ip', cur and cur.ip))
        except ValueError as e:
            raise serializers.ValidationError({'detail': str(e)})
        for field, label in (('duid', 'DUID'), ('ip', 'address')):
            dup = Dhcp6Reservation.objects.filter(**{field: d[field]})
            if cur:
                dup = dup.exclude(pk=cur.pk)
            if dup.exists():
                raise serializers.ValidationError({field: f'This {label} is already reserved.'})
        return d


class Dhcp6ReservationImportSerializer(DhcpReservationImportSerializer):
    text = serializers.CharField(max_length=2_000_000, help_text='CSV: duid,ip,note,enabled (first line may be that header)')
