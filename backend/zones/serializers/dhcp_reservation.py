import ipaddress
import re

from rest_framework import serializers

from .. import oui
from ..dhcp import v4 as dhcp
from ..models import DhcpReservation


def normalize_mac(v):
    """aa:bb:cc:dd:ee:ff from aa-bb-.., aabb.ccdd.eeff or aabbccddeeff; ValueError otherwise."""
    h = re.sub(r'[:.\-]', '', str(v).strip().lower())
    if not re.fullmatch(r'[0-9a-f]{12}', h):
        raise ValueError('Not a MAC address (aa:bb:cc:dd:ee:ff).')
    if int(h[1], 16) & 1 or h == '0' * 12:
        raise ValueError('A group or all-zero MAC address cannot be reserved.')
    return ':'.join(h[i:i + 2] for i in range(0, 12, 2))


def check_row(mac, ip, hostname):
    """(mac, ip, hostname) in canonical form, or ValueError with what is wrong. The address must be inside a network the DHCP server serves (when it is configured)."""
    mac = normalize_mac(mac)
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except ValueError:
        raise ValueError('Not an IPv4 address.')
    hostname = (hostname or '').strip().lower()
    if hostname and (dhcp.clean_hostname(hostname.encode()) != hostname or hostname in dhcp.RESERVED_NAMES):
        raise ValueError('Host name: one label of letters, digits and "-", not a reserved name.')
    s = dhcp.dhcp_settings()
    if s.DHCP:
        try:
            cfgs = dhcp.scopes(s)
        except ValueError:
            cfgs = []  # settings in error: the server will not start anyway, do not block the table too
        if cfgs and not any(addr in c.network and addr != c.server for c in cfgs):
            raise ValueError(f'{addr} is not in a network served by DHCP ({", ".join(str(c.network) for c in cfgs)}) or is the address of the server.')
    return mac, str(addr), hostname


class DhcpReservationSerializer(serializers.ModelSerializer):
    vendor = serializers.SerializerMethodField(help_text='Maker of the network card, empty if unknown')

    class Meta:
        model = DhcpReservation
        fields = ['id', 'mac', 'ip', 'hostname', 'note', 'enabled', 'created', 'vendor']
        read_only_fields = ['vendor']
        validators = []  # uniqueness is checked in validate() with a readable message
        extra_kwargs = {'hostname': {'required': False}, 'note': {'required': False}}

    def get_vendor(self, r) -> str:
        return oui.vendor(r.mac)

    def validate(self, d):
        cur = self.instance
        mac, ip, host = d.get('mac', cur and cur.mac), d.get('ip', cur and cur.ip), d.get('hostname', cur.hostname if cur else '')
        try:
            d['mac'], d['ip'], d['hostname'] = check_row(mac, ip, host)
        except ValueError as e:
            raise serializers.ValidationError({'detail': str(e)})
        for field, label in (('mac', 'MAC address'), ('ip', 'address')):
            dup = DhcpReservation.objects.filter(**{field: d[field]})
            if cur:
                dup = dup.exclude(pk=cur.pk)
            if dup.exists():
                raise serializers.ValidationError({field: f'This {label} is already reserved.'})
        return d


class DhcpReservationImportSerializer(serializers.Serializer):
    text = serializers.CharField(max_length=2_000_000, help_text='CSV: mac,ip,hostname,note,enabled (first line may be that header)')
    replace = serializers.BooleanField(default=False, help_text='Delete every reservation first (needs a second factor when the user has one)')
    dry_run = serializers.BooleanField(default=False, help_text='Only count, change nothing')


class DhcpReservationImportResultSerializer(serializers.Serializer):
    created = serializers.IntegerField()
    updated = serializers.IntegerField()
    skipped = serializers.IntegerField(help_text='Already present, same values')
    errors = serializers.ListField(child=serializers.CharField(), help_text='When there are errors nothing is changed')
