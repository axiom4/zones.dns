from rest_framework import serializers

from ..models import Zone
from ..reverse import zone_to_cidr


class ZoneSerializer(serializers.ModelSerializer):
    reverse = serializers.SerializerMethodField(help_text='True for in-addr.arpa / ip6.arpa zones')
    cidr = serializers.SerializerMethodField(help_text='Network covered by a reverse zone, e.g. 10.0.0.0/24')

    class Meta:
        model = Zone
        fields = ['id', 'name', 'enabled', 'reverse', 'cidr']

    def get_reverse(self, z) -> bool:
        return zone_to_cidr(z.name) is not None

    def get_cidr(self, z) -> str | None:
        return zone_to_cidr(z.name)

    def validate_name(self, v):
        return v.strip().strip('.').lower()


class ReverseZoneRequestSerializer(serializers.Serializer):
    cidr = serializers.CharField(help_text='Network, e.g. 10.0.0.0/24 or fd00:1234::/48')


class SyncPtrResultSerializer(serializers.Serializer):
    created = serializers.IntegerField()
    skipped = serializers.IntegerField(help_text='PTR already present')
