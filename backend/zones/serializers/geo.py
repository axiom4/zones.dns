from rest_framework import serializers


class GeoIpSerializer(serializers.Serializer):
    ip = serializers.CharField()
    private = serializers.BooleanField(help_text='Not a public address: nothing to locate')
    country = serializers.CharField(allow_blank=True, help_text='ISO 3166 alpha-2, empty if unknown')
    asn = serializers.CharField(allow_null=True)
    as_name = serializers.CharField(allow_null=True)
    prefix = serializers.CharField(allow_null=True)
    city = serializers.CharField(allow_null=True)
    region = serializers.CharField(allow_null=True)
    latitude = serializers.FloatField(allow_null=True)
    longitude = serializers.FloatField(allow_null=True)
    source = serializers.ChoiceField(['local', 'cymru', 'none', 'private'], help_text='Where the location came from')


class WhoisSerializer(serializers.Serializer):
    ip = serializers.CharField()
    server = serializers.CharField(help_text='The WHOIS server that answered')
    text = serializers.CharField(help_text='Its answer, as text')


class GeoIpsResultSerializer(serializers.Serializer):
    results = GeoIpSerializer(many=True)
    pending = serializers.IntegerField(help_text='Addresses not located yet (ask again)')


class DestinationCountrySerializer(serializers.Serializer):
    country = serializers.CharField(help_text='ISO code; PRIV = internal addresses, ?? = unknown')
    queries = serializers.IntegerField()
    ips = serializers.IntegerField()
    domains = serializers.IntegerField()
    top_domains = serializers.ListField(child=serializers.CharField())
    asns = serializers.ListField(child=serializers.CharField())
    cities = serializers.ListField(child=serializers.CharField())


class DestinationNetworkSerializer(serializers.Serializer):
    asn = serializers.CharField()
    as_name = serializers.CharField(allow_null=True)
    country = serializers.CharField(allow_blank=True)
    queries = serializers.IntegerField()
    ips = serializers.IntegerField()


class DestinationPointSerializer(serializers.Serializer):
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()
    city = serializers.CharField(allow_blank=True)
    country = serializers.CharField()
    queries = serializers.IntegerField()
    ips = serializers.IntegerField()
    domains = serializers.ListField(child=serializers.CharField())


class GeoIpDbSerializer(serializers.Serializer):
    type = serializers.CharField()
    built = serializers.CharField()
    file = serializers.CharField()


class GeoIpStatusSerializer(serializers.Serializer):
    city = GeoIpDbSerializer(allow_null=True)
    asn = GeoIpDbSerializer(allow_null=True)
    configured_city = serializers.BooleanField(help_text='GEOIP_CITY_DB is set (it may still be unreadable)')
    configured_asn = serializers.BooleanField()
    online_fallback = serializers.BooleanField()


class DestinationsSerializer(serializers.Serializer):
    scanned = serializers.IntegerField(help_text='Queries whose answer had at least one A/AAAA address (each query once, however many addresses)')
    ips_total = serializers.IntegerField()
    ips_located = serializers.IntegerField()
    pending = serializers.IntegerField(help_text='Addresses still to locate: ask again in a moment')
    countries = DestinationCountrySerializer(many=True)
    networks = DestinationNetworkSerializer(many=True)
    points = DestinationPointSerializer(many=True, help_text='Map points (needs a local city database)')
    geoip = GeoIpStatusSerializer()
