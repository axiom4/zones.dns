from rest_framework import serializers


class DhcpLeaseSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    family = serializers.IntegerField(help_text='4 or 6')
    kind = serializers.ChoiceField(choices=['address', 'prefix'])
    address = serializers.CharField(help_text='The address, or the delegated prefix')
    client = serializers.CharField(help_text='MAC address (DHCPv4) or DUID (DHCPv6)')
    mac = serializers.CharField(allow_blank=True, help_text='MAC address; for DHCPv6 the one inside the DUID (types 1 and 3), empty for the other DUIDs')
    hostname = serializers.CharField(allow_blank=True)
    vendor = serializers.CharField(allow_blank=True, help_text='Maker of the network card (from the MAC address), empty if unknown')
    expires = serializers.DateTimeField()
    active = serializers.BooleanField()


class DhcpNeighborSerializer(serializers.Serializer):
    address = serializers.CharField()
    mac = serializers.CharField()
    vendor = serializers.CharField(allow_blank=True, help_text='Maker of the network card, empty if unknown')
    hostname = serializers.CharField(allow_blank=True, help_text='The name this MAC has in DHCPv4 (lease or reservation)')
    interface = serializers.CharField()
    state = serializers.CharField(help_text='REACHABLE, STALE, DELAY, PROBE, PERMANENT ...')
    kind = serializers.ChoiceField(choices=['link-local', 'dhcpv6', 'slaac', 'other'], help_text='dhcpv6: a lease of this server; slaac: built by the client from its MAC; other: privacy or fixed address')


class DhcpSettingsSerializer(serializers.Serializer):
    DHCP = serializers.BooleanField(required=False)
    DHCP_SERVER = serializers.CharField(required=False, allow_blank=True, max_length=45)
    DHCP_NETMASK = serializers.CharField(required=False, allow_blank=True, max_length=45)
    DHCP_RANGE = serializers.CharField(required=False, allow_blank=True, max_length=120)
    DHCP_ROUTER = serializers.CharField(required=False, allow_blank=True, max_length=45)
    DHCP_DNS = serializers.CharField(required=False, allow_blank=True, max_length=255)
    DHCP_DOMAIN = serializers.CharField(required=False, allow_blank=True, max_length=253)
    DHCP_LEASE = serializers.IntegerField(required=False, min_value=60)
    DHCP_RESERVATIONS = serializers.CharField(required=False, allow_blank=True, max_length=4000)
    DHCP_INTERFACE = serializers.CharField(required=False, allow_blank=True, max_length=64)
    DHCP_NTP = serializers.CharField(required=False, allow_blank=True, max_length=255)
    DHCP_SEARCH = serializers.CharField(required=False, allow_blank=True, max_length=500)
    DHCP_ROUTES = serializers.CharField(required=False, allow_blank=True, max_length=2000)
    DHCP_MTU = serializers.IntegerField(required=False, min_value=0, max_value=65535)
    DHCP_BOOT_SERVER = serializers.CharField(required=False, allow_blank=True, max_length=255)
    DHCP_BOOT_FILE = serializers.CharField(required=False, allow_blank=True, max_length=128)
    DHCP_PROBE = serializers.BooleanField(required=False)
    DHCP_NAMES = serializers.BooleanField(required=False)
    DHCP_UNICAST = serializers.BooleanField(required=False)
    DHCP_DNR = serializers.BooleanField(required=False)
    DHCP_FAILOVER_SECS = serializers.IntegerField(required=False, min_value=0, max_value=3600)
    DHCP_SUBNETS = serializers.CharField(required=False, allow_blank=True, max_length=8000)
    DHCP6 = serializers.BooleanField(required=False)
    DHCP6_PREFIX = serializers.CharField(required=False, allow_blank=True, max_length=64)
    DHCP6_POOL = serializers.CharField(required=False, allow_blank=True, max_length=128)
    DHCP6_PD_POOL = serializers.CharField(required=False, allow_blank=True, max_length=64)
    DHCP6_PD_LEN = serializers.IntegerField(required=False, min_value=1, max_value=128)
    DHCP6_PD_ROUTES = serializers.BooleanField(required=False)
    DHCP6_LEASE = serializers.IntegerField(required=False, min_value=120)
    DHCP6_PREFERENCE = serializers.IntegerField(required=False, min_value=0, max_value=255)
    DHCP6_RAPID = serializers.BooleanField(required=False)
    DHCP6_DNS = serializers.CharField(required=False, allow_blank=True, max_length=255)
    DHCP_RA = serializers.BooleanField(required=False)
    DHCP_RA_INTERVAL = serializers.IntegerField(required=False, min_value=4, max_value=1800)
    DHCP_RA_ROUTER_LIFETIME = serializers.IntegerField(required=False, min_value=0, max_value=9000)
    DHCP_RA_SLAAC = serializers.BooleanField(required=False)
    DHCP_WPAD = serializers.BooleanField(required=False)
    DHCP_WPAD_URL = serializers.CharField(required=False, allow_blank=True, max_length=255)
    PROXY = serializers.BooleanField(required=False)
    PROXY_PORT = serializers.IntegerField(required=False, min_value=1, max_value=65535)
    PROXY_ADDRESS = serializers.CharField(required=False, allow_blank=True, max_length=64)
    PROXY_BLOCK_ADS = serializers.BooleanField(required=False)
    PROXY_BLOCK_POPUPS = serializers.BooleanField(required=False)
    PROXY_HTTPS_MITM = serializers.BooleanField(required=False)
    PROXY_CUSTOM_RULES = serializers.CharField(required=False, allow_blank=True, max_length=8000)


class ProxyInfoSerializer(serializers.Serializer):
    subject = serializers.CharField()
    fingerprint = serializers.CharField()
    expires = serializers.DateTimeField()
    pem = serializers.CharField()
    wpad_url = serializers.CharField(allow_blank=True)
    pac = serializers.CharField()


class ProxyTestRequestSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2000)


class ProxyTestResultSerializer(serializers.Serializer):
    url = serializers.CharField()
    host = serializers.CharField()
    blocked = serializers.BooleanField()
    reason = serializers.CharField(allow_blank=True)
    detail = serializers.CharField(allow_blank=True)


class ProxyLogSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    time = serializers.DateTimeField()
    client = serializers.CharField()
    method = serializers.CharField()
    host = serializers.CharField()
    url = serializers.CharField(allow_blank=True)
    outcome = serializers.ChoiceField(choices=['allowed', 'filtered', 'blocked', 'error'])
    status = serializers.IntegerField()
    reason = serializers.CharField(allow_blank=True)
    ms = serializers.IntegerField()


class ProxyLogsResponseSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    blocked_count = serializers.IntegerField()
    filtered_count = serializers.IntegerField()
    clients = serializers.ListField(child=serializers.CharField())
    results = ProxyLogSerializer(many=True)


class ProxyLogPurgeRequestSerializer(serializers.Serializer):
    older_than_hours = serializers.IntegerField(required=False, default=0, min_value=0)


class ProxyLogPurgeResultSerializer(serializers.Serializer):
    deleted = serializers.IntegerField()


class DhcpPingRequestSerializer(serializers.Serializer):
    addresses = serializers.ListField(child=serializers.CharField(max_length=64), max_length=64, help_text='IP addresses of the local network (at most 64)')


class DhcpPingResultSerializer(serializers.Serializer):
    address = serializers.CharField()
    up = serializers.BooleanField()
    ms = serializers.FloatField(allow_null=True, help_text='Round trip time')
    ttl = serializers.IntegerField(allow_null=True, help_text='TTL (hop limit) of the reply')
    bytes = serializers.IntegerField(allow_null=True, help_text='Size of the ICMP reply, like the first number of ping')
    error = serializers.CharField(allow_blank=True)


class MacVendorSerializer(serializers.Serializer):
    mac = serializers.CharField()
    vendor = serializers.CharField(allow_null=True, help_text='Maker of the network card, null if the address is in no registry')
    private = serializers.BooleanField(help_text='A locally administered (random) address: it has no maker')
