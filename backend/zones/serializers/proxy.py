from rest_framework import serializers


class ProxySettingsSerializer(serializers.Serializer):
    DHCP_WPAD = serializers.BooleanField(required=False)
    DHCP_WPAD_URL = serializers.CharField(required=False, allow_blank=True, max_length=255)
    PROXY = serializers.BooleanField(required=False)
    PROXY_PORT = serializers.IntegerField(required=False, min_value=1, max_value=65535)
    PROXY_ADDRESS = serializers.CharField(required=False, allow_blank=True, max_length=64)
    PROXY_BLOCK_ADS = serializers.BooleanField(required=False)
    PROXY_BLOCK_POPUPS = serializers.BooleanField(required=False)
    PROXY_HTTPS_MITM = serializers.BooleanField(required=False)
    PROXY_RULE_LISTS = serializers.CharField(required=False, allow_blank=True, max_length=4000)
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


class ProxyRuleListSerializer(serializers.Serializer):
    name = serializers.CharField()
    url = serializers.CharField()
    blocks = serializers.IntegerField(help_text='Domains blocked (with their subdomains)')
    allow = serializers.IntegerField(help_text='Domains never filtered')
    cosmetic = serializers.IntegerField(help_text='Selectors that hide page elements')
    updated = serializers.DateTimeField(allow_null=True, help_text='Last good download, null before the first')
    error = serializers.CharField(allow_blank=True, help_text='Why the last download failed (the old rules stay in use)')
