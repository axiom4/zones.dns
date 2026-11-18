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
    gui_url = serializers.CharField(allow_blank=True, help_text='GUI_URL without the final /: where /proxy.mobileconfig and /proxy-ca.crt are served over https')


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
    outcome = serializers.ChoiceField(choices=['allowed', 'filtered', 'blocked', 'error', 'timeout'])
    status = serializers.IntegerField()
    reason = serializers.CharField(allow_blank=True)
    ms = serializers.IntegerField()


class ProxyLogsResponseSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    blocked_count = serializers.IntegerField()
    filtered_count = serializers.IntegerField()
    clients = serializers.ListField(child=serializers.CharField())
    results = ProxyLogSerializer(many=True)


class ProxyLogGroupSerializer(serializers.Serializer):
    host = serializers.CharField()
    count = serializers.IntegerField()
    blocked = serializers.IntegerField()
    failed = serializers.IntegerField(help_text='Errors and timeouts')
    last = serializers.DateTimeField()
    avg_ms = serializers.FloatField()
    clients = serializers.IntegerField(help_text='Distinct devices')


class ProxyLogGroupsResponseSerializer(serializers.Serializer):
    count = serializers.IntegerField(help_text='Sites that match')
    results = ProxyLogGroupSerializer(many=True)


class ProxyLogPurgeRequestSerializer(serializers.Serializer):
    older_than_hours = serializers.IntegerField(required=False, default=0, min_value=0)
    dry_run = serializers.BooleanField(default=False, help_text='Only count what would be deleted')


class ProxyLogPurgeResultSerializer(serializers.Serializer):
    deleted = serializers.IntegerField(help_text='Entries deleted (or that would be, with dry_run)')
    dry_run = serializers.BooleanField()


class ProxyRuleListSerializer(serializers.Serializer):
    name = serializers.CharField()
    url = serializers.CharField()
    blocks = serializers.IntegerField(help_text='Domains blocked (with their subdomains)')
    allow = serializers.IntegerField(help_text='Domains never filtered')
    cosmetic = serializers.IntegerField(help_text='Selectors that hide page elements')
    updated = serializers.DateTimeField(allow_null=True, help_text='Last good download, null before the first')
    error = serializers.CharField(allow_blank=True, help_text='Why the last download failed (the old rules stay in use)')


class ProxyAllowRequestSerializer(serializers.Serializer):
    host = serializers.CharField(max_length=253)
    url = serializers.CharField(required=False, allow_blank=True, max_length=2000, help_text='The address that was blocked (the proxy log row), for the address rules')


class ProxyAllowPrevSerializer(serializers.Serializer):
    allow = serializers.BooleanField()
    enabled = serializers.BooleanField()
    regex = serializers.BooleanField()
    expires = serializers.DateTimeField(allow_null=True)


class ProxyAllowSerializer(serializers.Serializer):
    """What Allow did; sent back as is to undo it."""
    host = serializers.CharField(max_length=253)
    dns_block = serializers.CharField(allow_blank=True, help_text='The DNS blacklist entry that blocked the host, e.g. "ads.example.com (easylist)"; empty: none')
    dns_id = serializers.IntegerField(allow_null=True, help_text='The personal allow entry made or changed; null: none')
    dns_prev = ProxyAllowPrevSerializer(allow_null=True, help_text='That entry before it was changed; null: it was made new')
    dns_list = serializers.CharField(allow_blank=True, help_text='The public list whose entry of the same name gave way to the allow entry')
    proxy_block = serializers.CharField(allow_blank=True, help_text='The proxy rule that blocked the request, e.g. "ad-url: /pagead/"; empty: none')
    proxy_rule = serializers.CharField(allow_blank=True, help_text='The exception added to the proxy rules (@@host); empty: none')
    note = serializers.CharField(allow_blank=True, help_text='Why the exception may not apply yet')


class ProxyAllowUndoSerializer(ProxyAllowSerializer):
    dns_block = serializers.CharField(required=False, allow_blank=True)
    dns_id = serializers.IntegerField(required=False, allow_null=True)
    dns_prev = ProxyAllowPrevSerializer(required=False, allow_null=True)
    dns_list = serializers.CharField(required=False, allow_blank=True, max_length=40)
    proxy_block = serializers.CharField(required=False, allow_blank=True)
    proxy_rule = serializers.CharField(required=False, allow_blank=True, max_length=260)
    note = serializers.CharField(required=False, allow_blank=True)
