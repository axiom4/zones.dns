from rest_framework import serializers

from ..stats.audit import clean_domain


class AuditRequestSerializer(serializers.Serializer):
    domain = serializers.CharField(help_text='Domain or host name, e.g. example.com or www.example.com')
    deep = serializers.BooleanField(default=False, help_text='Slower, more thorough: TLS protocol probing, exact SPF lookup count, MTA-STS policy, subdomains from certificate logs')

    def validate_domain(self, v):
        d = clean_domain(v)
        if not d:
            raise serializers.ValidationError('Nome di dominio non valido.')
        return d


class FindingSerializer(serializers.Serializer):
    severity = serializers.ChoiceField(['ok', 'info', 'warn', 'bad'])
    category = serializers.CharField()
    title = serializers.CharField()
    detail = serializers.CharField(allow_blank=True)
    output = serializers.CharField(allow_blank=True, help_text='Raw data the test was based on (records, headers, ...)')


class AuditSummarySerializer(serializers.Serializer):
    ok = serializers.IntegerField()
    info = serializers.IntegerField()
    warn = serializers.IntegerField()
    bad = serializers.IntegerField()


class DnsRecordsSerializer(serializers.Serializer):
    type = serializers.CharField()
    values = serializers.ListField(child=serializers.CharField())


class SoaSerializer(serializers.Serializer):
    mname = serializers.CharField(help_text='Primary name server')
    rname = serializers.CharField(help_text='Responsible mailbox (dots instead of @)')
    serial = serializers.IntegerField()
    refresh = serializers.IntegerField()
    retry = serializers.IntegerField()
    expire = serializers.IntegerField()
    minimum = serializers.IntegerField(help_text='Negative-caching TTL')


class NameserverSerializer(serializers.Serializer):
    name = serializers.CharField()
    ips = serializers.ListField(child=serializers.CharField())
    ms = serializers.IntegerField(allow_null=True, help_text='Response time of a SOA query')
    serial = serializers.IntegerField(allow_null=True)
    responds = serializers.BooleanField()
    authoritative = serializers.BooleanField()
    asn = serializers.CharField(allow_null=True)
    as_name = serializers.CharField(allow_null=True)


class DnssecSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()
    algorithms = serializers.ListField(child=serializers.CharField())


class MxSerializer(serializers.Serializer):
    priority = serializers.IntegerField()
    host = serializers.CharField()
    ips = serializers.ListField(child=serializers.CharField())
    cname = serializers.BooleanField(help_text='True if the host is an alias, which is not allowed for an MX')


class SpfSerializer(serializers.Serializer):
    record = serializers.CharField()
    mechanisms = serializers.ListField(child=serializers.CharField())
    includes = serializers.ListField(child=serializers.CharField())
    all = serializers.CharField(allow_null=True, help_text='Qualifier of "all": - ~ ? +')
    redirect = serializers.CharField(allow_null=True)
    lookups = serializers.IntegerField(help_text='DNS lookups SPF needs (limit 10)')
    lookups_exact = serializers.BooleanField(help_text='False when only the first level was counted')


class DmarcSerializer(serializers.Serializer):
    record = serializers.CharField()
    policy = serializers.CharField(allow_null=True)
    subdomain_policy = serializers.CharField(allow_null=True)
    pct = serializers.IntegerField()
    rua = serializers.ListField(child=serializers.CharField())
    ruf = serializers.ListField(child=serializers.CharField())
    adkim = serializers.CharField()
    aspf = serializers.CharField()


class MtaStsSerializer(serializers.Serializer):
    txt = serializers.CharField()
    mode = serializers.CharField(allow_null=True)
    max_age = serializers.IntegerField(allow_null=True)
    mx = serializers.ListField(child=serializers.CharField())


class MailSerializer(serializers.Serializer):
    mx = MxSerializer(many=True)
    spf = SpfSerializer(allow_null=True)
    dmarc = DmarcSerializer(allow_null=True)
    dkim_selectors = serializers.ListField(child=serializers.CharField())
    mta_sts = MtaStsSerializer(allow_null=True)
    tls_rpt = serializers.CharField(allow_null=True)
    bimi = serializers.CharField(allow_null=True)


class RegistrationSerializer(serializers.Serializer):
    name = serializers.CharField(help_text='Registered domain the data refers to')
    registrar = serializers.CharField(allow_null=True)
    created = serializers.CharField(allow_null=True)
    expires = serializers.CharField(allow_null=True)
    updated = serializers.CharField(allow_null=True)
    status = serializers.ListField(child=serializers.CharField())
    nameservers = serializers.ListField(child=serializers.CharField())
    age_days = serializers.IntegerField(allow_null=True)
    dnssec_signed = serializers.BooleanField(allow_null=True)
    abuse_email = serializers.CharField(allow_null=True)


class HostSerializer(serializers.Serializer):
    ip = serializers.CharField()
    ptr = serializers.CharField(allow_null=True)
    network = serializers.CharField(allow_null=True)
    org = serializers.CharField(allow_null=True)
    country = serializers.CharField(allow_null=True)
    asn = serializers.CharField(allow_null=True)
    as_name = serializers.CharField(allow_null=True)
    prefix = serializers.CharField(allow_null=True)
    registry = serializers.CharField(allow_null=True)


class TlsProtocolSerializer(serializers.Serializer):
    name = serializers.CharField()
    supported = serializers.BooleanField(allow_null=True, help_text='null = could not be tested from this machine')


class TlsSerializer(serializers.Serializer):
    host = serializers.CharField()
    ip = serializers.CharField()
    valid = serializers.BooleanField()
    error = serializers.CharField(allow_null=True)
    version = serializers.CharField(allow_null=True)
    cipher = serializers.CharField(allow_null=True)
    subject = serializers.CharField(allow_null=True)
    issuer = serializers.CharField(allow_null=True)
    not_before = serializers.CharField(allow_null=True)
    not_after = serializers.CharField(allow_null=True)
    days_left = serializers.IntegerField(allow_null=True)
    serial = serializers.CharField(allow_null=True)
    wildcard = serializers.BooleanField()
    san = serializers.ListField(child=serializers.CharField())
    ocsp = serializers.ListField(child=serializers.CharField())
    alpn_h2 = serializers.BooleanField()
    protocols = TlsProtocolSerializer(many=True)


class RedirectSerializer(serializers.Serializer):
    url = serializers.CharField()
    status = serializers.IntegerField(allow_null=True)
    location = serializers.CharField(allow_null=True)
    ip = serializers.CharField(allow_null=True)


class CookieSerializer(serializers.Serializer):
    name = serializers.CharField()
    secure = serializers.BooleanField()
    httponly = serializers.BooleanField()
    samesite = serializers.CharField(allow_null=True)


class HstsSerializer(serializers.Serializer):
    max_age = serializers.IntegerField()
    include_subdomains = serializers.BooleanField()
    preload = serializers.BooleanField()


class WebSerializer(serializers.Serializer):
    redirects = RedirectSerializer(many=True)
    https_status = serializers.IntegerField(allow_null=True)
    headers = serializers.DictField(child=serializers.CharField())
    cookies = CookieSerializer(many=True)
    hsts = HstsSerializer(allow_null=True)
    security_txt = serializers.BooleanField(allow_null=True)
    robots_txt = serializers.BooleanField(allow_null=True)


class ServiceSerializer(serializers.Serializer):
    category = serializers.CharField()
    name = serializers.CharField()
    evidence = serializers.CharField()


class SubdomainsSerializer(serializers.Serializer):
    source = serializers.CharField()
    total = serializers.IntegerField()
    names = serializers.ListField(child=serializers.CharField())
    error = serializers.CharField(allow_null=True)


class AuditReportSerializer(serializers.Serializer):
    domain = serializers.CharField()
    checked_at = serializers.DateTimeField()
    deep = serializers.BooleanField()
    duration_ms = serializers.IntegerField()
    summary = AuditSummarySerializer()
    findings = FindingSerializer(many=True)
    dns = DnsRecordsSerializer(many=True)
    soa = SoaSerializer(allow_null=True)
    nameservers = NameserverSerializer(many=True)
    dnssec = DnssecSerializer()
    wildcard = serializers.BooleanField()
    mail = MailSerializer()
    registration = RegistrationSerializer(allow_null=True)
    hosts = HostSerializer(many=True)
    tls = TlsSerializer(allow_null=True)
    web = WebSerializer()
    services = ServiceSerializer(many=True)
    subdomains = SubdomainsSerializer(allow_null=True)
