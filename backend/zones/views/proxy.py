import re
from datetime import timedelta
import ipaddress
from urllib.parse import urlsplit

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import DisallowedHost
from django.db import transaction
from django.db.models import Avg, Count, Max, Q
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.views import View
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from ..dhcp import v4 as dhcp
from ..dnsd import ratelimit
from ..models import COUNTS_KEY, PERSONAL_BLOCKS, BlockedDomain, DataVersion, ProxyLog, Setting
from ..dnsd import resolver
from .token import client_ip
from .zone import GRANT, need_grant
from ..proxy import ca, filter as pfilter, pac, rules
from ..serializers import (
    ProxyInfoSerializer,
    ProxyLogPurgeRequestSerializer,
    ProxyLogPurgeResultSerializer,
    ProxyLogGroupsResponseSerializer,
    ProxyLogsResponseSerializer,
    ProxyRuleListSerializer,
    ProxySettingsSerializer,
    ProxyTestRequestSerializer,
    ProxyTestResultSerializer,
)
from ..serializers.proxy import ProxyAllowRequestSerializer, ProxyAllowSerializer, ProxyAllowUndoSerializer
from ..serializers.static_host import HOST_RE
from ..stats import rollup
# The proxy settings are stored with the DHCP ones (Setting rows `dhcp:<NAME>`): one snapshot, one restart signal for rundhcp and runproxy.

# Settings that send the clients' traffic somewhere else or open it to inspection: changing them needs a second-factor grant (scope proxy-change)
SENSITIVE = ('PROXY_HTTPS_MITM', 'DHCP_WPAD', 'DHCP_WPAD_URL', 'PROXY_ADDRESS', 'PROXY_PORT')


class ProxySettingsView(APIView):
    @staticmethod
    def _serialize(s):
        return {name: getattr(s, name) for name in ProxySettingsSerializer().fields}

    @extend_schema(responses=ProxySettingsSerializer)
    def get(self, request):
        """Current proxy configuration: the filtering proxy (`runproxy`) and its announcement to DHCP clients (WPAD)."""
        return Response(ProxySettingsSerializer(self._serialize(dhcp.dhcp_settings())).data)

    @extend_schema(request=ProxySettingsSerializer, responses=ProxySettingsSerializer, parameters=[GRANT])
    def patch(self, request):
        """Update the proxy settings and validate them before saving. `runproxy` and `rundhcp` apply them by themselves.
        Changing HTTPS inspection, WPAD or the proxy address/port needs a second-factor grant (scope proxy-change)."""
        ser = ProxySettingsSerializer(data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        cur = dhcp.dhcp_settings()
        if any(k in ser.validated_data and ser.validated_data[k] != getattr(cur, k) for k in SENSITIVE) \
                and (denied := need_grant(request, scope='proxy-change')) is not None:
            return denied
        cand = dhcp.dhcp_settings(overrides=ser.validated_data)
        try:
            if cand.DHCP:
                dhcp.scopes(cand)
            if cand.DHCP_WPAD_URL and (len(cand.DHCP_WPAD_URL) > 255 or not cand.DHCP_WPAD_URL.startswith(('http://', 'https://'))):
                raise ValueError('proxy settings: DHCP_WPAD_URL must be an http:// or https:// URL of at most 255 characters')
            if cand.PROXY_ADDRESS:
                try:
                    ipaddress.ip_address(cand.PROXY_ADDRESS)
                except ValueError:
                    raise ValueError(f'proxy settings: bad PROXY_ADDRESS {cand.PROXY_ADDRESS!r}')
            rules.split_entries(cand.PROXY_RULE_LISTS)
            if not 1 <= int(cand.PROXY_PORT or 8080) <= 65535:
                raise ValueError('proxy settings: PROXY_PORT must be 1-65535')
        except ValueError as e:
            raise serializers.ValidationError({'detail': str(e)})
        with transaction.atomic():
            for name, val in ser.validated_data.items():
                Setting.objects.update_or_create(
                    key=f'dhcp:{name}',
                    defaults={'value': ('true' if val else 'false') if isinstance(val, bool) else str(val)},
                )
            if ser.validated_data:
                DataVersion.bump()
        if cand.PROXY_HTTPS_MITM:
            ca.ensure_ca()
        return Response(ProxySettingsSerializer(self._serialize(cand)).data)


class ProxyRulesView(APIView):
    @extend_schema(responses=ProxyRuleListSerializer(many=True))
    def get(self, request):
        """The external ad-block lists of the settings and what the last download of each one did."""
        return Response(ProxyRuleListSerializer(rules.status(), many=True).data)

    @extend_schema(request=None, responses=ProxyRuleListSerializer(many=True))
    def post(self, request):
        """Download the external ad-block lists now (the proxy also does it every day). A list that fails keeps its old rules and shows the error."""
        return Response(ProxyRuleListSerializer(rules.sync_all(), many=True).data)


class ProxyInfoView(APIView):
    @staticmethod
    def _payload(regenerate=False, request=None):
        s = dhcp.dhcp_settings()
        info = ca.ca_info(regenerate=regenerate)
        req_host = request.get_host() if request else ''
        return {
            **info,
            'wpad_url': pac.wpad_url_for(s),
            'pac': pac.build_pac(s, request_host=req_host),
            'gui_url': str(settings.GUI_URL).rstrip('/'),
        }

    @extend_schema(responses=ProxyInfoSerializer)
    def get(self, request):
        """Return Proxy Root CA certificate info, active WPAD URL, and generated PAC script."""
        return Response(ProxyInfoSerializer(self._payload(request=request)).data)

    @extend_schema(request=None, responses=ProxyInfoSerializer, parameters=[GRANT])
    def post(self, request):
        """Regenerate the local Proxy Root CA certificate and private key. Needs a second-factor grant (scope proxy-change)."""
        if (denied := need_grant(request, scope='proxy-change')) is not None:
            return denied
        return Response(ProxyInfoSerializer(self._payload(regenerate=True, request=request)).data)


class ProxyTestView(APIView):
    @extend_schema(request=ProxyTestRequestSerializer, responses=ProxyTestResultSerializer)
    def post(self, request):
        """Test whether a URL or domain would be blocked by the proxy (Blacklist, ad URL rules, popup rules, or custom rules)."""
        ser = ProxyTestRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        raw_url = ser.validated_data['url'].strip()
        full_url = raw_url if '://' in raw_url else f'https://{raw_url}'
        parts = urlsplit(full_url)
        host = (parts.hostname or raw_url.split('/')[0]).lower()
        hit = pfilter.check_request(host, full_url, s=dhcp.dhcp_settings())
        return Response(ProxyTestResultSerializer({
            'url': full_url,
            'host': host,
            'blocked': hit is not None,
            'reason': hit[0] if hit else '',
            'detail': hit[1] if hit else '',
        }).data)


RULES_KEY, RULES_MAX = 'dhcp:PROXY_CUSTOM_RULES', 8000  # the max_length of ProxySettingsSerializer


def _set_rules(text):
    Setting.objects.update_or_create(key=RULES_KEY, defaults={'value': text})  # the signal raises DataVersion: runproxy applies it


def _forget_counts():
    try:
        cache.delete(COUNTS_KEY)
    except Exception:
        pass


def allow_host(host, url='', bypass=False):
    """Lets `host` (and its subdomains) through whichever layer blocks it now, and returns what was done (ProxyAllowSerializer), which undo_allow() reverses.
    DNS blacklist (personal block, public list, pattern): a personal allow entry, which fixes DNS and the proxy at once. A proxy rule (ad or popup address,
    your own rules, an ad-block list): an @@host exception in the proxy's own rules, which also keeps the site out of HTTPS inspection. Neither: the
    @@host exception too, as the proxy log's Allow always did (no page filtering, no inspection for the site).
    bypass: only the @@host exception, whatever blocks it: the proxy tunnels the site untouched (it outranks the DNS blacklist there), DNS stays as it is."""
    s = dhcp.dhcp_settings()
    out = {'host': host, 'dns_block': '', 'dns_id': None, 'dns_prev': None, 'dns_list': '', 'proxy_block': '', 'proxy_rule': '', 'note': ''}
    if not bypass and (hit := resolver.blocked_entry(host)):
        out['dns_block'] = f'{hit[0]} ({hit[1]})'
        row = BlockedDomain.objects.select_for_update().filter(name=host).first()
        if row and row.source == 'manual':
            out['dns_prev'] = {'allow': row.allow, 'enabled': row.enabled, 'regex': row.regex, 'expires': row.expires}
            row.allow, row.enabled, row.regex, row.expires = True, True, False, None
            row.save()
        else:
            if row:  # the same name in a public list gives way to the personal entry, as when it is added by hand (name is unique)
                out['dns_list'] = row.list_name
                row.delete()
                _forget_counts()
            row = BlockedDomain.objects.create(name=host, allow=True)
        out['dns_id'] = row.pk
        if not Setting.flag(PERSONAL_BLOCKS):
            out['note'] = 'Personal blocks are switched off: the DNS exception applies when they are on again.'
    allow_domains, _, _, _ = pfilter.parse_custom_rules(str(s.PROXY_CUSTOM_RULES or ''))
    if (hit := pfilter.check_request(host, url or f'https://{host}/', s=s, dns=False)) or not (out['dns_id'] or pfilter.is_domain_allowed(host, allow_domains)):
        out['proxy_block'] = f'{hit[0]}: {hit[1]}' if hit else ''
        rule, raw = f'@@{host}', str(s.PROXY_CUSTOM_RULES or '').rstrip()
        text = f'{raw}\n{rule}' if raw else rule
        if len(text) > RULES_MAX:
            raise serializers.ValidationError({'detail': f'Your own proxy rules are full ({RULES_MAX} characters): remove some in Proxy settings, then allow {host} again.'})
        _set_rules(text)
        out['proxy_rule'] = rule
    return out


def undo_allow(d):
    """Removes exactly what allow_host() added: the allow entry (or puts the entry it changed back), the public list entry that gave way, the @@ rule."""
    host = d['host']
    if d.get('dns_id') and (row := BlockedDomain.objects.select_for_update().filter(pk=d['dns_id'], name=host, source='manual').first()):
        if prev := d.get('dns_prev'):
            row.allow, row.enabled, row.regex, row.expires = prev['allow'], prev['enabled'], prev['regex'], prev['expires']
            row.save()
        else:
            row.delete()
    if d.get('dns_list') and not BlockedDomain.objects.filter(name=host).exists():
        BlockedDomain.objects.create(name=host, source='list', list_name=d['dns_list'])
        _forget_counts()
    if rule := d.get('proxy_rule'):
        if rule != f'@@{host}':
            raise serializers.ValidationError({'proxy_rule': f'Not the exception for {host}.'})
        lines = str(dhcp.dhcp_settings().PROXY_CUSTOM_RULES or '').split('\n')
        at = max((i for i, ln in enumerate(lines) if ln.strip() == rule), default=None)
        if at is not None:
            del lines[at]
            _set_rules('\n'.join(lines).rstrip())


def _host(raw):
    h = raw.strip().lower().rstrip('.')
    if not HOST_RE.match(h):
        raise serializers.ValidationError({'host': 'Not a site name (letters, digits, - and _ in labels separated by dots).'})
    return h


class ProxyAllowView(APIView):
    @extend_schema(request=ProxyAllowRequestSerializer, responses=ProxyAllowSerializer)
    def post(self, request):
        """Allow a site blocked in the proxy log: works out which layer blocks it now (DNS blacklist and/or the proxy's own rules) and adds the right
        exception to each, a personal allow entry and/or an @@host rule. Returns what was done; POST it to /api/proxy/allow/undo/ to take it back."""
        ser = ProxyAllowRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        with transaction.atomic():
            out = allow_host(_host(ser.validated_data['host']), ser.validated_data.get('url', '').strip(), ser.validated_data.get('bypass', False))
        return Response(ProxyAllowSerializer(out).data)


class ProxyAllowUndoView(APIView):
    @extend_schema(request=ProxyAllowUndoSerializer, responses={204: None})
    def post(self, request):
        """Undo an Allow: send back what /api/proxy/allow/ returned. Only that host's entry and @@ rule are touched."""
        ser = ProxyAllowUndoSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = {**ser.validated_data, 'host': _host(ser.validated_data['host'])}
        with transaction.atomic():
            undo_allow(d)
        return Response(status=204)


LOG_FILTERS = [
    OpenApiParameter('q', str, description='Search the host name (case-insensitive)'),
    OpenApiParameter('host', str, description='Exactly this host name'),
    OpenApiParameter('detail', str, description='Search the URL or the reason (case-insensitive)'),
    OpenApiParameter('status', str, description='HTTP status: a code (404) or a class (2xx, 3xx, 4xx, 5xx)'),
    OpenApiParameter('outcome', str, enum=['allowed', 'filtered', 'blocked', 'error', 'timeout'], description='Filter by outcome'),
    OpenApiParameter('client', str, description='Filter by client IP'),
    OpenApiParameter('method', str, description='Filter by HTTP/proxy method (GET, POST, CONNECT, MITM...)'),
    OpenApiParameter('hours', int, description='Only the last N hours (default 24, max 720)'),
]


def _log_filter(p):
    """The proxy log rows that match the filters of the query string (newest first by id), and the window in hours."""
    qs = ProxyLog.objects.order_by('-id')  # newest first by id (the proxy writes in time order): a page is a keyset, rows logged meanwhile do not shift it
    hours_str = p.get('hours', '24').strip()
    hours = int(hours_str) if hours_str.isdigit() else 24
    hours = min(hours, 720) or 720  # 0 (= all) made every filter scan the whole table: it means the longest window
    qs = qs.filter(time__gte=timezone.now() - timedelta(hours=hours))
    return qs, p


def _log_narrow(qs, p):
    if q := p.get('q', '').strip().lower():
        qs = qs.filter(host__icontains=q)
    if host := p.get('host', '').strip().lower():
        qs = qs.filter(host=host)
    if detail := p.get('detail', '').strip().lower():
        qs = qs.filter(Q(url__icontains=detail) | Q(reason__icontains=detail))
    if (status := p.get('status', '').strip().lower()) and re.fullmatch(r'[1-5]\d\d|[1-5]xx', status):
        qs = qs.filter(status__gte=int(status[0]) * 100, status__lt=int(status[0]) * 100 + 100) if status.endswith('xx') else qs.filter(status=int(status))
    if outcome := p.get('outcome', '').strip().lower():
        qs = qs.filter(outcome=outcome)
    if client := p.get('client', '').strip():
        qs = qs.filter(client=client)
    if method := p.get('method', '').strip().upper():
        qs = qs.filter(method__icontains=method)
    return qs


def _page_size(p, default=150):
    s = p.get('limit', str(default)).strip()
    return min(max(int(s) if s.isdigit() else default, 1), 500)


class ProxyLogsView(APIView):
    @extend_schema(
        parameters=[
            *LOG_FILTERS,
            OpenApiParameter('limit', int, description='Maximum rows returned (default 150, max 500)'),
            OpenApiParameter('before', int, description='Only the rows older than this id (the next page: the id of the last row shown)'),
        ],
        responses=ProxyLogsResponseSerializer,
    )
    def get(self, request):
        """Return recent HTTP/HTTPS proxy log entries with filters and summary counts."""
        p = request.query_params
        qs, _ = _log_filter(p)
        clients = list(qs.order_by('client').values_list('client', flat=True).distinct()[:200])
        qs = _log_narrow(qs, p)
        limit = _page_size(p)
        total = qs.count()
        blocked_count = qs.filter(outcome='blocked').count()
        filtered_count = qs.filter(outcome='filtered').count()
        before = p.get('before', '').strip()
        rows = list((qs.filter(id__lt=int(before)) if before.isdecimal() and len(before) < 19 else qs)[:limit])  # counts above are of every row that matches, the page is of the rows after `before`
        return Response(ProxyLogsResponseSerializer({
            'count': total,
            'blocked_count': blocked_count,
            'filtered_count': filtered_count,
            'clients': clients,
            'results': rows,
        }).data)


class ProxyLogsGroupedView(APIView):
    @extend_schema(
        parameters=[
            *LOG_FILTERS,
            OpenApiParameter('ordering', str, enum=['last', 'count'], description='Most recent first (default) or most requested first'),
            OpenApiParameter('limit', int, description='Maximum sites returned (default 50, max 500)'),
            OpenApiParameter('offset', int, description='Sites to skip (the next page)'),
        ],
        responses=ProxyLogGroupsResponseSerializer,
    )
    def get(self, request):
        """The proxy log grouped by site (host name): requests, blocked, failed, last request, average time and devices of each."""
        p = request.query_params
        qs, _ = _log_filter(p)
        qs = _log_narrow(qs, p).order_by()  # no ordering: it would be part of the GROUP BY
        limit = _page_size(p, 50)
        off = p.get('offset', '').strip()
        offset = int(off) if off.isdecimal() and len(off) < 9 else 0
        groups = (qs.values('host').annotate(
            count=Count('id'), blocked=Count('id', filter=Q(outcome='blocked')), failed=Count('id', filter=Q(outcome__in=['error', 'timeout'])),
            last=Max('time'), avg_ms=Avg('ms'), clients=Count('client', distinct=True))
            .order_by('-count' if p.get('ordering') == 'count' else '-last', 'host'))
        return Response(ProxyLogGroupsResponseSerializer({
            'count': qs.values('host').distinct().count(),
            'results': list(groups[offset:offset + limit]),
        }).data)


class ProxyLogsPurgeView(APIView):
    @extend_schema(request=ProxyLogPurgeRequestSerializer, responses=ProxyLogPurgeResultSerializer, parameters=[GRANT])
    def post(self, request):
        """Delete proxy log entries older than `older_than_hours` (0 = delete all). Like the query log: `dry_run` only counts; deleting needs a second-factor grant (scope log-purge)."""
        ser = ProxyLogPurgeRequestSerializer(data=request.data or {})
        ser.is_valid(raise_exception=True)
        hours = ser.validated_data.get('older_than_hours', 0)
        qs = ProxyLog.objects.filter(time__lt=timezone.now() - timedelta(hours=hours)) if hours > 0 else ProxyLog.objects.all()
        dry = ser.validated_data['dry_run']
        if dry:
            deleted = qs.count()
        elif (denied := need_grant(request, scope='log-purge')) is not None:
            return denied
        else:
            deleted = rollup.delete_chunked(qs)
        return Response(ProxyLogPurgeResultSerializer({'deleted': deleted, 'dry_run': dry}).data)


def _known_host(request):
    """The Host header only when ALLOWED_HOSTS accepts it: the PAC / profile must not point clients at a host the sender chose."""
    try:
        return request.get_host()
    except DisallowedHost:
        return ''


class WpadView(View):
    """Unauthenticated WPAD / PAC file endpoint (/wpad.dat, /proxy.pac) for LAN clients using DHCP option 252 or DNS wpad.<domain>."""

    def get(self, request):
        if not ratelimit.allowed(client_ip(request)):  # behind nginx REMOTE_ADDR is always 127.0.0.1
            return HttpResponseForbidden('Forbidden')
        s = dhcp.dhcp_settings()
        body = pac.build_pac(s, request_host=_known_host(request))
        resp = HttpResponse(body, content_type='application/x-ns-proxy-autoconfig; charset=utf-8')
        resp['Cache-Control'] = 'no-cache'
        return resp


def _https_only(request):
    """The redirect to the https GUI for a Root CA / profile asked over plain http (anyone on the path could swap the certificate), or None."""
    if request.is_secure() or not str(settings.GUI_URL).startswith('https://'):
        return None
    return HttpResponseRedirect(settings.GUI_URL.rstrip('/') + request.path)


class ProxyCaCertView(View):
    """Unauthenticated Root CA certificate download (/proxy-ca.crt) for LAN clients when HTTPS MITM inspection is used. https only."""

    def get(self, request):
        if (to := _https_only(request)) is not None:
            return to
        if not ratelimit.allowed(client_ip(request)):  # behind nginx REMOTE_ADDR is always 127.0.0.1
            return HttpResponseForbidden('Forbidden')
        cert_pem, _, _, _ = ca.ensure_ca(refresh=True)
        resp = HttpResponse(cert_pem, content_type='application/x-x509-ca-cert')
        resp['Content-Disposition'] = 'attachment; filename="zones-proxy-ca.crt"'
        return resp


class ProxyMobileConfigView(View):
    """Unauthenticated Apple Configuration Profile (/proxy.mobileconfig) for macOS and iOS (installs PAC proxy URL + Root CA). https only."""

    def get(self, request):
        if (to := _https_only(request)) is not None:
            return to
        if not ratelimit.allowed(client_ip(request)):  # behind nginx REMOTE_ADDR is always 127.0.0.1
            return HttpResponseForbidden('Forbidden')
        s = dhcp.dhcp_settings()
        cert_pem, _, _, _ = ca.ensure_ca(refresh=True)
        body = pac.build_mobileconfig(s, ca_cert_pem=cert_pem, request_host=_known_host(request))
        resp = HttpResponse(body, content_type='application/x-apple-aspen-config')
        resp['Content-Disposition'] = 'attachment; filename="zones-proxy.mobileconfig"'
        return resp


class WpadMiddleware:
    """Serve /wpad.dat, /proxy.pac, /proxy-ca.crt and /proxy.mobileconfig before SecurityMiddleware and CommonMiddleware
    so OS WPAD clients calling `http://wpad.<domain>/wpad.dat` over plain HTTP are neither 301-redirected to HTTPS nor rejected by ALLOWED_HOSTS."""

    _ROUTES = {
        '/wpad.dat': WpadView.as_view(),
        '/proxy.pac': WpadView.as_view(),
        '/proxy-ca.crt': ProxyCaCertView.as_view(),
        '/proxy.mobileconfig': ProxyMobileConfigView.as_view(),
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        view = self._ROUTES.get(request.path)
        if view is not None:
            return view(request)
        return self.get_response(request)
