from datetime import timedelta
import ipaddress
from urllib.parse import urlsplit

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.views import View
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from ..dhcp import v4 as dhcp
from ..dnsd import ratelimit
from ..models import DataVersion, ProxyLog, Setting
from .token import client_ip
from .zone import GRANT, need_grant
from ..proxy import ca, filter as pfilter, pac, rules
from ..serializers import (
    ProxyInfoSerializer,
    ProxyLogPurgeRequestSerializer,
    ProxyLogPurgeResultSerializer,
    ProxyLogsResponseSerializer,
    ProxyRuleListSerializer,
    ProxySettingsSerializer,
    ProxyTestRequestSerializer,
    ProxyTestResultSerializer,
)
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
        for name, val in ser.validated_data.items():
            Setting.objects.update_or_create(
                key=f'dhcp:{name}',
                defaults={'value': ('true' if val else 'false') if isinstance(val, bool) else str(val)},
            )
        if cand.PROXY_HTTPS_MITM:
            ca.ensure_ca()
        if ser.validated_data:
            DataVersion.bump()
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


class ProxyLogsView(APIView):
    @extend_schema(
        parameters=[
            OpenApiParameter('q', str, description='Search host, URL or reason (case-insensitive)'),
            OpenApiParameter('outcome', str, enum=['allowed', 'filtered', 'blocked', 'error'], description='Filter by outcome'),
            OpenApiParameter('client', str, description='Filter by client IP'),
            OpenApiParameter('method', str, description='Filter by HTTP/proxy method (GET, POST, CONNECT, MITM...)'),
            OpenApiParameter('hours', int, description='Only the last N hours (0 = all)'),
            OpenApiParameter('limit', int, description='Maximum rows returned (default 150, max 500)'),
        ],
        responses=ProxyLogsResponseSerializer,
    )
    def get(self, request):
        """Return recent HTTP/HTTPS proxy log entries with filters and summary counts."""
        p = request.query_params
        qs = ProxyLog.objects.order_by('-time', '-id')
        hours_str = p.get('hours', '24').strip()
        hours = int(hours_str) if hours_str.isdigit() else 24
        if hours > 0:
            qs = qs.filter(time__gte=timezone.now() - timedelta(hours=min(hours, 24 * 365)))
        clients = list(qs.order_by('client').values_list('client', flat=True).distinct()[:200])
        if q := p.get('q', '').strip().lower():
            qs = qs.filter(Q(host__icontains=q) | Q(url__icontains=q) | Q(reason__icontains=q))
        if outcome := p.get('outcome', '').strip().lower():
            qs = qs.filter(outcome=outcome)
        if client := p.get('client', '').strip():
            qs = qs.filter(client=client)
        if method := p.get('method', '').strip().upper():
            qs = qs.filter(method__icontains=method)
        lim_str = p.get('limit', '150').strip()
        limit = min(max(int(lim_str) if lim_str.isdigit() else 150, 1), 500)
        total = qs.count()
        blocked_count = qs.filter(outcome='blocked').count()
        filtered_count = qs.filter(outcome='filtered').count()
        rows = list(qs[:limit])
        return Response(ProxyLogsResponseSerializer({
            'count': total,
            'blocked_count': blocked_count,
            'filtered_count': filtered_count,
            'clients': clients,
            'results': rows,
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
            deleted, _ = qs.delete()
        return Response(ProxyLogPurgeResultSerializer({'deleted': deleted, 'dry_run': dry}).data)


class WpadView(View):
    """Unauthenticated WPAD / PAC file endpoint (/wpad.dat, /proxy.pac) for LAN clients using DHCP option 252 or DNS wpad.<domain>."""

    def get(self, request):
        if not ratelimit.allowed(client_ip(request)):  # behind nginx REMOTE_ADDR is always 127.0.0.1
            return HttpResponseForbidden('Forbidden')
        s = dhcp.dhcp_settings()
        body = pac.build_pac(s, request_host=request.META.get('HTTP_HOST', ''))
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
        body = pac.build_mobileconfig(s, ca_cert_pem=cert_pem, request_host=request.META.get('HTTP_HOST', ''))
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
