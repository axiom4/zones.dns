import ipaddress
from urllib.parse import urlsplit

from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.utils import timezone
from django.views import View
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import netcheck, oui
from ..dhcp import v4 as dhcp, v6 as dhcp6, ra
from ..dhcp.neighbors import neighbors
from ..dhcp.v6 import duid_mac
from ..dnsd import ratelimit
from ..models import DataVersion, Dhcp6Lease, DhcpLease, DhcpReservation, Setting
from ..proxy import ca, filter as pfilter, pac
from ..serializers import DhcpLeaseSerializer, DhcpNeighborSerializer, DhcpPingRequestSerializer, DhcpPingResultSerializer, DhcpSettingsSerializer, MacVendorSerializer, ProxyInfoSerializer, ProxyTestRequestSerializer, ProxyTestResultSerializer

LIMIT = 1000


def names_by_mac():
    """{mac: host name} from the DHCPv4 reservations and, over them, the newest DHCPv4 leases."""
    names = {}
    for r in DhcpReservation.objects.exclude(hostname='').values('mac', 'hostname'):
        names[r['mac']] = r['hostname']
    for r in DhcpLease.objects.exclude(hostname='').exclude(mac='').order_by('updated').values('mac', 'hostname'):
        names[r['mac']] = r['hostname']
    return names


class DhcpNeighborsView(APIView):
    @extend_schema(responses=DhcpNeighborSerializer(many=True))
    def get(self, request):
        """The IPv6 hosts on the network that this machine knows (kernel neighbour table, Linux): also the ones that configured themselves with SLAAC and so have no lease. 503 where `ip` is missing or fails."""
        try:
            rows = neighbors(dhcp.dhcp_settings().DHCP_INTERFACE)
        except RuntimeError as e:
            return Response({'detail': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        found, names = oui.lookup_many({r['mac'] for r in rows}), names_by_mac()
        for r in rows:
            r['vendor'], r['hostname'] = oui.label(found[r['mac']]), names.get(r['mac'], '')
        rows.sort(key=lambda r: (r['kind'] == 'link-local', ipaddress.IPv6Address(r['address'])))
        return Response(DhcpNeighborSerializer(rows, many=True).data)


class DhcpLeasesView(APIView):
    @extend_schema(parameters=[OpenApiParameter('q', str, description='Search address, client or host name'), OpenApiParameter('all', bool, description='Include the leases that ended')],
                   responses=DhcpLeaseSerializer(many=True))
    def get(self, request):
        """The addresses and prefixes given out by the DHCP servers (DHCPv4 and DHCPv6), newest first; the ones that ended are listed with all=true."""
        q, now = request.query_params.get('q', '').strip().lower(), timezone.now()
        every = request.query_params.get('all') in ('1', 'true')
        qs4 = DhcpLease.objects.exclude(client__startswith='declined-').exclude(client__startswith='conflict-')
        qs6 = Dhcp6Lease.objects.exclude(duid__startswith='declined')
        if not every:
            qs4, qs6 = qs4.filter(expires__gt=now), qs6.filter(expires__gt=now)
        rows = [{'id': r.id, 'family': 4, 'kind': 'address', 'address': r.ip, 'client': r.mac or r.client, 'mac': r.mac, 'hostname': r.hostname, 'vendor': '', 'expires': r.expires, 'active': r.expires > now}
                for r in qs4]
        rows += [{'id': r.id, 'family': 6, 'kind': 'address' if r.kind in ('na', 'ta') else 'prefix', 'address': r.value, 'client': r.duid, 'mac': r.mac or duid_mac(r.duid), 'hostname': r.hostname, 'vendor': '', 'expires': r.expires, 'active': r.expires > now}
                 for r in qs6]
        found = oui.lookup_many({r['mac'] for r in rows if r['mac']})
        names = names_by_mac()  # a DHCPv6 client has no host name of its own here: the one its MAC gave to DHCPv4
        for r in rows:
            r['vendor'] = oui.label(found[r['mac']]) if r['mac'] else ''
            if r['family'] == 6 and not r['hostname']:
                r['hostname'] = names.get(r['mac'], '')
        if q:
            rows = [r for r in rows if q in f"{r['address']} {r['client']} {r['hostname']}".lower()]
        rows.sort(key=lambda r: r['expires'], reverse=True)
        return Response(DhcpLeaseSerializer(rows[:LIMIT], many=True).data)


class DhcpLeaseView(APIView):
    @extend_schema(responses={204: None})
    def delete(self, request, family, pk):
        """End a lease: the address is free again (the client keeps using it until it renews, then is told it cannot)."""
        model = {4: DhcpLease, 6: Dhcp6Lease}.get(family)
        if model is None:
            raise Http404
        deleted, _ = model.objects.filter(pk=pk).delete()
        if not deleted:
            raise Http404
        return Response(status=status.HTTP_204_NO_CONTENT)


class DhcpSettingsView(APIView):
    @staticmethod
    def _serialize(s):
        return {name: getattr(s, name) for name, _ in dhcp.DHCP_SETTING_SPEC}

    @extend_schema(responses=DhcpSettingsSerializer)
    def get(self, request):
        """Current DHCPv4, DHCPv6 and Router Advertisement configuration (settings overlaid with GUI changes)."""
        return Response(DhcpSettingsSerializer(self._serialize(dhcp.dhcp_settings())).data)

    @extend_schema(request=DhcpSettingsSerializer, responses=DhcpSettingsSerializer)
    def patch(self, request):
        """Update DHCPv4, DHCPv6 and Router Advertisement settings and validate them before saving."""
        ser = DhcpSettingsSerializer(data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        cand = dhcp.dhcp_settings(overrides=ser.validated_data)
        try:
            if cand.DHCP:
                dhcp.scopes(cand)
            if cand.DHCP6:
                dhcp6.Config6.from_settings(cand, [])
            if cand.DHCP_RA:
                ra.RaConfig.from_settings(cand, [], False)
            if cand.DHCP_WPAD_URL and (len(cand.DHCP_WPAD_URL) > 255 or not cand.DHCP_WPAD_URL.startswith(('http://', 'https://'))):
                raise ValueError('DHCP settings: DHCP_WPAD_URL must be an http:// or https:// URL of at most 255 characters')
            if cand.PROXY_ADDRESS:
                try:
                    ipaddress.ip_address(cand.PROXY_ADDRESS)
                except ValueError:
                    raise ValueError(f'DHCP settings: bad PROXY_ADDRESS {cand.PROXY_ADDRESS!r}')
            if not 1 <= int(cand.PROXY_PORT or 8080) <= 65535:
                raise ValueError('DHCP settings: PROXY_PORT must be 1-65535')
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
        return Response(DhcpSettingsSerializer(self._serialize(cand)).data)


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

    @extend_schema(request=None, responses=ProxyInfoSerializer)
    def post(self, request):
        """Regenerate the local Proxy Root CA certificate and private key."""
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


class WpadView(View):
    """Unauthenticated WPAD / PAC file endpoint (/wpad.dat, /proxy.pac) for LAN clients using DHCP option 252 or DNS wpad.<domain>."""

    def get(self, request):
        client_ip = request.META.get('REMOTE_ADDR', '')
        if not ratelimit.allowed(client_ip):
            return HttpResponseForbidden('Forbidden')
        s = dhcp.dhcp_settings()
        body = pac.build_pac(s, request_host=request.META.get('HTTP_HOST', ''))
        resp = HttpResponse(body, content_type='application/x-ns-proxy-autoconfig; charset=utf-8')
        resp['Cache-Control'] = 'no-cache'
        return resp


class ProxyCaCertView(View):
    """Unauthenticated Root CA certificate download (/proxy-ca.crt) for LAN clients when HTTPS MITM inspection is used."""

    def get(self, request):
        client_ip = request.META.get('REMOTE_ADDR', '')
        if not ratelimit.allowed(client_ip):
            return HttpResponseForbidden('Forbidden')
        cert_pem, _, _, _ = ca.ensure_ca()
        resp = HttpResponse(cert_pem, content_type='application/x-x509-ca-cert')
        resp['Content-Disposition'] = 'attachment; filename="zones-proxy-ca.crt"'
        return resp


class ProxyMobileConfigView(View):
    """Unauthenticated Apple Configuration Profile (/proxy.mobileconfig) for macOS and iOS (installs PAC proxy URL + Root CA)."""

    def get(self, request):
        client_ip = request.META.get('REMOTE_ADDR', '')
        if not ratelimit.allowed(client_ip):
            return HttpResponseForbidden('Forbidden')
        s = dhcp.dhcp_settings()
        cert_pem, _, _, _ = ca.ensure_ca()
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


class MacVendorView(APIView):
    @extend_schema(parameters=[OpenApiParameter('mac', str, required=True, description='MAC address in any usual notation')], responses=MacVendorSerializer)
    def get(self, request):
        """Who made the network card with this MAC address (looked up in a local table, nothing is sent to the Internet)."""
        mac = request.query_params.get('mac', '')
        return Response(MacVendorSerializer({'mac': mac, **oui.lookup(mac)}).data)


class PingView(APIView):
    @extend_schema(request=DhcpPingRequestSerializer, responses=DhcpPingResultSerializer(many=True))
    def post(self, request):
        """Ping hosts of the local network from this server (one ICMP echo each, up to 64). Public addresses are refused."""
        ser = DhcpPingRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        return Response(DhcpPingResultSerializer(netcheck.ping_many(ser.validated_data['addresses']), many=True).data)
