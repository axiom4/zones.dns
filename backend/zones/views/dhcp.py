from django.http import Http404
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import netcheck, oui
from ..dhcp import v4 as dhcp, v6 as dhcp6, ra
from ..dhcp.v6 import duid_mac
from ..models import DataVersion, Dhcp6Lease, DhcpLease, DhcpReservation, Setting
from ..serializers import DhcpLeaseSerializer, DhcpPingRequestSerializer, DhcpPingResultSerializer, DhcpSettingsSerializer, MacVendorSerializer

LIMIT = 1000


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
        names = {}  # a DHCPv6 client has no host name of its own here: the one its MAC gave to DHCPv4 (the newest lease) or to a reservation
        for r in DhcpReservation.objects.exclude(hostname='').values('mac', 'hostname'):
            names[r['mac']] = r['hostname']
        for r in DhcpLease.objects.exclude(hostname='').exclude(mac='').order_by('updated').values('mac', 'hostname'):
            names[r['mac']] = r['hostname']
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
        except ValueError as e:
            raise serializers.ValidationError({'detail': str(e)})
        for name, val in ser.validated_data.items():
            Setting.objects.update_or_create(
                key=f'dhcp:{name}',
                defaults={'value': ('true' if val else 'false') if isinstance(val, bool) else str(val)},
            )
        if ser.validated_data:
            DataVersion.bump()
        return Response(DhcpSettingsSerializer(self._serialize(cand)).data)


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
