from django.http import Http404
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from ..dhcp import v4 as dhcp, v6 as dhcp6, ra
from ..models import DataVersion, Dhcp6Lease, DhcpLease, Setting
from ..serializers import DhcpLeaseSerializer, DhcpSettingsSerializer

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
        rows = [{'id': r.id, 'family': 4, 'kind': 'address', 'address': r.ip, 'client': r.mac or r.client, 'hostname': r.hostname, 'expires': r.expires, 'active': r.expires > now}
                for r in qs4]
        rows += [{'id': r.id, 'family': 6, 'kind': 'address' if r.kind in ('na', 'ta') else 'prefix', 'address': r.value, 'client': r.duid, 'hostname': '', 'expires': r.expires, 'active': r.expires > now}
                 for r in qs6]
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
