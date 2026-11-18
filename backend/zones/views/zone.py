from django.http import HttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..security import mfa
from ..dnsd import reverse, zonefile
from ..models import Zone
from ..serializers import (ReverseZoneRequestSerializer, SyncPtrResultSerializer, ZoneImportResultSerializer,
                           ZoneImportSerializer, ZoneSerializer)


GRANT = OpenApiParameter('X-MFA-Grant', str, OpenApiParameter.HEADER, required=False,
                         description='Proof of a second factor (POST /api/mfa/stepup/...; scope zone-delete:<id> for deleting, switching off or emptying a zone, log-purge for the query log, proxy-change and dhcp-change for settings that redirect the traffic of the clients). Required when the user has a second factor.')


def need_grant(request, zone_id=None, scope=None):
    """None, or the 403 answer when the user has a second factor and did not prove it for this zone (scope zone-delete:<id>) or this scope."""
    if not mfa.methods(request.user):  # someone who has no second factor cannot be asked for one
        return None
    try:
        mfa.use_grant(request.user, scope or f'zone-delete:{zone_id}', request.headers.get('X-MFA-Grant'))
    except mfa.MfaError as e:
        return Response({'detail': e.text, 'mfa_required': True}, status=status.HTTP_403_FORBIDDEN)
    return None


class ZoneViewSet(viewsets.ModelViewSet):
    queryset = Zone.objects.order_by('name')
    serializer_class = ZoneSerializer

    @extend_schema(parameters=[GRANT])
    def destroy(self, request, *args, **kwargs):
        if (denied := need_grant(request, self.get_object().pk)) is not None:
            return denied
        return super().destroy(request, *args, **kwargs)

    @extend_schema(parameters=[GRANT])
    def update(self, request, *args, **kwargs):
        """Switching a zone off, or renaming it, stops serving it under its name, like deleting it: the same proof of a second factor (scope zone-delete:<id>)."""
        zone = self.get_object()
        peek = self.get_serializer(zone, data=request.data, partial=True)
        peek.is_valid(raise_exception=True)
        vd = peek.validated_data
        if (zone.enabled and vd.get('enabled') is False or vd.get('name', zone.name) != zone.name) and (denied := need_grant(request, zone.pk)) is not None:
            return denied
        return super().update(request, *args, **kwargs)

    @extend_schema(parameters=[GRANT])
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(responses={(200, 'text/plain'): OpenApiTypes.STR})
    @action(detail=True, methods=['get'])
    def export(self, request, pk=None):
        zone = self.get_object()
        res = HttpResponse(zonefile.export_zone(zone), content_type='text/plain; charset=utf-8')
        res['Content-Disposition'] = f'attachment; filename="{zone.name}.zone"'
        return res

    @extend_schema(request=ZoneImportSerializer, responses=ZoneImportResultSerializer, parameters=[GRANT])
    @action(detail=True, methods=['post'], url_path='import')
    def import_(self, request, pk=None):
        s = ZoneImportSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        zone = self.get_object()
        # replace deletes every record first: the same proof as deleting the zone
        if s.validated_data['replace'] and not s.validated_data['dry_run'] and (denied := need_grant(request, zone.pk)) is not None:
            return denied
        return Response(zonefile.import_zone(zone, **s.validated_data))

    @extend_schema(request=ReverseZoneRequestSerializer, responses={201: ZoneSerializer})
    @action(detail=False, methods=['post'])
    def reverse(self, request):
        """Create the reverse zone for a network (CIDR)."""
        s = ReverseZoneRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        name = reverse.cidr_to_zone(s.validated_data['cidr'])
        zone, created = Zone.objects.get_or_create(name=name)
        if not created:
            raise serializers.ValidationError({'cidr': f'The zone {name} already exists.'})
        return Response(ZoneSerializer(zone).data, status=status.HTTP_201_CREATED)

    @extend_schema(request=None, responses=SyncPtrResultSerializer)
    @action(detail=True, methods=['post'], url_path='sync-ptr')
    def sync_ptr(self, request, pk=None):
        """Create the missing PTR records in this reverse zone from all A/AAAA records."""
        zone = self.get_object()
        if reverse.zone_to_cidr(zone.name) is None:
            raise serializers.ValidationError({'detail': 'This is not a reverse zone.'})
        return Response(reverse.sync_ptrs(zone))
