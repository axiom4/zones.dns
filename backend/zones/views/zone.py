from django.http import HttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .. import mfa, reverse, zonefile
from ..models import Zone
from ..serializers import (ReverseZoneRequestSerializer, SyncPtrResultSerializer, ZoneImportResultSerializer,
                           ZoneImportSerializer, ZoneSerializer)


class ZoneViewSet(viewsets.ModelViewSet):
    queryset = Zone.objects.order_by('name')
    serializer_class = ZoneSerializer

    @extend_schema(parameters=[OpenApiParameter('X-MFA-Grant', str, OpenApiParameter.HEADER, required=False,
                                                description='Proof of a second factor for this deletion (POST /api/mfa/stepup/...). Required when the user has a second factor.')])
    def destroy(self, request, *args, **kwargs):
        zone = self.get_object()
        if mfa.methods(request.user):  # someone who has no second factor cannot be asked for one
            try:
                mfa.use_grant(request.user, f'zone-delete:{zone.pk}', request.headers.get('X-MFA-Grant'))
            except mfa.MfaError as e:
                return Response({'detail': e.text, 'mfa_required': True}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    @extend_schema(responses={(200, 'text/plain'): OpenApiTypes.STR})
    @action(detail=True, methods=['get'])
    def export(self, request, pk=None):
        zone = self.get_object()
        res = HttpResponse(zonefile.export_zone(zone), content_type='text/plain; charset=utf-8')
        res['Content-Disposition'] = f'attachment; filename="{zone.name}.zone"'
        return res

    @extend_schema(request=ZoneImportSerializer, responses=ZoneImportResultSerializer)
    @action(detail=True, methods=['post'], url_path='import')
    def import_(self, request, pk=None):
        s = ZoneImportSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(zonefile.import_zone(self.get_object(), **s.validated_data))

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
