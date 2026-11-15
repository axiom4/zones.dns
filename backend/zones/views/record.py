from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from django.db import transaction

from ..models import DataVersion, Record
from ..serializers import BulkActionSerializer, BulkResultSerializer, RecordSerializer
from .zone import GRANT, need_grant


@extend_schema_view(list=extend_schema(parameters=[OpenApiParameter('zone', int, description='Filter by zone id')]))
class RecordViewSet(viewsets.ModelViewSet):
    serializer_class = RecordSerializer

    def get_queryset(self):
        qs = Record.objects.order_by('name', 'type')
        zone = self.request.query_params.get('zone')
        return qs.filter(zone=int(zone)) if zone and zone.isdigit() else qs.none() if zone else qs

    @extend_schema(request=BulkActionSerializer, responses=BulkResultSerializer, parameters=[GRANT])
    @action(detail=False, methods=['post'])
    def bulk(self, request):
        s = BulkActionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        qs = Record.objects.filter(id__in=s.validated_data['ids'])
        act = s.validated_data['action']
        if act == 'delete':
            # a delete that leaves a zone without records is the zone's deletion in all but name: the same proof of a second factor
            emptied = [z for z in qs.values_list('zone', flat=True).distinct() if not Record.objects.filter(zone=z).exclude(id__in=s.validated_data['ids']).exists()]
            if len(emptied) > 1:
                raise serializers.ValidationError({'ids': 'This deletes every record of more than one zone: do one zone at a time.'})
            if emptied and (denied := need_grant(request, emptied[0])) is not None:
                return denied
            count = qs.count()
            qs.delete()
        else:
            count = qs.update(enabled=(act == 'enable'))
            transaction.on_commit(DataVersion.bump)
        return Response({'count': count})
