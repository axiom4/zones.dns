from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from django.db import transaction

from ..models import DataVersion, Record
from ..serializers import BulkActionSerializer, BulkResultSerializer, RecordSerializer


@extend_schema_view(list=extend_schema(parameters=[OpenApiParameter('zone', int, description='Filter by zone id')]))
class RecordViewSet(viewsets.ModelViewSet):
    serializer_class = RecordSerializer

    def get_queryset(self):
        qs = Record.objects.order_by('name', 'type')
        zone = self.request.query_params.get('zone')
        return qs.filter(zone=int(zone)) if zone and zone.isdigit() else qs.none() if zone else qs

    @extend_schema(request=BulkActionSerializer, responses=BulkResultSerializer)
    @action(detail=False, methods=['post'])
    def bulk(self, request):
        s = BulkActionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        qs = Record.objects.filter(id__in=s.validated_data['ids'])
        act = s.validated_data['action']
        if act == 'delete':
            count = qs.count()
            qs.delete()
        else:
            count = qs.update(enabled=(act == 'enable'))
            transaction.on_commit(DataVersion.bump)
        return Response({'count': count})
