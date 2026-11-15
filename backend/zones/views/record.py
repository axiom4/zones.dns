from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from django.db import transaction
from django.db.models import Count

from ..models import DataVersion, Record
from ..serializers import BulkActionSerializer, BulkResultSerializer, RecordSerializer
from .zone import GRANT, need_grant


BULK_MIN = 10


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
            # a delete that takes all the records of a zone, or most of them (BULK_MIN or more and over half), is the zone's deletion in all
            # but name: the same proof of a second factor. The GUI asks under the same rule (zone-page.ts).
            emptied = []
            for z, n in qs.values_list('zone').annotate(n=Count('id')):
                total = Record.objects.filter(zone=z).count()
                if n == total or (n >= BULK_MIN and n * 2 > total):
                    emptied.append(z)
            if len(emptied) > 1:
                raise serializers.ValidationError({'ids': 'This deletes most records of more than one zone: do one zone at a time.'})
            if emptied and (denied := need_grant(request, emptied[0])) is not None:
                return denied
            count = qs.count()
            qs.delete()
        else:
            count = qs.update(enabled=(act == 'enable'))
            transaction.on_commit(DataVersion.bump)
        return Response({'count': count})
