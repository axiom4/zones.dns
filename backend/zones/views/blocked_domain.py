from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import BlockedDomain
from ..serializers import BlockedDomainSerializer, ImportedBlockedSerializer


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.filter(source='manual').order_by('name')
    serializer_class = BlockedDomainSerializer

    @extend_schema(parameters=[OpenApiParameter('q', str), OpenApiParameter('offset', int), OpenApiParameter('limit', int)], responses=ImportedBlockedSerializer)
    @action(detail=False, methods=['get'])
    def imported(self, request):
        """Domains imported from public blocklists (read-only, searchable, paged: there can be tens of thousands)."""
        qs = BlockedDomain.objects.filter(source='list').order_by('name')
        if q := request.query_params.get('q', '').strip().lower():
            qs = qs.filter(name__contains=q)
        try:
            offset, limit = max(int(request.query_params.get('offset', 0)), 0), min(max(int(request.query_params.get('limit', 100)), 1), 500)
        except ValueError:
            offset, limit = 0, 100
        return Response({'count': qs.count(), 'names': list(qs.values_list('name', flat=True)[offset:offset + limit])})
