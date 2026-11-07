import ipaddress
from datetime import timedelta

from django.db.models import Count
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import geo
from ..models import QueryLog
from ..serializers import DestinationsSerializer, GeoIpsResultSerializer


class GeoIpsView(APIView):
    @extend_schema(parameters=[OpenApiParameter('ips', str, description='Comma separated IP addresses (max 50)')], responses=GeoIpsResultSerializer)
    def get(self, request):
        """Country and network of some addresses (cached; unknown ones are looked up)."""
        ips = []
        for i in request.query_params.get('ips', '').split(',')[:50]:
            try:
                ips.append(str(ipaddress.ip_address(i.strip())))
            except ValueError:
                pass  # not an address: ignored
        found, pending = geo.locate(ips)
        return Response({'results': [found[i] for i in ips if i in found], 'pending': pending})


class GeoDestinationsView(APIView):
    @extend_schema(parameters=[OpenApiParameter('hours', int, description='Time window in hours (default 24, max 720)')], responses=DestinationsSerializer)
    def get(self, request):
        """Where the answers of the DNS queries point, by country and network."""
        try:
            hours = min(max(int(request.query_params.get('hours', 24)), 1), 720)
        except ValueError:
            hours = 24
        # Every answered query of the window, grouped by identical (domain, answers) so the whole period is counted, not a sample.
        # shortcut: at most 20000 distinct groups, most frequent first.
        rows = list(QueryLog.objects.filter(time__gte=timezone.now() - timedelta(hours=hours)).exclude(answers=[])
                    .values('domain', 'answers').annotate(n=Count('id')).order_by('-n')[:20000])
        return Response(geo.destinations(rows))
