from datetime import timedelta

from django.db.models import Avg, Count
from django.db.models.functions import TruncHour
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import QueryLog
from ..serializers import StatsSerializer


def _counts(qs, field, limit=None):
    rows = qs.values(field).annotate(count=Count('id')).order_by('-count')[:limit]
    return [{'name': r[field], 'count': r['count']} for r in rows]


class StatsView(APIView):
    @extend_schema(
        parameters=[OpenApiParameter('hours', int, description='Time window in hours (default 24, max 720)')],
        responses=StatsSerializer,
    )
    def get(self, request):
        try:
            hours = min(max(int(request.query_params.get('hours', 24)), 1), 720)
        except ValueError:
            hours = 24
        qs = QueryLog.objects.filter(time__gte=timezone.now() - timedelta(hours=hours))
        per_hour = qs.annotate(hour=TruncHour('time')).values('hour').annotate(count=Count('id')).order_by('hour')
        return Response({
            'total': qs.count(),
            'avg_ms': qs.aggregate(a=Avg('ms'))['a'] or 0,
            'by_outcome': _counts(qs, 'outcome'),
            'by_type': _counts(qs, 'type'),
            'top_domains': _counts(qs, 'name', 10),
            'top_blocked': _counts(qs.filter(outcome='blocked'), 'name', 10),
            'top_clients': _counts(qs, 'client', 10),
            'per_hour': list(per_hour),
        })
