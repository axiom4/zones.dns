from datetime import timedelta, timezone as dt_timezone

from django.db.models import Avg, Count
from django.db.models.functions import TruncHour, TruncMinute
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.types import OpenApiTypes
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
        parameters=[OpenApiParameter('hours', int, description='Time window in hours (default 24, max 720)'),
                    OpenApiParameter('since', OpenApiTypes.DATETIME, description='Start of the window (at most 720 hours back); replaces hours. For windows that begin at a local midnight')],
        responses=StatsSerializer,
    )
    def get(self, request):
        try:
            hours = min(max(int(request.query_params.get('hours', 24)), 1), 720)
        except ValueError:
            hours = 24
        now = timezone.now()
        start = now - timedelta(hours=hours)
        since = parse_datetime(request.query_params.get('since', ''))
        if since and timezone.is_aware(since):
            start = min(max(since, now - timedelta(hours=720)), now)
        qs = QueryLog.objects.filter(time__gte=start)
        # Counts per minute for short windows, per hour otherwise (the GUI groups them again as the period needs: 6 hours, days...).
        # In UTC: whole-hour offsets keep the same buckets, and MySQL needs no time zone tables.
        step = 60 if (now - start) <= timedelta(hours=2) else 3600
        trunc = TruncMinute if step == 60 else TruncHour
        series = qs.annotate(t=trunc('time', tzinfo=dt_timezone.utc)).values('t').annotate(count=Count('id')).order_by('t')
        return Response({
            'total': qs.count(),
            'avg_ms': qs.aggregate(a=Avg('ms'))['a'] or 0,
            'by_outcome': _counts(qs, 'outcome'),
            'by_type': _counts(qs, 'type'),
            'top_domains': _counts(qs, 'name', 10),
            'top_blocked': _counts(qs.filter(outcome='blocked'), 'name', 10),
            'top_clients': _counts(qs, 'client', 10),
            'step': step,
            'series': list(series),
        })
