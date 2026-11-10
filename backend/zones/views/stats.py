from datetime import timedelta, timezone as dt_timezone

from django.core.cache import cache
from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncMinute
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import QueryLog, StatCount
from ..rollup import floor_hour
from ..serializers import StatsSerializer


def _counts(qs, field, limit=None):
    rows = qs.values(field).annotate(count=Count('id')).order_by('-count')[:limit]
    return [{'name': r[field], 'count': r['count']} for r in rows]


def _from_log(start):
    qs = QueryLog.objects.filter(time__gte=start)
    outcomes = list(qs.values('outcome').annotate(count=Count('id'), ms=Sum('ms')).order_by('-count'))
    total = sum(r['count'] for r in outcomes)
    series = qs.annotate(t=TruncMinute('time', tzinfo=dt_timezone.utc)).values('t').annotate(count=Count('id'), blocked=Count('id', filter=Q(outcome='blocked'))).order_by('t')
    return {
        'total': total,
        'avg_ms': (sum(r['ms'] or 0 for r in outcomes) / total) if total else 0,
        'by_outcome': [{'name': r['outcome'], 'count': r['count']} for r in outcomes],
        'by_type': _counts(qs, 'type'),
        'top_domains': _counts(qs, 'name', 10),
        'top_blocked': _counts(qs.filter(outcome='blocked'), 'name', 10),
        'top_clients': _counts(qs, 'client', 10),
        'series': list(series),
    }


def _from_counters(start):
    rows = StatCount.objects.filter(hour__gte=floor_hour(start))

    def top(dim, limit=None):
        return [{'name': r['key'], 'count': r['c']} for r in rows.filter(dim=dim).values('key').annotate(c=Sum('n')).order_by('-c', 'key')[:limit]]

    agg = rows.filter(dim='outcome').aggregate(n=Sum('n'), ms=Sum('ms'))
    total = agg['n'] or 0
    series = rows.filter(dim='outcome').values('hour').annotate(count=Sum('n'), blocked=Sum('n', filter=Q(key='blocked'))).order_by('hour')
    return {
        'total': total,
        'avg_ms': (agg['ms'] / total) if total else 0,
        'by_outcome': top('outcome'),
        'by_type': top('type'),
        'top_domains': top('name', 10),
        'top_blocked': top('blocked', 10),
        'top_clients': top('client', 10),
        'series': [{'t': r['hour'], 'count': r['count'], 'blocked': r['blocked'] or 0} for r in series],
    }


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
        key = f"stats:{hours}:{request.query_params.get('since', '')}"
        if (hit := cache.get(key)) is not None:
            return Response(hit)
        now = timezone.now()
        start = now - timedelta(hours=hours)
        since = parse_datetime(request.query_params.get('since', ''))
        if since and timezone.is_aware(since):
            start = min(max(since, now - timedelta(hours=720)), now)
        step = 60 if (now - start) <= timedelta(hours=2) else 3600
        # Windows up to 2 hours (per minute) are exact and small: read the log. Longer ones (per hour, UTC buckets) read the hourly counters,
        # and start at the hour in which the window begins.
        data = (_from_log if step == 60 else _from_counters)(start)
        data['step'] = step
        cache.set(key, data, 30)  # shortcut: numbers up to 30 s old, to spare the repeated full scans of the log; lower it if that matters
        return Response(data)
