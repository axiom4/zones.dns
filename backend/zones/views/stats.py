from collections import Counter
from datetime import timedelta, timezone as dt_timezone

from django.core.cache import cache
from django.db.models import Count, Q, Sum, Value
from django.db.models.functions import TruncHour, TruncMinute
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import ProxyLog, QueryLog, StatCount
from ..stats.rollup import answer_kind, floor_hour
from ..serializers import StatsSerializer


def _counts(qs, field, limit=None):
    rows = qs.values(field).annotate(count=Count('id')).order_by('-count')[:limit]
    return [{'name': r[field], 'count': r['count']} for r in rows]


def _answers(qs):
    # shortcut: reads the answers of every row, fine for the 2 hours the log is read for; a longer window reads the 'answer' counters
    kinds = Counter(answer_kind(o, r, [a for a in ans if a['type'] in ('A', 'AAAA')]) for o, r, ans in qs.values_list('outcome', 'rcode', 'answers').iterator(chunk_size=5000))
    return [{'name': k, 'count': n} for k, n in kinds.most_common()]


def _from_log(start):
    qs = QueryLog.objects.filter(time__gte=start)
    outcomes = list(qs.values('outcome').annotate(count=Count('id'), ms=Sum('ms')).order_by('-count'))
    total = sum(r['count'] for r in outcomes)
    series = qs.annotate(t=TruncMinute('time', tzinfo=dt_timezone.utc)).values('t').annotate(count=Count('id'), blocked=Count('id', filter=Q(outcome='blocked')), proxy_blocked=Value(0), proxy_count=Value(0)).order_by('t')
    return {
        'total': total,
        'avg_ms': (sum(r['ms'] or 0 for r in outcomes) / total) if total else 0,
        'by_outcome': [{'name': r['outcome'], 'count': r['count']} for r in outcomes],
        'by_type': _counts(qs, 'type'),
        'by_answer': _answers(qs),
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
        'by_answer': top('answer'),
        'top_domains': top('name', 10),
        'top_blocked': top('blocked', 10),
        'top_clients': top('client', 10),
        'series': [{'t': r['hour'], 'count': r['count'], 'blocked': r['blocked'] or 0, 'proxy_blocked': 0, 'proxy_count': 0} for r in series],
    }


def _from_proxy(start, step):
    """The filtering proxy's own log in the same shape as the DNS statistics. Its outcomes are named proxied (allowed), filtered, blocked, error;
    the methods stand in for the query types; what it did is an answer kind too (blocked, error, proxied)."""
    qs = ProxyLog.objects.filter(time__gte=start if step == 60 else floor_hour(start))
    outcomes = list(qs.values('outcome').annotate(count=Count('id'), ms=Sum('ms')))
    total = sum(r['count'] for r in outcomes)
    trunc = TruncMinute if step == 60 else TruncHour
    series = qs.annotate(t=trunc('time', tzinfo=dt_timezone.utc)).values('t').annotate(count=Count('id'), blocked=Value(0), proxy_blocked=Count('id', filter=Q(outcome='blocked')), proxy_count=Count('id')).order_by('t')
    name = {'allowed': 'proxied'}
    answers = Counter()
    for r in outcomes:
        answers[r['outcome'] if r['outcome'] in ('blocked', 'error') else 'proxied'] += r['count']
    return {
        'total': total,
        'avg_ms': (sum(r['ms'] or 0 for r in outcomes) / total) if total else 0,
        'by_outcome': [{'name': name.get(r['outcome'], r['outcome']), 'count': r['count']} for r in outcomes],
        'by_type': _counts(qs, 'method'),
        'by_answer': [{'name': k, 'count': n} for k, n in answers.most_common()],
        'top_domains': _counts(qs, 'host', 10),
        'top_blocked': _counts(qs.filter(outcome='blocked'), 'host', 10),
        'top_clients': _counts(qs, 'client', 10),
        'series': list(series),
    }


def _sum_counts(a, b, limit=None):
    c = Counter()
    for row in a + b:
        c[row['name']] += row['count']
    return [{'name': k, 'count': n} for k, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def _merge(d, p):
    """DNS and proxy statistics as one. shortcut: the top lists join the top 10 of each side, so a name just outside both top 10s is missed."""
    total = d['total'] + p['total']
    series = {}
    for row in d['series'] + p['series']:
        t = row['t']
        o = series.setdefault(t, {'t': t, 'count': 0, 'blocked': 0, 'proxy_blocked': 0, 'proxy_count': 0})
        o['count'] += row['count']
        o['blocked'] += row['blocked'] or 0
        o['proxy_blocked'] += row['proxy_blocked'] or 0
        o['proxy_count'] += row['proxy_count'] or 0
    return {
        'total': total,
        'avg_ms': ((d['avg_ms'] * d['total'] + p['avg_ms'] * p['total']) / total) if total else 0,
        'by_outcome': _sum_counts(d['by_outcome'], p['by_outcome']),
        'by_type': _sum_counts(d['by_type'], p['by_type']),
        'by_answer': _sum_counts(d['by_answer'], p['by_answer']),
        'top_domains': _sum_counts(d['top_domains'], p['top_domains'], 10),
        'top_blocked': _sum_counts(d['top_blocked'], p['top_blocked'], 10),
        'top_clients': _sum_counts(d['top_clients'], p['top_clients'], 10),
        'series': [series[t] for t in sorted(series)],
    }


class StatsView(APIView):
    @extend_schema(
        parameters=[OpenApiParameter('hours', int, description='Time window in hours (default 24, max 720)'),
                    OpenApiParameter('source', str, enum=['all', 'dns', 'proxy'], description='What is counted: the DNS daemon (blacklist included), the filtering proxy, or both (default)'),
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
        since_raw = request.query_params.get('since', '')
        since = parse_datetime(since_raw) if len(since_raw) <= 40 else None
        since_key = ''
        if since and timezone.is_aware(since):
            start = min(max(since, now - timedelta(hours=720)), now)
            since_key = start.replace(second=0, microsecond=0).isoformat()
        source = request.query_params.get('source', 'all')
        source = source if source in ('all', 'dns', 'proxy') else 'all'
        key = f'stats:{hours}:{since_key}:{source}'
        try:
            if (hit := cache.get(key)) is not None:
                return Response(hit)
        except Exception:
            pass
        step = 60 if (now - start) <= timedelta(hours=2) else 3600
        # Windows up to 2 hours (per minute) are exact and small: read the log. Longer ones (per hour, UTC buckets) read the hourly counters,
        # and start at the hour in which the window begins.
        dns = (_from_log if step == 60 else _from_counters)(start) if source != 'proxy' else None
        prx = _from_proxy(start, step) if source != 'dns' else None
        data = dns if prx is None else prx if dns is None else _merge(dns, prx)
        data['step'] = step
        try:
            # shortcut: numbers up to 30 s old (5 min for periods over a day, which read the hourly counters of every name), to spare the repeated scans
            cache.set(key, data, 30 if now - start <= timedelta(hours=24) else 300)
        except Exception:
            pass
        return Response(data)
