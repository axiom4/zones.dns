import hashlib
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db.models import Avg, Count, Max, Q, Sum, TextField
from django.db.models.functions import Cast
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..stats import geo, rollup
from ..models import DomainStat, LogTotal, QueryLog, Record, StatCount
from ..stats.rollup import floor_hour
from ..serializers import GroupResolvedSerializer, QueryLogClientSerializer, PurgeRequestSerializer, QueryLogAnswersSerializer, PurgeResultSerializer, QueryLogGroupSerializer, QueryLogSerializer
from rest_framework.pagination import LimitOffsetPagination


class LogPagination(LimitOffsetPagination):
    default_limit = 50
    max_limit = 500

    def get_count(self, queryset):
        fast = stat_count(self.request.query_params)
        if fast is not None:
            return fast
        # exact, but remembered COUNT_TTL seconds per filter: the live refresh asks every few seconds and a COUNT(*) over millions of rows is slow
        if queryset.query.group_by is None:
            q = queryset.order_by().values('pk')
        else:
            q = queryset.order_by()
            q.query.annotations.clear()
        # the key is the request, not the SQL: 'hours' puts the current time in the SQL, so it would differ at every refresh
        params = sorted((k, v) for k, v in self.request.query_params.items() if k not in ('limit', 'offset'))
        key = 'qlog-count:' + hashlib.md5(repr((self.request.path, params)).encode()).hexdigest()
        n = cache.get(key)
        if n is None:
            n = q.count()
            cache.set(key, n, COUNT_TTL)
        return n


COUNT_TTL = 30


def stat_count(p):
    """The number of rows read from the hourly counters (a few thousand rows at most, never the log) when the filters allow it:
    none, or one of outcome / type / client, plus the period. The hours at the two ends of the period are not whole, so the first one is
    counted in the log (one hour of rows through the time index). None = this filter needs the log itself."""
    other = [f for f in ('q', 'name', 'domain', 'rcode', 'answer', 'country') if p.get(f)]
    one = [f for f in ('outcome', 'type', 'client') if p.get(f)]
    if other or len(one) > 1:
        return None
    dim, val = (one[0], p[one[0]].strip()) if one else ('outcome', '')
    if dim == 'type':
        val = val.upper()
    elif dim == 'outcome':
        val = val.lower()
    if not LogTotal.objects.exists():
        return None  # counters not built yet (manage.py rebuild_stats)
    logs = QueryLog.objects.filter(**{dim: val} if val else {})
    if p.get('hours', '').isdigit() and int(p['hours']):
        cutoff = timezone.now() - timedelta(hours=int(p['hours']))
        first = floor_hour(cutoff)
        if first < cutoff:
            first += timedelta(hours=1)
        edge = logs.filter(time__gte=cutoff, time__lt=first).count()
        counters = StatCount.objects.filter(dim=dim, hour__gte=first, **({'key': val} if val else {}))
        return (counters.aggregate(n=Sum('n'))['n'] or 0) + edge
    return LogTotal.objects.filter(dim=dim, **({'key': val} if val else {})).aggregate(n=Sum('n'))['n'] or 0  # at most 4 rows, usually 1


FILTERS = [
    OpenApiParameter('q', str, description='Name contains (case-insensitive)'),
    OpenApiParameter('name', str, description='Exact name'),
    OpenApiParameter('domain', str, description='Exact registrable domain, e.g. example.com'),
    OpenApiParameter('type', str, description='Exact query type, e.g. A'),
    OpenApiParameter('outcome', str, enum=['local', 'forwarded', 'blocked', 'error']),
    OpenApiParameter('client', str, description='Exact client IP'),
    OpenApiParameter('rcode', str, description='Response code, e.g. NXDOMAIN'),
    OpenApiParameter('answer', str, description='Text contained in the answer records, e.g. an IP address'),
    OpenApiParameter('hours', int, description='Only the last N hours'),
    OpenApiParameter('country', str, description='Only domains whose answers point to this country (ISO code, PRIV or ??) in the period (24 hours if hours is not given)'),
]


@extend_schema_view(list=extend_schema(parameters=FILTERS))
class QueryLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = QueryLogSerializer
    pagination_class = LogPagination

    def get_queryset(self):
        p = self.request.query_params
        qs = QueryLog.objects.order_by('-time', '-id')
        if self.action == 'list':
            qs = qs.defer('answers')  # the list does not show them (the answers endpoint does): no need to read the JSON of every row
        if p.get('q'):
            qs = qs.filter(name__contains=p['q'].strip().lower())  # QueryLog.name is always stored lowercase
        for f in ('name', 'domain', 'type', 'outcome', 'client', 'rcode'):
            if p.get(f):
                val = p[f].strip()
                if f in ('name', 'domain'):
                    val = '' if val == '.' else val.rstrip('.').lower()
                elif f in ('type', 'rcode'):
                    val = val.upper()
                qs = qs.filter(**{f: val})  # '.' is how the root (an empty name) is shown
        if p.get('answer'):
            qs = qs.annotate(answers_text=Cast('answers', TextField())).filter(answers_text__icontains=p['answer'].strip())
        if p.get('hours', '').isdigit():
            qs = qs.filter(time__gte=timezone.now() - timedelta(hours=int(p['hours'])))
        if p.get('country'):
            hours = int(p['hours']) if p.get('hours', '').isdigit() and int(p['hours']) else 24  # the counters have no 'all time': 24 h is the page default
            qs = qs.filter(domain__in=geo.country_domains(p['country'].strip().upper(), min(hours, 720)))
        return qs

    @extend_schema(
        parameters=FILTERS + [OpenApiParameter('ordering', str, enum=['last', 'count'], description='Most recent (default) or most requested first'),
                              OpenApiParameter('by', str, enum=['domain', 'name'], description='Group by registrable domain (default) or by full host name')],
        responses=QueryLogGroupSerializer(many=True),
    )
    @action(detail=False, methods=['get'])
    def grouped(self, request):
        """Same filters as the list, one row per registrable domain (or per host name with by=name)."""
        p = request.query_params
        key = 'name' if p.get('by') == 'name' else 'domain'
        by_count = p.get('ordering') == 'count'
        base = self.get_queryset().order_by()
        ranked = None
        stat_totals = {}
        if key == 'domain' and not any(p.get(f) for f in ('q', 'name', 'type', 'client', 'rcode', 'answer')):
            d_qs = DomainStat.objects.all()
            if p.get('domain'):
                val = p['domain'].strip()
                d_qs = d_qs.filter(domain='' if val == '.' else val.rstrip('.').lower())
            if p.get('hours', '').isdigit():
                d_qs = d_qs.filter(hour__gte=floor_hour(timezone.now() - timedelta(hours=int(p['hours']))))
            if p.get('country'):
                hours = int(p['hours']) if p.get('hours', '').isdigit() and int(p['hours']) else 24
                d_qs = d_qs.filter(domain__in=geo.country_domains(p['country'].strip().upper(), min(hours, 720)))
            outcome = p.get('outcome', '').strip().lower()
            if outcome in ('local', 'forwarded', 'blocked', 'error'):
                d_qs = d_qs.filter(**{f'{outcome}__gt': 0})
            if (by_count or (p.get('hours', '').isdigit() and int(p['hours']) >= 24)) and d_qs.exists():
                sort_agg = (Sum(outcome) if outcome in ('local', 'forwarded', 'blocked', 'error') else Sum('n')) if by_count else Max('hour')
                ranked = d_qs.values('domain').annotate(sort_val=sort_agg).order_by('-sort_val', 'domain')
                page_keys = [r['domain'] for r in self.paginate_queryset(ranked)]
                if not page_keys:
                    return self.get_paginated_response([])
                if not outcome:
                    stat_totals = {
                        r['domain']: r
                        for r in d_qs.filter(domain__in=page_keys).values('domain').annotate(
                            count=Sum('n'), local=Sum('local'), forwarded=Sum('forwarded'), blocked=Sum('blocked'), error=Sum('error'), total_ms=Sum('ms'), last=Max('hour'),
                        )
                    }
        elif key == 'name' and by_count and not any(p.get(f) for f in ('domain', 'type', 'client', 'rcode', 'answer', 'outcome')):
            s_qs = StatCount.objects.filter(dim='name')
            if p.get('q'):
                s_qs = s_qs.filter(key__contains=p['q'].strip().lower())
            if p.get('name'):
                val = p['name'].strip()
                s_qs = s_qs.filter(key='' if val == '.' else val.rstrip('.').lower())
            if p.get('hours', '').isdigit():
                s_qs = s_qs.filter(hour__gte=floor_hour(timezone.now() - timedelta(hours=int(p['hours']))))
            if s_qs.exists():
                ranked = s_qs.values('key').annotate(sort_val=Sum('n')).order_by('-sort_val', 'key')
                page_keys = [r['key'] for r in self.paginate_queryset(ranked)]
                if not page_keys:
                    return self.get_paginated_response([])
        if ranked is None:
            ranked = base.values(key).annotate(sort_val=Count('id') if by_count else Max('time')).order_by('-sort_val', key)
            page_keys = [r[key] for r in self.paginate_queryset(ranked)]
            if not page_keys:
                return self.get_paginated_response([])
        count = lambda o: Count('id', filter=Q(outcome=o))
        details = {r[key]: r for r in base.filter(**{f'{key}__in': page_keys}).values(key).annotate(
            names=Count('name', distinct=True), count=Count('id'), last=Max('time'), avg_ms=Avg('ms'), clients=Count('client', distinct=True),
            local=count('local'), forwarded=count('forwarded'), blocked=count('blocked'), error=count('error'),
        )}
        page = []
        for k in page_keys:
            r = details.get(k)
            if k in stat_totals:
                st = stat_totals[k]
                avg = (st['total_ms'] / st['count']) if st['count'] else 0.0
                r = {
                    **(r or {key: k, 'names': 1, 'clients': 1, 'last': st['last']}),
                    'count': st['count'], 'local': st['local'], 'forwarded': st['forwarded'], 'blocked': st['blocked'], 'error': st['error'], 'avg_ms': avg,
                }
            if r:
                r['name'] = r[key] or '.'  # the root name is empty in the log: an empty group name could not be asked for again
                page.append(r)
        return self.get_paginated_response(QueryLogGroupSerializer(page, many=True).data)

    @extend_schema(parameters=[OpenApiParameter('hours', int, description='Only the last N hours (whole hours); 0 or missing = all')], responses=QueryLogClientSerializer(many=True))
    @action(detail=False, methods=['get'], pagination_class=None)
    def clients(self, request):
        """Distinct client IPs, most active first (at most 500), with the FQDN of the default zone that points to each.
        Read from the hourly counters (a few rows), not by scanning the log."""
        rows = StatCount.objects.filter(dim='client')
        hours = request.query_params.get('hours', '')
        if hours.isdigit() and int(hours):
            rows = rows.filter(hour__gte=floor_hour(timezone.now() - timedelta(hours=int(hours))))
        found = list(rows.values('key').annotate(count=Sum('n')).order_by('-count', 'key')[:500])
        zone, names = settings.DEFAULT_ZONE, {}
        if zone:
            recs = Record.objects.filter(zone__name=zone, zone__enabled=True, enabled=True, type__in=('A', 'AAAA'), value__in=[r['key'] for r in found]).values_list('value', 'name')
            # shortcut: IPv6 compared as text (no normalisation); several names for one IP: the shortest wins. Wildcards are not names of a host
            for ip, n in sorted((r for r in recs if '*' not in r[1]), key=lambda r: (-len(r[1]), r[1])):
                names[ip] = (zone, zone) if n == '@' else (f'{n}.{zone}', n)
        return Response(QueryLogClientSerializer([{'ip': r['key'], 'name': names.get(r['key'], ('', ''))[0], 'host': names.get(r['key'], ('', ''))[1], 'count': r['count']} for r in found], many=True).data)

    @extend_schema(request=PurgeRequestSerializer, responses=PurgeResultSerializer)
    @action(detail=False, methods=['post'])
    def purge(self, request):
        """Delete old queries (not filtered by the list filters: it ages the whole log)."""
        s = PurgeRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        hours, dry = s.validated_data['older_than_hours'], s.validated_data['dry_run']
        qs = QueryLog.objects.filter(time__lt=timezone.now() - timedelta(hours=hours)) if hours else QueryLog.objects.all()
        if dry:
            count = qs.count()
        else:
            count, _ = qs.delete()
            rollup.purge(timezone.now() - timedelta(hours=hours) if hours else None)
        return Response({'count': count, 'dry_run': dry})

    @extend_schema(
        parameters=[OpenApiParameter('ids', str, description='Comma separated query ids (max 200)')],
        responses=QueryLogAnswersSerializer(many=True),
    )
    @action(detail=False, methods=['get'], pagination_class=None)
    def answers(self, request):
        """Answer records for some queries, loaded on demand."""
        ids = [int(i) for i in request.query_params.get('ids', '').split(',') if i.strip().isdigit()][:200]
        rows = QueryLog.objects.filter(id__in=ids).values('id', 'answers')
        return Response(QueryLogAnswersSerializer(rows, many=True).data)

    @extend_schema(
        parameters=[
            OpenApiParameter('by', str, enum=['domain', 'name'], description='What the names are: registrable domains (default) or host names'),
            OpenApiParameter('names', str, description='Comma separated names (max 50)'),
        ],
        responses=GroupResolvedSerializer(many=True),
    )
    @action(detail=False, methods=['get'], pagination_class=None)
    def resolved(self, request):
        """Recent distinct answers (A/AAAA/CNAME, at most 4) for some groups, loaded on demand."""
        key = 'name' if request.query_params.get('by') == 'name' else 'domain'
        names = ['' if n == '.' else n for n in (n.strip().lower() for n in request.query_params.get('names', '').split(',')) if n][:50]
        out = {n: [] for n in names}
        # shortcut: scans the latest 500 answered queries of these groups
        recent = QueryLog.objects.filter(**{f'{key}__in': names}).exclude(answers=[]).order_by('-time').values(key, 'answers')[:500]
        for row in recent:
            res = out[row[key]]
            for a in row['answers']:
                item = {'type': a['type'], 'value': a['value']}
                if a['type'] in ('A', 'AAAA', 'CNAME') and item not in res and len(res) < 4:
                    res.append(item)
        return Response(GroupResolvedSerializer([{'name': n or '.', 'resolved': v} for n, v in out.items()], many=True).data)
