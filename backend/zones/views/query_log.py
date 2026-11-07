from datetime import timedelta

from django.db.models import Avg, Count, Max, Q, TextField
from django.db.models.functions import Cast
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import QueryLog
from ..serializers import GroupResolvedSerializer, PurgeRequestSerializer, QueryLogAnswersSerializer, PurgeResultSerializer, QueryLogGroupSerializer, QueryLogSerializer
from rest_framework.pagination import LimitOffsetPagination


class LogPagination(LimitOffsetPagination):
    default_limit = 50
    max_limit = 500


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
]


@extend_schema_view(list=extend_schema(parameters=FILTERS))
class QueryLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = QueryLogSerializer
    pagination_class = LogPagination

    def get_queryset(self):
        p = self.request.query_params
        qs = QueryLog.objects.order_by('-time', '-id')
        if p.get('q'):
            qs = qs.filter(name__icontains=p['q'].strip())
        for f in ('name', 'domain', 'type', 'outcome', 'client', 'rcode'):
            if p.get(f):
                qs = qs.filter(**{f: p[f]})
        if p.get('answer'):
            qs = qs.annotate(answers_text=Cast('answers', TextField())).filter(answers_text__icontains=p['answer'].strip())
        if p.get('hours', '').isdigit():
            qs = qs.filter(time__gte=timezone.now() - timedelta(hours=int(p['hours'])))
        return qs

    @extend_schema(
        parameters=FILTERS + [OpenApiParameter('ordering', str, enum=['last', 'count'], description='Most recent (default) or most requested first'),
                              OpenApiParameter('by', str, enum=['domain', 'name'], description='Group by registrable domain (default) or by full host name')],
        responses=QueryLogGroupSerializer(many=True),
    )
    @action(detail=False, methods=['get'])
    def grouped(self, request):
        """Same filters as the list, one row per registrable domain (or per host name with by=name)."""
        key = 'name' if request.query_params.get('by') == 'name' else 'domain'
        count = lambda o: Count('id', filter=Q(outcome=o))
        qs = (self.get_queryset().order_by().values(key).annotate(
            names=Count('name', distinct=True), count=Count('id'), last=Max('time'), avg_ms=Avg('ms'), clients=Count('client', distinct=True),
            local=count('local'), forwarded=count('forwarded'), blocked=count('blocked'), error=count('error'),
        ))
        qs = qs.order_by('-count' if request.query_params.get('ordering') == 'count' else '-last', key)
        page = self.paginate_queryset(qs)
        for r in page:
            r['name'] = r[key]
        return self.get_paginated_response(QueryLogGroupSerializer(page, many=True).data)

    @extend_schema(request=PurgeRequestSerializer, responses=PurgeResultSerializer)
    @action(detail=False, methods=['post'])
    def purge(self, request):
        """Delete old queries (not filtered by the list filters: it ages the whole log)."""
        s = PurgeRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        hours, dry = s.validated_data['older_than_hours'], s.validated_data['dry_run']
        qs = QueryLog.objects.filter(time__lt=timezone.now() - timedelta(hours=hours)) if hours else QueryLog.objects.all()
        count = qs.count()
        if not dry:
            qs.delete()
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
        names = [n.strip().lower() for n in request.query_params.get('names', '').split(',') if n.strip()][:50]
        out = {n: [] for n in names}
        # shortcut: scans the latest 500 answered queries of these groups
        recent = QueryLog.objects.filter(**{f'{key}__in': names}).exclude(answers=[]).order_by('-time').values(key, 'answers')[:500]
        for row in recent:
            res = out[row[key]]
            for a in row['answers']:
                item = {'type': a['type'], 'value': a['value']}
                if a['type'] in ('A', 'AAAA', 'CNAME') and item not in res and len(res) < 4:
                    res.append(item)
        return Response(GroupResolvedSerializer([{'name': n, 'resolved': v} for n, v in out.items()], many=True).data)
