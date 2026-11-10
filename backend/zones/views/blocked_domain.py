import re
from datetime import timedelta

from django.db.models import Count, Sum
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import LISTS_OFF, PERSONAL_BLOCKS, PUBLIC_LISTS, BlockedDomain, Setting, StatCount, Zone
from ..resolver import blocked_match
from ..rollup import floor_hour
from ..serializers import BlockedDomainSerializer, ImportedBlockedSerializer, PersonalSwitchSerializer, PublicListSerializer, PublicListSwitchSerializer
from ..serializers.stats import CountSerializer

# a label that names what the host is for: ads, tracking, telemetry
TRACKER_LABEL = re.compile(r'(^|[-_])(ads?|adserver|adservice|adsystem|analytics?|telemetry|metrics?|track(er|ing)?|pixel|beacon|stats?|doubleclick|popunder|banner)([-_0-9]|$)')


class BlockedDomainViewSet(viewsets.ModelViewSet):
    queryset = BlockedDomain.objects.filter(source='manual').order_by('name')
    serializer_class = BlockedDomainSerializer

    @extend_schema(parameters=[OpenApiParameter('q', str), OpenApiParameter('list', str, description='Only this public list'), OpenApiParameter('offset', int),
                               OpenApiParameter('limit', int)], responses=ImportedBlockedSerializer)
    @action(detail=False, methods=['get'])
    def imported(self, request):
        """Domains imported from public blocklists (read-only, searchable, paged: there can be tens of thousands)."""
        qs = BlockedDomain.objects.filter(source='list').order_by('name')
        if lst := request.query_params.get('list', '').strip():
            qs = qs.filter(list_name=lst)
        if q := request.query_params.get('q', '').strip().lower():
            qs = qs.filter(name__contains=q)
        try:
            offset, limit = max(int(request.query_params.get('offset', 0)), 0), min(max(int(request.query_params.get('limit', 100)), 1), 500)
        except ValueError:
            offset, limit = 0, 100
        return Response({'count': qs.count(), 'names': list(qs.values_list('name', flat=True)[offset:offset + limit])})

    @extend_schema(request=PublicListSwitchSerializer, responses=PublicListSerializer(many=True))
    @action(detail=False, methods=['get', 'patch'])
    def lists(self, request):
        """The imported public lists, each with its domain count and an on/off switch (off = its domains are kept but ignored)."""
        off = set(filter(None, (Setting.objects.filter(key=LISTS_OFF).values_list('value', flat=True).first() or '').split(',')))
        if request.method == 'PATCH':
            ser = PublicListSwitchSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            name, on = ser.validated_data['name'], ser.validated_data['enabled']
            off = off - {name} if on else off | {name}
            Setting.objects.update_or_create(key=LISTS_OFF, defaults={'value': ','.join(sorted(off))})
        rows = BlockedDomain.objects.filter(source='list').values('list_name').annotate(n=Count('id')).order_by('list_name')
        return Response([{'name': r['list_name'] or 'list', 'count': r['n'], 'enabled': r['list_name'] not in off} for r in rows])

    @extend_schema(parameters=[OpenApiParameter('days', int, description='Look back this many days (default 7, max 30)')], responses=CountSerializer(many=True))
    @action(detail=False, methods=['get'])
    def suggestions(self, request):
        """Names that were asked for and look like ads or trackers (a label such as ads, track, pixel, telemetry), not blocked, not allowed and not
        in our zones, most asked first. A hint to confirm one by one, not a verdict."""
        try:
            days = min(max(int(request.query_params.get('days', 7)), 1), 30)
        except ValueError:
            days = 7
        rows = (StatCount.objects.filter(dim='name', hour__gte=floor_hour(timezone.now() - timedelta(days=days)))
                .values('key').annotate(c=Sum('n')).order_by('-c', 'key')[:5000])  # shortcut: only the 5000 most asked names are looked at
        zones = set(Zone.objects.values_list('name', flat=True))
        allowed = set(BlockedDomain.objects.filter(allow=True).values_list('name', flat=True))
        out = []
        for r in rows:
            name = r['key']
            labels = name.split('.')
            suffixes = {'.'.join(labels[i:]) for i in range(len(labels))}
            if (name and any(TRACKER_LABEL.search(lb) for lb in labels[:-1]) and not suffixes & (zones | allowed) and not blocked_match(name)):
                out.append({'name': name, 'count': r['c']})
                if len(out) == 50:
                    break
        return Response(out)

    @extend_schema(request=PersonalSwitchSerializer, responses=PersonalSwitchSerializer)
    @action(detail=False, methods=['get', 'patch'])
    def personal(self, request):
        """The master switch of the Personal blocks: off = the domains added by hand are kept but ignored."""
        return self._switch(request, PERSONAL_BLOCKS)

    @extend_schema(request=PersonalSwitchSerializer, responses=PersonalSwitchSerializer)
    @action(detail=False, methods=['get', 'patch'], url_path='public')
    def public_lists(self, request):
        """The master switch of the Public lists: off = the imported domains are kept but ignored."""
        return self._switch(request, PUBLIC_LISTS)

    def _switch(self, request, key):
        if request.method == 'PATCH':
            ser = PersonalSwitchSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            Setting.set_flag(key, ser.validated_data['enabled'])
        return Response({'enabled': Setting.flag(key)})
