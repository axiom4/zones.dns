from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

import re

from django.db import transaction
from django.db.models import Count, Q
from rest_framework.pagination import LimitOffsetPagination

from ..models import DataVersion, Record, Zone
from ..serializers import BulkActionSerializer, BulkResultSerializer, RecordSerializer
from .zone import GRANT, need_grant


BULK_MIN = 10


class RecordPagination(LimitOffsetPagination):
    default_limit = 100
    max_limit = 500


def _nat(s):
    """Natural order of a text: www2 before www10."""
    return tuple((0, int(p), '') if p.isdigit() else (1, 0, p) for p in re.split(r'(\d+)', (s or '').lower()) if p)


def _ip4(v):
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', v or '')
    return int(m[1]) << 24 | int(m[2]) << 16 | int(m[3]) << 8 | int(m[4]) if m and all(int(g) < 256 for g in m.groups()) else None


def _ptr_ip(zone, name, rtype):
    """The full IPv4 address of a PTR record of an in-addr.arpa zone (its name is only the tail), else None."""
    if rtype != 'PTR' or not zone.endswith('.in-addr.arpa') or name in ('', '@'):
        return None
    labels = (name + '.' + zone[:-len('.in-addr.arpa')]).split('.')
    return _ip4('.'.join(reversed(labels))) if len(labels) == 4 else None


def sort_key(by, zone_name):
    """The order of the GUI list: by IP (the value of A records, the address of PTR names), name, type or TTL; ties by type then name."""
    def addr(name, rtype, value):
        ip = _ptr_ip(zone_name, name, rtype)
        return (0, ip, ()) if ip is not None else (1, 0, _nat(name))

    def key(r):  # r = (id, name, type, value, ttl)
        _, name, rtype, value, ttl = r
        if by == 'ttl':
            main = (ttl,)
        elif by == 'type':
            main = _nat(rtype)
        elif by == 'name':
            main = addr(name, rtype, value)
        else:
            ip = _ip4(value)
            main = (0, ip, ()) if ip is not None else (1, 0, _nat(value))
        return main, _nat(rtype), addr(name, rtype, value)
    return key


@extend_schema_view(list=extend_schema(parameters=[OpenApiParameter('zone', int, description='Filter by zone id')]))
class RecordViewSet(viewsets.ModelViewSet):
    serializer_class = RecordSerializer
    pagination_class = RecordPagination

    def get_queryset(self):
        qs = Record.objects.order_by('name', 'type')
        zone = self.request.query_params.get('zone')
        return qs.filter(zone=int(zone)) if zone and zone.isdigit() else qs.none() if zone else qs

    @extend_schema(parameters=[
        OpenApiParameter('q', str, description='Words that must each appear in the name, type, value or note'),
        OpenApiParameter('sort', str, enum=['', 'name', 'type', 'value', 'ttl'], description='Order (default: by IP: the value, or the address of a reverse zone name)'),
        OpenApiParameter('desc', bool, description='Reverse the order'),
    ])
    def list(self, request, *args, **kwargs):
        # the order is natural (IP numbers, www2 before www10) so it is made here, on the light columns of the matches; only the page is read in full
        qs, p = self.get_queryset(), request.query_params
        for w in p.get('q', '').split()[:8]:
            qs = qs.filter(Q(name__icontains=w) | Q(type__icontains=w) | Q(value__icontains=w) | Q(note__icontains=w))
        zone = Zone.objects.filter(pk=int(p['zone'])).values_list('name', flat=True).first() if p.get('zone', '').isdigit() else ''
        by = p.get('sort', '')
        by = by if by in ('name', 'type', 'value', 'ttl') else 'name' if (zone or '').endswith('.arpa') else 'value'
        rows = sorted(qs.values_list('id', 'name', 'type', 'value', 'ttl'), key=sort_key(by, zone or ''), reverse=p.get('desc') in ('1', 'true', 'True'))
        ids = self.paginator.paginate_queryset([r[0] for r in rows], request, view=self)
        page = Record.objects.in_bulk(ids)
        return self.paginator.get_paginated_response(self.get_serializer([page[i] for i in ids if i in page], many=True).data)

    @extend_schema(request=BulkActionSerializer, responses=BulkResultSerializer, parameters=[GRANT])
    @action(detail=False, methods=['post'])
    def bulk(self, request):
        s = BulkActionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        qs = Record.objects.filter(id__in=s.validated_data['ids'])
        act = s.validated_data['action']
        if act in ('delete', 'disable'):
            # a delete or switch-off that takes all the records of a zone, or most of them (BULK_MIN or more and over half), is the zone's
            # deletion (or switch-off) in all but name: the same proof of a second factor. The GUI asks under the same rule (zone-page.ts).
            emptied = []
            for z, n in qs.values_list('zone').annotate(n=Count('id')):
                total = Record.objects.filter(zone=z).count()
                if n == total or (n >= BULK_MIN and n * 2 > total):
                    emptied.append(z)
            if len(emptied) > 1:
                raise serializers.ValidationError({'ids': f'This would {act} most records of more than one zone: do one zone at a time.'})
            if emptied and (denied := need_grant(request, emptied[0])) is not None:
                return denied
        if act == 'delete':
            count = qs.count()
            qs.delete()
        else:
            count = qs.update(enabled=(act == 'enable'))
            transaction.on_commit(DataVersion.bump)
        return Response({'count': count})
