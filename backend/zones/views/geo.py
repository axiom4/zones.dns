import ipaddress
import threading
import time
from datetime import timedelta

from django.core.cache import cache
from django.db import connection
from django.db.models import Sum
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework.exceptions import APIException, ValidationError

from .. import geo, whois
from ..models import GeoStat
from ..rollup import floor_hour
from ..serializers import DestinationsSerializer, GeoIpsResultSerializer, WhoisSerializer


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


class WhoisView(APIView):
    @extend_schema(parameters=[OpenApiParameter('ip', str, description='A public IP address')], responses=WhoisSerializer)
    def get(self, request):
        """Who owns an address: the WHOIS record from its regional registry (cached for a day)."""
        try:
            ip = ipaddress.ip_address(request.query_params.get('ip', '').strip())
        except ValueError:
            raise ValidationError({'ip': 'Not an IP address.'})
        if not ip.is_global:
            raise ValidationError({'ip': 'Only public addresses have a WHOIS record.'})  # also keeps this from reaching internal hosts
        try:
            server, text = whois.lookup(str(ip))
        except OSError:
            raise APIException('The WHOIS server did not answer.')
        return Response({'ip': str(ip), 'server': server, 'text': text})


class GeoDestinationsView(APIView):
    @extend_schema(parameters=[OpenApiParameter('hours', int, description='Time window in hours (default 24, max 720)')], responses=DestinationsSerializer)
    def get(self, request):
        """Where the answers of the DNS queries point, by country and network."""
        try:
            hours = min(max(int(request.query_params.get('hours', 24)), 1), 720)
        except ValueError:
            hours = 24
        key = f'geo-dest-{hours}'
        hit = cache.get(key)  # (computed at, result): kept a day, refreshed in the background so a request never waits for the aggregation
        if hit is None:
            return Response(_compute(key, hours))
        age = time.time() - hit[0]
        # stale, or lookups still pending: one process refreshes (the lock), everybody else gets the last result now
        if (age > REFRESH or hit[1]['pending']) and age > 5 and cache.add(key + '-lock', 1, 120):
            threading.Thread(target=_refresh, args=(key, hours), daemon=True).start()
        return Response(hit[1])


REFRESH = 60  # seconds


def _compute(key, hours):
    # The hourly counters of answered addresses per domain; the window starts at the hour.
    # shortcut: at most 20000 distinct (domain, address) pairs, most frequent first.
    rows = [{'domain': r['domain'], 'answers': [{'type': 'A', 'value': r['ip']}], 'n': r['c']}
            for r in GeoStat.objects.filter(hour__gte=floor_hour(timezone.now() - timedelta(hours=hours))).values('domain', 'ip').annotate(c=Sum('n')).order_by('-c')[:20000]]
    out = geo.destinations(rows)
    cache.set(key, (time.time(), out), 86400)
    return out


def _refresh(key, hours):
    try:
        _compute(key, hours)
    finally:
        connection.close()  # this thread's own database connection
        cache.delete(key + '-lock')
