import csv
import io
import re

from django.db import transaction
from django.http import HttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import DhcpReservation
from ..serializers import DhcpReservationImportResultSerializer, DhcpReservationImportSerializer, DhcpReservationSerializer
from ..serializers.dhcp_reservation import check_row
from .zone import GRANT, need_grant

COLUMNS = ['mac', 'ip', 'hostname', 'note', 'enabled']
NAMES = {'mac': 'mac', 'mac address': 'mac', 'macaddress': 'mac', 'ip': 'ip', 'ip address': 'ip', 'ipaddress': 'ip', 'address': 'ip',
         'hostname': 'hostname', 'host name': 'hostname', 'host': 'hostname', 'name': 'hostname', 'note': 'note', 'enabled': 'enabled'}
HEADER_NAMES = set(NAMES)
MAC_LIKE = re.compile(r'[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}(\.[0-9a-fA-F]{4}){2}')
IP_LIKE = re.compile(r'\d{1,3}(\.\d{1,3}){3}')
TRUE = ('1', 'true', 'yes', 'on', '')


def import_rows(text, replace, dry_run):
    """The result of importing CSV text. Any error in any line: nothing is changed."""
    rows, errors = [], []
    first = next((l for l in text.splitlines() if l.strip()), '')
    delim = next((d for d in (',', ';', '\t') if d in first), ',')  # Excel in many locales writes ';'
    lines = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if r and any(c.strip() for c in r) and not r[0].lstrip().startswith('#')]
    cols = None
    if lines and {c.strip().lower() for c in lines[0]} & HEADER_NAMES:  # header: columns in any order
        cols = [NAMES.get(c.strip().lower()) for c in lines[0]]
        lines = lines[1:]
    for n, r in enumerate(lines, 1):
        r = [c.strip() for c in r]
        if cols:
            d = {k: r[i] for i, k in enumerate(cols) if k and i < len(r)}
        else:  # no header: the MAC and the address are found by their look, the rest is hostname, note, enabled in that order
            mac = next((c for c in r if MAC_LIKE.fullmatch(c)), '')
            ip = next((c for c in r if IP_LIKE.fullmatch(c)), '')
            rest = [c for c in r if c not in (mac, ip)] + [''] * 3
            d = {'mac': mac, 'ip': ip, 'hostname': rest[0], 'note': rest[1], 'enabled': rest[2]}
        try:
            mac, ip, host = check_row(d.get('mac', ''), d.get('ip', ''), d.get('hostname', '').split('.')[0])  # nas.lan -> nas
            rows.append((mac, ip, host, d.get('note', '')[:255], d.get('enabled', '').lower() in TRUE))
        except ValueError as e:
            errors.append(f'line {n} ({d.get("mac", "")} {d.get("ip", "")}): {e}')
    seen_mac, seen_ip = {}, {}
    for mac, ip, *_ in rows:
        if mac in seen_mac or ip in seen_ip:
            errors.append(f'{mac} {ip}: repeated in the file')
        seen_mac[mac] = seen_ip[ip] = 1
    have = {} if replace else {r.mac: r for r in DhcpReservation.objects.all()}
    ip_owner = {} if replace else {r.ip: r.mac for r in have.values()}
    created = updated = skipped = 0
    plan = []
    for mac, ip, host, note, enabled in rows:
        if ip_owner.get(ip, mac) != mac and ip_owner[ip] not in seen_mac:
            errors.append(f'{mac}: {ip} is reserved for {ip_owner[ip]}')
            continue
        cur = have.get(mac)
        if cur is None:
            created += 1
        elif (cur.ip, cur.hostname, cur.note, cur.enabled) == (ip, host, note, enabled):
            skipped += 1
            continue
        else:
            updated += 1
        plan.append((mac, ip, host, note, enabled))
    if not errors and not dry_run:
        with transaction.atomic():
            if replace:
                DhcpReservation.objects.all().delete()
            else:  # free the addresses first: two MACs may swap
                DhcpReservation.objects.filter(mac__in=[p[0] for p in plan]).delete()
            DhcpReservation.objects.bulk_create([DhcpReservation(mac=m, ip=i, hostname=h, note=n, enabled=e) for m, i, h, n, e in plan])
        from ..models import DataVersion
        DataVersion.bump()  # bulk_create sends no signals
    return {'created': created, 'updated': updated, 'skipped': skipped, 'errors': errors}


class DhcpReservationViewSet(viewsets.ModelViewSet):
    """Fixed DHCPv4 addresses by MAC."""
    queryset = DhcpReservation.objects.all()
    serializer_class = DhcpReservationSerializer

    @extend_schema(responses={(200, 'text/csv'): OpenApiTypes.STR})
    @action(detail=False, methods=['get'])
    def export(self, request):
        """Every reservation as CSV (mac,ip,hostname,note,enabled)."""
        out = io.StringIO()
        w = csv.writer(out, lineterminator='\n')
        w.writerow(COLUMNS)
        for r in DhcpReservation.objects.all():
            w.writerow([r.mac, r.ip, r.hostname, r.note, 'true' if r.enabled else 'false'])
        res = HttpResponse(out.getvalue(), content_type='text/csv; charset=utf-8')
        res['Content-Disposition'] = 'attachment; filename="dhcp-reservations.csv"'
        return res

    @extend_schema(request=DhcpReservationImportSerializer, responses=DhcpReservationImportResultSerializer, parameters=[GRANT])
    @action(detail=False, methods=['post'], url_path='import')
    def import_(self, request):
        """Add or update reservations from CSV (matched by MAC); with replace the table is emptied first."""
        s = DhcpReservationImportSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        if s.validated_data['replace'] and not s.validated_data['dry_run'] and (denied := need_grant(request, scope='dhcp-replace')) is not None:
            return denied
        return Response(import_rows(**s.validated_data))
