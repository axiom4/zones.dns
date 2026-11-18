import csv
import io
import ipaddress

from django.db import transaction
from django.http import HttpResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import DataVersion, Dhcp6Reservation
from ..serializers import Dhcp6ReservationImportSerializer, Dhcp6ReservationSerializer, DhcpReservationImportResultSerializer
from ..serializers.dhcp6_reservation import check_row
from .dhcp_reservation import TRUE, csv_cell, csv_note
from .zone import GRANT, need_grant

COLUMNS = ['duid', 'ip', 'note', 'enabled']
NAMES = {'duid': 'duid', 'client id': 'duid', 'clientid': 'duid', 'ip': 'ip', 'ip address': 'ip', 'ipaddress': 'ip', 'ipv6': 'ip', 'address': 'ip', 'note': 'note', 'enabled': 'enabled'}


def is_ipv6(v):
    try:
        ipaddress.IPv6Address(v)
        return True
    except ValueError:
        return False


def import_rows(text, replace, dry_run):
    """The result of importing CSV text (duid,ip,note,enabled). Any error in any line: nothing is changed."""
    rows, errors = [], []
    first = next((l for l in text.splitlines() if l.strip()), '')
    delim = next((d for d in (',', ';', '\t') if d in first), ',')
    lines = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if r and any(c.strip() for c in r) and not r[0].lstrip().startswith('#')]
    cols = None
    if lines and {c.strip().lower() for c in lines[0]} & set(NAMES):  # header: columns in any order
        cols = [NAMES.get(c.strip().lower()) for c in lines[0]]
        lines = lines[1:]
    for n, r in enumerate(lines, 1):
        r = [c.strip() for c in r]
        if cols:
            d = {k: r[i] for i, k in enumerate(cols) if k and i < len(r)}
        else:  # no header: the address is the field that is an IPv6 address, the DUID the first other one, then note and enabled
            ip = next((c for c in r if is_ipv6(c)), '')
            rest = [c for c in r if c != ip] + [''] * 3
            d = {'duid': rest[0], 'ip': ip, 'note': rest[1], 'enabled': rest[2]}
        try:
            duid, ip = check_row(d.get('duid', ''), d.get('ip', ''))
            rows.append((duid, ip, csv_note(d.get('note', '')), d.get('enabled', '').lower() in TRUE))
        except ValueError as e:
            errors.append(f'line {n} ({d.get("duid", "")} {d.get("ip", "")}): {e}')
    seen_duid, seen_ip = {}, {}
    for duid, ip, *_ in rows:
        if duid in seen_duid or ip in seen_ip:
            errors.append(f'{duid[:16]} {ip}: repeated in the file')
        seen_duid[duid] = seen_ip[ip] = 1
    have = {} if replace else {r.duid: r for r in Dhcp6Reservation.objects.all()}
    ip_owner = {r.ip: r.duid for r in have.values()}
    created = updated = skipped = 0
    plan = []
    for duid, ip, note, enabled in rows:
        if ip_owner.get(ip, duid) != duid and ip_owner[ip] not in seen_duid:
            errors.append(f'{duid[:16]}: {ip} is reserved for {ip_owner[ip][:16]}')
            continue
        cur = have.get(duid)
        if cur is None:
            created += 1
        elif (cur.ip, cur.note, cur.enabled) == (ip, note, enabled):
            skipped += 1
            continue
        else:
            updated += 1
        plan.append((duid, ip, note, enabled))
    if not errors and not dry_run:
        with transaction.atomic():
            if replace:
                Dhcp6Reservation.objects.all().delete()
            else:  # free the addresses first: two clients may swap
                Dhcp6Reservation.objects.filter(duid__in=[p[0] for p in plan]).delete()
            Dhcp6Reservation.objects.bulk_create([Dhcp6Reservation(duid=d, ip=i, note=n, enabled=e) for d, i, n, e in plan])
        DataVersion.bump()  # bulk_create sends no signals
    return {'created': created, 'updated': updated, 'skipped': skipped, 'errors': errors}


class Dhcp6ReservationViewSet(viewsets.ModelViewSet):
    """Fixed DHCPv6 addresses by client DUID."""
    queryset = Dhcp6Reservation.objects.all()
    serializer_class = Dhcp6ReservationSerializer

    @extend_schema(responses={(200, 'text/csv'): OpenApiTypes.STR})
    @action(detail=False, methods=['get'])
    def export(self, request):
        """Every reservation as CSV (duid,ip,note,enabled)."""
        out = io.StringIO()
        w = csv.writer(out, lineterminator='\n')
        w.writerow(COLUMNS)
        for r in Dhcp6Reservation.objects.all():
            w.writerow([r.duid, r.ip, csv_cell(r.note), 'true' if r.enabled else 'false'])
        res = HttpResponse(out.getvalue(), content_type='text/csv; charset=utf-8')
        res['Content-Disposition'] = 'attachment; filename="dhcp6-reservations.csv"'
        return res

    @extend_schema(request=Dhcp6ReservationImportSerializer, responses=DhcpReservationImportResultSerializer, parameters=[GRANT])
    @action(detail=False, methods=['post'], url_path='import')
    def import_(self, request):
        """Add or update reservations from CSV (matched by DUID); with replace the table is emptied first."""
        s = Dhcp6ReservationImportSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        if s.validated_data['replace'] and not s.validated_data['dry_run'] and (denied := need_grant(request, scope='dhcp-replace')) is not None:
            return denied
        return Response(import_rows(**s.validated_data))
