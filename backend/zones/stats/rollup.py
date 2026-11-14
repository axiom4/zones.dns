"""Hourly counters of the query log (StatCount, GeoStat), updated with every batch of log rows.

The statistics and geolocation pages read these instead of grouping millions of log rows. Rows are added when the log rows are saved,
so a crash between the two can lose a few counts; `manage.py rebuild_stats` recomputes everything from the log.
"""
from datetime import timezone as dt_timezone

from django.db import connection, transaction
from django.db.models import Exists, F, OuterRef, Subquery, Sum, Value
from django.db.models.functions import Greatest

from ..models import DomainStat, GeoStat, LogTotal, StatCount

TOTAL_DIMS = ('outcome', 'type', 'client')  # what LogTotal counts
_OUTCOME_IDX = {'local': 1, 'forwarded': 2, 'blocked': 3, 'error': 4}


def floor_hour(t):
    return t.astimezone(dt_timezone.utc).replace(minute=0, second=0, microsecond=0)


def _upsert(model, keys, values, rows):
    """INSERT ... ON DUPLICATE: add the values to the counters that exist. rows: tuples (*keys, *values), saved in key order (same lock order everywhere)."""
    if not rows:
        return
    q, table = connection.ops.quote_name, connection.ops.quote_name(model._meta.db_table)
    cols = ', '.join(q(c) for c in keys + values)
    if connection.vendor == 'mysql':
        tail = 'ON DUPLICATE KEY UPDATE ' + ', '.join(f'{q(v)} = {q(v)} + VALUES({q(v)})' for v in values)
    else:
        tail = f'ON CONFLICT ({", ".join(q(k) for k in keys)}) DO UPDATE SET ' + ', '.join(f'{q(v)} = {table}.{q(v)} + excluded.{q(v)}' for v in values)
    sql = f'INSERT INTO {table} ({cols}) VALUES ({", ".join(["%s"] * (len(keys) + len(values)))}) {tail}'
    with transaction.atomic(), connection.cursor() as c:
        c.executemany(sql, sorted(rows, key=lambda r: tuple(str(x) for x in r[:len(keys)])))


def _totals(stats):
    """The per-hour counters of a batch added up over the hours: {(dim, None, key): [n]} for the dims LogTotal keeps."""
    t = {}
    for (dim, hour, key), v in stats.items():
        if dim in TOTAL_DIMS:
            t.setdefault((dim, None, key), [0])[0] += v[0]
    return t


def add(entries):
    """Count a batch of saved QueryLog rows."""
    stats, geo, doms = {}, {}, {}
    for e in entries:
        hour = floor_hour(e.time)
        dims = [('outcome', e.outcome), ('type', e.type), ('name', e.name), ('client', e.client)]
        if e.outcome == 'blocked':
            dims.append(('blocked', e.name))
        for dim, key in dims:
            s = stats.setdefault((dim, hour, key), [0, 0])
            s[0] += 1
            s[1] += e.ms
        ips = list(dict.fromkeys(a['value'] for a in e.answers if a['type'] in ('A', 'AAAA')))  # answer order: the first is the one used
        for i, ip in enumerate(ips):
            g = geo.setdefault((hour, e.domain, ip), [0, 0])
            g[0] += 1
            g[1] += i == 0
        d = doms.setdefault((hour, e.domain), [0, 0, 0, 0, 0, 0])
        d[0] += 1
        if idx := _OUTCOME_IDX.get(e.outcome):
            d[idx] += 1
        d[5] += e.ms
    _upsert(StatCount, ['dim', 'hour', 'key'], ['n', 'ms'], [(*k, *v) for k, v in stats.items()])
    _upsert(LogTotal, ['dim', 'key'], ['n'], [(d, k, v[0]) for (d, h, k), v in _totals(stats).items()])
    _upsert(GeoStat, ['hour', 'domain', 'ip'], ['n', 'first'], [(*k, *v) for k, v in geo.items()])
    _upsert(DomainStat, ['hour', 'domain'], ['n', 'local', 'forwarded', 'blocked', 'error', 'ms'], [(*k, *v) for k, v in doms.items()])


def purge(cutoff=None):
    """Forget the counters older than cutoff (a datetime), or all of them."""
    if not cutoff:
        LogTotal.objects.all().delete()
    else:
        # one UPDATE for every total (thousands of clients were one UPDATE each); a decrement, not a rebuild, so batches counted meanwhile are kept
        old = StatCount.objects.filter(dim=OuterRef('dim'), key=OuterRef('key'), hour__lt=floor_hour(cutoff))
        gone = old.values('dim', 'key').annotate(s=Sum('n')).values('s')
        LogTotal.objects.filter(dim__in=TOTAL_DIMS).filter(Exists(old)).update(n=Greatest(F('n') - Subquery(gone), Value(0)))
    for model in (StatCount, GeoStat, DomainStat):
        qs = model.objects.filter(hour__lt=floor_hour(cutoff)) if cutoff else model.objects.all()
        qs.delete()
