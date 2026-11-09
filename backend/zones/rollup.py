"""Hourly counters of the query log (StatCount, GeoStat), updated with every batch of log rows.

The statistics and geolocation pages read these instead of grouping millions of log rows. Rows are added when the log rows are saved,
so a crash between the two can lose a few counts; `manage.py rebuild_stats` recomputes everything from the log.
"""
from collections import Counter
from datetime import timezone as dt_timezone

from django.db import connection

from .models import GeoStat, StatCount


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
    with connection.cursor() as c:
        c.executemany(sql, sorted(rows, key=lambda r: tuple(str(x) for x in r[:len(keys)])))


def add(entries):
    """Count a batch of saved QueryLog rows."""
    stats, geo = {}, Counter()
    for e in entries:
        hour = floor_hour(e.time)
        dims = [('outcome', e.outcome), ('type', e.type), ('name', e.name), ('client', e.client)]
        if e.outcome == 'blocked':
            dims.append(('blocked', e.name))
        for dim, key in dims:
            s = stats.setdefault((dim, hour, key), [0, 0])
            s[0] += 1
            s[1] += e.ms
        for ip in {a['value'] for a in e.answers if a['type'] in ('A', 'AAAA')}:
            geo[(hour, e.domain, ip)] += 1
    _upsert(StatCount, ['dim', 'hour', 'key'], ['n', 'ms'], [(*k, *v) for k, v in stats.items()])
    _upsert(GeoStat, ['hour', 'domain', 'ip'], ['n'], [(*k, n) for k, n in geo.items()])


def purge(cutoff=None):
    """Forget the counters older than cutoff (a datetime), or all of them."""
    for model in (StatCount, GeoStat):
        qs = model.objects.filter(hour__lt=floor_hour(cutoff)) if cutoff else model.objects.all()
        qs.delete()
