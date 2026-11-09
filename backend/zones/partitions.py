"""Daily RANGE partitions of the query log on MySQL/MariaDB: old days are dropped with DROP PARTITION (instant) instead of a huge DELETE,
and queries on a time window read only the partitions of those days.

Other databases are left alone. The primary key becomes (id, time), as MySQL requires the partition column in every unique key; Django keeps
using `id` alone, which is still unique because it is auto-increment.
"""
from datetime import date, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import connection
from django.utils import timezone

from .models import QueryLog

AHEAD = 7  # days of empty partitions kept ready in front of today


def _day(n):
    return date.fromordinal(int(n) - 365)  # TO_DAYS(d) = d.toordinal() + 365


def _num(day):
    return day.toordinal() + 365


def _definition(name, upper):
    return f"PARTITION {name} VALUES LESS THAN (TO_DAYS('{upper:%Y-%m-%d}'))"


def plan(parts, today, cutoff_day, ahead=AHEAD):
    """parts: [(name, TO_DAYS bound or None for MAXVALUE)]. Returns (names to drop, [(name, upper day)] to add).

    A partition goes when all its rows are older than cutoff_day; the days from the last bound up to today + ahead are created."""
    bounds = [_day(b) for _, b in parts if b is not None]
    drop = [n for n, b in parts if b is not None and _day(b) <= cutoff_day]
    day, add = max(bounds, default=today), []
    while day <= today + timedelta(days=ahead):
        add.append((f'p{day:%Y%m%d}', day + timedelta(days=1)))
        day += timedelta(days=1)
    return drop, add


def _today_cutoff():
    today = timezone.now().astimezone(dt_timezone.utc).date()
    return today, today - timedelta(days=settings.QUERY_LOG_DAYS)


def _partitions(table):
    with connection.cursor() as c:
        c.execute('SELECT PARTITION_NAME, PARTITION_DESCRIPTION FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s '
                  'AND PARTITION_NAME IS NOT NULL ORDER BY PARTITION_ORDINAL_POSITION', [table])
        return [(n, None if d is None or not str(d).isdigit() else int(d)) for n, d in c.fetchall()]


def convert():
    """Partition the table (once). Rebuilds it: slow on a big log, and writes wait meanwhile. Returns the statement run."""
    table = connection.ops.quote_name(QueryLog._meta.db_table)
    today, first = _today_cutoff()
    _, days = plan([('pold', _num(first))], today, first)
    items = [f"PARTITION pold VALUES LESS THAN (TO_DAYS('{first:%Y-%m-%d}'))"] + [_definition(n, u) for n, u in days] + ['PARTITION pmax VALUES LESS THAN MAXVALUE']
    sql = f'ALTER TABLE {table} DROP PRIMARY KEY, ADD PRIMARY KEY (id, time) PARTITION BY RANGE (TO_DAYS(time)) ({", ".join(items)})'
    with connection.cursor() as c:
        c.execute(sql)
    return sql


def maintain():
    """Create the coming days' partitions and drop the ones older than QUERY_LOG_DAYS. False if the table is not partitioned (or not MySQL)."""
    if connection.vendor != 'mysql':
        return False
    table = QueryLog._meta.db_table
    parts = _partitions(table)
    if not parts:
        return False
    quoted = connection.ops.quote_name(table)
    today, cutoff = _today_cutoff()
    drop, add = plan(parts, today, cutoff)
    with connection.cursor() as c:
        if add:
            items = [_definition(n, u) for n, u in add] + ['PARTITION pmax VALUES LESS THAN MAXVALUE']
            c.execute(f'ALTER TABLE {quoted} REORGANIZE PARTITION pmax INTO ({", ".join(items)})')
        if drop:
            c.execute(f'ALTER TABLE {quoted} DROP PARTITION {", ".join(drop)}')
    return True
