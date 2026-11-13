"""Daily RANGE partitions of the query log on MySQL/MariaDB and PostgreSQL: old days are dropped with DROP PARTITION / DROP TABLE (instant)
instead of a huge DELETE, and queries on a time window read only the partitions of those days. Other databases are left alone.

The primary key becomes (id, time), as both engines require the partition column in every unique key; Django keeps using `id` alone, which is
still unique because it comes from one sequence / auto-increment.

MySQL: one table with partitions pYYYYMMDD (the day), `pold` (everything before the first day) and `pmax` (catch-all).
PostgreSQL: the table is replaced by a partitioned one whose partitions are the tables zones_querylog_pYYYYMMDD and zones_querylog_pold_YYYYMMDD
(everything before that date). There is no default partition, so the next AHEAD days must always exist: rundns creates them every hour.
"""
import re
from datetime import date, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from ..models import QueryLog

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


def supported():
    return connection.vendor in ('mysql', 'postgresql')


def _partitions(table):
    """[(name, TO_DAYS-style upper bound or None for the catch-all)] of the partitions, oldest first; [] if the table is not partitioned."""
    with connection.cursor() as c:
        if connection.vendor == 'postgresql':
            c.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = to_regclass(%s) ORDER BY c.relname", [table])
            out = []
            for (rel,) in c.fetchall():
                name = rel[len(table) + 1:]
                if m := re.fullmatch(r'pold_(\d{8})', name):
                    out.append((name, _num(date.fromisoformat(m[1][:4] + '-' + m[1][4:6] + '-' + m[1][6:]))))
                elif m := re.fullmatch(r'p(\d{8})', name):
                    out.append((name, _num(date.fromisoformat(m[1][:4] + '-' + m[1][4:6] + '-' + m[1][6:]) + timedelta(days=1))))
            return sorted(out, key=lambda p: p[1])
        c.execute('SELECT PARTITION_NAME, PARTITION_DESCRIPTION FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s '
                  'AND PARTITION_NAME IS NOT NULL ORDER BY PARTITION_ORDINAL_POSITION', [table])
        return [(n, None if d is None or not str(d).isdigit() else int(d)) for n, d in c.fetchall()]


def _pg_bounds(upper):
    return f"FROM ('{upper - timedelta(days=1):%Y-%m-%d} 00:00:00+00') TO ('{upper:%Y-%m-%d} 00:00:00+00')"


def _convert_pg():
    table = QueryLog._meta.db_table
    q, t, old, seq = connection.ops.quote_name, connection.ops.quote_name(table), connection.ops.quote_name(table + '_old'), connection.ops.quote_name(table + '_id_seq_p')
    today, first = _today_cutoff()
    _, days = plan([('pold', _num(first))], today, first)
    done = []
    with transaction.atomic(), connection.cursor() as c:
        c.execute(f'LOCK TABLE {t} IN ACCESS EXCLUSIVE MODE')  # writers wait here until the end; the log writer keeps its rows queued
        c.execute('SELECT i.relname, pg_get_indexdef(i.oid), x.indisprimary FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid WHERE x.indrelid = to_regclass(%s)', [table])
        indexes = c.fetchall()
        c.execute(f'ALTER TABLE {t} RENAME TO {old}')
        for name, _, _ in indexes:  # the new indexes take the names Django expects
            c.execute(f'ALTER INDEX {q(name)} RENAME TO {q(name[:55] + "_old")}')
        c.execute(f'CREATE TABLE {t} (LIKE {old} INCLUDING DEFAULTS) PARTITION BY RANGE ("time")')
        c.execute(f'CREATE SEQUENCE {seq} OWNED BY {t}."id"')
        c.execute(f"ALTER TABLE {t} ALTER COLUMN \"id\" SET DEFAULT nextval('{table}_id_seq_p'::regclass)")
        c.execute(f'ALTER TABLE {t} ADD PRIMARY KEY ("id", "time")')
        c.execute(f'CREATE TABLE {q(f"{table}_pold_{first:%Y%m%d}")} PARTITION OF {t} FOR VALUES FROM (MINVALUE) TO (\'{first:%Y-%m-%d} 00:00:00+00\')')
        for name, upper in days:
            c.execute(f'CREATE TABLE {q(f"{table}_{name}")} PARTITION OF {t} FOR VALUES {_pg_bounds(upper)}')
        c.execute(f'INSERT INTO {t} SELECT * FROM {old}')
        c.execute(f"SELECT setval('{table}_id_seq_p', COALESCE((SELECT max(\"id\") FROM {old}), 0) + 1, false)")
        for _, definition, primary in indexes:
            if not primary:
                c.execute(definition)  # same definition and name, now on the partitioned table
        c.execute(f'DROP TABLE {old}')
    return f'{table} replaced by a partitioned table ({len(days) + 1} partitions)'


def convert():
    """Partition the table (once). Rebuilds it: slow on a big log, and writes wait meanwhile. Returns what was done."""
    if connection.vendor == 'postgresql':
        return _convert_pg()
    table = connection.ops.quote_name(QueryLog._meta.db_table)
    today, first = _today_cutoff()
    _, days = plan([('pold', _num(first))], today, first)
    items = [f"PARTITION pold VALUES LESS THAN (TO_DAYS('{first:%Y-%m-%d}'))"] + [_definition(n, u) for n, u in days] + ['PARTITION pmax VALUES LESS THAN MAXVALUE']
    sql = f'ALTER TABLE {table} DROP PRIMARY KEY, ADD PRIMARY KEY (id, time) PARTITION BY RANGE (TO_DAYS(time)) ({", ".join(items)})'
    with connection.cursor() as c:
        c.execute(sql)
    return sql


def maintain():
    """Create the coming days' partitions and drop the ones older than QUERY_LOG_DAYS. False if the table is not partitioned (or not supported)."""
    if not supported():
        return False
    table = QueryLog._meta.db_table
    parts = _partitions(table)
    if not parts:
        return False
    quoted = connection.ops.quote_name(table)
    today, cutoff = _today_cutoff()
    drop, add = plan(parts, today, cutoff)
    with connection.cursor() as c:
        if connection.vendor == 'postgresql':
            for name, upper in add:
                c.execute(f'CREATE TABLE IF NOT EXISTS {connection.ops.quote_name(f"{table}_{name}")} PARTITION OF {quoted} FOR VALUES {_pg_bounds(upper)}')
            for name in drop:
                c.execute(f'DROP TABLE {connection.ops.quote_name(f"{table}_{name}")}')
            return True
        if add:
            items = [_definition(n, u) for n, u in add] + ['PARTITION pmax VALUES LESS THAN MAXVALUE']
            c.execute(f'ALTER TABLE {quoted} REORGANIZE PARTITION pmax INTO ({", ".join(items)})')
        if drop:
            c.execute(f'ALTER TABLE {quoted} DROP PARTITION {", ".join(drop)}')
    return True
