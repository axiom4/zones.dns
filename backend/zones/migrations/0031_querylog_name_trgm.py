"""PostgreSQL only: a trigram index on QueryLog.name, so the log search (q, a LIKE '%text%') reads the index instead of every row of the period.

Needs the pg_trgm extension: if the database user may not create it, the migration says so and goes on without the index (ask a superuser for
`CREATE EXTENSION pg_trgm;`, then `manage.py migrate zones 0030 && manage.py migrate`). A plain table gets the index CONCURRENTLY (writes go on);
a partitioned one (manage.py partition_querylog) cannot, so it is locked against writes while the index is built: on a large log run it at a quiet time.
Other databases: nothing (MySQL/MariaDB and SQLite have no such index).
"""
from django.db import migrations, transaction

INDEX = 'qlog_name_trgm'


def create(apps, schema_editor):
    c = schema_editor.connection
    if c.vendor != 'postgresql':
        return
    table = apps.get_model('zones', 'QueryLog')._meta.db_table
    with c.cursor() as cur:
        try:
            with transaction.atomic(using=c.alias):
                cur.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
        except Exception as e:
            print(f'\n  {INDEX} skipped: the pg_trgm extension cannot be created ({e}). The log search still works, without the index.')
            return
        cur.execute("SELECT relkind FROM pg_class WHERE oid = to_regclass(%s)", [table])
        partitioned = (cur.fetchone() or [''])[0] == 'p'
        cur.execute(f'CREATE INDEX {"" if partitioned else "CONCURRENTLY "}IF NOT EXISTS {INDEX} ON {c.ops.quote_name(table)} USING gin (name gin_trgm_ops)')


def drop(apps, schema_editor):
    if schema_editor.connection.vendor == 'postgresql':
        schema_editor.execute(f'DROP INDEX IF EXISTS {INDEX}')


class Migration(migrations.Migration):
    atomic = False  # CREATE INDEX CONCURRENTLY cannot run inside a transaction

    dependencies = [
        ('zones', '0030_geostat_first'),
    ]

    operations = [
        migrations.RunPython(create, drop),
    ]
