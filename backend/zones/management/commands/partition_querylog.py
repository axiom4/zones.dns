from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from ...stats import partitions
from ...models import QueryLog


class Command(BaseCommand):
    help = 'MySQL/MariaDB and PostgreSQL: split the query log into daily partitions (old days are then dropped instantly). Safe to run again; rundns keeps them up to date.'

    def handle(self, *a, **o):
        if not partitions.supported():
            raise CommandError('partitioning is for MySQL/MariaDB and PostgreSQL only')
        if partitions._partitions(QueryLog._meta.db_table):
            self.stdout.write('already partitioned; maintenance done' if partitions.maintain() else 'nothing to do')
            return
        self.stdout.write('Partitioning the query log: the table is rebuilt and writes wait until it ends...')
        self.stdout.write(partitions.convert())
        self.stdout.write('done')
