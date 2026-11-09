from django.core.management.base import BaseCommand

from ... import rollup
from ...models import QueryLog


class Command(BaseCommand):
    help = 'Recompute the hourly statistics counters (statistics and geolocation pages) from the query log. Run once after migrate.'

    def handle(self, *a, **o):
        rollup.purge()
        batch, total = [], 0
        for e in QueryLog.objects.only('time', 'name', 'domain', 'type', 'outcome', 'client', 'ms', 'answers').iterator(chunk_size=5000):
            batch.append(e)
            if len(batch) >= 5000:
                rollup.add(batch)
                total += len(batch)
                batch = []
        rollup.add(batch)
        self.stdout.write(f'{total + len(batch)} log rows counted')
