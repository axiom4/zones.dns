from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from zones.models import BlockedDomain, QueryLog, Zone
from zones.tracker_scan import probe


class Command(BaseCommand):
    help = ('Probe the domains seen in the query log over HTTP and blacklist those that redirect to another domain '
            'AND set persistent / cross-site cookies. Dry run unless --apply.')

    def add_arguments(self, p):
        p.add_argument('--days', type=int, default=settings.QUERY_LOG_DAYS)
        p.add_argument('--limit', type=int, default=200, help='max domains to probe, most queried first')
        p.add_argument('--apply', action='store_true', help='add the matches to the blacklist')

    def handle(self, *a, days, limit, apply, **o):
        from django.db.models import Count
        rows = (QueryLog.objects.filter(time__gte=timezone.now() - timedelta(days=days), outcome='forwarded').exclude(domain='')
                .values('domain').annotate(n=Count('id')).order_by('-n')[:limit])
        skip = set(BlockedDomain.objects.values_list('name', flat=True)) | set(Zone.objects.values_list('name', flat=True)) | settings.SUSPICIOUS_ALLOW
        todo = [r['domain'] for r in rows if r['domain'] not in skip]
        with ThreadPoolExecutor(8) as ex:
            results = list(ex.map(probe, todo))
        hits = 0
        for d, (target, cookies) in zip(todo, results):
            if target and cookies:
                hits += 1
                self.stdout.write(f'{d}: redirect -> {target}, cookie {", ".join(sorted(set(cookies)))}')
                if apply:
                    BlockedDomain.objects.get_or_create(name=d)
        self.stdout.write(f'{len(todo)} domains probed, {hits} match' + ('' if apply else ' (dry run: use --apply to blacklist)'))
