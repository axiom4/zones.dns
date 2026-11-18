import urllib.request

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from zones import blocklists
from zones.blocklists import parse, split_source  # noqa: F401  (split_source: imported from here by older code and tests)
from zones.models import COUNTS_KEY, BlockedDomain, DataVersion
from zones.proxy import rules


def download(source):
    if source.startswith(('http://', 'https://')):
        req = urllib.request.Request(source, headers={'User-Agent': 'zones-dns/1.0'})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read(50_000_001)
        if len(raw) > 50_000_000:
            raise OSError('response exceeds 50 MB limit')
        return raw.decode('utf-8', 'replace')
    with open(source, encoding='utf-8', errors='replace') as f:
        return f.read()


class Command(BaseCommand):
    help = ('Replace the imported blacklist (source=list) with the union of public blocklists (default: the lists of Blacklist > Public lists, '
            'else BLOCKLISTS). Manual entries are untouched; a list that fails keeps its old entries. Without arguments it also downloads the proxy '
            'ad-block rule lists (PROXY_RULE_LISTS, Proxy page).')

    def add_arguments(self, p):
        p.add_argument('sources', nargs='*', help='[name=]URL or file path (hosts format or one domain per line); default: the GUI lists, else BLOCKLISTS')
        p.add_argument('--locked', action='store_true', help='the caller (the GUI\'s Sync now) already holds the lock')

    def handle(self, *a, sources, locked=False, **o):
        if not locked and not blocklists.acquire():
            raise CommandError('another import_blocklist is running')
        try:
            failed = self.run(sources)
        except Exception as e:
            blocklists.save_status({**blocklists.status(), 'finished': blocklists.now_iso(), 'error': str(e)[:300]})
            raise
        finally:
            blocklists.release()
        if not sources:
            try:
                for r in rules.sync_all():
                    self.stdout.write(f"proxy rules {r['name']}: {r['blocks']} domains, {r['allow']} exceptions, {r['cosmetic']} selectors" + (f" (failed, old rules kept: {r['error']})" if r['error'] else ''))
            except ValueError as e:
                self.stderr.write(f'proxy rules not updated: {e}')
        if failed:
            raise CommandError(f'{failed} of the public lists failed: their old entries were kept')

    def run(self, sources):
        """Downloads every list and writes what changed; the number of lists that failed."""
        entries = [split_source(e) for e in sources] if sources else blocklists.configured(settings.BLOCKLISTS)
        old = blocklists.status().get('lists', {})
        st = {'started': blocklists.now_iso(), 'finished': None, 'error': '', 'lists': {}}
        blocklists.save_status({**blocklists.status(), 'started': st['started'], 'finished': None, 'error': ''})
        names = {}  # domain -> the first list that has it
        failed = 0
        for label, source in entries:
            row = {'url': source, 'tried': blocklists.now_iso(), 'synced': old.get(label, {}).get('synced'), 'error': ''}
            try:
                found = parse(download(source))
                if not found:
                    raise ValueError('no domains found')
                row.update(synced=row['tried'], domains=len(found))
                self.stdout.write(f'{label}: {len(found)} domains')
            except (OSError, ValueError) as e:
                # the list keeps what it had: its old entries are taken as if downloaded again
                found = set(BlockedDomain.objects.filter(source='list', list_name=label).values_list('name', flat=True).iterator(chunk_size=50000))
                row.update(error=str(e)[:300], domains=len(found))
                failed += 1
                self.stderr.write(f'{label}: {source}: {e}: its {len(found)} old entries kept')
            st['lists'][label] = row
            for d in found:
                names.setdefault(d, label)
            blocklists.renew()
        manual = set(BlockedDomain.objects.filter(source='manual').values_list('name', flat=True))
        todo = {n: label for n, label in names.items() if n not in manual}
        # Only what changed is written: the lists differ by a few percent from one night to the next, and a DELETE + INSERT of a million rows
        # is the slow, lock-holding way to learn that.
        have = dict(BlockedDomain.objects.filter(source='list').values_list('name', 'list_name').iterator(chunk_size=50000))
        drop = [n for n, label in have.items() if todo.get(n) != label]  # gone, or moved to another list
        add = [n for n, label in todo.items() if have.get(n) != label]
        with transaction.atomic():
            for i in range(0, len(drop), 5000):
                BlockedDomain.objects.filter(source='list', name__in=drop[i:i + 5000]).delete()
            BlockedDomain.objects.bulk_create([BlockedDomain(name=n, source='list', list_name=todo[n]) for n in add], batch_size=5000)
            if drop or add:
                transaction.on_commit(DataVersion.bump)  # after the commit, so the daemon never reloads half-way
        cache.delete(COUNTS_KEY)
        removed = sum(1 for n in drop if n not in todo)
        blocklists.save_status({**st, 'finished': blocklists.now_iso(), 'imported': len(todo), 'added': len(add), 'removed': removed, 'failed': failed})
        self.stdout.write(f'{len(todo)} domains imported ({len(add)} added, {removed} removed)')
        return failed
