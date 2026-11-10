import re
import urllib.request

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.db import transaction

from zones.audit import NAME_RE
from zones.models import COUNTS_KEY, BlockedDomain, DataVersion

LOCAL = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', '0.0.0.0'}


def split_source(entry):
    """('name', 'url or path') from `name=url`; a plain URL or path is named after its file."""
    m = re.match(r'^([a-z0-9._-]{1,40})=(.+)$', entry)
    if m and not m[1].startswith(('http', 'file')):
        return m[1], m[2]
    return re.sub(r'[^a-z0-9._-]', '-', entry.rstrip('/').rsplit('/', 1)[-1].lower())[:40] or 'list', entry


def parse(text):
    """Domains from a hosts file ('0.0.0.0 bad.com') or a plain list (one domain per line); comments ignored."""
    out = set()
    for line in text.splitlines():
        parts = line.split('#', 1)[0].split()
        if parts and re.match(r'^(\d+\.){3}\d+$|^::1?$', parts[0]):
            parts = parts[1:]
        for d in parts[:1]:
            d = d.lower().strip('.')
            if d not in LOCAL and NAME_RE.match(d):
                out.add(d)
    return out


class Command(BaseCommand):
    help = 'Replace the imported blacklist (source=list) with the union of public blocklists (default: BLOCKLISTS). Manual entries are untouched.'

    def add_arguments(self, p):
        p.add_argument('sources', nargs='*', help='URLs or file paths (hosts format or one domain per line); default: BLOCKLISTS')

    def handle(self, *a, sources, **o):
        names = {}  # domain -> the first list that has it
        for entry in sources or settings.BLOCKLISTS:
            label, source = split_source(entry)
            if source.startswith(('http://', 'https://')):
                req = urllib.request.Request(source, headers={'User-Agent': 'zones-dns/1.0'})
                try:
                    text = urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'replace')
                except OSError as e:  # shortcut: one list down = no update at all (the old entries stay); the next run retries
                    raise SystemExit(f'{source}: {e}: blacklist left unchanged')
            else:
                with open(source, encoding='utf-8', errors='replace') as f:
                    text = f.read()
            found = parse(text)
            if not found:
                raise SystemExit(f'{source}: no domains found: blacklist left unchanged')
            self.stdout.write(f'{label}: {len(found)} domains')
            for d in found:
                names.setdefault(d, label)
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
        self.stdout.write(f'{len(todo)} domains imported ({len(add)} added, {sum(1 for n in drop if n not in todo)} removed)')
