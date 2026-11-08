import re
import urllib.request

from django.core.management.base import BaseCommand
from django.db import transaction

from zones.audit import NAME_RE
from zones.models import BlockedDomain, DataVersion

DEFAULT_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'  # ads + malware, hosts format
LOCAL = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', '0.0.0.0'}


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
    help = 'Replace the imported blacklist (source=list) with a public blocklist. Manual entries are untouched.'

    def add_arguments(self, p):
        p.add_argument('source', nargs='?', default=DEFAULT_URL, help='URL or file path (hosts format or one domain per line)')

    def handle(self, *a, source, **o):
        if source.startswith(('http://', 'https://')):
            req = urllib.request.Request(source, headers={'User-Agent': 'zones-dns/1.0'})
            text = urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'replace')
        else:
            with open(source, encoding='utf-8', errors='replace') as f:
                text = f.read()
        names = parse(text)
        if not names:
            raise SystemExit('no domains found: blacklist left unchanged')
        manual = set(BlockedDomain.objects.filter(source='manual').values_list('name', flat=True))
        with transaction.atomic():
            BlockedDomain.objects.filter(source='list').delete()
            BlockedDomain.objects.bulk_create([BlockedDomain(name=n, source='list') for n in names - manual], batch_size=2000)
            transaction.on_commit(DataVersion.bump)  # after the commit, so the daemon never reloads half-way
        self.stdout.write(f'{len(names - manual)} domains imported')
