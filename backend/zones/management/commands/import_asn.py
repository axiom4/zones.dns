import os
import sys
import tempfile
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from zones import asnindex

MIN_PREFIXES = 100000  # a real archive has about 500,000; less means a broken download
MAX_BYTES = 300 * 1024 * 1024


class Command(BaseCommand):
    help = 'Build the IP -> ASN index from ipverse/as-ip-blocks (BGP prefixes per ASN, CC0). Schedule it nightly; the old index stays if anything fails.'

    def add_arguments(self, p):
        p.add_argument('source', nargs='?', default=settings.ASN_IMPORT_URL, help='URL or path of as-ip-blocks.tar.gz')

    def handle(self, *a, source, **o):
        path = settings.ASN_INDEX
        if not path:
            raise CommandError('ASN_INDEX is empty')
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with tempfile.TemporaryFile(dir=os.path.dirname(path) or '.') as tmp:
            if source.startswith(('http://', 'https://')):
                req = urllib.request.Request(source, headers={'User-Agent': 'zones-dns/1.0'})
                with urllib.request.urlopen(req, timeout=120) as r:
                    size = 0
                    while chunk := r.read(1 << 20):
                        size += len(chunk)
                        if size > MAX_BYTES:
                            raise CommandError('download too big: index left unchanged')
                        tmp.write(chunk)
            else:
                with open(source, 'rb') as f:
                    tmp.write(f.read())
            tmp.seek(0)
            try:
                v4, v6, names = asnindex.read_archive(tmp)
            except Exception as e:
                raise CommandError(f'cannot read the archive ({e}): index left unchanged')
        if len(v4) + len(v6) < MIN_PREFIXES:
            raise CommandError(f'only {len(v4) + len(v6)} prefixes found: index left unchanged')
        n4, n6 = asnindex.write(path, v4, v6, names)
        self.stdout.write(f'{n4} IPv4 and {n6} IPv6 ranges, {len(names)} ASNs written to {path}')
