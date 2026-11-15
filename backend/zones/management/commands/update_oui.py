import gzip
import urllib.request

from django.core.management.base import BaseCommand, CommandError

from zones import oui

MIN_ROWS = 10000  # the real file has about 50,000: fewer means a broken download
URL = 'https://www.wireshark.org/download/automated/data/manuf.gz'


class Command(BaseCommand):
    help = ('Refresh the MAC vendor table in the database from the IEEE registry (Wireshark manuf file, updated weekly upstream: run it nightly from cron at most). '
            'The table is replaced in one transaction; if the download or the file is bad, the old one stays.')

    def add_arguments(self, p):
        p.add_argument('--url', default=URL)

    def handle(self, *a, url, **o):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'dns-admin'}), timeout=60) as r:
                raw = r.read(50_000_000)
            rows = oui.parse_manuf((gzip.decompress(raw) if raw[:2] == b'\x1f\x8b' else raw).decode('utf-8', 'replace'))
        except (OSError, EOFError) as e:
            raise CommandError(f'Download failed: {e}')
        if len(rows) < MIN_ROWS:
            raise CommandError(f'Only {len(rows)} usable lines in the file: the table was not changed.')
        self.stdout.write(f'{oui.replace_table(rows)} vendor blocks stored.')
