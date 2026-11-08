import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from zones.models import QueryLog
from zones.resolver import Resolver
from dnslib.server import DNSServer


class Command(BaseCommand):
    help = 'Run the DNS daemon: internal zones from DB, everything else forwarded upstream.'

    def add_arguments(self, p):
        p.add_argument('--address', default='127.0.0.1')
        p.add_argument('--port', type=int, default=5353)  # 53 needs root
        p.add_argument('--upstream', default=settings.UPSTREAM_DNS, help='one or more resolvers, comma separated, tried in order')

    def handle(self, *a, address, port, upstream, **o):
        r = Resolver(upstream)
        servers = [DNSServer(r, port=port, address=address, tcp=t) for t in (False, True)]
        for s in servers:
            s.start_thread()
        self.stdout.write(f'DNS on {address}:{port} (udp+tcp), upstream {upstream}')
        try:
            while True:
                QueryLog.objects.filter(time__lt=timezone.now() - timedelta(days=settings.QUERY_LOG_DAYS)).delete()
                time.sleep(3600)
        except KeyboardInterrupt:
            for s in servers:
                s.stop()
