import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from zones import partitions, rollup
from zones.models import QueryLog
from zones.resolver import Resolver
from dnslib.server import DNSServer

from zones.logwriter import LogWriter
from zones.dnsserver import PooledTCPServer, PooledUDPServer


class Command(BaseCommand):
    help = 'Run the DNS daemon: internal zones from DB, everything else forwarded upstream.'

    def add_arguments(self, p):
        p.add_argument('--address', default='127.0.0.1')
        p.add_argument('--port', type=int, default=5353)  # 53 needs root
        p.add_argument('--upstream', default=settings.UPSTREAM_DNS, help='one or more resolvers, comma separated, tried in order')

    def handle(self, *a, address, port, upstream, **o):
        if settings.REDIS_URL:
            from django.core.cache import cache
            from zones import redis_pool
            try:
                cache.get('warmup')  # creates the pool
                redis_pool.warm(min(settings.REDIS_POOL_SIZE, 4))  # a few connections ready from the first query
            except Exception as e:
                self.stderr.write(f'Redis is not reachable ({e}): continuing without it until it answers')
        writer = LogWriter(settings.DNS_LOG_FLUSH, settings.DNS_LOG_QUEUE) if settings.DNS_LOG_FLUSH > 0 else None
        if writer:
            writer.start()
        r = Resolver(upstream, log=writer)
        for cls in (PooledUDPServer, PooledTCPServer):
            cls.workers = settings.DNS_WORKERS
        servers = [DNSServer(r, port=port, address=address, tcp=t, server=PooledTCPServer if t else PooledUDPServer) for t in (False, True)]
        try:
            for s in servers:
                s.server.warm(min(settings.DNS_WORKERS, 4))  # a few database connections ready from the first query
        except Exception as e:
            self.stderr.write(f'Database is not reachable yet ({e}): connections are opened as queries arrive')
        for s in servers:
            s.start_thread()
        self.stdout.write(f'DNS on {address}:{port} (udp+tcp), upstream {upstream}')
        try:
            while True:
                close_old_connections()  # this thread sleeps for an hour: do not reuse a connection the database has closed meanwhile
                try:
                    partitions.maintain()  # MySQL partitioned log: drops old days instantly, creates the next ones
                except Exception as e:
                    self.stderr.write(f'Log partitions: {e}')
                cutoff = timezone.now() - timedelta(days=settings.QUERY_LOG_DAYS)
                QueryLog.objects.filter(time__lt=cutoff).delete()
                rollup.purge(cutoff)
                time.sleep(3600)
        except KeyboardInterrupt:
            for s in servers:
                s.stop()
            if writer:
                writer.stop()  # saves the rows still waiting
                if writer.dropped:
                    self.stderr.write(f'{writer.dropped} log rows were dropped (queue full)')
