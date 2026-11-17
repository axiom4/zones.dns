from datetime import timedelta
import os
import sys
import threading
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, close_old_connections, connections
from django.utils import timezone

from zones.dnsd import resolver
from zones.models import DataVersion, ProxyLog
from zones.proxy import ca, filter as pfilter, rules
from zones.proxy.server import ProxyLogWriter, ProxyServer, cached_proxy_settings
from zones.logfmt import stamp_output

BIND_KEYS = ('PROXY', 'PROXY_PORT', 'PROXY_ADDRESS')


class Command(BaseCommand):
    help = (
        'Run the HTTP/HTTPS ad-blocking and popup-filtering proxy server (settings PROXY_*). '
        'Configured in the GUI (Proxy page) and announced to DHCP clients via WPAD (option 252 + wpad.<domain>).'
    )

    def add_arguments(self, p):
        p.add_argument('--address', default='', help='bind to this address (default: PROXY_ADDRESS or 0.0.0.0)')
        p.add_argument('--port', type=int, default=0, help='bind to this TCP port (default: PROXY_PORT or 8080)')

    def handle(self, *a, address, port, **o):
        stamp_output(self)
        s = cached_proxy_settings(settings, force=True)
        if not s.PROXY:
            self.stdout.write('Proxy is off: waiting until it is turned on in the GUI (DHCP > Proxy).')
            self.stdout.flush()
            while not s.PROXY:
                time.sleep(2)
                close_old_connections()
                s = cached_proxy_settings(settings, force=True)
        bind_addr = address or s.PROXY_ADDRESS or '0.0.0.0'
        bind_port = port or s.PROXY_PORT or 8080
        if not 1 <= bind_port <= 65535:
            raise CommandError(f'Invalid proxy port {bind_port} (must be 1-65535).')
        if s.PROXY_HTTPS_MITM:
            ca.ensure_ca()
        writer = ProxyLogWriter()
        writer.start()
        try:
            srv = ProxyServer((bind_addr, bind_port), settings_getter=cached_proxy_settings, log=writer)
        except OSError as e:
            writer.stop()
            raise CommandError(f'Cannot bind TCP {bind_addr}:{bind_port} ({e}).')
        srv.timeout = 2
        pfilter.run_on_db_pool(resolver._snapshot)
        self.snap = {k: getattr(s, k) for k in BIND_KEYS}
        self.seen = DataVersion.version()
        connections.close_all()
        self.stdout.write(
            f'Proxy listening on {bind_addr}:{bind_port} '
            f'(ads={"on" if s.PROXY_BLOCK_ADS else "off"}, '
            f'popups={"on" if s.PROXY_BLOCK_POPUPS else "off"}, '
            f'https={"MITM" if s.PROXY_HTTPS_MITM else "CONNECT"})'
        )
        self.stdout.flush()
        last_check = time.monotonic()
        last_purge = 0.0
        while True:
            srv.handle_request()
            now = time.monotonic()
            if now - last_check >= 2.0:
                last_check = now
                try:
                    self.reload_if_changed(srv, writer)
                except DatabaseError as e:
                    self.stderr.write(f'Proxy: cannot check settings: {e!r}')
            if now - last_purge >= 3600.0:
                last_purge = now
                threading.Thread(target=self.sync_rules, daemon=True).start()  # a download takes seconds: not in the accept loop
                try:
                    cutoff = timezone.now() - timedelta(days=settings.QUERY_LOG_DAYS)
                    pfilter.run_on_db_pool(lambda: ProxyLog.objects.filter(time__lt=cutoff).delete())
                except Exception:
                    pass

    @staticmethod
    def sync_rules():
        try:
            if rules.due():
                rules.sync_all()
        except Exception as e:
            print(f'Proxy: rule lists not updated: {e!r}', file=sys.stderr)
        finally:
            connections.close_all()

    def reload_if_changed(self, srv, writer=None):
        ver = pfilter.run_on_db_pool(DataVersion.version)
        if ver == self.seen:
            return
        self.seen = ver
        new = cached_proxy_settings(settings, force=True)
        if new.PROXY_HTTPS_MITM:
            ca.ensure_ca()
        snap = {k: getattr(new, k) for k in BIND_KEYS}
        if snap == self.snap:
            return
        srv.server_close()
        if writer:
            writer.stop()
        if not new.PROXY:
            self.stdout.write('Proxy switched off in the settings: stopping.')
            raise SystemExit(0)
        self.stdout.write('Proxy bind settings changed: restarting with them.')
        self.stdout.flush()
        connections.close_all()
        os.execv(sys.executable, [sys.executable] + sys.argv)
