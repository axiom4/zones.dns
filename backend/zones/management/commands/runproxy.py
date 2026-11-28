import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
import signal
import subprocess
import sys
import threading
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, close_old_connections, connections
from django.utils import timezone

from zones.dnsd import resolver
from zones.models import DataVersion, ProxyLog
from zones.proxy import ca, filter as pfilter, memwatch, rules
from zones.proxy.server import ProxyLogWriter, ProxyServer, cached_proxy_settings
from zones.logfmt import stamp_output
from zones import heartbeat
from zones.stats import rollup

BIND_KEYS = ('PROXY', 'PROXY_PORT', 'PROXY_ADDRESS')


class Command(BaseCommand):
    help = (
        'Run the HTTP/HTTPS ad-blocking and popup-filtering proxy server (settings PROXY_*). '
        'Configured in the GUI (Proxy page) and announced to DHCP clients via WPAD (option 252 + wpad.<domain>).'
    )

    def add_arguments(self, p):
        p.add_argument('--address', default='', help='bind to this address (default: PROXY_ADDRESS or 0.0.0.0)')
        p.add_argument('--port', type=int, default=0, help='bind to this TCP port (default: PROXY_PORT or 8080)')
        p.add_argument('--worker', type=int, default=None, help=argparse.SUPPRESS)  # set by the supervisor on the processes it starts

    def handle(self, *a, address, port, worker, **o):
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
            pfilter.run_on_db_pool(ca.ensure_ca)  # before the workers start: two of them must not each make a Root CA
        if worker is None and settings.PROXY_WORKERS > 1:
            connections.close_all()
            return self.supervise(settings.PROXY_WORKERS)
        writer = ProxyLogWriter()
        writer.start()
        try:
            asyncio.run(self.serve(bind_addr, bind_port, s, writer, shared=worker is not None, primary=not worker))
        finally:
            writer.stop()

    def supervise(self, n):
        """Start `n` worker processes (this command with --worker i) and keep them running. No database, no sockets here: only the processes.
        A worker that exits with 0 was told by the settings to stop (the proxy is off): the others stop too."""
        stopping = []
        signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
        signal.signal(signal.SIGINT, lambda *_: stopping.append(1))

        def spawn(i):
            return subprocess.Popen([sys.executable, *sys.argv, '--worker', str(i)])
        procs = {i: spawn(i) for i in range(n)}
        started = {i: time.monotonic() for i in procs}
        self.stdout.write(f'Proxy: {n} worker processes share the port (PROXY_WORKERS).')
        self.stdout.flush()
        while not stopping:
            time.sleep(0.5)
            for i, p in procs.items():
                rc = p.poll()
                if rc is None:
                    continue
                if rc == 0:
                    stopping.append(1)
                    break
                self.stderr.write(f'Proxy: worker {i} exited with {rc}: starting it again.')
                if time.monotonic() - started[i] < 5:
                    time.sleep(2)  # a worker that dies at once (port in use, bad config) must not spin
                procs[i], started[i] = spawn(i), time.monotonic()
        for p in procs.values():
            if p.poll() is None:
                p.terminate()
        for p in procs.values():
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        raise SystemExit(0)

    async def serve(self, bind_addr, bind_port, s, writer, shared=False, primary=True):
        """`shared`: one of several workers on the port. `primary`: the one that also does the hourly work (rule lists, log purge) and the heartbeat."""
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=8, thread_name_prefix='proxy-misc'))
        try:
            srv = await ProxyServer((bind_addr, bind_port), settings_getter=cached_proxy_settings, log=writer, reuse_port=shared).start()
        except OSError as e:
            raise CommandError(f'Cannot bind TCP {bind_addr}:{bind_port} ({e}).')
        await asyncio.to_thread(pfilter.run_on_db_pool, resolver._snapshot)
        self.snap = {k: getattr(s, k) for k in BIND_KEYS}
        self.seen = await asyncio.to_thread(DataVersion.version)
        await asyncio.to_thread(connections.close_all)
        if primary:
            heartbeat.start('proxy', run=pfilter.run_on_db_pool)  # the GUI's status line; on the pool: no database connection of its own
        self.memwatch = memwatch.start(srv, lambda line: (self.stdout.write(line), self.stdout.flush()))
        self.stdout.write(
            f'Proxy listening on {bind_addr}:{bind_port} '
            f'(ads={"on" if s.PROXY_BLOCK_ADS else "off"}, '
            f'popups={"on" if s.PROXY_BLOCK_POPUPS else "off"}, '
            f'https={"MITM" if s.PROXY_HTTPS_MITM else "CONNECT"}, asyncio, HTTP/2'
            f'{", one of several workers" if shared else ""})'
        )
        self.stdout.flush()
        last_purge = 0.0
        while True:
            await asyncio.sleep(2.0)
            try:
                action = await asyncio.to_thread(self.reload_if_changed)
            except DatabaseError as e:
                self.stderr.write(f'Proxy: cannot check settings: {e!r}')
                action = None
            if action:
                srv.close()
                writer.stop()
                if action == 'stop':
                    self.stdout.write('Proxy switched off in the settings: stopping.')
                    raise SystemExit(0)
                self.stdout.write('Proxy bind settings changed: restarting with them.')
                self.stdout.flush()
                await asyncio.to_thread(connections.close_all)  # Django refuses database calls on the event loop's thread
                os.execv(sys.executable, [sys.executable] + sys.argv)
            now = time.monotonic()
            if primary and now - last_purge >= 3600.0:  # once for all the workers
                last_purge = now
                threading.Thread(target=self.sync_rules, daemon=True).start()  # a download takes seconds: not on the event loop
                try:
                    cutoff = timezone.now() - timedelta(days=settings.QUERY_LOG_DAYS)
                    await asyncio.to_thread(pfilter.run_on_db_pool, lambda: rollup.delete_chunked(ProxyLog.objects.filter(time__lt=cutoff)))
                except Exception as e:
                    print(f'Proxy: log purge failed: {e!r} (retried in an hour)', file=sys.stderr)

    @staticmethod
    def sync_rules():
        try:
            if rules.due():
                rules.sync_all()
        except Exception as e:
            print(f'Proxy: rule lists not updated: {e!r}', file=sys.stderr)
        finally:
            connections.close_all()

    def reload_if_changed(self):
        """None, 'restart' (address or port changed) or 'stop' (the proxy was switched off)."""
        ver = pfilter.run_on_db_pool(DataVersion.version)
        if ver == self.seen:
            return None
        self.seen = ver
        new = cached_proxy_settings(settings, force=True)
        if new.PROXY_HTTPS_MITM:
            pfilter.run_on_db_pool(ca.ensure_ca, refresh=True)  # a Root CA made anew in the GUI: signed with from now on
        snap = {k: getattr(new, k) for k in BIND_KEYS}
        if snap == self.snap:
            return None
        return 'restart' if new.PROXY else 'stop'
