"""Daemon heartbeats: rundns, rundhcp and runproxy each write Setting 'heartbeat:<name>' every INTERVAL seconds, so the GUI can tell whether they run.
Separate processes, no Redis needed: the database is what they share. Written with queryset.update()/bulk_create(), which send no signal: a heartbeat
must not raise DataVersion (that would make every daemon reload its data every 30 s)."""
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta

from django.db import close_old_connections
from django.utils import timezone

from dnsadmin import __version__

from .models import Setting

INTERVAL = 30  # seconds between two beats
STALE = 90  # a daemon not heard from for this long is not running
DAEMONS = ('dns', 'dhcp', 'proxy')


def key(name):
    return f'heartbeat:{name}'


def beat(name):
    value = json.dumps({'at': timezone.now().isoformat(), 'pid': os.getpid(), 'version': __version__})
    if not Setting.objects.filter(key=key(name)).update(value=value):
        Setting.objects.bulk_create([Setting(key=key(name), value=value)], ignore_conflicts=True)


def start(name, run=None):
    """Beat now and then every INTERVAL seconds on a daemon thread. run(beat, name) runs the write elsewhere (the proxy: on its database pool).
    A database error is written to stderr and retried at the next beat: it never stops the daemon."""
    def loop():
        while True:
            try:
                if run:
                    run(beat, name)
                else:
                    close_old_connections()  # this thread sleeps 30 s: not on a connection the database closed meanwhile
                    beat(name)
            except Exception as e:
                print(f'Heartbeat {name}: {e!r} (retried in {INTERVAL} s)', file=sys.stderr, flush=True)
            time.sleep(INTERVAL)
    threading.Thread(target=loop, daemon=True, name=f'heartbeat-{name}').start()


def read():
    """{name: {'last_seen': datetime or None, 'pid': int or None, 'version': str, 'running': bool}} for every daemon."""
    rows = dict(Setting.objects.filter(key__in=[key(n) for n in DAEMONS]).values_list('key', 'value'))
    now, out = timezone.now(), {}
    for n in DAEMONS:
        try:
            d = json.loads(rows.get(key(n)) or '{}')
            at = datetime.fromisoformat(d['at'])
        except (ValueError, KeyError, TypeError):
            d, at = {}, None
        out[n] = {'last_seen': at, 'pid': d.get('pid'), 'version': str(d.get('version') or ''),
                  'running': at is not None and now - at < timedelta(seconds=STALE)}
    return out
