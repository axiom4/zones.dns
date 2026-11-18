"""The public blocklists (Blacklist > Public lists): which lists, what the last `import_blocklist` did, and the lock that lets only one run at a time.

All three live in Setting rows. The status and lock rows are written with queryset update()/bulk_create(), which send no signals: a heartbeat
must not make the DNS daemon reload its copy of the blacklist (signals.py bumps DataVersion on every Setting save).
"""
import json
import re
import time
from urllib.parse import urlsplit

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import Setting
from .stats.audit import NAME_RE

KEY = 'blocklists'  # the lists, `name=url` one per line; no row = settings.BLOCKLISTS
STATUS = 'blocklists:status'  # JSON: what the last run did, per list
LOCK = 'blocklists:lock'  # unix time of the running import's last sign of life; older than LOCK_TTL (or '0') = free
LOCK_TTL = 900  # a run that died is taken over after this; a live one renews it after every list
MAX_LISTS = 50
MAX_URL = 2000
NAME = re.compile(r'^[a-z0-9._-]{1,40}$')
LOCAL = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', '0.0.0.0'}


class ListError(ValueError):
    """A list text refused; field = name, url or text (which input of the GUI it concerns)."""
    def __init__(self, field, msg):
        super().__init__(msg)
        self.field = field


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


def split_lists(text):
    """[(name, url)] from the GUI's text: `name=https://…` one per line (or a plain https URL, named after its file). Raises ListError."""
    out = []
    for entry in re.split(r'[\s,]+', str(text or '').strip()):
        if not entry:
            continue
        if entry.startswith(('http://', 'https://', 'file:')) or '=' not in entry:
            name, url = split_source(entry)
        else:
            name, url = entry.split('=', 1)
            if not NAME.match(name):
                raise ListError('name', f'“{name[:50]}”: a name is 1 to 40 of a-z, 0-9, dot, - and _.')
        # https only, as the proxy's rule lists: whoever can change a list downloaded over plain http decides what is blocked
        if not url.startswith('https://') or not urlsplit(url).hostname:
            raise ListError('url', f'{url[:100]}: public lists are downloaded over https only (https://…).')
        if len(url) > MAX_URL:
            raise ListError('url', f'{name}: the URL is longer than {MAX_URL} characters.')
        if any(n == name for n, _ in out):
            raise ListError('name', f'Two lists are named {name}: give each list its own name.')
        out.append((name, url))
    if len(out) > MAX_LISTS:
        raise ListError('text', f'{len(out)} lists: at most {MAX_LISTS}.')
    return out


def configured(default=None):
    """[(name, url or path)]: the lists saved in the GUI, else BLOCKLISTS of .env (read leniently: it may name files or http URLs)."""
    raw = Setting.objects.filter(key=KEY).values_list('value', flat=True).first()
    if raw is None:
        return [split_source(e) for e in (settings.BLOCKLISTS if default is None else default)]
    return split_lists(raw)


def save(entries):
    Setting.objects.update_or_create(key=KEY, defaults={'value': ''.join(f'{n}={u}\n' for n, u in entries)})


def _put(key, value):
    """Writes a Setting row without the save signal (no DataVersion bump)."""
    if not Setting.objects.filter(key=key).update(value=value):
        try:
            with transaction.atomic():
                Setting.objects.bulk_create([Setting(key=key, value=value)])
        except IntegrityError:  # written by another process in between
            Setting.objects.filter(key=key).update(value=value)


def status():
    raw = Setting.objects.filter(key=STATUS).values_list('value', flat=True).first()
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def save_status(st):
    _put(STATUS, json.dumps(st))


def now_iso():
    return timezone.now().isoformat()


def acquire():
    """True when this process now holds the lock: free, released, or left by a run that stopped renewing it."""
    now = int(time.time())
    if Setting.objects.filter(key=LOCK, value__lt=str(now - LOCK_TTL)).update(value=str(now)):  # '0' and 10-digit times compare as text
        return True
    try:
        with transaction.atomic():
            Setting.objects.bulk_create([Setting(key=LOCK, value=str(now))])
        return True
    except IntegrityError:
        return False


def renew():
    Setting.objects.filter(key=LOCK).update(value=str(int(time.time())))


def release():
    Setting.objects.filter(key=LOCK).update(value='0')


def running():
    v = Setting.objects.filter(key=LOCK).values_list('value', flat=True).first()
    return bool(v) and v.isdigit() and int(v) >= time.time() - LOCK_TTL
