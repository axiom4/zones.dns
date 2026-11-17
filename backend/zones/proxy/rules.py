"""External ad-block rule lists (EasyList / uBlock / Adblock Plus syntax) for the proxy: downloaded, reduced to what the proxy can apply fast, kept in the database.

Kept: `||domain^` (the domain and its subdomains are blocked), `@@||domain^` (never filtered), `##selector` and `domain##selector` (hide page elements).
Dropped: URL fragments, regular expressions and rules with options that need a browser (`$domain=`, `~third-party`...): they would be one regex per
request for tens of thousands of rules. shortcut: domain and cosmetic rules only, add path rules when a real list needs them.
"""
import json
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field

from django.utils import timezone

from ..models import DataVersion, Setting

RULES = 'prl:'   # prl:<name> = the reduced rules, prm:<name> = what the last sync did (JSON)
META = 'prm:'
MAX_BYTES = 50_000_000
MAX_GLOBAL_CSS = 5000  # generic selectors go into every page: a cap keeps the pages small
SAFE_OPTIONS = {'third-party', '3p', 'script', 'image', 'stylesheet', 'subdocument', 'xmlhttprequest', 'xhr', 'media', 'font', 'ping', 'other', 'popup', 'important'}
DOMAIN_RX = re.compile(r'^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$')
REFRESH_SECONDS = 86400


def split_entries(text):
    """[(name, url)] from lines or words `name=url`; a plain URL is named after its file."""
    out = []
    for entry in re.split(r'[\s,]+', str(text or '').strip()):
        if not entry:
            continue
        # https only: whoever can change a list downloaded over plain http can add @@ rules that turn the filter off
        m = re.match(r'^([a-z0-9._-]{1,40})=(https://.+)$', entry)
        if m:
            out.append((m[1], m[2]))
        elif entry.startswith('https://'):
            name = re.sub(r'[^a-z0-9._-]', '-', entry.split('?')[0].rstrip('/').rsplit('/', 1)[-1].lower())[:40] or 'list'
            out.append((name, entry))
        else:
            raise ValueError(f'rule list {entry!r}: use name=https://… (or a plain https:// URL)')
    names = [n for n, _ in out]
    if len(set(names)) != len(names):
        raise ValueError('rule lists: two lists have the same name')
    return out


def _network(rule):
    """The domain of a `||domain^` rule (without the @@), or None when the proxy cannot apply it."""
    body, _, opts = rule.partition('$')
    if opts and not set(opts.split(',')) <= SAFE_OPTIONS:
        return None
    m = re.match(r'^\|\|([^/^*|:?]+)\^?$', body)
    d = m[1].lower().strip('.') if m else ''
    return d if DOMAIN_RX.match(d) and '.' in d else None


def reduce(text):
    """The lines of an Adblock Plus list that the proxy applies, as one text; (text, counts)."""
    keep, blocks, allow, css = [], 0, 0, 0
    for line in str(text).splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '[', '#')) and not line.startswith('##'):
            continue
        if '#@#' in line or '#?#' in line or '#$#' in line or '#%#' in line:
            continue
        if line.startswith('@@'):
            if (d := _network(line[2:])):
                keep.append(f'@@||{d}^')
                allow += 1
        elif '##' in line:
            dom, _, sel = line.partition('##')
            if not sel.strip() or sel.startswith(('+js(', '^', 'script:inject')) or '</style' in sel.lower() or ':-abp-' in sel or ':has-text(' in sel or ':xpath(' in sel:
                continue
            if not dom and css >= MAX_GLOBAL_CSS:
                continue
            keep.append(line)
            css += 1
        elif (d := _network(line)):
            keep.append(f'||{d}^')
            blocks += 1
    return '\n'.join(keep), {'blocks': blocks, 'allow': allow, 'cosmetic': css}


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'zones-dns/1.0'})
    with urllib.request.urlopen(req, timeout=60) as r:
        if not r.geturl().startswith('https://'):
            raise OSError('the list was redirected to plain http')  # urllib follows an https -> http redirect
        raw = r.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise OSError('response exceeds 50 MB limit')
    return raw.decode('utf-8', 'replace')


def sync_all(lists_text=None, fetcher=None):
    """Download every configured list and replace what is stored; a list that fails keeps its old rules. Returns [status dict]; bumps DataVersion on change."""
    from ..dhcp import v4 as dhcp
    entries = split_entries(dhcp.dhcp_settings().PROXY_RULE_LISTS if lists_text is None else lists_text)
    out = []
    for name, url in entries:
        try:
            text, counts = reduce((fetcher or fetch)(url))
            Setting.objects.update_or_create(key=RULES + name, defaults={'value': text})
            meta = {'name': name, 'url': url, **counts, 'updated': timezone.now().isoformat(), 'error': ''}
        except (OSError, ValueError) as e:
            old = _meta(name)
            meta = {**old, 'name': name, 'url': url, 'error': str(e)[:300]}
            meta.setdefault('blocks', 0), meta.setdefault('allow', 0), meta.setdefault('cosmetic', 0), meta.setdefault('updated', None)
        Setting.objects.update_or_create(key=META + name, defaults={'value': json.dumps(meta)})
        out.append(meta)
    keep = {n for n, _ in entries}
    for key in Setting.objects.filter(key__startswith=RULES).values_list('key', flat=True):
        if key[len(RULES):] not in keep:
            Setting.objects.filter(key__in=(key, META + key[len(RULES):])).delete()
    DataVersion.bump()
    reset()
    return out


def _meta(name):
    raw = Setting.objects.filter(key=META + name).values_list('value', flat=True).first()
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def status():
    """One dict per configured list: what the last sync did (counts 0 and updated None before the first)."""
    from ..dhcp import v4 as dhcp
    rows = []
    for name, url in split_entries(dhcp.dhcp_settings().PROXY_RULE_LISTS):
        m = _meta(name)
        rows.append({'name': name, 'url': url, 'blocks': m.get('blocks', 0), 'allow': m.get('allow', 0), 'cosmetic': m.get('cosmetic', 0), 'updated': m.get('updated'), 'error': m.get('error', '')})
    return rows


def due():
    """True when a configured list was never synced or is older than a day."""
    try:
        rows = status()
    except ValueError:
        return False
    now = timezone.now()
    return any(not r['updated'] or (now - timezone.datetime.fromisoformat(r['updated'])).total_seconds() > REFRESH_SECONDS for r in rows)


@dataclass
class Loaded:
    blocks: dict = field(default_factory=dict)   # domain -> list name
    allow: set = field(default_factory=set)
    global_css: list = field(default_factory=list)
    domain_css: dict = field(default_factory=dict)


_lock = threading.Lock()
_cache = {'ver': None, 'checked': 0.0, 'data': Loaded()}


def reset():
    with _lock:
        _cache.update(ver=None, checked=0.0)


def _read(prev_ver):
    """(version, stored lists or None when the version did not move)."""
    ver = DataVersion.version()
    if ver == prev_ver:
        return ver, None
    return ver, list(Setting.objects.filter(key__startswith=RULES).values_list('key', 'value'))


def loaded():
    """The stored rules, parsed; looked at again when DataVersion moves (checked at most every 2 s)."""
    now = time.monotonic()
    if _cache['ver'] is not None and now - _cache['checked'] < 2.0:
        return _cache['data']
    from .filter import run_on_db_pool  # filter imports this module
    with _lock:
        ver, rows = run_on_db_pool(_read, _cache['ver'])
        _cache['checked'] = now
        if rows is None:
            return _cache['data']
        data = Loaded()
        for key, text in rows:
            name = key[len(RULES):]
            for line in text.splitlines():
                if line.startswith('@@||'):
                    data.allow.add(line[4:-1])
                elif line.startswith('||'):
                    data.blocks.setdefault(line[2:-1], name)
                elif '##' in line:
                    dom, _, sel = line.partition('##')
                    if not dom:
                        data.global_css.append(sel)
                    else:
                        for d in dom.split(','):
                            d = d.strip().lower().strip('.')
                            if d and not d.startswith('~'):
                                data.domain_css.setdefault(d, []).append(sel)
        _cache.update(ver=ver, data=data)
        return data


def blocked_by(host, data):
    """(domain, list name) when `host` or a parent domain is blocked by a list, else None."""
    labels = (host or '').split('.')
    for i in range(len(labels) - 1):
        sub = '.'.join(labels[i:])
        if sub in data.blocks:
            return sub, data.blocks[sub]
    return None
