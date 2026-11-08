import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from dnslib import AAAA, QTYPE, RCODE, RR, SOA, A, DNSRecord
from dnslib.server import BaseResolver

from .domains import main_domain
from . import suspicious
from .models import BlockedDomain, DataVersion, QueryLog, Record, StaticHost, Zone


# The zones, their enabled records and the blacklist answers stay in memory until the data changes. The API runs in another process, so every
# change raises DataVersion (zones/signals.py). With REDIS_URL the counter, the data and the blacklist answers are also kept in Redis, so the daemon
# sees a change at once (it checks on every query), restarts warm, and several daemons share one copy. Without Redis the daemon looks at the
# counter in the database at most once per DNS_DATA_CHECK seconds.
# DNS_DATA_TTL is the upper bound for a copy, in case a change slipped through without raising the counter (raw SQL, a restored backup).
_data_lock = threading.Lock()
_data = None  # (zone names longest first, {(zone name, record name): [Record]}, {host name: [(address, ttl)]})
_data_at = 0.0  # when the copy was made
_data_checked = 0.0  # when the counter was last read
_data_version = None
_blocked = {}  # name -> blacklist entry or None; emptied when the data changes
_NONE = ''  # a name that is not blocked, as stored in Redis (a missing key means "not asked yet")


def _shared():
    return bool(settings.REDIS_URL)


def _build():
    """The data as plain values (these are what Redis stores): ([zone names], {(zone, name): [(type, value, ttl)]}, {host: [(address, ttl)]})."""
    zones = [z.name for z in Zone.objects.all()]
    recs = defaultdict(list)
    for r in Record.objects.filter(enabled=True).select_related('zone'):
        recs[(r.zone.name, r.name)].append((r.type, r.value, r.ttl))
    hosts = defaultdict(list)
    for h in StaticHost.objects.filter(enabled=True):
        hosts[h.name].append((h.address, h.ttl))
    return zones, dict(recs), dict(hosts)


def _load():
    global _data, _data_at, _data_version
    version = DataVersion.version()  # read before the data: a change during the load makes the next check reload again
    plain = None
    if _shared():
        try:
            plain = cache.get(f'snap:{version}')
        except Exception:
            pass
    if plain is None:
        plain = _build()
        if _shared():
            try:
                cache.set(f'snap:{version}', plain, settings.DNS_DATA_TTL)
            except Exception:
                pass
    names, plain_recs, hosts = plain
    by_name = {key: [Record(name=key[1], type=t, value=v, ttl=ttl, zone=Zone(name=key[0])) for t, v, ttl in rows] for key, rows in plain_recs.items()}
    _data, _data_at, _data_version = (sorted(names, key=len, reverse=True), by_name, hosts), time.monotonic(), version
    _blocked.clear()


def _snapshot():
    global _data_checked
    now = time.monotonic()
    if _data is not None and now - _data_checked < (0 if _shared() else settings.DNS_DATA_CHECK):  # with Redis: look at every query
        return _data
    if _data_lock.acquire(blocking=_data is None):  # while one thread checks or reloads, the others keep using the current copy
        try:
            now = _data_checked = time.monotonic()
            try:
                if _data is None or now - _data_at > settings.DNS_DATA_TTL or DataVersion.version() != _data_version:
                    _load()
            except Exception:
                if _data is None:
                    raise  # nothing to fall back on; with a copy we keep serving it and look again at the next check
        finally:
            _data_lock.release()
    return _data


def static_hosts(qname):
    """[(address, ttl)] of the static host with this exact name, or None if there is none."""
    return _snapshot()[2].get(qname.rstrip('.').lower())


def static_reply(request, qtype, hosts):
    """Answer from a static host: A gets the IPv4 addresses, AAAA the IPv6 ones, every other type an empty answer (nothing leaks from the real DNS)."""
    reply = request.reply()
    reply.header.aa = 1
    want, rdata = {'A': (4, A), 'AAAA': (6, AAAA)}.get(qtype, (None, None))
    for address, ttl in hosts:
        if want and (':' in address) == (want == 6):
            reply.add_answer(RR(request.q.qname, request.q.qtype, rdata=rdata(address), ttl=ttl))
    return reply


def lookup(qname, qtype):
    """Return (records, via_wildcard) from the longest matching internal zone, or None to ask upstream.

    Exact name wins; otherwise the closest wildcard (a.b.zone -> *.b.zone, then *.zone).
    """
    q = qname.rstrip('.').lower()
    zones, by_name, _ = _snapshot()
    for zname in zones:
        if q == zname or q.endswith('.' + zname):
            rel = '@' if q == zname else q[: -len(zname) - 1]
            recs, wild = by_name.get((zname, rel), []), False
            if not recs and rel != '@':
                labels = rel.split('.')
                cands = [f'*.{".".join(labels[i:])}' for i in range(1, len(labels))] + ['*']
                for c in cands:  # most specific first
                    recs = by_name.get((zname, c), [])
                    if recs:
                        wild = True
                        break
            if not recs:
                return None  # zone is ours but name unknown: ask upstream
            hit = [r for r in recs if r.type == qtype] or [r for r in recs if r.type == 'CNAME']
            return (hit, wild) if hit else None  # no record of this type: ask upstream too
    return None


def authority(qname):
    """(zone, exists) when qname is inside one of our zones, else None. Our zones are authoritative: a name or type they lack gets a
    negative answer (RFC 2308), not an upstream lookup. exists is False only for a name with no records, no wildcard and nothing below it."""
    q = qname.rstrip('.').lower()
    zones, by_name, _ = _snapshot()
    for zname in zones:
        if q == zname or q.endswith('.' + zname):
            rel = '@' if q == zname else q[: -len(zname) - 1]
            if rel == '@' or (zname, rel) in by_name:
                return zname, True
            labels = rel.split('.')
            wild = [f'*.{".".join(labels[i:])}' for i in range(1, len(labels))] + ['*']
            if any((zname, c) in by_name for c in wild):
                return zname, True
            # empty non-terminal: a.b.zone exists, so b.zone exists (without data)
            return zname, any(z == zname and n.endswith('.' + rel) for z, n in by_name)
    return None


def soa(zone, ttl=300):
    """The zone has no stored SOA: build one. mname is the first apex NS (or ns.<zone>), the serial is the data version."""
    _, by_name, _ = _snapshot()
    ns = next((r for r in by_name.get((zone, '@'), []) if r.type == 'NS'), None)
    mname = str(ns.to_rr()[0].rdata.label) if ns else f'ns.{zone}.'
    times = (int(_data_version or 1) % 2**32, 3600, 600, 86400, ttl)
    return RR(zone, QTYPE.SOA, rdata=SOA(mname, f'hostmaster.{zone}.', times), ttl=ttl)


def negative(request, zone, exists):
    """NODATA (name exists, no record of this type) or NXDOMAIN, authoritative, with the SOA in the authority section."""
    reply = request.reply()
    reply.header.aa = 1
    if request.q.qtype == QTYPE.SOA and str(request.q.qname).rstrip('.').lower() == zone:
        reply.add_answer(soa(zone))
        return reply
    reply.header.rcode = RCODE.NOERROR if exists else RCODE.NXDOMAIN
    reply.add_auth(soa(zone))
    return reply


def blocked_match(qname):
    """The blacklist entry that covers qname (itself or a parent), or None. Answers are remembered per name until the data changes."""
    _snapshot()  # notices a change and empties _blocked
    if qname in _blocked:
        return _blocked[qname]
    if _shared():
        try:
            stored = cache.get(f'bl:{_data_version}:{qname}')
            if stored is not None:
                _blocked[qname] = match = stored or None
                return match
        except Exception:
            pass
    labels = qname.rstrip('.').lower().split('.')
    suffixes = ['.'.join(labels[i:]) for i in range(len(labels))]
    hit = BlockedDomain.objects.filter(name__in=suffixes).order_by('-name').first()
    if len(_blocked) > 20000:  # bounded: names that were asked once are the bulk
        _blocked.clear()
    _blocked[qname] = match = hit.name if hit else None
    if _shared():
        try:
            cache.set(f'bl:{_data_version}:{qname}', match or _NONE, settings.DNS_DATA_TTL)
        except Exception:
            pass
    return match


def summarize(reply):
    """What the client was told: response code and the answer records (capped)."""
    answers = []
    for rr in reply.rr[:20]:
        try:
            value = rr.rdata.toZone()
        except Exception:
            value = str(rr.rdata)
        answers.append({'name': str(rr.rname).rstrip('.'), 'type': QTYPE[rr.rtype], 'value': value[:300], 'ttl': rr.ttl})
    return RCODE[reply.header.rcode], answers


class Resolver(BaseResolver):
    def __init__(self, upstream, log=None):
        self.log = log  # a LogWriter; None = write each log row at once
        self.upstream = upstream  # as given, for messages
        self.upstreams = [u.strip() for u in upstream.split(',') if u.strip()]
        self.down = {}  # upstream -> monotonic time until which it is skipped
        self._prefetch_pool = ThreadPoolExecutor(max_workers=settings.DNS_PREFETCH_WORKERS, thread_name_prefix='dns-prefetch')
        self._prefetch_room = threading.BoundedSemaphore(settings.DNS_PREFETCH_WORKERS * 8)

    def resolve(self, request, handler):
        connection.close_if_health_check_failed()  # a connection the database dropped while idle is replaced before use
        t0 = time.monotonic()
        qname, qtype = str(request.q.qname).rstrip('.').lower(), QTYPE[request.q.qtype]
        try:
            hosts = static_hosts(qname)
            found = None if hosts else lookup(qname, qtype)
            if hosts:
                outcome, reply, via = 'local', static_reply(request, qtype, hosts), 'static host'
            elif found is not None:
                recs, wild = found
                outcome, reply = 'local', request.reply()
                via = f'zone {recs[0].zone.name}' + (f' (wildcard {recs[0].name})' if wild else '')
                reply.header.aa = 1
                for r in recs:
                    for rr in r.to_rr(owner=qname if wild else None):
                        reply.add_answer(rr)
                # A CNAME to a name in our own zones: add the target's records too, so the client gets an address
                target, hops = recs, 0
                while qtype != 'CNAME' and target[0].type == 'CNAME' and hops < 8:
                    nxt = str(target[0].to_rr()[0].rdata.label).rstrip('.').lower()
                    more = lookup(nxt, qtype)
                    if not more:
                        break
                    target, hops = more[0], hops + 1
                    for r in target:
                        for rr in r.to_rr(owner=nxt if more[1] else None):
                            reply.add_answer(rr)
            elif (auth := authority(qname)):
                outcome, via = 'local', f'zone {auth[0]} (no such {"record" if auth[1] else "name"})'
                reply = negative(request, *auth)
            elif (match := blocked_match(qname)):
                outcome, reply, via = 'blocked', request.reply(), f'blacklist {match}'
                reply.header.rcode = RCODE.NXDOMAIN
            elif (why := suspicious.check(qname, qtype, handler.client_address[0])) and settings.SUSPICIOUS_MODE == 'block':
                outcome, reply, via = 'blocked', request.reply(), f'suspicious: {why}'
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                reply, via = self.forward(request)
                outcome = 'error' if reply.header.rcode == RCODE.SERVFAIL else 'forwarded'
                if why:  # log-only mode
                    via += f' (suspicious: {why})'
            rcode, answers = summarize(reply)
            entry = QueryLog(name=qname, domain=main_domain(qname), type=qtype, outcome=outcome, client=handler.client_address[0],
                             ms=int((time.monotonic() - t0) * 1000), rcode=rcode, via=via, answers=answers)
            if self.log:
                self.log.add(entry)  # saved in a batch a moment later
            else:
                entry.save()
            return reply
        finally:
            connection.close_if_unusable_or_obsolete()  # the worker thread keeps its connection for the next query, unless it broke or is older than CONN_MAX_AGE

    def forward(self, request):
        """(reply, via). Answers are cached for their TTL; a cache failure (Redis down) just means asking upstream.
        A cached answer that is about to expire and is still being asked for is renewed in the background (DNS_PREFETCH).
        When every upstream is down an expired answer is served instead, if we still have one (DNS_STALE_TTL)."""
        key = f'dns:{QTYPE[request.q.qtype]}:{str(request.q.qname).lower()}'
        if settings.DNS_CACHE:
            entry = self._cache_get(key)
            if entry:
                if isinstance(entry, (bytes, bytearray)):  # written by an older version: no expiry time stored
                    return self._parse(entry, request), 'cache'
                raw, expires, ttl = entry
                remaining = expires - time.time()
                reply = self._parse(raw, request)
                for rr in reply.rr:
                    rr.ttl = max(1, min(rr.ttl, int(remaining)))  # count the TTL down, so clients never keep it longer than the origin allowed
                if settings.DNS_PREFETCH and ttl >= 10 and remaining < ttl * settings.DNS_PREFETCH_AT:
                    self._prefetch(key, request)
                return reply, 'cache'
        reply, used = self.ask_upstream(request)
        if used is None:  # nobody answered
            raw = settings.DNS_CACHE and settings.DNS_STALE_TTL and self._cache_get('stale:' + key)
            if raw:
                reply = self._parse(raw, request)
                for rr in reply.rr:
                    rr.ttl = min(rr.ttl, 30)  # clients must ask again soon
                return reply, 'stale cache (upstream down)'
            return reply, f'upstream {self.upstream} (no answer)'
        if settings.DNS_CACHE:
            self._store(key, reply)
        return reply, f'upstream {used}'

    @staticmethod
    def _store(key, reply):
        if reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN) and not reply.header.tc:
            ttl = min([rr.ttl for rr in reply.rr] or [settings.DNS_CACHE_NEG_TTL])
            ttl = min(ttl, settings.DNS_CACHE_MAX_TTL) if reply.rr else min(ttl, settings.DNS_CACHE_NEG_TTL)
            if ttl > 0:
                try:
                    raw = reply.pack()
                    cache.set(key, (raw, time.time() + ttl, ttl), ttl)
                    if settings.DNS_STALE_TTL:
                        cache.set('stale:' + key, raw, settings.DNS_STALE_TTL)
                except Exception:
                    pass  # cache down: the answer was still delivered, just not stored

    def _prefetch(self, key, request):
        """Ask the upstream again for a name that is still wanted, so the next query finds a fresh answer. Once per name at a time."""
        try:
            if not cache.add('pf:' + key, 1, 10):  # another thread (or daemon) is already on it; also retries a failed one after 10 s
                return
        except Exception:
            return
        if not self._prefetch_room.acquire(blocking=False):
            return  # too many renewals under way
        q = DNSRecord.question(str(request.q.qname), QTYPE[request.q.qtype])
        self._prefetch_pool.submit(self._renew, key, q)

    def _renew(self, key, question):
        try:
            reply, used = self.ask_upstream(question)
            if used is not None:  # if every upstream is down, the old entry simply expires (and the stale copy stays)
                self._store(key, reply)
        finally:
            self._prefetch_room.release()

    @staticmethod
    def _cache_get(key):
        try:
            return cache.get(key)
        except Exception:
            return None

    @staticmethod
    def _parse(raw, request):
        reply = DNSRecord.parse(raw)
        reply.header.id = request.header.id  # the cached copy carries the id of the first asker
        return reply

    def ask_upstream(self, request):
        """(reply, upstream that answered) or (SERVFAIL reply, None). Tries the upstreams in order; one that failed is skipped for
        DNS_UPSTREAM_DOWN seconds so a dead server does not slow down every query. If all are marked down, all are tried anyway."""
        now = time.monotonic()
        order = [u for u in self.upstreams if self.down.get(u, 0) <= now] or self.upstreams
        for server in order:
            try:
                v6 = ':' in server
                reply = DNSRecord.parse(request.send(server, 53, timeout=settings.DNS_UPSTREAM_TIMEOUT, ipv6=v6))
                if reply.header.tc:  # truncated: retry over TCP
                    reply = DNSRecord.parse(request.send(server, 53, tcp=True, timeout=settings.DNS_UPSTREAM_TIMEOUT, ipv6=v6))
                if reply.header.rcode != RCODE.SERVFAIL:
                    return reply, server
            except Exception:
                self.down[server] = time.monotonic() + settings.DNS_UPSTREAM_DOWN  # no answer at all; a SERVFAIL only moves on to the next
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply, None
