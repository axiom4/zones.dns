import re
import secrets
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.models import Q
from django.utils import timezone
from dnslib import AAAA, EDNS0, OPCODE, PTR, QTYPE, RCODE, RR, SOA, A, DNSHeader, DNSRecord
from dnslib.server import BaseResolver

from .domains import main_domain
from . import ddr, ddns, dnssec, ratelimit, suspicious
from ..dhcp import v4 as dhcp
from ..stats import rollup
from ..models import PERSONAL_BLOCKS, PUBLIC_LISTS, BlockedDomain, DataVersion, QueryLog, Record, Setting, StaticHost, Zone


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
_ents = frozenset()  # (zone name, relative empty-non-terminal name) precomputed at load time for O(1) RFC 4592 / 2308 checks
_off_sources = frozenset()  # sources whose master switch is off (Setting): 'manual' = Personal blocks, 'list' = Public lists; read at every reload
_regexes = ()  # enabled personal pattern entries: (compiled pattern, pattern text, allow)
_blocked_lock = threading.Lock()
_blocked = {}  # name -> (blacklist entry, where it came from) or None; emptied when the data changes
_NONE = ''  # a name that is not blocked, as stored in Redis (a missing key means "not asked yet")


def _shared():
    return bool(settings.REDIS_URL)


def _build():
    """The data as plain values (these are what Redis stores): ([zone names], {(zone, name): [(type, value, ttl)]}, {host: [(address, ttl)]})."""
    zones = [z.name for z in Zone.objects.filter(enabled=True)]
    recs = defaultdict(list)
    for zone, name, rtype, value, ttl in Record.objects.filter(enabled=True, zone__enabled=True).values_list('zone__name', 'name', 'type', 'value', 'ttl'):
        recs[(zone, name)].append((rtype, value, ttl))
    hosts = defaultdict(list)
    for name, address, ttl in StaticHost.objects.filter(enabled=True).values_list('name', 'address', 'ttl'):
        hosts[name].append((address, ttl))
    return zones, dict(recs), dict(hosts)


def _load():
    global _data, _data_at, _data_version, _ents, _off_sources, _regexes
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
    _ents = frozenset((z, '.'.join(pts[i:])) for z, n in by_name if '.' in n for pts in (n.split('.'),) for i in range(1, len(pts)))
    _data, _data_at, _data_version = (sorted(names, key=len, reverse=True), by_name, hosts), time.monotonic(), version
    st = dict(Setting.objects.filter(key__in=[PERSONAL_BLOCKS, PUBLIC_LISTS]).values_list('key', 'value'))  # one query for the switches
    _off_sources = frozenset(s for s, key in (('manual', PERSONAL_BLOCKS), ('list', PUBLIC_LISTS)) if st.get(key) == 'false')
    _regexes = () if 'manual' in _off_sources else _load_regexes()
    with _blocked_lock:
        _blocked.clear()


def _live(qs):
    """Entries that have not expired. shortcut: expiry is looked at when the data is (re)loaded and per name, so a temporary entry ends up to DNS_DATA_TTL late."""
    return qs.filter(Q(expires__isnull=True) | Q(expires__gt=timezone.now()))


def _load_regexes():
    out = []
    for name, allow in _live(BlockedDomain.objects.filter(enabled=True, regex=True)).values_list('name', 'allow'):
        try:
            out.append((re.compile(name, re.IGNORECASE), name, allow))
        except re.error:
            pass  # the API refuses a bad pattern; one that got in anyway just does nothing
    return tuple(out)


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
    if not reply.rr:  # NODATA: the SOA lets clients cache it (RFC 2308)
        name = str(request.q.qname).rstrip('.').lower()
        reply.add_auth(soa((authority(name) or (name,))[0]))
    return reply


def _closest_wildcard(zname, rel, by_name):
    """RFC 4592 §3.3.1: walk suffixes of rel from most specific to zone apex; stop if a suffix exists as a node or empty non-terminal."""
    if (zname, rel) in _ents:
        return []  # rel itself is an empty non-terminal
    labels = rel.split('.')
    for i in range(1, len(labels)):
        sub = '.'.join(labels[i:])
        recs = by_name.get((zname, f'*.{sub}'), [])
        if recs:
            return recs
        if (zname, sub) in by_name or (zname, sub) in _ents:
            return []  # closest encloser is sub, and *.sub does not exist
    return by_name.get((zname, '*'), [])


def has_zone_node(qname):
    """True when qname is an explicit record node or empty non-terminal inside the longest matching internal zone."""
    q = qname.rstrip('.').lower()
    zones, by_name, _ = _snapshot()
    for zname in zones:
        if q == zname or q.endswith('.' + zname):
            rel = '@' if q == zname else q[: -len(zname) - 1]
            return rel == '@' or (zname, rel) in by_name or (zname, rel) in _ents
    return False


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
                recs = _closest_wildcard(zname, rel, by_name)
                wild = bool(recs)
            if not recs:
                return None  # zone is ours but name unknown: ask upstream
            hit = recs if qtype == 'ANY' else ([r for r in recs if r.type == qtype] or [r for r in recs if r.type == 'CNAME'])
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
            if rel == '@' or (zname, rel) in by_name or _closest_wildcard(zname, rel, by_name):
                return zname, True
            # empty non-terminal: a.b.zone exists, so b.zone exists (without data)
            return zname, (zname, rel) in _ents
    return None


# RFC 6303: reverse zones of addresses that mean nothing outside the local network. Nobody else can answer for them, so they are never sent upstream.
# resolver.arpa (RFC 9462, discovery of encrypted DNS) is the same: only the resolver the client talks to can answer, and this one offers none, so the answer is negative.
_LOCAL_REVERSE = frozenset(
    ['resolver.arpa', '10.in-addr.arpa', '168.192.in-addr.arpa', '254.169.in-addr.arpa', '127.in-addr.arpa', '0.in-addr.arpa', '255.255.255.255.in-addr.arpa']
    + [f'{n}.172.in-addr.arpa' for n in range(16, 32)]  # 172.16.0.0/12
    + [f'{n}.100.in-addr.arpa' for n in range(64, 128)]  # 100.64.0.0/10 (RFC 6598)
    + ['1.' + '0.' * 31 + 'ip6.arpa', '0.' * 32 + 'ip6.arpa', 'd.f.ip6.arpa', 'c.f.ip6.arpa', '8.e.f.ip6.arpa', '9.e.f.ip6.arpa', 'a.e.f.ip6.arpa', 'b.e.f.ip6.arpa'])  # ::1, ::, fc00::/7, fe80::/10


def local_reverse(qname):
    """The RFC 6303 zone qname is in (a private or special address), or None."""
    labels = qname.rstrip('.').lower().split('.')
    return next((z for z in ('.'.join(labels[i:]) for i in range(len(labels))) if z in _LOCAL_REVERSE), None)


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


def blocked_entry(qname):
    """(blacklist entry, where it came from) that covers qname, or None. Domain entries cover the name and its subdomains and the most specific wins;
    an allow entry (exception) beats a block. A pattern entry is tried last for a block, first for an allow. Remembered per name until the data changes."""
    qname = qname.rstrip('.').lower()
    _snapshot()  # notices a change and empties _blocked
    with _blocked_lock:
        if qname in _blocked:
            return _blocked[qname]
    if _shared():
        try:
            stored = cache.get(f'bl:{_data_version}:{qname}')
            parts = stored.split('\t', 1) if stored else []
            if stored is not None and (not stored or len(parts) == 2):  # an entry without the tab is the old name-only format: ask the database
                hit = tuple(parts) or None
                with _blocked_lock:
                    _blocked[qname] = hit
                return hit
        except Exception:
            pass
    labels = qname.split('.')
    suffixes = ['.'.join(labels[i:]) for i in range(len(labels))]
    found = _live(BlockedDomain.objects.filter(enabled=True, regex=False, name__in=suffixes))
    if _off_sources:
        found = found.exclude(source__in=_off_sources)  # a feature that is switched off blocks nothing
    top = max(found, key=lambda b: len(b.name), default=None)  # the most specific entry wins: an allowed host inside a blocked domain, and the reverse
    pats = [(p, allow) for rx, p, allow in _regexes if rx.search(qname)]
    if any(allow for _, allow in pats) or (top and top.allow):
        hit = None
    elif top:
        hit = (top.name, 'personal' if top.source == 'manual' else top.list_name or 'list')
    elif pats:
        hit = (qname, f'pattern {pats[0][0]}')  # the name asked for, not the pattern: it becomes the owner of the SOA of the answer
    else:
        hit = None
    with _blocked_lock:
        if len(_blocked) > 20000:  # bounded: names that were asked once are the bulk
            _blocked.clear()
        _blocked[qname] = hit
    if _shared():
        try:
            cache.set(f'bl:{_data_version}:{qname}', '\t'.join(hit) if hit else _NONE, settings.DNS_DATA_TTL)
        except Exception:
            pass
    return hit


def blocked_match(qname):
    """The blacklist entry that covers qname, or None."""
    hit = blocked_entry(qname)
    return hit[0] if hit else None


def cname_blocked(reply):
    """(target, blacklist entry, where it came from) of the first CNAME in the answer that points at a blocked name, else None: a tracker hidden behind a
    subdomain of the site (CNAME cloaking) is only seen in the answer, never in the name that was asked."""
    for rr in reply.rr:
        if rr.rtype == QTYPE.CNAME:
            target = str(rr.rdata.label).rstrip('.').lower()
            if hit := blocked_entry(target):
                return target, *hit
    return None


def blocked_reply(request, zone):
    """NXDOMAIN for a blocked name: not authoritative, with an SOA so clients can cache it (RFC 2308)."""
    reply = request.reply(aa=0)
    reply.header.rcode = RCODE.NXDOMAIN
    reply.add_auth(soa(zone, ttl=settings.DNS_CACHE_NEG_TTL))
    return reply


def early_error(request):
    """FORMERR / NOTIMP / REFUSED for what is not one ordinary IN query (RFC 1035 §4.1.1, RFC 5625 §4.1), else None."""
    if not request.header.qr and request.header.opcode == OPCODE.UPDATE:
        return None
    if request.header.qr or len(request.questions) != 1:
        return DNSRecord(DNSHeader(id=request.header.id, qr=1, opcode=request.header.opcode, rcode=RCODE.FORMERR))
    opt = edns_option(request)
    if opt and ((opt.ttl >> 16) & 0xFF) != 0:  # RFC 6891 §6.1.3: unsupported EDNS version -> BADVERS (16 = (1 << 4) | 0)
        reply = request.reply(aa=0)
        reply.header.rcode = 0
        edns = EDNS0(udp_len=1232)
        edns.ttl = 1 << 24
        reply.add_ar(edns)
        return reply
    rcode = RCODE.NOTIMP if request.header.opcode != OPCODE.QUERY else RCODE.REFUSED if request.q.qclass != 1 else None
    if rcode is None:
        return None
    reply = request.reply(aa=0)
    reply.header.rcode = rcode
    return reply


def edns_option(request):
    return next((rr for rr in request.ar if rr.rtype == QTYPE.OPT), None)


def finish(request, reply, handler):
    """Answer EDNS with an OPT (RFC 6891) and cut a UDP answer that does not fit: TC=1 makes the client retry over TCP (RFC 1035 §4.2.1)."""
    opt = edns_option(request)
    do_bit = bool(opt and (opt.ttl & 0x8000))
    if not do_bit and request.questions and request.q.qtype not in (QTYPE.RRSIG, QTYPE.ANY):
        reply.rr = [rr for rr in reply.rr if rr.rtype != QTYPE.RRSIG]
    reply.ar = [rr for rr in reply.ar if rr.rtype != QTYPE.OPT]
    if opt:
        reply.add_ar(EDNS0(udp_len=1232, flags='do' if do_bit else ''))
    if getattr(handler, 'protocol', 'tcp') == 'udp' and len(reply.pack()) > (max(512, min(opt.rclass, 1232)) if opt else 512):
        reply = reply.truncate()
        if opt:
            reply.add_ar(EDNS0(udp_len=1232, flags='do' if do_bit else ''))
    return reply


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
        if (bad := early_error(request)) is not None:
            return bad
        connection.close_if_health_check_failed()  # a connection the database dropped while idle is replaced before use
        if request.header.opcode == OPCODE.UPDATE:
            try:
                return ddns.handle_update(request, handler.client_address[0])
            finally:
                connection.close_if_unusable_or_obsolete()
        t0 = time.monotonic()
        qname, qtype = str(request.q.qname).rstrip('.').lower(), QTYPE[request.q.qtype]
        try:
            if ratelimit.exceeded(handler.client_address[0]):
                outcome, reply, via = 'blocked', request.reply(aa=0), 'rate limit'
                reply.header.rcode = RCODE.REFUSED
            else:
                hosts = static_hosts(qname)
                found = None if hosts else lookup(qname, qtype)
                leased = not hosts and (not found or found[1]) and not has_zone_node(qname) and dhcp.lease_hosts(qname)  # a DHCP client that called itself <name>.<DHCP_DOMAIN>
                if leased:
                    hosts, found = leased, None
                if hosts:
                    outcome, reply, via = 'local', static_reply(request, qtype, hosts), 'DHCP lease' if leased else 'static host'
                elif found is not None:
                    recs, wild = found
                    outcome, reply = 'local', request.reply()
                    via = f'zone {recs[0].zone.name}' + (f' (wildcard {recs[0].name})' if wild else '')
                    reply.header.aa = 1
                    for r in recs:
                        for rr in r.to_rr(owner=qname if wild else None):
                            reply.add_answer(rr)
                    # A CNAME to a name in our own zones: add the target's records too, so the client gets an address
                    target, hops, seen_cnames = recs, 0, {qname}
                    while qtype != 'CNAME' and target[0].type == 'CNAME' and hops < 8:
                        nxt = str(target[0].to_rr()[0].rdata.label).rstrip('.').lower()
                        if nxt in seen_cnames:
                            break
                        seen_cnames.add(nxt)
                        more = lookup(nxt, qtype)
                        if not more:
                            if sh := static_hosts(nxt):
                                want, rdata = {'A': (4, A), 'AAAA': (6, AAAA)}.get(qtype, (None, None))
                                added = False
                                for address, ttl in sh:
                                    if want and (':' in address) == (want == 6):
                                        reply.add_answer(RR(nxt, request.q.qtype, rdata=rdata(address), ttl=ttl))
                                        added = True
                                if not added:
                                    reply.add_auth(soa((authority(nxt) or (nxt,))[0]))
                            elif settings.DNS_AUTHORITATIVE and (auth := authority(nxt)):
                                if not auth[1]:
                                    reply.header.rcode = RCODE.NXDOMAIN
                                reply.add_auth(soa(auth[0]))
                            break
                        target, hops = more[0], hops + 1
                        for r in target:
                            for rr in r.to_rr(owner=nxt if more[1] else None):
                                reply.add_answer(rr)
                elif settings.DNS_DDR and ddr.is_ours(settings.DNS_DDR, qname):  # before the zones: _dns.<adn> may sit inside one
                    outcome, via = 'local', 'DDR (RFC 9462 / 9463)'
                    if qtype in ('SVCB', 'ANY'):
                        reply = request.reply()
                        reply.header.aa = 1
                        for rr in ddr.answers(settings.DNS_DDR, qname):
                            reply.add_answer(rr)
                    else:
                        reply = negative(request, 'resolver.arpa' if qname.endswith('.resolver.arpa') else qname, False)
                elif qtype == 'PTR' and (ptr := dhcp.lease_ptr(qname)):  # the reverse name of a DHCP client that has a name
                    outcome, via, reply = 'local', 'DHCP lease', request.reply()
                    reply.header.aa = 1
                    reply.add_answer(RR(request.q.qname, QTYPE.PTR, rdata=PTR(ptr + '.'), ttl=60))
                elif settings.DNS_AUTHORITATIVE and (auth := authority(qname)):
                    outcome, via = 'local', f'zone {auth[0]} (no such {"record" if auth[1] else "name"})'
                    reply = negative(request, *auth)
                elif settings.DNS_LOCAL_REVERSE and (zone := local_reverse(qname)):
                    outcome, via = 'local', f'local-only zone {zone} (RFC 6303 / 9462)'
                    reply = negative(request, zone, qname == zone)
                elif (hit := blocked_entry(qname)):
                    outcome, reply, via = 'blocked', blocked_reply(request, hit[0]), f'blacklist {hit[0]} ({hit[1]})'
                elif (why := suspicious.check(qname, qtype, handler.client_address[0])) and settings.SUSPICIOUS_MODE == 'block':
                    outcome, reply, via = 'blocked', blocked_reply(request, qname), f'suspicious: {why}'
                else:
                    reply, via = self.forward(request)
                    if cloak := cname_blocked(reply):
                        outcome, reply, via = 'blocked', blocked_reply(request, cloak[1]), f'cname {cloak[0]} -> blacklist {cloak[1]} ({cloak[2]})'
                    else:
                        outcome = 'error' if reply.header.rcode == RCODE.SERVFAIL else 'forwarded'
                        if why:  # log-only mode
                            via += f' (suspicious: {why})'
            rcode, answers = summarize(reply)
            clean_name = qname.replace('\x00', '')[:253]
            entry = QueryLog(name=clean_name, domain=main_domain(clean_name)[:253], type=qtype[:10], outcome=outcome, client=handler.client_address[0],
                             ms=int((time.monotonic() - t0) * 1000), rcode=rcode[:16], via=via.replace('\x00', '')[:120], answers=answers)
            if self.log:
                self.log.add(entry)  # saved in a batch a moment later
            else:
                entry.save()
                rollup.add([entry])
            return finish(request, reply, handler)
        finally:
            connection.close_if_unusable_or_obsolete()  # the worker thread keeps its connection for the next query, unless it broke or is older than CONN_MAX_AGE

    def forward(self, request):
        """(reply, via). Answers are cached for their TTL; a cache failure (Redis down) just means asking upstream.
        A cached answer that is about to expire and is still being asked for is renewed in the background (DNS_PREFETCH).
        When every upstream is down an expired answer is served instead, if we still have one (DNS_STALE_TTL)."""
        opt = edns_option(request)  # EDNS, DO and CD change the answer, so they are part of the key
        key = f'dns:{QTYPE[request.q.qtype]}:{str(request.q.qname).lower()}:{int(bool(opt))}{(opt.ttl >> 15) & 1 if opt else 0}{request.header.cd}'
        if settings.DNS_CACHE:
            entry = self._cache_get(key)
            if entry:
                if isinstance(entry, (bytes, bytearray)):  # written by an older version: no expiry time stored
                    return self._parse(entry, request), 'cache'
                raw, expires, ttl = entry
                remaining = expires - time.time()
                reply = self._parse(raw, request)
                for section in (reply.rr, reply.auth, [r for r in reply.ar if r.rtype != QTYPE.OPT]):
                    for rr in section:
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
        self._prefetch_pool.submit(self._renew, key, request)

    def _renew(self, key, request):
        try:
            reply, used = self.ask_upstream(request)
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
        if reply.questions and request.questions:
            reply.q.qname = request.q.qname  # preserve client 0x20 bit-encoding case
        return reply

    @staticmethod
    def _upstream_addr(server):
        if server.startswith('[') and ']:' in server:
            host, _, p = server[1:].partition(']:')
            return host, int(p), True
        if server.count(':') == 1 and server.rpartition(':')[2].isdigit():
            host, _, p = server.rpartition(':')
            return host, int(p), False
        host = server.strip('[]')
        return host, 53, ':' in host

    def _fetch_dnskeys(self, zone_name):
        q = DNSRecord.question(zone_name, 'DNSKEY')
        q.add_ar(EDNS0(flags='do', udp_len=1232))
        rep, _ = self.ask_upstream(q, validate_dnssec=False)
        return [rr for rr in rep.rr if rr.rtype == QTYPE.DNSKEY]

    def ask_upstream(self, request, validate_dnssec=True):
        """(reply, upstream that answered) or (SERVFAIL reply, None). Tries the upstreams in order; one that failed is skipped for
        DNS_UPSTREAM_DOWN seconds so a dead server does not slow down every query. If all are marked down, all are tried anyway."""
        now = time.monotonic()
        order = [u for u in self.upstreams if self.down.get(u, 0) <= now] or self.upstreams
        orig_id = request.header.id
        want_dnssec = validate_dnssec and getattr(settings, 'DNS_DNSSEC', False)
        for server in order:
            try:
                host, port, v6 = self._upstream_addr(server)
                txid = secrets.randbits(16)
                out_req = DNSRecord.parse(request.pack())
                out_req.header.id = txid
                out_req.header.rd = 1
                if want_dnssec:
                    out_req.ar = [rr for rr in out_req.ar if rr.rtype != QTYPE.OPT]
                    out_req.add_ar(EDNS0(flags='do', udp_len=1232))
                reply = DNSRecord.parse(out_req.send(host, port, timeout=settings.DNS_UPSTREAM_TIMEOUT, ipv6=v6))
                if reply.header.tc:  # truncated: retry over TCP
                    txid = secrets.randbits(16)
                    out_req.header.id = txid
                    reply = DNSRecord.parse(out_req.send(host, port, tcp=True, timeout=settings.DNS_UPSTREAM_TIMEOUT, ipv6=v6))
                if reply.header.id != txid or not reply.header.qr or reply.q != request.q:
                    continue
                reply.header.id = orig_id
                if reply.header.rcode != RCODE.SERVFAIL:
                    if want_dnssec and not request.header.cd:
                        state = dnssec.validate_reply(reply, fetch_dnskeys=self._fetch_dnskeys)
                        if state == 'bogus':
                            bad = request.reply()
                            bad.header.rcode = RCODE.SERVFAIL
                            return bad, f'{server} (DNSSEC bogus)'
                        reply.header.ad = int(state == 'secure')
                    return reply, server
            except Exception:
                self.down[server] = time.monotonic() + settings.DNS_UPSTREAM_DOWN  # no answer at all; a SERVFAIL only moves on to the next
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply, None
