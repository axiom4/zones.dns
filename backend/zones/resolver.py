import time

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import BaseResolver

from .domains import main_domain
from . import suspicious
from .models import BlockedDomain, QueryLog, Record, Zone


def lookup(qname, qtype):
    """Return (records, via_wildcard) from the longest matching internal zone, or None to ask upstream.

    Exact name wins; otherwise the closest wildcard (a.b.zone -> *.b.zone, then *.zone).
    """
    q = qname.rstrip('.').lower()
    for z in sorted(Zone.objects.all(), key=lambda z: -len(z.name)):
        if q == z.name or q.endswith('.' + z.name):
            rel = '@' if q == z.name else q[: -len(z.name) - 1]
            recs, wild = list(Record.objects.filter(zone=z, name=rel, enabled=True)), False
            if not recs and rel != '@':
                labels = rel.split('.')
                cands = [f'*.{".".join(labels[i:])}' for i in range(1, len(labels))] + ['*']
                found = list(Record.objects.filter(zone=z, name__in=cands, enabled=True))
                for c in cands:  # most specific first
                    recs = [r for r in found if r.name == c]
                    if recs:
                        wild = True
                        break
            if not recs:
                return None  # zone is ours but name unknown: ask upstream
            hit = [r for r in recs if r.type == qtype] or [r for r in recs if r.type == 'CNAME']
            return (hit, wild) if hit else None  # no record of this type: ask upstream too
    return None


def blocked_match(qname):
    """The blacklist entry that covers qname (itself or a parent), or None."""
    labels = qname.rstrip('.').lower().split('.')
    suffixes = ['.'.join(labels[i:]) for i in range(len(labels))]
    hit = BlockedDomain.objects.filter(name__in=suffixes).order_by('-name').first()
    return hit.name if hit else None


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
    def __init__(self, upstream):
        self.upstream = upstream  # as given, for messages
        self.upstreams = [u.strip() for u in upstream.split(',') if u.strip()]
        self.down = {}  # upstream -> monotonic time until which it is skipped

    def resolve(self, request, handler):
        t0 = time.monotonic()
        qname, qtype = str(request.q.qname).rstrip('.').lower(), QTYPE[request.q.qtype]
        try:
            found = lookup(qname, qtype)
            if found is not None:
                recs, wild = found
                outcome, reply = 'local', request.reply()
                via = f'zone {recs[0].zone.name}' + (f' (wildcard {recs[0].name})' if wild else '')
                reply.header.aa = 1
                for r in recs:
                    for rr in r.to_rr(owner=qname if wild else None):
                        reply.add_answer(rr)
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
            QueryLog.objects.create(name=qname, domain=main_domain(qname), type=qtype, outcome=outcome, client=handler.client_address[0],
                                    ms=int((time.monotonic() - t0) * 1000), rcode=rcode, via=via, answers=answers)
            return reply
        finally:
            connection.close()  # one thread per request; don't leak DB connections

    def forward(self, request):
        """(reply, via). Answers are cached for their TTL; a cache failure (Redis down) just means asking upstream.
        When every upstream is down an expired answer is served instead, if we still have one (DNS_STALE_TTL)."""
        key = f'dns:{QTYPE[request.q.qtype]}:{str(request.q.qname).lower()}'
        if settings.DNS_CACHE:
            raw = self._cache_get(key)
            if raw:
                return self._parse(raw, request), 'cache'
        reply, used = self.ask_upstream(request)
        if used is None:  # nobody answered
            raw = settings.DNS_CACHE and settings.DNS_STALE_TTL and self._cache_get('stale:' + key)
            if raw:
                reply = self._parse(raw, request)
                for rr in reply.rr:
                    rr.ttl = min(rr.ttl, 30)  # clients must ask again soon
                return reply, 'stale cache (upstream down)'
            return reply, f'upstream {self.upstream} (no answer)'
        if settings.DNS_CACHE and reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN) and not reply.header.tc:
            # shortcut: cached TTLs are not counted down, so a client may see a record live up to 2x its TTL (capped by DNS_CACHE_MAX_TTL)
            ttl = min([rr.ttl for rr in reply.rr] or [settings.DNS_CACHE_NEG_TTL])
            ttl = min(ttl, settings.DNS_CACHE_MAX_TTL) if reply.rr else min(ttl, settings.DNS_CACHE_NEG_TTL)
            if ttl > 0:
                try:
                    raw = reply.pack()
                    cache.set(key, raw, ttl)
                    if settings.DNS_STALE_TTL:
                        cache.set('stale:' + key, raw, settings.DNS_STALE_TTL)
                except Exception:
                    pass  # cache down: the answer was still delivered, just not stored
        return reply, f'upstream {used}'

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
