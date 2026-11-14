"""Where do the answers point? Country and network of the IPs that DNS answers contained.

Source: Team Cymru's IP-to-ASN DNS service (country, ASN, network): country-level accuracy, no data leaves except
DNS queries through the configured upstream. Results are cached in IpGeo (30 days, unknown ones retried after 1 day).
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.db import connection
from django.utils import timezone

from . import geoip
from .audit import asn_info, is_public
from ..models import IpGeo

FRESH_KNOWN = timedelta(days=30)
FRESH_UNKNOWN = timedelta(days=1)


BLANK = {'private': False, 'country': '', 'asn': None, 'as_name': None, 'prefix': None, 'city': None, 'region': None, 'latitude': None, 'longitude': None, 'source': 'none'}


def locate(ips, budget=150):
    """Return ({ip: info}, pending). The local GeoIP databases answer first (instant, offline). What they lack (the network,
    or everything when none is configured) is asked to Team Cymru's DNS service and cached; at most `budget` such lookups per call."""
    ips = list(dict.fromkeys(ips))
    out = {ip: {**BLANK, 'ip': ip, 'private': True, 'source': 'private'} for ip in ips if not is_public(ip)}
    public = [ip for ip in ips if ip not in out]
    local = {ip: geoip.lookup(ip) for ip in public}
    # the DNS fallback is needed when the local data lacks the country or the network
    need = [ip for ip in public if settings.GEOIP_ONLINE_FALLBACK and not (local[ip].get('country') and local[ip].get('asn'))]
    cached = {g.ip: g for i in range(0, len(need), 5000) for g in IpGeo.objects.filter(ip__in=need[i:i + 5000])}  # chunks: SQLite caps the parameters of one query
    now, todo = timezone.now(), []
    for ip in need:
        g = cached.get(ip)
        if not (g and now - g.updated < (FRESH_KNOWN if g.country else FRESH_UNKNOWN)):
            todo.append(ip)
    batch = todo[:budget]
    if batch:
        with ThreadPoolExecutor(12) as ex:  # network only; the database is written from this thread
            infos = list(ex.map(asn_info, batch))
        rows = []
        for ip, info in zip(batch, infos):
            info = info or {}
            rows.append(IpGeo(ip=ip, country=(info.get('country') or '')[:2].upper(), asn=info.get('asn') or '', as_name=(info.get('as_name') or '')[:200], prefix=info.get('prefix') or ''))
        IpGeo.objects.bulk_create(rows, update_conflicts=True, unique_fields=['ip'] if connection.features.supports_update_conflicts_with_target else None, update_fields=['country', 'asn', 'as_name', 'prefix', 'updated'])  # one round trip, not two per address
        cached.update({g.ip: g for g in rows})
    skipped = set(todo[budget:])
    for ip in public:
        if ip in skipped and not local[ip].get('country'):
            continue  # over budget and no local country: not located yet
        loc, g = local[ip], cached.get(ip)
        country = loc.get('country') or (g.country if g else '')
        out[ip] = {
            **BLANK, 'ip': ip, 'country': country, 'asn': loc.get('asn') or (g.asn if g else '') or None, 'as_name': loc.get('as_name') or (g.as_name if g else '') or None,
            'prefix': (g.prefix if g else '') or None, 'city': loc.get('city') or None, 'region': loc.get('region') or None,
            'latitude': loc.get('latitude'), 'longitude': loc.get('longitude'),
            'source': 'local' if loc.get('country') else ('cymru' if country else 'none'),
        }
    return out, len(todo) - len(batch)


def country_domains(code, hours):
    """Registrable domains that had an answer pointing to country `code` (PRIV = private addresses, ?? = unknown) in the last `hours`.
    Same data as the geolocation page. shortcut: a domain also answered from other countries is listed whole; at most 5000 domains (the most
    asked), and the list is remembered COUNTRY_TTL seconds: the live log asks for it at every refresh."""
    from django.core.cache import cache
    from django.db.models import Sum
    from ..models import GeoStat
    from .rollup import floor_hour
    key = f'geo-country-domains:{code}:{hours}'
    try:
        if (hit := cache.get(key)) is not None:
            return hit
    except Exception:
        pass
    rows = GeoStat.objects.filter(hour__gte=floor_hour(timezone.now() - timedelta(hours=hours))).values_list('domain', 'ip').annotate(n=Sum('n'))
    pairs = {(d, ip): n for d, ip, n in rows}
    found, _ = locate({ip for _, ip in pairs}, budget=0)  # only what is already known: no network lookups while listing the log
    want = lambda g: (g['private'] if code == 'PRIV' else not g['private'] and (g['country'] or '??') == code)
    asked = Counter()
    for (d, ip), n in pairs.items():
        if d and ip in found and want(found[ip]):
            asked[d] += n
    out = sorted(d for d, _ in asked.most_common(5000))
    try:
        cache.set(key, out, COUNTRY_TTL)
    except Exception:
        pass
    return out


COUNTRY_TTL = 60


def destinations(rows):
    """Aggregate answered A/AAAA addresses by country and network. rows: (domain, ip, queries that had ip, queries that had it first).
    A query is counted once, at its first address, so the countries and networks add up to the total. Counters written before GeoStat.first
    existed have first = 0: then every address of an answer counts (manage.py rebuild_stats fills first)."""
    rows = list(rows)
    by_first = any(f for *_, f in rows)
    per_ip = {}
    for domain, ip, n, f in rows:
        d = per_ip.setdefault(ip, {'q': 0, 'domains': Counter()})
        w = f if by_first else n
        d['q'] += w
        if domain:
            d['domains'][domain] += w  # a domain with no query first here still counts as one of the country's domains (weight 0)
    ranked = sorted(per_ip.items(), key=lambda kv: -kv[1]['q'])  # no cap: a cap hid the rare countries, so a longer period showed fewer
    geo, pending = locate([ip for ip, _ in ranked])
    countries, networks, points = {}, {}, {}
    for ip, d in ranked:
        g = geo.get(ip)
        if g is None:  # not located yet (over budget)
            continue
        code = 'PRIV' if g['private'] else (g['country'] or '??')
        c = countries.setdefault(code, {'country': code, 'queries': 0, 'ips': 0, 'domains': Counter(), 'asns': set(), 'cities': Counter()})
        c['queries'] += d['q']; c['ips'] += 1; c['domains'].update(d['domains'])
        if g['city']:
            c['cities'][g['city']] += d['q']
        if g['latitude'] is not None and g['longitude'] is not None:  # one map point per ~11 km cell
            p = points.setdefault((round(g['latitude'], 1), round(g['longitude'], 1)), {'latitude': round(g['latitude'], 2), 'longitude': round(g['longitude'], 2), 'city': g['city'] or '', 'country': code, 'queries': 0, 'ips': 0, 'domains': Counter()})
            p['queries'] += d['q']; p['ips'] += 1; p['domains'].update(d['domains'])
        if g['asn']:
            c['asns'].add(g['asn'])
            n = networks.setdefault(g['asn'], {'asn': g['asn'], 'as_name': g['as_name'], 'country': g['country'], 'queries': 0, 'ips': 0})
            n['queries'] += d['q']; n['ips'] += 1
    by_country = sorted(({**c, 'domains': len(c['domains']), 'top_domains': [n for n, _ in c['domains'].most_common(6)], 'asns': sorted(c['asns'])[:6], 'cities': [n for n, _ in c['cities'].most_common(6)]} for c in countries.values()), key=lambda c: -c['queries'])
    return {
        'scanned': sum(d['q'] for d in per_ip.values()), 'ips_total': len(per_ip), 'ips_located': sum(c['ips'] for c in countries.values()), 'pending': pending,
        'countries': by_country, 'networks': sorted(networks.values(), key=lambda n: -n['queries'])[:15],
        'points': sorted(({**p, 'domains': [n for n, _ in p['domains'].most_common(4)]} for p in points.values()), key=lambda p: -p['queries'])[:1000],
        'geoip': geoip.status(),
    }
