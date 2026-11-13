"""Local GeoIP lookups from MaxMind-format databases (.mmdb). Everything stays on this machine."""
import os
import threading
from datetime import datetime, timezone

import maxminddb
from django.conf import settings

from . import asnindex


class _Db:
    """One or more database files (comma separated in the setting: some publishers ship IPv4 and IPv6 apart).
    Each is reopened by itself when the file is replaced, since they are updated monthly."""

    def __init__(self, setting):
        self.setting, self.readers, self.lock = setting, {}, threading.Lock()  # path -> (mtime, reader)

    def paths(self):
        return [p.strip() for p in getattr(settings, self.setting).split(',') if p.strip()]

    def get(self):
        out = []
        for path in self.paths():
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            cur = self.readers.get(path)
            if cur is None or cur[0] != mtime:
                with self.lock:
                    try:
                        cur = self.readers[path] = (mtime, maxminddb.open_database(path))
                    except (OSError, maxminddb.InvalidDatabaseError, ValueError):
                        continue
            out.append((path, cur[1]))
        return out

    def record(self, ip):
        for _, r in self.get():
            try:
                rec = r.get(ip)
            except ValueError:  # e.g. an IPv6 address in an IPv4-only file: try the next one
                continue
            if rec:
                return rec
        return {}


_city, _asn = _Db('GEOIP_CITY_DB'), _Db('GEOIP_ASN_DB')


def lookup(ip):
    """What the local databases know about ip: country, city, region, latitude, longitude, asn, as_name (missing keys = unknown)."""
    out = {}
    c = _city.record(ip)
    if 'country_code' in c:  # flat layout (e.g. sapics/ip-location-db): country_code, city, state1, latitude, longitude
        out.update(country=c.get('country_code') or '', city=c.get('city') or '', region=c.get('state1') or '',
                   latitude=c.get('latitude'), longitude=c.get('longitude'))
    elif c:  # GeoLite2 / DB-IP "compat" layout
        loc = c.get('location') or {}
        out.update(
            country=(c.get('country') or c.get('registered_country') or {}).get('iso_code') or '',
            city=((c.get('city') or {}).get('names') or {}).get('en') or '',
            region=(((c.get('subdivisions') or [{}])[0]).get('names') or {}).get('en') or '',
            latitude=loc.get('latitude'), longitude=loc.get('longitude'),
        )
    a = _asn.record(ip)
    if a.get('autonomous_system_number'):
        out.update(asn=f'AS{a["autonomous_system_number"]}', as_name=a.get('autonomous_system_organization') or '')
    elif x := asnindex.lookup(ip):  # not in the .mmdb: the index built by import_asn
        out.update(asn=f'AS{x[0]}', as_name=x[1])
    return out


def status():
    """Which databases are in use, for the UI."""
    def info(db):
        rs = db.get()
        if not rs:
            return None
        md = rs[0][1].metadata()
        return {'type': ' + '.join(dict.fromkeys(r.metadata().database_type for _, r in rs)),
                'built': datetime.fromtimestamp(md.build_epoch, timezone.utc).isoformat(), 'file': ', '.join(os.path.basename(p) for p, _ in rs)}
    return {'city': info(_city), 'asn': info(_asn), 'configured_city': bool(settings.GEOIP_CITY_DB), 'configured_asn': bool(settings.GEOIP_ASN_DB),
            'online_fallback': settings.GEOIP_ONLINE_FALLBACK}
