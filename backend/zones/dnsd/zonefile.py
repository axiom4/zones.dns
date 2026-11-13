"""BIND zone file export/import. Import is line based: no multi-line ( ) records, SOA is ignored."""
import re

from dnslib import QTYPE, RR

from ..models import RECORD_TYPES, Record


def export_zone(zone):
    lines = [
        f'$ORIGIN {zone.name}.', '$TTL 300',
        f'@ IN SOA ns.{zone.name}. hostmaster.{zone.name}. 1 3600 600 86400 300',
    ]
    for r in zone.records.order_by('name', 'type'):
        line = f'{r.name} {r.ttl} IN {r.type} {r.value}'
        if r.note:
            note = r.note.replace('\r', ' ').replace('\n', ' ')
            line += f' ; {note}'
        lines.append(line if r.enabled else f';{line}')  # disabled records stay as comments
    return '\n'.join(lines) + '\n'


def _expand_at(line, zone):
    """'@' in RDATA means the zone apex; dnslib doesn't expand it there. Leave quoted text alone."""
    parts = line.split('"')
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r'(?<=\s)@(?=\s|$)', f'{zone}.', parts[i])
    return '"'.join(parts)


def _strip_comment(line):
    inq = False
    for i, c in enumerate(line):
        if c == '"':
            inq = not inq
        elif c == ';' and not inq:
            return line[:i]
    return line


def parse_zone(zone_name, text):
    """Return (records, errors). records are dicts ready for Record(**d)."""
    out, errors, ttl, owner = [], [], 300, '@'
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if line.startswith('$TTL'):
            try:
                ttl = int(line.split()[1])
            except (IndexError, ValueError):
                errors.append(f'line {n}: invalid $TTL')
            continue
        if line.startswith('$'):
            continue  # $ORIGIN and others: the target zone always wins
        if line[0].isspace():
            line = f'{owner} {line.strip()}'
        else:
            owner = line.split()[0]
        try:
            rrs = RR.fromZone(f'$ORIGIN {zone_name}.\n$TTL {ttl}\n' + _expand_at(line, zone_name))
        except Exception:
            errors.append(f'line {n}: invalid record')
            continue
        for rr in rrs:
            rtype = QTYPE[rr.rtype]
            if rtype == 'SOA':
                continue
            name = str(rr.rname).rstrip('.').lower()
            if rtype not in RECORD_TYPES:
                errors.append(f'line {n}: type {rtype} not supported')
            elif name == zone_name:
                out.append(dict(name='@', type=rtype, value=rr.rdata.toZone(), ttl=rr.ttl))
            elif name.endswith('.' + zone_name):
                out.append(dict(name=name[: -len(zone_name) - 1], type=rtype, value=rr.rdata.toZone(), ttl=rr.ttl))
            else:
                errors.append(f'line {n}: {name} is outside the zone')
    return out, errors


def import_zone(zone, text, replace=False, dry_run=False):
    from django.db import transaction

    records, errors = parse_zone(zone.name, text)
    created = skipped = 0
    with transaction.atomic():
        if replace and not dry_run:
            zone.records.all().delete()
        seen = set() if replace else set(zone.records.values_list('name', 'type', 'value'))
        for d in records:
            key = (d['name'], d['type'], d['value'])
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            created += 1
            if not dry_run:
                Record.objects.create(zone=zone, **d)
    return {'created': created, 'skipped': skipped, 'errors': errors}
