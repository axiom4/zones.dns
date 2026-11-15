"""Who made a network card: the vendor of a MAC address from its OUI (IEEE registry, as published in Wireshark's `manuf` file).

The table is in the database (MacVendor: prefixes of 24, 28 and 36 bits), so a lookup never leaves this machine. `manage.py update_oui` downloads
the registry and fills it; run it once after installing and every night from cron. Until then every vendor is unknown."""
import re

from django.db import transaction

from .models import MacVendor

LENGTHS = (9, 7, 6)  # the longest block wins: a 36-bit block is carved out of a 24-bit one


def parse_manuf(text):
    """The lines of a Wireshark manuf file as (prefix, vendor), prefix in hex of 6, 7 or 9 digits; comments and unusable lines are skipped."""
    out = {}
    for line in text.splitlines():
        cols = line.split('\t')
        if not line or line.startswith('#') or len(cols) < 2:
            continue
        mac, _, bits = cols[0].partition('/')
        digits = re.sub(r'[^0-9a-fA-F]', '', mac).upper()
        bits = int(bits) if bits.isdigit() else 24
        n = bits // 4
        if bits in (24, 28, 36) and len(digits) >= n:
            out[digits[:n]] = (cols[2] if len(cols) > 2 and cols[2].strip() else cols[1]).strip()[:255]
    return list(out.items())


def replace_table(rows):
    """Swap the whole table for `rows` [(prefix, vendor)] in one transaction: lookups see the old table or the new one, never half of each."""
    with transaction.atomic():
        MacVendor.objects.all().delete()
        MacVendor.objects.bulk_create([MacVendor(prefix=p, name=n) for p, n in rows], batch_size=5000)
    return len(rows)


def _hex(mac):
    h = re.sub(r'[^0-9a-fA-F]', '', str(mac)).upper()
    return h if len(h) == 12 else ''


def lookup_many(macs):
    """{mac as given: {'vendor': name or None, 'private': bool}} with one query. private: a locally administered address (bit 0x02 of the first byte),
    which is in no registry: phones and PCs use random ones per network."""
    hexes = {m: _hex(m) for m in macs}
    names = dict(MacVendor.objects.filter(prefix__in={h[:n] for h in hexes.values() if h for n in LENGTHS}).values_list('prefix', 'name'))
    out = {}
    for m, h in hexes.items():
        name = next((names[h[:n]] for n in LENGTHS if h and h[:n] in names), None)
        out[m] = {'vendor': name, 'private': bool(h and not name and int(h[:2], 16) & 2)}
    return out


def lookup(mac):
    return lookup_many([mac])[mac]


def label(r):
    """The text to show for a lookup result."""
    return r['vendor'] or ('Private (random address)' if r['private'] else '')


def vendor(mac):
    return label(lookup(mac))
