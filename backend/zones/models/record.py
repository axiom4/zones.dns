import re

from django.core.exceptions import ValidationError
from django.db import models
from dnslib import QTYPE, RR, DNSLabel

from .zone import Zone

RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV', 'CAA', 'SSHFP', 'TLSA', 'NAPTR', 'HTTPS']


def build_rr(zone, name, rtype, value, ttl):
    """Parse one record. Relative names in value resolve against the zone; '@' means the zone apex."""
    if any(c in f'{name}{value}' for c in '\r\n') or any(c.isspace() for c in name):
        raise ValueError('newline or whitespace in record')
    fqdn = zone if name == '@' else f'{name}.{zone}'
    parts = value.split('"')
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r'(?:^|(?<=\s))@(?=\s|$)', f'{zone}.', parts[i])
    expanded = '"'.join(parts)
    rrs = RR.fromZone(f'{fqdn}. {ttl} IN {rtype} {expanded}', origin=zone)
    if len(rrs) != 1 or QTYPE[rrs[0].rtype] != rtype or str(rrs[0].rname).rstrip('.').lower() != fqdn.lower():
        raise ValueError('unexpected record parsed from RDATA')
    return rrs


class Record(models.Model):
    zone = models.ForeignKey(Zone, on_delete=models.CASCADE, related_name='records')
    name = models.CharField(max_length=253, default='@')  # relative to zone, '@' = apex
    type = models.CharField(max_length=10, choices=[(t, t) for t in RECORD_TYPES])
    value = models.CharField(max_length=1024)  # zone-file RDATA, e.g. "10 mail.example.lan."
    ttl = models.PositiveIntegerField(default=300)
    enabled = models.BooleanField(default=True)  # disabled records are kept but never served
    note = models.CharField(max_length=255, blank=True)

    @property
    def fqdn(self):
        return self.zone.name if self.name == '@' else f'{self.name}.{self.zone.name}'

    def clean(self):
        # Same RDATA check as the API serializer, so the Django admin can't store a record the daemon can't serve.
        self.name = (self.name or '@').strip().strip('.').lower() or '@'
        self.note = (self.note or '').replace('\r', ' ').replace('\n', ' ')
        try:
            build_rr(self.zone.name, self.name, self.type, self.value, self.ttl or 0)
        except Exception as e:
            raise ValidationError({'value': f'Invalid RDATA: {e}'})

    def to_rr(self, owner=None):
        """owner overrides the name, used when a wildcard record answers for another name."""
        key = (self.zone.name, self.name, self.type, self.value, self.ttl)
        if getattr(self, '_rr_key', None) != key:
            self._rr_cache = tuple(build_rr(*key))
            self._rr_key = key
        if owner:
            lbl = DNSLabel(owner)
            return [RR(lbl, rr.rtype, rr.rclass, rr.ttl, rr.rdata) for rr in self._rr_cache]
        return list(self._rr_cache)
