from django.core.exceptions import ValidationError
from django.db import models
from dnslib import RR, DNSLabel

from .zone import Zone

RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV', 'CAA', 'SSHFP', 'TLSA', 'NAPTR', 'HTTPS']


def build_rr(zone, name, rtype, value, ttl):
    """Parse one record. Relative names in value resolve against the zone; '@' means the zone apex."""
    fqdn = zone if name == '@' else f'{name}.{zone}'
    value = ' '.join(f'{zone}.' if t == '@' else t for t in value.split(' '))
    return RR.fromZone(f'{fqdn}. {ttl} IN {rtype} {value}', origin=zone)


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
        try:
            build_rr(self.zone.name, self.name, self.type, self.value, self.ttl or 0)
        except Exception as e:
            raise ValidationError({'value': f'Invalid RDATA: {e}'})

    def to_rr(self, owner=None):
        """owner overrides the name, used when a wildcard record answers for another name."""
        rrs = build_rr(self.zone.name, self.name, self.type, self.value, self.ttl)
        if owner:
            for rr in rrs:
                rr.rname = DNSLabel(owner)
        return rrs
