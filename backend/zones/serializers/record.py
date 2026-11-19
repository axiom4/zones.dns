import ipaddress

from django.db import transaction
from rest_framework import serializers

from ..models import CNAME_ALONE, Record, Zone, build_rr, cname_conflict, lock_zone
from ..dnsd.reverse import find_reverse_zone


def make_ptr(rec):
    """Create (or update) the reverse PTR for an A/AAAA record. Missing reverse zones are created on demand: /24 for IPv4, /64 for IPv6."""
    ptr = ipaddress.ip_address(rec.value.strip()).reverse_pointer
    zone = find_reverse_zone(ptr)
    if zone is None:
        zone = Zone.objects.create(name=ptr.split('.', 16 if ':' in rec.value else 1)[-1])
    lock_zone(zone)
    Record.objects.update_or_create(
        zone=zone, name=ptr[: -len(zone.name) - 1], type='PTR', value=f'{rec.fqdn}.',
        defaults={'ttl': rec.ttl},
    )


class RecordSerializer(serializers.ModelSerializer):
    create_ptr = serializers.BooleanField(write_only=True, default=False, help_text='Create the reverse PTR (A/AAAA only)')

    class Meta:
        model = Record
        fields = ['id', 'zone', 'name', 'type', 'value', 'ttl', 'enabled', 'note', 'create_ptr']

    def validate_name(self, v):
        return v.strip().strip('.').lower() or '@'

    def validate_note(self, v):
        return (v or '').replace('\r', ' ').replace('\n', ' ')

    def validate(self, d):
        # Round-trip through the same parser the daemon uses, so bad RDATA is rejected here.
        get = lambda k: d.get(k, getattr(self.instance, k, None))
        if d.get('create_ptr') and get('type') not in ('A', 'AAAA'):
            raise serializers.ValidationError({'create_ptr': 'The automatic PTR only applies to A and AAAA records.'})
        try:
            build_rr(get('zone').name, get('name'), get('type'), get('value'), get('ttl') or 0)
        except Exception:
            raise serializers.ValidationError({'value': f"Invalid RDATA for a {get('type')} record: check the format of the value."})
        self._conflicts(get('zone'), get('name'), get('type'), get('value'), getattr(self.instance, 'pk', None))
        return d

    @staticmethod
    def _conflicts(zone, name, rtype, value, pk):
        if Record.objects.filter(zone=zone, name=name, type=rtype, value=value).exclude(pk=pk).exists():
            raise serializers.ValidationError({'value': 'This record already exists.'})
        if cname_conflict(zone, name, rtype, pk):  # the daemon would answer only one of the two
            raise serializers.ValidationError({'type': CNAME_ALONE})

    def create(self, d):
        ptr = d.pop('create_ptr', False)
        with transaction.atomic():
            lock_zone(d['zone'])
            self._conflicts(d['zone'], d['name'], d['type'], d['value'], None)  # again, now that no other writer can slip in
            rec = super().create(d)
            if ptr:
                make_ptr(rec)
        return rec

    def update(self, instance, d):
        d.pop('create_ptr', None)  # only on create
        with transaction.atomic():
            lock_zone(instance.zone)
            self._conflicts(instance.zone, d.get('name', instance.name), d.get('type', instance.type), d.get('value', instance.value), instance.pk)
            return super().update(instance, d)
