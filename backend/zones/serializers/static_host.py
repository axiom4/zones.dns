import ipaddress
import re

from rest_framework import serializers

from ..models import StaticHost

HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$')


class StaticHostSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticHost
        fields = ['id', 'name', 'address', 'ttl', 'enabled', 'note', 'created']
        validators = []  # (name, address) uniqueness is checked in validate() with a readable message

    def validate_name(self, v):
        v = v.strip().strip('.').lower()
        if not HOST_RE.match(v):
            raise serializers.ValidationError('Not a valid host name (letters, digits, - and _ in labels separated by dots; no wildcards).')
        return v

    def validate_address(self, v):
        return str(ipaddress.ip_address(v))  # canonical form: 2001:DB8::1 and 2001:db8:0::1 are the same row

    def validate(self, d):
        name, address = d.get('name', getattr(self.instance, 'name', None)), d.get('address', getattr(self.instance, 'address', None))
        dup = StaticHost.objects.filter(name=name, address=address)
        if self.instance:
            dup = dup.exclude(pk=self.instance.pk)
        if dup.exists():
            raise serializers.ValidationError({'address': f'{name} already has this address.'})
        return d
