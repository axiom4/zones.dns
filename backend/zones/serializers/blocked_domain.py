import re

from rest_framework import serializers

from ..models import BlockedDomain


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = ['id', 'name', 'enabled', 'allow', 'regex', 'expires', 'created']
        extra_kwargs = {'name': {'validators': []}}  # uniqueness is checked below: a name that only sits in a public list is taken over

    def validate(self, d):
        regex = d.get('regex', getattr(self.instance, 'regex', False))
        name = d.get('name', getattr(self.instance, 'name', ''))
        if regex:  # shortcut: a pattern with nested repeats can be slow; the name is at most 253 characters, and only staff can add one
            try:
                re.compile(name)
            except re.error as e:
                raise serializers.ValidationError({'name': f'Not a valid pattern: {e}'})
            if len(name) > 200:
                raise serializers.ValidationError({'name': 'Pattern too long (200 characters at most).'})
        return d

    def validate_name(self, v):
        v = v.strip()
        if not self.initial_data.get('regex', getattr(self.instance, 'regex', False)):
            v = v.strip('.').lower()
        if not v:
            raise serializers.ValidationError('Nome vuoto.')
        if BlockedDomain.objects.filter(name=v, source='manual').exclude(pk=getattr(self.instance, 'pk', None)).exists():
            raise serializers.ValidationError('This domain is already in the list.')
        return v

    def save(self, **kw):
        # the same name in a public list gives way to the personal entry (the next import skips it)
        BlockedDomain.objects.filter(name=self.validated_data.get('name'), source='list').delete()
        return super().save(**kw)


class PersonalSwitchSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()


class PublicListSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField()
    enabled = serializers.BooleanField()


class PublicListSwitchSerializer(serializers.Serializer):
    name = serializers.CharField()
    enabled = serializers.BooleanField()


class ImportedBlockedSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    names = serializers.ListField(child=serializers.CharField())
