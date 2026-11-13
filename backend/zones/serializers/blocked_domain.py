import re

from django.core.cache import cache
from rest_framework import serializers

from ..models import COUNTS_KEY, BlockedDomain
from .static_host import HOST_RE

# Nested quantifiers such as (a+)+, ((a+))+, ([a-z]*)*, repeated .*.*.*, or backreferences cause catastrophic backtracking on 253-char DNS names
_REDOS_RE = re.compile(r'\\[1-9]|(?:\.\*|\.\+){3,}')


def _has_redos(pat):
    if _REDOS_RE.search(pat):
        return True
    stack = []  # each open group stores whether it (or a nested group inside it) contains a quantifier
    i = 0
    while i < len(pat):
        ch = pat[i]
        if ch == '\\':
            i += 2
            continue
        if ch == '(':
            stack.append(False)
        elif ch == ')' and stack:
            had_q = stack.pop()
            rest = pat[i + 1:].lstrip()
            if had_q and rest and rest[0] in '+*?{':
                return True
            if stack and (had_q or (rest and rest[0] in '+*?{')):
                stack[-1] = True
        elif ch in '+*?{' and stack:
            stack[-1] = True
        i += 1
    return False


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = ['id', 'name', 'enabled', 'allow', 'regex', 'expires', 'created']
        extra_kwargs = {'name': {'validators': []}}  # uniqueness is checked below: a name that only sits in a public list is taken over

    def validate(self, d):
        regex = d.get('regex', getattr(self.instance, 'regex', False))
        name = d.get('name', getattr(self.instance, 'name', '')).strip()
        if not regex:
            name = name.strip('.').lower()
        if not name:
            raise serializers.ValidationError({'name': 'Empty name.'})
        if re.search(r'[\x00-\x1f\x7f]', name):
            raise serializers.ValidationError({'name': 'Control characters are not allowed.'})
        if regex:
            try:
                re.compile(name)
            except re.error as e:
                raise serializers.ValidationError({'name': f'Not a valid pattern: {e}'})
            if len(name) > 200:
                raise serializers.ValidationError({'name': 'Pattern too long (200 characters at most).'})
            if _has_redos(name):
                raise serializers.ValidationError({'name': 'Pattern contains nested repeats or backreferences that could slow DNS resolution.'})
        elif not HOST_RE.match(name):
            raise serializers.ValidationError({'name': 'Not a valid domain name (letters, digits, - and _ in labels separated by dots).'})
        if BlockedDomain.objects.filter(name=name, source='manual').exclude(pk=getattr(self.instance, 'pk', None)).exists():
            raise serializers.ValidationError({'name': 'This domain is already in the list.'})
        if 'name' in d or not self.instance:
            d['name'] = name
        return d

    def validate_name(self, v):
        v = v.strip()
        if not v:
            raise serializers.ValidationError('Empty name.')
        return v

    def save(self, **kw):
        # the same name in a public list gives way to the personal entry (the next import skips it)
        name = self.validated_data.get('name')
        regex = self.validated_data.get('regex', getattr(self.instance, 'regex', False))
        if name and not regex and BlockedDomain.objects.filter(name=name, source='list').delete()[0]:
            try:
                cache.delete(COUNTS_KEY)
            except Exception:
                pass
        return super().save(**kw)


class PersonalSwitchSerializer(serializers.Serializer):
    enabled = serializers.BooleanField()


class PublicListSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField()


class ImportedBlockedSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    names = serializers.ListField(child=serializers.CharField())
