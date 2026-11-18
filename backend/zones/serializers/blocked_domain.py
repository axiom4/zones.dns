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
    stack = []  # each open group: [it (or a group inside it) has a quantifier, it has an alternation]
    i, in_class = 0, False
    while i < len(pat):
        ch = pat[i]
        if ch == '\\':
            i += 2
            continue
        if in_class:
            in_class = ch != ']'
        elif ch == '[':
            in_class = True
        elif ch == '(':
            stack.append([False, False])
        elif ch == ')' and stack:
            had_q, had_alt = stack.pop()
            rest = pat[i + 1:].lstrip()
            repeated = bool(rest) and rest[0] in '+*{'
            if (had_q and rest and rest[0] in '+*?{') or (had_alt and repeated):
                return True  # (a+)+ nested repeats, or (a|aa)+ a repeated alternation whose branches can overlap
            if stack and (had_q or (rest and rest[0] in '+*?{')):
                stack[-1][0] = True
        elif ch == '|' and stack:
            stack[-1][1] = True
        elif ch in '+*?{' and stack:
            stack[-1][0] = True
        i += 1
    return False


def pattern_error(name):
    """Why a blacklist pattern is refused, or None. Also used by the Django admin, which saved patterns without these checks."""
    try:
        re.compile(name)
    except re.error as e:
        return f'Not a valid pattern: {e}'
    if len(name) > 200:
        return 'Pattern too long (200 characters at most).'
    if _has_redos(name) or _too_slow(name):
        return 'Pattern contains nested repeats, repeated alternations or backreferences that could slow DNS resolution.'
    return None


_PROBE = 'import re, sys\nrx = re.compile(sys.argv[1], re.IGNORECASE)\nfor s in sys.argv[2:]:\n    rx.search(s)\n'
PROBE_SECONDS = 2  # the whole trial, start of the interpreter included: a sound pattern takes a few hundredths


def _too_slow(pat):
    """True when the pattern takes too long on names made to hurt it. The check above reads the pattern and misses what is slow without
    nested repeats (a*a*a*a*a*b); this one tries it, in another process: Python cannot stop a search that has started, and in this one
    it would hold every thread. The names: each character of the pattern (and each pair) repeated to the longest DNS name, ending with
    a character that makes the match fail, which is when a pattern backtracks.
    shortcut: a trial, not a proof; a guarantee needs a linear-time engine (the re2 package) in the daemon."""
    import subprocess
    import sys
    chars = list(dict.fromkeys(c.lower() for c in pat if c.isalnum() or c in '-_.'))[:8] or ['a']
    names = [c * 252 + '!' for c in chars] + [(a + b) * 126 + '!' for a in chars[:4] for b in chars[:4] if a != b]
    try:
        subprocess.run([sys.executable, '-I', '-c', _PROBE, pat, *names], timeout=PROBE_SECONDS, capture_output=True)
    except subprocess.TimeoutExpired:
        return True
    except OSError:
        return False  # no process could be started: the pattern is judged by the check above alone
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
            if why := pattern_error(name):
                raise serializers.ValidationError({'name': why})
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
        # the same name in a public list gives way to the personal entry, a pattern too (name is unique; the next import skips it)
        name = self.validated_data.get('name')
        if name and BlockedDomain.objects.filter(name=name, source='list').delete()[0]:
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


class BlocklistSourceSerializer(serializers.Serializer):
    """One public list of Blacklist > Public lists and what the last import did with it."""
    name = serializers.CharField()
    url = serializers.CharField()
    domains = serializers.IntegerField(help_text='Domains it blocks now (imported entries labelled with this list)')
    synced = serializers.DateTimeField(allow_null=True, help_text='Last download that worked; null = never')
    tried = serializers.DateTimeField(allow_null=True, help_text='Last attempt')
    error = serializers.CharField(allow_blank=True, help_text='Why the last attempt failed (its old entries were kept); empty = it worked')
    in_use = serializers.BooleanField(help_text='Its domains are blocked now: it has entries and the Public lists switch is on')


class BlocklistSourcesSerializer(serializers.Serializer):
    text = serializers.CharField(allow_blank=True, max_length=200_000, help_text='The lists, `name=https://…` one per line. Saving it replaces them; the next import (nightly, or Sync now) applies it.')
    saved = serializers.BooleanField(read_only=True, help_text='false = nothing saved in the GUI yet: these are the BLOCKLISTS of .env')
    lists = BlocklistSourceSerializer(many=True, read_only=True)
    running = serializers.BooleanField(read_only=True, help_text='An import is running now')
    started = serializers.DateTimeField(read_only=True, allow_null=True)
    finished = serializers.DateTimeField(read_only=True, allow_null=True)
    error = serializers.CharField(read_only=True, help_text='The last run stopped with this error (not a single list: see lists[].error)')

    def validate(self, d):
        from ..blocklists import ListError, split_lists
        try:
            d['entries'] = split_lists(d['text'])
        except ListError as e:
            raise serializers.ValidationError({e.field: str(e)}) from None  # name / url / text: the input of the GUI it concerns
        return d
