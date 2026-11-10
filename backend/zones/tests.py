from types import SimpleNamespace

from dnslib import DNSQuestion, DNSRecord, QTYPE
from django.test import TestCase

from . import resolver
from .models import Record, Zone
from .resolver import Resolver


class CnameChaseTests(TestCase):
    def setUp(self):
        resolver._data = None  # the daemon's in-memory copy must not leak between tests

    def ask(self, name):
        handler = SimpleNamespace(client_address=('127.0.0.1', 0))
        return Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question(name, 'A'), handler)

    def test_cname_to_apex_also_returns_the_address(self):
        z = Zone.objects.create(name='axiom4.net')
        Record.objects.create(zone=z, name='@', type='A', value='192.168.1.240')
        Record.objects.create(zone=z, name='www', type='CNAME', value='@')
        reply = self.ask('www.axiom4.net')
        self.assertEqual([(QTYPE[r.rtype], str(r.rdata)) for r in reply.rr],
                         [('CNAME', 'axiom4.net.'), ('A', '192.168.1.240')])


class AuthoritativeTests(TestCase):
    def ask(self, name, qtype='A'):
        handler = SimpleNamespace(client_address=('127.0.0.1', 0))
        return Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question(name, qtype), handler)

    def setUp(self):
        resolver._data = None
        z = Zone.objects.create(name='lan')
        Record.objects.create(zone=z, name='host', type='A', value='10.0.0.1')
        Record.objects.create(zone=z, name='a.b', type='A', value='10.0.0.2')

    def test_missing_type_is_nodata_with_soa(self):
        r = self.ask('host.lan', 'AAAA')
        self.assertEqual((r.header.rcode, r.header.aa, len(r.rr)), (0, 1, 0))
        self.assertEqual([QTYPE[a.rtype] for a in r.auth], ['SOA'])

    def test_missing_name_is_nxdomain_with_soa(self):
        r = self.ask('nope.lan')
        self.assertEqual((r.header.rcode, r.header.aa), (3, 1))
        self.assertEqual([QTYPE[a.rtype] for a in r.auth], ['SOA'])

    def test_empty_non_terminal_is_nodata(self):
        self.assertEqual(self.ask('b.lan').header.rcode, 0)

    def test_soa_query_at_apex(self):
        r = self.ask('lan', 'SOA')
        self.assertEqual([QTYPE[a.rtype] for a in r.rr], ['SOA'])

    def test_not_authoritative_forwards_missing_names(self):
        from django.test import override_settings
        with override_settings(DNS_AUTHORITATIVE=False):
            r = self.ask('nope.lan')  # upstream 127.0.0.1:9 is dead, so a forwarded query ends in SERVFAIL, not our NXDOMAIN
        self.assertEqual(r.header.rcode, 2)


class BlocklistEnabledTests(TestCase):
    def test_disabled_block_does_not_block(self):
        from .models import BlockedDomain
        from .resolver import blocked_match
        b = BlockedDomain.objects.create(name='ads.example.com')
        resolver._data = None
        self.assertEqual(blocked_match('x.ads.example.com'), 'ads.example.com')
        b.enabled = False
        b.save()  # signals bump the data version, which empties the memory copy
        resolver._blocked.clear()
        self.assertIsNone(blocked_match('x.ads.example.com'))

    def test_allow_wins_over_a_longer_domain_block_and_the_longest_entry_wins(self):
        from .models import BlockedDomain
        from .resolver import blocked_match
        BlockedDomain.objects.create(name='tracker.example', source='list')
        BlockedDomain.objects.create(name='cdn.tracker.example', allow=True)
        BlockedDomain.objects.create(name='bad.cdn.tracker.example')
        resolver._data = None
        self.assertEqual(blocked_match('x.tracker.example'), 'tracker.example')
        self.assertIsNone(blocked_match('a.cdn.tracker.example'))  # allowed host inside a blocked domain
        self.assertEqual(blocked_match('bad.cdn.tracker.example'), 'bad.cdn.tracker.example')  # but a longer block wins again

    def test_personal_entry_takes_over_a_public_list_name_through_the_api(self):
        from django.contrib.auth.models import User
        from rest_framework.test import APIClient

        from .models import BlockedDomain
        BlockedDomain.objects.create(name='ads.example', source='list')
        c = APIClient()
        c.force_authenticate(User.objects.create_user('u', is_staff=True, is_superuser=True))
        r = c.post('/api/blocked/', {'name': 'ADS.example', 'allow': True}, format='json')
        self.assertEqual((r.status_code, r.data['allow']), (201, True))
        self.assertEqual(list(BlockedDomain.objects.filter(name='ads.example').values_list('source', 'allow')), [('manual', True)])
        self.assertEqual(c.post('/api/blocked/', {'name': 'ads.example'}, format='json').status_code, 400)  # already in the personal list

    def test_pattern_entries_block_and_allow(self):
        from .models import BlockedDomain
        from .resolver import blocked_entry
        BlockedDomain.objects.create(name=r'^ads?\d+\.', regex=True)
        BlockedDomain.objects.create(name=r'^ads9\.good\.example$', regex=True, allow=True)
        resolver._data = None
        self.assertEqual(blocked_entry('ads3.site.example'), ('ads3.site.example', r'pattern ^ads?\d+\.'))
        self.assertIsNone(blocked_entry('ads9.good.example'))
        self.assertIsNone(blocked_entry('www.site.example'))

    def test_expired_entry_is_ignored_and_a_list_can_be_switched_off(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import LISTS_OFF, BlockedDomain, Setting
        from .resolver import blocked_entry
        BlockedDomain.objects.create(name='old.example', expires=timezone.now() - timedelta(hours=1))
        BlockedDomain.objects.create(name='soon.example', expires=timezone.now() + timedelta(hours=1))
        BlockedDomain.objects.create(name='a.example', source='list', list_name='hagezi-tif')
        resolver._data = None
        self.assertIsNone(blocked_entry('old.example'))
        self.assertEqual(blocked_entry('soon.example'), ('soon.example', 'personal'))
        self.assertEqual(blocked_entry('a.example'), ('a.example', 'hagezi-tif'))
        Setting.objects.create(key=LISTS_OFF, value='hagezi-tif')
        resolver._data = None
        self.assertIsNone(blocked_entry('a.example'))

    def test_lists_endpoint_counts_and_switches(self):
        from django.contrib.auth.models import User
        from rest_framework.test import APIClient

        from .models import BlockedDomain
        BlockedDomain.objects.create(name='a.example', source='list', list_name='one')
        BlockedDomain.objects.create(name='b.example', source='list', list_name='one')
        BlockedDomain.objects.create(name='c.example', source='list', list_name='two')
        c = APIClient()
        c.force_authenticate(User.objects.create_user('u3', is_staff=True, is_superuser=True))
        r = c.patch('/api/blocked/lists/', {'name': 'two', 'enabled': False}, format='json')
        self.assertEqual(r.data, [{'name': 'one', 'count': 2, 'enabled': True}, {'name': 'two', 'count': 1, 'enabled': False}])
        self.assertEqual(c.post('/api/blocked/', {'name': '(', 'regex': True}, format='json').status_code, 400)  # not a valid pattern

    def test_suggestions_list_tracker_looking_names_only(self):
        from django.contrib.auth.models import User
        from django.utils import timezone
        from rest_framework.test import APIClient

        from .models import BlockedDomain, StatCount
        from .rollup import floor_hour
        h = floor_hour(timezone.now())
        for name, n in (('track.site.example', 9), ('www.site.example', 50), ('ads.listed.example', 5), ('pixel.fine.example', 4)):
            StatCount.objects.create(dim='name', hour=h, key=name, n=n)
        BlockedDomain.objects.create(name='listed.example', source='list')
        BlockedDomain.objects.create(name='fine.example', allow=True)
        resolver._data = None
        c = APIClient()
        c.force_authenticate(User.objects.create_user('u2', is_staff=True, is_superuser=True))
        self.assertEqual(c.get('/api/blocked/suggestions/').data, [{'name': 'track.site.example', 'count': 9}])

    def test_master_switch_off_ignores_personal_blocks_only(self):
        from .models import PERSONAL_BLOCKS, BlockedDomain, Setting
        from .resolver import blocked_match
        BlockedDomain.objects.create(name='mine.example')
        BlockedDomain.objects.create(name='listed.example', source='list')
        Setting.set_flag(PERSONAL_BLOCKS, False)
        resolver._data = None
        self.assertIsNone(blocked_match('mine.example'))
        self.assertEqual(blocked_match('listed.example'), 'listed.example')
        Setting.set_flag(PERSONAL_BLOCKS, True)
        resolver._data = None
        self.assertEqual(blocked_match('mine.example'), 'mine.example')

    def test_master_switch_off_ignores_public_lists_only(self):
        from .models import PUBLIC_LISTS, BlockedDomain, Setting
        from .resolver import blocked_match
        BlockedDomain.objects.create(name='mine.example')
        BlockedDomain.objects.create(name='listed.example', source='list')
        Setting.set_flag(PUBLIC_LISTS, False)
        resolver._data = None
        self.assertIsNone(blocked_match('listed.example'))
        self.assertEqual(blocked_match('mine.example'), 'mine.example')


class ZoneEnabledTests(TestCase):
    def test_disabled_zone_is_not_served(self):
        z = Zone.objects.create(name='off.lan')
        Record.objects.create(zone=z, name='h', type='A', value='10.0.0.9')
        resolver._data = None
        self.assertIsNotNone(resolver.lookup('h.off.lan', 'A'))
        z.enabled = False
        z.save()
        resolver._data = None
        self.assertIsNone(resolver.lookup('h.off.lan', 'A'))
        self.assertIsNone(resolver.authority('nope.off.lan'))  # no NXDOMAIN from a zone that is off: the name is forwarded


class ZoneDeleteMfaTests(TestCase):
    def setUp(self):
        import time
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        from . import mfa
        from .models import TotpDevice
        self.mfa, self.time = mfa, time
        self.user = get_user_model().objects.create_user('u', password='x', is_staff=True)
        self.api = APIClient()
        self.api.force_authenticate(self.user)
        self.zone = Zone.objects.create(name='del.lan')
        resolver._data = None
        self.TotpDevice = TotpDevice

    def totp(self):
        dev = self.TotpDevice.objects.create(user=self.user, secret=self.mfa.new_secret(), confirmed=True)
        return lambda: self.mfa.totp_code(dev.secret, int(self.time.time() // 30))

    def test_no_factor_set_up_deletes_without_grant(self):
        self.assertEqual(self.api.delete(f'/api/zones/{self.zone.pk}/').status_code, 204)

    def test_with_a_factor_a_grant_is_needed_and_works_once(self):
        from django.test import override_settings
        code = self.totp()
        self.assertEqual(self.api.delete(f'/api/zones/{self.zone.pk}/').status_code, 403)
        with override_settings(LOGIN_ENCRYPTION='off'):
            r = self.api.post('/api/mfa/stepup/totp/', {'code': code(), 'scope': f'zone-delete:{self.zone.pk}'}, format='json')
        self.assertEqual(r.status_code, 200)
        grant = r.json()['grant']
        other = Zone.objects.create(name='other.lan')
        self.assertEqual(self.api.delete(f'/api/zones/{other.pk}/', HTTP_X_MFA_GRANT=grant).status_code, 403)  # grant is for another zone
        self.assertEqual(self.api.delete(f'/api/zones/{self.zone.pk}/', HTTP_X_MFA_GRANT=grant).status_code, 204)
        again = Zone.objects.create(name='del.lan')
        self.assertEqual(self.api.delete(f'/api/zones/{again.pk}/', HTTP_X_MFA_GRANT=grant).status_code, 403)  # used once

    def test_wrong_code_gives_no_grant(self):
        from django.test import override_settings
        self.totp()
        with override_settings(LOGIN_ENCRYPTION='off'):
            r = self.api.post('/api/mfa/stepup/totp/', {'code': '000000', 'scope': f'zone-delete:{self.zone.pk}'}, format='json')
        self.assertEqual(r.status_code, 400)


class LocalReverseTests(TestCase):
    def ask(self, name, qtype='PTR'):
        handler = SimpleNamespace(client_address=('127.0.0.1', 0))
        return Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question(name, qtype), handler)

    def setUp(self):
        resolver._data = None

    def test_private_ptr_without_zone_is_nxdomain_not_forwarded(self):
        for name in ('229.1.168.192.in-addr.arpa', '5.0.0.10.in-addr.arpa', '9.20.16.172.in-addr.arpa', '1.' + '0.' * 31 + 'd.f.ip6.arpa'):
            r = self.ask(name)
            self.assertEqual((r.header.rcode, r.header.aa), (3, 1), name)
            self.assertEqual([QTYPE[a.rtype] for a in r.auth], ['SOA'])

    def test_public_ptr_is_still_forwarded(self):
        self.assertEqual(self.ask('8.8.8.8.in-addr.arpa').header.rcode, 2)  # dead upstream: SERVFAIL

    def test_172_outside_the_private_range_is_forwarded(self):
        self.assertEqual(self.ask('9.20.15.172.in-addr.arpa').header.rcode, 2)  # 172.15.x is public

    def test_a_local_reverse_zone_still_answers_first(self):
        z = Zone.objects.create(name='1.168.192.in-addr.arpa')
        Record.objects.create(zone=z, name='229', type='PTR', value='nas.lan.')
        r = self.ask('229.1.168.192.in-addr.arpa')
        self.assertEqual([str(a.rdata) for a in r.rr], ['nas.lan.'])

    def test_switch_off_forwards(self):
        from django.test import override_settings
        with override_settings(DNS_LOCAL_REVERSE=False):
            self.assertEqual(self.ask('229.1.168.192.in-addr.arpa').header.rcode, 2)


class PartitionPlanTests(TestCase):
    def test_plan(self):
        from datetime import date
        from .partitions import _num, plan
        today = date(2026, 11, 9)
        parts = [('pold', _num(date(2026, 11, 2))), ('p20261102', _num(date(2026, 11, 3))), ('p20261109', _num(date(2026, 11, 10))), ('pmax', None)]
        drop, add = plan(parts, today, date(2026, 11, 2), ahead=2)
        self.assertEqual(drop, ['pold'])
        self.assertEqual([n for n, _ in add], ['p20261110', 'p20261111'])
        self.assertEqual(add[0][1], date(2026, 11, 11))


class SessionExpiryTests(TestCase):
    def test_token_expires(self):
        from datetime import timedelta
        from django.contrib.auth import get_user_model
        from django.utils import timezone
        from rest_framework.authtoken.models import Token
        from rest_framework.test import APIClient
        u = get_user_model().objects.create_user('s', password='x', is_staff=True)
        t = Token.objects.create(user=u)
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f'Token {t.key}')
        self.assertEqual(c.get('/api/zones/').status_code, 200)
        Token.objects.filter(pk=t.pk).update(created=timezone.now() - timedelta(hours=3))
        self.assertEqual(c.get('/api/zones/').status_code, 401)


class AsnIndexTests(TestCase):
    def test_flatten_and_lookup(self):
        import io, os, tarfile, tempfile
        from django.test import override_settings
        from . import asnindex
        # 10.0.0.0/8 is AS1, the 10.1.0.0/16 inside it is AS2
        self.assertEqual(asnindex.flatten([(10 << 24, (11 << 24) - 1, 1), (10 << 24 | 1 << 16, 10 << 24 | (2 << 16) - 1, 2)]),
                         [(10 << 24, (10 << 24 | 1 << 16) - 1, 1), (10 << 24 | 1 << 16, 10 << 24 | (2 << 16) - 1, 2), (10 << 24 | 2 << 16, (11 << 24) - 1, 1)])
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as t:
            for name, text in [('as/1/ipv4-aggregated.txt', '# AS1 (ONE)\n# One Net\n10.0.0.0/8\n'), ('as/2/ipv4-aggregated.txt', '# AS2 (TWO)\n# Two Net\n10.1.0.0/16\n'),
                               ('as/3/ipv6-aggregated.txt', '# AS3 (THREE)\n# Three Net\n2001:db8::/32\n')]:
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        buf.seek(0)
        v4, v6, names = asnindex.read_archive(buf)
        with tempfile.TemporaryDirectory() as d, override_settings(ASN_INDEX=os.path.join(d, 'i.bin')):
            asnindex.write(os.path.join(d, 'i.bin'), v4, v6, names)
            self.assertEqual(asnindex.lookup('10.1.2.3'), (2, 'Two Net'))
            self.assertEqual(asnindex.lookup('10.9.9.9'), (1, 'One Net'))
            self.assertEqual(asnindex.lookup('2001:db8::1'), (3, 'Three Net'))
            self.assertIsNone(asnindex.lookup('11.0.0.1'))
            self.assertIsNone(asnindex.lookup('2001:db9::1'))


class RfcConformanceTests(TestCase):
    def setUp(self):
        resolver._data = None
        z = Zone.objects.create(name='lan')
        Record.objects.create(zone=z, name='a.b', type='A', value='10.0.0.2')
        Record.objects.create(zone=z, name='*', type='A', value='10.0.0.9')
        Record.objects.create(zone=z, name='big', type='TXT', value='x' * 250)
        Record.objects.create(zone=z, name='big', type='TXT', value='y' * 250)
        Record.objects.create(zone=z, name='big', type='TXT', value='z' * 250)

    def ask(self, q, proto='tcp'):
        handler = SimpleNamespace(client_address=('127.0.0.1', 0), protocol=proto)
        return Resolver('127.0.0.1:9', log=None).resolve(q, handler)

    def test_wildcard_does_not_cover_empty_non_terminal(self):
        self.assertEqual(len(self.ask(DNSRecord.question('b.lan', 'A')).rr), 0)  # b.lan exists (a.b.lan below it)
        self.assertEqual(len(self.ask(DNSRecord.question('other.lan', 'A')).rr), 1)

    def test_blocked_name_is_not_authoritative_and_has_soa(self):
        from .models import BlockedDomain
        BlockedDomain.objects.create(name='ads.example')
        resolver._data = None
        r = self.ask(DNSRecord.question('x.ads.example', 'A'))
        self.assertEqual((r.header.rcode, r.header.aa, [QTYPE[a.rtype] for a in r.auth]), (3, 0, ['SOA']))

    def test_cname_to_a_blocked_name_is_blocked(self):
        from unittest import mock

        from dnslib import CNAME, RR

        from .models import BlockedDomain
        BlockedDomain.objects.create(name='tracker.example')
        resolver._data = None
        q = DNSRecord.question('metrics.site.example', 'A')
        upstream = q.reply()
        upstream.add_answer(RR('metrics.site.example', QTYPE.CNAME, rdata=CNAME('eu.tracker.example'), ttl=60))
        with mock.patch.object(Resolver, 'forward', return_value=(upstream, 'upstream test')):
            r = self.ask(q)
        self.assertEqual((r.header.rcode, len(r.rr), [QTYPE[a.rtype] for a in r.auth]), (3, 0, ['SOA']))

    def test_static_host_nodata_has_soa(self):
        from .models import StaticHost
        StaticHost.objects.create(name='printer.lan', address='10.0.0.5')
        resolver._data = None
        r = self.ask(DNSRecord.question('printer.lan', 'AAAA'))
        self.assertEqual((len(r.rr), [QTYPE[a.rtype] for a in r.auth]), (0, ['SOA']))

    def test_edns_gets_an_opt_back(self):
        from dnslib import EDNS0
        q = DNSRecord.question('a.b.lan', 'A')
        q.add_ar(EDNS0(udp_len=4096))
        self.assertEqual([QTYPE[a.rtype] for a in self.ask(q).ar], ['OPT'])
        self.assertEqual(self.ask(DNSRecord.question('a.b.lan', 'A')).ar, [])

    def test_big_udp_answer_is_truncated_tcp_is_not(self):
        q = DNSRecord.question('big.lan', 'TXT')
        r = self.ask(q, 'udp')
        self.assertEqual((r.header.tc, len(r.rr)), (1, 0))
        self.assertEqual((self.ask(q, 'tcp').header.tc, len(self.ask(q, 'tcp').rr)), (0, 3))

    def test_notimp_and_refused_and_formerr(self):
        q = DNSRecord.question('a.b.lan', 'A')
        q.header.opcode = 4  # NOTIFY
        self.assertEqual(self.ask(q).header.rcode, 4)
        self.assertEqual(self.ask(DNSRecord(q=DNSQuestion('a.b.lan', 1, 3))).header.rcode, 5)  # class CH
        two = DNSRecord.question('a.lan')
        two.add_question(*DNSRecord.question('b.lan').questions)
        self.assertEqual(self.ask(two).header.rcode, 1)


class QueryLogClientsTests(TestCase):
    def test_distinct_clients_with_default_zone_names(self):
        from django.contrib.auth import get_user_model
        from django.test import override_settings
        from rest_framework.test import APIClient
        from datetime import datetime, timezone as tz
        from .models import StatCount
        z = Zone.objects.create(name='axiom4.net')
        Record.objects.create(zone=z, name='pc', type='A', value='192.168.1.10')
        Record.objects.create(zone=z, name='*', type='A', value='192.168.1.11')
        h = datetime(2026, 1, 1, tzinfo=tz.utc)
        for hour, key, n in [(h, '192.168.1.10', 5), (h.replace(hour=1), '192.168.1.10', 2), (h, '192.168.1.11', 9)]:
            StatCount.objects.create(dim='client', hour=hour, key=key, n=n)
        StatCount.objects.create(dim='type', hour=h, key='A', n=99)
        c = APIClient()
        c.force_authenticate(get_user_model().objects.create_user('u', password='x', is_staff=True))
        with override_settings(DEFAULT_ZONE='axiom4.net'):
            r = c.get('/api/logs/clients/')
        self.assertEqual(r.json(), [{'ip': '192.168.1.11', 'name': '', 'host': '', 'count': 9}, {'ip': '192.168.1.10', 'name': 'pc.axiom4.net', 'host': 'pc', 'count': 7}])


class WhoisTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        self.c = APIClient()
        self.c.force_authenticate(get_user_model().objects.create_user('w', password='x', is_staff=True))

    def test_private_and_bad_addresses_are_refused_without_a_lookup(self):
        from unittest import mock
        with mock.patch('zones.whois._ask') as ask:
            self.assertEqual(self.c.get('/api/geo/whois/?ip=192.168.1.1').status_code, 400)
            self.assertEqual(self.c.get('/api/geo/whois/?ip=nope').status_code, 400)
            ask.assert_not_called()

    def test_follows_only_a_known_registry(self):
        from unittest import mock
        from . import whois
        from django.core.cache import cache
        cache.clear()
        with mock.patch('zones.whois._ask', side_effect=['refer: whois.arin.net\n', 'NetName: GOOGLE\n']) as ask:
            self.assertEqual(whois.lookup('8.8.8.8'), ('whois.arin.net', 'NetName: GOOGLE\n'))
        cache.clear()
        with mock.patch('zones.whois._ask', return_value='refer: evil.example\n') as ask:
            self.assertEqual(whois.lookup('8.8.4.4')[0], 'whois.iana.org')
            self.assertEqual(ask.call_count, 1)
        cache.clear()
        with mock.patch('zones.whois._ask', side_effect=['refer: whois.ripe.net\n', 'inetnum: x\n']):
            r = self.c.get('/api/geo/whois/?ip=8.8.8.8')
        self.assertEqual((r.status_code, r.json()['server']), (200, 'whois.ripe.net'))


class RootGroupTests(TestCase):
    def test_root_name_is_a_group_called_dot_and_can_be_asked_for(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        from .models import QueryLog
        QueryLog.objects.create(name='', domain='', type='NS', outcome='forwarded', client='1.1.1.1', ms=1)
        QueryLog.objects.create(name='a.example.com', domain='example.com', type='A', outcome='forwarded', client='1.1.1.1', ms=1)
        c = APIClient()
        c.force_authenticate(get_user_model().objects.create_user('r', password='x', is_staff=True))
        names = [g['name'] for g in c.get('/api/logs/grouped/').json()['results']]
        self.assertIn('.', names)
        self.assertEqual(c.get('/api/logs/?domain=.').json()['count'], 1)  # not every query: '.' selects the root only


def paths_label(path):  # an unnamed source is named after its file (the first list that has a domain labels it, so a.example belongs to the first)
    from .management.commands.import_blocklist import split_source
    return split_source(path)[0]


class ImportBlocklistTests(TestCase):
    def test_several_lists_are_merged_and_manual_entries_kept(self):
        import os
        import tempfile

        from django.core.management import call_command

        from .models import BlockedDomain
        BlockedDomain.objects.create(name='mine.example')
        paths = []
        for text in ('0.0.0.0 a.example\n', 'b.example\na.example\n'):
            f = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False)
            f.write(text)
            f.close()
            paths.append(f.name)
        try:
            call_command('import_blocklist', *paths, stdout=open(os.devnull, 'w'))
        finally:
            for p in paths:
                os.unlink(p)
        self.assertEqual(sorted(BlockedDomain.objects.filter(source='list').values_list('name', 'list_name')), [('a.example', paths_label(paths[0])), ('b.example', paths_label(paths[1]))])
        self.assertTrue(BlockedDomain.objects.filter(name='mine.example', source='manual').exists())
