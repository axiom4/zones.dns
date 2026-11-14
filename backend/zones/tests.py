from types import SimpleNamespace

from dnslib import DNSQuestion, DNSRecord, QTYPE
from django.test import TestCase, override_settings

from .dnsd import resolver
from .models import Record, Zone
from .dnsd.resolver import Resolver


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


@override_settings(DNS_AUTHORITATIVE=True)  # the tests do not depend on the .env of whoever runs them
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
        from .dnsd.resolver import blocked_match
        b = BlockedDomain.objects.create(name='ads.example.com')
        resolver._data = None
        self.assertEqual(blocked_match('x.ads.example.com'), 'ads.example.com')
        b.enabled = False
        b.save()  # signals bump the data version, which empties the memory copy
        resolver._blocked.clear()
        self.assertIsNone(blocked_match('x.ads.example.com'))

    def test_allow_wins_over_a_longer_domain_block_and_the_longest_entry_wins(self):
        from .models import BlockedDomain
        from .dnsd.resolver import blocked_match
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
        from .dnsd.resolver import blocked_entry
        BlockedDomain.objects.create(name=r'^ads?\d+\.', regex=True)
        BlockedDomain.objects.create(name=r'^ads9\.good\.example$', regex=True, allow=True)
        resolver._data = None
        self.assertEqual(blocked_entry('ads3.site.example'), ('ads3.site.example', r'pattern ^ads?\d+\.'))
        self.assertIsNone(blocked_entry('ads9.good.example'))
        self.assertIsNone(blocked_entry('www.site.example'))

    def test_expired_entry_is_ignored(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import BlockedDomain
        from .dnsd.resolver import blocked_entry
        BlockedDomain.objects.create(name='old.example', expires=timezone.now() - timedelta(hours=1))
        BlockedDomain.objects.create(name='soon.example', expires=timezone.now() + timedelta(hours=1))
        BlockedDomain.objects.create(name='a.example', source='list', list_name='hagezi-tif')
        resolver._data = None
        self.assertIsNone(blocked_entry('old.example'))
        self.assertEqual(blocked_entry('soon.example'), ('soon.example', 'personal'))
        self.assertEqual(blocked_entry('a.example'), ('a.example', 'hagezi-tif'))

    def test_lists_endpoint_counts(self):
        from django.contrib.auth.models import User
        from rest_framework.test import APIClient

        from .models import BlockedDomain
        BlockedDomain.objects.create(name='a.example', source='list', list_name='one')
        BlockedDomain.objects.create(name='b.example', source='list', list_name='one')
        BlockedDomain.objects.create(name='c.example', source='list', list_name='two')
        c = APIClient()
        c.force_authenticate(User.objects.create_user('u3', is_staff=True, is_superuser=True))
        self.assertEqual(c.get('/api/blocked/lists/').data, [{'name': 'one', 'count': 2}, {'name': 'two', 'count': 1}])
        self.assertEqual(c.post('/api/blocked/', {'name': '(', 'regex': True}, format='json').status_code, 400)  # not a valid pattern

    def test_suggestions_list_tracker_looking_names_only(self):
        from django.contrib.auth.models import User
        from django.utils import timezone
        from rest_framework.test import APIClient

        from .models import BlockedDomain, StatCount
        from .stats.rollup import floor_hour
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
        from .dnsd.resolver import blocked_match
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
        from .dnsd.resolver import blocked_match
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
        from .security import mfa
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

    def test_ddr_announces_the_encrypted_resolvers(self):
        from django.test import override_settings
        with override_settings(DNS_DDR='dot:dns.example.lan doh:dns.example.lan:8443/dns-query{?dns}'):
            r = self.ask('_dns.resolver.arpa', 'SVCB')
            self.assertEqual((r.header.rcode, r.header.aa, [a.rtype for a in r.rr]), (0, 1, [64, 64]))
            wire = DNSRecord.parse(r.pack())  # packs and parses back
            self.assertEqual(len(wire.rr), 2)
            self.assertEqual(r.rr[0].rdata.params[3], (853).to_bytes(2, 'big'))
            self.assertEqual(r.rr[1].rdata.params[7], b'/dns-query{?dns}')
            self.assertEqual(self.ask('_dns.resolver.arpa', 'A').header.rcode, 3)  # other types: negative, not forwarded
        self.assertEqual(self.ask('_dns.resolver.arpa', 'SVCB').header.rcode, 3)  # nothing configured

    def test_ddr_address_hints(self):
        from .dnsd.ddr import IPV4HINT, IPV6HINT, parse
        (_, host, params), = parse('dot:dns.example.lan@192.168.1.23,2001:db8::1')
        self.assertEqual((params[IPV4HINT], params[IPV6HINT][:2]), (bytes([192, 168, 1, 23]), b'\x20\x01'))
        with self.assertRaises(ValueError):
            parse('dot:h@nope')

    def test_dnr_options_have_consistent_lengths(self):
        from .dnsd.ddr import adn, dnr_ra, dnr_v4, dnr_v6, parse
        self.assertEqual(adn('doh1.example.com'), b'\x04doh1\x07example\x03com\x00')  # the RFC 9463 example, 18 octets
        e = parse('dot:dns.example.lan@192.168.1.23,2001:db8::1 doh:dns.example.lan/dns-query{?dns}@192.168.1.23')
        v4 = dnr_v4(e)
        n = int.from_bytes(v4[:2], 'big')  # first instance: its length covers priority, adn, addr length, addresses, svcparams
        inst = v4[2:2 + n]
        alen = inst[2]
        self.assertEqual(inst[3 + alen], 4)  # one IPv4 address
        self.assertEqual(inst[4 + alen:8 + alen], bytes([192, 168, 1, 23]))
        self.assertNotIn(b'\x00\x04\x00\x04', inst[8 + alen:])  # no ipv4hint left in the SvcParams
        self.assertEqual(len(dnr_v6(e)), 1)  # the DoH entry has no IPv6 address
        ra = dnr_ra(e)[0]
        self.assertEqual((ra[0], len(ra) % 8, ra[1] * 8), (144, 0, len(ra)))
        self.assertEqual(len(dnr_v4(parse('dot:dns.example.lan'))), 2 + 2 + 1 + len(adn('dns.example.lan')))  # ADN-only: priority, ADN length, ADN

    def test_adn_only_resolver_is_found_by_its_name(self):
        from django.test import override_settings
        with override_settings(DNS_DDR='dot:dns.example.lan'):
            r = self.ask('_dns.dns.example.lan', 'SVCB')
            self.assertEqual([a.rtype for a in r.rr], [64])
            self.assertEqual(str(r.rr[0].rname), '_dns.dns.example.lan.')

    def test_dnr_refuses_addresses_clients_discard_and_ra_has_adn_only_form(self):
        from .dnsd.ddr import dnr_ra, parse
        for bad in ('dot:h@224.0.0.1', 'dot:h@127.0.0.1', 'dot:h@::1', 'dot:h@0.0.0.0'):
            with self.assertRaises(ValueError, msg=bad):
                parse(bad)
        ra = dnr_ra(parse('dot:dns.example.lan'))[0]  # priority 2, lifetime 4, ADN length 2, ADN 17: type and length 2 + 2+4+2+17 = 27, padded to 32
        self.assertEqual((ra[0], ra[1], len(ra), ra[8:10]), (144, 4, 32, bytes([0, 17])))
        self.assertEqual(dnr_ra(parse('dot:dns.example.lan@192.168.1.23')), [])  # IPv4 only: not in an RA

    def test_ddr_refuses_a_bad_entry(self):
        from .dnsd.ddr import parse
        for bad in ('dot', 'dot:', 'dot:h/x', 'doh:h/dns-query', 'tls:h', 'dot:h:x'):
            with self.assertRaises(ValueError, msg=bad):
                parse(bad)

    def test_switch_off_forwards(self):
        from django.test import override_settings
        with override_settings(DNS_LOCAL_REVERSE=False):
            self.assertEqual(self.ask('229.1.168.192.in-addr.arpa').header.rcode, 2)


class PartitionPlanTests(TestCase):
    def test_plan(self):
        from datetime import date
        from .stats.partitions import _num, plan
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
        from .stats import asnindex
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


class QueryLogCountTests(TestCase):
    def test_count_comes_from_the_counters_and_matches_the_log(self):
        from datetime import timedelta
        from django.contrib.auth import get_user_model
        from django.utils import timezone
        from rest_framework.test import APIClient
        from .models import LogTotal, QueryLog
        from .stats import rollup
        now = timezone.now()
        rows = [QueryLog(time=now - timedelta(minutes=m), name='a.example', domain='example', type=t, outcome=o, client=c, ms=1)
                for m, t, o, c in [(5, 'A', 'local', '10.0.0.1'), (90, 'AAAA', 'blocked', '10.0.0.1'), (200, 'A', 'forwarded', '10.0.0.2'),
                                   (3000, 'A', 'forwarded', '10.0.0.2'), (100000, 'A', 'error', '10.0.0.3')]]
        QueryLog.objects.bulk_create(rows)
        rollup.add(rows)
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('u', password='x', is_staff=True))
        cases = [('', 5), ('hours=1', 1), ('hours=2', 2), ('hours=24', 3), ('hours=720', 4), ('type=A', 4), ('client=10.0.0.2', 2), ('outcome=forwarded&hours=24', 1),
                 ('type=aaaa', 1), ('q=a.example', 5)]  # the last one needs the log itself
        for query, expected in cases:
            with self.subTest(query):
                self.assertEqual(api.get('/api/logs/?limit=1&' + query).json()['count'], expected)
        from .views.query_log import stat_count
        self.assertEqual(stat_count({}), 5)
        self.assertIsNone(stat_count({'q': 'x'}))
        self.assertEqual(LogTotal.objects.get(dim='client', key='10.0.0.2').n, 2)
        rollup.purge(now - timedelta(hours=48))  # forgets the hours older than two days: 3 rows
        self.assertEqual(stat_count({}), 3)
        self.assertEqual(stat_count({'client': '10.0.0.3'}), 0)


class WhoisTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        self.c = APIClient()
        self.c.force_authenticate(get_user_model().objects.create_user('w', password='x', is_staff=True))

    def test_private_and_bad_addresses_are_refused_without_a_lookup(self):
        from unittest import mock
        with mock.patch('zones.stats.whois._ask') as ask:
            self.assertEqual(self.c.get('/api/geo/whois/?ip=192.168.1.1').status_code, 400)
            self.assertEqual(self.c.get('/api/geo/whois/?ip=nope').status_code, 400)
            ask.assert_not_called()

    def test_follows_only_a_known_registry(self):
        from unittest import mock
        from .stats import whois
        from django.core.cache import cache
        cache.clear()
        with mock.patch('zones.stats.whois._ask', side_effect=['refer: whois.arin.net\n', 'NetName: GOOGLE\n']) as ask:
            self.assertEqual(whois.lookup('8.8.8.8'), ('whois.arin.net', 'NetName: GOOGLE\n'))
        cache.clear()
        with mock.patch('zones.stats.whois._ask', return_value='refer: evil.example\n') as ask:
            self.assertEqual(whois.lookup('8.8.4.4')[0], 'whois.iana.org')
            self.assertEqual(ask.call_count, 1)
        cache.clear()
        with mock.patch('zones.stats.whois._ask', side_effect=['refer: whois.ripe.net\n', 'inetnum: x\n']):
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


class DohTests(TestCase):
    def test_doh_needs_the_switch_and_a_dns_message(self):
        import base64
        from unittest import mock

        from django.test import Client, override_settings
        c = Client()
        wire = bytes(DNSRecord.question('example.com', 'A').pack())
        q = base64.urlsafe_b64encode(wire).rstrip(b'=').decode()
        self.assertEqual(c.get('/dns-query', {'dns': q}).status_code, 404)  # off by default
        with override_settings(DNS_DOH=True), mock.patch('zones.views.doh._exchange', return_value=DNSRecord.parse(wire).reply().pack()) as ex:
            r = c.get('/dns-query', {'dns': q})
            self.assertEqual((r.status_code, r['Content-Type']), (200, 'application/dns-message'))
            self.assertEqual(c.post('/dns-query', wire, content_type='application/dns-message').status_code, 200)
            self.assertEqual(c.post('/dns-query', wire, content_type='text/plain').status_code, 415)
            self.assertEqual(c.post('/dns-query', b'x' * 40, content_type='application/dns-message').status_code, 400)  # not a DNS message
            self.assertEqual(ex.call_count, 2)


class DhcpTests(TestCase):
    def setUp(self):
        import ipaddress

        from .dhcp.v4 import Config, Server
        self.cfg = Config(ipaddress.IPv4Address('192.168.1.2'), ipaddress.IPv4Network('192.168.1.0/24'), ipaddress.IPv4Address('192.168.1.100'),
                          ipaddress.IPv4Address('192.168.1.102'), ipaddress.IPv4Address('192.168.1.1'), [ipaddress.IPv4Address('192.168.1.2')], 'lan', 3600,
                          {'aa:aa:aa:aa:aa:01': ipaddress.IPv4Address('192.168.1.50')}, b'')
        self.server = Server(self.cfg)  # no probe: the tests do not ping

    def packet(self, mac, kind, **opts):
        import struct
        head = struct.pack('!BBBBIHH4s4s4s4s', 1, 1, 6, 0, 7, 0, 0, bytes(opts.pop('ciaddr', b'\0\0\0\0')), b'\0' * 4, b'\0' * 4, b'\0' * 4)
        body = bytes.fromhex(mac.replace(':', '')).ljust(16, b'\0') + b'\0' * 192 + b'\x63\x82\x53\x63' + bytes([53, 1, kind])
        for code, v in opts.items():
            body += bytes([int(code[1:]), len(v)]) + v
        return head + body + b'\xff'

    def reply(self, mac, kind, **opts):
        from .dhcp.v4 import parse
        out = self.server.handle(self.packet(mac, kind, **opts))
        if not out:
            return None, None
        # a reply has op 2: read it with the request parser after flipping the op byte
        r = parse(b'\x01' + out[0][1:])
        r['yiaddr'] = str(__import__('ipaddress').IPv4Address(out[0][16:20]))
        return r, out[1]

    def test_offer_ack_and_next_client_gets_next_address(self):
        r, dest = self.reply('aa:aa:aa:aa:aa:10', 1)
        self.assertEqual((r['opts'][53], r['yiaddr'], dest), (b'\x02', '192.168.1.100', '255.255.255.255'))
        self.assertEqual(r['opts'][1], bytes([255, 255, 255, 0]))
        self.assertEqual(r['opts'][3], bytes([192, 168, 1, 1]))
        r, _ = self.reply('aa:aa:aa:aa:aa:10', 3, o50=bytes([192, 168, 1, 100]), o54=bytes([192, 168, 1, 2]))
        self.assertEqual((r['opts'][53], r['yiaddr']), (b'\x05', '192.168.1.100'))
        r, _ = self.reply('aa:aa:aa:aa:aa:11', 1)
        self.assertEqual(r['yiaddr'], '192.168.1.101')
        r, _ = self.reply('aa:aa:aa:aa:aa:10', 1)  # same client: same address
        self.assertEqual(r['yiaddr'], '192.168.1.100')

    def test_reservation_wins_and_the_pool_runs_out(self):
        r, _ = self.reply('aa:aa:aa:aa:aa:01', 1)
        self.assertEqual(r['yiaddr'], '192.168.1.50')
        for n in (10, 11, 12):
            self.assertIsNotNone(self.reply(f'aa:aa:aa:aa:aa:{n}', 1)[0])
        self.assertIsNone(self.reply('aa:aa:aa:aa:aa:13', 1)[0])  # 3 addresses in the range, all offered

    def test_wrong_request_is_nak_and_other_server_is_ignored(self):
        r, _ = self.reply('aa:aa:aa:aa:aa:20', 3, o50=bytes([10, 9, 9, 9]))
        self.assertEqual(r['opts'][53], b'\x06')
        self.assertIsNone(self.reply('aa:aa:aa:aa:aa:20', 3, o50=bytes([192, 168, 1, 100]), o54=bytes([192, 168, 1, 9]))[0])  # chose another server
        self.reply('aa:aa:aa:aa:aa:21', 3, o50=bytes([192, 168, 1, 100]))
        r, _ = self.reply('aa:aa:aa:aa:aa:22', 3, o50=bytes([192, 168, 1, 100]))  # taken by another client
        self.assertEqual(r['opts'][53], b'\x06')
        r, _ = self.reply('aa:aa:aa:aa:aa:50', 3, o50=bytes([192, 168, 1, 50]))  # reserved for another MAC
        self.assertEqual(r['opts'][53], b'\x06')

    def test_release_decline_and_inform(self):
        from .models import DhcpLease
        self.reply('aa:aa:aa:aa:aa:30', 3, o50=bytes([192, 168, 1, 101]))
        self.assertTrue(DhcpLease.objects.filter(ip='192.168.1.101').exists())
        self.reply('aa:aa:aa:aa:aa:30', 7, ciaddr=bytes([192, 168, 1, 101]))
        self.assertFalse(DhcpLease.objects.filter(ip='192.168.1.101').exists())
        self.reply('aa:aa:aa:aa:aa:31', 4, o50=bytes([192, 168, 1, 100]))  # declined: out of the pool for a while
        r, _ = self.reply('aa:aa:aa:aa:aa:32', 1)
        self.assertEqual(r['yiaddr'], '192.168.1.101')
        r, dest = self.reply('aa:aa:aa:aa:aa:33', 8, ciaddr=bytes([192, 168, 1, 77]))
        self.assertEqual((r['opts'][53], dest, 51 in r['opts']), (b'\x05', '192.168.1.77', False))

    def test_dnr_option_only_when_asked_and_config_is_checked(self):
        from types import SimpleNamespace as NS

        from .dhcp.v4 import Config, Server
        from .dnsd.ddr import dnr_v4, parse
        self.server = Server(Config(**{**self.cfg.__dict__, 'dnr': dnr_v4(parse('dot:dns.example.lan'))}))
        r, _ = self.reply('aa:aa:aa:aa:aa:40', 1, o55=bytes([1, 3, 162]))
        self.assertEqual(r['opts'][162], self.server.cfg.dnr)
        r, _ = self.reply('aa:aa:aa:aa:aa:41', 1, o55=bytes([1, 3]))
        self.assertNotIn(162, r['opts'])
        good = dict(DHCP_SERVER='192.168.1.2', DHCP_NETMASK='255.255.255.0', DHCP_RANGE='192.168.1.100-192.168.1.200', DHCP_ROUTER='', DHCP_DNS='', DHCP_DOMAIN='',
                    DHCP_LEASE=3600, DHCP_RESERVATIONS='AA-AA-AA-AA-AA-01=192.168.1.5', DHCP_DNR=True, DNS_DDR='', DHCP_NTP='', DHCP_ROUTES='', DHCP_SEARCH='',
                    DHCP_MTU=0, DHCP_BOOT_SERVER='', DHCP_BOOT_FILE='', DHCP_PROBE=False)
        self.assertEqual(Config.from_settings(NS(**good)).reservations, {'aa:aa:aa:aa:aa:01': __import__('ipaddress').IPv4Address('192.168.1.5')})
        for bad in ({'DHCP_RANGE': '192.168.2.1-192.168.2.9'}, {'DHCP_RANGE': '192.168.1.9-192.168.1.1'}, {'DHCP_SERVER': ''}, {'DHCP_LEASE': 5}, {'DHCP_RESERVATIONS': 'zz=1.1.1.1'}, {'DHCP_ROUTER': '10.0.0.1'}, {'DHCP_ROUTES': '10.0.0.0/8=172.16.0.1'}, {'DHCP_MTU': 20}, {'DHCP_NTP': 'x'}):
            with self.assertRaises(ValueError, msg=bad):
                Config.from_settings(NS(**{**good, **bad}))

    def test_client_identifier_names_the_client_and_options_follow_the_request_list(self):
        import ipaddress

        from .dhcp.v4 import Config, Server
        cfg = Config(**{**self.cfg.__dict__, 'ntp': [ipaddress.IPv4Address('192.168.1.3')], 'search': ['lan', 'corp.lan'], 'mtu': 1400,
                        'routes': [(ipaddress.IPv4Network('10.0.0.0/8'), ipaddress.IPv4Address('192.168.1.5'))], 'boot_server': 'tftp.lan', 'boot_file': 'pxe.0'})
        self.server = Server(cfg)
        cid = bytes([1, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x60])
        r, _ = self.reply('aa:aa:aa:aa:aa:60', 1, o61=cid, o55=bytes([1, 3, 42, 119, 121, 26, 66, 67]))
        o = r['opts']
        self.assertEqual(o[42], bytes([192, 168, 1, 3]))
        self.assertEqual(o[119], b'\x03lan\x00\x04corp\x03lan\x00')
        self.assertEqual(o[121], bytes([0, 192, 168, 1, 1, 8, 10, 192, 168, 1, 5]))  # default route first, then 10.0.0.0/8 (one octet of the destination)
        self.assertEqual((o[26], o[66], o[67]), (bytes([5, 120]), b'tftp.lan', b'pxe.0'))
        r, _ = self.reply('aa:aa:aa:aa:aa:60', 1, o61=cid)  # not asked: not sent
        self.assertFalse({42, 119, 121, 26, 66, 67} & r['opts'].keys())
        from .models import DhcpLease
        self.assertEqual(DhcpLease.objects.get(client=cid.hex()).mac, 'aa:aa:aa:aa:aa:60')
        # the same MAC with another identifier is another client
        r2, _ = self.reply('aa:aa:aa:aa:aa:60', 1, o61=bytes([0, 9, 9]))
        self.assertNotEqual(r2['yiaddr'], r['yiaddr'])

    def test_address_that_answers_a_ping_is_skipped(self):
        from .dhcp.v4 import Server
        self.server = Server(self.cfg, probe=lambda ip: ip == '192.168.1.100')
        r, _ = self.reply('aa:aa:aa:aa:aa:70', 1)
        self.assertEqual(r['yiaddr'], '192.168.1.101')
        from .models import DhcpLease
        self.assertTrue(DhcpLease.objects.filter(client='conflict-192.168.1.100').exists())

    def test_leased_host_names_are_answered_by_the_dns_server(self):
        from django.test import override_settings

        from .dhcp.v4 import lease_hosts
        self.reply('aa:aa:aa:aa:aa:80', 3, o50=bytes([192, 168, 1, 101]), o12=b'My_Laptop.local')
        with override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True):
            self.assertEqual(lease_hosts('mylaptop.lan'), [('192.168.1.101', 60)])
            self.assertIsNone(lease_hosts('other.lan'))
            self.assertIsNone(lease_hosts('a.mylaptop.lan'))
        with override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=False):
            self.assertIsNone(lease_hosts('mylaptop.lan'))

    def test_resolver_answers_a_leased_name(self):
        from types import SimpleNamespace

        from django.test import override_settings
        self.reply('aa:aa:aa:aa:aa:81', 3, o50=bytes([192, 168, 1, 102]), o12=b'tv')
        resolver._data = None
        with override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True):
            r = Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question('tv.lan', 'A'), SimpleNamespace(client_address=('127.0.0.1', 0)))
        self.assertEqual((r.header.rcode, [str(a.rdata) for a in r.rr]), (0, ['192.168.1.102']))

    def test_relay_agent_scope_option_82_and_reply_to_the_relay(self):
        import ipaddress
        import json
        from types import SimpleNamespace as NS

        from .dhcp.v4 import Server, scopes
        base = dict(DHCP_SERVER='192.168.1.2', DHCP_NETMASK='255.255.255.0', DHCP_RANGE='192.168.1.100-192.168.1.110', DHCP_ROUTER='', DHCP_DNS='', DHCP_DOMAIN='lan', DHCP_LEASE=3600,
                    DHCP_RESERVATIONS='', DHCP_DNR=False, DNS_DDR='', DHCP_NTP='', DHCP_ROUTES='', DHCP_SEARCH='', DHCP_MTU=0, DHCP_BOOT_SERVER='', DHCP_BOOT_FILE='', DHCP_PROBE=False)
        sub = [{'network': '10.1.0.0/24', 'range': '10.1.0.10-10.1.0.20', 'router': '10.1.0.1'}]
        cfgs = scopes(NS(**base, DHCP_SUBNETS=json.dumps(sub)))
        self.assertEqual([str(c.network) for c in cfgs], ['192.168.1.0/24', '10.1.0.0/24'])
        self.server = Server(cfgs)
        pkt = bytearray(self.packet('aa:aa:aa:aa:aa:90', 1, o82=b'\x01\x04abcd'))
        pkt[24:28] = bytes([10, 1, 0, 1])  # giaddr
        out = self.server.handle(bytes(pkt))
        self.assertEqual((out.ip, out.port, out.hw), ('10.1.0.1', 67, None))
        from .dhcp.v4 import parse
        r = parse(b'\x01' + out.data[1:])
        self.assertEqual((str(ipaddress.IPv4Address(out.data[16:20])), r['opts'][82], r['opts'][3]), ('10.1.0.10', b'\x01\x04abcd', bytes([10, 1, 0, 1])))
        pkt[24:28] = bytes([172, 16, 0, 1])  # a relay for a network we do not serve
        self.assertIsNone(self.server.handle(bytes(pkt)))
        for bad in ([{'network': '192.168.1.0/25', 'range': '192.168.1.1-192.168.1.9'}], [{'network': '10.1.0.0/24'}], 'nope'):
            with self.assertRaises(ValueError, msg=bad):
                scopes(NS(**base, DHCP_SUBNETS=json.dumps(bad)))

    def test_direct_reply_to_the_hardware_address_only_without_broadcast_flag(self):
        r = self.server.handle(self.packet('aa:aa:aa:aa:aa:91', 1))
        self.assertEqual((r.ip, r.port, r.hw), ('255.255.255.255', 68, bytes.fromhex('aaaaaaaaaa91')))
        pkt = bytearray(self.packet('aa:aa:aa:aa:aa:91', 1))
        pkt[10] = 0x80  # broadcast flag
        self.assertIsNone(self.server.handle(bytes(pkt)).hw)

    def test_l2_frame_has_valid_headers(self):
        import ipaddress
        import struct

        from .dhcp.v4 import ip_checksum, l2_frame
        f = l2_frame(bytes.fromhex('020000000001'), bytes.fromhex('aaaaaaaaaa91'), ipaddress.IPv4Address('192.168.1.2'), ipaddress.IPv4Address('192.168.1.100'), 67, 68, b'x' * 10)
        self.assertEqual((f[:6], f[12:14], len(f)), (bytes.fromhex('aaaaaaaaaa91'), b'\x08\x00', 14 + 20 + 8 + 10))
        self.assertEqual(ip_checksum(f[14:34]), 0)  # a header with its checksum sums to zero
        self.assertEqual(struct.unpack('!HHH', f[34:40]), (67, 68, 18))

    def test_client_fqdn_gives_the_name_and_the_dns_server_answers_the_reverse_name(self):
        from types import SimpleNamespace

        from django.test import override_settings

        from .dhcp.v4 import parse
        from .dhcp.v4 import lease_ptr
        fq = bytes([0x04, 0, 0]) + b'\x06phone1\x03lan\x00'  # E flag: wire format
        out = self.server.handle(self.packet('aa:aa:aa:aa:aa:92', 3, o50=bytes([192, 168, 1, 101]), o81=fq, o55=bytes([1])))
        r = parse(b'\x01' + out.data[1:])
        self.assertEqual(r['opts'][81][:3], bytes([0x0c, 0, 0]))  # N=1, E
        self.assertEqual(r['opts'][81][3:], b'\x06phone1\x03lan\x00')
        resolver._data = None
        with override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True):
            self.assertEqual(lease_ptr('101.1.168.192.in-addr.arpa'), 'phone1.lan')
            self.assertIsNone(lease_ptr('102.1.168.192.in-addr.arpa'))
            ptr = Resolver('127.0.0.1:9', log=None).resolve(DNSRecord.question('101.1.168.192.in-addr.arpa', 'PTR'), SimpleNamespace(client_address=('127.0.0.1', 0)))
        self.assertEqual((ptr.header.rcode, [str(a.rdata) for a in ptr.rr]), (0, ['phone1.lan.']))


class Dhcp6Tests(TestCase):
    def setUp(self):
        import ipaddress

        from .dhcp.v6 import Config6, Server6
        self.cfg = Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [b'\x00\x01dnr'], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                           ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::101'), ipaddress.IPv6Network('2001:db8:ff00::/40'), 56, name='test')
        self.s = Server6(self.cfg)

    def msg(self, kind, cid=b'\x00\x03abc', sid=None, ias=(), oro=(23, 24, 144, 32), extra=b''):
        import struct

        from .dhcp.v6 import CLIENTID, ORO, SERVERID, option
        out = bytes([kind, 1, 2, 3])
        if cid:
            out += option(CLIENTID, cid)
        if sid:
            out += option(SERVERID, sid)
        out += option(ORO, struct.pack('!%dH' % len(oro), *oro)) if oro else b''
        return out + b''.join(ias) + extra

    def ia(self, code, iaid=1, hint=b''):
        import struct

        from .dhcp.v6 import option
        return option(code, struct.pack('!III', iaid, 0, 0) + hint)

    def test_information_request_gets_dns_search_list_and_dnr(self):
        import ipaddress
        import struct

        from .dhcp.v6 import DNR, DNS, DOMAINS, IA_NA, REFRESH, option, parse
        typ, txid, o = parse(self.s.handle(self.msg(11)))
        self.assertEqual((typ, txid), (7, b'\x01\x02\x03'))
        self.assertEqual((o[1][0], o[2][0], o[DNS][0], o[DOMAINS][0], o[DNR][0]), (b'\x00\x03abc', self.s.duid, ipaddress.IPv6Address('2001:db8::53').packed, b'\x03lan\x00', b'\x00\x01dnr'))
        self.assertEqual(o[REFRESH][0], struct.pack('!I', 86400))
        self.assertEqual(sorted(parse(self.s.handle(self.msg(11, oro=())))[2]), [1, 2])  # nothing asked: only the identifiers
        self.assertIsNone(self.s.handle(self.msg(11, ias=[self.ia(IA_NA)])))  # IA options in an Information-request: invalid
        self.assertIsNone(self.s.handle(self.msg(11, sid=b'\x00\x04other')))  # for another server

    def test_solicit_advertise_request_reply_gives_an_address_and_a_prefix(self):
        import ipaddress
        import struct

        from .dhcp.v6 import IA_NA, IA_PD, IAADDR, IAPREFIX, options, parse
        ias = [self.ia(IA_NA, 7), self.ia(IA_PD, 8)]
        typ, _, o = parse(self.s.handle(self.msg(1, ias=ias)))
        self.assertEqual(typ, 2)  # Advertise
        na = options(o[IA_NA][0][12:])[IAADDR][0]
        pd = options(o[IA_PD][0][12:])[IAPREFIX][0]
        self.assertEqual(str(ipaddress.IPv6Address(na[:16])), '2001:db8:1::100')
        pref, valid = struct.unpack('!II', na[16:24])
        self.assertEqual((pref, valid), (900, 1200))
        self.assertEqual((pd[8], str(ipaddress.IPv6Address(pd[9:25]))), (56, '2001:db8:ff00::'))
        self.assertIsNone(self.s.handle(self.msg(3, ias=ias)))  # a Request must name the server
        typ, _, o = parse(self.s.handle(self.msg(3, sid=self.s.duid, ias=ias)))
        self.assertEqual(typ, 7)
        self.assertEqual(struct.unpack('!II', o[IA_NA][0][:4] + o[IA_NA][0][4:8])[0], 7)
        # a second client gets the next ones; the first keeps its own when it asks again
        _, _, o2 = parse(self.s.handle(self.msg(3, cid=b'\x00\x03xyz', sid=self.s.duid, ias=ias)))
        self.assertEqual(str(ipaddress.IPv6Address(options(o2[IA_NA][0][12:])[IAADDR][0][:16])), '2001:db8:1::101')
        self.assertEqual(str(ipaddress.IPv6Address(options(o2[IA_PD][0][12:])[IAPREFIX][0][9:25])), '2001:db8:ff00:100::')
        _, _, o3 = parse(self.s.handle(self.msg(3, sid=self.s.duid, ias=ias)))
        self.assertEqual(options(o3[IA_NA][0][12:])[IAADDR][0][:16], na[:16])
        # the pool is empty now
        _, _, o4 = parse(self.s.handle(self.msg(3, cid=b'\x00\x03new', sid=self.s.duid, ias=[self.ia(IA_NA, 1)])))
        self.assertEqual(options(o4[IA_NA][0][12:])[13][0][:2], b'\x00\x02')  # NoAddrsAvail

    def test_renew_rebind_confirm_release_decline(self):
        import ipaddress

        from .dhcp.v6 import IA_NA, IAADDR, STATUS, option, options, parse
        self.s.handle(self.msg(3, sid=self.s.duid, ias=[self.ia(IA_NA, 5)]))
        _, _, o = parse(self.s.handle(self.msg(5, sid=self.s.duid, ias=[self.ia(IA_NA, 5)])))
        self.assertIn(IAADDR, options(o[IA_NA][0][12:]))  # renewed
        _, _, o = parse(self.s.handle(self.msg(5, sid=self.s.duid, ias=[self.ia(IA_NA, 6)])))
        self.assertEqual(options(o[IA_NA][0][12:])[STATUS][0][:2], b'\x00\x03')  # NoBinding
        self.assertIsNone(self.s.handle(self.msg(6, ias=[self.ia(IA_NA, 6)])))  # Rebind of something unknown: silence
        self.assertIsNotNone(self.s.handle(self.msg(6, ias=[self.ia(IA_NA, 5)])))
        good = option(5, ipaddress.IPv6Address('2001:db8:1::100').packed + bytes(8))
        bad = option(5, ipaddress.IPv6Address('2001:db8:9::1').packed + bytes(8))
        self.assertEqual(parse(self.s.handle(self.msg(4, ias=[self.ia(IA_NA, 5, good)])))[2][STATUS][0][:2], b'\x00\x00')
        self.assertEqual(parse(self.s.handle(self.msg(4, ias=[self.ia(IA_NA, 5, bad)])))[2][STATUS][0][:2], b'\x00\x04')  # NotOnLink
        self.s.handle(self.msg(8, sid=self.s.duid, ias=[self.ia(IA_NA, 5)]))  # release
        from .models import Dhcp6Lease
        self.assertFalse(Dhcp6Lease.objects.filter(duid='000361626 3'.replace(' ', ''), iaid=5).exists())
        self.s.handle(self.msg(9, sid=self.s.duid, ias=[self.ia(IA_NA, 5, good)]))  # decline: that address is out for a while
        _, _, o = parse(self.s.handle(self.msg(3, cid=b'\x00\x03zzz', sid=self.s.duid, ias=[self.ia(IA_NA, 1)])))
        self.assertEqual(str(ipaddress.IPv6Address(options(o[IA_NA][0][12:])[IAADDR][0][:16])), '2001:db8:1::101')

    def test_relay_forward_is_answered_with_a_relay_reply(self):
        from .dhcp.v6 import INTERFACE_ID, RELAY_MSG, option, options
        inner = self.msg(11)
        fwd = bytes([12, 0]) + b'\x20\x01\x0d\xb8' + bytes(12) + b'\xfe\x80' + bytes(14) + option(RELAY_MSG, inner) + option(INTERFACE_ID, b'eth1')
        out = self.s.handle(fwd)
        self.assertEqual((out[0], out[1], out[2:34]), (13, 0, fwd[2:34]))
        o = options(out[34:])
        self.assertEqual(o[INTERFACE_ID][0], b'eth1')
        self.assertEqual(o[RELAY_MSG][0][0], 7)
        twice = bytes([12, 1]) + bytes(32) + option(RELAY_MSG, fwd)  # a relay behind a relay
        self.assertEqual(self.s.handle(twice)[0], 13)

    def test_rapid_commit_and_stateless_mode(self):
        from .dhcp.v6 import IA_NA, RAPID, Server6, option, parse
        self.cfg.rapid = True
        typ, _, o = parse(self.s.handle(self.msg(1, ias=[self.ia(IA_NA, 1)], extra=option(RAPID, b''))))
        self.assertEqual((typ, RAPID in o), (7, True))
        stateless = Server6(type(self.cfg)(self.cfg.dns, self.cfg.search, self.cfg.dnr, name='x'))
        self.assertIsNone(stateless.handle(self.msg(1, ias=[self.ia(IA_NA, 1)])))  # no pool: no addresses
        self.assertIsNotNone(stateless.handle(self.msg(11)))

    def test_config_is_checked(self):
        from types import SimpleNamespace as NS

        from .dhcp.v6 import Config6
        good = dict(DHCP6_DNS='2001:db8::53', DHCP6_PREFIX='2001:db8:1::/64', DHCP6_POOL='2001:db8:1::100-2001:db8:1::1ff', DHCP6_PD_POOL='2001:db8:ff00::/40',
                    DHCP6_PD_LEN=56, DHCP6_LEASE=3600, DHCP6_RAPID=False, DHCP_DNR=False, DNS_DDR='', DHCP_SERVER='192.168.1.2')
        self.assertTrue(Config6.from_settings(NS(**good), []).stateful)
        for bad in ({'DHCP6_POOL': '2001:db9::1-2001:db9::9'}, {'DHCP6_PD_LEN': 30}, {'DHCP6_LEASE': 5}, {'DHCP6_DNS': 'nope'}, {'DHCP6_PREFIX': ''}):
            with self.assertRaises(ValueError, msg=bad):
                Config6.from_settings(NS(**{**good, **bad}), [])


class RouterAdvertisementTests(TestCase):
    def test_advertisement_carries_dns_search_list_prefix_and_dnr(self):
        import ipaddress
        import struct

        from .dnsd.ddr import parse
        from .dhcp.ra import RaConfig, build
        cfg = RaConfig([ipaddress.IPv6Address('2001:db8::53')], ['lan'], parse('dot:dns.example.lan'), ipaddress.IPv6Network('2001:db8:1::/64'), managed=True, interval=600)
        m = build(cfg, bytes.fromhex('aabbccddeeff'))
        self.assertEqual((m[0], m[4], m[5], struct.unpack('!H', m[6:8])[0]), (134, 64, 0xc0, 0))  # type, hop limit, M+O flags, router lifetime 0: not a default router
        self.assertEqual(len(m) % 8, 0)
        i, seen = 16, {}
        while i < len(m):  # walk the options by their length in units of 8 octets
            seen[m[i]] = m[i:i + m[i + 1] * 8]
            i += m[i + 1] * 8
        self.assertEqual(sorted(seen), [1, 3, 25, 31, 144])
        self.assertEqual((seen[3][2], seen[3][3]), (64, 0xc0))  # /64, on-link + autonomous
        self.assertEqual(struct.unpack('!I', seen[25][4:8])[0], 1800)  # RDNSS lifetime: 3 x interval
        self.assertEqual(seen[25][8:24], ipaddress.IPv6Address('2001:db8::53').packed)
        self.assertEqual(seen[31][8:14], b'\x03lan\x00\x00')
        self.assertEqual(seen[144][0:2], bytes([144, len(seen[144]) // 8]))


class DhcpApiTests(TestCase):
    def test_leases_list_search_and_end(self):
        from datetime import timedelta

        from django.contrib.auth.models import User
        from django.utils import timezone
        from rest_framework.test import APIClient

        from .models import Dhcp6Lease, DhcpLease
        now = timezone.now()
        DhcpLease.objects.create(client='01aabb', mac='aa:bb:cc:dd:ee:01', ip='192.168.1.100', hostname='tv', expires=now + timedelta(hours=1))
        DhcpLease.objects.create(client='x2', mac='aa:bb:cc:dd:ee:02', ip='192.168.1.101', expires=now - timedelta(hours=1))
        DhcpLease.objects.create(client='declined-192.168.1.102', ip='192.168.1.102', expires=now + timedelta(hours=1))
        Dhcp6Lease.objects.create(duid='0003abc', iaid=1, kind='pd', value='2001:db8:ff00::/56', expires=now + timedelta(hours=1))
        c = APIClient()
        c.force_authenticate(User.objects.create_user('dh', is_staff=True, is_superuser=True))
        got = c.get('/api/dhcp/leases/').data
        self.assertEqual(sorted((r['family'], r['kind'], r['address']) for r in got), [(4, 'address', '192.168.1.100'), (6, 'prefix', '2001:db8:ff00::/56')])  # no ended lease, no block marker
        self.assertEqual(len(c.get('/api/dhcp/leases/?all=true').data), 3)
        self.assertEqual([r['hostname'] for r in c.get('/api/dhcp/leases/?q=TV').data], ['tv'])
        lease = DhcpLease.objects.get(ip='192.168.1.100')
        self.assertEqual(c.delete(f'/api/dhcp/leases/4/{lease.id}/').status_code, 204)
        self.assertEqual(c.delete(f'/api/dhcp/leases/4/{lease.id}/').status_code, 404)
        self.assertEqual(c.delete('/api/dhcp/leases/5/1/').status_code, 404)
        self.assertEqual(APIClient().get('/api/dhcp/leases/').status_code, 401)  # login needed


class SecurityAndProtocolHardeningTests(TestCase):
    def test_record_newline_injection_and_quote_at_expansion_blocked(self):
        from .serializers import RecordSerializer
        z = Zone.objects.create(name='example.lan')
        s = RecordSerializer(data={'zone': z.id, 'name': '@', 'type': 'A', 'value': '1.2.3.4\nevil.com. 300 IN A 6.6.6.6'})
        self.assertFalse(s.is_valid())
        # '@' inside TXT quotes must remain '@', not expand to zone name
        s2 = RecordSerializer(data={'zone': z.id, 'name': '@', 'type': 'TXT', 'value': '"contact admin@example.lan"'})
        self.assertTrue(s2.is_valid(), s2.errors)
        rec = s2.save()
        self.assertIn('admin@example.lan', str(rec.to_rr()[0].rdata))

    def test_redos_regex_rejected_in_blocked_domain_serializer(self):
        from .serializers import BlockedDomainSerializer
        s = BlockedDomainSerializer(data={'name': '(a+)+$', 'regex': True})
        self.assertFalse(s.is_valid())
        s_backref = BlockedDomainSerializer(data={'name': r'(a+)\1$', 'regex': True})
        self.assertFalse(s_backref.is_valid())
        s_ok = BlockedDomainSerializer(data={'name': r'^ads\.[a-z0-9-]+\.com$', 'regex': True})
        self.assertTrue(s_ok.is_valid(), s_ok.errors)

    def test_mfa_tickets_are_single_use_and_expired_tokens_rejected(self):
        from datetime import timedelta
        from django.contrib.auth.models import User
        from django.core.cache import cache
        from django.utils import timezone
        from rest_framework.authtoken.models import Token
        from rest_framework.test import APIClient
        from .security import mfa
        from .models import TotpDevice

        cache.clear()
        u = User.objects.create_user('secuser', password='Password123!', is_staff=True)
        t = mfa.make_ticket(u, 'setup')
        self.assertEqual(mfa.read_ticket(t, 'setup', consume=True), u)
        with self.assertRaises(mfa.MfaError):
            mfa.read_ticket(t, 'setup', consume=True)  # second use of the same ticket is rejected

        # once MFA is enrolled, a setup ticket cannot be redeemed
        TotpDevice.objects.create(user=u, secret='JBSWY3DPEHPK3PXP', confirmed=True)
        t2 = mfa.make_ticket(u, 'setup')
        with self.assertRaises(mfa.MfaError):
            mfa.read_ticket(t2, 'setup')

        # expired token is rejected on MFA endpoints
        tok = Token.objects.create(user=u)
        Token.objects.filter(pk=tok.pk).update(created=timezone.now() - timedelta(days=30))
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f'Token {tok.key}')
        self.assertEqual(c.get('/api/mfa/').status_code, 401)

    def test_dhcp_decline_does_not_evict_other_clients_and_discover_preserves_expiry(self):
        import ipaddress
        from datetime import timedelta
        from django.utils import timezone
        from .dhcp.v4 import Config, Server
        from .models import DhcpLease

        cfg = Config(ipaddress.IPv4Address('192.168.1.2'), ipaddress.IPv4Network('192.168.1.0/24'),
                     ipaddress.IPv4Address('192.168.1.100'), ipaddress.IPv4Address('192.168.1.102'),
                     ipaddress.IPv4Address('192.168.1.1'), [ipaddress.IPv4Address('192.168.1.2')], 'lan', 3600, {}, b'')
        srv = Server(cfg)
        # Client A acquires 192.168.1.100 via REQUEST
        pkt_req = DhcpTests().packet('aa:aa:aa:aa:aa:01', 3, o50=bytes([192, 168, 1, 100]))
        srv.handle(pkt_req)
        lease = DhcpLease.objects.get(ip='192.168.1.100')
        orig_exp = lease.expires
        self.assertGreater(orig_exp, timezone.now() + timedelta(seconds=1800))

        # Spoofed DISCOVER from Client A must not shrink lease expiry to 60s
        pkt_disc = DhcpTests().packet('aa:aa:aa:aa:aa:01', 1)
        srv.handle(pkt_disc)
        lease.refresh_from_db()
        self.assertGreaterEqual(lease.expires, orig_exp)

        # Unrelated Client B sends DECLINE for Client A's IP: must be ignored
        pkt_dec = DhcpTests().packet('aa:aa:aa:aa:aa:99', 4, o50=bytes([192, 168, 1, 100]))
        srv.handle(pkt_dec)
        self.assertEqual(DhcpLease.objects.get(ip='192.168.1.100').client, 'aa:aa:aa:aa:aa:01')

    def test_rfc4592_closest_encloser_stops_wildcard_and_edns_badvers(self):
        from types import SimpleNamespace
        from django.test import override_settings
        from dnslib import DNSRecord, EDNS0
        z = Zone.objects.create(name='wild.lan')
        Record.objects.create(zone=z, name='*', type='A', value='10.0.0.1')
        Record.objects.create(zone=z, name='sub.branch', type='A', value='10.0.0.2')
        resolver._data = None
        res = Resolver('127.0.0.1:9', log=None)
        h = SimpleNamespace(client_address=('127.0.0.1', 0))

        with override_settings(DNS_AUTHORITATIVE=True):
            # foo.wild.lan matches *.wild.lan
            r1 = res.resolve(DNSRecord.question('foo.wild.lan', 'A'), h)
            self.assertEqual([str(a.rdata) for a in r1.rr], ['10.0.0.1'])

            # other.branch.wild.lan has closest encloser branch.wild.lan (ENT) -> must NOT match *.wild.lan
            r2 = res.resolve(DNSRecord.question('other.branch.wild.lan', 'A'), h)
            self.assertEqual((r2.header.rcode, len(r2.rr)), (3, 0))  # NXDOMAIN

        # EDNS version 1 -> BADVERS (16)
        q_edns1 = DNSRecord.question('foo.wild.lan', 'A')
        q_edns1.add_ar(EDNS0(version=1))
        r3 = res.resolve(q_edns1, h)
        self.assertEqual(r3.ar[0].ttl >> 24, 1)  # extended rcode upper 8 bits = 1 -> (1 << 4) | 0 = 16 (BADVERS)

    def test_dhcp_hostname_cannot_hijack_internal_zone_record(self):
        from datetime import timedelta
        from django.utils import timezone
        from .models import DhcpLease
        z = Zone.objects.create(name='lan')
        Record.objects.create(zone=z, name='router', type='A', value='192.168.1.1')
        Record.objects.create(zone=z, name='*', type='A', value='192.168.1.250')
        now = timezone.now()
        DhcpLease.objects.create(client='evil', mac='aa:bb:cc:dd:ee:99', ip='192.168.1.199', hostname='router', expires=now + timedelta(hours=1))
        DhcpLease.objects.create(client='good', mac='aa:bb:cc:dd:ee:10', ip='192.168.1.110', hostname='laptop', expires=now + timedelta(hours=1))
        resolver._data = None
        res = Resolver('127.0.0.1:9', log=None)
        h = SimpleNamespace(client_address=('127.0.0.1', 0))
        with override_settings(DHCP=True, DHCP_DOMAIN='lan', DHCP_NAMES=True, DNS_AUTHORITATIVE=True):
            # Explicit zone record 'router.lan' must NOT be overridden by a DHCP client claiming hostname 'router'
            r_router = res.resolve(DNSRecord.question('router.lan', 'A'), h)
            self.assertEqual([str(a.rdata) for a in r_router.rr], ['192.168.1.1'])
            # Unassigned host 'laptop.lan' with a DHCP lease resolves to the lease IP (even when wildcard *.lan exists)
            r_laptop = res.resolve(DNSRecord.question('laptop.lan', 'A'), h)
            self.assertEqual([str(a.rdata) for a in r_laptop.rr], ['192.168.1.110'])

    def test_dhcp_and_dhcp6_decline_pool_exhaustion_prevented_and_relayed_nak_broadcast(self):
        import ipaddress
        from .dhcp.v4 import Config, Server
        from .dhcp.v6 import IA_NA, Config6, Server6, option, options, parse

        cfg = Config(ipaddress.IPv4Address('192.168.1.2'), ipaddress.IPv4Network('192.168.1.0/24'),
                     ipaddress.IPv4Address('192.168.1.100'), ipaddress.IPv4Address('192.168.1.102'),
                     ipaddress.IPv4Address('192.168.1.1'), [ipaddress.IPv4Address('192.168.1.2')], 'lan', 3600, {}, b'')
        srv = Server(cfg)
        helper = DhcpTests()
        # Attacker tries to DECLINE all 3 IPs in the pool (.100, .101, .102)
        for last_octet in (100, 101, 102):
            srv.handle(helper.packet('aa:aa:aa:aa:aa:88', 4, o50=bytes([192, 168, 1, last_octet])))
        # Legitimate client must still get an address from the pool
        out = srv.handle(helper.packet('aa:aa:aa:aa:aa:12', 1))
        self.assertIsNotNone(out)

        # Relayed NAK must set the broadcast bit 0x8000 (RFC 2131 §4.3.2)
        bad_req = bytearray(helper.packet('aa:aa:aa:aa:aa:12', 3, o50=bytes([10, 99, 99, 99])))
        bad_req[24:28] = bytes([192, 168, 1, 1])  # giaddr inside scope
        nak_out = srv.handle(bytes(bad_req))
        self.assertTrue(nak_out.data[10] & 0x80)

        # DHCPv6: attacker tries to DECLINE both addresses in a 2-address pool; pool must not be exhausted
        cfg6 = Config6([ipaddress.IPv6Address('2001:db8::53')], ['lan'], [], 1200, ipaddress.IPv6Network('2001:db8:1::/64'),
                       ipaddress.IPv6Address('2001:db8:1::100'), ipaddress.IPv6Address('2001:db8:1::101'), name='test6')
        s6 = Server6(cfg6)
        h6 = Dhcp6Tests()
        for addr in ('2001:db8:1::100', '2001:db8:1::101'):
            ia_opt = h6.ia(IA_NA, 1, option(5, ipaddress.IPv6Address(addr).packed + bytes(8)))
            s6.handle(h6.msg(9, cid=b'\x00\x03att', sid=s6.duid, ias=[ia_opt]))
        _, _, o6 = parse(s6.handle(h6.msg(3, cid=b'\x00\x03legit', sid=s6.duid, ias=[h6.ia(IA_NA, 1), h6.ia(IA_NA, 1)])))
        self.assertEqual(len(o6[IA_NA]), 1)  # duplicate IAID deduplicated
        self.assertIn(5, options(o6[IA_NA][0][12:]))  # address still allocated

    def test_qr1_response_packets_rejected_and_0x20_case_preserved(self):
        from unittest import mock
        from django.core.cache import cache
        from django.test import Client
        from .dnsd.dnsserver import PooledUDPServer

        # QR=1 in Resolver.resolve -> FORMERR
        res = Resolver('127.0.0.1:9', log=None)
        h = SimpleNamespace(client_address=('127.0.0.1', 0))
        pkt = DNSRecord.question('example.com', 'A')
        pkt.header.qr = 1
        self.assertEqual(res.resolve(pkt, h).header.rcode, 1)

        # QR=1 in DohView -> 400 Bad Request
        with override_settings(DNS_DOH=True):
            self.assertEqual(Client().post('/dns-query', bytes(pkt.pack()), content_type='application/dns-message').status_code, 400)

        # QR=1 in PooledUDPServer.process_request -> silently ignored without submitting to worker pool
        dummy_srv = SimpleNamespace(_room= mock.MagicMock(), _pool=mock.MagicMock(), shutdown_request=mock.MagicMock())
        PooledUDPServer.process_request(dummy_srv, (bytes(pkt.pack()), None), ('127.0.0.1', 53))
        dummy_srv._pool.submit.assert_not_called()

        # 0x20 bit-encoding case preservation on cached replies
        cache.clear()
        q1 = DNSRecord.question('eXaMpLe.CoM', 'A')
        ans = q1.reply()
        with mock.patch.object(Resolver, 'ask_upstream', return_value=(ans, '1.1.1.1')):
            res.forward(q1)
        q2 = DNSRecord.question('ExAmPlE.cOm', 'A')
        cached_reply, via = res.forward(q2)
        self.assertEqual((via, str(cached_reply.q.qname)), ('cache', 'ExAmPlE.cOm.'))

    def test_behind_proxy_login_rate_limit_uses_forwarded_ip(self):
        from django.test import RequestFactory
        from .views.token import client_ip
        rf = RequestFactory()
        req = rf.post('/api/token/', REMOTE_ADDR='127.0.0.1', HTTP_X_REAL_IP='203.0.113.50')
        with override_settings(BEHIND_PROXY=False):
            self.assertEqual(client_ip(req), '127.0.0.1')
        with override_settings(BEHIND_PROXY=True):
            self.assertEqual(client_ip(req), '203.0.113.50')

    def test_nested_redos_control_chars_and_invalid_domain_rejected(self):
        from .serializers import BlockedDomainSerializer
        for bad in (
            {'name': '((a+))+$', 'regex': True},
            {'name': 'a.*.*.*b', 'regex': True},
            {'name': 'bad\tname.com', 'regex': False},
            {'name': 'not a domain!', 'regex': False},
        ):
            self.assertFalse(BlockedDomainSerializer(data=bad).is_valid(), bad)

    def test_logwriter_recovers_from_poison_row_and_cname_to_static_host_or_nodata(self):
        from .stats.logwriter import LogWriter
        from .models import QueryLog, StaticHost
        lw = LogWriter(interval=60)
        good_row = QueryLog(name='ok.example', domain='example', type='A', outcome='local', client='127.0.0.1', ms=1)
        bad_row = QueryLog(name='bad.example', domain='example', type='A', outcome='local', client='127.0.0.1', ms=-1)  # NegativePositiveIntegerField fails on save/validation if forced
        lw.add(good_row)
        lw.add(bad_row)
        from django.db import IntegrityError
        orig_save = QueryLog.save
        with __import__('unittest.mock', fromlist=['patch']).patch.object(
            QueryLog.objects, 'bulk_create', side_effect=IntegrityError('poison')
        ), __import__('unittest.mock', fromlist=['patch']).patch.object(
            QueryLog, 'save', autospec=True,
            side_effect=lambda self_row, *a, **kw: (_ for _ in ()).throw(IntegrityError('bad')) if self_row.name == 'bad.example' else orig_save(self_row, *a, **kw)
        ):
            lw._flush()
        self.assertEqual(lw._retry, [])
        self.assertEqual(lw.dropped, 1)
        self.assertTrue(QueryLog.objects.filter(name='ok.example').exists())

        # Internal CNAME to StaticHost and to NODATA record
        z = Zone.objects.create(name='corp.lan')
        StaticHost.objects.create(name='nas.corp.lan', address='10.0.0.50')
        Record.objects.create(zone=z, name='storage', type='CNAME', value='nas.corp.lan.')
        Record.objects.create(zone=z, name='v4only', type='A', value='10.0.0.51')
        Record.objects.create(zone=z, name='alias', type='CNAME', value='v4only.corp.lan.')
        resolver._data = None
        res = Resolver('127.0.0.1:9', log=None)
        h = SimpleNamespace(client_address=('127.0.0.1', 0))
        with override_settings(DNS_AUTHORITATIVE=True):
            r_sh = res.resolve(DNSRecord.question('storage.corp.lan', 'A'), h)
            self.assertEqual([str(a.rdata) for a in r_sh.rr], ['nas.corp.lan.', '10.0.0.50'])
            r_nodata = res.resolve(DNSRecord.question('alias.corp.lan', 'AAAA'), h)
            self.assertEqual((r_nodata.header.rcode, [QTYPE[a.rtype] for a in r_nodata.auth]), (0, ['SOA']))

    def test_check_ddr_with_real_tls_certificate_and_dnr_options_formats(self):
        import datetime
        import io
        import socket
        import ssl
        import struct
        import tempfile
        import threading
        from unittest import mock
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from django.core.management import call_command

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Zones.dns internal CA')])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        srv_key = ec.generate_private_key(ec.SECP256R1())
        srv_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'dns.example.lan')]))
            .issuer_name(ca_name)
            .public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('dns.example.lan')]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        with tempfile.TemporaryDirectory() as d:
            ca_path, cert_path, key_path = f'{d}/ca.pem', f'{d}/cert.pem', f'{d}/key.pem'
            with open(ca_path, 'wb') as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            with open(cert_path, 'wb') as f:
                f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, 'wb') as f:
                f.write(srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

            srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ctx.load_cert_chain(cert_path, key_path)
            cli_ctx = ssl.create_default_context(cafile=ca_path)

            def tls_roundtrip(server_host, app_fn):
                c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                cli = cli_ctx.wrap_bio(c_in, c_out, server_hostname=server_host)
                srv = srv_ctx.wrap_bio(s_in, s_out, server_side=True)
                for _ in range(10):
                    for side, bio_out, peer_in in ((cli, c_out, s_in), (srv, s_out, c_in)):
                        try:
                            side.do_handshake()
                        except ssl.SSLWantReadError:
                            pass
                        if pending := bio_out.read():
                            peer_in.write(pending)
                return app_fn(cli, srv, c_in, c_out, s_in, s_out)

            # Verify real X.509 SAN & CA chain validation succeeds for dns.example.lan and fails for wrong.example.lan
            self.assertEqual(tls_roundtrip('dns.example.lan', lambda cli, *_: cli.version()), 'TLSv1.3')
            with self.assertRaises(ssl.SSLCertVerificationError):
                tls_roundtrip('wrong.example.lan', lambda cli, *_: None)

            ddr_cfg = 'dot:dns.example.lan:853@192.168.1.23,2001:db8::53 doh:dns.example.lan:443/dns-query{?dns}@192.168.1.23'
            reply_wire = bytes(DNSRecord.question('example.com', 'A').reply().pack())
            out = io.StringIO()
            from .management.commands.check_ddr import Command as CheckDdrCmd
            with override_settings(DNS_DDR=ddr_cfg), mock.patch.object(
                CheckDdrCmd, 'dot', side_effect=lambda host, port, q, ctx=None: tls_roundtrip(host, lambda *_: reply_wire)
            ), mock.patch.object(
                CheckDdrCmd, 'doh', side_effect=lambda host, port, path, q, ctx=None: tls_roundtrip(host, lambda *_: reply_wire)
            ):
                call_command('check_ddr', cafile=ca_path, stdout=out)
            self.assertEqual(out.getvalue().count('OK'), 2)

            for fmt, needle in (('dnsmasq', 'dhcp-option=162,'), ('kea', '"space": "dhcp4"'), ('all', 'OPTION_V4_DNR')):
                buf = io.StringIO()
                with override_settings(DNS_DDR=ddr_cfg):
                    call_command('dnr_options', format=fmt, stdout=buf)
                self.assertIn(needle, buf.getvalue())

    def test_arp_probe_frames_and_rundhcp_l2_and_lists_off_migration(self):
        import ipaddress
        import struct
        from django.apps import apps
        from .dhcp.v4 import Reply, arp_request, is_arp_reply
        from .management.commands.rundhcp import Command as RunDhcpCmd
        from .models import Setting

        req = arp_request(bytes.fromhex('020000000001'), '192.168.1.2', '192.168.1.100')
        self.assertEqual((len(req), req[:6], req[12:14]), (42, b'\xff' * 6, b'\x08\x06'))
        self.assertFalse(is_arp_reply(req, '192.168.1.100'))  # oper=1 is a request, not a reply
        reply_frame = bytes.fromhex('020000000001aaaaaaaaaa990806') + struct.pack(
            '!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 2,
            bytes.fromhex('aaaaaaaaaa99'), ipaddress.IPv4Address('192.168.1.100').packed,
            bytes.fromhex('020000000001'), ipaddress.IPv4Address('192.168.1.2').packed,
        )
        self.assertTrue(is_arp_reply(reply_frame, '192.168.1.100'))
        self.assertFalse(is_arp_reply(reply_frame, '192.168.1.101'))

        # rundhcp.Command.send with L2 hardware unicast
        cmd = RunDhcpCmd()
        cmd.opt = {'port': 67, 'client_port': 68}
        sent_frames = []
        l2 = SimpleNamespace(mac=bytes.fromhex('020000000001'), send=sent_frames.append)
        payload = bytearray(244)
        payload[16:20] = bytes([192, 168, 1, 100])  # yiaddr
        cmd.send(None, l2, ipaddress.IPv4Address('192.168.1.2'), Reply(bytes(payload), '255.255.255.255', 68, bytes.fromhex('aaaaaaaaaa10')))
        self.assertEqual(len(sent_frames), 1)
        self.assertEqual(sent_frames[0][:6], bytes.fromhex('aaaaaaaaaa10'))

        # 0025_remove_lists_off migration cleans up legacy lists_off setting
        from importlib import import_module
        mig = import_module('zones.migrations.0025_remove_lists_off')
        Setting.objects.create(key='lists_off', value='one,two')
        Setting.objects.create(key='public_lists', value='true')
        mig.remove_lists_off(apps, None)
        self.assertFalse(Setting.objects.filter(key='lists_off').exists())
        self.assertTrue(Setting.objects.filter(key='public_lists').exists())

    def test_rate_limiting_and_dnssec_validation(self):
        import hashlib
        import struct
        import time
        from unittest import mock
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from dnslib import A, DNSKEY, RCODE, RR, RRSIG
        from .dnsd import dnssec, ratelimit
        from .models import QueryLog

        Zone.objects.create(name='corp.lan')
        resolver._data = None
        h = SimpleNamespace(client_address=('127.0.0.1', 0))

        # 1. Per-client DNS rate limiting
        ratelimit.reset()
        r = Resolver('1.1.1.1')
        with override_settings(DNS_AUTHORITATIVE=True, DNS_RATE_LIMIT=2, DNS_RATE_WINDOW=60):
            for _ in range(2):
                rep = r.resolve(DNSRecord.question('ok.corp.lan', 'A'), h)
                self.assertEqual(rep.header.rcode, RCODE.NXDOMAIN)
            blocked_rep = r.resolve(DNSRecord.question('ok.corp.lan', 'A'), h)
            self.assertEqual(blocked_rep.header.rcode, RCODE.REFUSED)
            self.assertTrue(QueryLog.objects.filter(outcome='blocked', via='rate limit').exists())
        ratelimit.reset()

        # 2. DNSSEC key_tag, DS verification, and ECDSA P-256 RRSIG validation
        priv = ec.generate_private_key(ec.SECP256R1())
        nums = priv.public_key().public_numbers()
        pub_bytes = nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')
        tag = dnssec.key_tag(257, 3, 13, pub_bytes)
        ds_msg = b'\x07example\x03com\x00' + struct.pack('!HBB', 257, 3, 13) + pub_bytes
        ds_hex = hashlib.sha256(ds_msg).hexdigest().upper()
        self.assertTrue(dnssec.verify_ds('example.com.', 257, 3, 13, pub_bytes, tag, 13, 2, ds_hex))
        self.assertFalse(dnssec.verify_ds('example.com.', 257, 3, 13, pub_bytes, tag, 13, 2, '00' * 32))

        now = int(time.time())
        a_rr = RR('www.example.com.', QTYPE.A, rdata=A('93.184.216.34'), ttl=300)
        dnskey_rr = RR('example.com.', QTYPE.DNSKEY, rdata=DNSKEY(257, 3, 13, pub_bytes), ttl=300)
        placeholder_sig = RRSIG(QTYPE.A, 13, 3, 300, now + 3600, now - 60, tag, 'example.com.', b'\x00' * 64)
        signed_wire = dnssec._rrset_wire([a_rr], placeholder_sig)
        der_sig = priv.sign(signed_wire, ec.ECDSA(hashes.SHA256()))
        r_int, s_int = decode_dss_signature(der_sig)
        raw_sig = r_int.to_bytes(32, 'big') + s_int.to_bytes(32, 'big')
        rrsig_rr = RR('www.example.com.', QTYPE.RRSIG, rdata=RRSIG(QTYPE.A, 13, 3, 300, now + 3600, now - 60, tag, 'example.com.', raw_sig), ttl=300)
        self.assertTrue(dnssec.verify_rrsig([a_rr], rrsig_rr, [dnskey_rr], now=now))

        # Resolver sets AD=1 on valid DNSSEC reply and returns SERVFAIL on bogus signature (unless CD=1)
        def make_upstream_reply(sig_bytes):
            def _send(self_pkt, host, port, tcp=False, timeout=2, ipv6=False):
                ans = self_pkt.reply()
                ans.add_answer(a_rr)
                ans.add_answer(RR('www.example.com.', QTYPE.RRSIG, rdata=RRSIG(QTYPE.A, 13, 3, 300, now + 3600, now - 60, tag, 'example.com.', sig_bytes), ttl=300))
                ans.add_auth(dnskey_rr)
                return ans.pack()
            return _send

        with override_settings(DNS_DNSSEC=True, DNS_CACHE=False), mock.patch.object(DNSRecord, 'send', new=make_upstream_reply(raw_sig)):
            rep_ok = r.resolve(DNSRecord.question('www.example.com', 'A'), h)
            self.assertEqual((rep_ok.header.rcode, rep_ok.header.ad), (RCODE.NOERROR, 1))
            self.assertTrue(all(rr.rtype != QTYPE.RRSIG for rr in rep_ok.rr))  # stripped when client did not set DO=1

        bad_sig = raw_sig[:-1] + bytes([raw_sig[-1] ^ 0xFF])
        with override_settings(DNS_DNSSEC=True, DNS_CACHE=False), mock.patch.object(DNSRecord, 'send', new=make_upstream_reply(bad_sig)):
            rep_bogus = r.resolve(DNSRecord.question('www.example.com', 'A'), h)
            self.assertEqual(rep_bogus.header.rcode, RCODE.SERVFAIL)
            q_cd = DNSRecord.question('www.example.com', 'A')
            q_cd.header.cd = 1
            rep_cd = r.resolve(q_cd, h)
            self.assertEqual(rep_cd.header.rcode, RCODE.NOERROR)

    def test_rfc2136_dynamic_dns_updates(self):
        from dnslib import A, CLASS, DNSHeader, DNSQuestion, OPCODE, RCODE, RR, TXT
        from .dnsd import ddns
        zone = Zone.objects.create(name='corp.lan')
        resolver._data = None
        h = SimpleNamespace(client_address=('127.0.0.1', 0))
        r = Resolver('1.1.1.1')

        def make_update(zname, prereqs=(), updates=()):
            pkt = DNSRecord(DNSHeader(opcode=OPCODE.UPDATE))
            pkt.add_question(DNSQuestion(zname, QTYPE.SOA, CLASS.IN))
            for rr in prereqs:
                pkt.add_answer(rr)
            for rr in updates:
                pkt.add_auth(rr)
            return pkt

        # Refused when DNS_UPDATE_ALLOW does not match client IP
        upd = make_update('corp.lan', updates=[RR('dyn.corp.lan', QTYPE.A, rclass=ddns.CLASS_IN, ttl=120, rdata=A('10.0.0.55'))])
        with override_settings(DNS_UPDATE_ALLOW='192.168.99.0/24'):
            rep = r.resolve(upd, h)
            self.assertEqual(rep.header.rcode, RCODE.REFUSED)

        # Allowed when client IP is in DNS_UPDATE_ALLOW: adds record and bumps zone serial
        old_serial = zone.serial
        with override_settings(DNS_UPDATE_ALLOW='127.0.0.0/8'):
            rep = r.resolve(upd, h)
            self.assertEqual(rep.header.rcode, RCODE.NOERROR)
            self.assertTrue(Record.objects.filter(zone=zone, name='dyn', type='A', value='10.0.0.55', ttl=120).exists())
            zone.refresh_from_db()
            self.assertGreater(zone.serial, old_serial)

            # Prerequisite NXDOMAIN fails when 'dyn.corp.lan' already exists
            pre_nx = RR('dyn.corp.lan', QTYPE.ANY, rclass=ddns.CLASS_NONE, ttl=0, rdata=TXT(''))
            rep_nx = r.resolve(make_update('corp.lan', prereqs=[pre_nx]), h)
            self.assertEqual(rep_nx.header.rcode, RCODE.NXDOMAIN)

            # Delete specific RR (CLASS_NONE)
            del_rr = RR('dyn.corp.lan', QTYPE.A, rclass=ddns.CLASS_NONE, ttl=0, rdata=A('10.0.0.55'))
            rep_del = r.resolve(make_update('corp.lan', updates=[del_rr]), h)
            self.assertEqual(rep_del.header.rcode, RCODE.NOERROR)
            self.assertFalse(Record.objects.filter(zone=zone, name='dyn').exists())

    def test_dhcpv4_leasequery_forcerenew_and_dhcpv6_ta_leasequery_reconfigure(self):
        import ipaddress
        import struct
        from datetime import timedelta
        from unittest import mock
        from django.conf import settings
        from django.utils import timezone
        from .dhcp import v4 as dhcp, v6 as dhcp6
        from .models import Dhcp6Lease, DhcpLease

        # 1. DHCPv4 Leasequery (RFC 4388), Failover secs, and authenticated FORCERENEW (RFC 3203 / RFC 3118)
        with override_settings(
            DHCP=True, DHCP_SERVER='192.168.1.2', DHCP_NETMASK='255.255.255.0',
            DHCP_RANGE='192.168.1.100-192.168.1.110', DHCP_ROUTER='192.168.1.1', DHCP_FAILOVER_SECS=4,
        ):
            srv4 = dhcp.Server(dhcp.scopes(settings), probe=lambda ip: False)
            now = timezone.now()
            DhcpLease.objects.create(client='aa:bb:cc:dd:ee:01', ip='192.168.1.100', mac='aa:bb:cc:dd:ee:01', hostname='laptop', expires=now + timedelta(hours=1))

            # Standby failover: DISCOVER with secs=0 ignored, secs=4 answered
            disc_head = lambda secs: (
                struct.pack('!BBBBIHH4s4s4s4s', 1, 1, 6, 0, 0x55, secs, 0, b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4)
                + bytes.fromhex('aabbccddeeff').ljust(16, b'\0') + b'\0' * 192 + dhcp.MAGIC + bytes([53, 1, dhcp.DISCOVER, 255])
            )
            self.assertIsNone(srv4.handle(disc_head(0)))
            self.assertIsNotNone(srv4.handle(disc_head(4)))

            def lq_pkt(ciaddr='0.0.0.0', mac=b'\0' * 6, htype=0, hlen=0, giaddr='192.168.1.1', extra_opts=b''):
                head = struct.pack('!BBBBIHH4s4s4s4s', 1, htype, hlen, 0, 0x1234, 0, 0,
                                   ipaddress.IPv4Address(ciaddr).packed, b'\0' * 4, b'\0' * 4, ipaddress.IPv4Address(giaddr).packed)
                return head + mac.ljust(16, b'\0') + b'\0' * 192 + dhcp.MAGIC + bytes([53, 1, dhcp.DHCPLEASEQUERY]) + extra_opts + b'\xff'

            rep_active = srv4.handle(lq_pkt(ciaddr='192.168.1.100'))
            self.assertIsNotNone(rep_active)
            parsed_active = dhcp.parse(b'\x01' + rep_active.data[1:])
            self.assertEqual(parsed_active['opts'][53][0], dhcp.DHCPLEASEACTIVE)
            self.assertEqual(parsed_active['opts'][12], b'laptop')

            rep_unassigned = srv4.handle(lq_pkt(ciaddr='192.168.1.105'))
            self.assertEqual(dhcp.parse(b'\x01' + rep_unassigned.data[1:])['opts'][53][0], dhcp.DHCPLEASEUNASSIGNED)

            rep_unknown = srv4.handle(lq_pkt(ciaddr='192.168.1.50'))
            self.assertEqual(dhcp.parse(b'\x01' + rep_unknown.data[1:])['opts'][53][0], dhcp.DHCPLEASEUNKNOWN)

            k4 = dhcp.reconf_key('aa:bb:cc:dd:ee:01')
            fr = dhcp.forcerenew_packet('192.168.1.2', 'aa:bb:cc:dd:ee:01', xid=99, key=k4)
            self.assertEqual(dhcp.parse(b'\x01' + fr[1:])['opts'][53][0], dhcp.FORCERENEW)
            self.assertTrue(dhcp.verify_forcerenew(fr, k4))
            self.assertFalse(dhcp.verify_forcerenew(fr, b'0' * 16))

        # 2. DHCPv6 IA_TA, Preference, Reconfigure HMAC-MD5 auth, IA_PD routes, and Leasequery (RFC 5007)
        with override_settings(
            DHCP6=True, DHCP6_PREFIX='2001:db8:1::/64', DHCP6_POOL='2001:db8:1::10-2001:db8:1::20',
            DHCP6_PD_POOL='2001:db8:ff00::/48', DHCP6_PD_LEN=56, DHCP6_PD_ROUTES=True, DHCP6_PREFERENCE=255,
            DHCP6_DNS='2001:db8:1::2', DHCP_SERVER='192.168.1.2', DHCP_INTERFACE='eth0',
        ):
            srv6 = dhcp6.Server6(dhcp6.Config6.from_settings(settings, ['corp.lan']))
            c_duid = b'\x00\x03\x00\x01\xaa\xbb\xcc\xdd\xee\x01'
            sol_ta = (
                bytes([dhcp6.SOLICIT, 1, 2, 3])
                + dhcp6.option(dhcp6.CLIENTID, c_duid)
                + dhcp6.option(dhcp6.IA_TA, struct.pack('!I', 7))
                + dhcp6.option(dhcp6.RECONF_ACCEPT, b'')
            )
            adv = srv6.handle(sol_ta)
            _, _, adv_opts = dhcp6.parse(adv)
            self.assertIn(dhcp6.IA_TA, adv_opts)
            self.assertIn(dhcp6.RECONF_ACCEPT, adv_opts)
            self.assertEqual(adv_opts[dhcp6.PREFERENCE], [b'\xff'])
            self.assertTrue(Dhcp6Lease.objects.filter(duid=c_duid.hex(), iaid=7, kind='ta').exists())

            # REQUEST with IA_PD installs kernel route via peer_ip and returns Reconfigure Key (AUTH option 11)
            req_pd = (
                bytes([dhcp6.REQUEST, 2, 3, 4])
                + dhcp6.option(dhcp6.CLIENTID, c_duid)
                + dhcp6.option(dhcp6.SERVERID, srv6.duid)
                + dhcp6.option(dhcp6.IA_PD, struct.pack('!III', 9, 0, 0))
                + dhcp6.option(dhcp6.RECONF_ACCEPT, b'')
            )
            with mock.patch('zones.dhcp.v6.subprocess.run') as run_mock:
                run_mock.return_value = SimpleNamespace(returncode=0)
                rep_pd = srv6.handle(req_pd, peer_ip='fe80::1234%eth0')
                run_mock.assert_called_once()
                self.assertIn('fe80::1234', run_mock.call_args[0][0])
            _, _, rep_opts = dhcp6.parse(rep_pd)
            self.assertIn(dhcp6.AUTH, rep_opts)
            client_key = rep_opts[dhcp6.AUTH][0][12:]
            self.assertEqual(client_key, dhcp.reconf_key(c_duid.hex()))

            # Leasequery by ClientID (RFC 5007)
            lq_opt = bytes([dhcp6.QUERY_BY_CLIENTID]) + b'\x00' * 16 + dhcp6.option(dhcp6.CLIENTID, c_duid)
            lq_msg = bytes([dhcp6.LEASEQUERY, 4, 5, 6]) + dhcp6.option(dhcp6.CLIENTID, b'\x00\x01\x00\x01relay') + dhcp6.option(dhcp6.LQ_QUERY, lq_opt)
            lq_rep = srv6.handle(lq_msg)
            kind6, _, lq_ropts = dhcp6.parse(lq_rep)
            self.assertEqual(kind6, dhcp6.LEASEQUERY_REPLY)
            self.assertIn(dhcp6.CLIENT_DATA, lq_ropts)

            reconf = dhcp6.reconfigure_msg(srv6.duid, c_duid, dhcp6.RENEW, key=client_key)
            self.assertEqual(reconf[0], dhcp6.RECONFIGURE)
            self.assertTrue(dhcp6.verify_reconfigure(reconf, client_key))
            self.assertFalse(dhcp6.verify_reconfigure(reconf, b'0' * 16))

    def test_domain_stat_rollup_and_dhcp_settings_api(self):
        from django.contrib.auth.models import User
        from django.core.cache import cache
        from rest_framework.test import APIClient
        from .dhcp import v4 as dhcp
        from .stats import rollup
        from .models import DhcpLease, DomainStat, QueryLog

        api = APIClient()
        api.force_authenticate(User.objects.create_user('adm', is_staff=True, is_superuser=True))

        # 1. DomainStat rollup, grouped query log acceleration, and young-domain suggestion signal
        e1 = QueryLog.objects.create(name='a.fast.example.com', domain='example.com', type='A', outcome='forwarded', client='10.0.0.1', ms=12, rcode='NOERROR', answers=[{'name': 'a.fast.example.com', 'type': 'A', 'value': '93.184.216.34', 'ttl': 60}])
        e2 = QueryLog.objects.create(name='b.fast.example.com', domain='example.com', type='AAAA', outcome='blocked', client='10.0.0.2', ms=2, rcode='NXDOMAIN', answers=[])
        e3 = QueryLog.objects.create(name='app.newlyreg.example', domain='newlyreg.example', type='A', outcome='forwarded', client='10.0.0.1', ms=5, rcode='NOERROR', answers=[])
        rollup.add([e1, e2, e3])
        ds = DomainStat.objects.get(domain='example.com')
        self.assertEqual((ds.n, ds.forwarded, ds.blocked, ds.ms), (2, 1, 1, 14))

        res = api.get('/api/logs/grouped/?by=domain&ordering=count&hours=24')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['results'][0]['name'], 'example.com')
        self.assertEqual(res.json()['results'][0]['count'], 2)

        res_last = api.get('/api/logs/grouped/?by=domain&ordering=last&hours=24')
        self.assertEqual(res_last.status_code, 200)
        self.assertEqual(len(res_last.json()['results']), 2)

        cache.set('dom-age:newlyreg.example', 5, 3600)
        sug = api.get('/api/blocked/suggestions/?days=7').json()
        self.assertIn('app.newlyreg.example', [s['name'] for s in sug])

        # 2. DHCP settings GET and PATCH API + validation + GUI-enabled DNS lease names
        get_res = api.get('/api/dhcp/settings/')
        self.assertEqual(get_res.status_code, 200)
        self.assertIn('DHCP_LEASE', get_res.json())

        bad_patch = api.patch('/api/dhcp/settings/', {'DHCP': True, 'DHCP_SERVER': '192.168.1.2', 'DHCP_RANGE': '10.0.0.10-10.0.0.20'}, format='json')
        self.assertEqual(bad_patch.status_code, 400)

        ok_patch = api.patch('/api/dhcp/settings/', {
            'DHCP': True,
            'DHCP_SERVER': '192.168.1.2',
            'DHCP_NETMASK': '255.255.255.0',
            'DHCP_RANGE': '192.168.1.100-192.168.1.200',
            'DHCP_DOMAIN': 'home.lan',
            'DHCP_NAMES': True,
        }, format='json')
        self.assertEqual(ok_patch.status_code, 200)
        self.assertEqual(ok_patch.json()['DHCP_DOMAIN'], 'home.lan')
        from datetime import timedelta
        from django.utils import timezone
        DhcpLease.objects.create(client='c1', ip='192.168.1.150', mac='aa:bb:cc:dd:ee:11', hostname='printer', expires=timezone.now() + timedelta(hours=1))
        self.assertEqual(dhcp.lease_hosts('printer.home.lan'), [('192.168.1.150', 60)])
        self.assertEqual(dhcp.lease_ptr('150.1.168.192.in-addr.arpa'), 'printer.home.lan')






class HotPathTests(TestCase):
    """What the DNS daemon does per query once warm, and the API paths that used to be slow."""

    def setUp(self):
        resolver._data = None
        resolver._blocked.clear()

    @override_settings(DHCP=False, DNS_CACHE=False, DNS_DNSSEC=False, SUSPICIOUS_MODE='off', DNS_RATE_LIMIT=0)
    def test_warm_forwarded_query_reads_no_database(self):
        from unittest import mock
        Zone.objects.create(name='lan')
        r = Resolver('127.0.0.1:9', log=SimpleNamespace(add=lambda e: None))
        h = SimpleNamespace(client_address=('127.0.0.1', 0))
        send = lambda pkt, *a, **k: pkt.reply().pack()
        with mock.patch.object(DNSRecord, 'send', new=send):
            r.resolve(DNSRecord.question('www.example.com', 'A'), h)  # loads the data, asks the blacklist once
            with self.assertNumQueries(0):  # no Setting read for the DHCP names, no ping, no blacklist query
                r.resolve(DNSRecord.question('www.example.com', 'A'), h)

    def test_longest_zone_wins(self):
        Zone.objects.create(name='lan')
        z = Zone.objects.create(name='b.lan')
        Record.objects.create(zone=z, name='a', type='A', value='10.0.0.9')
        self.assertEqual(resolver._zone_of('a.b.lan', resolver._snapshot()[0]), ('b.lan', 'a'))
        self.assertEqual(resolver._zone_of('b.lan', resolver._snapshot()[0]), ('b.lan', '@'))
        self.assertEqual(resolver._zone_of('x.lan', resolver._snapshot()[0]), ('lan', 'x'))
        self.assertIsNone(resolver._zone_of('example.com', resolver._snapshot()[0]))
        self.assertEqual(resolver.lookup('a.b.lan', 'A')[0][0].value, '10.0.0.9')

    def test_blacklist_memory_drops_the_least_recently_used(self):
        from unittest import mock
        with mock.patch.object(resolver, '_BLOCKED_MAX', 2):
            resolver._remember_blocked('a', None)
            resolver._remember_blocked('b', None)
            resolver._blocked.move_to_end('a')  # 'a' asked again
            resolver._remember_blocked('c', None)
        self.assertEqual(list(resolver._blocked), ['a', 'c'])

    def test_dnskeys_are_fetched_once_per_ttl(self):
        from unittest import mock
        from dnslib import DNSKEY, RR
        r = Resolver('127.0.0.1:9', log=None)
        key = RR('example.com.', QTYPE.DNSKEY, rdata=DNSKEY(257, 3, 13, b'\x01' * 64), ttl=300)

        def ask(q, validate_dnssec=True):
            rep = q.reply()
            rep.add_answer(key)
            return rep, 'x'
        with mock.patch.object(r, 'ask_upstream', side_effect=ask) as up:
            self.assertEqual(len(r._fetch_dnskeys('example.com')), 1)
            self.assertEqual(len(r._fetch_dnskeys('example.com')), 1)
        self.assertEqual(up.call_count, 1)

    def test_grouped_by_name_from_counters(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        from .models import QueryLog
        from .stats import rollup
        rows = [QueryLog.objects.create(name=n, domain='example.com', type='A', outcome='forwarded', client='10.0.0.1', ms=1) for n in ('a.example.com', 'a.example.com', 'b.example.com')]
        rollup.add(rows)
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('g', is_staff=True))
        res = api.get('/api/logs/grouped/?by=name&ordering=count&hours=24')
        self.assertEqual(res.status_code, 200)
        self.assertEqual([(g['name'], g['count']) for g in res.json()['results']], [('a.example.com', 2), ('b.example.com', 1)])

    def test_geolocation_counts_queries_not_addresses(self):
        from django.contrib.auth import get_user_model
        from django.core.cache import cache
        from rest_framework.test import APIClient
        from .models import QueryLog
        from .stats import rollup
        four = [{'name': 'cdn.example.com', 'type': 'A', 'value': f'93.184.216.{i}', 'ttl': 60} for i in range(4)]
        rows = [QueryLog.objects.create(name='cdn.example.com', domain='example.com', type='A', outcome='forwarded', client='10.0.0.1', ms=1, answers=four),
                QueryLog.objects.create(name='nx.example.com', domain='example.com', type='A', outcome='forwarded', client='10.0.0.1', ms=1, answers=[])]
        rollup.add(rows)
        cache.delete('geo-dest-24')
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('geo', is_staff=True))
        with override_settings(GEOIP_ONLINE_FALLBACK=False):
            self.assertEqual(api.get('/api/geo/destinations/?hours=24').json()['scanned'], 1)  # one query with an address, not four
