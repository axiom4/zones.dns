from types import SimpleNamespace

from dnslib import DNSRecord, QTYPE
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
