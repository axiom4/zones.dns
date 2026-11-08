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
