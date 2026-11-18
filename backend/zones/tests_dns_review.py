"""Regression tests for the DNS daemon review: upstream exchanges, truncation, DNSSEC verdicts, DNS UPDATE apex and prerequisites."""
import socket
import threading
import time
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from dnslib import NS, QTYPE, RCODE, RD, RR, SOA, TXT, A, DNSRecord, EDNS0

from .dnsd import ddns, dnssec, resolver
from .models import Record, Zone
from .tests import DnssecPki


class UpstreamExchangeTests(SimpleTestCase):
    def test_tcp_answer_cut_short_raises_instead_of_spinning(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)

        def serve():
            c, _ = srv.accept()
            c.recv(1024)
            c.sendall(b'\x00\x40abc')  # announces 64 bytes, sends 3, closes
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        t0 = time.monotonic()
        with self.assertRaises(ConnectionError):
            resolver._tcp_exchange(b'\x12\x34q', '127.0.0.1', srv.getsockname()[1], 3)
        self.assertLess(time.monotonic() - t0, 2)
        srv.close()

    @override_settings(DNS_DNSSEC=False, DNS_UPSTREAM_DOWN=30)
    def test_unreadable_answer_does_not_mark_the_upstream_down(self):
        r = resolver.Resolver('127.0.0.1:9')
        with mock.patch.object(resolver, '_udp_exchange', side_effect=lambda wire, *a: wire[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xff'):
            _, used = r.ask_upstream(DNSRecord.question('example.com'))
        self.assertIsNone(used)
        self.assertEqual(r.down, {})

    @override_settings(DNS_CACHE_NEG_TTL=3600, DNS_CACHE_MAX_TTL=86400, DNS_STALE_TTL=0)
    def test_negative_answer_cached_for_the_soa_minimum(self):
        rep = DNSRecord.question('nope.example.com').reply()
        rep.header.rcode = RCODE.NXDOMAIN
        rep.add_auth(RR('example.com', QTYPE.SOA, rdata=SOA('ns.example.com', 'h.example.com', (1, 2, 3, 4, 60)), ttl=900))
        with mock.patch.object(resolver.cache, 'set') as put:
            resolver.Resolver._store('k', rep)
        self.assertEqual(put.call_args.args[2], 60)


class TruncationTests(SimpleTestCase):
    def test_truncated_udp_answer_keeps_the_question(self):
        q = DNSRecord.question('big.example', 'TXT')
        rep = q.reply()
        for _ in range(3):
            rep.add_answer(RR('big.example', QTYPE.TXT, rdata=TXT('x' * 250)))
        out = resolver.finish(q, rep, SimpleNamespace(protocol='udp'))
        parsed = DNSRecord.parse(out.wire)
        self.assertEqual((parsed.header.tc, len(parsed.rr), parsed.q.qname), (1, 0, q.q.qname))

    def test_nsec_and_rrsig_of_the_authority_go_without_do(self):
        q = DNSRecord.question('a.example')
        q.add_ar(EDNS0(udp_len=1232))
        rep = q.reply()
        rep.add_auth(RR('example', QTYPE.SOA, rdata=SOA('ns.example', 'h.example', (1, 2, 3, 4, 5))))
        rep.add_auth(RR('example', QTYPE.NSEC, rdata=RD(b'\x00\x00')))
        rep.add_auth(RR('example', QTYPE.RRSIG, rdata=RD(b'\x00' * 20)))
        self.assertEqual([QTYPE[rr.rtype] for rr in resolver.finish(q, rep, SimpleNamespace(protocol='tcp')).auth], ['SOA'])


class DnssecVerdictTests(SimpleTestCase):
    def setUp(self):
        self.now = int(time.time())
        self.pki = DnssecPki(self.now)
        self.v = dnssec.Validator(self.pki.ask, anchors=[self.pki.root_ds])

    def test_one_good_signature_is_enough(self):
        rep = self.pki.answer()
        bad = self.pki.sign([rep.rr[0]], self.pki.zone_priv, self.pki.zone_tag, 'example.com.', bad=True)
        rep.add_answer(bad)  # a second signature that fails (key rollover)
        self.assertEqual(dnssec.validate_reply(rep, self.v, now=self.now), 'secure')
        unknown = self.pki.sign([rep.rr[0]], self.pki.zone_priv, self.pki.zone_tag, 'example.com.')
        unknown.rdata.algorithm = 16  # Ed448: not supported, so ignored next to the good one
        rep.add_answer(unknown)
        self.assertEqual(dnssec.validate_reply(rep, self.v, now=self.now), 'secure')

    def test_only_unsupported_algorithms_is_insecure_not_bogus(self):
        rep = self.pki.answer()
        rep.rr[1].rdata.algorithm = 16
        self.assertEqual(dnssec.validate_reply(rep, self.v, now=self.now), 'insecure')

    def test_signed_negative_answer_is_not_secure(self):
        rep = DNSRecord.question('nope.example.com').reply()
        rep.header.rcode = RCODE.NXDOMAIN
        soa = RR('example.com.', QTYPE.SOA, rdata=SOA('ns.example.com', 'h.example.com', (1, 2, 3, 4, 5)), ttl=300)
        rep.add_auth(soa, self.pki.sign([soa], self.pki.zone_priv, self.pki.zone_tag, 'example.com.'))
        self.assertEqual(dnssec.validate_reply(rep, self.v, now=self.now), 'insecure')
        rep.auth[1] = self.pki.sign([soa], self.pki.zone_priv, self.pki.zone_tag, 'example.com.', bad=True)
        self.assertEqual(dnssec.validate_reply(rep, self.v, now=self.now), 'bogus')

    def test_ds_of_unsupported_algorithm_only_is_insecure(self):
        from dnslib import DS
        pki = self.pki

        def ask(name, qtype):
            if (name, qtype) == ('example.com', 'DS'):
                rep = DNSRecord.question(name, qtype).reply()
                d = RR('example.com.', QTYPE.DS, rdata=DS(pki.zone_tag, 16, 2, pki.zone_ds_digest), ttl=300)
                rep.add_answer(d, pki.sign([d], pki.root_priv, pki.root_tag, '.'))
                return rep
            return pki.ask(name, qtype)
        v = dnssec.Validator(ask, anchors=[pki.root_ds])
        self.assertEqual(v.keys('example.com', now=self.now)[0], 'insecure')


class DdnsApexAndPrereqTests(TestCase):
    def setUp(self):
        self.zone = Zone.objects.create(name='corp.lan')
        Record.objects.create(zone=self.zone, name='@', type='NS', value='ns1.corp.lan.')
        Record.objects.create(zone=self.zone, name='@', type='TXT', value='hello')

    def _msg(self, prereqs=(), updates=()):
        req = DNSRecord.question('corp.lan', 'SOA')
        for rr in prereqs:
            req.add_answer(rr)
        for rr in updates:
            req.add_auth(rr)
        return req

    def test_apex_ns_survives_deletes(self):
        ddns._apply(self._msg(updates=[RR('corp.lan', QTYPE.ANY, rclass=ddns.CLASS_ANY, ttl=0, rdata=RD(b''))]), self.zone)
        self.assertEqual(list(Record.objects.filter(zone=self.zone).values_list('type', flat=True)), ['NS'])
        ddns._apply(self._msg(updates=[RR('corp.lan', QTYPE.NS, rclass=ddns.CLASS_NONE, ttl=0, rdata=NS('ns1.corp.lan'))]), self.zone)
        self.assertTrue(Record.objects.filter(zone=self.zone, type='NS').exists())  # the last NS stays

    def test_value_dependent_prerequisite_needs_the_whole_rrset(self):
        Record.objects.create(zone=self.zone, name='h', type='A', value='10.0.0.1')
        Record.objects.create(zone=self.zone, name='h', type='A', value='10.0.0.2')
        one = RR('h.corp.lan', QTYPE.A, rclass=ddns.CLASS_IN, ttl=0, rdata=A('10.0.0.1'))
        with self.assertRaises(ddns._Abort) as e:
            ddns._apply(self._msg(prereqs=[one]), self.zone)
        self.assertEqual(e.exception.rcode, RCODE.NXRRSET)
        two = RR('h.corp.lan', QTYPE.A, rclass=ddns.CLASS_IN, ttl=0, rdata=A('10.0.0.2'))
        ddns._apply(self._msg(prereqs=[one, two]), self.zone)  # the exact RRset: no error


class UpstreamTcpDeadlineTests(SimpleTestCase):
    def test_dripping_upstream_hits_the_deadline(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)

        def serve():
            c, _ = srv.accept()
            c.recv(1024)
            try:
                c.sendall(b'\x00\x40')
                for _ in range(20):
                    time.sleep(0.1)
                    c.sendall(b'x')  # a byte now and then: each read succeeds, the whole answer never comes
            except OSError:
                pass
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        t0 = time.monotonic()
        with self.assertRaises(OSError):  # TimeoutError
            resolver._tcp_exchange(b'\x12\x34q', '127.0.0.1', srv.getsockname()[1], 0.5)
        self.assertLess(time.monotonic() - t0, 1.5)
        srv.close()
