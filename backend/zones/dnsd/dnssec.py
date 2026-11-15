"""DNSSEC validation (RFC 4034, RFC 4035, RFC 5155, RFC 6605, RFC 8080).

Validates RRSIG records in DNS responses against DNSKEY records, and verifies
DNSKEY records against DS records or configured trust anchors.
Supported algorithms:
- 8: RSA/SHA-256 (RSASHA256)
- 10: RSA/SHA-512 (RSASHA512)
- 13: ECDSA Curve P-256 with SHA-256 (ECDSAP256SHA256)
- 14: ECDSA Curve P-384 with SHA-384 (ECDSAP384SHA384)
- 15: Ed25519 (ED25519)
Supported DS digest types:
- 1: SHA-1
- 2: SHA-256
- 4: SHA-384
"""
import hashlib
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from dnslib import DNSBuffer, DNSLabel, QTYPE

# IANA root KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696) DS digests
ROOT_TRUST_ANCHORS = [
    (20326, 8, 2, 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D'),
    (38696, 8, 2, '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16'),
]


def _canonical_name_wire(label):
    """RFC 4034 §6.1 canonical wire format of a domain name (lowercase, uncompressed)."""
    if isinstance(label, str):
        label = DNSLabel(label)
    parts = [bytes(p).lower() for p in label.label]
    return b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'


def key_tag(flags, protocol, algorithm, key_bytes):
    """RFC 4034 Appendix B key tag calculation for a DNSKEY RDATA."""
    rdata = struct.pack('!HBB', flags, protocol, algorithm) + key_bytes
    if algorithm == 1:
        return struct.unpack('!H', rdata[-3:-1])[0] if len(rdata) >= 3 else 0
    ac = 0
    for i, b in enumerate(rdata):
        ac += (b << 8) if (i & 1) == 0 else b
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def verify_ds(owner, flags, protocol, algorithm, key_bytes, ds_key_tag, ds_algo, digest_type, digest_hex):
    """Verify that a DNSKEY matches a DS record (RFC 4034 §5.1.4)."""
    if key_tag(flags, protocol, algorithm, key_bytes) != ds_key_tag or algorithm != ds_algo:
        return False
    rdata = struct.pack('!HBB', flags, protocol, algorithm) + key_bytes
    msg = _canonical_name_wire(owner) + rdata
    h_fn = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}.get(digest_type)
    if not h_fn:
        return False
    return h_fn(msg).hexdigest().upper() == digest_hex.strip().upper()


def _rdata_canonical_wire(rr):
    """RFC 4034 §6.2 canonical RDATA wire format (lowercasing embedded domain names for known types)."""
    b = DNSBuffer()
    if rr.rtype in (QTYPE.NS, QTYPE.CNAME, QTYPE.DNAME, QTYPE.PTR):
        b.encode_name_nocompress(DNSLabel(str(rr.rdata.label).lower()))
        return bytes(b.data)
    if rr.rtype == QTYPE.MX:
        b.pack('!H', rr.rdata.preference)
        b.encode_name_nocompress(DNSLabel(str(rr.rdata.label).lower()))
        return bytes(b.data)
    if rr.rtype == QTYPE.SRV:
        b.pack('!HHH', rr.rdata.priority, rr.rdata.weight, rr.rdata.port)
        b.encode_name_nocompress(DNSLabel(str(rr.rdata.target).lower()))
        return bytes(b.data)
    if rr.rtype == QTYPE.SOA:
        b.encode_name_nocompress(DNSLabel(str(rr.rdata.mname).lower()))
        b.encode_name_nocompress(DNSLabel(str(rr.rdata.rname).lower()))
        b.pack('!IIIII', *rr.rdata.times)
        return bytes(b.data)
    rr.rdata.pack(b)
    return bytes(b.data)


def _rrset_wire(rrset, rrsig_rdata):
    """Build the RFC 4034 §3.1.8.1 signed data buffer: RRSIG_RDATA_prefix || canonical sorted RRset."""
    signer_wire = _canonical_name_wire(rrsig_rdata.name)  # not `name or ...`: the root ('.') is an empty, so false, DNSLabel
    prefix = struct.pack(
        '!HBBIIIH',
        rrsig_rdata.covered,
        rrsig_rdata.algorithm,
        rrsig_rdata.labels,
        rrsig_rdata.orig_ttl,
        rrsig_rdata.sig_exp,
        rrsig_rdata.sig_inc,
        rrsig_rdata.key_tag,
    ) + signer_wire

    owner_labels = [bytes(p).lower() for p in rrset[0].rname.label]
    if len(owner_labels) > rrsig_rdata.labels:
        # Wildcard expansion per RFC 4035 §5.3.2
        owner_labels = [b'*'] + owner_labels[len(owner_labels) - rrsig_rdata.labels:]
    owner_wire = b''.join(bytes([len(p)]) + p for p in owner_labels) + b'\x00'

    encoded_rdatas = sorted(_rdata_canonical_wire(rr) for rr in rrset)
    rr_wires = []
    for rdata_bytes in encoded_rdatas:
        rr_wires.append(
            owner_wire
            + struct.pack('!HHIH', rrset[0].rtype, rrset[0].rclass, rrsig_rdata.orig_ttl, len(rdata_bytes))
            + rdata_bytes
        )
    return prefix + b''.join(rr_wires)


def _load_public_key(algorithm, key_bytes):
    """Parse DNSKEY public key bytes into a cryptography public key object."""
    if algorithm in (8, 10):  # RSA/SHA-256, RSA/SHA-512 (RFC 3110)
        if not key_bytes:
            return None
        exp_len = key_bytes[0]
        offset = 1
        if exp_len == 0:
            if len(key_bytes) < 3:
                return None
            exp_len = struct.unpack('!H', key_bytes[1:3])[0]
            offset = 3
        if len(key_bytes) <= offset + exp_len:
            return None
        e = int.from_bytes(key_bytes[offset:offset + exp_len], 'big')
        n = int.from_bytes(key_bytes[offset + exp_len:], 'big')
        return rsa.RSAPublicNumbers(e, n).public_key()
    if algorithm == 13 and len(key_bytes) == 64:  # ECDSA P-256 (RFC 6605)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + key_bytes)
    if algorithm == 14 and len(key_bytes) == 96:  # ECDSA P-384 (RFC 6605)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), b'\x04' + key_bytes)
    if algorithm == 15 and len(key_bytes) == 32:  # Ed25519 (RFC 8080)
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    return None


def verify_rrsig(rrset, rrsig_rr, dnskey_rrs, now=None):
    """Verify an RRSIG record over `rrset` using one of `dnskey_rrs`.

    Returns True if a matching DNSKEY cryptographically validates `rrsig_rr`, else False.
    """
    if not rrset or rrsig_rr.rtype != QTYPE.RRSIG:
        return False
    sig = rrsig_rr.rdata
    now = int(time.time()) if now is None else int(now)
    if not (sig.sig_inc <= now <= sig.sig_exp):
        return False

    signed_data = _rrset_wire(rrset, sig)
    sig_bytes = bytes(sig.sig)

    for krr in dnskey_rrs:
        if krr.rtype != QTYPE.DNSKEY:
            continue
        kd = krr.rdata
        if kd.protocol != 3 or kd.algorithm != sig.algorithm or not (kd.flags & 0x0100):
            continue
        raw_key = bytes(kd.key)
        if key_tag(kd.flags, kd.protocol, kd.algorithm, raw_key) != sig.key_tag:
            continue
        pub = _load_public_key(kd.algorithm, raw_key)
        if pub is None:
            continue
        try:
            if kd.algorithm == 8:
                pub.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
                return True
            if kd.algorithm == 10:
                pub.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA512())
                return True
            if kd.algorithm in (13, 14):
                half = 32 if kd.algorithm == 13 else 48
                if len(sig_bytes) != half * 2:
                    continue
                r = int.from_bytes(sig_bytes[:half], 'big')
                s = int.from_bytes(sig_bytes[half:], 'big')
                der_sig = encode_dss_signature(r, s)
                hash_alg = hashes.SHA256() if kd.algorithm == 13 else hashes.SHA384()
                pub.verify(der_sig, signed_data, ec.ECDSA(hash_alg))
                return True
            if kd.algorithm == 15:
                pub.verify(sig_bytes, signed_data)
                return True
        except (InvalidSignature, ValueError):
            continue
    return False


def _name(label):
    """A name as text, lower case, without the final dot ('' = the root)."""
    return str(label).rstrip('.').lower()


def _within(name, zone):
    return zone == '' or name == zone or name.endswith('.' + zone)


def _signed_by(rrset, rrsigs, keys, now):
    """True if one of rrsigs (RRSIG records over rrset) verifies with one of keys."""
    return any(verify_rrsig(rrset, sig, keys, now=now) for sig in rrsigs)


class Validator:
    """The chain of trust (RFC 4035 §5): the keys of a zone are trusted only when its DNSKEY RRset is signed by a key that matches a DS
    record of the parent, itself signed by the parent's trusted keys, up to the root trust anchors. Keys found in an answer are never
    trusted by themselves (anyone forging an answer can add a key of their own).

    ask(name, qtype) -> DNSRecord or None: asks the upstream with DO=1. A zone without DS at its parent is 'insecure': its data is
    passed on without AD. shortcut: the absence of the DS is not proven (no NSEC/NSEC3 check), so a forged "no DS" makes a signed zone
    look unsigned (AD=0) instead of bogus; upgrade with NSEC/NSEC3 denial proofs if downgrade protection is needed.
    """
    MAX_DEPTH = 16

    def __init__(self, ask, anchors=ROOT_TRUST_ANCHORS):
        self.ask, self.anchors, self.cache = ask, anchors, {}  # zone -> (monotonic expiry, state, keys)

    def keys(self, zone, now=None, depth=0):
        """(state, trusted DNSKEY records) of zone ('' = root): 'secure', 'insecure' or 'bogus'."""
        mono = time.monotonic()
        hit = self.cache.get(zone)
        if hit and hit[0] > mono:
            return hit[1], hit[2]
        state, keys, ttl = self._keys(zone, now, depth)
        if state != 'bogus' or keys is not None:  # a failure to ask (None keys) is asked again next time
            if len(self.cache) > 1000:
                self.cache.clear()
            self.cache[zone] = (mono + min(3600, max(30, ttl)), state, keys or [])
        return state, keys or []

    def _keys(self, zone, now, depth):
        if depth > self.MAX_DEPTH:
            return 'bogus', None, 0
        rep = self.ask(zone or '.', 'DNSKEY')
        if rep is None:
            return 'bogus', None, 0
        dnskeys = [rr for rr in rep.rr if rr.rtype == QTYPE.DNSKEY and _name(rr.rname) == zone]
        sigs = [rr for rr in rep.rr if rr.rtype == QTYPE.RRSIG and rr.rdata.covered == QTYPE.DNSKEY and _name(rr.rname) == zone]
        if zone == '':
            ds = self.anchors
            ttl = 3600
        else:
            drep = self.ask(zone, 'DS')
            if drep is None:
                return 'bogus', None, 0
            ds_rrs = [rr for rr in drep.rr if rr.rtype == QTYPE.DS and _name(rr.rname) == zone]
            if not ds_rrs:
                return 'insecure', [], 300  # no DS at the parent: an unsigned delegation (not proven, see the class docstring)
            ds_sigs = [rr for rr in drep.rr if rr.rtype == QTYPE.RRSIG and rr.rdata.covered == QTYPE.DS and _name(rr.rname) == zone]
            parents = {_name(sig.rdata.name) for sig in ds_sigs}
            for parent in parents:
                if parent == zone or not _within(zone, parent):
                    continue  # the DS is signed by the parent, a zone above this one
                pstate, pkeys = self.keys(parent, now, depth + 1)
                if pstate == 'insecure':
                    return 'insecure', [], 300
                if pstate == 'secure' and _signed_by(ds_rrs, [s for s in ds_sigs if _name(s.rdata.name) == parent], pkeys, now):
                    break
            else:
                return 'bogus', [], 60
            ds = [(rr.rdata.key_tag, rr.rdata.algorithm, rr.rdata.digest_type, bytes(rr.rdata.digest).hex()) for rr in ds_rrs]
            ttl = min(rr.ttl for rr in ds_rrs)
        ksk = [k for k in dnskeys if any(verify_ds(zone + '.' if zone else '.', k.rdata.flags, k.rdata.protocol, k.rdata.algorithm, bytes(k.rdata.key), *d)
                                         for d in ds)]
        if not ksk or not _signed_by(dnskeys, sigs, ksk, now):
            return 'bogus', [], 60
        return 'secure', dnskeys, min([ttl] + [rr.ttl for rr in dnskeys])


def validate_reply(reply, validator, now=None):
    """Validate the RRSIGs in `reply.rr` (or `reply.auth` on negative responses) through the chain of trust.

    Returns:
      - 'secure'   if every RRset of the section is signed by trusted keys of a zone that contains it.
      - 'insecure' if there are no RRSIGs, a signer zone is an unsigned delegation, or some RRset is not signed.
      - 'bogus'    if an RRSIG fails, the signer does not contain the name, or the signer's keys do not chain to the root.
    """
    section = reply.rr if any(rr.rtype == QTYPE.RRSIG for rr in reply.rr) else reply.auth
    rrsigs = [rr for rr in section if rr.rtype == QTYPE.RRSIG]
    if not rrsigs:
        return 'insecure'
    covered, insecure = set(), False
    for rrsig in rrsigs:
        owner, signer = _name(rrsig.rname), _name(rrsig.rdata.name)
        rrset = [rr for rr in section if rr.rname == rrsig.rname and rr.rtype == rrsig.rdata.covered]
        if not rrset or not _within(owner, signer):
            return 'bogus'  # a signature with nothing under it, or a zone signing names that are not its own
        state, keys = validator.keys(signer, now)
        if state == 'bogus':
            return 'bogus'
        if state == 'insecure':
            insecure = True
            continue
        if not verify_rrsig(rrset, rrsig, keys, now=now):
            return 'bogus'
        covered.add((owner, rrsig.rdata.covered))
    rrsets = {(_name(rr.rname), rr.rtype) for rr in section if rr.rtype not in (QTYPE.RRSIG, QTYPE.OPT)}
    return 'insecure' if insecure or not rrsets <= covered else 'secure'
