"""Dynamic DNS Updates (RFC 2136) for authoritative zones (OPCODE.UPDATE = 5).

Every UPDATE must be signed with TSIG (RFC 8945, keys in settings.DNS_UPDATE_KEYS, see tsig.py): an IP address can be forged over UDP, and
DoH / DoT clients all reach the daemon from 127.0.0.1. settings.DNS_UPDATE_ALLOW (IP addresses or CIDR networks, comma separated) narrows down
who may send them as well. No key = UPDATE refused. The message is applied whole or not at all (RFC 2136 §3.4).
"""
import ipaddress

from django.conf import settings
from django.db import transaction
from dnslib import QTYPE, RCODE

from ..models import RECORD_TYPES, DataVersion, Record, Zone, build_rr
from . import tsig

CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255


def _client_allowed(client_ip):
    """Return True if client_ip matches any entry in settings.DNS_UPDATE_ALLOW."""
    allow_raw = getattr(settings, 'DNS_UPDATE_ALLOW', '') or ''
    if not allow_raw:
        return True  # no address list: the TSIG key alone decides
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip.split('%')[0])
    except ValueError:
        return False
    for entry in allow_raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '/' in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _rel_name(rname, zone_name):
    """Convert an FQDN DNSLabel into the relative record name used by Zone (`@` or subdomain)."""
    fqdn = str(rname).rstrip('.').lower()
    z = zone_name.rstrip('.').lower()
    if fqdn == z:
        return '@'
    suffix = '.' + z
    if fqdn.endswith(suffix):
        return fqdn[:-len(suffix)]
    return None


def _rdata_to_value(rr):
    """Convert a dnslib RR rdata into the string format stored in Record.value."""
    rtype = QTYPE.get(rr.rtype, '')
    rd = rr.rdata
    if rtype in ('A', 'AAAA', 'CNAME', 'NS', 'PTR'):
        return str(rd).rstrip('.')
    if rtype == 'TXT':
        if hasattr(rd, 'data') and rd.data:
            return b''.join(rd.data).decode('utf-8', errors='replace')
        return str(rd).strip('"')
    return str(rd)


class _Abort(Exception):
    """Stops an UPDATE with this rcode; raised inside the transaction, so what was already changed is rolled back."""
    def __init__(self, rcode):
        super().__init__(rcode)
        self.rcode = rcode


def handle_update(request, client_ip, wire=None):
    """Process an RFC 2136 UPDATE message and return a DNSRecord response. wire: the bytes received (the TSIG MAC covers them)."""
    reply = request.reply()
    reply.rr = []
    reply.auth = []
    reply.ar = []

    # RFC 2136 §3.1: Zone Section must have exactly 1 record of type SOA
    if len(request.questions) != 1 or request.q.qtype != QTYPE.SOA or request.q.qclass != CLASS_IN:
        reply.header.rcode = RCODE.FORMERR
        return reply

    # who is asking, before anything about the zones is told (NOTAUTH / NOTZONE would list them)
    if not tsig.keys() or not _client_allowed(client_ip):
        reply.header.rcode = RCODE.REFUSED
        return reply
    try:
        key, alg, mac = tsig.verify(wire or b'')
    except tsig.TsigError:
        reply.header.rcode = RCODE.NOTAUTH  # RFC 8945 §5.2: unsigned or badly signed
        return reply

    zname = str(request.q.qname).rstrip('.').lower()
    zone = Zone.objects.filter(name__iexact=zname, enabled=True).first()
    try:
        if not zone:
            raise _Abort(RCODE.NOTAUTH)
        with transaction.atomic():
            _apply(request, zone)
        reply.header.rcode = RCODE.NOERROR
    except _Abort as e:
        reply.header.rcode = e.rcode
    reply.wire = tsig.sign(reply.pack(), key, alg, mac)
    return reply


def _apply(request, zone):
    """Prerequisites, then updates; raises _Abort (the caller's transaction rolls back) at the first failure."""
    # 1. Prerequisite Section (carried in the Answer section `request.rr`, RFC 2136 §3.2; failure codes of §3.2.5)
    for pre in request.rr:
        rel = _rel_name(pre.rname, zone.name)
        if rel is None:
            raise _Abort(RCODE.NOTZONE)
        rtype = QTYPE.get(pre.rtype, '')
        if pre.ttl != 0:
            raise _Abort(RCODE.FORMERR)
        if pre.rclass == CLASS_ANY:
            if pre.rtype == QTYPE.ANY:  # name is in use
                if not Record.objects.filter(zone=zone, name=rel).exists():
                    raise _Abort(RCODE.NXDOMAIN)
            elif not Record.objects.filter(zone=zone, name=rel, type=rtype).exists():  # RRset exists (value independent)
                raise _Abort(RCODE.NXRRSET)
        elif pre.rclass == CLASS_NONE:
            if pre.rtype == QTYPE.ANY:  # name is not in use
                if Record.objects.filter(zone=zone, name=rel).exists():
                    raise _Abort(RCODE.YXDOMAIN)
            elif Record.objects.filter(zone=zone, name=rel, type=rtype).exists():  # RRset does not exist
                raise _Abort(RCODE.YXRRSET)
        elif pre.rclass == CLASS_IN:  # RRset exists (value dependent)
            if not Record.objects.filter(zone=zone, name=rel, type=rtype, value=_rdata_to_value(pre)).exists():
                raise _Abort(RCODE.NXRRSET)
        else:
            raise _Abort(RCODE.FORMERR)

    # 2. Update Section (carried in the Authority section `request.auth`, RFC 2136 §3.4)
    changed = False
    for upd in request.auth:
        rel = _rel_name(upd.rname, zone.name)
        if rel is None:
            raise _Abort(RCODE.NOTZONE)
        rtype = QTYPE.get(upd.rtype, '')
        if upd.rclass == CLASS_IN:
            # Add to an RRset
            if rtype not in RECORD_TYPES:
                raise _Abort(RCODE.FORMERR)
            val = _rdata_to_value(upd)
            ttl = int(upd.ttl) or 300  # the column has no NULL: a TTL of 0 took the default
            try:  # the same check as the API: a record the daemon cannot build would fail every query for its name
                if len(rel) > 253 or len(val) > 1024:
                    raise ValueError('too long')
                build_rr(zone.name, rel, rtype, val, ttl or 0)
            except Exception:
                raise _Abort(RCODE.FORMERR)
            if rtype == 'CNAME':
                Record.objects.filter(zone=zone, name=rel, type='CNAME').delete()
            rec, created = Record.objects.get_or_create(zone=zone, name=rel, type=rtype, value=val, defaults={'ttl': ttl})
            if not created and rec.ttl != ttl:
                rec.ttl = ttl
                rec.save(update_fields=['ttl'])
            changed = True
        elif upd.rclass == CLASS_ANY:
            # Delete an RRset or all RRsets from a name
            qs = Record.objects.filter(zone=zone, name=rel) if upd.rtype == QTYPE.ANY else Record.objects.filter(zone=zone, name=rel, type=rtype)
            changed = qs.delete()[0] > 0 or changed
        elif upd.rclass == CLASS_NONE:
            # Delete a specific RR from an RRset
            changed = Record.objects.filter(zone=zone, name=rel, type=rtype, value=_rdata_to_value(upd)).delete()[0] > 0 or changed
        else:
            raise _Abort(RCODE.FORMERR)
    if changed:
        DataVersion.bump()
