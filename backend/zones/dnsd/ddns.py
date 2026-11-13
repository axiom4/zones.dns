"""Dynamic DNS Updates (RFC 2136) for authoritative zones (OPCODE.UPDATE = 5).

Controlled by settings.DNS_UPDATE_ALLOW (comma-separated list of IP addresses or CIDR networks).
"""
import ipaddress

from django.conf import settings
from django.db import transaction
from dnslib import QTYPE, RCODE

from ..models import DataVersion, Record, Zone

CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255
_SUPPORTED_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'NAPTR', 'PTR', 'CAA', 'SVCB', 'HTTPS', 'TLSA', 'SSHFP'}


def _client_allowed(client_ip):
    """Return True if client_ip matches any entry in settings.DNS_UPDATE_ALLOW."""
    allow_raw = getattr(settings, 'DNS_UPDATE_ALLOW', '') or ''
    if not allow_raw or not client_ip:
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


def handle_update(request, client_ip):
    """Process an RFC 2136 UPDATE message and return a DNSRecord response."""
    reply = request.reply()
    reply.rr = []
    reply.auth = []
    reply.ar = []

    # RFC 2136 §3.1: Zone Section must have exactly 1 record of type SOA
    if len(request.questions) != 1 or request.q.qtype != QTYPE.SOA or request.q.qclass != CLASS_IN:
        reply.header.rcode = RCODE.FORMERR
        return reply

    zname = str(request.q.qname).rstrip('.').lower()
    zone = Zone.objects.filter(name__iexact=zname, enabled=True).first()
    if not zone:
        reply.header.rcode = RCODE.NOTAUTH
        return reply

    if not _client_allowed(client_ip):
        reply.header.rcode = RCODE.REFUSED
        return reply

    with transaction.atomic():
        # 1. Prerequisite Section (carried in the Answer section `request.rr`, RFC 2136 §3.2)
        for pre in request.rr:
            rel = _rel_name(pre.rname, zone.name)
            if rel is None:
                reply.header.rcode = RCODE.NOTZONE
                return reply
            rtype = QTYPE.get(pre.rtype, '')
            if pre.rclass == CLASS_ANY:
                if pre.ttl != 0:
                    reply.header.rcode = RCODE.FORMERR
                    return reply
                if pre.rtype == QTYPE.ANY:
                    # Name is in use (YXDOMAIN)
                    if not Record.objects.filter(zone=zone, name=rel).exists():
                        reply.header.rcode = RCODE.YXDOMAIN
                        return reply
                else:
                    # RRset exists (value independent) (YXRRSET)
                    if not Record.objects.filter(zone=zone, name=rel, type=rtype).exists():
                        reply.header.rcode = RCODE.YXRRSET
                        return reply
            elif pre.rclass == CLASS_NONE:
                if pre.ttl != 0:
                    reply.header.rcode = RCODE.FORMERR
                    return reply
                if pre.rtype == QTYPE.ANY:
                    # Name is not in use (NXDOMAIN)
                    if Record.objects.filter(zone=zone, name=rel).exists():
                        reply.header.rcode = RCODE.NXDOMAIN
                        return reply
                else:
                    # RRset does not exist (NXRRSET)
                    if Record.objects.filter(zone=zone, name=rel, type=rtype).exists():
                        reply.header.rcode = RCODE.NXRRSET
                        return reply
            elif pre.rclass == CLASS_IN:
                if pre.ttl != 0:
                    reply.header.rcode = RCODE.FORMERR
                    return reply
                val = _rdata_to_value(pre)
                if not Record.objects.filter(zone=zone, name=rel, type=rtype, value=val).exists():
                    reply.header.rcode = RCODE.YXRRSET
                    return reply
            else:
                reply.header.rcode = RCODE.FORMERR
                return reply

        # 2. Update Section (carried in the Authority section `request.auth`, RFC 2136 §3.4)
        changed = False
        for upd in request.auth:
            rel = _rel_name(upd.rname, zone.name)
            if rel is None:
                reply.header.rcode = RCODE.NOTZONE
                return reply
            rtype = QTYPE.get(upd.rtype, '')
            if upd.rclass == CLASS_IN:
                # Add to an RRset
                if rtype not in _SUPPORTED_TYPES:
                    reply.header.rcode = RCODE.FORMERR
                    return reply
                val = _rdata_to_value(upd)
                ttl = int(upd.ttl) if upd.ttl else None
                if rtype == 'CNAME':
                    Record.objects.filter(zone=zone, name=rel, type='CNAME').delete()
                rec, created = Record.objects.get_or_create(
                    zone=zone, name=rel, type=rtype, value=val,
                    defaults={'ttl': ttl},
                )
                if not created and rec.ttl != ttl:
                    rec.ttl = ttl
                    rec.save(update_fields=['ttl'])
                changed = True
            elif upd.rclass == CLASS_ANY:
                # Delete an RRset or all RRsets from a name
                if upd.rtype == QTYPE.ANY:
                    deleted, _ = Record.objects.filter(zone=zone, name=rel).delete()
                else:
                    deleted, _ = Record.objects.filter(zone=zone, name=rel, type=rtype).delete()
                if deleted:
                    changed = True
            elif upd.rclass == CLASS_NONE:
                # Delete a specific RR from an RRset
                val = _rdata_to_value(upd)
                deleted, _ = Record.objects.filter(zone=zone, name=rel, type=rtype, value=val).delete()
                if deleted:
                    changed = True
            else:
                reply.header.rcode = RCODE.FORMERR
                return reply

        if changed:
            DataVersion.bump()

    reply.header.rcode = RCODE.NOERROR
    return reply
