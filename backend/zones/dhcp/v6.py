"""DHCPv6 server (RFC 8415, 3736, 3633): addresses (IA_NA), delegated prefixes (IA_PD) and, always, the DNS servers, the search list and the encrypted
resolvers (RFC 9463 option 144). Without DHCP6_POOL / DHCP6_PD_POOL it is stateless (Information-request only). Relay agents are supported (Relay-forward /
Relay-reply, nested too). Used by `manage.py rundhcp` when DHCP6=true."""
import hashlib
import hmac
import ipaddress
import struct
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..dnsd import ddr
from . import v4 as dhcp
from ..models import Dhcp6Lease

SOLICIT, ADVERTISE, REQUEST, CONFIRM, RENEW, REBIND, REPLY, RELEASE, DECLINE, RECONFIGURE, INFORMATION_REQUEST, RELAY_FORW, RELAY_REPL, LEASEQUERY, LEASEQUERY_REPLY = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
CLIENTID, SERVERID, IA_NA, IA_TA, IAADDR, ORO, PREFERENCE, AUTH, STATUS, RAPID, DNS, DOMAINS, IA_PD, IAPREFIX, REFRESH, INTERFACE_ID, RELAY_MSG, DNR = 1, 2, 3, 4, 5, 6, 7, 11, 13, 14, 23, 24, 25, 26, 32, 18, 9, 144
RECONF_MSG, RECONF_ACCEPT = 19, 20
LQ_QUERY, CLIENT_DATA, CLT_TIME, LQ_RELAY_DATA = 44, 45, 46, 47
QUERY_BY_ADDRESS, QUERY_BY_CLIENTID = 1, 2
SUCCESS, NOADDRS, NOBINDING, NOTONLINK, NOPREFIX, UNKNOWN_QUERY_TYPE, MALFORMED_QUERY, NOT_CONFIGURED = 0, 2, 3, 4, 6, 7, 8, 9
OFFER_HOLD, MAX_HOPS, MAX_PD_SCAN = 60, 32, 65536


def sync_pd_route(prefix, peer_ip=None, interface=None, add=True, enabled=None):
    """Install or remove a kernel IPv6 route (`ip -6 route replace/del`) for a delegated IA_PD prefix when DHCP6_PD_ROUTES=true."""
    on = getattr(settings, 'DHCP6_PD_ROUTES', False) if enabled is None else enabled
    if not on:
        return False
    cmd = ['ip', '-6', 'route', 'replace' if add else 'del', str(prefix)]
    if add and peer_ip:
        cmd += ['via', str(peer_ip).split('%')[0]]
    iface = interface or getattr(settings, 'DHCP_INTERFACE', '')
    if add and iface:
        cmd += ['dev', iface]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def reconfigure_msg(server_duid, client_duid, msg_type=RENEW, key=None, replay=None):
    """Build an RFC 8415 §20.4 & §21.19 authenticated DHCPv6 RECONFIGURE (type 10) message with HMAC-MD5 (option 11)."""
    s_duid = bytes.fromhex(server_duid) if isinstance(server_duid, str) else bytes(server_duid)
    c_duid = bytes.fromhex(client_duid) if isinstance(client_duid, str) else bytes(client_duid)
    k = key if key is not None else dhcp.reconf_key(c_duid.hex())
    rep_val = int(time.time()) if replay is None else int(replay)
    auth_zero = struct.pack('!BBBQB', 3, 1, 0, rep_val, 2) + b'\x00' * 16
    raw = (
        bytes([RECONFIGURE, 0, 0, 0])
        + option(SERVERID, s_duid)
        + option(CLIENTID, c_duid)
        + option(RECONF_MSG, bytes([msg_type]))
        + option(AUTH, auth_zero)
    )
    digest = hmac.new(k, raw, hashlib.md5).digest()
    return raw[:-16] + digest


def verify_reconfigure(msg, key):
    """Verify the RFC 8415 §20.4 HMAC-MD5 Authentication option (11) on a DHCPv6 RECONFIGURE message."""
    m = parse(msg)
    if not m or m[0] != RECONFIGURE:
        return False
    auths = m[2].get(AUTH, [])
    if not auths or len(auths[0]) != 28 or auths[0][:3] != b'\x03\x01\x00' or auths[0][11] != 2:
        return False
    auth = auths[0]
    idx = msg.rfind(option(AUTH, auth))
    if idx < 0:
        return False
    zeroed = msg[:idx + 16] + b'\x00' * 16 + msg[idx + 32:]
    return hmac.compare_digest(auth[12:], hmac.new(key, zeroed, hashlib.md5).digest())


def option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def options(data):
    """{option code: [values]} of a run of options, or None when it is cut short."""
    opts, i = {}, 0
    while i + 4 <= len(data):
        code, n = struct.unpack('!HH', data[i:i + 4])
        if i + 4 + n > len(data):
            return None
        opts.setdefault(code, []).append(data[i + 4:i + 4 + n])
        i += 4 + n
    return opts if i == len(data) else None


def parse(data):
    """(message type, transaction id, {option code: [values]}) of a client message, or None."""
    if len(data) < 4 or data[0] == RELAY_FORW:
        return None
    opts = options(data[4:])
    return None if opts is None else (data[0], data[1:4], opts)


def status(code, text=''):
    return option(STATUS, struct.pack('!H', code) + text.encode())


@dataclass
class Config6:
    dns: list
    search: list
    dnr: list  # bodies of option 144, one per resolver
    lease: int = 86400  # valid lifetime in seconds; preferred is three quarters of it
    prefix: ipaddress.IPv6Network | None = None  # the on-link prefix (CONFIRM)
    na_first: ipaddress.IPv6Address | None = None
    na_last: ipaddress.IPv6Address | None = None
    pd_pool: ipaddress.IPv6Network | None = None
    pd_len: int = 56
    rapid: bool = False
    name: str = 'dhcp6'
    refresh: int = 86400
    pd_routes: bool = False
    preference: int = 0
    interface: str = ''

    @classmethod
    def from_settings(cls, s, search):
        try:
            dns = [ipaddress.IPv6Address(x) for x in s.DHCP6_DNS.replace(',', ' ').split()]
            prefix = ipaddress.IPv6Network(s.DHCP6_PREFIX) if s.DHCP6_PREFIX else None
            first, _, last = s.DHCP6_POOL.partition('-')
            first, last = (ipaddress.IPv6Address(first.strip()), ipaddress.IPv6Address(last.strip())) if s.DHCP6_POOL else (None, None)
            pd = ipaddress.IPv6Network(s.DHCP6_PD_POOL) if s.DHCP6_PD_POOL else None
            pref = int(getattr(s, 'DHCP6_PREFERENCE', 0) or 0)
        except ValueError as e:
            raise ValueError(f'DHCPv6 settings: {e}')
        if first and not (first <= last and prefix and first in prefix and last in prefix):
            raise ValueError('DHCPv6 settings: DHCP6_POOL is first-last inside DHCP6_PREFIX')
        if pd and not (pd.prefixlen < s.DHCP6_PD_LEN <= 64):
            raise ValueError('DHCPv6 settings: DHCP6_PD_LEN is longer than the prefix of DHCP6_PD_POOL and at most 64')
        if s.DHCP6_LEASE < 120:
            raise ValueError('DHCPv6 settings: DHCP6_LEASE is at least 120 seconds')
        if not 0 <= pref <= 255:
            raise ValueError('DHCPv6 settings: DHCP6_PREFERENCE is 0-255')
        dnr = ddr.dnr_v6(ddr.parse(s.DNS_DDR)) if s.DHCP_DNR and s.DNS_DDR else []
        return cls(
            dns, search, dnr, s.DHCP6_LEASE, prefix, first, last, pd, s.DHCP6_PD_LEN, s.DHCP6_RAPID,
            f'dhcp6.{s.DHCP_SERVER}', 86400, bool(getattr(s, 'DHCP6_PD_ROUTES', False)), pref, getattr(s, 'DHCP_INTERFACE', ''),
        )

    @property
    def stateful(self):
        return bool(self.na_first or self.pd_pool)


class Server6:
    def __init__(self, cfg):
        self.cfg = cfg
        self.duid = struct.pack('!H', 4) + uuid.uuid5(uuid.NAMESPACE_DNS, cfg.name).bytes  # DUID-UUID (RFC 6355): no hardware address needed

    # ---- messages
    def handle(self, data, peer_ip=None):
        """The reply to a client message or a Relay-forward, or None."""
        if data[:1] == bytes([RELAY_FORW]):
            return self._relay(data, 0)
        m = parse(data)
        if not m:
            return None
        kind, txid, o = m
        first = lambda c: (o.get(c) or [None])[0]
        cid, sid = first(CLIENTID), first(SERVERID)
        if sid is not None and sid != self.duid:
            return None  # for another server
        now = timezone.now()
        oro = {struct.unpack('!H', v[i:i + 2])[0] for v in o.get(ORO, []) for i in range(0, len(v) - 1, 2)}
        if kind == INFORMATION_REQUEST:
            if {IA_NA, IA_TA, IA_PD} & o.keys():
                return None  # invalid: an Information-request carries no IA options
            return self._msg(REPLY, txid, cid, oro, b'')
        if kind == LEASEQUERY:
            return self._leasequery(txid, cid, o, now)
        if not self.cfg.stateful or cid is None or not (3 <= len(cid) <= 130) or kind in (ADVERTISE, REPLY, RECONFIGURE, LEASEQUERY_REPLY):
            return None
        duid = cid.hex()
        reconf_adv = option(RECONF_ACCEPT, b'') if RECONF_ACCEPT in o else b''
        reconf_rep = (reconf_adv + option(AUTH, dhcp.auth_key_body(duid))) if RECONF_ACCEPT in o else b''
        if kind == SOLICIT:
            if sid is not None:
                return None
            rapid = self.cfg.rapid and RAPID in o
            body = self._bind(o, duid, now, self.cfg.lease if rapid else OFFER_HOLD, RENEW_NONE, peer_ip=peer_ip)[0]
            return self._msg(REPLY if rapid else ADVERTISE, txid, cid, oro, body + (option(RAPID, b'') + reconf_rep if rapid else reconf_adv))
        if kind == REQUEST:
            if sid is None:
                return None
            return self._msg(REPLY, txid, cid, oro, self._bind(o, duid, now, self.cfg.lease, RENEW_NONE, peer_ip=peer_ip)[0] + reconf_rep)
        if kind in (RENEW, REBIND):
            if (kind == RENEW) != (sid is not None):
                return None  # Renew names the server, Rebind does not
            body, known = self._bind(o, duid, now, self.cfg.lease, RENEW_ONLY, peer_ip=peer_ip)
            if kind == REBIND and not known:
                return None
            return self._msg(REPLY, txid, cid, oro, body + reconf_rep)
        if kind == CONFIRM:
            if sid is not None:
                return None
            addrs = [ipaddress.IPv6Address(v[:16]) for ia in o.get(IA_NA, []) for v in (options(ia[12:]) or {}).get(IAADDR, []) if len(v) >= 24]
            addrs += [ipaddress.IPv6Address(v[:16]) for ia in o.get(IA_TA, []) for v in (options(ia[4:]) or {}).get(IAADDR, []) if len(v) >= 24]
            if not addrs or not self.cfg.prefix:
                return None
            ok = all(a in self.cfg.prefix for a in addrs)
            return self._msg(REPLY, txid, cid, oro, status(SUCCESS if ok else NOTONLINK))
        if kind == RELEASE:
            if sid is None:
                return None
            self._free(o, duid)
            return self._msg(REPLY, txid, cid, oro, status(SUCCESS, 'released'))
        if kind == DECLINE:
            if sid is None:
                return None
            self._decline(o, duid, now)
            return self._msg(REPLY, txid, cid, oro, status(SUCCESS))
        return None

    def _leasequery(self, txid, cid, o, now):
        """RFC 5007 DHCPv6 Leasequery handler (QUERY_BY_ADDRESS = 1, QUERY_BY_CLIENTID = 2)."""
        if cid is None or LQ_QUERY not in o:
            return None
        lq = o[LQ_QUERY][0]
        if len(lq) < 17:
            return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(MALFORMED_QUERY)
        qtype = lq[0]
        try:
            link = ipaddress.IPv6Address(lq[1:17])
        except ValueError:
            return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(MALFORMED_QUERY)
        qopts = options(lq[17:])
        if qopts is None:
            return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(MALFORMED_QUERY)
        if link != ipaddress.IPv6Address(0) and self.cfg.prefix and link not in self.cfg.prefix:
            return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(NOT_CONFIGURED)

        rows = []
        if qtype == QUERY_BY_ADDRESS:
            iaaddrs = qopts.get(IAADDR, [])
            if not iaaddrs or len(iaaddrs[0]) < 16:
                return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(MALFORMED_QUERY)
            addr = str(ipaddress.IPv6Address(iaaddrs[0][:16]))
            row = Dhcp6Lease.objects.filter(value=addr, expires__gt=now).exclude(duid__startswith='declined').first()
            if row:
                rows = [row]
        elif qtype == QUERY_BY_CLIENTID:
            cids = qopts.get(CLIENTID, [])
            if not cids:
                return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(MALFORMED_QUERY)
            rows = list(Dhcp6Lease.objects.filter(duid=cids[0].hex(), expires__gt=now).order_by('kind', 'iaid'))
        else:
            return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + status(UNKNOWN_QUERY_TYPE)

        body = b''
        if rows:
            client_duid = bytes.fromhex(rows[0].duid)
            clt = max(0, int((now - rows[0].updated).total_seconds())) if getattr(rows[0], 'updated', None) else 0
            cdata = option(CLIENTID, client_duid) + option(CLT_TIME, struct.pack('!I', clt))
            for r in rows:
                rem = max(1, int((r.expires - now).total_seconds()))
                pref = rem * 3 // 4
                if r.kind in ('na', 'ta'):
                    cdata += option(IAADDR, ipaddress.IPv6Address(r.value).packed + struct.pack('!II', pref, rem))
                elif r.kind == 'pd':
                    net = ipaddress.IPv6Network(r.value)
                    cdata += option(IAPREFIX, struct.pack('!IIB', pref, rem, net.prefixlen) + net.network_address.packed)
            body = option(CLIENT_DATA, cdata)
        return bytes([LEASEQUERY_REPLY]) + txid + option(SERVERID, self.duid) + option(CLIENTID, cid) + body + status(SUCCESS)

    def _msg(self, kind, txid, cid, oro, body):
        out = bytes([kind]) + txid + option(SERVERID, self.duid) + (option(CLIENTID, cid) if cid else b'') + body
        c = self.cfg
        if c.preference > 0 and kind in (ADVERTISE, REPLY):
            out += option(PREFERENCE, bytes([c.preference]))
        if c.dns and DNS in oro:
            out += option(DNS, b''.join(d.packed for d in c.dns))
        if c.search and DOMAINS in oro:
            out += option(DOMAINS, b''.join(ddr.adn(n) for n in c.search))
        if REFRESH in oro and kind == REPLY and not body:
            out += option(REFRESH, struct.pack('!I', c.refresh))
        if DNR in oro:
            out += b''.join(option(DNR, b) for b in c.dnr)
        return out

    def _relay(self, data, depth):
        """Relay-forward: answer the message inside and wrap the answer in a Relay-reply (RFC 8415 19)."""
        if len(data) < 34 or data[1] > MAX_HOPS or depth > MAX_HOPS:
            return None
        o = options(data[34:])
        if not o or RELAY_MSG not in o:
            return None
        inner = o[RELAY_MSG][0]
        relay_peer = str(ipaddress.IPv6Address(data[18:34]))
        reply = self._relay(inner, depth + 1) if inner[:1] == bytes([RELAY_FORW]) else self.handle(inner, peer_ip=relay_peer)
        if reply is None:
            return None
        out = bytes([RELAY_REPL]) + data[1:34] + option(RELAY_MSG, reply)
        if INTERFACE_ID in o:
            out += option(INTERFACE_ID, o[INTERFACE_ID][0])
        return out

    # ---- leases
    def _times(self):
        valid = self.cfg.lease
        pref = valid * 3 // 4
        return pref, valid, pref // 2, pref * 4 // 5

    def _bind(self, o, duid, now, seconds, mode, peer_ip=None):
        """(IA options for the reply, whether any binding was known). mode RENEW_ONLY: only what the client already has (Renew / Rebind)."""
        body, known, seen = b'', False, set()
        for ia in o.get(IA_NA, []):
            if len(ia) < 12:
                continue
            iaid = struct.unpack('!I', ia[:4])[0]
            if ('na', iaid) in seen:
                continue
            seen.add(('na', iaid))
            got = self._take('na', duid, iaid, (options(ia[12:]) or {}).get(IAADDR, []), now, seconds, mode == RENEW_ONLY)
            known = known or got is not None
            body += self._ia(IA_NA, iaid, got, 'na', mode)
        for ia in o.get(IA_TA, []):
            if len(ia) < 4:
                continue
            iaid = struct.unpack('!I', ia[:4])[0]
            if ('ta', iaid) in seen:
                continue
            seen.add(('ta', iaid))
            got = self._take('ta', duid, iaid, (options(ia[4:]) or {}).get(IAADDR, []), now, seconds, mode == RENEW_ONLY)
            known = known or got is not None
            body += self._ia(IA_TA, iaid, got, 'ta', mode)
        for ia in o.get(IA_PD, []):
            if len(ia) < 12:
                continue
            iaid = struct.unpack('!I', ia[:4])[0]
            if ('pd', iaid) in seen:
                continue
            seen.add(('pd', iaid))
            got = self._take('pd', duid, iaid, (options(ia[12:]) or {}).get(IAPREFIX, []), now, seconds, mode == RENEW_ONLY, peer_ip=peer_ip)
            known = known or got is not None
            body += self._ia(IA_PD, iaid, got, 'pd', mode)
        return body, known

    def _ia(self, code, iaid, value, kind, mode):
        pref, valid, t1, t2 = self._times()
        head = struct.pack('!I', iaid) if kind == 'ta' else struct.pack('!III', iaid, t1, t2)
        if value is None:
            miss = NOBINDING if mode == RENEW_ONLY else (NOPREFIX if kind == 'pd' else NOADDRS)
            return option(code, head + status(miss))
        if kind in ('na', 'ta'):
            return option(code, head + option(IAADDR, ipaddress.IPv6Address(value).packed + struct.pack('!II', pref, valid)))
        net = ipaddress.IPv6Network(value)
        return option(code, head + option(IAPREFIX, struct.pack('!IIB', pref, valid, net.prefixlen) + net.network_address.packed))

    def _take(self, kind, duid, iaid, hints, now, seconds, only_existing, peer_ip=None):
        """The address or prefix (text) this IA holds now, allocating one unless only_existing; None when there is none."""
        c = self.cfg
        cur = Dhcp6Lease.objects.filter(duid=duid, iaid=iaid, kind=kind).first()
        if cur and self._in_pool(kind, cur.value):
            return self._store(kind, duid, iaid, cur.value, now, seconds, peer_ip=peer_ip)
        if only_existing:
            return None
        pool_on = c.na_first if kind in ('na', 'ta') else c.pd_pool
        if pool_on is None:
            return None
        for h in hints:  # the client may ask for a particular one
            want = self._hint(kind, h)
            if want and self._in_pool(kind, want) and self._free(None, duid, check=want, iaid=iaid, kind=kind, now=now):
                return self._store(kind, duid, iaid, want, now, seconds, peer_ip=peer_ip)
        kinds = ('na', 'ta') if kind in ('na', 'ta') else ('pd',)
        taken = set(Dhcp6Lease.objects.filter(kind__in=kinds, expires__gt=now).exclude(duid=duid, iaid=iaid, kind=kind).values_list('value', flat=True))
        for cand in self._candidates(kind):
            if cand not in taken:
                return self._store(kind, duid, iaid, cand, now, seconds, peer_ip=peer_ip)
        return None

    def _candidates(self, kind):
        c = self.cfg
        if kind in ('na', 'ta'):
            n, last = int(c.na_first), int(c.na_last)
            while n <= last:
                yield str(ipaddress.IPv6Address(n))
                n += 1
            return
        step = 1 << (128 - c.pd_len)
        base = int(c.pd_pool.network_address)
        for i in range(min(1 << (c.pd_len - c.pd_pool.prefixlen), MAX_PD_SCAN)):  # shortcut: the first 65536 prefixes of the pool
            yield f'{ipaddress.IPv6Address(base + i * step)}/{c.pd_len}'

    def _in_pool(self, kind, value):
        c = self.cfg
        try:
            if kind in ('na', 'ta'):
                return bool(c.na_first) and c.na_first <= ipaddress.IPv6Address(value) <= c.na_last
            net = ipaddress.IPv6Network(value)
            return bool(c.pd_pool) and net.subnet_of(c.pd_pool) and net.prefixlen == c.pd_len
        except ValueError:
            return False

    @staticmethod
    def _hint(kind, v):
        try:
            if kind in ('na', 'ta'):
                return str(ipaddress.IPv6Address(v[:16])) if len(v) >= 24 else None
            return f'{ipaddress.IPv6Address(v[9:25])}/{v[8]}' if len(v) >= 25 else None
        except ValueError:
            return None

    def _store(self, kind, duid, iaid, value, now, seconds, peer_ip=None):
        Dhcp6Lease.objects.filter(value=value).exclude(duid=duid, iaid=iaid, kind=kind).delete()  # an expired lease of someone else
        cur = Dhcp6Lease.objects.filter(duid=duid, iaid=iaid, kind=kind, value=value, expires__gt=now).first()
        expires = max(cur.expires, now + timedelta(seconds=seconds)) if cur else now + timedelta(seconds=seconds)
        Dhcp6Lease.objects.update_or_create(duid=duid, iaid=iaid, kind=kind, defaults={'value': value, 'expires': expires})
        if kind == 'pd' and seconds > OFFER_HOLD:
            sync_pd_route(value, peer_ip=peer_ip, interface=self.cfg.interface, add=True, enabled=self.cfg.pd_routes)
        return value

    def _free(self, o, duid, check=None, iaid=None, kind=None, now=None):
        """With check: is this value free for this IA. With o: drop the leases the Release names."""
        if check is not None:
            return not Dhcp6Lease.objects.filter(value=check, expires__gt=now).exclude(duid=duid, iaid=iaid, kind=kind).exists()
        for code, k in ((IA_NA, 'na'), (IA_TA, 'ta'), (IA_PD, 'pd')):
            for ia in o.get(code, []):
                if len(ia) >= 4:
                    qs = Dhcp6Lease.objects.filter(duid=duid, iaid=struct.unpack('!I', ia[:4])[0], kind=k)
                    if k == 'pd':
                        for val in qs.values_list('value', flat=True):
                            sync_pd_route(val, interface=self.cfg.interface, add=False, enabled=self.cfg.pd_routes)
                    qs.delete()

    def _decline(self, o, duid, now):
        max_declined = max(1, (int(self.cfg.na_last) - int(self.cfg.na_first) + 1) // 2) if self.cfg.na_first and self.cfg.na_last else 0
        for code, hdr_len in ((IA_NA, 12), (IA_TA, 4)):
            for ia in o.get(code, []):
                for v in (options(ia[hdr_len:]) or {}).get(IAADDR, []):
                    addr = self._hint('na', v)
                    if addr and self._in_pool('na', addr) and not Dhcp6Lease.objects.filter(value=addr, expires__gt=now).exclude(duid=duid).exists():
                        Dhcp6Lease.objects.filter(value=addr).delete()
                        if Dhcp6Lease.objects.filter(duid__startswith='declined', expires__gt=now).count() < max_declined:
                            Dhcp6Lease.objects.update_or_create(duid=f'declined-{addr}', iaid=0, kind='na',
                                                                defaults={'value': addr, 'expires': now + timedelta(seconds=600)})

    @staticmethod
    def cleanup(now=None):
        Dhcp6Lease.objects.filter(expires__lt=(now or timezone.now()) - timedelta(days=7)).delete()


RENEW_NONE, RENEW_ONLY = 0, 1
