"""A DHCPv4 server (RFC 2131/2132/3046/3396/3397/3442/4702/6842): address ranges, leases in the database, fixed addresses by MAC.

Run it with `manage.py rundhcp` (settings DHCP_*). The network of this host is the first scope; DHCP_SUBNETS adds networks reached through relay agents
(giaddr, option 82 echoed). Only one DHCP server may answer on a network: turn the router's off first.
"""
import hashlib
import hmac
import ipaddress
import json
import re
import struct
import subprocess
import sys
import time
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..dnsd import ddr
from ..models import DhcpLease, Setting

MAGIC = b'\x63\x82\x53\x63'
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM, FORCERENEW = 1, 2, 3, 4, 5, 6, 7, 8, 9
DHCPLEASEQUERY, DHCPLEASEUNASSIGNED, DHCPLEASEUNKNOWN, DHCPLEASEACTIVE = 10, 11, 12, 13
OFFER_HOLD, BLOCK_HOLD = 60, 600  # seconds: an offer waits for the REQUEST; a refused or answering address stays out of the pool
ZERO = ipaddress.IPv4Address(0)
BROADCAST = '255.255.255.255'

DHCP_SETTING_SPEC = (
    ('DHCP', bool),
    ('DHCP_SERVER', str),
    ('DHCP_NETMASK', str),
    ('DHCP_RANGE', str),
    ('DHCP_ROUTER', str),
    ('DHCP_DNS', str),
    ('DHCP_DOMAIN', str),
    ('DHCP_LEASE', int),
    ('DHCP_RESERVATIONS', str),
    ('DHCP_INTERFACE', str),
    ('DHCP_NTP', str),
    ('DHCP_SEARCH', str),
    ('DHCP_ROUTES', str),
    ('DHCP_MTU', int),
    ('DHCP_BOOT_SERVER', str),
    ('DHCP_BOOT_FILE', str),
    ('DHCP_PROBE', bool),
    ('DHCP_NAMES', bool),
    ('DHCP_UNICAST', bool),
    ('DHCP_DNR', bool),
    ('DHCP_FAILOVER_SECS', int),
    ('DHCP_SUBNETS', str),
    ('DHCP6', bool),
    ('DHCP6_PREFIX', str),
    ('DHCP6_POOL', str),
    ('DHCP6_PD_POOL', str),
    ('DHCP6_PD_LEN', int),
    ('DHCP6_PD_ROUTES', bool),
    ('DHCP6_LEASE', int),
    ('DHCP6_PREFERENCE', int),
    ('DHCP6_RAPID', bool),
    ('DHCP6_DNS', str),
    ('DHCP_RA', bool),
    ('DHCP_RA_INTERVAL', int),
    ('DHCP_RA_ROUTER_LIFETIME', int),
    ('DHCP_RA_SLAAC', bool),
)


def reconf_key(client_id):
    """Deterministic per-client 16-byte Reconfigure Key (RFC 3118 / RFC 8415 §20.4) derived from SECRET_KEY."""
    cid = client_id.hex() if isinstance(client_id, (bytes, bytearray)) else str(client_id)
    return hmac.new(settings.SECRET_KEY.encode(), f'dhcp-reconf:{cid}'.encode(), hashlib.md5).digest()


def auth_key_body(client_id, replay=None):
    """Authentication option payload (protocol=3 Reconfigure Key, algorithm=1 HMAC-MD5, rdm=0, type=1 key value)."""
    rep = int(time.time()) if replay is None else int(replay)
    return struct.pack('!BBBQB', 3, 1, 0, rep, 1) + reconf_key(client_id)


def dhcp_settings(base=None, overrides=None):
    """Return a settings-like namespace where DB `Setting(key='dhcp:<NAME>')` and `overrides` overlay `django.conf.settings`."""
    base = base or settings
    db_rows = dict(Setting.objects.filter(key__startswith='dhcp:').values_list('key', 'value'))
    ns = type('DhcpSettings', (), {'DNS_DDR': getattr(base, 'DNS_DDR', '')})()
    for name, kind in DHCP_SETTING_SPEC:
        raw = db_rows.get(f'dhcp:{name}')
        if raw is None:
            val = getattr(base, name)
        elif kind is bool:
            val = str(raw).lower() in ('1', 'true', 'yes', 'on')
        elif kind is int:
            val = int(raw or 0)
        else:
            val = str(raw)
        if overrides and name in overrides:
            val = overrides[name]
        setattr(ns, name, val)
    return ns


def _ip_list(text):
    return [ipaddress.IPv4Address(x) for x in text.replace(',', ' ').split()]


def _names(text):
    return [x.strip('.').lower() for x in text.replace(',', ' ').split() if x.strip('.')]


@dataclass
class Config:
    server: ipaddress.IPv4Address
    network: ipaddress.IPv4Network
    first: ipaddress.IPv4Address
    last: ipaddress.IPv4Address
    router: ipaddress.IPv4Address | None
    dns: list
    domain: str
    lease: int
    reservations: dict  # mac -> IPv4Address
    dnr: bytes  # body of option 162 (RFC 9463), empty = none
    ntp: list = field(default_factory=list)
    search: list = field(default_factory=list)
    routes: list = field(default_factory=list)  # [(IPv4Network, gateway)]
    mtu: int = 0
    boot_server: str = ''
    boot_file: str = ''
    probe: bool = False
    failover_secs: int = 0

    @classmethod
    def from_settings(cls, s, extra=None):
        """The configuration from the DHCP_* settings (extra: the overrides of one DHCP_SUBNETS entry); a ValueError says what is wrong (the server must not start on a guess)."""
        extra = extra or {}
        g = lambda name, key: extra.get(key, getattr(s, name))
        try:
            server = ipaddress.IPv4Address(s.DHCP_SERVER)
            network = ipaddress.IPv4Network(extra['network']) if 'network' in extra else ipaddress.IPv4Network(f'{server}/{s.DHCP_NETMASK}', strict=False)
            first, _, last = str(g('DHCP_RANGE', 'range')).partition('-')
            first, last = ipaddress.IPv4Address(first.strip()), ipaddress.IPv4Address(last.strip())
            router = extra.get('router', '' if extra else getattr(s, 'DHCP_ROUTER'))
            router = ipaddress.IPv4Address(router) if router else None
            dns = _ip_list(str(g('DHCP_DNS', 'dns'))) or [server]
            res = {}
            for item in str(extra.get('reservations', '' if extra else getattr(s, 'DHCP_RESERVATIONS'))).split():
                mac, _, ip = item.partition('=')
                mac = mac.lower().replace('-', ':')
                if len(mac.split(':')) != 6 or any(len(x) != 2 for x in mac.split(':')):
                    raise ValueError(f'bad MAC {mac!r}')
                int(mac.replace(':', ''), 16)
                res[mac] = ipaddress.IPv4Address(ip)
            routes = []
            for item in str(extra.get('routes', '' if extra else getattr(s, 'DHCP_ROUTES'))).split():
                net, _, gw = item.partition('=')
                routes.append((ipaddress.IPv4Network(net), ipaddress.IPv4Address(gw)))
            ntp = _ip_list(str(g('DHCP_NTP', 'ntp')))
            lease, mtu = int(g('DHCP_LEASE', 'lease')), int(g('DHCP_MTU', 'mtu'))
            failover_secs = max(0, int(getattr(s, 'DHCP_FAILOVER_SECS', 0) or 0))
        except (ValueError, TypeError) as e:
            raise ValueError(f'DHCP settings: {e} (DHCP_SERVER, DHCP_NETMASK, DHCP_RANGE=first-last, DHCP_ROUTER, DHCP_DNS, DHCP_NTP, DHCP_ROUTES=net=gateway, DHCP_RESERVATIONS=mac=ip ...)')
        if not (first <= last and first in network and last in network):
            raise ValueError(f'DHCP settings: the range {first}-{last} must be inside the network {network}')
        if any(ip not in network for ip in res.values()) or (router and router not in network) or any(gw not in network for _, gw in routes):
            raise ValueError('DHCP settings: reservations, DHCP_ROUTER and the gateways of DHCP_ROUTES must be inside the network')
        if lease < 60:
            raise ValueError('DHCP settings: DHCP_LEASE is at least 60 seconds')
        if not 0 <= mtu <= 65535 or (mtu and mtu < 68):
            raise ValueError('DHCP settings: DHCP_MTU is 0 (not sent) or 68-65535')
        boot_server, boot_file, domain = str(g('DHCP_BOOT_SERVER', 'boot_server')), str(g('DHCP_BOOT_FILE', 'boot_file')), str(g('DHCP_DOMAIN', 'domain')).strip()
        if len(boot_server) > 255 or len(boot_file) > 128:
            raise ValueError('DHCP settings: DHCP_BOOT_SERVER / DHCP_BOOT_FILE too long')
        dnr = ddr.dnr_v4(ddr.parse(s.DNS_DDR)) if s.DHCP_DNR and s.DNS_DDR else b''
        search = _names(str(g('DHCP_SEARCH', 'search'))) or ([domain.strip('.').lower()] if domain.strip('.') else [])
        return cls(server, network, first, last, router, dns, domain, lease, res, dnr, ntp, search, routes, mtu, boot_server, boot_file, s.DHCP_PROBE, failover_secs)


def scopes(s):
    """[the network of this host] + one Config per entry of DHCP_SUBNETS (a JSON list of objects: network, range, router, dns, domain, lease, ntp, search, routes, mtu,
    boot_server, boot_file, reservations), the networks behind relay agents. They must not overlap."""
    try:
        extra = json.loads(s.DHCP_SUBNETS or '[]')
        assert isinstance(extra, list) and all(isinstance(e, dict) and 'network' in e and 'range' in e for e in extra)
    except (ValueError, AssertionError):
        raise ValueError('DHCP settings: DHCP_SUBNETS is a JSON list of objects with at least "network" and "range"')
    out = [Config.from_settings(s)] + [Config.from_settings(s, e) for e in extra]
    for i, a in enumerate(out):
        for b in out[i + 1:]:
            if a.network.overlaps(b.network):
                raise ValueError(f'DHCP settings: the networks {a.network} and {b.network} overlap')
    return out


def parse(data):
    """A BOOTREQUEST from an Ethernet client (or a relay Leasequery with htype=0/hlen=0) as a dict, or None."""
    if len(data) < 241 or data[236:240] != MAGIC:
        return None
    op, htype, hlen, _, xid, secs, flags, ciaddr, _, _, giaddr = struct.unpack('!BBBBIHH4s4s4s4s', data[:28])
    if op != 1 or not ((htype == 1 and hlen == 6) or (htype == 0 and hlen == 0)):
        return None
    opts, i = {}, 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        n = data[i + 1]
        opts[data[i]] = opts.get(data[i], b'') + data[i + 2:i + 2 + n]  # a long option comes in pieces (RFC 3396)
        i += 2 + n
    chaddr = data[28:34] if hlen == 6 else b'\0' * 6
    mac = ':'.join(f'{b:02x}' for b in chaddr) if hlen == 6 else ''
    cid = opts.get(61, b'')
    return {'xid': xid, 'secs': secs, 'flags': flags, 'htype': htype, 'hlen': hlen,
            'ciaddr': ipaddress.IPv4Address(ciaddr), 'giaddr': ipaddress.IPv4Address(giaddr),
            'chaddr': chaddr, 'mac': mac, 'opts': opts,
            'client': cid.hex() if 2 <= len(cid) <= 70 else mac}  # the client identifier names the client when it sends one (RFC 2131 4.2, RFC 6842)


def forcerenew_packet(server_ip, chaddr, xid=1, client_id=None, key=None, replay=None):
    """Build an RFC 3203 / RFC 3118 authenticated DHCPFORCERENEW (type 9) packet with HMAC-MD5 (option 90)."""
    srv = ipaddress.IPv4Address(server_ip)
    mac_str = chaddr.lower().replace('-', ':') if isinstance(chaddr, str) else ':'.join(f'{b:02x}' for b in chaddr[:6])
    hw = bytes.fromhex(mac_str.replace(':', ''))
    req = {'xid': xid, 'flags': 0, 'giaddr': ZERO, 'chaddr': hw[:6].ljust(6, b'\0')}
    k = key if key is not None else reconf_key(client_id or mac_str)
    rep_val = int(time.time()) if replay is None else int(replay)
    auth_zero = struct.pack('!BBBQB', 3, 1, 0, rep_val, 2) + b'\x00' * 16
    raw = build(req, ZERO, [(53, bytes([FORCERENEW])), (54, srv.packed), (90, auth_zero)])
    digest = hmac.new(k, raw, hashlib.md5).digest()
    return raw[:-17] + digest + b'\xff'


def verify_forcerenew(pkt, key):
    """Verify the RFC 3118 / RFC 3203 HMAC-MD5 authentication option (90) on a FORCERENEW packet."""
    parsed = parse(b'\x01' + pkt[1:]) if pkt else None
    if not parsed or parsed['opts'].get(53) != bytes([FORCERENEW]):
        return False
    auth = parsed['opts'].get(90, b'')
    if len(auth) != 28 or auth[:3] != b'\x03\x01\x00' or auth[11] != 2:
        return False
    # Zero out the 16-byte HMAC-MD5 field inside option 90 before computing the digest
    idx = pkt.rfind(bytes([90, 28]) + auth)
    if idx < 0:
        return False
    zeroed = pkt[:idx + 14] + b'\x00' * 16 + pkt[idx + 30:]
    return hmac.compare_digest(auth[12:], hmac.new(key, zeroed, hashlib.md5).digest())


def build(req, yiaddr, options, ciaddr=ZERO, siaddr=ZERO, sname=b'', bootfile=b''):
    """A BOOTREPLY for req. options: [(code, bytes)]; a value over 255 octets is split into several options (RFC 3396)."""
    head = struct.pack('!BBBBIHH4s4s4s4s', 2, 1, 6, 0, req['xid'], 0, req['flags'], ciaddr.packed, yiaddr.packed, siaddr.packed, req['giaddr'].packed)
    out = bytearray(head + req['chaddr'].ljust(16, b'\0') + sname[:63].ljust(64, b'\0') + bootfile[:127].ljust(128, b'\0') + MAGIC)
    for code, value in options:
        for i in range(0, max(len(value), 1), 255):
            piece = value[i:i + 255]
            out += bytes([code, len(piece)]) + piece
    return bytes(out + b'\xff')


def classless_routes(routes):
    """Option 121 (RFC 3442): prefix length, the significant octets of the destination, the gateway."""
    out = b''
    for net, gw in routes:
        out += bytes([net.prefixlen]) + net.network_address.packed[:(net.prefixlen + 7) // 8] + gw.packed
    return out


def arp_request(src_mac, src_ip, target_ip):
    """An Ethernet ARP Who-Has broadcast frame (42 octets, ethertype 0x0806) asking for target_ip."""
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, src_mac, ipaddress.IPv4Address(src_ip).packed, b'\0' * 6, ipaddress.IPv4Address(target_ip).packed)
    return b'\xff' * 6 + src_mac + b'\x08\x06' + arp


def is_arp_reply(frame, target_ip):
    """Whether an Ethernet frame is an ARP reply (oper=2) from target_ip."""
    return len(frame) >= 42 and frame[12:22] == b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02' and frame[28:32] == ipaddress.IPv4Address(target_ip).packed


def arp_probe(ip, interface=None, src_ip=ZERO, timeout=0.25):
    """Send an ARP request on interface (Linux AF_PACKET, CAP_NET_RAW) and wait briefly for a reply: sees hosts that block ICMP."""
    import select
    import socket
    import time
    iface = interface if interface is not None else getattr(settings, 'DHCP_INTERFACE', '')
    if not iface or not hasattr(socket, 'AF_PACKET'):
        return False
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            mac = bytes.fromhex(f.read().strip().replace(':', ''))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as raw:
            raw.bind((iface, 0x0806))
            raw.send(arp_request(mac, src_ip or getattr(settings, 'DHCP_SERVER', '') or ZERO, ip))
            deadline = time.monotonic() + timeout
            while (wait := deadline - time.monotonic()) > 0:
                ready, _, _ = select.select([raw], [], [], wait)
                if not ready:
                    break
                if is_arp_reply(raw.recv(128), ip):
                    return True
    except (OSError, ValueError):
        return False
    return False


def ping(ip):
    """Does something answer at this address? Tries an ARP probe on DHCP_INTERFACE first (if available), then one ICMP echo (RFC 2131 3.1.2)."""
    if arp_probe(ip):
        return True
    wait = '1000' if sys.platform == 'darwin' else '1'  # -W is milliseconds on macOS, seconds on Linux
    try:
        return subprocess.run(['ping', '-c', '1', '-W', wait, ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False  # no ping program: no probe


def clean_hostname(raw):
    """A client's host name as one DNS label: lower case letters, digits and "-" (it will be answered by the DNS server)."""
    return re.sub(r'[^a-z0-9-]', '', raw.decode(errors='ignore').lower().split('.')[0]).strip('-')[:63]


Reply = namedtuple('Reply', 'data ip port hw')  # hw: the client's hardware address when the reply may be sent to it directly (RFC 2131 4.1), else None


def fqdn_label(value):
    """The host name in a client FQDN option (RFC 4702): flags, two result codes, then the name (wire format when the E flag is set)."""
    if len(value) < 4:
        return b''
    name = value[3:]
    if value[0] & 4:  # wire format: take the first label
        return name[1:1 + name[0]] if name and name[0] < len(name) else b''
    return name


def ip_checksum(header):
    total = sum(struct.unpack('!%dH' % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def l2_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload):
    """An Ethernet frame carrying a UDP datagram, for a client that has no address yet (RFC 2131 4.1: unicast to the hardware address, a broadcast is the alternative)."""
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload  # UDP checksum 0: not used over IPv4
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 16, 17, 0, src_ip.packed, dst_ip.packed)
    ip = ip[:10] + struct.pack('!H', ip_checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b'\x08\x00' + ip + udp


class Server:
    def __init__(self, cfgs, probe=None):
        self.cfgs = cfgs if isinstance(cfgs, list) else [cfgs]
        self.cfg = self.cfgs[0]  # the network of this host
        self.probe = probe if probe is not None else (ping if self.cfg.probe else None)

    def _scope(self, req):
        """The Config for this client: the local network, or the one a relay agent (giaddr) is in; None = not ours."""
        if req['giaddr'] == ZERO:
            return self.cfg
        return next((c for c in self.cfgs if req['giaddr'] in c.network), None)

    def handle(self, data):
        """A Reply(data, ip, port, hw) for a client packet, or None when nothing is to be sent."""
        req = parse(data)
        if not req or not req['opts'].get(53):
            return None
        cfg = self._scope(req)
        if cfg is None:
            return None
        kind, mac, key, opts = req['opts'][53][0], req['mac'], req['client'], req['opts']
        if kind == DHCPLEASEQUERY:
            return self._leasequery(cfg, req, timezone.now())
        if req.get('hlen', 6) != 6:
            return None
        sid = opts.get(54)
        if sid and sid != cfg.server.packed:  # the client chose another server: our offer (if any) lapses by itself
            return None
        now = timezone.now()
        want = ipaddress.IPv4Address(opts[50]) if len(opts.get(50, b'')) == 4 else None
        if kind == DISCOVER:
            if cfg.failover_secs > 0 and req.get('secs', 0) < cfg.failover_secs:
                return None  # standby server: let primary answer first unless client has been retrying for >= failover_secs
            for _ in range(5):
                ip, fresh = self._pick(cfg, mac, key, want, now)
                if ip is None:
                    return None  # pool exhausted
                if fresh and self.probe and self.probe(str(ip)):  # in use by something that is not in our table: keep it out of the pool and try the next
                    self._hold(f'conflict-{ip}', ip, BLOCK_HOLD, now)
                    continue
                break
            else:
                return None
            self._store(req, ip, OFFER_HOLD, now)
            return self._send(req, self._reply(cfg, req, ip, OFFER, True), BROADCAST, True)
        if kind == REQUEST:
            ip = want or (req['ciaddr'] if req['ciaddr'] != ZERO else None)
            if ip is None:
                return None
            if not self._ok(cfg, ip, mac, key, now):
                nak = [(53, bytes([NAK])), (54, cfg.server.packed)] + ([(61, opts[61])] if 61 in opts else []) + ([(82, opts[82])] if 82 in opts else [])
                nak_req = {**req, 'flags': req['flags'] | 0x8000} if req['giaddr'] != ZERO else req  # RFC 2131 §4.3.2: set broadcast bit on relayed NAK
                return self._send(nak_req, build(nak_req, ZERO, nak), BROADCAST, False)
            self._store(req, ip, cfg.lease, now)
            return self._send(req, self._reply(cfg, req, ip, ACK, True), str(req['ciaddr']) if req['ciaddr'] != ZERO else BROADCAST, True)
        if kind == INFORM and req['ciaddr'] != ZERO:
            return self._send(req, self._reply(cfg, req, ZERO, ACK, False, ciaddr=req['ciaddr']), str(req['ciaddr']), False)
        if kind == RELEASE:
            DhcpLease.objects.filter(client=key, ip=str(req['ciaddr'])).delete()
        elif kind == DECLINE and want and self._ok(cfg, want, mac, key, now):
            DhcpLease.objects.filter(client=key).delete()
            max_declined = max(1, (int(cfg.last) - int(cfg.first) + 1) // 2)
            active_declined = DhcpLease.objects.filter(client__startswith='declined-', expires__gt=now)
            if not active_declined.filter(mac=mac).exists() and active_declined.count() < max_declined:
                self._hold(f'declined-{want}', want, BLOCK_HOLD, now, mac=mac)
        return None

    def _leasequery(self, cfg, req, now):
        """RFC 4388 DHCPv4 Leasequery handler (by IP, MAC, or Client-identifier). Answered only to relay agents (giaddr != 0)."""
        if req['giaddr'] == ZERO:
            return None
        opts = req['opts']
        base_opts = [(54, cfg.server.packed)] + ([(82, opts[82])] if 82 in opts else [])
        row = None
        if req['ciaddr'] != ZERO:
            q_ip = req['ciaddr']
            if q_ip not in cfg.network:
                return Reply(build(req, ZERO, [(53, bytes([DHCPLEASEUNKNOWN]))] + base_opts, ciaddr=q_ip), str(req['giaddr']), 67, None)
            row = DhcpLease.objects.filter(ip=str(q_ip), expires__gt=now).exclude(client__startswith='conflict-').exclude(client__startswith='declined-').first()
            if not row:
                code = DHCPLEASEUNASSIGNED if cfg.first <= q_ip <= cfg.last or q_ip in cfg.reservations.values() else DHCPLEASEUNKNOWN
                return Reply(build(req, ZERO, [(53, bytes([code]))] + base_opts, ciaddr=q_ip), str(req['giaddr']), 67, None)
        elif 61 in opts and 2 <= len(opts[61]) <= 70:
            row = DhcpLease.objects.filter(client=opts[61].hex(), expires__gt=now).order_by('-updated').first()
        elif req['mac'] and req['mac'] != '00:00:00:00:00:00':
            row = DhcpLease.objects.filter(mac=req['mac'], expires__gt=now).order_by('-updated').first()
        else:
            return None

        if not row:
            return Reply(build(req, ZERO, [(53, bytes([DHCPLEASEUNKNOWN]))] + base_opts), str(req['giaddr']), 67, None)

        rem = max(1, int((row.expires - now).total_seconds()))
        clt = max(0, int((now - row.updated).total_seconds())) if getattr(row, 'updated', None) else 0
        out = [
            (53, bytes([DHCPLEASEACTIVE])),
            (54, cfg.server.packed),
            (51, struct.pack('!I', rem)),
            (58, struct.pack('!I', rem // 2)),
            (59, struct.pack('!I', rem * 7 // 8)),
            (91, struct.pack('!I', clt)),  # client-last-transaction-time (RFC 4388)
        ]
        if row.hostname:
            out.append((12, row.hostname.encode()))
        if ':' not in row.client:
            try:
                out.append((61, bytes.fromhex(row.client)))
            except ValueError:
                pass
        if 82 in opts:
            out.append((82, opts[82]))
        chaddr = bytes.fromhex(row.mac.replace(':', '')) if row.mac and len(row.mac) == 17 else req['chaddr']
        rep_req = {**req, 'htype': 1, 'hlen': 6, 'chaddr': chaddr}
        return Reply(build(rep_req, ZERO, out, ciaddr=ipaddress.IPv4Address(row.ip)), str(req['giaddr']), 67, None)

    @staticmethod
    def _send(req, data, ip, direct):
        """Where the reply goes (RFC 2131 4.1): to the relay agent when there is one, to the client's own address when it has one, else a broadcast.
        With no relay, no address yet and no broadcast flag it may also go straight to the hardware address (hw)."""
        if req['giaddr'] != ZERO:
            return Reply(data, str(req['giaddr']), 67, None)
        hw = req['chaddr'] if direct and ip == BROADCAST and not req['flags'] & 0x8000 else None
        return Reply(data, ip, 68, hw)

    def _reply(self, cfg, req, ip, kind, lease, ciaddr=ZERO):
        """OFFER / ACK. The options the client may not need (NTP, search list, routes, MTU, boot, DNR) are sent when its parameter request list names them (RFC 2132 9.8)."""
        prl = req['opts'].get(55, b'')
        out = [(53, bytes([kind])), (54, cfg.server.packed)]
        if lease:
            out += [(51, struct.pack('!I', cfg.lease)), (58, struct.pack('!I', cfg.lease // 2)), (59, struct.pack('!I', cfg.lease * 7 // 8))]
        out += [(1, cfg.network.netmask.packed), (28, cfg.network.broadcast_address.packed)]
        if cfg.router:
            out.append((3, cfg.router.packed))
        out.append((6, b''.join(d.packed for d in cfg.dns)))
        if cfg.domain:
            out.append((15, cfg.domain.encode()))
        if cfg.ntp and 42 in prl:
            out.append((42, b''.join(n.packed for n in cfg.ntp)))
        if cfg.search and 119 in prl:
            out.append((119, b''.join(ddr.adn(n) for n in cfg.search)))
        if cfg.routes and 121 in prl:  # a client that understands 121 ignores option 3: the default route goes in as well
            out.append((121, classless_routes(([(ipaddress.IPv4Network('0.0.0.0/0'), cfg.router)] if cfg.router else []) + cfg.routes)))
        if cfg.mtu and 26 in prl:
            out.append((26, struct.pack('!H', cfg.mtu)))
        if cfg.boot_server and 66 in prl:
            out.append((66, cfg.boot_server.encode()))
        if cfg.boot_file and 67 in prl:
            out.append((67, cfg.boot_file.encode()))
        if cfg.dnr and 162 in prl:
            out.append((162, cfg.dnr))
        host = self._hostname(req)
        if len(req['opts'].get(81, b'')) >= 4 and host and cfg.domain:  # client FQDN (RFC 4702): N=1, S=0: nobody updates the DNS, this server answers the name from the lease itself
            wire = bool(req['opts'][81][0] & 4)
            name = f'{host}.{cfg.domain.strip(".")}'
            out.append((81, bytes([0x08 | (4 if wire else 0), 0, 0]) + (ddr.adn(name) if wire else name.encode())))
        if 61 in req['opts']:  # RFC 6842: echo client identifier when sent
            out.append((61, req['opts'][61]))
        if kind == ACK and (90 in prl or 90 in req['opts'] or 80 in req['opts']):  # RFC 3118 / RFC 3203: per-client Reconfigure Key (HMAC-MD5)
            out.append((90, auth_key_body(req['client'])))
        if 82 in req['opts']:  # relay agent information: echoed unchanged (RFC 3046 2.2)
            out.append((82, req['opts'][82]))
        return build(req, ip, out, ciaddr=ciaddr, bootfile=cfg.boot_file.encode() if cfg.boot_file else b'')

    @staticmethod
    def _hostname(req):
        return clean_hostname(req['opts'].get(12) or fqdn_label(req['opts'].get(81, b'')))

    def _ok(self, cfg, ip, mac, key, now):
        """May this client have this address: reserved for it, or in the pool and not in use by another client."""
        if mac in cfg.reservations:
            return ip == cfg.reservations[mac]
        if not (cfg.first <= ip <= cfg.last) or ip == cfg.server or ip in cfg.reservations.values():
            return False
        return not DhcpLease.objects.filter(ip=str(ip), expires__gt=now).exclude(client=key).exists()

    def _pick(self, cfg, mac, key, want, now):
        """(address, fresh): RFC 2131 4.3.1 order: a reservation, the address the client had, the one it asks for, then the first free one. fresh = never held by this client."""
        if mac in cfg.reservations:
            return cfg.reservations[mac], False
        cur = DhcpLease.objects.filter(client=key).first()
        if cur and self._ok(cfg, ipaddress.IPv4Address(cur.ip), mac, key, now):
            return ipaddress.IPv4Address(cur.ip), False
        if want and self._ok(cfg, want, mac, key, now):
            return want, True
        taken = set(DhcpLease.objects.filter(expires__gt=now).exclude(client=key).values_list('ip', flat=True)) | {str(i) for i in cfg.reservations.values()} | {str(cfg.server)}
        n = int(cfg.first)
        while n <= int(cfg.last):  # shortcut: a linear scan of the range, fine up to a few thousand addresses
            if str(ipaddress.IPv4Address(n)) not in taken:
                return ipaddress.IPv4Address(n), True
            n += 1
        return None, False

    def _store(self, req, ip, seconds, now):
        self._hold(req['client'], ip, seconds, now, self._hostname(req), req['mac'])

    def _hold(self, key, ip, seconds, now, host='', mac=''):
        DhcpLease.objects.filter(ip=str(ip)).exclude(client=key).delete()  # an expired lease of someone else (_ok said it is free)
        cur = DhcpLease.objects.filter(client=key, ip=str(ip), expires__gt=now).first()
        expires = max(cur.expires, now + timedelta(seconds=seconds)) if cur else now + timedelta(seconds=seconds)
        hostname = (cur.hostname if cur and seconds <= OFFER_HOLD and cur.expires > expires - timedelta(seconds=1) else host) or (cur.hostname if cur else '')
        DhcpLease.objects.update_or_create(client=key, defaults={'ip': str(ip), 'mac': mac, 'hostname': hostname, 'expires': expires})

    @staticmethod
    def cleanup(now=None):
        """Forget leases that ended more than a week ago (until then a returning client gets its old address back)."""
        DhcpLease.objects.filter(expires__lt=(now or timezone.now()) - timedelta(days=7)).delete()


def _name_cfg():
    if settings.DHCP and settings.DHCP_NAMES and settings.DHCP_DOMAIN.strip('.'):
        return True, settings.DHCP_DOMAIN.strip('.').lower()
    s = dhcp_settings()
    return bool(s.DHCP and s.DHCP_NAMES and s.DHCP_DOMAIN.strip('.')), s.DHCP_DOMAIN.strip('.').lower()


def lease_hosts(qname):
    """[(address, ttl)] of the client that called itself <label>.<DHCP_DOMAIN> and has a live lease, or None (the DNS server answers these names)."""
    on, domain = _name_cfg()
    if not (on and qname.endswith('.' + domain)):
        return None
    label = qname[:-len(domain) - 1]
    if not label or '.' in label:
        return None
    row = DhcpLease.objects.filter(hostname=label, expires__gt=timezone.now()).order_by('-updated').first()
    return [(row.ip, 60)] if row else None


def lease_ptr(qname):
    """The name of the client that holds the address in a reverse name (d.c.b.a.in-addr.arpa), or None."""
    on, domain = _name_cfg()
    if not (on and qname.endswith('.in-addr.arpa')):
        return None
    parts = qname[:-len('.in-addr.arpa')].split('.')
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    row = DhcpLease.objects.filter(ip='.'.join(reversed(parts)), expires__gt=timezone.now()).exclude(hostname='').first()
    return f'{row.hostname}.{domain}' if row else None
