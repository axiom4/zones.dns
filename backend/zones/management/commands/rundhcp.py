import ipaddress
import select
import socket
import struct
import threading
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections

from zones.dhcp import ra
from zones.dhcp.v4 import Server, dhcp_settings, l2_frame, scopes
from zones.dhcp.v6 import Config6, Server6


def mac_of(interface):
    with open(f'/sys/class/net/{interface}/address') as f:
        return bytes.fromhex(f.read().strip().replace(':', ''))


class Command(BaseCommand):
    help = ('Run the DHCPv4 server (settings DHCP_*) and, as set in .env, the DHCPv6 server (DHCP6) and the Router Advertisements (DHCP_RA). '
            'Needs the right to bind UDP ports 67 and 547 (root, or CAP_NET_BIND_SERVICE), CAP_NET_RAW for DHCP_RA and DHCP_UNICAST. Only one DHCP server may run on a network.')

    def add_arguments(self, p):  # for tests on the loopback interface: other ports and one address
        p.add_argument('--address', default='', help='bind to this address only (default: all)')
        p.add_argument('--address6', default='', help='the same for DHCPv6 (an IPv6 address)')
        p.add_argument('--port', type=int, default=67)
        p.add_argument('--client-port', type=int, default=68)
        p.add_argument('--port6', type=int, default=547)
        p.add_argument('--client-port6', type=int, default=546)

    def handle(self, *a, address, address6, port, client_port, port6, client_port6, **o):
        s = dhcp_settings(settings)
        if not s.DHCP:
            raise CommandError('DHCP is off: set DHCP=true in .env (and turn off the DHCP server of your router first).')
        self.opt = dict(address=address, address6=address6, port=port, client_port=client_port, port6=port6, client_port6=client_port6)
        try:
            cfgs = scopes(s)
            cfg = cfgs[0]
            cfg6 = Config6.from_settings(s, cfg.search) if s.DHCP6 else None
            racfg = ra.RaConfig.from_settings(s, cfg.search, bool(cfg6 and cfg6.stateful)) if s.DHCP_RA else None
        except ValueError as e:
            raise CommandError(e)
        if (s.DHCP6 or s.DHCP_RA or s.DHCP_UNICAST) and not s.DHCP_INTERFACE:
            raise CommandError('DHCP6, DHCP_RA and DHCP_UNICAST need DHCP_INTERFACE (the interface they work on).')
        self.iface = s.DHCP_INTERFACE
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if self.iface:
            if hasattr(socket, 'SO_BINDTODEVICE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode())
            else:
                self.stderr.write('DHCP_INTERFACE: binding DHCPv4 to an interface needs Linux, listening on all of them.')
        try:
            sock.bind((address, port))
        except OSError as e:
            raise CommandError(f'Cannot bind UDP port {port} ({e}): run as root or give the program CAP_NET_BIND_SERVICE, and stop any other DHCP server on this host.')
        l2 = self.l2_sender() if s.DHCP_UNICAST else None
        if cfg6:
            threading.Thread(target=self.loop6, args=(Server6(cfg6),), daemon=True, name='dhcp6').start()
        if racfg:
            threading.Thread(target=self.loop_ra, args=(racfg,), daemon=True, name='ra').start()
        server = Server(cfgs)
        self.stdout.write(f'DHCP on {", ".join(str(c.network) for c in cfgs)}: {cfg.first}-{cfg.last}, server {cfg.server}, lease {cfg.lease}s, {len(cfg.reservations)} reservation(s)'
                          + (', DNR announced' if cfg.dnr else '') + (', ping probe' if server.probe else '') + (', unicast to the client' if l2 else '')
                          + (f', DHCPv6 ({"stateful" if cfg6.stateful else "stateless"})' if cfg6 else '') + (', Router Advertisements' if racfg else ''))
        sock.settimeout(3600)
        while True:
            try:
                data, peer = sock.recvfrom(1500)
            except socket.timeout:  # an idle hour: forget the leases that ended long ago
                close_old_connections()
                server.cleanup()
                if cfg6:
                    Server6.cleanup()
                continue
            close_old_connections()
            try:
                out = server.handle(data)
            except Exception as e:  # one bad packet or a database hiccup must not stop the server
                self.stderr.write(f'DHCP: {e!r} (from {peer[0]})')
                continue
            if out:
                self.send(sock, l2, cfg.server, out)

    def send(self, sock, l2, server_ip, out):
        data, ip, port, hw = out
        if hw and l2:  # RFC 2131 4.1: no address yet, no broadcast flag: straight to the hardware address
            try:
                l2.send(l2_frame(l2.mac, hw, server_ip, ipaddress.IPv4Address(data[16:20]), self.opt['port'], self.opt['client_port'], data))
                return
            except OSError as e:
                self.stderr.write(f'DHCP: direct reply failed ({e}), broadcasting')
        try:
            sock.sendto(data, (ip, self.opt['client_port'] if port == 68 else port))
        except OSError as e:
            self.stderr.write(f'DHCP: cannot send to {ip}: {e}')

    def l2_sender(self):
        if not hasattr(socket, 'AF_PACKET'):
            raise CommandError('DHCP_UNICAST needs Linux.')
        iface = getattr(self, 'iface', '') or settings.DHCP_INTERFACE
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        raw.bind((iface, 0x0800))
        return type('L2', (), {'mac': mac_of(iface), 'send': staticmethod(raw.send)})()

    def loop6(self, v6):
        try:
            iface = getattr(self, 'iface', '') or settings.DHCP_INTERFACE
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if not self.opt['address6']:  # a test on the loopback binds one address and joins no group
                index = socket.if_nametoindex(iface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, socket.inet_pton(socket.AF_INET6, 'ff02::1:2') + struct.pack('@I', index))
            sock.bind((self.opt['address6'] or '::', self.opt['port6']))
        except OSError as e:
            self.stderr.write(f'DHCPv6 not started: {e}')
            return
        while True:
            try:
                data, peer = sock.recvfrom(4096)
                close_old_connections()
                out = v6.handle(data, peer_ip=peer[0])
                if out:
                    sock.sendto(out, (peer[0], self.opt['client_port6'] if data[0] != 12 else self.opt['port6'], 0, peer[3]))  # a relay agent listens on 547
            except Exception as e:
                self.stderr.write(f'DHCPv6: {e!r}')
                time.sleep(0.1)

    def loop_ra(self, cfg):
        try:
            iface = getattr(self, 'iface', '') or settings.DHCP_INTERFACE
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            index = socket.if_nametoindex(iface)
            for opt in (socket.IPV6_MULTICAST_HOPS, socket.IPV6_UNICAST_HOPS):
                sock.setsockopt(socket.IPPROTO_IPV6, opt, 255)  # RFC 4861: hosts discard anything with another hop limit
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            block = [0xffffffff] * 8
            block[ra.RS // 32] &= ~(1 << (ra.RS % 32))  # ICMP6_FILTER: only Router Solicitations come in
            sock.setsockopt(socket.IPPROTO_ICMPV6, 1, struct.pack('8I', *block))
            msg = ra.build(cfg, mac_of(iface))
        except OSError as e:
            self.stderr.write(f'Router Advertisements not started: {e}')
            return
        last, pending_rs = 0, False
        while True:
            try:
                now = time.monotonic()
                if now - last >= cfg.interval or (pending_rs and now - last >= 3):
                    sock.sendto(msg, ('ff02::1', 0, 0, index))
                    last, pending_rs = now, False
                wait = max(0.1, (3 if pending_rs else cfg.interval) - (time.monotonic() - last))
                ready, _, _ = select.select([sock], [], [], wait)
                if ready:
                    pkt, _ = sock.recvfrom(1500)  # a Router Solicitation: answer soon, but not more often than every 3 seconds (RFC 4861 6.2.6)
                    if len(pkt) >= 8 and pkt[1] == 0:
                        pending_rs = True
            except OSError as e:
                self.stderr.write(f'Router Advertisements: {e!r}')
                time.sleep(1)
