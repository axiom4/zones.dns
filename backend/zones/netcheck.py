"""Is a host of the network up: one ICMP echo request sent from here (RFC 792, RFC 4443), the answer matched by source address and sequence number.

The socket is an unprivileged ICMP "datagram" socket (macOS; Linux when the group is in net.ipv4.ping_group_range), else a raw one (root or CAP_NET_RAW).
When the system allows neither, the `ping` program is run instead."""
import ipaddress
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

MAX_HOSTS = 64
TIME = re.compile(r'time[=<]\s*([\d.]+)')
TTL = re.compile(r'ttl[= ](\d+)', re.I)
SIZE = re.compile(r'(\d+) bytes from')
DATA = 56  # bytes of data in the request, like `ping`: 64 bytes with the 8 of the ICMP header


def allowed(ip):
    """Only addresses of a local network (private, link-local, unique local): this server must not be a tool to probe the Internet."""
    return ip.is_private and not ip.is_unspecified and not ip.is_multicast


def checksum(data):
    """The Internet checksum (RFC 1071) of the bytes."""
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def echo_request(version, ident, seq):
    """An ICMP (v4: type 8) or ICMPv6 (type 128) echo request. ICMPv6 has its checksum filled in by the kernel."""
    body = struct.pack('!HH', ident, seq) + b'dns-admin ping '.ljust(DATA, b'.')
    head = struct.pack('!BBH', 8 if version == 4 else 128, 0, 0)
    return head[:2] + struct.pack('!H', checksum(head + body) if version == 4 else 0) + body


def is_reply(version, data, seq, ident=None):
    """Is this packet the echo reply with this sequence number (and identifier, when the kernel keeps ours)? A raw IPv4 socket delivers the IP header too."""
    return _icmp(version, data, seq, ident) is not None


def _icmp(version, data, seq, ident=None):
    """(the ICMP part of the packet, the TTL of its IP header or None) when it is our echo reply, else None."""
    ttl = None
    if version == 4 and data and data[0] >> 4 == 4:
        ttl, data = data[8], data[(data[0] & 15) * 4:]
    if len(data) < 8 or data[0] != (0 if version == 4 else 129):
        return None
    got_ident, got_seq = struct.unpack('!HH', data[4:8])
    return (data, ttl) if got_seq == seq and (ident is None or got_ident == ident) else None


DOWN = (False, None, None, None)


class Unavailable(Exception):
    """The system lets this program open neither kind of ICMP socket."""


def _socket(version):
    family, proto = (socket.AF_INET, socket.IPPROTO_ICMP) if version == 4 else (socket.AF_INET6, socket.IPPROTO_ICMPV6)
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            return socket.socket(family, kind, proto), kind
        except OSError:
            continue
    raise Unavailable


_seq = iter(range(1, 1 << 62))  # next() on an itertools-like iterator is atomic enough for threads; only the low 16 bits go on the wire


def ping_socket(ip, timeout=1.0):
    """(up, milliseconds, ttl, bytes of the reply) with our own packet (the last three None when down); raises Unavailable when no ICMP socket can be opened."""
    sock, kind = _socket(ip.version)
    seq, ident = next(_seq) & 0xFFFF, os.getpid() & 0xFFFF
    level, option = (socket.IPPROTO_IP, getattr(socket, 'IP_RECVTTL', None)) if ip.version == 4 else (socket.IPPROTO_IPV6, getattr(socket, 'IPV6_RECVHOPLIMIT', None))
    kinds = {getattr(socket, n) for n in ('IP_TTL', 'IP_RECVTTL', 'IPV6_HOPLIMIT') if hasattr(socket, n)}  # what the cmsg type is called depends on the system
    with sock:
        sock.setblocking(False)
        if option is not None:
            try:
                sock.setsockopt(level, option, 1)  # the kernel hands over the TTL (hop limit) of the reply as ancillary data
            except OSError:
                option = None
        start = time.monotonic()
        try:
            sock.sendto(echo_request(ip.version, ident, seq), (str(ip), 0))
        except OSError:
            return DOWN  # no route, network unreachable, firewall
        while (left := timeout - (time.monotonic() - start)) > 0:
            if not select.select([sock], [], [], left)[0]:
                break
            try:
                data, anc, _, peer = sock.recvmsg(1500, 64)
            except OSError:
                continue
            try:
                same = ipaddress.ip_address(peer[0].split('%')[0]) == ip
            except ValueError:
                same = False
            # a datagram socket on Linux rewrites the identifier, so only a raw one can check it
            found = _icmp(ip.version, data, seq, ident if kind == socket.SOCK_RAW else None) if same else None
            if found:
                ttl = found[1]
                for lvl, typ, value in anc:
                    if lvl == level and typ in kinds and value:
                        ttl = value[0] if len(value) == 1 else int.from_bytes(value[:4], sys.byteorder)
                return True, round((time.monotonic() - start) * 1000, 2), ttl, len(found[0])
    return DOWN


def ping_command(ip, timeout=1):
    """The same with the system's `ping` program."""
    if ip.version == 6:
        cmd = ['ping6', '-c', '1', str(ip)] if sys.platform == 'darwin' else ['ping', '-6', '-c', '1', '-W', str(timeout), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout * 1000 if sys.platform == 'darwin' else timeout), str(ip)]  # -W: milliseconds on macOS, seconds on Linux
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except (OSError, subprocess.TimeoutExpired):
        return DOWN
    m, t, n = TIME.search(r.stdout), TTL.search(r.stdout), SIZE.search(r.stdout)
    if r.returncode != 0:
        return DOWN
    return True, (float(m.group(1)) if m else None), (int(t.group(1)) if t else None), (int(n.group(1)) if n else None)


def ping_one(ip, timeout=1):
    """(up, milliseconds or None) for an ipaddress object."""
    try:
        return ping_socket(ip, timeout)
    except Unavailable:
        return ping_command(ip, timeout)


def ping_many(addresses):
    """[{'address', 'up', 'ms', 'ttl', 'bytes', 'error'}] in the order given. A name, a public address or too many hosts get an error instead of a ping."""
    out, todo = [], []
    for a in addresses[:MAX_HOSTS]:
        try:
            ip = ipaddress.ip_address(str(a).strip())
        except ValueError:
            out.append({'address': str(a)[:64], 'up': False, 'ms': None, 'ttl': None, 'bytes': None, 'error': 'Not an IP address.'})
            continue
        if not allowed(ip):
            out.append({'address': str(ip), 'up': False, 'ms': None, 'ttl': None, 'bytes': None, 'error': 'Only addresses of a local network can be pinged.'})
            continue
        out.append({'address': str(ip), 'up': False, 'ms': None, 'ttl': None, 'bytes': None, 'error': ''})
        todo.append((len(out) - 1, ip))
    with ThreadPoolExecutor(max_workers=16) as pool:
        for (i, _), (up, ms, ttl, size) in zip(todo, pool.map(lambda t: ping_one(t[1]), todo)):
            out[i].update(up=up, ms=ms, ttl=ttl, bytes=size)
    return out
