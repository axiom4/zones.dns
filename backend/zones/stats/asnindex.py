"""IP -> ASN from a compact index built by `manage.py import_asn` (ipverse/as-ip-blocks: the prefixes each ASN announces in BGP).

It fills in what the .mmdb ASN database lacks (see geoip.lookup). The index is a sorted file of non-overlapping ranges (the most specific
prefix wins), searched in place with mmap: nothing is loaded in memory, and it is reopened by itself when import_asn replaces it.
"""
import ipaddress
import json
import mmap
import os
import re
import struct
import tarfile
import threading

from django.conf import settings

HEAD, R4, R6 = struct.Struct('>4sII'), struct.Struct('>III'), struct.Struct('>16s16sI')  # magic, counts | start, end, asn (IPv6: 16-byte addresses)
MAGIC = b'ASNX'
MEMBER = re.compile(r'^(?:\./)?as/(\d+)/(ipv4|ipv6)-aggregated\.txt$')


def flatten(prefixes):
    """[(start, end, asn)] in any order, nested prefixes allowed -> sorted, non-overlapping ranges where the innermost prefix wins."""
    out, stack, pos = [], [], 0

    def emit(s, e, asn):
        if s > e:
            return
        if out and out[-1][2] == asn and out[-1][1] + 1 == s:
            out[-1] = (out[-1][0], e, asn)
        else:
            out.append((s, e, asn))

    for s, e, asn in sorted(prefixes, key=lambda p: (p[0], -p[1])):
        while stack and stack[-1][0] < s:  # the enclosing prefixes that end before this one starts
            pe, pasn = stack.pop()
            emit(pos, pe, pasn)
            pos = pe + 1
        if stack:
            emit(pos, s - 1, stack[-1][1])
        pos = s
        stack.append((e, asn))
    while stack:
        pe, pasn = stack.pop()
        emit(pos, pe, pasn)
        pos = pe + 1
    return out


def read_archive(fileobj):
    """Stream the as-ip-blocks tarball (never extracted to disk). Returns (v4 ranges, v6 ranges, {asn: name})."""
    v4, v6, names = [], [], {}
    with tarfile.open(fileobj=fileobj, mode='r|gz') as tar:
        for m in tar:
            hit = m.isfile() and MEMBER.match(m.name)
            if not hit:
                continue
            asn, fam = int(hit[1]), hit[2]
            if asn > 0xFFFFFFFF:
                continue
            lines = tar.extractfile(m).read(50_000_000).decode('utf-8', 'replace').splitlines()
            if asn not in names and len(lines) > 1 and lines[1].startswith('# '):
                names[asn] = lines[1][2:].strip()[:200]  # header: "# AS1234 (HANDLE)" then "# description"
            for line in lines:
                line = line.strip()
                if not line or line[0] == '#':
                    continue
                try:
                    n = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                (v4 if fam == 'ipv4' else v6).append((int(n.network_address), int(n.broadcast_address), asn))
    return v4, v6, names


def write(path, v4, v6, names):
    """Write the index and the names file next to it. Each is replaced atomically; the names first, so the index never points at older names."""
    r4, r6 = flatten(v4), flatten(v6)
    with open(path + '.json.tmp', 'w') as f:
        json.dump({str(k): v for k, v in names.items()}, f, separators=(',', ':'))
    with open(path + '.tmp', 'wb') as f:
        f.write(HEAD.pack(MAGIC, len(r4), len(r6)))
        for s, e, a in r4:
            f.write(R4.pack(s, e, a))
        for s, e, a in r6:
            f.write(R6.pack(s.to_bytes(16, 'big'), e.to_bytes(16, 'big'), a))
    os.replace(path + '.json.tmp', path + '.json')
    os.replace(path + '.tmp', path)
    return len(r4), len(r6)


class _Index:
    def __init__(self):
        self.lock, self.mtime, self.state = threading.Lock(), None, None

    def _open(self, path):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return False
        if mtime != self.mtime:
            with self.lock:
                if mtime != self.mtime:
                    try:
                        with open(path, 'rb') as f:
                            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                        magic, n4, n6 = HEAD.unpack_from(mm, 0)
                        if magic != MAGIC:
                            return False
                        try:
                            with open(path + '.json') as f:
                                names = {int(k): v for k, v in json.load(f).items()}
                        except (OSError, ValueError):
                            names = {}
                        self.state = (mm, n4, n6, names)
                        self.mtime = mtime
                    except (OSError, ValueError, struct.error):
                        return False
        return self.state is not None

    def lookup(self, ip):
        """(asn, name) of the range containing ip, or None."""
        path = getattr(settings, 'ASN_INDEX', '')
        if not path or not self._open(path):
            return None
        mm, n4, n6, names = self.state
        a = ipaddress.ip_address(ip)
        if a.version == 4:
            base, n, rec, key = HEAD.size, n4, R4, int(a)
            get = lambda i: rec.unpack_from(mm, base + i * rec.size)
        else:
            base, n, rec, key = HEAD.size + n4 * R4.size, n6, R6, a.packed
            get = lambda i: rec.unpack_from(mm, base + i * rec.size)
        lo, hi = 0, n  # last range whose start <= key
        while lo < hi:
            mid = (lo + hi) // 2
            if get(mid)[0] <= key:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        s, e, asn = get(lo - 1)
        return (asn, names.get(asn, '')) if key <= e else None


_index = _Index()
lookup = _index.lookup
