"""TSIG (RFC 8945): the shared-key signature that authenticates DNS UPDATE messages (an IP address alone can be forged over UDP).

Keys: settings.DNS_UPDATE_KEYS, "name:base64secret" separated by commas (the same name and secret as in `nsupdate -y hmac-sha256:name:secret`
or a BIND `key` block). Algorithms: hmac-sha256 and hmac-sha512. The MAC is computed over the bytes received, so it is checked before
anything else is read from the message, and the answer is signed with the same key (nsupdate refuses an unsigned answer).
"""
import base64
import hashlib
import hmac
import struct
import time

from django.conf import settings

TSIG_TYPE, CLASS_ANY = 250, 255
ALGORITHMS = {'hmac-sha256': hashlib.sha256, 'hmac-sha512': hashlib.sha512}


class TsigError(Exception):
    pass


def keys():
    """{key name (lower case, no final dot): secret bytes} from DNS_UPDATE_KEYS; entries that do not decode are ignored."""
    out = {}
    for entry in (settings.DNS_UPDATE_KEYS or '').split(','):
        name, _, secret = entry.strip().partition(':')
        try:
            if name and secret:
                out[name.strip().lower().rstrip('.')] = base64.b64decode(secret.strip(), validate=True)
        except ValueError:
            continue
    return out


def _read_name(wire, i):
    """(name in lower case without the final dot, offset after the name in the message). Follows compression pointers, at most 64 of them."""
    labels, end, hops = [], None, 0
    while True:
        if i >= len(wire):
            raise TsigError('truncated name')
        n = wire[i]
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(wire) or hops > 64:
                raise TsigError('bad pointer')
            end = i + 2 if end is None else end
            i, hops = ((n & 0x3F) << 8) | wire[i + 1], hops + 1
            continue
        if n & 0xC0:
            raise TsigError('bad label')
        i += 1
        if n == 0:
            return '.'.join(labels).lower(), (i if end is None else end)
        labels.append(wire[i:i + n].decode('ascii', 'replace'))
        i += n


def name_wire(name):
    """A name in canonical wire form: lower case, uncompressed."""
    return b''.join(bytes([len(l)]) + l.encode('ascii') for l in name.lower().rstrip('.').split('.') if l) + b'\0'


def _variables(key, alg, signed, fudge, error=0, other=b''):
    return name_wire(key) + struct.pack('!HI', CLASS_ANY, 0) + name_wire(alg) + signed.to_bytes(6, 'big') + struct.pack('!HHH', fudge, error, len(other)) + other


def verify(wire):
    """Check the TSIG record that ends `wire` (a whole request). Returns (key name, algorithm, request MAC). Raises TsigError when there is no
    TSIG, the key is unknown, the MAC is wrong, the time is outside the fudge, or the same MAC was already accepted (a replayed message)."""
    if len(wire) < 12:
        raise TsigError('short message')
    qd, an, ns, ar = struct.unpack('!4H', wire[4:12])
    if ar < 1:
        raise TsigError('no TSIG')
    i = 12
    for _ in range(qd):
        _, i = _read_name(wire, i)
        i += 4
    start = None
    for n in range(an + ns + ar):
        rr = i
        _, i = _read_name(wire, i)
        if i + 10 > len(wire):
            raise TsigError('truncated record')
        rtype, _, _, rdlen = struct.unpack('!HHIH', wire[i:i + 10])
        i += 10 + rdlen
        if rtype == TSIG_TYPE:
            if n != an + ns + ar - 1:
                raise TsigError('TSIG not last')  # RFC 8945 §5.1
            start = rr
    if start is None or i != len(wire):
        raise TsigError('no TSIG')
    key, j = _read_name(wire, start)
    j += 10  # type, class, ttl, rdlength
    alg, j = _read_name(wire, j)
    if j + 10 > len(wire):
        raise TsigError('truncated TSIG')
    signed, fudge, mlen = int.from_bytes(wire[j:j + 6], 'big'), *struct.unpack('!HH', wire[j + 6:j + 10])
    mac = wire[j + 10:j + 10 + mlen]
    j += 10 + mlen
    if j + 6 > len(wire):
        raise TsigError('truncated TSIG')
    orig_id, error, olen = struct.unpack('!HHH', wire[j:j + 6])
    other = wire[j + 6:j + 6 + olen]
    secret = keys().get(key)
    if secret is None or alg not in ALGORITHMS:
        raise TsigError('unknown key')
    body = struct.pack('!H', orig_id) + wire[2:10] + struct.pack('!H', ar - 1) + wire[12:start]  # original id, one record less, no TSIG
    good = hmac.new(secret, body + _variables(key, alg, signed, fudge, error, other), ALGORITHMS[alg]).digest()
    if len(mac) < max(10, len(good) // 2) or not hmac.compare_digest(mac, good[:len(mac)]):
        raise TsigError('bad signature')
    if abs(time.time() - signed) > fudge:
        raise TsigError('bad time')
    from django.core.cache import cache
    try:
        fresh = cache.add('tsig-mac:' + hashlib.sha256(mac).hexdigest(), 1, 2 * fudge + 60)
    except Exception:
        fresh = True  # no cache: the time window still bounds a replay
    if not fresh:
        raise TsigError('replayed')
    return key, alg, mac


def sign(reply_wire, key, alg, request_mac):
    """reply_wire with a TSIG record added, signed over the request MAC and the reply (RFC 8945 §5.3)."""
    reply_wire, secret, signed, fudge = bytes(reply_wire), keys()[key], int(time.time()), 300
    mac = hmac.new(secret, struct.pack('!H', len(request_mac)) + request_mac + reply_wire + _variables(key, alg, signed, fudge), ALGORITHMS[alg]).digest()
    rdata = name_wire(alg) + signed.to_bytes(6, 'big') + struct.pack('!HH', fudge, len(mac)) + mac + reply_wire[:2] + struct.pack('!HH', 0, 0)
    record = name_wire(key) + struct.pack('!HHIH', TSIG_TYPE, CLASS_ANY, 0, len(rdata)) + rdata
    ar = struct.unpack('!H', reply_wire[10:12])[0] + 1
    return reply_wire[:10] + struct.pack('!H', ar) + reply_wire[12:] + record
