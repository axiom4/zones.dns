"""Encrypted login and second-factor packets (NaCl crypto_box: Curve25519 + XSalsa20-Poly1305).

The server makes a new key pair each time it starts and keeps it only in memory; clients read the public key from
GET /api/login-key/ right before logging in, so the key is different after every restart.

Request  p = base64( client_ephemeral_pub[32] || nonce[24] || box(payload) )   payload = JSON {t, n, ...fields}: login {u, p}, second factor {a: action, d: data}
Response p = base64( nonce[24] || box(body) )   encrypted for the same ephemeral key, so only that client can read it.
Nothing about the login (not even the user name) travels in clear text.

Note: the key lives in the memory of one process. Run the server as a single process (several workers would each have their own key).
"""
import base64
import json
import threading

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

MAX_SKEW_MS = 60_000

_lock = threading.Lock()
_key = None


def private_key():
    """This process's key pair, created on first use (which is always before the first login)."""
    global _key
    if _key is None:
        with _lock:
            if _key is None:
                _key = PrivateKey.generate()
    return _key


def public_key_b64():
    return base64.b64encode(bytes(private_key().public_key)).decode()


def open_packet(packet_b64):
    """Return (payload dict, reply(body) -> base64 str). Raises ValueError for anything malformed or forged."""
    try:
        raw = base64.b64decode(packet_b64, validate=True)
        if len(raw) < 32 + 24 + 16:
            raise ValueError('too short')
        box = Box(private_key(), PublicKey(raw[:32]))
        payload = json.loads(box.decrypt(raw[32:]))
        ok = (isinstance(payload, dict) and isinstance(payload.get('t'), int) and isinstance(payload.get('n'), str) and 8 <= len(payload['n']) <= 64)
        if not ok:
            raise ValueError('bad payload')
    except (ValueError, TypeError, CryptoError) as e:
        raise ValueError('invalid packet') from e
    return payload, lambda body: base64.b64encode(box.encrypt(json.dumps(body).encode())).decode()
