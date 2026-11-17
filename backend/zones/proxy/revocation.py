"""Revocation of upstream certificates when the proxy inspects HTTPS (MITM): the browser sees only the proxy's certificate, so the proxy checks.

CRL first (it does not tell the CA which site is visited), OCSP when the certificate has no CRL. Soft-fail, like browsers: a connection is
refused only when a CRL or an OCSP responder says the certificate is revoked, never because the check could not be done. The first
connection to a site never waits: the answer is fetched in the background and used from the next connection on.
"""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import sys
import threading
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from django.conf import settings

MAX_CRL_BYTES = 20 * 1024 * 1024
MAX_OCSP_BYTES = 64 * 1024
MIN_TTL, MAX_TTL = 600.0, 86400.0
FAIL_TTL = 900.0  # a CRL or responder that did not answer is asked again after this long
_MAX_ENTRIES = 20000
_MAX_CRLS = 64

_lock = threading.Lock()
_status = OrderedDict()  # (issuer key hash, serial) -> (expires_at, revoked)
_crls = OrderedDict()  # url -> (expires_at, CertificateRevocationList or None)
_inflight = set()
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='proxy-revocation')


def fetch(url, body=None, limit=MAX_CRL_BYTES):
    """GET (or POST an OCSP request to) a CA URL; the bytes, at most `limit`."""
    req = urllib.request.Request(url, data=body, headers={'User-Agent': 'zones-dns/1.0', **({'Content-Type': 'application/ocsp-request'} if body else {})})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise OSError(f'{url}: answer larger than {limit} bytes')
    return data


def _ttl(next_update):
    if next_update is None:
        return MIN_TTL
    return max(MIN_TTL, min(MAX_TTL, (next_update - datetime.now(timezone.utc)).total_seconds()))


def _key(leaf, issuer):
    der = issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest(), leaf.serial_number


def _urls(cert, oid):
    try:
        ext = cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return []
    if oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
        names = [n for dp in ext for n in (dp.full_name or ())]
    else:
        names = [d.access_location for d in ext if d.access_method == AuthorityInformationAccessOID.OCSP]
    return [n.value for n in names if isinstance(n, x509.UniformResourceIdentifier) and n.value.startswith('http')]


def _crl(url, issuer):
    """The CRL at `url`, cached until its nextUpdate; None when it cannot be fetched or is not signed by `issuer`."""
    now = time.monotonic()
    with _lock:
        hit = _crls.get(url)
        if hit and hit[0] > now:
            return hit[1]
    crl, ttl = None, FAIL_TTL
    try:
        data = fetch(url)
        loaded = x509.load_der_x509_crl(data) if not data.startswith(b'-----') else x509.load_pem_x509_crl(data)
        if loaded.is_signature_valid(issuer.public_key()):
            crl, ttl = loaded, _ttl(loaded.next_update_utc)
    except Exception as e:
        print(f'Proxy: revocation list {url} not usable: {e!r}', file=sys.stderr, flush=True)
    with _lock:
        _crls[url] = (time.monotonic() + ttl, crl)
        while len(_crls) > _MAX_CRLS:
            _crls.popitem(last=False)
    return crl


def _ocsp(url, leaf, issuer):
    """True/False from the responder, None when it gives no usable answer; with the seconds it may be kept."""
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
    try:
        resp = ocsp.load_der_ocsp_response(fetch(url, req.public_bytes(serialization.Encoding.DER), MAX_OCSP_BYTES))
    except Exception as e:
        print(f'Proxy: OCSP responder {url} not usable: {e!r}', file=sys.stderr, flush=True)
        return None, FAIL_TTL
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL or resp.serial_number != leaf.serial_number:
        return None, FAIL_TTL
    # shortcut: the responder's signature is not checked; a forged "good" is the same as no check (soft-fail), a forged "revoked" only blocks
    # a site that whoever forges it could already block on the path
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return True, _ttl(resp.next_update_utc)
    if resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return False, _ttl(resp.next_update_utc)
    return None, FAIL_TTL


def lookup(leaf, issuer):
    """Fetch the revocation state of `leaf` and remember it. Returns True (revoked), False (good) or None (unknown)."""
    key = _key(leaf, issuer)
    revoked, ttl = None, FAIL_TTL
    try:
        crl_urls = _urls(leaf, ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for url in crl_urls[:2]:
            crl = _crl(url, issuer)
            if crl is not None:
                revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
                ttl = _ttl(crl.next_update_utc)
                break
        if revoked is None and not crl_urls:
            for url in _urls(leaf, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)[:1]:
                revoked, ttl = _ocsp(url, leaf, issuer)
    finally:
        with _lock:
            _status[key] = (time.monotonic() + ttl, revoked)
            while len(_status) > _MAX_ENTRIES:
                _status.popitem(last=False)
            _inflight.discard(key)
    return revoked


def is_revoked(der_chain):
    """True when the chain's certificate is known to be revoked. Never blocks: unknown certificates are looked up in the background."""
    if not getattr(settings, 'PROXY_REVOCATION', True) or len(der_chain) < 2:
        return False
    try:
        leaf, issuer = (x509.load_der_x509_certificate(bytes(c)) for c in der_chain[:2])
        key = _key(leaf, issuer)
    except Exception:
        return False
    with _lock:
        hit = _status.get(key)
        if hit and hit[0] > time.monotonic():
            return bool(hit[1])
        if key in _inflight:
            return False
        _inflight.add(key)
    _pool.submit(lookup, leaf, issuer)
    return False


def reset():
    with _lock:
        _status.clear()
        _crls.clear()
        _inflight.clear()
