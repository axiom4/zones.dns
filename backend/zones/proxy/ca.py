"""Local Root CA and dynamic per-host leaf certificates for optional HTTPS MITM content filtering."""
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import ssl
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.db import DatabaseError, transaction

from ..models import DataVersion, Setting

CA_CERT_KEY = 'proxy:ca_cert'
CA_PRIV_KEY = 'proxy:ca_key'

_lock = threading.Lock()
_cached_ca = None  # (cert_pem, key_pem, x509_cert, private_key)
_leaf_contexts = OrderedDict()  # host -> ssl.SSLContext
_LEAF_MAX = 512


CA_DAYS = 5 * 365  # a stolen CA key works on every device that trusts it until it expires


def _key_password():
    """The CA private key is stored encrypted with a password derived from SECRET_KEY: the database (or a backup of it) alone does not give it away."""
    return hashlib.sha256(b'zones-proxy-ca:' + settings.SECRET_KEY.encode()).hexdigest().encode()


def _encrypt_key(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_key_password()),
    ).decode()


def _load_key(key_pem):
    """(key, plaintext): the stored key, and whether it was stored without encryption (before it was encrypted: it is then saved again)."""
    try:
        return serialization.load_pem_private_key(key_pem.encode(), password=_key_password()), False
    except TypeError:  # not encrypted
        return serialization.load_pem_private_key(key_pem.encode(), password=None), True


def _generate_ca():
    """Generate a new ECDSA P-256 Root CA certificate and private key (valid CA_DAYS)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Zones.dns Proxy Root CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Zones.dns'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, _encrypt_key(key), cert, key


def ensure_ca(regenerate=False, refresh=False):
    """Return (cert_pem, encrypted key_pem, cert_obj, key_obj), creating and storing the CA in Setting if needed.
    `refresh`: read the database again, the CA may have been made anew by another process (the GUI's "new Root CA")."""
    global _cached_ca
    with _lock:
        if not regenerate and not refresh and _cached_ca is not None:
            return _cached_ca
        try:
            rows = dict(Setting.objects.filter(key__in=(CA_CERT_KEY, CA_PRIV_KEY)).values_list('key', 'value'))
        except DatabaseError:
            if _cached_ca is not None and not regenerate:
                return _cached_ca  # a refresh while the database is away: never a new CA for that
            if not regenerate:
                raise  # a failed read says nothing about the stored CA: never a new CA for that
            rows = {}
        cert_pem, key_pem = rows.get(CA_CERT_KEY, ''), rows.get(CA_PRIV_KEY, '')
        if not regenerate and cert_pem and key_pem:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode())
                key, plaintext = _load_key(key_pem)
                if _cached_ca is not None and _cached_ca[0] != cert_pem:
                    _leaf_contexts.clear()  # signed by the old CA
                if plaintext:
                    key_pem = _encrypt_key(key)
                    try:
                        Setting.objects.filter(key=CA_PRIV_KEY).update(value=key_pem)
                    except DatabaseError:
                        pass  # encrypted at the next start
                _cached_ca = (cert_pem, key_pem, cert, key)
                return _cached_ca
            except ValueError:
                # unreadable, or SECRET_KEY changed: a new CA, that every client has to install again
                print('Proxy: the stored Root CA key cannot be read (SECRET_KEY changed?): a new Root CA is made', file=sys.stderr, flush=True)
        cert_pem, key_pem, cert, key = _generate_ca()
        try:
            with transaction.atomic():
                Setting.objects.update_or_create(key=CA_CERT_KEY, defaults={'value': cert_pem})
                Setting.objects.update_or_create(key=CA_PRIV_KEY, defaults={'value': key_pem})
                DataVersion.bump()
        except DatabaseError:
            pass  # migration 0037 not applied yet on PostgreSQL/MySQL: keep CA in memory until `manage.py migrate` is run
        _cached_ca = (cert_pem, key_pem, cert, key)
        _leaf_contexts.clear()
        return _cached_ca


def ca_info(regenerate=False):
    """Metadata and PEM certificate of the Proxy Root CA (never exposes the private key)."""
    cert_pem, _, cert, _ = ensure_ca(regenerate=regenerate, refresh=True)
    der = cert.public_bytes(serialization.Encoding.DER)
    fp = ':'.join(f'{b:02X}' for b in hashlib.sha256(der).digest())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        'subject': cn[0].value if cn else 'Zones.dns Proxy Root CA',
        'fingerprint': fp,
        'expires': cert.not_valid_after_utc,
        'pem': cert_pem,
    }


def build_leaf_pem(host):
    """Generate a leaf certificate and private key PEM signed by the Proxy Root CA for `host`."""
    host = host.strip().lower().rstrip('.')
    ca_cert_pem, _, ca_cert, ca_key = ensure_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    try:
        ip = ipaddress.ip_address(host.strip('[]'))
        san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(host)])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,  # an EC key signs, it never encrypts a key (RFC 5480 3)
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_pem = cert.public_bytes(serialization.Encoding.PEM).decode() + ca_cert_pem
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return leaf_pem, key_pem


def leaf_context(host):
    """Return a cached server-side ssl.SSLContext for `host` signed by the Proxy Root CA."""
    host = host.strip().lower().rstrip('.')
    with _lock:
        if host in _leaf_contexts:
            _leaf_contexts.move_to_end(host)
            return _leaf_contexts[host]
    ensure_ca()
    leaf_pem, key_pem = build_leaf_pem(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_alpn_protocols(['h2', 'http/1.1'])  # HTTP/2 towards the browser when it offers it (zones/proxy/h2conn.py)
    except NotImplementedError:
        pass
    with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=True) as cf, tempfile.NamedTemporaryFile('w', suffix='.key', delete=True) as kf:
        cf.write(leaf_pem)
        cf.flush()
        kf.write(key_pem)
        kf.flush()
        ctx.load_cert_chain(certfile=cf.name, keyfile=kf.name)
    with _lock:
        _leaf_contexts[host] = ctx
        if len(_leaf_contexts) > _LEAF_MAX:
            _leaf_contexts.popitem(last=False)
    return ctx
