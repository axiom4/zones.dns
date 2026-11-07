"""Second factor for the GUI login: authenticator-app code (TOTP) or passkey (WebAuthn).

Password OK -> login_result() answers with a short-lived signed ticket instead of the API token. The token is issued
only after a factor is proven (or, when none is set up yet and MFA is required, after the first one is enrolled).
"""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import time

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from .models import Passkey, TotpDevice

TICKET_AGE = 600  # seconds
MAX_FAILS = 5  # wrong codes per user per FAIL_WINDOW


class MfaError(Exception):
    pass


# ---- tickets and brute-force guard
def make_ticket(user, kind):
    return signing.dumps({'u': user.pk, 'k': kind}, salt='mfa-ticket')


def read_ticket(ticket, kind):
    from django.contrib.auth import get_user_model
    try:
        d = signing.loads(ticket or '', salt='mfa-ticket', max_age=TICKET_AGE)
        if d['k'] != kind:
            raise signing.BadSignature
        return get_user_model().objects.get(pk=d['u'], is_staff=True, is_active=True)
    except (signing.BadSignature, get_user_model().DoesNotExist):
        raise MfaError('Sign-in session expired: sign in again.')


def guard(user):
    if cache.get(f'mfa-fail:{user.pk}', 0) >= MAX_FAILS:
        raise MfaError('Too many wrong attempts: try again in a few minutes.')


def fail(user):
    cache.add(f'mfa-fail:{user.pk}', 0, 300)
    try:
        cache.incr(f'mfa-fail:{user.pk}')
    except ValueError:
        pass
    raise MfaError('Wrong code.')


# ---- TOTP
def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret, step):
    h = hmac.new(base64.b32decode(secret), struct.pack('>Q', step), hashlib.sha1).digest()
    o = h[-1] & 15
    return f'{(struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10**6:06d}'


def check_totp(device, code):
    """True if code is valid now (±1 step) and not used before."""
    now = int(time.time() // 30)
    code = (code or '').replace(' ', '')
    for step in (now - 1, now, now + 1):
        if step > device.last_step and hmac.compare_digest(totp_code(device.secret, step), code):
            device.last_step = step
            if device.pk:
                device.save(update_fields=['last_step'])
            return True
    return False


def totp_uri(user, secret):
    from urllib.parse import quote
    issuer = settings.MFA_ISSUER
    return f'otpauth://totp/{quote(issuer)}:{quote(user.get_username())}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30'


# ---- state and login
def methods(user):
    out = []
    if TotpDevice.objects.filter(user=user, confirmed=True).exists():
        out.append('totp')
    if user.passkeys.exists():
        out.append('passkey')
    return out


def token_for(user):
    return Token.objects.get_or_create(user=user)[0].key


def login_result(user):
    """What a correct password gets: the token, or a ticket for the second step."""
    m = methods(user)
    if m:
        return {'mfa': 'verify', 'ticket': make_ticket(user, 'verify'), 'methods': m}
    if settings.MFA_REQUIRED:
        return {'mfa': 'setup', 'ticket': make_ticket(user, 'setup'), 'methods': []}
    return {'token': token_for(user)}


# ---- WebAuthn
def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def registration_options(user):
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    opts = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID, rp_name=settings.MFA_ISSUER, user_id=str(user.pk).encode(), user_name=user.get_username(),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64(p.credential_id)) for p in user.passkeys.all()])
    cache.set(f'webauthn-reg:{user.pk}', opts.challenge, 300)
    return json.loads(options_to_json(opts))


def register_passkey(user, credential, name):
    from webauthn import verify_registration_response
    challenge = cache.get(f'webauthn-reg:{user.pk}')
    if not challenge:
        raise MfaError('Request expired: try again.')
    cache.delete(f'webauthn-reg:{user.pk}')
    try:
        v = verify_registration_response(credential=credential, expected_challenge=challenge, expected_rp_id=settings.WEBAUTHN_RP_ID,
                                         expected_origin=settings.WEBAUTHN_ORIGINS)
    except Exception:
        raise MfaError('Invalid passkey or domain not allowed (check WEBAUTHN_RP_ID and WEBAUTHN_ORIGINS).')
    return Passkey.objects.create(user=user, credential_id=_b64(v.credential_id), public_key=_b64(v.credential_public_key),
                                  sign_count=v.sign_count, name=(name or 'Passkey').strip()[:80])


def authentication_options(user):
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    opts = generate_authentication_options(rp_id=settings.WEBAUTHN_RP_ID,
                                           allow_credentials=[PublicKeyCredentialDescriptor(id=_unb64(p.credential_id)) for p in user.passkeys.all()])
    cache.set(f'webauthn-auth:{user.pk}', opts.challenge, 300)
    return json.loads(options_to_json(opts))


def check_passkey(user, credential):
    from webauthn import verify_authentication_response
    challenge = cache.get(f'webauthn-auth:{user.pk}')
    pk = user.passkeys.filter(credential_id=(credential or {}).get('id', '')).first() if isinstance(credential, dict) else None
    if not challenge or not pk:
        return False
    cache.delete(f'webauthn-auth:{user.pk}')  # one challenge, one try
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=challenge, expected_rp_id=settings.WEBAUTHN_RP_ID,
                                           expected_origin=settings.WEBAUTHN_ORIGINS, credential_public_key=_unb64(pk.public_key),
                                           credential_current_sign_count=pk.sign_count)
    except Exception:
        return False
    pk.sign_count = v.new_sign_count
    pk.save(update_fields=['sign_count'])
    return True
