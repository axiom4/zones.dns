from django.conf import settings
from django.db import models


class TotpDevice(models.Model):
    """Authenticator-app secret (RFC 6238). Usable only once confirmed with a first valid code."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='totp')
    secret = models.CharField(max_length=32)  # base32
    confirmed = models.BooleanField(default=False)
    last_step = models.BigIntegerField(default=0)  # last accepted 30 s step: a code works once
    created = models.DateTimeField(auto_now_add=True)


class Passkey(models.Model):
    """A WebAuthn credential (security key, Touch ID, Windows Hello, phone...)."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='passkeys')
    # base64url. shortcut: 255 is the MariaDB limit for unique CharFields; real authenticators use 16-128 byte ids (<= 171 chars), longer ones are refused at registration
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()  # base64url COSE key
    sign_count = models.BigIntegerField(default=0)
    name = models.CharField(max_length=80, blank=True)
    created = models.DateTimeField(auto_now_add=True)
