from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class ExpiringTokenAuthentication(TokenAuthentication):
    """The API token stops working SESSION_MAX_AGE seconds after the sign-in that issued it (absolute, not idle)."""
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token.created < timezone.now() - timedelta(seconds=settings.SESSION_MAX_AGE):
            token.delete()
            raise AuthenticationFailed('Session expired: sign in again.')
        return user, token
