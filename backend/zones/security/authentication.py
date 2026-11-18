from datetime import timedelta

from django.conf import settings
from django.middleware.csrf import get_token
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

COOKIE = 'dns_token'  # the GUI's token: HttpOnly, so a script on the page (XSS) cannot read it and use it elsewhere
COOKIE_PATH = '/api/'


class ExpiringTokenAuthentication(TokenAuthentication):
    """The API token stops working SESSION_MAX_AGE seconds after the sign-in that issued it (absolute, not idle)."""
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token.created < timezone.now() - timedelta(seconds=settings.SESSION_MAX_AGE):
            token.delete()
            raise AuthenticationFailed('Session expired: sign in again.')
        return user, token


class CookieTokenAuthentication(ExpiringTokenAuthentication):
    """The same token in the HttpOnly cookie the GUI gets at sign-in (scripts keep `Authorization: Token`, checked first). The browser sends a
    cookie with any request, so a request that changes something also needs the CSRF header (X-CSRFToken), as Django's session does."""
    def authenticate(self, request):
        key = request.COOKIES.get(COOKIE)
        if not key:
            return None
        try:
            user, token = self.authenticate_credentials(key)
        except AuthenticationFailed:
            return None  # a stale cookie is no sign-in: the sign-in steps and logout must still work with it
        SessionAuthentication().enforce_csrf(request)
        if settings.CSRF_COOKIE_NAME not in request.COOKIES:
            get_token(request._request)  # the cookie went missing: send it again
        return user, token


def with_token_cookie(request, response, body):
    """When body hands out a token (sign-in finished), puts it in the HttpOnly cookie too and sends the CSRF cookie the GUI echoes."""
    if isinstance(body, dict) and body.get('token'):
        response.set_cookie(COOKIE, body['token'], max_age=settings.SESSION_MAX_AGE, path=COOKIE_PATH, secure=settings.SESSION_COOKIE_SECURE,
                            httponly=True, samesite='Strict')
        get_token(request._request)
    return response


def drop_token_cookie(response):
    response.delete_cookie(COOKIE, path=COOKIE_PATH, samesite='Strict')
    return response
