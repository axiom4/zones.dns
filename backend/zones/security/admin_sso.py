"""The Django admin is entered only from the GUI, never with its own password form.

The GUI (password + second factor, all inside the encrypted channel) asks POST /api/admin-ticket/ for a one-use ticket and
posts it to /admin/sso/, which starts the admin session. /admin/login/ just sends people to the GUI, so the admin has
no separate password door to guess; a session that did not come through here is ended.
"""
import secrets
import time

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.core import signing
from django.core.cache import cache
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

SESSION_KEY = 'admin_sso_at'
TICKET_AGE = 60  # seconds
OPEN = ('/admin/sso/', '/admin/login/', '/admin/logout/')


def make_ticket(user):
    return signing.dumps({'u': user.pk, 'j': secrets.token_urlsafe(12)}, salt='admin-sso')


class AdminSsoMiddleware:
    """An admin session is ended unless it came through /admin/sso/ and belongs to a superuser (also for sessions opened before that rule)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        p = request.path
        sso_at = request.session.get(SESSION_KEY)
        valid_sso = isinstance(sso_at, int) and (time.time() - sso_at <= settings.SESSION_MAX_AGE)
        if p.startswith('/admin/') and not p.startswith(OPEN) and request.user.is_authenticated and not (valid_sso and request.user.is_superuser):
            logout(request)
            return redirect('admin:login')
        return self.get_response(request)


def admin_login(request):
    return redirect(settings.GUI_URL)


@csrf_exempt  # the signed one-use ticket is the credential
@require_POST
def admin_sso(request):
    try:
        d = signing.loads(request.POST.get('ticket', ''), salt='admin-sso', max_age=TICKET_AGE)
        user = get_user_model().objects.get(pk=d['u'], is_superuser=True, is_active=True)
    except (signing.BadSignature, get_user_model().DoesNotExist):
        return redirect(settings.GUI_URL)
    if not cache.add(f'admin-sso:{d["j"]}', 1, timeout=2 * TICKET_AGE):
        return redirect(settings.GUI_URL)  # already used
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    request.session[SESSION_KEY] = int(time.time())
    return redirect('/admin/')
