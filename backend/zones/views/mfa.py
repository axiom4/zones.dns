import re

from django.conf import settings
from django.core.cache import cache
from drf_spectacular.utils import extend_schema
from rest_framework.authentication import TokenAuthentication
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import mfa
from ..models import Passkey, TotpDevice
from ..serializers import (AdminTicketSerializer, MeSerializer, MfaCodeSerializer, MfaCredentialSerializer, MfaOptionsSerializer, MfaStatusSerializer, MfaTicketSerializer,
                           StepUpCodeSerializer, StepUpCredentialSerializer, StepUpGrantSerializer, StepUpScopeSerializer, TokenResultSerializer, TotpSetupSerializer)
from .token import EncryptedView


# ---- the second-factor steps. Each takes (data, auth_user) and returns the reply body; used by the plain and the encrypted endpoints.
def _login_user(d, auth):
    return mfa.read_ticket(d.get('ticket'), 'verify')


def _enrol_user(d, auth):
    """Already logged in (Security page) or holding the 'setup' ticket of the password step."""
    if auth and auth.is_authenticated:
        if not auth.is_staff:
            raise mfa.MfaError('forbidden')
        return auth
    return mfa.read_ticket(d.get('ticket'), 'setup')


def totp_verify(d, auth):
    user = _login_user(d, auth)
    mfa.guard(user)
    dev = TotpDevice.objects.filter(user=user, confirmed=True).first()
    if not dev or not mfa.check_totp(dev, str(d.get('code', ''))):
        mfa.fail(user)
    return {'token': mfa.token_for(user)}


def passkey_options(d, auth):
    user = _login_user(d, auth)
    if not user.passkeys.exists():
        raise mfa.MfaError('no_passkey')
    return {'options': mfa.authentication_options(user)}


def passkey_verify(d, auth):
    user = _login_user(d, auth)
    mfa.guard(user)
    if not mfa.check_passkey(user, d.get('credential')):
        mfa.fail(user)
    return {'token': mfa.token_for(user)}


def _stepup(d, auth):
    """The logged-in user and the action to confirm (only known actions can be confirmed)."""
    if not (auth and auth.is_authenticated and auth.is_staff):
        raise mfa.MfaError('forbidden')
    scope = str(d.get('scope', ''))
    if not re.fullmatch(r'zone-delete:\d+', scope):
        raise mfa.MfaError('forbidden')
    return auth, scope


def stepup_totp(d, auth):
    user, scope = _stepup(d, auth)
    mfa.guard(user)
    dev = TotpDevice.objects.filter(user=user, confirmed=True).first()
    if not dev or not mfa.check_totp(dev, str(d.get('code', ''))):
        mfa.fail(user)
    return {'grant': mfa.make_grant(user, scope)}


def stepup_passkey_options(d, auth):
    user, _ = _stepup(d, auth)
    if not user.passkeys.exists():
        raise mfa.MfaError('no_passkey')
    return {'options': mfa.authentication_options(user)}


def stepup_passkey_verify(d, auth):
    user, scope = _stepup(d, auth)
    mfa.guard(user)
    if not mfa.check_passkey(user, d.get('credential')):
        mfa.fail(user)
    return {'grant': mfa.make_grant(user, scope)}


def totp_setup(d, auth):
    user = _enrol_user(d, auth)
    secret = mfa.new_secret()
    cache.set(f'totp-new:{user.pk}', secret, 600)
    return {'secret': secret, 'uri': mfa.totp_uri(user, secret)}


def totp_confirm(d, auth):
    user = _enrol_user(d, auth)
    mfa.guard(user)
    secret = cache.get(f'totp-new:{user.pk}')
    if not secret:
        raise mfa.MfaError('setup_expired')
    dev = TotpDevice(user=user, secret=secret, confirmed=True)
    if not mfa.check_totp(dev, str(d.get('code', ''))):
        mfa.fail(user)
    TotpDevice.objects.filter(user=user).delete()
    dev.save()
    cache.delete(f'totp-new:{user.pk}')
    return {'token': mfa.token_for(user)}


def passkey_register_options(d, auth):
    return {'options': mfa.registration_options(_enrol_user(d, auth))}


def passkey_register(d, auth):
    user = _enrol_user(d, auth)
    mfa.register_passkey(user, d.get('credential'), d.get('name'))
    return {'token': mfa.token_for(user)}


ACTIONS = {'totp': totp_verify, 'passkey-options': passkey_options, 'passkey-verify': passkey_verify, 'totp-setup': totp_setup,
           'totp-confirm': totp_confirm, 'passkey-register-options': passkey_register_options, 'passkey-register': passkey_register,
           'stepup-totp': stepup_totp, 'stepup-passkey-options': stepup_passkey_options, 'stepup-passkey-verify': stepup_passkey_verify}


class _Plain(APIView):
    """One step over a plain request. Refused when LOGIN_ENCRYPTION=required: use the encrypted endpoint."""
    authentication_classes = [TokenAuthentication]  # only the enrolment steps use it (Security page)
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    action = ''

    def post(self, request):
        if settings.LOGIN_ENCRYPTION == 'required':
            return Response({'detail': 'Plain requests are disabled: use the encrypted channel.'}, status=403)
        try:
            return Response(ACTIONS[self.action](request.data, request.user))
        except mfa.MfaError as e:
            return Response({'detail': e.text}, status=400)


def _plain(action, req, res, doc):
    @extend_schema(request=req, responses=res)
    def post(self, request):
        return _Plain.post(self, request)
    post.__doc__ = doc
    return type(f'Plain_{action}', (_Plain,), {'action': action, 'post': post})


TotpVerifyView = _plain('totp', MfaCodeSerializer, TokenResultSerializer, 'Finish the login with an authenticator-app code.')
PasskeyOptionsView = _plain('passkey-options', MfaTicketSerializer, MfaOptionsSerializer, 'Challenge for the login with a passkey.')
PasskeyVerifyView = _plain('passkey-verify', MfaCredentialSerializer, TokenResultSerializer, "Finish the login with the browser's answer to the challenge.")
TotpSetupView = _plain('totp-setup', MfaTicketSerializer, TotpSetupSerializer, 'New authenticator-app secret; becomes active when confirmed with a code.')
TotpConfirmView = _plain('totp-confirm', MfaCodeSerializer, TokenResultSerializer, 'Activate the authenticator app with the first code it shows.')
PasskeyRegisterOptionsView = _plain('passkey-register-options', MfaTicketSerializer, MfaOptionsSerializer, 'Challenge to register a new passkey.')
PasskeyRegisterView = _plain('passkey-register', MfaCredentialSerializer, TokenResultSerializer, 'Store the passkey the browser created.')
TotpStepUpView = _plain('stepup-totp', StepUpCodeSerializer, StepUpGrantSerializer, 'Confirm one action (e.g. deleting a zone) with an authenticator-app code: returns a one-use grant.')
PasskeyStepUpOptionsView = _plain('stepup-passkey-options', StepUpScopeSerializer, MfaOptionsSerializer, 'Challenge to confirm one action with a passkey.')
PasskeyStepUpVerifyView = _plain('stepup-passkey-verify', StepUpCredentialSerializer, StepUpGrantSerializer, 'Confirm one action with the browser\'s answer to the challenge: returns a one-use grant.')


class MfaEncryptedView(EncryptedView):
    """Every second-factor step inside the encrypted channel: payload {a: step, d: its data}, reply = the step's body. Nothing readable on the wire."""
    authentication_classes = [TokenAuthentication]  # a logged-in user adding a factor from the Security page

    def handle(self, request, payload):
        step, data = ACTIONS.get(payload.get('a')), payload.get('d')
        if step is None or not isinstance(data, dict):
            return {'error': 'Invalid request.'}, 400
        try:
            return step(data, request.user), 200
        except mfa.MfaError as e:
            return {'error': e.text}, 400


class MfaStatusView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(responses=MfaStatusSerializer)
    def get(self, request):
        """Second factors of the logged-in user."""
        u = request.user
        return Response({'required': settings.MFA_REQUIRED, 'totp': TotpDevice.objects.filter(user=u, confirmed=True).exists(),
                         'passkeys': [{'id': p.id, 'name': p.name, 'created': p.created} for p in u.passkeys.order_by('created')]})


class TotpRemoveView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(request=None, responses={204: None})
    def delete(self, request):
        """Remove the authenticator app (not if it is the last factor and MFA is required)."""
        if settings.MFA_REQUIRED and not request.user.passkeys.exists():
            return Response({'detail': 'It is your only second factor and MFA is mandatory: add another one first.'}, status=400)
        TotpDevice.objects.filter(user=request.user).delete()
        return Response(status=204)


class PasskeyRemoveView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(request=None, responses={204: None})
    def delete(self, request, pk):
        """Remove a passkey (not if it is the last factor and MFA is required)."""
        user = request.user
        has_totp = TotpDevice.objects.filter(user=user, confirmed=True).exists()
        if settings.MFA_REQUIRED and not has_totp and user.passkeys.count() <= 1:
            return Response({'detail': 'It is your only second factor and MFA is mandatory: add another one first.'}, status=400)
        Passkey.objects.filter(user=user, pk=pk).delete()
        return Response(status=204)


class IsSuperuser(IsAdminUser):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_active and request.user.is_superuser)


class MeView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(responses=MeSerializer)
    def get(self, request):
        """Who is logged in, to show only what they can use."""
        return Response({'username': request.user.get_username(), 'is_superuser': request.user.is_superuser, 'default_zone': settings.DEFAULT_ZONE})


class AdminTicketView(APIView):
    permission_classes = [IsSuperuser]  # the Django admin is for superusers only

    @extend_schema(request=None, responses=AdminTicketSerializer)
    def post(self, request):
        """One-use ticket (60 s) that opens the Django admin: the GUI posts it to /admin/sso/."""
        from .. import admin_sso
        return Response({'ticket': admin_sso.make_ticket(request.user)})
