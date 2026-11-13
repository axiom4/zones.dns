import time

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.cache import cache
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ..security import login_crypto, mfa
from ..serializers import EncryptedPacketSerializer, LoginKeySerializer, LoginResultSerializer


NOT_STAFF = 'User not enabled for the GUI: in the Django admin turn on "Staff status" for this user.'


def client_ip(request):
    """Real client IP for login rate limiting: trusts X-Real-IP / X-Forwarded-For only when BEHIND_PROXY=true."""
    if settings.BEHIND_PROXY:
        real = request.META.get('HTTP_X_REAL_IP', '').strip()
        if real:
            return real[:64]
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if xff:
            return xff.split(',')[0].strip()[:64]
    return request.META.get('REMOTE_ADDR', '')[:64]


class TokenView(APIView):
    """Plain login. Refused when LOGIN_ENCRYPTION=required. Answers with the token, or with a ticket when a second factor is needed."""
    authentication_classes = []
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    @extend_schema(request=inline_serializer('TokenCredentials', {'username': serializers.CharField(), 'password': serializers.CharField()}),
                   responses=LoginResultSerializer)
    def post(self, request):
        if settings.LOGIN_ENCRYPTION == 'required':
            return Response({'detail': 'Plain sign-in is disabled: use the encrypted sign-in.'}, status=403)
        uname = str(request.data.get('username', ''))
        ip = client_ip(request)
        try:
            mfa.login_guard(f'u:{uname[:64]}')
            mfa.login_guard(f'ip:{ip}')
        except mfa.MfaError as e:
            return Response({'detail': e.text}, status=429)
        user = authenticate(request, username=uname, password=str(request.data.get('password', '')))
        if user is None:
            mfa.login_fail(f'u:{uname[:64]}')
            mfa.login_fail(f'ip:{ip}')
            return Response({'detail': 'Wrong credentials.'}, status=400)
        if not user.is_staff:  # only someone who knows the password sees this
            return Response({'detail': NOT_STAFF}, status=400)
        return Response(mfa.login_result(user))


class EncryptedView(APIView):
    """Base of the views whose whole request is one encrypted packet and so is the reply. Subclasses implement handle()."""
    authentication_classes = []
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def handle(self, request, payload):
        """Return (body dict, status)."""
        raise NotImplementedError

    @extend_schema(request=EncryptedPacketSerializer, responses=EncryptedPacketSerializer)
    def post(self, request):
        if settings.LOGIN_ENCRYPTION == 'off':
            return Response({'detail': 'Encrypted sign-in is not active.'}, status=404)
        s = EncryptedPacketSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            payload, reply = login_crypto.open_packet(s.validated_data['p'])
        except ValueError:
            return Response({'detail': 'Invalid packet.'}, status=400)  # can't answer in cipher; also what a client with a pre-restart key gets

        def answer(body, status):
            return Response({'p': reply({**body, 'n': payload['n']})}, status=status)  # n binds the reply to this request

        if abs(time.time() * 1000 - payload['t']) > login_crypto.MAX_SKEW_MS:
            return answer({'error': 'Packet expired: check the client clock.'}, 400)
        if not cache.add(f'login-nonce:{payload["n"]}', 1, timeout=2 * login_crypto.MAX_SKEW_MS // 1000):
            return answer({'error': 'Packet already used.'}, 400)
        body, status = self.handle(request, payload)
        return answer(body, status)


class EncryptedTokenView(EncryptedView):
    """Encrypted password login."""

    def handle(self, request, payload):
        if not (isinstance(payload.get('u'), str) and isinstance(payload.get('p'), str)):
            return {'error': 'Invalid packet.'}, 400
        uname = payload['u']
        ip = client_ip(request)
        try:
            mfa.login_guard(f'u:{uname[:64]}')
            mfa.login_guard(f'ip:{ip}')
        except mfa.MfaError as e:
            return {'error': e.text}, 429
        user = authenticate(request, username=uname, password=payload['p'])
        if user is None:
            mfa.login_fail(f'u:{uname[:64]}')
            mfa.login_fail(f'ip:{ip}')
            return {'error': 'Wrong credentials.'}, 401
        if not user.is_staff:
            return {'error': NOT_STAFF}, 403
        return mfa.login_result(user), 200


class LoginKeyView(APIView):
    """Public key for the encrypted login. A new key pair is made at every server start."""
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(responses=LoginKeySerializer)
    def get(self, request):
        if settings.LOGIN_ENCRYPTION == 'off':
            return Response({'detail': 'Encrypted sign-in is not active.'}, status=404)
        return Response({'key': login_crypto.public_key_b64()}, headers={'Cache-Control': 'no-store'})
