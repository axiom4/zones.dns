from rest_framework import serializers


class LoginResultSerializer(serializers.Serializer):
    """Either token (logged in) or mfa + ticket + methods (a second step is needed)."""
    token = serializers.CharField(required=False)
    mfa = serializers.ChoiceField(['verify', 'setup'], required=False, help_text='verify: prove a factor; setup: enrol the first factor')
    ticket = serializers.CharField(required=False, help_text='Short-lived signed ticket for the next step')
    methods = serializers.ListField(child=serializers.ChoiceField(['totp', 'passkey']), required=False)


class TokenResultSerializer(serializers.Serializer):
    token = serializers.CharField()


class MfaTicketSerializer(serializers.Serializer):
    ticket = serializers.CharField(required=False, allow_blank=True, help_text='Login ticket; not needed when already logged in')


class MfaCodeSerializer(MfaTicketSerializer):
    code = serializers.CharField(max_length=10)


class MfaCredentialSerializer(MfaTicketSerializer):
    credential = serializers.JSONField(help_text='PublicKeyCredential.toJSON() from the browser')
    name = serializers.CharField(required=False, allow_blank=True, max_length=80)


class MfaOptionsSerializer(serializers.Serializer):
    options = serializers.JSONField(help_text='WebAuthn options for PublicKeyCredential.parse*OptionsFromJSON()')


class TotpSetupSerializer(serializers.Serializer):
    secret = serializers.CharField()
    uri = serializers.CharField(help_text='otpauth:// URI (shown as QR code)')


class PasskeyInfoSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    created = serializers.DateTimeField()


class MfaStatusSerializer(serializers.Serializer):
    required = serializers.BooleanField()
    totp = serializers.BooleanField()
    passkeys = PasskeyInfoSerializer(many=True)


class AdminTicketSerializer(serializers.Serializer):
    ticket = serializers.CharField(help_text='One-use ticket (60 s) for POST /admin/sso/')


class MeSerializer(serializers.Serializer):
    username = serializers.CharField()
    is_superuser = serializers.BooleanField()
    default_zone = serializers.CharField(allow_blank=True, help_text='Name of the zone the GUI opens by default (DEFAULT_ZONE)')
