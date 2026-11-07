from rest_framework import serializers


class EncryptedPacketSerializer(serializers.Serializer):
    p = serializers.CharField(max_length=32768, help_text='Base64 encrypted packet (see zones/login_crypto.py)')


class LoginKeySerializer(serializers.Serializer):
    key = serializers.CharField(help_text='Public key (base64) to encrypt the login packet to; new after every server restart')
