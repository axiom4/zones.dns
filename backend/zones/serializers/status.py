from rest_framework import serializers


class DaemonStatusSerializer(serializers.Serializer):
    command = serializers.CharField(help_text='The manage.py command that runs it')
    enabled = serializers.BooleanField(help_text='Turned on in the settings (DNS: always)')
    running = serializers.BooleanField(help_text='It wrote its heartbeat in the last 90 seconds')
    last_seen = serializers.DateTimeField(allow_null=True, help_text='Its last heartbeat; null: never')
    pid = serializers.IntegerField(allow_null=True)
    version = serializers.CharField(allow_blank=True)


class StatusSerializer(serializers.Serializer):
    dns = DaemonStatusSerializer()
    dhcp = DaemonStatusSerializer()
    proxy = DaemonStatusSerializer()
