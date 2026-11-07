from rest_framework import serializers

from ..models import QueryLog


class AnswerSerializer(serializers.Serializer):
    name = serializers.CharField()
    type = serializers.CharField()
    value = serializers.CharField()
    ttl = serializers.IntegerField()


class ResolvedSerializer(serializers.Serializer):
    type = serializers.CharField()
    value = serializers.CharField()


class QueryLogSerializer(serializers.ModelSerializer):
    """List item. The answer records are heavy, so they are served separately (see QueryLogAnswersSerializer)."""

    class Meta:
        model = QueryLog
        fields = ['id', 'time', 'name', 'domain', 'type', 'outcome', 'client', 'ms', 'rcode', 'via']


class QueryLogAnswersSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    answers = AnswerSerializer(many=True)


class GroupResolvedSerializer(serializers.Serializer):
    name = serializers.CharField()
    resolved = ResolvedSerializer(many=True)


class QueryLogGroupSerializer(serializers.Serializer):
    name = serializers.CharField()
    names = serializers.IntegerField(help_text='Distinct host names in the group')
    count = serializers.IntegerField()
    last = serializers.DateTimeField(help_text='Time of the most recent query')
    avg_ms = serializers.FloatField()
    clients = serializers.IntegerField(help_text='Distinct client IPs')
    local = serializers.IntegerField()
    forwarded = serializers.IntegerField()
    blocked = serializers.IntegerField()
    error = serializers.IntegerField()


class PurgeRequestSerializer(serializers.Serializer):
    older_than_hours = serializers.IntegerField(min_value=0, help_text='Delete queries older than this many hours; 0 = everything')
    dry_run = serializers.BooleanField(default=False, help_text='Only count what would be deleted')


class PurgeResultSerializer(serializers.Serializer):
    count = serializers.IntegerField(help_text='Queries deleted (or that would be, with dry_run)')
    dry_run = serializers.BooleanField()
