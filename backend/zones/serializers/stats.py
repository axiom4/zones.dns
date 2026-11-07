from rest_framework import serializers


class CountSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField()


class HourSerializer(serializers.Serializer):
    hour = serializers.DateTimeField()
    count = serializers.IntegerField()


class StatsSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    avg_ms = serializers.FloatField()
    by_outcome = CountSerializer(many=True)
    by_type = CountSerializer(many=True)
    top_domains = CountSerializer(many=True)
    top_blocked = CountSerializer(many=True)
    top_clients = CountSerializer(many=True)
    per_hour = HourSerializer(many=True)
