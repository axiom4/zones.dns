from rest_framework import serializers


class CountSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField()


class BucketSerializer(serializers.Serializer):
    t = serializers.DateTimeField(help_text='Start of the minute or hour (UTC)')
    count = serializers.IntegerField(help_text='All queries in the bucket')
    blocked = serializers.IntegerField(help_text='Of which blocked')


class StatsSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    avg_ms = serializers.FloatField()
    by_outcome = CountSerializer(many=True)
    by_type = CountSerializer(many=True)
    top_domains = CountSerializer(many=True)
    top_blocked = CountSerializer(many=True)
    top_clients = CountSerializer(many=True)
    step = serializers.IntegerField(help_text='Length of one series entry in seconds: 60 or 3600')
    series = BucketSerializer(many=True)
