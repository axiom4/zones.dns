from rest_framework import serializers


class CountSerializer(serializers.Serializer):
    name = serializers.CharField()
    count = serializers.IntegerField()


class BucketSerializer(serializers.Serializer):
    t = serializers.DateTimeField(help_text='Start of the minute or hour (UTC)')
    count = serializers.IntegerField(help_text='All queries and proxy requests in the bucket')
    proxy_count = serializers.IntegerField(help_text='Of which proxy requests')
    blocked = serializers.IntegerField(help_text='Of which blocked by the DNS daemon')
    proxy_blocked = serializers.IntegerField(help_text='Of which blocked by the filtering proxy')


class StatsSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    avg_ms = serializers.FloatField()
    by_outcome = CountSerializer(many=True)
    by_type = CountSerializer(many=True)
    by_answer = CountSerializer(many=True, help_text='What the queries got back: address (an A/AAAA record: the geolocation total), no_address, nxdomain, blocked, error, proxied (went through the proxy)')
    top_domains = CountSerializer(many=True)
    top_blocked = CountSerializer(many=True)
    top_clients = CountSerializer(many=True)
    timeouts = serializers.IntegerField(help_text='Proxy requests that timed out (upstream connect/read/write): not part of total, the outcomes or the average time')
    top_timeouts = CountSerializer(many=True, help_text='The sites with the most proxy timeouts')
    step = serializers.IntegerField(help_text='Length of one series entry in seconds: 60 or 3600')
    series = BucketSerializer(many=True)
