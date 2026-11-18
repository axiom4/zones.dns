from rest_framework import serializers


class BulkActionSerializer(serializers.Serializer):
    ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=False, max_length=5000)
    action = serializers.ChoiceField(['delete', 'enable', 'disable'])


class BulkResultSerializer(serializers.Serializer):
    count = serializers.IntegerField()


class ZoneImportSerializer(serializers.Serializer):
    text = serializers.CharField(max_length=5_000_000)
    replace = serializers.BooleanField(default=False, help_text='Delete existing records first')
    dry_run = serializers.BooleanField(default=False, help_text='Only report what would happen')


class ZoneImportResultSerializer(serializers.Serializer):
    created = serializers.IntegerField()
    skipped = serializers.IntegerField()
    errors = serializers.ListField(child=serializers.CharField())
