from rest_framework import serializers

from ..models import BlockedDomain


class BlockedDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedDomain
        fields = ['id', 'name', 'created']

    def validate_name(self, v):
        v = v.strip().strip('.').lower()
        if not v:
            raise serializers.ValidationError('Nome vuoto.')
        return v


class ImportedBlockedSerializer(serializers.Serializer):
    count = serializers.IntegerField()
    names = serializers.ListField(child=serializers.CharField())
