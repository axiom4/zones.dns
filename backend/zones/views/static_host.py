from rest_framework import viewsets

from ..models import StaticHost
from ..serializers import StaticHostSerializer


class StaticHostViewSet(viewsets.ModelViewSet):
    """Static hosts (like /etc/hosts): a name answered with a fixed address."""
    queryset = StaticHost.objects.all()
    serializer_class = StaticHostSerializer
