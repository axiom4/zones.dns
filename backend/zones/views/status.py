from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import heartbeat
from ..dhcp import v4 as dhcp
from ..serializers.status import StatusSerializer


class StatusView(APIView):
    @extend_schema(responses=StatusSerializer)
    def get(self, request):
        """Whether the daemons run: each one (rundns, rundhcp, runproxy) writes a heartbeat every 30 s; running = heard from in the last 90 s.
        enabled: turned on in the settings (DNS always; DHCP: DHCP, which DHCPv6 and RA also need to run; proxy: PROXY)."""
        s, beats = dhcp.dhcp_settings(), heartbeat.read()
        enabled = {'dns': True, 'dhcp': bool(s.DHCP), 'proxy': bool(s.PROXY)}
        return Response(StatusSerializer({n: {'command': f'run{n}', 'enabled': enabled[n], **beats[n]} for n in heartbeat.DAEMONS}).data)
