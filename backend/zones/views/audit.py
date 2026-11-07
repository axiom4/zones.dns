from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from .. import audit
from ..serializers import AuditReportSerializer, AuditRequestSerializer


class AuditView(APIView):
    @extend_schema(request=AuditRequestSerializer, responses=AuditReportSerializer)
    def post(self, request):
        """Collect public information about a domain and flag common problems. Takes ~5-15 s; deep=true adds slower checks (up to ~40 s)."""
        s = AuditRequestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        return Response(audit.audit(s.validated_data['domain'], deep=s.validated_data['deep']))
