import base64
import binascii
import re
import socket
import struct

from django.conf import settings
from django.http import Http404, HttpResponse
from dnslib import DNSRecord
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

MAX_QUERY = 4096
_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def _exchange(wire):
    """One query over TCP to the DNS daemon (length-prefixed, RFC 1035 4.2.2); its answer, or None."""
    host, _, port = settings.DNS_DOH_BACKEND.rpartition(':')
    with socket.create_connection((host.strip('[]'), int(port)), timeout=5) as s:
        s.sendall(struct.pack('!H', len(wire)) + wire)
        head = s.recv(2, socket.MSG_WAITALL)
        if len(head) < 2:
            return None
        data = b''
        n = struct.unpack('!H', head)[0]
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


class DohView(APIView):
    """DNS over HTTPS (RFC 8484): GET ?dns=<base64url> or POST application/dns-message, passed on to the DNS daemon.
    No login (clients cannot give one): keep it reachable only by the clients that may use this resolver. The daemon logs the client as 127.0.0.1."""
    authentication_classes = []
    permission_classes = [AllowAny]
    schema = None

    def get(self, request):
        if not settings.DNS_DOH:
            raise Http404
        raw = request.query_params.get('dns', '')
        if not _B64URL_RE.match(raw):
            return HttpResponse(status=400)
        try:
            return self.answer(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
        except (binascii.Error, ValueError):
            return HttpResponse(status=400)

    def post(self, request):
        if not settings.DNS_DOH:
            raise Http404
        if request.content_type != 'application/dns-message':
            return HttpResponse(status=415)
        return self.answer(request.body)

    def answer(self, wire):
        if not settings.DNS_DOH:
            raise Http404
        if not 12 <= len(wire) <= MAX_QUERY:
            return HttpResponse(status=400)
        try:
            q = DNSRecord.parse(wire)  # not a DNS message: refused here, the daemon never sees it
            if q.header.qr:
                return HttpResponse(status=400)
            out = _exchange(wire)
        except OSError:
            return HttpResponse(status=502)
        except Exception:
            return HttpResponse(status=400)
        if out is None:
            return HttpResponse(status=502)
        return HttpResponse(out, content_type='application/dns-message', headers={'Cache-Control': 'max-age=0'})
