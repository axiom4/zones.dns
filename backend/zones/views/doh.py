import base64
import binascii
import ipaddress
import re
import socket
import struct

from django.conf import settings
from django.http import Http404, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from dnslib import DNSRecord

from .token import client_ip

MAX_QUERY = 4096
_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def _proxy_line(client):
    """The PROXY protocol v1 line that tells the daemon who the client is (DNS_PROXY_PROTOCOL), or b''."""
    try:
        addr = ipaddress.ip_address(client)
    except ValueError:
        return b''
    return f'PROXY TCP{addr.version} {addr} {"127.0.0.1" if addr.version == 4 else "::1"} 0 53\r\n'.encode() if settings.DNS_PROXY_PROTOCOL else b''


def _exchange(wire, client=''):
    """One query over TCP to the DNS daemon (length-prefixed, RFC 1035 4.2.2); its answer, or None."""
    host, _, port = settings.DNS_DOH_BACKEND.rpartition(':')
    with socket.create_connection((host.strip('[]'), int(port)), timeout=5) as s:
        s.sendall(_proxy_line(client) + struct.pack('!H', len(wire)) + wire)
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


@method_decorator(csrf_exempt, name='dispatch')
class DohView(View):
    """DNS over HTTPS (RFC 8484): GET ?dns=<base64url> or POST application/dns-message, passed on to the DNS daemon.
    No login (clients cannot give one): keep it reachable only by the clients that may use this resolver.
    A plain Django view: REST framework's content negotiation answered 406 to "Accept: application/dns-message", which browsers send."""

    def get(self, request):
        if not settings.DNS_DOH:
            raise Http404
        raw = request.GET.get('dns', '')
        if not _B64URL_RE.match(raw):
            return HttpResponse(status=400)
        try:
            return self.answer(request, base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
        except (binascii.Error, ValueError):
            return HttpResponse(status=400)

    def post(self, request):
        if not settings.DNS_DOH:
            raise Http404
        if request.content_type != 'application/dns-message':
            return HttpResponse(status=415)
        return self.answer(request, request.body)

    def answer(self, request, wire):
        if not settings.DNS_DOH:
            raise Http404
        if not 12 <= len(wire) <= MAX_QUERY:
            return HttpResponse(status=400)
        try:
            q = DNSRecord.parse(wire)  # not a DNS message: refused here, the daemon never sees it
            if q.header.qr or q.header.opcode != 0:  # only queries: DoH clients reach the daemon from 127.0.0.1, so an UPDATE would look local
                return HttpResponse(status=400)
            out = _exchange(wire, client_ip(request))
        except OSError:
            return HttpResponse(status=502)
        except Exception:
            return HttpResponse(status=400)
        if out is None:
            return HttpResponse(status=502)
        return HttpResponse(out, content_type='application/dns-message', headers={'Cache-Control': 'max-age=0'})
