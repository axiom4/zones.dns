import socket
import ssl
import struct
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from dnslib import DNSRecord

from zones.dnsd import ddr


class Command(BaseCommand):
    help = 'Ask each encrypted resolver announced in DNS_DDR (RFC 9462) a real query and say whether it answers over a valid TLS connection.'

    def add_arguments(self, p):
        p.add_argument('--cafile', default='', help='CA certificate file to trust (e.g. your internal CA from INSTALL.md 2B)')

    def handle(self, *a, cafile='', **o):
        try:
            entries = ddr.parse(settings.DNS_DDR)
        except ValueError as e:
            raise CommandError(e)
        if not entries:
            self.stdout.write('DNS_DDR is empty: nothing is announced.')
            return
        ctx = ssl.create_default_context(cafile=cafile or None)
        query = DNSRecord.question('example.com', 'A').pack()
        failed = 0
        for _, host, params in entries:
            port = int.from_bytes(params.get(ddr.PORT, b'\x01\xbb'), 'big')
            doh = ddr.DOHPATH in params
            what = f'{"doh" if doh else "dot"} {host}:{port}'
            try:
                reply = self.doh(host, port, params[ddr.DOHPATH].decode().split('{')[0], query, ctx) if doh else self.dot(host, port, query, ctx)
                code = DNSRecord.parse(reply).header.rcode
                self.stdout.write(self.style.SUCCESS(f'OK    {what}: answered (rcode {code})'))
            except Exception as e:
                failed += 1
                self.stdout.write(self.style.ERROR(f'FAIL  {what}: {e}'))
        if failed:
            raise CommandError(f'{failed} announced resolver(s) do not work: clients that try them will fail.')

    def dot(self, host, port, query, ctx=None):
        ctx = ctx or ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:  # certificate and name are checked
            s.sendall(struct.pack('!H', len(query)) + query)
            hdr = b''
            while len(hdr) < 2:
                chunk = s.recv(2 - len(hdr))
                if not chunk:
                    raise EOFError('connection closed before DNS response length')
                hdr += chunk
            n = struct.unpack('!H', hdr)[0]
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    raise EOFError('connection closed before full DNS response')
                data += chunk
            return data

    def doh(self, host, port, path, query, ctx=None):
        ctx = ctx or ssl.create_default_context()
        req = urllib.request.Request(f'https://{host}:{port}{path}', data=query, headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:  # certificate and name are checked
            return r.read()
