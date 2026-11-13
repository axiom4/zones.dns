from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from zones.dnsd import ddr


class Command(BaseCommand):
    help = ('Print the DHCPv4 (162), DHCPv6 (144) and IPv6 RA (144) options of RFC 9463 (DNR) for the resolvers of DNS_DDR, for your DHCP server or router. '
            '--format dnsmasq or kea prints only that configuration, ready to save to a file.')

    def add_arguments(self, p):
        p.add_argument('--format', choices=['all', 'dnsmasq', 'kea'], default='all')
        p.add_argument('--lifetime', type=int, default=1800, help='RA option lifetime in seconds (at least 3 x MaxRtrAdvInterval)')

    def handle(self, *a, format, lifetime, **o):
        try:
            entries = ddr.parse(settings.DNS_DDR)
        except ValueError as e:
            raise CommandError(e)
        if not entries:
            raise CommandError('DNS_DDR is empty: nothing to announce.')
        w = self.stdout.write
        v4, v6, ra = ddr.dnr_v4(entries), ddr.dnr_v6(entries), ddr.dnr_ra(entries, lifetime)
        colon = lambda b: ':'.join(f'{x:02x}' for x in b)
        dnsmasq = ([f'dhcp-option=162,{colon(v4)}'] if v4 else []) + [f'dhcp-option=option6:144,{colon(b)}' for b in v6]
        kea4 = [f'{{ "code": 162, "space": "dhcp4", "csv-format": false, "data": "{v4.hex()}" }}'] if v4 else []
        kea6 = [f'{{ "code": 144, "space": "dhcp6", "csv-format": false, "data": "{b.hex()}" }}' for b in v6]
        if format == 'dnsmasq':
            w('\n'.join(dnsmasq))
            return
        if format == 'kea':
            w('// DHCPv4: add to "option-data" of the subnet or the global scope; DHCPv6 likewise in the Dhcp6 section.')
            w('// dhcp4:\n' + ',\n'.join(kea4) + '\n// dhcp6:\n' + ',\n'.join(kea6))
            return
        w('# DHCPv4 option 162 (OPTION_V4_DNR), hex of the option data (over 255 octets the server splits it, RFC 3396).')
        w(f'v4 hex   : {v4.hex()}' if v4 else '# none: every resolver has only IPv6 hints.')
        w('\n# DHCPv6 option 144 (OPTION_V6_DNR), one option per resolver.')
        for body in v6:
            w(f'v6 hex   : {body.hex()}')
        if not v6:
            w('# none: every resolver has only IPv4 hints.')
        w('\n# IPv6 Router Advertisement option 144, the whole option as hex (a router that takes raw options).')
        for opt in ra:
            w(f'ra hex   : {opt.hex()}')
        if not ra:
            w('# none: every resolver has only IPv4 hints.')
        w('\n# dnsmasq (--format dnsmasq):\n' + '\n'.join(dnsmasq))
        w('\n# Without @ip hints a resolver is announced by name only (ADN-only): clients then ask this server for the SVCB record of _dns.<name>, which it answers.')
