"""WPAD / PAC (Proxy Auto-Configuration) and Apple .mobileconfig generator for DHCP option 252 and DNS `wpad.<domain>`."""
import base64
import ipaddress
import json
import plistlib
import re
import uuid

from django.conf import settings


def _extract_host(host_header):
    """Strip port from an HTTP Host header, keeping IPv6 brackets if present."""
    if not host_header:
        return ''
    h = host_header.strip()
    if h.startswith('[') and ']' in h:
        return h[:h.index(']') + 1]
    return h.partition(':')[0]


def server_ip_for(s):
    """Best server IPv4/IPv6 address for WPAD and PAC: DHCP_SERVER, specific PROXY_ADDRESS, or an IP in ALLOWED_HOSTS."""
    for cand in (getattr(s, 'DHCP_SERVER', ''), getattr(s, 'PROXY_ADDRESS', '')):
        c = str(cand or '').strip()
        if c and c not in ('0.0.0.0', '::', '*'):
            return c
    for h in getattr(settings, 'ALLOWED_HOSTS', ()):
        h = str(h or '').strip().strip('[]')
        try:
            ip = ipaddress.ip_address(h)
            if not ip.is_loopback and not ip.is_unspecified:
                return str(ip)
        except ValueError:
            continue
    return ''


def wpad_url_for(s, server_ip=None, extra_url=None):
    """Return the WPAD PAC URL to announce in DHCP option 252, or '' when WPAD is disabled."""
    explicit = (extra_url if extra_url is not None else getattr(s, 'DHCP_WPAD_URL', '')).strip()
    if explicit:
        return explicit
    if not getattr(s, 'DHCP_WPAD', False):
        return ''
    ip = str(server_ip or server_ip_for(s) or '').strip()
    if not ip:
        return ''
    port = int(getattr(s, 'PROXY_PORT', 8080) or 8080)
    host_str = f'[{ip}]' if ':' in ip and not ip.startswith('[') else ip
    return f'http://{host_str}:{port}/wpad.dat'


def parse_allow_domains(raw_rules):
    """Extract @@domain exceptions from PROXY_CUSTOM_RULES."""
    out = []
    for line in re.split(r'[\r\n]+', str(raw_rules or '')):
        line = line.strip()
        if line.startswith('@@') and len(line) > 2:
            dom = line[2:].strip().lstrip('|').rstrip('^/').lower().strip('.')
            if dom and all(c.isalnum() or c in '.-_' for c in dom):
                out.append(dom)
    return out


def build_pac(s, request_host=None):
    """Build a Proxy Auto-Configuration (PAC) JavaScript file."""
    if not (getattr(s, 'PROXY', False) or getattr(s, 'DHCP_WPAD', False)):
        return 'function FindProxyForURL(url, host) {\n  return "DIRECT";\n}\n'
    req_h = _extract_host(request_host)
    if req_h.lower().startswith('wpad.'):
        req_h = ''  # never point PROXY at wpad.<domain> itself if we have a real server IP/host
    server_ip = server_ip_for(s) or req_h or '127.0.0.1'
    port = int(getattr(s, 'PROXY_PORT', 8080) or 8080)
    host_str = f'[{server_ip}]' if ':' in server_ip and not server_ip.startswith('[') else server_ip
    proxy_str = f'PROXY {host_str}:{port}'
    domain = str(getattr(s, 'DHCP_DOMAIN', '') or '').strip().strip('.').lower()
    default_zone = str(getattr(settings, 'DEFAULT_ZONE', '') or '').strip().strip('.').lower()
    bypass_domains = ['localhost', 'local', 'home.arpa']
    for d in (domain, default_zone):
        if d and d not in bypass_domains:
            bypass_domains.append(d)
    for h in getattr(settings, 'ALLOWED_HOSTS', ()):
        h = str(h or '').strip().strip('.').lower()
        if h and h != '*' and ':' not in h:
            try:
                ipaddress.ip_address(h)
            except ValueError:
                if h not in bypass_domains:
                    bypass_domains.append(h)
    for d in parse_allow_domains(getattr(s, 'PROXY_CUSTOM_RULES', '')):
        if d not in bypass_domains:
            bypass_domains.append(d)
    dom_checks = ' || '.join(f'dnsDomainIs(h, {json.dumps("." + d)}) || h === {json.dumps(d)}' for d in bypass_domains)
    return (
        'function FindProxyForURL(url, host) {\n'
        '  var h = (host || "").toLowerCase();\n'
        '  if (!h || isPlainHostName(h) || h === "wpad" || h.indexOf("wpad.") === 0) return "DIRECT";\n'
        f'  if ({dom_checks}) return "DIRECT";\n'
        '  if (/^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/.test(h)) {\n'
        '    return "DIRECT";\n'
        '  }\n'
        '  if (url.substring(0, 5) === "http:" || url.substring(0, 6) === "https:" || url.substring(0, 3) === "ws:" || url.substring(0, 4) === "wss:") {\n'
        f'    return {json.dumps(proxy_str)};\n'
        '  }\n'
        '  return "DIRECT";\n'
        '}\n'
    )


def build_mobileconfig(s, ca_cert_pem='', request_host=None):
    """Build an Apple Configuration Profile (.mobileconfig) for macOS and iOS that configures the PAC proxy URL and Root CA."""
    req_h = _extract_host(request_host)
    if req_h.lower().startswith('wpad.'):
        req_h = ''
    server_ip = server_ip_for(s) or req_h or '127.0.0.1'
    port = int(getattr(s, 'PROXY_PORT', 8080) or 8080)
    host_str = f'[{server_ip}]' if ':' in server_ip and not server_ip.startswith('[') else server_ip
    pac_url = str(getattr(s, 'DHCP_WPAD_URL', '') or '').strip() or f'http://{host_str}:{port}/wpad.dat'

    payloads = [
        {
            'PayloadType': 'com.apple.proxy.http.global',
            'PayloadVersion': 1,
            'PayloadIdentifier': 'net.zonesdns.proxy.pac',
            'PayloadUUID': str(uuid.uuid5(uuid.NAMESPACE_DNS, f'zones-dns-pac-{pac_url}')),
            'PayloadDisplayName': 'Zones.dns Auto Proxy (PAC)',
            'PayloadDescription': 'Configures automatic HTTP/HTTPS ad & popup filtering proxy via PAC.',
            'ProxyType': 'Auto',
            'ProxyAutoConfigEnable': 1,
            'ProxyAutoConfigURLString': pac_url,
            'ProxyCaptiveLoginAllowed': True,
        }
    ]
    if ca_cert_pem:
        b64_lines = [line.strip() for line in ca_cert_pem.splitlines() if line.strip() and not line.startswith('-----')]
        der_bytes = base64.b64decode(''.join(b64_lines))
        payloads.append({
            'PayloadType': 'com.apple.security.root',
            'PayloadVersion': 1,
            'PayloadIdentifier': 'net.zonesdns.proxy.ca',
            'PayloadUUID': str(uuid.uuid5(uuid.NAMESPACE_DNS, f'zones-dns-ca-{len(der_bytes)}')),
            'PayloadDisplayName': 'Zones.dns Proxy Root CA',
            'PayloadDescription': 'Root CA certificate for Zones.dns HTTPS ad & popup filtering.',
            'PayloadCertificateFileName': 'zones-proxy-ca.crt',
            'PayloadContent': der_bytes,
        })

    profile = {
        'PayloadType': 'Configuration',
        'PayloadVersion': 1,
        'PayloadIdentifier': 'net.zonesdns.proxy.profile',
        'PayloadUUID': str(uuid.uuid5(uuid.NAMESPACE_DNS, f'zones-dns-profile-{pac_url}')),
        'PayloadDisplayName': 'Zones.dns Ad & Popup Proxy',
        'PayloadDescription': 'Configures the Zones.dns HTTP/HTTPS ad-blocking proxy (PAC) and Root CA certificate on macOS and iOS.',
        'PayloadOrganization': 'Zones.dns',
        'PayloadRemovalDisallowed': False,
        'PayloadScope': 'System',
        'PayloadContent': payloads,
    }
    return plistlib.dumps(profile)
