"""WPAD / PAC (Proxy Auto-Configuration) generator for DHCP option 252 and DNS `wpad.<domain>`."""
import json
import re


def _extract_host(host_header):
    """Strip port from an HTTP Host header, keeping IPv6 brackets if present."""
    if not host_header:
        return ''
    h = host_header.strip()
    if h.startswith('[') and ']' in h:
        return h[:h.index(']') + 1]
    return h.partition(':')[0]


def wpad_url_for(s, server_ip=None, extra_url=None):
    """Return the WPAD PAC URL to announce in DHCP option 252, or '' when WPAD is disabled."""
    explicit = (extra_url if extra_url is not None else getattr(s, 'DHCP_WPAD_URL', '')).strip()
    if explicit:
        return explicit
    if not getattr(s, 'DHCP_WPAD', False):
        return ''
    ip = str(server_ip or getattr(s, 'DHCP_SERVER', '') or '').strip()
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
    server_ip = str(getattr(s, 'DHCP_SERVER', '') or '').strip() or _extract_host(request_host) or '127.0.0.1'
    port = int(getattr(s, 'PROXY_PORT', 8080) or 8080)
    host_str = f'[{server_ip}]' if ':' in server_ip and not server_ip.startswith('[') else server_ip
    proxy_str = f'PROXY {host_str}:{port}; DIRECT'
    domain = str(getattr(s, 'DHCP_DOMAIN', '') or '').strip().strip('.').lower()
    bypass_domains = ['localhost', 'local', 'home.arpa']
    if domain and domain not in bypass_domains:
        bypass_domains.append(domain)
    for d in parse_allow_domains(getattr(s, 'PROXY_CUSTOM_RULES', '')):
        if d not in bypass_domains:
            bypass_domains.append(d)
    dom_checks = ' || '.join(f'dnsDomainIs(h, {json.dumps("." + d)}) || h === {json.dumps(d)}' for d in bypass_domains)
    return (
        'function FindProxyForURL(url, host) {\n'
        '  var h = (host || "").toLowerCase();\n'
        '  if (!h || isPlainHostName(h) || h === "wpad" || h.indexOf("wpad.") === 0) return "DIRECT";\n'
        f'  if ({dom_checks}) return "DIRECT";\n'
        '  if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(h)) {\n'
        '    if (isInNet(h, "127.0.0.0", "255.0.0.0") ||\n'
        '        isInNet(h, "10.0.0.0", "255.0.0.0") ||\n'
        '        isInNet(h, "172.16.0.0", "255.240.0.0") ||\n'
        '        isInNet(h, "192.168.0.0", "255.255.0.0") ||\n'
        '        isInNet(h, "169.254.0.0", "255.255.0.0")) {\n'
        '      return "DIRECT";\n'
        '    }\n'
        '  }\n'
        '  if (url.substring(0, 5) === "http:" || url.substring(0, 6) === "https:") {\n'
        f'    return {json.dumps(proxy_str)};\n'
        '  }\n'
        '  return "DIRECT";\n'
        '}\n'
    )
