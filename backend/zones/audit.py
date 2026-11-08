"""Public-information audit of a domain: DNS, delegation, mail security, registration (RDAP), hosts, TLS, web, linked services.

Active probes (TLS, HTTP, AXFR, name-server queries) only go to globally routable addresses on ports 53/80/443, follow
redirects only through hosts that pass the same check, and connect to the address that was validated, so this can't be
used to scan the internal network. `deep=True` adds slower checks (TLS protocol probing, full SPF lookup count,
MTA-STS policy, certificate-transparency subdomain list).
"""
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from django.conf import settings
from dnslib import QTYPE, DNSRecord

TIMEOUT = 5
UA = 'zones-dns-audit/1.0'
NAME_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$')
DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2']
SECURITY_HEADERS = {
    'content-security-policy': ('info', 'Content-Security-Policy missing', 'Limits where the page can load scripts and resources from.'),
    'x-content-type-options': ('info', 'X-Content-Type-Options missing', 'Recommended value: nosniff.'),
    'referrer-policy': ('info', 'Referrer-Policy missing', 'Controls what browsing information is sent to other sites.'),
    'permissions-policy': ('info', 'Permissions-Policy missing', 'Limits access to the camera, microphone, geolocation and other browser features.'),
}
DNSSEC_ALGOS = {5: 'RSA/SHA-1', 7: 'RSASHA1-NSEC3', 8: 'RSA/SHA-256', 10: 'RSA/SHA-512', 13: 'ECDSA P-256', 14: 'ECDSA P-384', 15: 'Ed25519', 16: 'Ed448'}
WEAK_DNSSEC = {5, 7}
SENSITIVE_SUBDOMAINS = re.compile(r'(^|[.-])(admin|vpn|dev|test|staging|stage|uat|jenkins|gitlab|git|jira|intranet|internal|backup|db|sql|phpmyadmin|grafana|kibana|sso|portal)([.-]|\d|$)')

# What a name / header / record reveals about the services behind a domain: (substring, service name)
MX_SERVICES = [('google.com', 'Google Workspace'), ('googlemail.com', 'Google Workspace'), ('outlook.com', 'Microsoft 365'), ('protection.outlook', 'Microsoft 365'),
               ('icloud.com', 'iCloud Mail'), ('zoho', 'Zoho Mail'), ('proton', 'Proton Mail'), ('mimecast', 'Mimecast'), ('pphosted', 'Proofpoint'),
               ('mailgun', 'Mailgun'), ('secureserver.net', 'GoDaddy Mail'), ('ovh.net', 'OVHcloud Mail'), ('aruba', 'Aruba Mail'), ('fastmail', 'Fastmail'),
               ('yandex', 'Yandex Mail'), ('barracuda', 'Barracuda')]
NS_SERVICES = [('cloudflare', 'Cloudflare DNS'), ('awsdns', 'Amazon Route 53'), ('azure-dns', 'Azure DNS'), ('googledomains', 'Google Domains DNS'),
               ('google', 'Google Cloud DNS'), ('nsone', 'NS1'), ('dnsimple', 'DNSimple'), ('domaincontrol', 'GoDaddy DNS'), ('ovh.net', 'OVHcloud DNS'),
               ('registrar-servers', 'Namecheap DNS'), ('dnsmadeeasy', 'DNS Made Easy'), ('ultradns', 'UltraDNS'), ('digitalocean', 'DigitalOcean DNS'),
               ('hetzner', 'Hetzner DNS'), ('gandi', 'Gandi DNS'), ('akam', 'Akamai DNS'), ('dynect', 'Oracle Dyn')]
SPF_SERVICES = [('_spf.google.com', 'Google Workspace'), ('spf.protection.outlook.com', 'Microsoft 365'), ('sendgrid.net', 'SendGrid'), ('mailgun.org', 'Mailgun'),
                ('amazonses.com', 'Amazon SES'), ('mcsv.net', 'Mailchimp'), ('mandrillapp.com', 'Mandrill'), ('zendesk.com', 'Zendesk'),
                ('salesforce.com', 'Salesforce'), ('hubspot', 'HubSpot'), ('freshdesk', 'Freshdesk'), ('mailjet', 'Mailjet'), ('sparkpostmail', 'SparkPost'),
                ('postmarkapp', 'Postmark'), ('servers.mcsv', 'Mailchimp'), ('icloud.com', 'iCloud Mail'), ('zoho', 'Zoho')]
TXT_SERVICES = [('google-site-verification=', 'Google (Search Console / Workspace)'), ('ms=', 'Microsoft 365'), ('facebook-domain-verification=', 'Meta'),
                ('atlassian-domain-verification=', 'Atlassian'), ('stripe-verification=', 'Stripe'), ('docusign=', 'DocuSign'),
                ('apple-domain-verification=', 'Apple'), ('zoom-domain-verification', 'Zoom'), ('adobe-idp-site-verification=', 'Adobe'),
                ('onetrust-domain-verification=', 'OneTrust'), ('miro-verification=', 'Miro'), ('slack-domain-verification', 'Slack'),
                ('globalsign-domain-verification=', 'GlobalSign'), ('cisco-ci-domain-verification=', 'Cisco')]
HTTP_SERVICES = [  # (header name, substring of value or '' for presence, service)
    ('server', 'cloudflare', 'Cloudflare'), ('cf-ray', '', 'Cloudflare'), ('x-amz-cf-id', '', 'Amazon CloudFront'), ('x-served-by', 'cache', 'Fastly'),
    ('x-vercel-id', '', 'Vercel'), ('x-github-request-id', '', 'GitHub Pages'), ('x-azure-ref', '', 'Azure Front Door'), ('x-sucuri-id', '', 'Sucuri'),
    ('server', 'akamai', 'Akamai'), ('x-akamai-transformed', '', 'Akamai'), ('server', 'netlify', 'Netlify'), ('x-nf-request-id', '', 'Netlify'),
    ('x-powered-by', 'php', 'PHP'), ('x-powered-by', 'asp.net', 'ASP.NET'), ('x-powered-by', 'express', 'Express (Node.js)'), ('x-generator', 'drupal', 'Drupal'),
    ('x-generator', 'wordpress', 'WordPress'), ('x-drupal-cache', '', 'Drupal'), ('link', 'api.w.org', 'WordPress'), ('x-shopify-stage', '', 'Shopify'),
]
COOKIE_SERVICES = [('phpsessid', 'PHP'), ('asp.net_sessionid', 'ASP.NET'), ('jsessionid', 'Java (servlet)'), ('laravel_session', 'Laravel'),
                   ('csrftoken', 'Django'), ('wordpress_', 'WordPress'), ('_shopify', 'Shopify'), ('__cfduid', 'Cloudflare'), ('__cf_bm', 'Cloudflare')]


def clean_domain(raw):
    d = (raw or '').strip().lower().rstrip('.')
    d = re.sub(r'^[a-z]+://', '', d).split('/')[0].split(':')[0]
    try:
        d = d.encode('idna').decode()
    except UnicodeError:
        return None
    return d if NAME_RE.match(d) else None


# ---------- DNS ----------
def dns_query(name, qtype, server=None, tcp=False):
    server = server or settings.UPSTREAMS[0]
    try:
        reply = DNSRecord.parse(DNSRecord.question(name, qtype).send(server, 53, tcp=tcp, timeout=TIMEOUT, ipv6=':' in server))
        if reply.header.tc and not tcp:
            return dns_query(name, qtype, server, tcp=True)
        return reply
    except Exception:
        return None


def dns_rdata(name, qtype, server=None):
    reply = dns_query(name, qtype, server)
    return [rr.rdata for rr in reply.rr if QTYPE[rr.rtype] == qtype] if reply else []


def dns_values(name, qtype):
    out = []
    for rd in dns_rdata(name, qtype):
        if qtype == 'TXT':
            out.append(b''.join(rd.data).decode('utf-8', 'replace'))
        elif qtype == 'MX':
            out.append(f'{rd.preference} {str(rd.label).rstrip(".") or "."}')  # "0 ." is the null MX (RFC 7505)
        elif qtype in ('NS', 'CNAME', 'PTR'):
            out.append(str(rd).rstrip('.'))
        elif qtype == 'SOA':
            out.append(f'{str(rd.mname).rstrip(".")} serial {rd.times[0]}')
        else:
            out.append(rd.toZone() if hasattr(rd, 'toZone') else str(rd))
    return out


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def public_ips(host):
    return [i for i in dns_values(host, 'A') + dns_values(host, 'AAAA') if is_public(i)]


def asn_info(ip):
    """Origin AS, prefix, country and registry from Team Cymru's DNS service (no extra connection to the host)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    q = ('.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com') if a.version == 4 else ('.'.join(reversed(a.exploded.replace(':', ''))) + '.origin6.asn.cymru.com')
    txt = dns_values(q, 'TXT')
    if not txt:
        return None
    p = [x.strip() for x in txt[0].split('|')]
    asn = p[0].split()[0]
    name = dns_values(f'AS{asn}.asn.cymru.com', 'TXT')
    return {'asn': f'AS{asn}', 'prefix': p[1] if len(p) > 1 else None, 'country': p[2] if len(p) > 2 else None, 'registry': p[3] if len(p) > 3 else None,
            'as_name': name[0].split('|')[-1].strip() if name else None}


# ---------- RDAP / hosts ----------
def rdap(path):
    req = urllib.request.Request(f'https://rdap.org/{path}', headers={'User-Agent': UA, 'Accept': 'application/rdap+json'})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read(1_000_000))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _vcard(entity, field):
    for item in (entity.get('vcardArray') or [None, []])[1]:
        if item[0] == field:
            return item[3]
    return None


def registration(domain):
    labels = domain.split('.')
    # shortcut: no public-suffix list, so try the name and its parents (down to 2 labels); first RDAP hit wins
    for i in range(min(len(labels) - 1, 4)):
        name = '.'.join(labels[i:])
        data = rdap('domain/' + urllib.parse.quote(name))
        if data and data.get('ldhName'):
            ev = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
            registrar = next((e for e in data.get('entities', []) if 'registrar' in e.get('roles', [])), {})
            abuse = next((_vcard(e, 'email') for e in registrar.get('entities', []) if 'abuse' in e.get('roles', [])), None)
            age = None
            if ev.get('registration'):
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(ev['registration'].replace('Z', '+00:00'))).days
            return {
                'name': name, 'registrar': _vcard(registrar, 'fn'), 'created': ev.get('registration'), 'expires': ev.get('expiration'),
                'updated': ev.get('last changed'), 'status': data.get('status', []), 'age_days': age,
                'dnssec_signed': (data.get('secureDNS') or {}).get('delegationSigned'), 'abuse_email': abuse or None,
                'nameservers': sorted(n.get('ldhName', '').lower() for n in data.get('nameservers', [])),
            }
    return None


def ip_info(ip):
    pub = is_public(ip)
    data = rdap('ip/' + ip) if pub else None
    ptr = dns_values(ipaddress.ip_address(ip).reverse_pointer, 'PTR')
    info = {'ip': ip, 'ptr': ptr[0] if ptr else None, 'network': None, 'org': None, 'country': None,
            'asn': None, 'as_name': None, 'prefix': None, 'registry': None}
    if data:
        cidr = (data.get('cidr0_cidrs') or [{}])[0]
        pre = cidr.get('v4prefix') or cidr.get('v6prefix')
        info.update(network=f'{pre}/{cidr["length"]}' if pre else data.get('name'), country=data.get('country'),
                    org=next((_vcard(e, 'fn') for e in data.get('entities', []) if _vcard(e, 'fn')), data.get('name')))
    cym = asn_info(ip) if pub else None
    if cym:
        info.update(asn=cym['asn'], as_name=cym['as_name'], prefix=cym['prefix'], registry=cym['registry'], country=info['country'] or cym['country'])
    return info


# ---------- name servers ----------
def ns_probe(domain, ns):
    ips = dns_values(ns, 'A') + dns_values(ns, 'AAAA')
    out = {'name': ns, 'ips': ips[:4], 'ms': None, 'serial': None, 'responds': False, 'authoritative': False, 'asn': None, 'as_name': None}
    pub = [i for i in ips if is_public(i)]
    if pub:
        t0 = time.monotonic()
        reply = dns_query(domain, 'SOA', server=pub[0])
        if reply and reply.header.rcode == 0:
            soa = [rr for rr in reply.rr if QTYPE[rr.rtype] == 'SOA']
            out.update(responds=bool(soa), ms=int((time.monotonic() - t0) * 1000), authoritative=bool(reply.header.aa),
                       serial=soa[0].rdata.times[0] if soa else None)
        a = asn_info(pub[0])
        if a:
            out.update(asn=a['asn'], as_name=a['as_name'])
    return out


def axfr_open(domain, ns_ip):
    reply = dns_query(domain, 'AXFR', server=ns_ip, tcp=True)
    return bool(reply and reply.header.rcode == 0 and len(reply.rr) > 1)


# ---------- mail ----------
def parse_spf(record):
    mech, incl, all_q, redirect = [], [], None, None
    for t in record.split()[1:]:
        q = t[0] if t[0] in '+-~?' else '+'
        body = t.lstrip('+-~?')
        name = re.split(r'[:=/]', body)[0].lower()
        mech.append(t)
        if name == 'all':
            all_q = q
        elif name == 'include' and ':' in body:
            incl.append(body.split(':', 1)[1].lower())
        elif name == 'redirect' and '=' in body:
            redirect = body.split('=', 1)[1].lower()
    return {'mechanisms': mech, 'includes': incl, 'all': all_q, 'redirect': redirect}


def spf_lookups(record, depth=0, budget=None):
    """Count DNS-lookup mechanisms the way receivers do (include/a/mx/ptr/exists/redirect), following includes. Returns (count, all includes)."""
    budget = budget if budget is not None else [15]  # also caps our own queries
    count, includes = 0, []
    for t in record.split()[1:]:
        body = t.lstrip('+-~?')
        name = re.split(r'[:=/]', body)[0].lower()
        if name in ('include', 'a', 'mx', 'ptr', 'exists', 'redirect'):
            count += 1
        if name in ('include', 'redirect') and depth < 5 and budget[0] > 0:
            target = re.split(r'[:=]', body, 1)[1].lower()
            includes.append(target)
            budget[0] -= 1
            sub = next((v for v in dns_values(target, 'TXT') if v.lower().startswith('v=spf1')), None)
            if sub:
                c, inc = spf_lookups(sub, depth + 1, budget)
                count, includes = count + c, includes + inc
    return count, includes


def parse_dmarc(record):
    tags = {}
    for kv in re.split(r';\s*', record):
        if '=' in kv:
            k, v = kv.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    split = lambda v: [x.strip() for x in v.split(',') if x.strip()] if v else []
    return {'record': record, 'policy': tags.get('p'), 'subdomain_policy': tags.get('sp'), 'pct': int(tags['pct']) if tags.get('pct', '').isdigit() else 100,
            'rua': split(tags.get('rua')), 'ruf': split(tags.get('ruf')), 'adkim': tags.get('adkim', 'r'), 'aspf': tags.get('aspf', 'r')}


# ---------- TLS / HTTP ----------
def _read_response(sock, body_limit=0):
    buf = b''
    while b'\r\n\r\n' not in buf and len(buf) < 32768:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b'\r\n\r\n')
    lines = head.decode('latin-1').split('\r\n')
    headers, cookies = {}, []
    for ln in lines[1:]:
        k, _, v = ln.partition(':')
        k = k.strip().lower()
        if k == 'set-cookie':
            cookies.append(v.strip())
        elif k:
            headers[k] = v.strip()
    body = rest
    while body_limit and len(body) < body_limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    m = re.match(r'HTTP/\S+ (\d{3})', lines[0])
    return (int(m.group(1)) if m else None), headers, cookies, body[:body_limit]


def _request(host, path='/', method='HEAD'):
    return f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n'.encode()


def fetch(host, ip, port, use_tls, path='/', method='HEAD', body_limit=0):
    """One request to an already validated public address. Certificates are not verified here (probe_https reports them)."""
    if port not in (80, 443):
        return None, {}, [], b''
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.sendall(_request(host, path, method))
            return _read_response(s, body_limit)
    except (OSError, ssl.SSLError):
        return None, {}, [], b''


def probe_https(host, ip):
    tls = {'host': host, 'ip': ip, 'valid': False, 'error': None, 'version': None, 'cipher': None, 'subject': None, 'issuer': None,
           'not_before': None, 'not_after': None, 'days_left': None, 'serial': None, 'wildcard': False, 'san': [], 'ocsp': [], 'protocols': []}
    status, headers, cookies = None, {}, []
    for verify in (True, False):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # a TLS 1.0/1.1-only server is reported by tls_protocols(), not read here
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                tls['version'], tls['cipher'] = t.version(), t.cipher()[0]
                cert = t.getpeercert()
                if cert:
                    flat = lambda f: ', '.join(v for rdn in cert.get(f, ()) for k, v in rdn if k in ('commonName', 'organizationName'))
                    exp, nb = ssl.cert_time_to_seconds(cert['notAfter']), ssl.cert_time_to_seconds(cert['notBefore'])
                    san = [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS']
                    tls.update(valid=True, subject=flat('subject'), issuer=flat('issuer'), serial=cert.get('serialNumber'),
                               not_before=datetime.fromtimestamp(nb, timezone.utc).isoformat(), not_after=datetime.fromtimestamp(exp, timezone.utc).isoformat(),
                               days_left=int((exp - time.time()) // 86400), san=san[:30], wildcard=any(n.startswith('*.') for n in san),
                               ocsp=list(cert.get('OCSP', ())))
                t.sendall(_request(host))
                status, headers, cookies, _ = _read_response(t)
                break
        except ssl.SSLCertVerificationError as e:
            tls['error'] = e.verify_message or str(e)
        except (OSError, ssl.SSLError) as e:
            tls['error'] = str(e)
            return (tls if tls['version'] else None), None, {}, []
    return tls, status, headers, cookies


def supports_h2(host, ip):
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            return t.selected_alpn_protocol() == 'h2'
    except (OSError, ssl.SSLError):
        return False


def tls_protocols(host, ip):
    """Which TLS versions the server accepts. None = this machine's OpenSSL can't speak that version, so unknown."""
    versions = [('TLSv1.0', ssl.TLSVersion.TLSv1), ('TLSv1.1', ssl.TLSVersion.TLSv1_1), ('TLSv1.2', ssl.TLSVersion.TLSv1_2), ('TLSv1.3', ssl.TLSVersion.TLSv1_3)]
    out = []
    for name, v in versions:
        try:
            # Deliberate: this probe asks the server whether it still accepts each old protocol version (audit finding); only the handshake is made, no data is sent.
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.set_ciphers('ALL:@SECLEVEL=0')
            ctx.minimum_version = ctx.maximum_version = v
        except (ValueError, ssl.SSLError):
            out.append({'name': name, 'supported': None})
            continue
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host):
                out.append({'name': name, 'supported': True})
        except ssl.SSLError as e:
            # NO_PROTOCOLS_AVAILABLE = this machine's OpenSSL refuses that version (unknown); any other failure = the server refused it
            out.append({'name': name, 'supported': None if 'NO_PROTOCOLS_AVAILABLE' in str(e) else False})
        except OSError:
            out.append({'name': name, 'supported': False})
    return out


def redirect_chain(domain, max_hops=6):
    """Follows the redirects from http://domain/ , one validated public host at a time (ports 80/443 only)."""
    url, hops, seen = f'http://{domain}/', [], set()
    for _ in range(max_hops):
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or '').lower()
        port = u.port or (443 if u.scheme == 'https' else 80)
        if u.scheme not in ('http', 'https') or not NAME_RE.match(host) or url in seen or port not in (80, 443):
            break
        seen.add(url)
        ips = public_ips(host)
        if not ips:
            hops.append({'url': url, 'status': None, 'location': None, 'ip': None})
            break
        path = (u.path or '/') + (f'?{u.query}' if u.query else '')
        status, headers, _c, _b = fetch(host, ips[0], port, u.scheme == 'https', path)
        loc = headers.get('location')
        hops.append({'url': url, 'status': status, 'location': loc, 'ip': ips[0]})
        if status in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
        else:
            break
    return hops


def parse_cookie(raw):
    parts = [p.strip() for p in raw.split(';')]
    low = [p.lower() for p in parts]
    ss = next((p.split('=', 1)[1] for p in low if p.startswith('samesite=')), None)
    return {'name': parts[0].split('=', 1)[0], 'secure': 'secure' in low, 'httponly': 'httponly' in low, 'samesite': ss}


def parse_hsts(value):
    if not value:
        return None
    m = re.search(r'max-age=(\d+)', value.lower())
    return {'max_age': int(m.group(1)) if m else 0, 'include_subdomains': 'includesubdomains' in value.lower(), 'preload': 'preload' in value.lower()}


def mta_sts_policy(domain):
    ips = public_ips(f'mta-sts.{domain}')
    if not ips:
        return None
    status, _h, _c, body = fetch(f'mta-sts.{domain}', ips[0], 443, True, '/.well-known/mta-sts.txt', 'GET', 4096)
    if status != 200:
        return None
    kv = {}
    mx = []
    for line in body.decode('utf-8', 'replace').splitlines():
        k, _, v = line.partition(':')
        k, v = k.strip().lower(), v.strip()
        if k == 'mx':
            mx.append(v)
        elif k:
            kv[k] = v
    return {'mode': kv.get('mode'), 'max_age': int(kv['max_age']) if kv.get('max_age', '').isdigit() else None, 'mx': mx}


def ct_subdomains(domain):
    """Names seen in public certificate-transparency logs (crt.sh). Best effort: the service is slow and sometimes down."""
    req = urllib.request.Request(f'https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json', headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            raw = r.read(6_000_000).decode('utf-8', 'replace')
    except (urllib.error.URLError, OSError) as e:
        return {'source': 'crt.sh', 'total': 0, 'names': [], 'error': f'crt.sh not reachable ({getattr(e, "reason", e)})'}
    names = set()
    for blob in re.findall(r'"name_value":"([^"]+)"', raw):  # regex, not json: tolerates a response cut at the size cap
        for n in blob.split('\\n'):
            n = n.lower().lstrip('*.')
            if n == domain or n.endswith('.' + domain):
                names.add(n)
    return {'source': 'crt.sh', 'total': len(names), 'names': sorted(names)[:300], 'error': None}


def detect_services(mx, ns, spf_includes, txt, headers, cookies, hosts):
    found = {}

    def add(cat, name, ev):
        found.setdefault((cat, name), ev)
    for h in mx:
        for sub, name in MX_SERVICES:
            if sub in h.lower():
                add('Mail', name, f'MX {h}')
    for n in ns:
        for sub, name in NS_SERVICES:
            if sub in n.lower():
                add('DNS', name, f'NS {n}')
                break
    for i in spf_includes:
        for sub, name in SPF_SERVICES:
            if sub in i:
                add('Outbound mail', name, f'SPF include:{i}')
    for t in txt:
        for pre, name in TXT_SERVICES:
            if t.lower().startswith(pre):
                add('Linked services', name, 'verification TXT')
    for h, sub, name in HTTP_SERVICES:
        if h in headers and sub in headers[h].lower():
            add('Web', name, f'header {h}')
    for c in cookies:
        for sub, name in COOKIE_SERVICES:
            if c['name'].lower().startswith(sub):
                add('Web', name, f'cookie {c["name"]}')
    srv = headers.get('server', '')
    if srv and not any(srv.lower().startswith(x) for x in ('cloudflare', 'akamai', 'netlify')):
        add('Web', srv.split('/')[0], f'Server: {srv}')
    for h in hosts[:2]:
        if h.get('as_name'):
            add('Hosting', h['as_name'].rsplit(',', 1)[0], f'{h["ip"]} ({h["asn"]})')
    return [{'category': c, 'name': n, 'evidence': e} for (c, n), e in found.items()]


# ---------- the audit ----------
def audit(domain, deep=False):
    t0 = time.monotonic()
    findings = []

    def add(sev, cat, title, detail=''):
        findings.append({'severity': sev, 'category': cat, 'title': title, 'detail': detail, 'output': ''})

    types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CAA', 'CNAME']
    with ThreadPoolExecutor(16) as ex:
        reg_f = ex.submit(registration, domain)
        dns_f = {t: ex.submit(dns_values, domain, t) for t in types}
        soa_f = ex.submit(dns_rdata, domain, 'SOA')
        ds_f, key_f = ex.submit(dns_rdata, domain, 'DS'), ex.submit(dns_rdata, domain, 'DNSKEY')
        wc_name = f'wc-{uuid.uuid4().hex[:12]}.{domain}'
        wild_f = ex.submit(dns_values, wc_name, 'A')
        www_f = ex.submit(public_ips, f'www.{domain}')
        dmarc_f = ex.submit(dns_values, f'_dmarc.{domain}', 'TXT')
        mta_f = ex.submit(dns_values, f'_mta-sts.{domain}', 'TXT')
        rpt_f = ex.submit(dns_values, f'_smtp._tls.{domain}', 'TXT')
        bimi_f = ex.submit(dns_values, f'default._bimi.{domain}', 'TXT')
        dkim_f = {s: ex.submit(dns_values, f'{s}._domainkey.{domain}', 'TXT') for s in DKIM_SELECTORS}
        chain_f = ex.submit(redirect_chain, domain)
        sub_f = ex.submit(ct_subdomains, domain) if deep else None

        dns = {t: f.result() for t, f in dns_f.items()}
        ips = list(dict.fromkeys(dns['A'] + dns['AAAA']))[:4]
        real_mx = [m for m in dns['MX'] if m.split()[1] != '.']
        null_mx = bool(dns['MX']) and not real_mx  # the domain says it does not receive mail
        public = [ip for ip in ips if is_public(ip)]
        mx_hosts = [m.split()[1] for m in real_mx[:5]]
        ns_f = [ex.submit(ns_probe, domain, n) for n in dns['NS'][:6]]
        mx_ips_f = {h: ex.submit(lambda h=h: (dns_values(h, 'A') + dns_values(h, 'AAAA'), bool(dns_values(h, 'CNAME')))) for h in mx_hosts}
        hosts_f = [ex.submit(ip_info, ip) for ip in ips]
        https_f = ex.submit(probe_https, domain, public[0]) if public else None
        h2_f = ex.submit(supports_h2, domain, public[0]) if public else None
        proto_f = ex.submit(tls_protocols, domain, public[0]) if (public and deep) else None
        sectxt_f = ex.submit(fetch, domain, public[0], 443, True, '/.well-known/security.txt', 'GET', 2048) if public else None
        robots_f = ex.submit(fetch, domain, public[0], 443, True, '/robots.txt', 'HEAD') if public else None
        spf_txt = [v for v in dns['TXT'] if v.lower().startswith('v=spf1')]
        spf_deep_f = ex.submit(spf_lookups, spf_txt[0]) if (deep and len(spf_txt) == 1) else None
        mtasts_f = ex.submit(mta_sts_policy, domain) if deep and real_mx else None

        reg, soa_rd = reg_f.result(), soa_f.result()
        nameservers = [f.result() for f in ns_f]
        ns_pub_ips = {n['name']: next((i for i in n['ips'] if is_public(i)), None) for n in nameservers}
        axfr_f = {n: ex.submit(axfr_open, domain, ip) for n, ip in ns_pub_ips.items() if ip}
        hosts = [f.result() for f in hosts_f]
        tls, status, headers, cookies_raw = https_f.result() if https_f else (None, None, {}, [])
        h2 = h2_f.result() if h2_f else False
        protocols = proto_f.result() if proto_f else []
        sectxt = sectxt_f.result() if sectxt_f else None
        robots = robots_f.result() if robots_f else None
        chain = chain_f.result()
        mx_info = {h: f.result() for h, f in mx_ips_f.items()}
        spf_count, spf_chain = spf_deep_f.result() if spf_deep_f else (None, [])
        mta_policy = mtasts_f.result() if mtasts_f else None
        axfr_res = {n: f.result() for n, f in axfr_f.items()}
        axfr = [n for n, v in axfr_res.items() if v]
        ds, keys, wild_vals, www_ips = ds_f.result(), key_f.result(), wild_f.result(), www_f.result()
        wildcard = bool(wild_vals)
        dmarc_txt = [v for v in dmarc_f.result() if v.lower().startswith('v=dmarc1')]
        mta_txt = [v for v in mta_f.result() if v.lower().startswith('v=stsv1')]
        rpt = next((v for v in rpt_f.result() if v.lower().startswith('v=tlsrptv1')), None)
        bimi = next((v for v in bimi_f.result() if v.lower().startswith('v=bimi1')), None)
        dkim_raw = {s: f.result() for s, f in dkim_f.items()}
        dkim = [s for s, v in dkim_raw.items() if any('p=' in x for x in v)]
        subdomains = sub_f.result() if sub_f else None

    cookies = [parse_cookie(c) for c in cookies_raw]
    hsts = parse_hsts(headers.get('strict-transport-security'))
    spf = None
    if spf_txt:
        spf = {'record': spf_txt[0], **parse_spf(spf_txt[0])}
        spf['lookups'] = spf_count if spf_count is not None else len(re.findall(r'\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)', spf_txt[0].lower()))
        spf['lookups_exact'] = spf_count is not None
        if spf_chain:
            spf['includes'] = list(dict.fromkeys(spf['includes'] + spf_chain))
    dmarc = parse_dmarc(dmarc_txt[0]) if dmarc_txt else None
    soa = None
    if soa_rd:
        r = soa_rd[0]
        soa = {'mname': str(r.mname).rstrip('.'), 'rname': str(r.rname).rstrip('.'), 'serial': r.times[0], 'refresh': r.times[1], 'retry': r.times[2], 'expire': r.times[3], 'minimum': r.times[4]}
    algos = sorted({DNSSEC_ALGOS.get(r.algorithm, f'algoritmo {r.algorithm}') for r in ds + keys})
    weak = {r.algorithm for r in ds + keys} & WEAK_DNSSEC
    mail = {
        'mx': [{'priority': int(m.split()[0]), 'host': m.split()[1], 'ips': mx_info[m.split()[1]][0][:4], 'cname': mx_info[m.split()[1]][1]} for m in real_mx[:5]],
        'spf': spf, 'dmarc': dmarc, 'dkim_selectors': dkim,
        'mta_sts': {'txt': mta_txt[0], **(mta_policy or {'mode': None, 'max_age': None, 'mx': []})} if mta_txt else None,
        'tls_rpt': rpt, 'bimi': bimi,
    }
    web = {
        'redirects': chain, 'https_status': status,
        'headers': {k: headers[k] for k in ('server', 'location', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options',
                                           'referrer-policy', 'permissions-policy', 'x-powered-by', 'cross-origin-opener-policy', 'access-control-allow-origin', 'content-type')
                    if k in headers} if status else {},
        'cookies': cookies, 'hsts': hsts,
        'security_txt': (sectxt[0] == 200 and b'contact:' in sectxt[3].lower()) if sectxt else None,
        'robots_txt': (robots[0] == 200) if robots else None,
    }
    if tls:
        tls['alpn_h2'] = h2
        tls['protocols'] = protocols
    services = detect_services(mx_hosts, dns['NS'], (spf or {}).get('includes', []), dns['TXT'], headers, cookies, hosts)

    # --- findings: DNS and delegation ---
    if not any(dns[t] for t in ('A', 'AAAA', 'CNAME', 'NS', 'MX')) and not soa:
        add('bad', 'DNS', 'The domain does not answer', 'No record found: the name may not exist or the upstream is unreachable.')
    if len(dns['NS']) >= 2:
        add('ok', 'DNS', f'{len(dns["NS"])} name server', ', '.join(dns['NS']))
    elif dns['NS']:
        add('warn', 'DNS', 'Only one name server', 'If it stops answering, the domain disappears. Use at least two.')
    silent = [n['name'] for n in nameservers if ns_pub_ips.get(n['name']) and not n['responds']]
    if silent:
        add('warn', 'DNS', 'Name servers not answering', 'They do not answer as authoritative for the domain: ' + ', '.join(silent))
    serials = {n['serial'] for n in nameservers if n['serial'] is not None}
    if len(serials) > 1:
        multi = len({n['asn'] for n in nameservers if n['asn']}) > 1  # several DNS providers: each keeps its own serial, that is normal
        add('info' if multi else 'warn', 'DNS', 'The name servers have different SOA serial numbers' if multi else 'The name servers have different versions of the zone',
            ('Normal with several DNS providers. ' if multi else 'The zone may be out of sync. ') + ', '.join(f'{n["name"]}={n["serial"]}' for n in nameservers if n['serial'] is not None))
    elif len(nameservers) > 1 and serials:
        add('ok', 'DNS', 'Name servers in sync', f'Same SOA serial number ({next(iter(serials))}).')
    slow = [n for n in nameservers if n['ms'] and n['ms'] > 800]
    if slow:
        add('info', 'DNS', 'Slow name servers', ', '.join(f'{n["name"]} ({n["ms"]} ms)' for n in slow))
    asns = {n['asn'] for n in nameservers if n['asn']}
    if len(nameservers) > 1 and len(asns) == 1:
        add('info', 'DNS', 'All name servers are on the same network', f'{next(iter(asns))}: an outage at that provider takes them all down.')
    if axfr:
        add('bad', 'DNS', 'Zone transfer (AXFR) allowed', 'Anyone can download the whole zone from: ' + ', '.join(axfr))
    elif axfr_f:
        add('ok', 'DNS', 'Zone transfer not allowed')
    if soa:
        if soa['expire'] < 604800:
            add('info', 'DNS', 'Short SOA expire', f'expire = {soa["expire"]} s: if the secondaries cannot reach the primary, they stop answering soon.')
        if soa['minimum'] > 86400:
            add('info', 'DNS', 'High negative TTL', f'minimum = {soa["minimum"]} s: "does not exist" errors stay cached for a long time.')
    if wildcard:
        add('info', 'DNS', 'DNS wildcard active', 'Any non-existent subdomain resolves: it makes typos harder to notice and can hide real subdomains.')
    if dns['AAAA']:
        add('ok', 'DNS', 'Reachable over IPv6')
    elif dns['A']:
        add('info', 'DNS', 'No IPv6 address (AAAA)', 'Anyone on IPv6 only cannot reach the site.')
    if not domain.startswith('www.') and dns['A'] + dns['AAAA'] and not www_ips:
        add('info', 'DNS', f'www.{domain} does not resolve', 'Anyone who types "www." in front of the name cannot reach the site.')
    if ds or keys:
        add('ok', 'DNSSEC', 'DNSSEC attivo', 'Algorithms: ' + ', '.join(algos))
        if weak:
            add('warn', 'DNSSEC', 'Weak DNSSEC algorithm', 'SHA-1 is considered obsolete: switch to RSA/SHA-256, ECDSA or Ed25519.')
    else:
        add('warn', 'DNSSEC', 'DNSSEC not active', 'DNS answers are not signed: they are easier to forge.')
    if keys and not ds:
        add('warn', 'DNSSEC', 'Zone signed but no DS record at the registry', 'The chain of trust is broken: validating resolvers do not trust the signatures.')
    if dns['CAA']:
        add('ok', 'Certificates', 'CAA record present', '; '.join(dns['CAA']))
    else:
        add('info', 'Certificates', 'No CAA record', 'Any certification authority can issue certificates for the domain.')

    # --- mail ---
    if null_mx:
        add('ok', 'Mail', 'The domain declares it receives no mail (null MX)', 'Correct for a domain without mail: SPF "-all" and DMARC "reject" are also needed.')
    if real_mx:
        add('ok', 'Mail', f'{len(real_mx)} mail servers (MX)', ', '.join(real_mx))
        for m in mail['mx']:
            if m['cname']:
                add('bad', 'Mail', f'The MX {m["host"]} is an alias (CNAME)', 'MX records must point to a name with an A/AAAA address, not to a CNAME.')
            elif not m['ips']:
                add('bad', 'Mail', f'The MX {m["host"]} has no addresses', 'Mail to this server cannot be delivered.')
    if len(spf_txt) > 1:
        add('bad', 'Mail', 'Several SPF records', 'Only one is allowed: with several SPF records it fails.')
    elif spf:
        a = spf['all']
        if a == '-':
            add('ok', 'Mail', 'SPF restrittivo (-all)', spf['record'])
        elif a == '~':
            add('warn', 'Mail', 'Permissive SPF (~all)', 'Unauthorised messages are only marked as suspicious. ' + spf['record'])
        elif a in ('?', '+'):
            add('bad', 'Mail', f'SPF does not protect ({a}all)', spf['record'])
        elif not spf['redirect']:
            add('warn', 'Mail', 'SPF senza regola finale "all"', spf['record'])
        if spf['lookups'] > 10:
            add('bad' if spf['lookups_exact'] else 'warn', 'Mail', f'SPF with {spf["lookups"]} DNS lookups', 'The limit is 10: beyond it, SPF fails.' + ('' if spf['lookups_exact'] else ' (first level only: use the deep analysis for the exact count)'))
        if any(t.lstrip('+-~?').lower().startswith('ptr') for t in spf['mechanisms']):
            add('warn', 'Mail', 'SPF usa il meccanismo "ptr"', 'È sconsigliato: lento e inaffidabile.')
    elif real_mx:
        add('warn', 'Mail', 'SPF missing', 'Anyone can send mail pretending to be this domain.')
    if dmarc:
        pol = (dmarc['policy'] or '').lower()
        if pol in ('quarantine', 'reject'):
            add('ok', 'Mail', f'DMARC attivo (p={pol})', dmarc['record'])
        else:
            add('warn', 'Mail', 'DMARC not enforced (p=none)', 'The domain collects reports but does not block forged messages. ' + dmarc['record'])
        if dmarc['pct'] < 100:
            add('warn', 'Mail', f'DMARC applied to only {dmarc["pct"]}% of messages')
        if not dmarc['rua']:
            add('info', 'Mail', 'DMARC without a report address (rua)', 'Without reports you cannot see who sends on your behalf.')
        if dmarc['subdomain_policy'] and dmarc['subdomain_policy'].lower() == 'none' and pol in ('quarantine', 'reject'):
            add('warn', 'Mail', 'DMARC does not protect subdomains (sp=none)')
    elif real_mx:
        add('bad', 'Mail', 'DMARC missing', 'Without DMARC recipients do not know what to do with messages that fail SPF/DKIM.')
    if dkim:
        add('ok', 'Mail', 'DKIM keys found', 'selectors: ' + ', '.join(dkim))
    elif real_mx:
        add('info', 'Mail', 'No DKIM key on the common selectors', 'It may use a non-standard selector: they cannot be listed.')
    if mta_txt:
        pol = mail['mta_sts']
        if pol['mode'] == 'enforce':
            add('ok', 'Mail', 'MTA-STS in enforce mode', f'max_age {pol["max_age"]} s')
        elif pol['mode']:
            add('warn', 'Mail', f'MTA-STS in "{pol["mode"]}" mode', 'Only "enforce" really requires TLS encryption.')
        else:
            add('ok', 'Mail', 'MTA-STS configured', 'Policy not read: use the deep analysis.' if not deep else 'The HTTPS policy is not reachable.')
    elif real_mx:
        add('info', 'Mail', 'MTA-STS not configured', 'Requires TLS encryption between mail servers.')
    if rpt:
        add('ok', 'Mail', 'TLS-RPT configurato', rpt)
    if bimi:
        add('ok', 'Mail', 'BIMI configurato', bimi)

    # --- registration ---
    if reg:
        if reg['expires']:
            days = (datetime.fromisoformat(reg['expires'].replace('Z', '+00:00')) - datetime.now(timezone.utc)).days
            add('bad' if days < 14 else 'warn' if days < 60 else 'ok', 'Registration', f'The domain expires in {days} days' if days >= 0 else 'The domain has expired', reg['expires'][:10])
        if reg['age_days'] is not None:
            add('info' if reg['age_days'] < 180 else 'ok', 'Registration', f'Domain registered {reg["age_days"] // 365} years and {reg["age_days"] % 365 // 30} months ago' if reg['age_days'] >= 365 else f'Domain registered {reg["age_days"]} days ago',
                'A very recent domain deserves more caution.' if reg['age_days'] < 180 else '')
        if not any('transferprohibited' in s.replace(' ', '').lower() for s in reg['status']):
            add('info', 'Registration', 'Transfer lock not active', 'The registrar does not report "transfer prohibited": consider turning it on.')
        if reg['nameservers'] and set(reg['nameservers']) != {n.lower() for n in dns['NS']}:
            add('warn', 'Registration', 'Name servers differ between registry and zone', f'Registry: {", ".join(reg["nameservers"])}. Zone: {", ".join(dns["NS"])}.')
    else:
        add('info', 'Registration', 'Registration data not available', 'RDAP returned no results (some country-code domains do not support it).')

    # --- HTTPS / web ---
    if tls:
        if tls['valid']:
            d = tls['days_left']
            add('bad' if d < 0 else 'warn' if d < 30 else 'ok', 'HTTPS', 'Certificate expired' if d < 0 else f'Certificate valid, expires in {d} days', tls['issuer'])
            if tls['wildcard']:
                add('info', 'HTTPS', 'Wildcard certificate', 'A single key protects all subdomains: if it leaks, it applies to all of them.')
        else:
            add('bad', 'HTTPS', 'Certificate not valid', tls['error'] or '')
        if tls['version'] in ('TLSv1', 'TLSv1.1', 'SSLv3'):
            add('bad', 'HTTPS', f'Obsolete protocol ({tls["version"]})')
        elif tls['version']:
            add('ok', 'HTTPS', f'Protocol {tls["version"]}')
        for p in protocols:
            if p['name'] in ('TLSv1.0', 'TLSv1.1') and p['supported']:
                add('bad', 'HTTPS', f'The server still accepts {p["name"]}', 'Obsolete and vulnerable protocol: turn it off.')
        if protocols and not any(p['name'] == 'TLSv1.3' and p['supported'] for p in protocols) and any(p['name'] == 'TLSv1.3' and p['supported'] is False for p in protocols):
            add('info', 'HTTPS', 'TLS 1.3 not supported')
        add('ok' if h2 else 'info', 'HTTPS', 'HTTP/2 supported' if h2 else 'HTTP/2 not supported')
    elif public:
        add('warn', 'HTTPS', 'HTTPS not reachable', f'No answer on port 443 of {public[0]}.')
    elif ips:
        add('info', 'HTTPS', 'Non-public addresses: HTTPS not probed', ', '.join(ips))
    if status:
        if not hsts:
            add('warn', 'HTTPS', 'HSTS missing', 'Without HSTS the browser can be tricked into using plain HTTP.')
        else:
            add('ok', 'HTTPS', 'HSTS attivo', headers['strict-transport-security'])
            if hsts['max_age'] < 15552000:
                add('warn', 'HTTPS', f'HSTS with a short duration ({hsts["max_age"]} s)', 'At least 6 months (15552000 s) recommended.')
            if not hsts['include_subdomains']:
                add('info', 'HTTPS', 'HSTS senza includeSubDomains')
        for h in SECURITY_HEADERS:
            if h not in headers:
                add(SECURITY_HEADERS[h][0], 'HTTP headers', SECURITY_HEADERS[h][1], SECURITY_HEADERS[h][2])
        if 'x-frame-options' not in headers and 'frame-ancestors' not in headers.get('content-security-policy', ''):
            add('info', 'HTTP headers', 'No clickjacking protection', 'X-Frame-Options and CSP frame-ancestors are missing: the page can be embedded in other sites.')
        if re.search(r'\d+\.\d+', headers.get('server', '') + headers.get('x-powered-by', '')):
            add('info', 'HTTP headers', 'Software version exposed', f'{headers.get("server", "")} {headers.get("x-powered-by", "")}'.strip())
        if headers.get('access-control-allow-origin') == '*':
            add('info', 'HTTP headers', 'CORS open to any origin (*)')
        loose = [c['name'] for c in cookies if not c['secure']]
        if loose:
            add('warn', 'Cookies', 'Cookies without the Secure flag', ', '.join(loose))
        nohttp = [c['name'] for c in cookies if not c['httponly']]
        if nohttp:
            add('info', 'Cookies', 'Cookies readable by JavaScript (no HttpOnly)', ', '.join(nohttp))
        nosame = [c['name'] for c in cookies if not c['samesite']]
        if nosame:
            add('info', 'Cookies', 'Cookies without SameSite', ', '.join(nosame))
    if chain:
        first, last = chain[0], chain[-1]
        if first['status'] in (301, 302, 307, 308) and (first['location'] or '').startswith('https://'):
            add('ok', 'Web', 'HTTP reindirizza a HTTPS')
        elif first['status']:
            add('warn', 'Web', 'HTTP does not redirect to HTTPS', f'Response {first["status"]} on port 80.')
        if len(chain) > 3:
            add('warn', 'Web', f'Chain of {len(chain)} redirects', ' → '.join(h['url'] for h in chain))
        elif len(chain) > 1:
            add('info', 'Web', f'{len(chain)} hops to the final page', ' → '.join(h['url'] for h in chain))
        landing = urllib.parse.urlsplit(last['url']).hostname or ''
        if landing and not (landing == domain or landing.endswith('.' + domain) or domain.endswith('.' + landing)):
            add('info', 'Web', f'The site redirects to another domain ({landing})')
    if web['security_txt']:
        add('ok', 'Web', 'security.txt present', 'Anyone who finds a vulnerability knows whom to tell.')
    elif web['security_txt'] is False:
        add('info', 'Web', 'security.txt missing', 'Publish /.well-known/security.txt with a contact for security reports.')
    if subdomains and subdomains['names']:
        hit = [n for n in subdomains['names'] if SENSITIVE_SUBDOMAINS.search(n[: -len(domain) - 1] if n != domain else '')]
        add('info', 'Subdomains', f'{subdomains["total"]} names in the certificate logs', 'Public list: anyone can see it.')
        if hit:
            add('warn', 'Subdomains', 'Subdomains that suggest exposed internal services', ', '.join(hit[:12]))
    elif subdomains and subdomains['error']:
        add('info', 'Subdomains', 'Subdomain list not available', subdomains['error'])


    # --- raw output of each test, shown on demand in the UI ---
    def block(*lines):
        return '\n'.join(str(x) for x in lines)

    def kv(d):
        return '\n'.join(f'{k}: {v}' for k, v in d.items() if v not in (None, '', [], {}))

    out_dns_all = block(*[f'{t:<6} {", ".join(dns[t]) if dns[t] else "(no record)"}' for t in types])
    out_ns = block(*[f'{n["name"]:<34} {", ".join(n["ips"]) or "-":<42} {n["asn"] or "-":<9} serial {n["serial"]} · ' + (f'{n["ms"]} ms' + (' · authoritative' if n['authoritative'] else '') if n['responds'] else 'no answer') for n in nameservers]) or 'No name server.'
    out_soa = kv({'primary server': soa and soa['mname'], 'responsible': soa and soa['rname'], 'serial': soa and soa['serial'], 'refresh': soa and soa['refresh'], 'retry': soa and soa['retry'], 'expire': soa and soa['expire'], 'minimum': soa and soa['minimum']}) if soa else 'SOA not obtained.'
    out_ns_soa = block(out_ns, '', 'SOA', out_soa)
    out_axfr = block(*[f'AXFR {n} ({ns_pub_ips[n] or "non-public address"})  →  ' + ('ALLOWED' if axfr_res.get(n) else 'refused' if n in axfr_res else 'not probed') for n in ns_pub_ips]) or 'No name server to probe.'
    out_wild = f'A {wc_name}  →  ' + (', '.join(wild_vals) if wild_vals else 'NXDOMAIN / no record (non-existent random name)')
    out_aaaa = 'AAAA ' + domain + '  →  ' + (', '.join(dns['AAAA']) or '(no record)') + '\nA    ' + domain + '  →  ' + (', '.join(dns['A']) or '(no record)')
    out_www = f'A/AAAA www.{domain}  →  ' + (', '.join(www_ips) or 'no public address')
    out_dnssec = block('DS (published by the registry):', *(['  ' + str(r)[:200] for r in ds] or ['  (none)']), 'DNSKEY (in the zone):', *(['  ' + str(r)[:200] for r in keys] or ['  (none)']), 'Algorithms: ' + (', '.join(algos) or '—'))
    out_caa = 'CAA ' + domain + '  →  ' + ('\n'.join(dns['CAA']) or '(no record)')
    out_mx = block(*[f'{m["priority"]:<4} {m["host"]:<40} →  {", ".join(m["ips"]) or "no address"}' + ('   [ALIAS: CNAME not allowed]' if m['cname'] else '') for m in mail['mx']]) or ('MX ' + ', '.join(dns['MX']) if dns['MX'] else 'No MX record.')
    out_spf = block(*(['SPF ' + spf['record'], '', 'Mechanisms:', *['  ' + m for m in spf['mechanisms']], '', f'Final rule: {spf["all"] or "none"}', f'DNS lookups: {spf["lookups"]} ({"exact count" if spf["lookups_exact"] else "first level only"})', 'Included providers: ' + (', '.join(spf['includes']) or '—')] if spf else ['No SPF record.', *(['TXT found:', *['  ' + t for t in dns['TXT']]] if dns['TXT'] else [])]))
    out_dmarc = block(*(['_dmarc.' + domain + '  TXT', '  ' + dmarc['record'], '', kv({'policy (p)': dmarc['policy'], 'subdomains (sp)': dmarc['subdomain_policy'], 'percentage (pct)': dmarc['pct'], 'reports (rua)': ', '.join(dmarc['rua']), 'forensic (ruf)': ', '.join(dmarc['ruf']), 'DKIM alignment': dmarc['adkim'], 'SPF alignment': dmarc['aspf']})] if dmarc else ['No TXT record on _dmarc.' + domain]))
    out_dkim = block(*[f'{sel}._domainkey.{domain}  →  ' + (next((x[:80] + ('…' if len(x) > 80 else '') for x in v if 'p=' in x), '(no key)')) for sel, v in dkim_raw.items()])
    out_mta = block(*(['_mta-sts.' + domain + '  TXT', '  ' + mta_txt[0], '', 'Policy https://mta-sts.' + domain + '/.well-known/mta-sts.txt', kv({'mode': (mta_policy or {}).get('mode'), 'max_age': (mta_policy or {}).get('max_age'), 'mx': ', '.join((mta_policy or {}).get('mx', []))}) or '  (not read: quick analysis or policy not reachable)'] if mta_txt else ['No TXT record on _mta-sts.' + domain]))
    out_rpt = f'_smtp._tls.{domain}  TXT  →  {rpt or "(no record)"}'
    out_bimi = f'default._bimi.{domain}  TXT  →  {bimi or "(no record)"}'
    out_reg = kv({'registered domain': reg and reg['name'], 'registrar': reg and reg['registrar'], 'created': reg and reg['created'], 'expires': reg and reg['expires'], 'last updated': reg and reg['updated'], 'age (days)': reg and reg['age_days'], 'status': reg and ', '.join(reg['status']), 'DNSSEC delegation signed': reg and reg['dnssec_signed'], 'abuse': reg and reg['abuse_email'], 'name servers (registry)': reg and ', '.join(reg['nameservers']), 'name servers (zone)': ', '.join(dns['NS'])}) if reg else f'RDAP rdap.org/domain/{domain}: no result (parent domains tried too).'
    out_tls = (block(kv({'address probed': tls['ip'], 'negotiated protocol': tls['version'], 'cipher': tls['cipher'], 'HTTP/2 (ALPN)': 'yes' if tls.get('alpn_h2') else 'no', 'certificate check': 'valid' if tls['valid'] else f'NOT valid: {tls["error"]}', 'issued to': tls['subject'], 'issued by': tls['issuer'], 'valid from': tls['not_before'], 'valid until': tls['not_after'], 'days left': tls['days_left'], 'serial': tls['serial'], 'wildcard': tls['wildcard'], 'names (SAN)': ', '.join(tls['san']), 'OCSP': ', '.join(tls['ocsp'])}),
                '', 'TLS versions accepted (deep analysis):' if protocols else 'TLS versions: not checked (quick analysis).', *[f'  {p["name"]}: ' + ('n/a' if p['supported'] is None else 'yes' if p['supported'] else 'no') for p in protocols]) if tls
               else f'Connection to {public[0] if public else "(no public address)"}:443 failed.')
    out_headers = block(f'HEAD / → HTTP {status}', *[f'{k}: {v}' for k, v in headers.items()]) if status else 'No HTTPS response.'
    out_cookies = block(*[f'Set-Cookie: {c}' for c in cookies_raw]) or 'No cookie set by the main page.'
    out_chain = block(*[f'{i}. {h["status"] or "—"}  {h["url"]}' + (f'\n     → {h["location"]}' if h['location'] else '') + (f'  [{h["ip"]}]' if h['ip'] else '  [non-public or unresolvable address]') for i, h in enumerate(chain, 1)]) or 'No response on http://' + domain + '/'
    out_sectxt = block(f'GET /.well-known/security.txt → {sectxt[0] if sectxt else "—"}', (sectxt[3][:600].decode('utf-8', 'replace') if sectxt and sectxt[3] else '(no content)')) if sectxt else 'Not probed (no public address).'
    out_subs = block(f'Source: {subdomains["source"]} — {subdomains["total"]} names' + (f' (first {len(subdomains["names"])})' if subdomains['total'] > len(subdomains['names']) else ''), *subdomains['names'], *([f'Error: {subdomains["error"]}'] if subdomains['error'] else [])) if subdomains else ''

    rules = [  # (category, title substrings or None for all, output)
        ('DNS', ('does not answer',), out_dns_all), ('DNS', ('Zone transfer',), out_axfr), ('DNS', ('SOA', 'negative TTL'), out_soa), ('DNS', ('wildcard',), out_wild),
        ('DNS', ('IPv6',), out_aaaa), ('DNS', ('www.',), out_www), ('DNS', ('name server', 'Name server'), out_ns_soa),
        ('DNSSEC', None, out_dnssec), ('Certificates', None, out_caa),
        ('Mail', ('SPF',), out_spf), ('Mail', ('DMARC',), out_dmarc), ('Mail', ('DKIM',), out_dkim), ('Mail', ('MTA-STS',), out_mta),
        ('Mail', ('TLS-RPT',), out_rpt), ('Mail', ('BIMI',), out_bimi), ('Mail', None, out_mx),
        ('Registration', None, out_reg),
        ('HTTPS', ('ertificate', 'rotocol', 'HTTP/2', 'still accepts', 'TLS 1.3', 'not reachable', 'not probed'), out_tls),
        ('HTTPS', None, out_headers), ('HTTP headers', None, out_headers), ('Cookies', None, out_cookies),
        ('Web', ('security.txt',), out_sectxt), ('Web', None, out_chain), ('Subdomains', None, out_subs),
    ]
    for f in findings:
        f['output'] = next((text for cat, subs, text in rules if f['category'] == cat and (subs is None or any(x in f['title'] for x in subs))), '')

    order = {'bad': 0, 'warn': 1, 'info': 2, 'ok': 3}
    findings.sort(key=lambda f: order[f['severity']])
    return {
        'domain': domain, 'checked_at': datetime.now(timezone.utc).isoformat(), 'deep': deep, 'duration_ms': int((time.monotonic() - t0) * 1000),
        'summary': {s: sum(f['severity'] == s for f in findings) for s in order}, 'findings': findings,
        'dns': [{'type': t, 'values': v} for t, v in dns.items() if v], 'soa': soa, 'nameservers': nameservers,
        'dnssec': {'enabled': bool(ds or keys), 'algorithms': algos}, 'wildcard': wildcard,
        'mail': mail, 'registration': reg, 'hosts': hosts, 'tls': tls, 'web': web, 'services': services, 'subdomains': subdomains,
    }
