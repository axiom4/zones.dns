import urllib.parse

from .audit import NAME_RE, fetch, public_ips
from .domains import main_domain

REDIRECTS = (301, 302, 303, 307, 308)


def _tracking_cookie(raw):
    low = [p.strip().lower() for p in raw.split(';')]
    return any(p.startswith(('max-age=', 'expires=')) for p in low) or 'samesite=none' in low


def probe(domain, max_hops=6):
    """Follow http://domain/ and report (redirect_target, cookie_names): a different registrable domain reached, and persistent/cross-site cookies set on the way.

    A chain that ends on an HTML page is a site a person uses (gmail.com -> google.com): reported as no match.
    Only chains ending on a non-page (pixel, empty, JSON) look like tracker endpoints.
    """
    url, seen, cookies, target, page = f'http://{domain}/', set(), [], None, True
    for _ in range(max_hops):
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or '').lower()
        port = u.port or (443 if u.scheme == 'https' else 80)
        if u.scheme not in ('http', 'https') or not NAME_RE.match(host) or url in seen or port not in (80, 443):
            break
        seen.add(url)
        ips = public_ips(host)  # public addresses only: no SSRF into the LAN
        if not ips:
            break
        status, headers, raw, _ = fetch(host, ips[0], port, u.scheme == 'https', (u.path or '/') + (f'?{u.query}' if u.query else ''), 'GET')
        cookies += [c.split('=', 1)[0] for c in raw if _tracking_cookie(c)]
        page = not (status and status < 400 and not headers.get('content-type', '').lower().startswith('text/html'))
        if main_domain(host) != domain:
            target = main_domain(host)
        if status in REDIRECTS and headers.get('location'):
            url = urllib.parse.urljoin(url, headers['location'])
        else:
            break
    return (None if page else target), cookies
