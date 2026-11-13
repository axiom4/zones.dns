import urllib.parse

from .audit import NAME_RE, fetch, public_ips
from ..dnsd.domains import main_domain

REDIRECTS = (301, 302, 303, 307, 308)


def _tracking_cookie(raw):
    low = [p.strip().lower() for p in raw.split(';')]
    return any(p.startswith(('max-age=', 'expires=')) for p in low) or 'samesite=none' in low


def probe(domain, max_hops=6):
    """Follow http://domain/ and report (redirect_target, cookie_names, pixel): a different registrable domain reached, persistent/cross-site cookies set on
    the way, and whether the chain ends on a tracking pixel (an image of under 200 bytes, or an empty 204).

    A chain that ends on an HTML page is a site a person uses (gmail.com -> google.com): reported as no match.
    Only chains ending on a non-page (pixel, empty, JSON) look like tracker endpoints.
    """
    url, seen, cookies, target, page, pixel = f'http://{domain}/', set(), [], None, True, False
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
        status, headers, raw, body = fetch(host, ips[0], port, u.scheme == 'https', (u.path or '/') + (f'?{u.query}' if u.query else ''), 'GET', body_limit=256)
        cookies += [c.split('=', 1)[0] for c in raw if _tracking_cookie(c)]
        page = not (status and status < 400 and not headers.get('content-type', '').lower().startswith('text/html'))
        ctype = headers.get('content-type', '').lower()
        pixel = bool(status) and ((status == 204) or (status < 300 and ctype.startswith('image/') and len(body) < 200))
        if main_domain(host) != domain:
            target = main_domain(host)
        if status in REDIRECTS and headers.get('location'):
            url = urllib.parse.urljoin(url, headers['location'])
        else:
            break
    return (None if page else target), cookies, pixel
