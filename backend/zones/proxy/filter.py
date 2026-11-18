"""Content, URL, and domain filtering for the HTTP/HTTPS proxy: ad blocking, cosmetic CSS, and popup/popunder blocking."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from functools import lru_cache
import html
import re
import threading
import time
from urllib.parse import urlparse

from django.db import DatabaseError, connection

from ..dnsd import resolver
from . import rules

_db_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='proxy-db')


def run_on_db_pool(fn, *args, timeout=10, **kwargs):
    """Execute a DB-touching function on the dedicated 2-worker pool so persistent DB connections are reused and tunnel threads never touch PostgreSQL.
    The proxy's other threads then hold no database connection: the proxy uses 2 (plus 1 for its log writer), however busy it is."""
    if connection.in_atomic_block or threading.current_thread().name.startswith('proxy-db'):
        return fn(*args, **kwargs)  # already in a transaction (tests) or on the pool itself: waiting on the pool would deadlock it

    def _task():
        resolver._db_check()
        return fn(*args, **kwargs)

    fut = _db_pool.submit(_task)
    try:
        return fut.result(timeout=timeout)
    except FutureTimeout:
        # a DatabaseError, not a TimeoutError: that one means the client's connection, and the request was dropped without an answer
        fut.cancel()  # still queued: it would only lengthen the queue
        raise DatabaseError(f'the database did not answer within {timeout} s') from None


def _check_domain_blocked(h):
    """Fast in-memory check against `resolver._blocked` when fresh; falls back to `run_on_db_pool(resolver.blocked_entry, h)` on cache miss."""
    if resolver._data is not None and (time.monotonic() - resolver._data_checked) < 1.0:
        with resolver._blocked_lock:
            if h in resolver._blocked:
                resolver._blocked.move_to_end(h)
                return resolver._blocked[h]
    try:
        return run_on_db_pool(resolver.blocked_entry, h, timeout=3)
    except DatabaseError:
        resolver._db_away('the proxy lets through names it has not seen yet')
        return None  # like the DNS daemon: unfiltered rather than no answer (and a work thread held 10 s per request)

# Common ad-serving URL paths and query patterns
AD_URL_RX = re.compile(
    r'(?:'
    r'/(?:pagead|adserver|adservice|adsense|adsbygoogle|adframe|adbanner|banner_ads?|dfp|prebid| outstream|sponsor(?:ed)?_ads?)(?:/|\.js|\.html|\.php|\?|$)'
    r'|/(?:ads|adv)/(?:banner|pop|iframe|load|show|track|delivery|beacon)'
    r'|[?&](?:ad_type|ad_slot|ad_unit|adurl|google_ad_client)='
    r'|/(?:gpt|pubads_impl|show_ads)\.js'
    r')',
    re.IGNORECASE,
)

# Common popup / popunder / clickunder script & URL patterns
POPUP_URL_RX = re.compile(
    r'(?:'
    r'/(?:popunder|popup_ads?|popads|popcash|clickunder|tabunder|exitpop|adcash|propellerads|hilltopads|exoclick|juicyads)(?:/|\.min\.js|\.js|\.php|\?|$)'
    r'|(?:[/_.-](?:popunder|clickunder|tabunder|exitpopup)\b[a-z0-9_.-]*\.js)'
    r')',
    re.IGNORECASE,
)

# Inline script signatures known to trigger popups/popunders or ad injections
INLINE_POPUP_RX = re.compile(
    r'(?:\b(?:PopAds|popunder|clickunder|aclib\.runPop|exoLoader|openPopunder|_pop\.push)\b)',
    re.IGNORECASE,
)

# Cosmetic CSS rules injected into HTML pages when PROXY_BLOCK_ADS is enabled.
# Avoids classic anti-adblock bait class names (.adsbox, .ad-banner, .advertisement) so bait offsetHeight checks do not trigger "Ad Blocker Detected" modals.
DEFAULT_AD_SELECTORS = (
    'ins.adsbygoogle',
    '[id^="div-gpt-ad"]',
    '[id^="google_ads_iframe"]',
    '[id^="taboola-"]',
    '[id^="outbrain_widget"]',
    '[class*="popup-ad"]',
    '[class*="popunder"]',
    'iframe[src*="/ads/"]',
    'iframe[src*="doubleclick.net"]',
    'iframe[src*="googlesyndication.com"]',
)

# Anti-popup & anti-popunder script (plus harmless tracker/ad global stubs to prevent anti-adblock detection)
POPUP_BLOCKER_JS = (
    '<script id="zones-popup-blocker">(function(){'
    'var me=document.currentScript;if(me&&me.parentNode)me.parentNode.removeChild(me);'
    'var noop=function(){};'
    'window.adsbygoogle=window.adsbygoogle||{loaded:true,push:noop};'
    'window.ga=window.ga||noop;window.gtag=window.gtag||noop;'
    'window.google_tag_manager=window.google_tag_manager||{};'
    'window.Intercom=window.Intercom||function(){(window.Intercom.q=window.Intercom.q||[]).push(arguments);};'
    'window.Intercom.booted=true;'
    'window.Appcues=window.Appcues||{identify:noop,page:noop,track:noop,on:noop,anonymous:noop,reset:noop,debug:noop};'
    'var origOpen=window.open;'
    'var lastTrusted=0;'
    'var recordTrust=function(e){if(e&&e.isTrusted)lastTrusted=Date.now();};'
    'window.addEventListener("pointerdown",recordTrust,true);'
    'window.addEventListener("keydown",recordTrust,true);'
    'var badRx=/(?:popunder|popup|popads|clickunder|tabunder|adserver|doubleclick|googlesyndication|exoclick|propellerads)/i;'
    # sign-in popups (OAuth) open a sized window a moment after the click, once a request has answered: not blocked
    'window.open=function(u,n,f){'
    'var s=String(u||"");'
    'if(!s||s==="about:blank"||badRx.test(s)||(Date.now()-lastTrusted>3000)){'
    'console.debug("[Zones.dns] Blocked popup:",s);'
    'return null;'
    '}'
    'return origOpen.apply(window,arguments);'
    '};'
    'document.addEventListener("click",function(e){'
    'var a=e.target&&e.target.closest?e.target.closest(\'a[target="_blank"]\'):null;'
    'if(!a)return;'
    'var href=String(a.getAttribute("href")||"");'
    'var st=window.getComputedStyle(a);'
    'if(badRx.test(href)||(st.position==="fixed"&&parseFloat(st.opacity||"1")<0.05)){'
    'e.preventDefault();e.stopImmediatePropagation();'
    'console.debug("[Zones.dns] Blocked overlay/popup link:",href);'
    '}'
    '},true);'
    '})();</script>'
)

_SCRIPT_TAG_RX = re.compile(r'<script\b([^>]*)>(.*?)</script\s*>', re.IGNORECASE | re.DOTALL)
_IFRAME_TAG_RX = re.compile(r'<iframe\b([^>]*)>.*?</iframe\s*>', re.IGNORECASE | re.DOTALL)
_SRC_ATTR_RX = re.compile(r'\bsrc\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', re.IGNORECASE)
_HEAD_OPEN_RX = re.compile(r'(<head\b[^>]*>)', re.IGNORECASE)
_HEAD_CLOSE_RX = re.compile(r'(</head\s*>)', re.IGNORECASE)
_CHARSET_RX = re.compile(r'charset\s*=\s*([a-zA-Z0-9._-]+)', re.IGNORECASE)
_NO_HTML_FILTER_DOMAINS = frozenset({'challenges.cloudflare.com', 'hcaptcha.com', 'recaptcha.net'})


@lru_cache(maxsize=32)
def parse_custom_rules(raw_rules):
    """Parse PROXY_CUSTOM_RULES (including Adblock Plus / EasyList / uBlock syntax) into (allow_domains, url_patterns, global_css, domain_css)."""
    allow_domains = set()
    url_patterns = []
    global_css = []
    domain_css = {}
    for line in re.split(r'[\r\n]+', str(raw_rules or '')):
        line = line.strip()
        if not line or (line.startswith('#') and not line.startswith('##')) or line.startswith(('!', '[')):
            continue
        if '#@#' in line or '#?#' in line or '#$#' in line:
            continue  # advanced cosmetic exceptions/procedural filters ignored safely
        if line.startswith('@@'):
            rule = line[2:].split('$', 1)[0].strip().lstrip('|')
            if rule.startswith(('http://', 'https://')):
                rule = rule.split('://', 1)[1]
            dom = rule.split('/', 1)[0].split('^', 1)[0].lower().strip('.')
            if dom:
                allow_domains.add(dom)
        elif '##' in line:
            dom_part, _, sel = line.partition('##')
            sel = sel.strip()
            if not sel or not rules.css_ok(sel) or sel.startswith(('+js(', '^', 'script:inject')):
                continue
            if not dom_part.strip():
                global_css.append(sel)
            else:
                for d in dom_part.split(','):
                    d = d.strip().lower().strip('.')
                    if d and not d.startswith('~'):
                        domain_css.setdefault(d, []).append(sel)
        else:
            rule = line.split('$', 1)[0].strip()
            if not rule:
                continue
            if len(rule) >= 2 and rule.startswith('/') and rule.endswith('/'):
                try:
                    url_patterns.append((line, re.compile(rule[1:-1], re.IGNORECASE)))
                except re.error:
                    pass
            elif rule.startswith('||'):
                body = rule[2:].rstrip('^')
                pat = r'(?:^|[/.])' + r'.*'.join(re.escape(p) for p in body.split('*')).replace(r'\^', r'(?:[/?#:]|$)')
                try:
                    url_patterns.append((line, re.compile(pat, re.IGNORECASE)))
                except re.error:
                    pass
            else:
                pat = r'.*'.join(re.escape(p) for p in rule.split('*')).replace(r'\^', r'(?:[/?#:]|$)')
                url_patterns.append((line, re.compile(pat, re.IGNORECASE)))
    return allow_domains, url_patterns, global_css, domain_css


def is_domain_allowed(host, allow_domains):
    """True when `host` or a parent domain is in `allow_domains` (@@domain exception)."""
    h = (host or '').strip().lower().rstrip('.')
    if not h or not allow_domains:
        return False
    labels = h.split('.')
    return any('.'.join(labels[i:]) in allow_domains for i in range(len(labels)))


def check_request(host, url='', s=None, dns=True):
    """Return (reason_kind, detail) if the request to `host` / `url` should be blocked, else None. dns=False: the proxy's own rules only, not the DNS blacklist."""
    h = (host or '').strip().lower().rstrip('.')
    if h.startswith('[') and ']' in h:
        h = h[1:h.index(']')]
    elif ':' in h:
        h = h.partition(':')[0]
    block_ads = True if s is None else bool(getattr(s, 'PROXY_BLOCK_ADS', True))
    block_popups = True if s is None else bool(getattr(s, 'PROXY_BLOCK_POPUPS', True))
    custom_raw = '' if s is None else str(getattr(s, 'PROXY_CUSTOM_RULES', '') or '')
    allow_domains, url_patterns, _, _ = parse_custom_rules(custom_raw)
    ext = rules.loaded()
    if is_domain_allowed(h, allow_domains) or is_domain_allowed(h, ext.allow):
        return None
    if block_ads and h:
        if dns and (hit := _check_domain_blocked(h)):
            return ('blacklist', f'{hit[0]} ({hit[1]})')
        if hit := rules.blocked_by(h, ext):
            return ('rule-list', f'{hit[0]} ({hit[1]})')
    full_url = url or h
    if block_popups and full_url and (m := POPUP_URL_RX.search(full_url)):
        return ('popup-url', m.group(0))
    if block_ads and full_url and (m := AD_URL_RX.search(full_url)):
        return ('ad-url', m.group(0))
    for label, rx in url_patterns:
        if rx.search(full_url) or (h and rx.search(h)):
            return ('custom-rule', label)
    return None


def _extract_src(attrs_str):
    m = _SRC_ATTR_RX.search(attrs_str)
    if not m:
        return ''
    return (m.group(1) or m.group(2) or m.group(3) or '').strip()


def _src_is_blocked(src, page_host, s):
    if not src or src.startswith('data:') or src.startswith('blob:') or src.startswith('javascript:'):
        return False
    parsed = urlparse(src if '://' in src else ('http:' + src if src.startswith('//') else f'http://{page_host}/{src.lstrip("/")}'))
    target_host = (parsed.hostname or page_host or '').lower()
    return check_request(target_host, src, s=s) is not None


_UNDECODABLE_RX = re.compile('[\udc80-\udcff]')
_META_RX = re.compile(r'<meta\b[^>]*>', re.IGNORECASE)
_HTTP_EQUIV_CSP_RX = re.compile(r'''\bhttp-equiv\s*=\s*["']?content-security-policy["'\s>]''', re.IGNORECASE)
_CONTENT_ATTR_RX = re.compile(r'''\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')''', re.IGNORECASE)


def meta_csp(text):
    """The policies a page declares in <meta http-equiv="Content-Security-Policy" content="..."> (the browser applies them like the header)."""
    out = []
    for tag in _META_RX.findall(text):
        if _HTTP_EQUIV_CSP_RX.search(tag) and (m := _CONTENT_ATTR_RX.search(tag)):
            out.append(html.unescape(m.group(1) if m.group(1) is not None else m.group(2)))
    return out


def csp_allows_inline(csp, directive):
    """Whether an inline element we add (directive 'script-src' or 'style-src') may run under this Content-Security-Policy header.
    Every policy must allow it; with a nonce, a hash or 'strict-dynamic' the browser ignores 'unsafe-inline' (CSP 3)."""
    for policy in str(csp or '').split(','):
        found = {}
        for part in policy.split(';'):
            name, _, value = part.strip().partition(' ')
            if name:
                found.setdefault(name.lower(), value.lower())
        src = found.get(f'{directive}-elem', found.get(directive, found.get('default-src')))
        if src is None:
            continue
        tokens = src.split()
        if "'unsafe-inline'" not in tokens or any(t == "'strict-dynamic'" or t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens):
            return False
    return True


def filter_html(html_bytes, content_type='', host='', s=None, csp=''):
    """Filter an HTML response body: strip blocked ad/popup scripts and iframes, inject cosmetic CSS and popup-blocker JS.
    `csp`: the page's Content-Security-Policy header; with the policies of its <meta http-equiv> tags, what they would block is not injected
    (the browser would only report a violation)."""
    if not html_bytes:
        return html_bytes
    block_ads = True if s is None else bool(getattr(s, 'PROXY_BLOCK_ADS', True))
    block_popups = True if s is None else bool(getattr(s, 'PROXY_BLOCK_POPUPS', True))
    if not block_ads and not block_popups:
        return html_bytes
    custom_raw = '' if s is None else str(getattr(s, 'PROXY_CUSTOM_RULES', '') or '')
    allow_domains, _, global_css, domain_css = parse_custom_rules(custom_raw)
    h = (host or '').strip().lower().rstrip('.').partition(':')[0]
    ext = rules.loaded()
    if is_domain_allowed(h, allow_domains) or is_domain_allowed(h, ext.allow) or is_domain_allowed(h, _NO_HTML_FILTER_DOMAINS):
        return html_bytes

    if b'\x00' in html_bytes[:1024]:
        raise ValueError('Binary content cannot be filtered as HTML')

    m_cs = _CHARSET_RX.search(content_type or '')
    charset = m_cs.group(1) if m_cs else 'utf-8'
    # surrogateescape: bytes that are not valid in the charset (a page whose real charset is only in a <meta> tag) come back unchanged
    try:
        text = html_bytes.decode(charset, errors='surrogateescape')
    except LookupError:
        charset = 'utf-8'
        text = html_bytes.decode('utf-8', errors='surrogateescape')

    if len(_UNDECODABLE_RX.findall(text)) > max(8, len(text) // 20):
        raise ValueError('Compressed or non-text payload cannot be filtered as HTML')

    def _clean_script(match):
        attrs, body = match.group(1), match.group(2)
        src = _extract_src(attrs)
        if src and _src_is_blocked(src, h, s):
            return '<!-- blocked script -->'
        if block_popups and body and INLINE_POPUP_RX.search(body):
            return '<!-- blocked popup script -->'
        return match.group(0)

    def _clean_iframe(match):
        attrs = match.group(1)
        src = _extract_src(attrs)
        if src and _src_is_blocked(src, h, s):
            return '<!-- blocked iframe -->'
        return match.group(0)

    text = _SCRIPT_TAG_RX.sub(_clean_script, text)
    if block_ads:
        text = _IFRAME_TAG_RX.sub(_clean_iframe, text)

    csp = ', '.join(p for p in [csp, *meta_csp(text)] if p)
    injections = []
    if block_popups and 'id="zones-popup-blocker"' not in text and csp_allows_inline(csp, 'script-src'):
        injections.append(POPUP_BLOCKER_JS)
    if block_ads and 'id="zones-adblock-css"' not in text and csp_allows_inline(csp, 'style-src'):
        selectors = list(DEFAULT_AD_SELECTORS) + global_css + ext.global_css
        if h:
            labels = h.split('.')
            for i in range(len(labels)):
                sub = '.'.join(labels[i:])
                selectors.extend(domain_css.get(sub, ()))
                selectors.extend(ext.domain_css.get(sub, ()))
        css_rule = ', '.join(selectors) + ' { display: none !important; visibility: hidden !important; height: 0 !important; min-height: 0 !important; pointer-events: none !important; }'
        injections.append(f'<style id="zones-adblock-css">{css_rule}</style>')

    if injections:
        snippet = ''.join(injections)
        if _HEAD_CLOSE_RX.search(text):
            text = _HEAD_CLOSE_RX.sub(lambda m: snippet + m.group(1), text, count=1)
        elif _HEAD_OPEN_RX.search(text):
            text = _HEAD_OPEN_RX.sub(lambda m: m.group(1) + snippet, text, count=1)
        else:
            text = snippet + text

    return text.encode(charset, errors='surrogateescape')
