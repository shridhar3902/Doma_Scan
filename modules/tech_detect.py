"""Technology detection from HTTP headers and HTML content."""

from __future__ import annotations

from typing import Dict, List

import requests

from utils.http import get_text
from utils.output import verbose_print

# ── Signature tables ──────────────────────────────────────────────────────────

# (marker_in_html_lowercase, label)
_CMS_SIGNATURES = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("drupal.js", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("joomla", "Joomla"),
    ("cdn.shopify.com", "Shopify"),
    ("squarespace", "Squarespace"),
    ("wix.com", "Wix"),
    ("ghost.io", "Ghost"),
    ("ghost-url", "Ghost"),
)

_JS_SIGNATURES = (
    ("react", "React"),
    ("reactdom", "React"),
    ("_react", "React"),
    ("ng-", "Angular"),
    ("angular", "Angular"),
    ("vue", "Vue.js"),
    ("__next", "Next.js"),
    ("_next/", "Next.js"),
    ("__nuxt", "Nuxt.js"),
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
)

_ANALYTICS_SIGNATURES = (
    ("google-analytics.com", "Google Analytics"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("gtag(", "Google Analytics"),
    ("fbq(", "Facebook Pixel"),
    ("facebook.net/en_US/fbevents", "Facebook Pixel"),
    ("hotjar.com", "Hotjar"),
    ("static.hotjar.com", "Hotjar"),
)

_SECURITY_HEADERS = (
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Permissions-Policy",
)

_LANGUAGE_HEADERS = (
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
    ("python", "Python"),
    ("ruby", "Ruby"),
    ("express", "Node.js"),
)

_SERVER_NAMES = (
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("iis", "IIS"),
    ("litespeed", "LiteSpeed"),
    ("caddy", "Caddy"),
    ("cloudflare", "Cloudflare"),
    ("openresty", "OpenResty"),
)


def _unique(items: List[str]) -> List[str]:
    """Deduplicate while preserving order."""
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def detect_technologies(domain: str, verbose: bool = False) -> Dict[str, object]:
    """Detect technologies used by *domain* via HTTP headers + HTML content.

    Returns
    -------
    dict
        ``technologies``  – categorised dict of detected tech.
        ``subdomains``, ``emails``, ``warnings`` – standard module keys.
    """
    warnings: List[str] = []
    web_server: List[str] = []
    cms: List[str] = []
    js_frameworks: List[str] = []
    cdn: List[str] = []
    security_headers: List[str] = []
    analytics: List[str] = []
    language: List[str] = []

    headers: dict = {}
    html_lower: str = ""

    # ── Fetch headers via HEAD request ────────────────────────────────────
    url = f"https://{domain}"
    try:
        verbose_print(verbose, f"HEAD request to {url}")
        resp = requests.head(
            url,
            headers={"User-Agent": "DomaScan/2.0"},
            timeout=8,
            allow_redirects=True,
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        verbose_print(verbose, f"Response headers: {list(headers.keys())}")
    except requests.RequestException as exc:
        verbose_print(verbose, f"HEAD request failed: {exc}")
        # Try HTTP fallback
        try:
            resp = requests.head(
                f"http://{domain}",
                headers={"User-Agent": "DomaScan/2.0"},
                timeout=8,
                allow_redirects=True,
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except requests.RequestException:
            warnings.append("Could not retrieve HTTP headers")

    # ── Fetch HTML body ───────────────────────────────────────────────────
    html = get_text(url, verbose=verbose)
    if html is None:
        html = get_text(f"http://{domain}", verbose=verbose)
    if html is None:
        warnings.append("Could not fetch homepage HTML")
    else:
        html_lower = html.lower()

    # ── Web Server ────────────────────────────────────────────────────────
    server_header = headers.get("server", "").lower()
    if server_header:
        for marker, name in _SERVER_NAMES:
            if marker in server_header:
                web_server.append(name)

    # ── CDN / Proxy ───────────────────────────────────────────────────────
    if "cf-ray" in headers:
        cdn.append("Cloudflare")
    if headers.get("x-cdn", "").lower() == "akamai" or "akamai" in headers.get("server", "").lower():
        cdn.append("Akamai")
    if "x-fastly-request-id" in headers or "fastly" in headers.get("via", "").lower():
        cdn.append("Fastly")
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower():
        cdn.append("AWS CloudFront")
    if "x-served-by" in headers and "cache" in headers.get("x-served-by", "").lower():
        cdn.append("Varnish/CDN Cache")

    # ── Programming Language ──────────────────────────────────────────────
    powered_by = headers.get("x-powered-by", "").lower()
    for marker, name in _LANGUAGE_HEADERS:
        if marker in powered_by:
            language.append(name)
    if "x-aspnet-version" in headers:
        language.append("ASP.NET")

    # ── Security Headers ──────────────────────────────────────────────────
    for hdr in _SECURITY_HEADERS:
        if hdr.lower() in headers:
            security_headers.append(hdr)

    # ── HTML-based detection ──────────────────────────────────────────────
    if html_lower:
        for marker, name in _CMS_SIGNATURES:
            if marker in html_lower:
                cms.append(name)
                verbose_print(verbose, f"CMS detected: {name} (marker: {marker})")

        for marker, name in _JS_SIGNATURES:
            if marker in html_lower:
                js_frameworks.append(name)

        for marker, name in _ANALYTICS_SIGNATURES:
            if marker in html_lower:
                analytics.append(name)

    technologies = {
        "web_server": _unique(web_server),
        "cms": _unique(cms),
        "js_frameworks": _unique(js_frameworks),
        "cdn": _unique(cdn),
        "security_headers": _unique(security_headers),
        "analytics": _unique(analytics),
        "language": _unique(language),
    }

    verbose_print(verbose, f"Technology scan complete for {domain}")
    return {
        "technologies": technologies,
        "subdomains": [],
        "emails": [],
        "warnings": warnings,
    }
