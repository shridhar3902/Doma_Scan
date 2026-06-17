"""BFS web crawler with robots.txt parsing, JS scanning, and subdomain extraction."""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.cleaner import extract_emails, normalize_subdomains
from utils.http import get_text
from utils.output import verbose_print

MAX_PAGES = 50


def _normalize_url(url: str) -> str:
    """Ensure *url* has a scheme."""
    parsed = urlparse(url)
    if parsed.scheme:
        return url
    return f"https://{url}"


def _extract_internal_links(base_url: str, html: str, domain: str) -> Set[str]:
    """Return absolute URLs that belong to *domain* found in *html*."""
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()
    for anchor in soup.find_all("a", href=True):
        candidate = urljoin(base_url, anchor["href"])
        parsed = urlparse(candidate)
        if parsed.netloc.endswith(domain) and parsed.scheme in ("http", "https"):
            # Strip fragments
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            links.add(clean)
    return links


def _extract_js_urls(base_url: str, html: str) -> Set[str]:
    """Extract JavaScript file URLs from <script src='…'> tags."""
    soup = BeautifulSoup(html, "html.parser")
    urls: Set[str] = set()
    for script in soup.find_all("script", src=True):
        src = script["src"]
        absolute = urljoin(base_url, src)
        if absolute.endswith((".js", ".mjs", ".jsx")):
            urls.add(absolute)
        elif "/js/" in absolute or "javascript" in absolute.lower():
            urls.add(absolute)
        else:
            # Include any script src that looks like a full URL
            urls.add(absolute)
    return urls


def _extract_subdomains_from_text(text: str, domain: str) -> Set[str]:
    """Find hostnames matching *.domain in raw text using regex."""
    pattern = re.compile(
        r"[a-zA-Z0-9][-a-zA-Z0-9]*\." + re.escape(domain), re.IGNORECASE
    )
    matches = pattern.findall(text)
    return normalize_subdomains(matches, domain)


def _parse_robots_txt(robots_text: str, base_url: str) -> Set[str]:
    """Extract interesting paths and Sitemap URLs from robots.txt content."""
    urls: Set[str] = set()
    for line in robots_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        lower = line.lower()
        if lower.startswith(("disallow:", "allow:")):
            _, _, path = line.partition(":")
            path = path.strip()
            if path and path != "/" and not path.startswith("*"):
                urls.add(urljoin(base_url, path))
        elif lower.startswith("sitemap:"):
            _, _, sitemap_url = line.partition(":")
            sitemap_url = sitemap_url.strip()
            # 'Sitemap:' value is a full URL, but the partition eats the first ':'
            # Reconstruct for http/https
            if sitemap_url.startswith("//"):
                sitemap_url = "https:" + sitemap_url
            elif not sitemap_url.startswith("http"):
                # The partition split on the first ':', so for "Sitemap: https://..."
                # we got "//..." — need to re-join
                pass
            urls.add(sitemap_url.strip())

    return urls


def crawl_domain(
    domain: str, verbose: bool = False, depth: int = 2
) -> Dict[str, List[str]]:
    """BFS-crawl *domain* up to *depth* levels, extracting subdomains and emails.

    Features:
        - robots.txt path & Sitemap discovery
        - JavaScript file content scanning for subdomains
        - Subdomain regex extraction from page HTML
        - BFS with depth limiting and a 50-page cap

    Returns
    -------
    dict
        ``subdomains`` – sorted list of discovered subdomains.
        ``emails``     – sorted list of discovered email addresses.
        ``warnings``   – list of warning strings.
    """
    warnings: List[str] = []
    collected_emails: Set[str] = set()
    collected_subdomains: Set[str] = set()
    visited: Set[str] = set()
    js_visited: Set[str] = set()
    pages_crawled = 0

    homepage = _normalize_url(domain)

    # ── robots.txt ────────────────────────────────────────────────────────
    robots_urls: Set[str] = set()
    robots_text = get_text(f"https://{domain}/robots.txt", verbose=verbose)
    if robots_text is None:
        robots_text = get_text(f"http://{domain}/robots.txt", verbose=verbose)

    if robots_text:
        verbose_print(verbose, "Parsing robots.txt")
        robots_urls = _parse_robots_txt(robots_text, homepage)
        verbose_print(verbose, f"robots.txt yielded {len(robots_urls)} paths")
        # Also scan robots.txt itself for subdomains
        collected_subdomains.update(_extract_subdomains_from_text(robots_text, domain))
    else:
        verbose_print(verbose, "robots.txt not found or inaccessible")

    # ── BFS setup ─────────────────────────────────────────────────────────
    queue: deque[tuple[str, int]] = deque()
    queue.append((homepage, 0))

    # Seed with robots.txt paths
    for rurl in robots_urls:
        parsed = urlparse(rurl)
        if parsed.netloc.endswith(domain) or not parsed.netloc:
            queue.append((rurl, 1))

    # ── BFS loop ──────────────────────────────────────────────────────────
    while queue and pages_crawled < MAX_PAGES:
        current_url, current_depth = queue.popleft()

        if current_url in visited:
            continue
        visited.add(current_url)

        verbose_print(
            verbose,
            f"Crawling [{pages_crawled + 1}/{MAX_PAGES}] depth={current_depth}: {current_url}",
        )

        html = get_text(current_url, verbose=verbose)
        if html is None:
            # Try www. fallback only for the homepage
            if pages_crawled == 0:
                fallback = _normalize_url(f"www.{domain}")
                html = get_text(fallback, verbose=verbose)
                if html:
                    homepage = fallback
                    current_url = fallback
            if html is None:
                continue

        pages_crawled += 1

        # ── Extract emails ────────────────────────────────────────────────
        collected_emails.update(extract_emails(html, domain))

        # ── Extract subdomains from HTML ──────────────────────────────────
        collected_subdomains.update(_extract_subdomains_from_text(html, domain))

        # ── Extract internal links ────────────────────────────────────────
        if current_depth < depth:
            internal_links = _extract_internal_links(current_url, html, domain)
            for link in internal_links:
                if link not in visited:
                    queue.append((link, current_depth + 1))

        # ── Scan JavaScript files ─────────────────────────────────────────
        js_urls = _extract_js_urls(current_url, html)
        for js_url in js_urls:
            if js_url in js_visited:
                continue
            js_visited.add(js_url)

            js_content = get_text(js_url, verbose=verbose)
            if js_content:
                # Subdomains in JS
                collected_subdomains.update(
                    _extract_subdomains_from_text(js_content, domain)
                )
                # Emails in JS (less common but possible)
                collected_emails.update(extract_emails(js_content, domain))

    verbose_print(
        verbose,
        f"Crawl complete: {pages_crawled} pages, {len(collected_subdomains)} subdomains, {len(collected_emails)} emails",
    )

    if pages_crawled == 0:
        warnings.append("Web crawler could not fetch any pages")
    elif pages_crawled >= MAX_PAGES:
        warnings.append(f"Crawl stopped at {MAX_PAGES}-page limit")

    return {
        "subdomains": sorted(collected_subdomains),
        "emails": sorted(collected_emails),
        "warnings": warnings,
    }
