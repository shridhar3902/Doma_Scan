"""DuckDuckGo HTML search scraping for public OSINT enrichment."""

from __future__ import annotations

import re
from typing import Dict, List, Set
from urllib.parse import quote_plus, urlparse

from bs4 import BeautifulSoup

from utils.cleaner import extract_emails, normalize_subdomains
from utils.http import get_text
from utils.output import verbose_print

DOMAIN_RE_TEMPLATE = r"(?:[a-zA-Z0-9-]+\.)+{domain}"


def search_duckduckgo(domain: str, verbose: bool = False) -> Dict[str, List[str]]:
    warnings: List[str] = []
    query = quote_plus(f"site:{domain}")
    url = f"https://html.duckduckgo.com/html/?q={query}"
    html = get_text(url, verbose=verbose)

    if html is None:
        warnings.append("DuckDuckGo search failed after retries")
        return {"subdomains": [], "emails": [], "warnings": warnings}

    soup = BeautifulSoup(html, "html.parser")
    possible_subdomains: Set[str] = set()
    possible_emails: Set[str] = set(extract_emails(html, domain))

    domain_regex = re.compile(DOMAIN_RE_TEMPLATE.format(domain=re.escape(domain)), re.IGNORECASE)
    for match in domain_regex.findall(html):
        possible_subdomains.add(match)

    for anchor in soup.find_all("a", href=True):
        parsed = urlparse(anchor["href"])
        host = parsed.netloc.lower().strip()
        if host.endswith(domain):
            possible_subdomains.add(host)
        text = anchor.get_text(" ", strip=True)
        possible_emails.update(extract_emails(text, domain))

    cleaned = sorted(normalize_subdomains(possible_subdomains, domain))
    verbose_print(
        verbose,
        f"DuckDuckGo yielded {len(cleaned)} subdomains and {len(possible_emails)} emails",
    )
    return {
        "subdomains": cleaned,
        "emails": sorted(possible_emails),
        "warnings": warnings,
    }
