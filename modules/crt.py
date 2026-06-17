"""Certificate Transparency lookups via crt.sh."""

from __future__ import annotations

from typing import Dict, List

from utils.cleaner import normalize_subdomains
from utils.http import get_json
from utils.output import verbose_print


def fetch_crtsh_subdomains(domain: str, verbose: bool = False) -> Dict[str, List[str]]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    warnings: List[str] = []
    subdomains = set()

    response = get_json(url, verbose=verbose)
    if response is None:
        warnings.append("crt.sh request failed after retries")
        return {"subdomains": [], "emails": [], "warnings": warnings}

    for item in response:
        raw_value = item.get("name_value", "")
        for line in raw_value.splitlines():
            subdomain = line.strip()
            if subdomain:
                subdomains.add(subdomain)

    cleaned = sorted(normalize_subdomains(subdomains, domain))
    verbose_print(verbose, f"crt.sh yielded {len(cleaned)} normalized subdomains")
    return {"subdomains": cleaned, "emails": [], "warnings": warnings}
