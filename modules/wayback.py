"""Wayback Machine CDX API integration for historical subdomain discovery."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

from utils.cleaner import normalize_subdomains
from utils.http import get_json
from utils.output import verbose_print


def _parse_timestamp(ts: str) -> str:
    """Convert a Wayback CDX timestamp (YYYYMMDDHHmmss) to YYYY-MM-DD."""
    if len(ts) >= 8:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


def query_wayback(domain: str, verbose: bool = False) -> Dict[str, object]:
    """Query the Wayback Machine CDX API for archived URLs of *domain*.

    Returns
    -------
    dict
        ``subdomains``    – unique subdomains extracted from archived URLs.
        ``wayback_data``  – summary dict (total_urls, first/last_seen, count).
        ``emails``, ``warnings`` – standard module keys.
    """
    warnings: List[str] = []

    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original,timestamp"
        f"&collapse=urlkey&limit=500"
    )

    verbose_print(verbose, f"Querying Wayback CDX API for {domain}")
    data = get_json(cdx_url, verbose=verbose)

    if data is None:
        warnings.append("Wayback Machine CDX API returned no data")
        return {
            "subdomains": [],
            "wayback_data": {
                "total_urls": 0,
                "first_seen": "N/A",
                "last_seen": "N/A",
                "unique_subdomains_count": 0,
            },
            "emails": [],
            "warnings": warnings,
        }

    # First row is the header ["original", "timestamp"] — skip it
    rows = data[1:] if len(data) > 1 else []

    if not rows:
        warnings.append("Wayback Machine returned results but no URL entries")
        return {
            "subdomains": [],
            "wayback_data": {
                "total_urls": 0,
                "first_seen": "N/A",
                "last_seen": "N/A",
                "unique_subdomains_count": 0,
            },
            "emails": [],
            "warnings": warnings,
        }

    verbose_print(verbose, f"Wayback returned {len(rows)} URL entries")

    # ── Extract subdomains from original URLs ─────────────────────────────
    raw_hosts: set[str] = set()
    timestamps: List[str] = []

    for row in rows:
        if len(row) < 2:
            continue
        original_url, timestamp = row[0], row[1]
        timestamps.append(timestamp)

        try:
            parsed = urlparse(original_url)
            host = parsed.netloc.lower().split(":")[0]  # strip port
            if host:
                raw_hosts.add(host)
        except Exception:
            continue

    subdomains = sorted(normalize_subdomains(raw_hosts, domain))
    verbose_print(verbose, f"Extracted {len(subdomains)} unique subdomains from Wayback")

    # ── Date range ────────────────────────────────────────────────────────
    timestamps.sort()
    first_seen = _parse_timestamp(timestamps[0]) if timestamps else "N/A"
    last_seen = _parse_timestamp(timestamps[-1]) if timestamps else "N/A"

    wayback_data = {
        "total_urls": len(rows),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "unique_subdomains_count": len(subdomains),
    }

    verbose_print(verbose, f"Wayback date range: {first_seen} — {last_seen}")

    return {
        "subdomains": subdomains,
        "wayback_data": wayback_data,
        "emails": [],
        "warnings": warnings,
    }
