"""WHOIS data extraction for domain intelligence."""

from __future__ import annotations

from typing import Any, Dict, List

import whois

from utils.output import verbose_print


def _safe_str(value: Any) -> str:
    """Return a string representation, handling lists and None."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return _safe_str(value[0]) if value else "N/A"
    return str(value)


def _safe_date(value: Any) -> str:
    """Extract a date string from a whois field that might be a list or datetime."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return _safe_date(value[0]) if value else "N/A"
    try:
        return value.strftime("%Y-%m-%d")
    except AttributeError:
        return str(value)


def _normalize_name_servers(ns: Any) -> List[str]:
    """Return a sorted list of lowercase name-server strings."""
    if ns is None:
        return []
    if isinstance(ns, str):
        return [ns.lower().rstrip(".")]
    try:
        return sorted({s.lower().rstrip(".") for s in ns if s})
    except TypeError:
        return [str(ns).lower()]


def lookup_whois(domain: str, verbose: bool = False) -> Dict[str, object]:
    """Query WHOIS data for *domain* and return a structured dict.

    Returns
    -------
    dict
        ``whois_data``  – dict of extracted WHOIS fields.
        ``warnings``    – list of warning strings.
    """
    warnings: List[str] = []

    try:
        verbose_print(verbose, f"Performing WHOIS lookup for {domain}")
        w = whois.whois(domain)

        if w is None or w.domain_name is None:
            warnings.append("WHOIS query returned no data (domain may not exist)")
            return {"whois_data": {}, "warnings": warnings}

        verbose_print(verbose, f"WHOIS data retrieved for {domain}")

        # Privacy-protected fields gracefully fall back to 'REDACTED'
        registrant_org = _safe_str(w.org) if hasattr(w, "org") else "N/A"
        if registrant_org.lower() in ("", "none"):
            registrant_org = "REDACTED"

        registrant_country = _safe_str(w.country) if hasattr(w, "country") else "N/A"
        if registrant_country.lower() in ("", "none"):
            registrant_country = "REDACTED"

        dnssec_value = _safe_str(w.dnssec) if hasattr(w, "dnssec") else "N/A"

        whois_data: Dict[str, object] = {
            "registrar": _safe_str(w.registrar),
            "creation_date": _safe_date(w.creation_date),
            "expiration_date": _safe_date(w.expiration_date),
            "name_servers": _normalize_name_servers(w.name_servers),
            "registrant_org": registrant_org,
            "registrant_country": registrant_country,
            "dnssec": dnssec_value,
        }

        verbose_print(verbose, f"WHOIS fields parsed: {list(whois_data.keys())}")
        return {"whois_data": whois_data, "warnings": warnings}

    except Exception as exc:
        warnings.append(f"WHOIS lookup failed: {exc}")
        verbose_print(verbose, f"WHOIS error for {domain}: {exc}")
        return {"whois_data": {}, "warnings": warnings}
