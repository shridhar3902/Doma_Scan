"""SSL/TLS certificate analysis and SAN-based subdomain extraction."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List

from utils.cleaner import normalize_subdomains
from utils.output import verbose_print


def _parse_x509_name(name_tuples: tuple) -> Dict[str, str]:
    """Flatten the nested tuple structure from cert issuer/subject into a dict."""
    result: Dict[str, str] = {}
    for rdn in name_tuples:
        for attr_type, attr_value in rdn:
            result[attr_type] = attr_value
    return result


def _cert_date(date_str: str | None) -> datetime | None:
    """Parse a certificate date string into a datetime object."""
    if date_str is None:
        return None
    # Python's ssl module uses the format: 'Mon DD HH:MM:SS YYYY GMT'
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None


def analyze_ssl(
    domain: str, verbose: bool = False, port: int = 443
) -> Dict[str, object]:
    """Retrieve and analyse the SSL/TLS certificate for *domain*.

    Returns
    -------
    dict
        ``ssl_info``     – dict of certificate fields + grade + days_until_expiry.
        ``subdomains``   – SANs matching the target domain.
        ``emails``, ``warnings`` – standard module keys.
    """
    warnings: List[str] = []

    try:
        verbose_print(verbose, f"Connecting to {domain}:{port} for SSL analysis")

        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as conn:
                cert = conn.getpeercert()

        if not cert:
            warnings.append("Peer returned an empty certificate")
            return {
                "ssl_info": {},
                "subdomains": [],
                "emails": [],
                "warnings": warnings,
            }

        verbose_print(verbose, f"Certificate retrieved for {domain}")

    except ssl.SSLCertVerificationError as exc:
        # Try again without verification to still extract cert info
        verbose_print(verbose, f"SSL verification failed, retrying without verify: {exc}")
        warnings.append(f"SSL verification error: {exc}")
        try:
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=5) as raw_sock:
                with ctx_noverify.wrap_socket(raw_sock, server_hostname=domain) as conn:
                    cert = conn.getpeercert(binary_form=False)
            if not cert:
                # binary DER, can't parse fields easily — report failure
                return {
                    "ssl_info": {},
                    "subdomains": [],
                    "emails": [],
                    "warnings": warnings,
                }
        except Exception as inner_exc:
            warnings.append(f"SSL connection failed entirely: {inner_exc}")
            return {
                "ssl_info": {},
                "subdomains": [],
                "emails": [],
                "warnings": warnings,
            }

    except Exception as exc:
        warnings.append(f"SSL connection failed: {exc}")
        verbose_print(verbose, f"SSL error for {domain}: {exc}")
        return {
            "ssl_info": {},
            "subdomains": [],
            "emails": [],
            "warnings": warnings,
        }

    # ── Parse certificate fields ──────────────────────────────────────────
    issuer_dict = _parse_x509_name(cert.get("issuer", ()))
    subject_dict = _parse_x509_name(cert.get("subject", ()))

    issuer_cn = issuer_dict.get("commonName", "N/A")
    issuer_org = issuer_dict.get("organizationName", "N/A")
    subject_cn = subject_dict.get("commonName", "N/A")

    serial_number = cert.get("serialNumber", "N/A")
    version = cert.get("version", "N/A")

    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")
    not_before_dt = _cert_date(not_before_str)
    not_after_dt = _cert_date(not_after_str)

    # Friendly date strings
    not_before_friendly = not_before_dt.strftime("%Y-%m-%d") if not_before_dt else "N/A"
    not_after_friendly = not_after_dt.strftime("%Y-%m-%d") if not_after_dt else "N/A"

    # signature_algorithm is not exposed by getpeercert() — report N/A
    signature_algorithm = "N/A"

    # ── Subject Alternative Names ─────────────────────────────────────────
    san_entries = cert.get("subjectAltName", ())
    san_dns: List[str] = [
        value for san_type, value in san_entries if san_type == "DNS"
    ]

    verbose_print(verbose, f"SANs found: {len(san_dns)}")
    filtered_subs = sorted(normalize_subdomains(san_dns, domain))

    # ── Days until expiry & grading ───────────────────────────────────────
    now = datetime.now(timezone.utc)
    days_until_expiry: int | None = None
    if not_after_dt:
        days_until_expiry = (not_after_dt - now).days

    is_expired = days_until_expiry is not None and days_until_expiry < 0
    is_self_signed = issuer_cn == subject_cn and issuer_org == "N/A"
    expires_soon = days_until_expiry is not None and 0 <= days_until_expiry <= 30

    if is_expired:
        grade = "F"
    elif is_self_signed:
        grade = "C"
    elif expires_soon:
        grade = "B"
    else:
        grade = "A"

    verbose_print(verbose, f"SSL grade for {domain}: {grade} (expires in {days_until_expiry} days)")

    ssl_info: Dict[str, object] = {
        "issuer": f"{issuer_org} ({issuer_cn})" if issuer_org != "N/A" else issuer_cn,
        "subject": subject_cn,
        "serial_number": serial_number,
        "version": version,
        "not_before": not_before_friendly,
        "not_after": not_after_friendly,
        "signature_algorithm": signature_algorithm,
        "grade": grade,
        "days_until_expiry": days_until_expiry if days_until_expiry is not None else "N/A",
        "san_count": len(san_dns),
    }

    return {
        "ssl_info": ssl_info,
        "subdomains": filtered_subs,
        "emails": [],
        "warnings": warnings,
    }
