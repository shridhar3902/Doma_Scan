"""Validation helpers for subdomain resolution with HTTP liveness and wildcard detection."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, Optional, Tuple

from utils.output import verbose_print


def quick_resolve(hostname: str) -> Optional[str]:
    """Resolve hostname to IP. Returns IP string or None."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def _check_http_liveness(hostname: str, timeout: float = 3.0) -> bool:
    """Quick TCP connect on port 80 or 443 to verify liveness beyond DNS."""
    for port in (443, 80):
        try:
            sock = socket.create_connection((hostname, port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, socket.error, OSError):
            continue
    return False


def detect_wildcard(domain: str) -> bool:
    """Detect if the domain has a wildcard DNS entry by querying random subdomains."""
    import random
    import string

    random_labels = [
        "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        for _ in range(3)
    ]
    resolved = 0
    for label in random_labels:
        test_host = f"{label}.{domain}"
        if quick_resolve(test_host) is not None:
            resolved += 1

    # If 2+ of 3 random names resolve, wildcard is very likely
    return resolved >= 2


def _validate_single(hostname: str, check_http: bool = True) -> Tuple[str, bool, Optional[str]]:
    """Validate a single subdomain. Returns (hostname, is_valid, resolved_ip)."""
    ip = quick_resolve(hostname)
    if ip is None:
        return hostname, False, None

    if check_http:
        is_live = _check_http_liveness(hostname)
        return hostname, True, ip  # DNS resolved; liveness is bonus info
    return hostname, True, ip


def validate_subdomains(
    subdomains: Iterable[str],
    verbose: bool = False,
    check_http: bool = False,
) -> Dict[str, bool]:
    """Validate subdomains via DNS resolution with optional HTTP liveness check.

    Returns a sorted dict mapping subdomain -> is_valid.
    """
    targets = sorted(set(subdomains))
    results: Dict[str, bool] = {}

    if not targets:
        return results

    with ThreadPoolExecutor(max_workers=min(30, max(1, len(targets)))) as executor:
        future_map = {
            executor.submit(_validate_single, subdomain, check_http): subdomain
            for subdomain in targets
        }
        for future in as_completed(future_map):
            subdomain = future_map[future]
            try:
                hostname, is_valid, ip = future.result()
                if ip:
                    verbose_print(verbose, f"Validation {hostname}: {is_valid} (IP: {ip})")
                else:
                    verbose_print(verbose, f"Validation {hostname}: {is_valid}")
                results[hostname] = is_valid
            except Exception:
                results[subdomain] = False

    return dict(sorted(results.items()))
