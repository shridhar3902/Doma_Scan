"""Lightweight TCP port scanner using threaded socket connections."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from utils.output import verbose_print

COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
}


def _scan_single_port(
    ip: str, port: int, service: str, timeout: float
) -> Tuple[int, str, bool]:
    """Attempt a TCP connect to *ip*:*port* and return (port, service, is_open)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return (port, service, result == 0)
    except (socket.error, OSError):
        return (port, service, False)


def scan_ports(
    domain: str, verbose: bool = False, timeout: float = 1.5
) -> Dict[str, object]:
    """Scan common TCP ports on *domain* and return results.

    Returns
    -------
    dict
        ``open_ports``   – list of dicts with port, service, state.
        ``target_ip``    – resolved IP address string.
        ``subdomains``, ``emails``, ``warnings`` – standard module keys.
    """
    warnings: List[str] = []
    open_ports: List[Dict[str, object]] = []
    target_ip: str = ""

    # ── Resolve domain ────────────────────────────────────────────────────
    try:
        target_ip = socket.gethostbyname(domain)
        verbose_print(verbose, f"Resolved {domain} -> {target_ip}")
    except socket.gaierror as exc:
        warnings.append(f"Could not resolve domain {domain}: {exc}")
        verbose_print(verbose, f"DNS resolution failed for {domain}: {exc}")
        return {
            "open_ports": [],
            "target_ip": "",
            "subdomains": [],
            "emails": [],
            "warnings": warnings,
        }

    # ── Threaded scan ─────────────────────────────────────────────────────
    verbose_print(verbose, f"Starting port scan on {target_ip} ({len(COMMON_PORTS)} ports)")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_scan_single_port, target_ip, port, svc, timeout): port
            for port, svc in COMMON_PORTS.items()
        }

        for future in as_completed(futures):
            try:
                port, service, is_open = future.result()
                if is_open:
                    open_ports.append(
                        {"port": port, "service": service, "state": "open"}
                    )
                    verbose_print(verbose, f"Port {port}/{service} is OPEN")
                else:
                    verbose_print(verbose, f"Port {port}/{service} is closed")
            except Exception as exc:
                port_num = futures[future]
                warnings.append(f"Error scanning port {port_num}: {exc}")

    # Sort by port number for consistent output
    open_ports.sort(key=lambda p: p["port"])

    verbose_print(
        verbose,
        f"Port scan complete: {len(open_ports)} open ports found on {target_ip}",
    )

    return {
        "open_ports": open_ports,
        "target_ip": target_ip,
        "subdomains": [],
        "emails": [],
        "warnings": warnings,
    }
