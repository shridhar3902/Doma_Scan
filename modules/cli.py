"""CLI orchestration for DomaScan v2.0."""

from __future__ import annotations

import argparse
import itertools
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from colorama import Fore, Style, init

from modules.crawler import crawl_domain
from modules.crt import fetch_crtsh_subdomains
from modules.dns_enum import enumerate_dns
from modules.duckduckgo import search_duckduckgo
from modules.port_scanner import scan_ports
from modules.ssl_info import analyze_ssl
from modules.tech_detect import detect_technologies
from modules.wayback import query_wayback
from modules.whois_lookup import lookup_whois
from utils.cleaner import clean_emails, normalize_subdomains
from utils.exporter import export_html, export_json
from utils.http import configure as configure_http
from utils.output import (
    print_banner,
    print_module_done,
    print_module_start,
    print_module_warning,
    print_results,
    save_results,
    verbose_print,
)
from utils.validator import detect_wildcard, validate_subdomains


VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScanResults:
    """Aggregated results from all scan modules."""
    target: str
    subdomains: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    validation_map: Dict[str, bool] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(
        default_factory=lambda: {"A": [], "MX": [], "NS": [], "AAAA": [], "TXT": [], "SOA": [], "CNAME": []}
    )
    warnings: List[str] = field(default_factory=list)
    status: str = "SUCCESS"
    # v2.0 additions
    whois_data: Optional[Dict[str, Any]] = None
    technologies: Optional[Dict[str, List[str]]] = None
    open_ports: Optional[List[Dict[str, Any]]] = None
    wayback_data: Optional[Dict[str, Any]] = None
    ssl_info: Optional[Dict[str, Any]] = None
    scan_duration: float = 0.0
    target_ip: Optional[str] = None
    is_wildcard: bool = False


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class Spinner:
    """Animated CLI spinner while background work executes."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, message: str = "Scanning") -> None:
        self.message = message
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + (" " * 80) + "\r")
        sys.stdout.flush()

    def update(self, message: str) -> None:
        self.message = message

    def _run(self) -> None:
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write(
                f"\r  {Fore.CYAN}{frame}{Style.RESET_ALL} {self.message}"
            )
            sys.stdout.flush()
            time.sleep(0.08)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domascan",
        description="DomaScan v2.0 — CLI-based OSINT Domain Intelligence Tool",
        epilog="Developed by Shridhar Kirtane | https://github.com/shridhar3902/DomaScan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")

    # Module selection
    modules_group = parser.add_argument_group("Module Selection")
    modules_group.add_argument("-a", "--all", action="store_true", help="Run all modules")
    modules_group.add_argument("-s", "--subdomains", action="store_true", help="Subdomain enumeration modules")
    modules_group.add_argument("-e", "--emails", action="store_true", help="Email extraction modules")
    modules_group.add_argument("-dns", "--dns", action="store_true", help="DNS enumeration")
    modules_group.add_argument("-w", "--whois", action="store_true", help="WHOIS lookup")
    modules_group.add_argument("-t", "--tech", action="store_true", help="Technology detection")
    modules_group.add_argument("-p", "--ports", action="store_true", help="Port scanning")
    modules_group.add_argument("--wayback", action="store_true", help="Wayback Machine history")
    modules_group.add_argument("--ssl", action="store_true", help="SSL/TLS certificate analysis")

    # Output
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Save results to text file")
    output_group.add_argument("--json", dest="json_output", help="Save results as JSON file")
    output_group.add_argument("--html", dest="html_output", help="Generate HTML report")

    # Tuning
    tuning_group = parser.add_argument_group("Tuning")
    tuning_group.add_argument("-v", "--verbose", action="store_true", help="Verbose debug output")
    tuning_group.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    tuning_group.add_argument("--threads", type=int, default=10, help="Max concurrent threads (default: 10)")
    tuning_group.add_argument("--depth", type=int, default=2, help="Crawler depth (default: 2)")
    tuning_group.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    tuning_group.add_argument("--rate-limit", type=float, default=0.0, help="Delay between requests in seconds")

    return parser


# ---------------------------------------------------------------------------
# Module selection
# ---------------------------------------------------------------------------

def parse_module_selection(args: argparse.Namespace) -> Dict[str, bool]:
    """Determine which modules to run based on CLI flags."""
    has_specific = any([
        args.subdomains, args.emails, args.dns, args.whois,
        args.tech, args.ports, args.wayback, args.ssl,
    ])

    if args.all or not has_specific:
        return {
            "crt": True, "dns": True, "crawler": True, "duckduckgo": True,
            "whois": True, "tech": True, "ports": True, "wayback": True, "ssl": True,
        }

    return {
        "crt": args.subdomains,
        "dns": args.subdomains or args.dns,
        "crawler": args.emails,
        "duckduckgo": args.subdomains or args.emails,
        "whois": args.whois,
        "tech": args.tech,
        "ports": args.ports,
        "wayback": args.wayback,
        "ssl": args.ssl,
    }


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------

def run_scan(
    domain: str,
    enabled_modules: Dict[str, bool],
    verbose: bool,
    threads: int = 10,
    depth: int = 2,
) -> ScanResults:
    """Execute all enabled modules and aggregate results."""
    results = ScanResults(target=domain)
    start_time = time.time()

    # Wildcard detection
    verbose_print(verbose, "Checking for wildcard DNS...")
    results.is_wildcard = detect_wildcard(domain)
    if results.is_wildcard:
        results.warnings.append(
            f"Wildcard DNS detected for {domain} — subdomain results may include false positives"
        )
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Wildcard DNS detected — results may include false positives")

    # Build job map
    module_jobs: Dict[str, Callable[[], dict]] = {}

    if enabled_modules.get("crt"):
        module_jobs["crt.sh"] = lambda: fetch_crtsh_subdomains(domain, verbose=verbose)
    if enabled_modules.get("dns"):
        module_jobs["DNS Enum"] = lambda: enumerate_dns(domain, verbose=verbose)
    if enabled_modules.get("crawler"):
        module_jobs["Crawler"] = lambda: crawl_domain(domain, verbose=verbose, depth=depth)
    if enabled_modules.get("duckduckgo"):
        module_jobs["DuckDuckGo"] = lambda: search_duckduckgo(domain, verbose=verbose)
    if enabled_modules.get("whois"):
        module_jobs["WHOIS"] = lambda: lookup_whois(domain, verbose=verbose)
    if enabled_modules.get("tech"):
        module_jobs["Tech Detect"] = lambda: detect_technologies(domain, verbose=verbose)
    if enabled_modules.get("ports"):
        module_jobs["Port Scan"] = lambda: scan_ports(domain, verbose=verbose)
    if enabled_modules.get("wayback"):
        module_jobs["Wayback"] = lambda: query_wayback(domain, verbose=verbose)
    if enabled_modules.get("ssl"):
        module_jobs["SSL/TLS"] = lambda: analyze_ssl(domain, verbose=verbose)

    if not module_jobs:
        results.status = "NO_MODULES"
        return results

    # Print active modules
    active = [name for name in module_jobs]
    print(f"  {Fore.BLUE}[◆]{Style.RESET_ALL} Active modules: {Fore.CYAN}{', '.join(active)}{Style.RESET_ALL}")
    print()

    spinner = Spinner("Running scan modules...")
    spinner.start()

    try:
        worker_count = min(threads, max(2, len(module_jobs)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(job): module_name
                for module_name, job in module_jobs.items()
            }

            completed = 0
            total = len(future_map)

            for future in as_completed(future_map):
                module_name = future_map[future]
                completed += 1
                spinner.update(f"Scanning... [{completed}/{total}] {module_name} done")

                try:
                    module_result = future.result()
                    verbose_print(verbose, f"{module_name} module completed")

                    # Aggregate subdomains & emails
                    results.subdomains.update(module_result.get("subdomains", []))
                    results.emails.update(module_result.get("emails", []))

                    # DNS records
                    if "dns_records" in module_result:
                        dns_info = module_result["dns_records"]
                        for key, values in dns_info.items():
                            existing = set(results.dns_records.get(key, []))
                            existing.update(values)
                            results.dns_records[key] = sorted(existing)

                    # WHOIS
                    if "whois_data" in module_result:
                        results.whois_data = module_result["whois_data"]

                    # Technologies
                    if "technologies" in module_result:
                        results.technologies = module_result["technologies"]

                    # Ports
                    if "open_ports" in module_result:
                        results.open_ports = module_result["open_ports"]
                        if "target_ip" in module_result:
                            results.target_ip = module_result["target_ip"]

                    # Wayback
                    if "wayback_data" in module_result:
                        results.wayback_data = module_result["wayback_data"]

                    # SSL
                    if "ssl_info" in module_result:
                        results.ssl_info = module_result["ssl_info"]

                    # Warnings
                    warnings = module_result.get("warnings", [])
                    if warnings:
                        results.warnings.extend(warnings)

                except Exception as exc:
                    warning = f"{module_name} module failed: {exc}"
                    results.warnings.append(warning)
                    print_module_warning(module_name, str(exc))

    finally:
        spinner.stop()

    # Post-processing
    results.subdomains = normalize_subdomains(results.subdomains, domain)
    results.emails = clean_emails(results.emails, domain)

    if results.subdomains:
        verbose_print(verbose, f"Validating {len(results.subdomains)} subdomains...")
        results.validation_map = validate_subdomains(results.subdomains, verbose=verbose)
        results.subdomains = set(results.validation_map.keys())

    if results.warnings:
        results.status = "PARTIAL"

    results.scan_duration = time.time() - start_time
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """DomaScan CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(errors="replace")
        except Exception:
            pass

    init(autoreset=True)
    parser = build_parser()
    args = parser.parse_args()
    args.domain = args.domain.lower().strip()

    # Configure HTTP layer
    configure_http(proxy=args.proxy, rate_limit=args.rate_limit)

    # Banner
    print_banner(args.domain)

    # Module selection
    enabled_modules = parse_module_selection(args)

    # Run scan
    results = run_scan(
        domain=args.domain,
        enabled_modules=enabled_modules,
        verbose=args.verbose,
        threads=args.threads,
        depth=args.depth,
    )

    # Print results
    print_results(
        target=results.target,
        subdomains=results.validation_map,
        emails=sorted(results.emails),
        dns_records=results.dns_records,
        warnings=results.warnings,
        status=results.status,
        whois_data=results.whois_data,
        technologies=results.technologies,
        open_ports=results.open_ports,
        wayback_data=results.wayback_data,
        ssl_info=results.ssl_info,
        scan_duration=results.scan_duration,
        target_ip=results.target_ip,
    )

    # --- Export ---
    export_kwargs = dict(
        target=results.target,
        subdomains=results.validation_map,
        emails=sorted(results.emails),
        dns_records=results.dns_records,
        warnings=results.warnings,
        status=results.status,
        whois_data=results.whois_data,
        technologies=results.technologies,
        open_ports=results.open_ports,
        wayback_data=results.wayback_data,
        ssl_info=results.ssl_info,
        scan_duration=results.scan_duration,
        target_ip=results.target_ip,
    )

    if args.output:
        save_results(
            output_path=args.output,
            target=results.target,
            subdomains=results.validation_map,
            emails=sorted(results.emails),
            dns_records=results.dns_records,
            warnings=results.warnings,
            status=results.status,
        )

    if args.json_output:
        export_json(args.json_output, **export_kwargs)
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} JSON report saved to {Fore.WHITE}{args.json_output}{Style.RESET_ALL}")

    if args.html_output:
        export_html(args.html_output, **export_kwargs)
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} HTML report saved to {Fore.WHITE}{args.html_output}{Style.RESET_ALL}")

    return 0
