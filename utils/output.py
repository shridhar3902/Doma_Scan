"""CLI output helpers with Rich-powered formatting and ASCII art banner."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from colorama import Fore, Style

# ---------------------------------------------------------------------------
# Console (Rich)
# ---------------------------------------------------------------------------
console = Console(highlight=False) if HAS_RICH else None

VERSION = "2.0.0"
AUTHOR = "Shridhar Kirtane"

BANNER_ART = rf"""{Fore.CYAN}
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║██║   ██║██╔████╔██║███████║███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}"""

TAGLINE = "Domain Intelligence. Reimagined."


def verbose_print(verbose: bool, message: str) -> None:
    """Print debug message when verbose mode is active."""
    if verbose:
        print(f"{Fore.CYAN}  [DEBUG]{Style.RESET_ALL} {message}")


def print_banner(target: str) -> None:
    """Print the stylish DomaScan banner with target info."""
    print(BANNER_ART)
    print(f"  {Fore.WHITE}{Style.BRIGHT}{TAGLINE}{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}v{VERSION}{Style.RESET_ALL} | {Fore.MAGENTA}Developed by {AUTHOR}{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}https://github.com/shridhar3902/DomaScan{Style.RESET_ALL}")
    print()
    print(f"  {Fore.GREEN}{'━' * 62}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[TARGET]{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}{target}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}{'━' * 62}{Style.RESET_ALL}")
    print()


def print_module_warning(module_name: str, message: str) -> None:
    """Print a module-specific warning."""
    print(f"  {Fore.YELLOW}[⚠ {module_name.upper()}]{Style.RESET_ALL} {message}")


def print_module_start(module_name: str) -> None:
    """Print when a module starts execution."""
    print(f"  {Fore.BLUE}[▸]{Style.RESET_ALL} Running {Fore.CYAN}{module_name}{Style.RESET_ALL} module...")


def print_module_done(module_name: str) -> None:
    """Print when a module completes."""
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {Fore.CYAN}{module_name}{Style.RESET_ALL} complete")


# ---------------------------------------------------------------------------
# Rich-powered result printing
# ---------------------------------------------------------------------------

def _print_section_header(title: str, icon: str = "►") -> None:
    print()
    print(f"  {Fore.GREEN}{icon} {title}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}{'─' * 58}{Style.RESET_ALL}")


def print_results(
    target: str,
    subdomains: Dict[str, bool],
    emails: Iterable[str],
    dns_records: Dict[str, List[str]],
    warnings: List[str],
    status: str,
    whois_data: Optional[Dict[str, Any]] = None,
    technologies: Optional[Dict[str, List[str]]] = None,
    open_ports: Optional[List[Dict[str, Any]]] = None,
    wayback_data: Optional[Dict[str, Any]] = None,
    ssl_info: Optional[Dict[str, Any]] = None,
    scan_duration: float = 0.0,
    target_ip: Optional[str] = None,
) -> None:
    """Print all scan results with colored, formatted output."""
    email_list = list(emails)

    if HAS_RICH and console:
        _print_results_rich(
            target, subdomains, email_list, dns_records, warnings, status,
            whois_data, technologies, open_ports, wayback_data, ssl_info,
            scan_duration, target_ip,
        )
    else:
        _print_results_basic(
            target, subdomains, email_list, dns_records, warnings, status,
            whois_data, technologies, open_ports, wayback_data, ssl_info,
            scan_duration, target_ip,
        )


def _print_results_rich(
    target: str,
    subdomains: Dict[str, bool],
    emails: List[str],
    dns_records: Dict[str, List[str]],
    warnings: List[str],
    status: str,
    whois_data: Optional[Dict[str, Any]],
    technologies: Optional[Dict[str, List[str]]],
    open_ports: Optional[List[Dict[str, Any]]],
    wayback_data: Optional[Dict[str, Any]],
    ssl_info: Optional[Dict[str, Any]],
    scan_duration: float,
    target_ip: Optional[str],
) -> None:
    """Rich-powered pretty output with tables and panels."""
    assert console is not None

    # --- Subdomains Table ---
    if subdomains:
        sub_table = Table(
            title="🌐 Subdomains", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
            show_lines=False, padding=(0, 1),
        )
        sub_table.add_column("Subdomain", style="white", min_width=35)
        sub_table.add_column("Status", justify="center", min_width=10)
        for sub, valid in sorted(subdomains.items()):
            style = "bold green" if valid else "bold red"
            label = "✓ VALID" if valid else "✗ INVALID"
            sub_table.add_row(sub, Text(label, style=style))
        console.print()
        console.print(sub_table)
    else:
        console.print("\n  [dim italic]No subdomains discovered.[/]")

    # --- Emails ---
    if emails:
        email_table = Table(
            title="📧 Emails", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        email_table.add_column("Email Address", style="white")
        for email in emails:
            email_table.add_row(email)
        console.print()
        console.print(email_table)

    # --- DNS Records ---
    dns_count = sum(len(v) for v in dns_records.values())
    if dns_count > 0:
        dns_table = Table(
            title="📡 DNS Records", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        dns_table.add_column("Type", style="bold yellow", min_width=8)
        dns_table.add_column("Value", style="white")
        for rtype in sorted(dns_records.keys()):
            values = dns_records[rtype]
            for val in values:
                dns_table.add_row(rtype, str(val))
        console.print()
        console.print(dns_table)

    # --- WHOIS ---
    if whois_data:
        whois_table = Table(
            title="📋 WHOIS Information", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        whois_table.add_column("Field", style="bold yellow", min_width=20)
        whois_table.add_column("Value", style="white")
        for key, val in whois_data.items():
            if val and str(val).strip():
                whois_table.add_row(key.replace("_", " ").title(), str(val))
        console.print()
        console.print(whois_table)

    # --- Technologies ---
    if technologies:
        has_items = any(v for v in technologies.values())
        if has_items:
            tech_table = Table(
                title="🛠️  Technologies Detected", box=box.ROUNDED,
                title_style="bold cyan", border_style="dim",
            )
            tech_table.add_column("Category", style="bold yellow", min_width=20)
            tech_table.add_column("Detected", style="white")
            for cat, items in technologies.items():
                if items:
                    tech_table.add_row(
                        cat.replace("_", " ").title(),
                        ", ".join(items),
                    )
            console.print()
            console.print(tech_table)

    # --- Open Ports ---
    if open_ports:
        port_table = Table(
            title="🔌 Open Ports", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        port_table.add_column("Port", style="bold white", justify="right")
        port_table.add_column("Service", style="white")
        port_table.add_column("State", style="bold green", justify="center")
        if target_ip:
            console.print(f"\n  [dim]Target IP: [bold white]{target_ip}[/][/]")
        for p in sorted(open_ports, key=lambda x: x.get("port", 0)):
            port_table.add_row(str(p.get("port", "")), p.get("service", ""), "OPEN")
        console.print()
        console.print(port_table)

    # --- SSL Info ---
    if ssl_info:
        grade = ssl_info.get("grade", "?")
        grade_colors = {"A": "bold green", "B": "bold yellow", "C": "bold yellow", "F": "bold red"}
        grade_style = grade_colors.get(grade, "bold white")

        ssl_table = Table(
            title="🔒 SSL/TLS Certificate", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        ssl_table.add_column("Field", style="bold yellow", min_width=22)
        ssl_table.add_column("Value", style="white")
        ssl_table.add_row("Grade", Text(grade, style=grade_style))
        display_keys = ["issuer", "subject", "not_before", "not_after", "days_until_expiry", "serial_number", "signature_algorithm"]
        for key in display_keys:
            val = ssl_info.get(key)
            if val is not None:
                ssl_table.add_row(key.replace("_", " ").title(), str(val))
        console.print()
        console.print(ssl_table)

    # --- Wayback ---
    if wayback_data:
        wb_table = Table(
            title="🕰️  Wayback Machine", box=box.ROUNDED,
            title_style="bold cyan", border_style="dim",
        )
        wb_table.add_column("Metric", style="bold yellow", min_width=25)
        wb_table.add_column("Value", style="white")
        for key in ("total_urls", "unique_subdomains_count", "first_seen", "last_seen"):
            val = wayback_data.get(key)
            if val is not None:
                wb_table.add_row(key.replace("_", " ").title(), str(val))
        console.print()
        console.print(wb_table)

    # --- Warnings ---
    if warnings:
        console.print()
        for w in warnings:
            console.print(f"  [yellow]⚠ {w}[/]")

    # --- Summary Panel ---
    valid = sum(1 for v in subdomains.values() if v)
    status_color = "green" if status == "SUCCESS" else "yellow"
    summary = (
        f"[bold white]{len(subdomains)}[/] subdomains ([green]{valid} valid[/]) · "
        f"[bold white]{len(emails)}[/] emails · "
        f"[bold white]{dns_count}[/] DNS records"
    )
    if open_ports:
        summary += f" · [bold white]{len(open_ports)}[/] open ports"
    summary += f"\n[dim]Scan completed in [bold]{scan_duration:.2f}s[/] · Status: [{status_color}]{status}[/][/]"

    console.print()
    console.print(Panel(summary, title="[bold]Scan Summary[/]", border_style="green", padding=(0, 2)))
    console.print()


def _print_results_basic(
    target: str,
    subdomains: Dict[str, bool],
    emails: List[str],
    dns_records: Dict[str, List[str]],
    warnings: List[str],
    status: str,
    whois_data: Optional[Dict[str, Any]],
    technologies: Optional[Dict[str, List[str]]],
    open_ports: Optional[List[Dict[str, Any]]],
    wayback_data: Optional[Dict[str, Any]],
    ssl_info: Optional[Dict[str, Any]],
    scan_duration: float,
    target_ip: Optional[str],
) -> None:
    """Fallback plain-colored output when Rich is not installed."""
    _print_section_header("SUBDOMAINS", "🌐")
    if subdomains:
        for sub, valid in sorted(subdomains.items()):
            marker_color = Fore.GREEN if valid else Fore.RED
            marker = "[VALID]" if valid else "[INVALID]"
            print(f"    {sub:<40} {marker_color}{marker}{Style.RESET_ALL}")
    else:
        print(f"    {Fore.YELLOW}No subdomains found{Style.RESET_ALL}")

    _print_section_header("EMAILS", "📧")
    if emails:
        for email in emails:
            print(f"    {email}")
    else:
        print(f"    {Fore.YELLOW}No emails found{Style.RESET_ALL}")

    _print_section_header("DNS RECORDS", "📡")
    for rtype in sorted(dns_records.keys()):
        values = dns_records[rtype]
        for val in values:
            print(f"    {Fore.YELLOW}{rtype:<8}{Style.RESET_ALL} {val}")

    if whois_data:
        _print_section_header("WHOIS", "📋")
        for k, v in whois_data.items():
            if v and str(v).strip():
                print(f"    {k.replace('_', ' ').title():<25} {v}")

    if technologies:
        has = any(v for v in technologies.values())
        if has:
            _print_section_header("TECHNOLOGIES", "🛠️")
            for cat, items in technologies.items():
                if items:
                    print(f"    {cat.replace('_', ' ').title():<25} {', '.join(items)}")

    if open_ports:
        _print_section_header("OPEN PORTS", "🔌")
        if target_ip:
            print(f"    Target IP: {target_ip}")
        for p in sorted(open_ports, key=lambda x: x.get("port", 0)):
            print(f"    {p.get('port', ''):<8} {p.get('service', ''):<15} {Fore.GREEN}OPEN{Style.RESET_ALL}")

    if ssl_info:
        _print_section_header("SSL/TLS", "🔒")
        grade = ssl_info.get("grade", "?")
        grade_color = {
            "A": Fore.GREEN, "B": Fore.YELLOW, "C": Fore.YELLOW, "F": Fore.RED
        }.get(grade, Fore.WHITE)
        print(f"    Grade: {grade_color}{Style.BRIGHT}{grade}{Style.RESET_ALL}")
        for key in ["issuer", "subject", "not_before", "not_after", "days_until_expiry"]:
            val = ssl_info.get(key)
            if val is not None:
                print(f"    {key.replace('_', ' ').title():<25} {val}")

    if wayback_data:
        _print_section_header("WAYBACK MACHINE", "🕰️")
        for key in ("total_urls", "unique_subdomains_count", "first_seen", "last_seen"):
            val = wayback_data.get(key)
            if val is not None:
                print(f"    {key.replace('_', ' ').title():<25} {val}")

    if warnings:
        _print_section_header("WARNINGS", "⚠️")
        for w in warnings:
            print(f"    {Fore.YELLOW}{w}{Style.RESET_ALL}")

    # Summary
    valid = sum(1 for v in subdomains.values() if v)
    dns_count = sum(len(v) for v in dns_records.values())
    print()
    print(f"  {Fore.GREEN}{'━' * 62}{Style.RESET_ALL}")
    status_color = Fore.GREEN if status == "SUCCESS" else Fore.YELLOW
    print(
        f"  {Fore.WHITE}{Style.BRIGHT}SUMMARY{Style.RESET_ALL}  "
        f"{len(subdomains)} subdomains ({valid} valid) · "
        f"{len(emails)} emails · {dns_count} DNS records"
    )
    print(
        f"  {Fore.WHITE}Completed in {scan_duration:.2f}s{Style.RESET_ALL} · "
        f"Status: {status_color}{status}{Style.RESET_ALL}"
    )
    print(f"  {Fore.GREEN}{'━' * 62}{Style.RESET_ALL}")
    print()


# ---------------------------------------------------------------------------
# File saving (plain text - legacy)
# ---------------------------------------------------------------------------

def _format_results(
    target: str,
    subdomains: Dict[str, bool],
    emails: Iterable[str],
    dns_records: Dict[str, List[str]],
    warnings: List[str],
    status: str,
) -> str:
    """Format results as plain text for file output."""
    lines = [
        f"DomaScan v{VERSION} — Domain Intelligence Report",
        f"Developed by {AUTHOR}",
        "=" * 60,
        f"Target: {target}",
        "",
    ]

    lines.append("[+] Subdomains:")
    if subdomains:
        for subdomain, is_valid in sorted(subdomains.items()):
            marker = "[VALID]" if is_valid else "[INVALID]"
            lines.append(f"  {subdomain:<40} {marker}")
    else:
        lines.append("  No subdomains found")

    lines.append("")
    lines.append("[+] Emails:")
    email_list = list(emails)
    if email_list:
        for email in email_list:
            lines.append(f"  {email}")
    else:
        lines.append("  No emails found")

    lines.append("")
    lines.append("[+] DNS Info:")
    for record_type in sorted(dns_records.keys()):
        values = dns_records.get(record_type, [])
        if values:
            for value in values:
                lines.append(f"  {record_type}: {value}")
        else:
            lines.append(f"  {record_type}: None")

    if warnings:
        lines.append("")
        lines.append("[+] Warnings:")
        for w in warnings:
            lines.append(f"  {w}")

    lines.append("")
    lines.append("=" * 60)
    lines.append(
        f"[+] Counts: {len(subdomains)} subdomains, {len(email_list)} emails, "
        f"{sum(len(dns_records.get(item, [])) for item in dns_records)} DNS records"
    )
    lines.append(f"[+] Status: {status}")
    return "\n".join(lines)


def save_results(
    output_path: str,
    target: str,
    subdomains: Dict[str, bool],
    emails: Iterable[str],
    dns_records: Dict[str, List[str]],
    warnings: List[str],
    status: str,
) -> None:
    """Save results to a plain text file."""
    formatted = _format_results(target, subdomains, emails, dns_records, warnings, status)
    with open(output_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(formatted + "\n")
    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} Results saved to {Fore.WHITE}{output_path}{Style.RESET_ALL}")
