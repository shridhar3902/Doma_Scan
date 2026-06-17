"""Export helpers for JSON, HTML, and enhanced TXT report generation."""

from __future__ import annotations

import html as html_mod
import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


def _build_result_dict(
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
) -> Dict[str, Any]:
    """Build a unified result dictionary for export."""
    return {
        "meta": {
            "tool": "DomaScan",
            "version": "2.0.0",
            "author": "Shridhar Kirtane",
            "timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": round(scan_duration, 2),
        },
        "target": {
            "domain": target,
            "ip": target_ip,
        },
        "subdomains": {
            "total": len(subdomains),
            "valid": sum(1 for v in subdomains.values() if v),
            "invalid": sum(1 for v in subdomains.values() if not v),
            "entries": {k: ("VALID" if v else "INVALID") for k, v in sorted(subdomains.items())},
        },
        "emails": {
            "total": len(list(emails)),
            "entries": sorted(emails),
        },
        "dns_records": dns_records,
        "whois": whois_data or {},
        "technologies": technologies or {},
        "open_ports": open_ports or [],
        "wayback": wayback_data or {},
        "ssl": ssl_info or {},
        "warnings": warnings,
        "status": status,
    }


def export_json(filepath: str, **kwargs: Any) -> None:
    """Export scan results to a JSON file."""
    data = _build_result_dict(**kwargs)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def export_json_string(**kwargs: Any) -> str:
    """Return scan results as a JSON string."""
    data = _build_result_dict(**kwargs)
    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DomaScan Report — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --purple: #bc8cff; --cyan: #39d2c0;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 2rem;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{
    text-align: center; padding: 2.5rem 1rem;
    background: linear-gradient(135deg, #1a1e2e 0%, #0d1117 100%);
    border: 1px solid var(--border); border-radius: 16px;
    margin-bottom: 2rem;
  }}
  .header h1 {{ font-size: 2.4rem; color: var(--accent); margin-bottom: 0.3rem; }}
  .header .subtitle {{ color: var(--muted); font-size: 1rem; }}
  .header .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 1rem; }}
  .stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.2rem; text-align: center;
  }}
  .stat-card .number {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .stat-card .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .section {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;
  }}
  .section h2 {{
    font-size: 1.2rem; color: var(--accent); margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{
    padding: 0.6rem 0.8rem; text-align: left;
    border-bottom: 1px solid var(--border); font-size: 0.9rem;
  }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  .valid {{ color: var(--green); font-weight: 600; }}
  .invalid {{ color: var(--red); font-weight: 600; }}
  .open {{ color: var(--green); }}
  .tag {{
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px;
    font-size: 0.8rem; margin: 0.15rem;
    background: rgba(88,166,255,0.15); color: var(--accent);
  }}
  .tag.security {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .tag.warning {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .grade {{ font-size: 2rem; font-weight: 700; }}
  .grade-A {{ color: var(--green); }} .grade-B {{ color: var(--yellow); }}
  .grade-C {{ color: var(--yellow); }} .grade-F {{ color: var(--red); }}
  .footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
  .empty {{ color: var(--muted); font-style: italic; }}
  ul {{ list-style: none; }}
  ul li {{ padding: 0.3rem 0; }}
  ul li::before {{ content: "›"; color: var(--accent); font-weight: bold; margin-right: 0.5rem; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔍 DomaScan Report</h1>
    <div class="subtitle">Domain Intelligence for <strong>{domain}</strong></div>
    <div class="meta">
      Generated on {timestamp} &bull; Scan duration: {duration}s &bull; Status: {status}
    </div>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="number">{sub_count}</div><div class="label">Subdomains</div></div>
    <div class="stat-card"><div class="number">{email_count}</div><div class="label">Emails</div></div>
    <div class="stat-card"><div class="number">{dns_count}</div><div class="label">DNS Records</div></div>
    <div class="stat-card"><div class="number">{port_count}</div><div class="label">Open Ports</div></div>
    <div class="stat-card"><div class="number">{tech_count}</div><div class="label">Technologies</div></div>
  </div>

  {sections}

  <div class="footer">
    DomaScan v2.0.0 &bull; Developed by Shridhar Kirtane &bull; 
    <a href="https://github.com/shridhar3902/DomaScan" style="color:var(--accent);text-decoration:none;">GitHub</a>
  </div>
</div>
</body>
</html>"""


def _html_subdomains_section(subdomains: Dict[str, bool]) -> str:
    if not subdomains:
        return '<div class="section"><h2>🌐 Subdomains</h2><p class="empty">No subdomains discovered.</p></div>'
    rows = ""
    for sub, valid in sorted(subdomains.items()):
        cls = "valid" if valid else "invalid"
        label = "VALID" if valid else "INVALID"
        rows += f'<tr><td>{html_mod.escape(sub)}</td><td class="{cls}">{label}</td></tr>'
    return f'''<div class="section"><h2>🌐 Subdomains ({len(subdomains)})</h2>
    <table><tr><th>Subdomain</th><th>Status</th></tr>{rows}</table></div>'''


def _html_emails_section(emails: List[str]) -> str:
    if not emails:
        return '<div class="section"><h2>📧 Emails</h2><p class="empty">No emails discovered.</p></div>'
    items = "".join(f"<li>{html_mod.escape(e)}</li>" for e in emails)
    return f'<div class="section"><h2>📧 Emails ({len(emails)})</h2><ul>{items}</ul></div>'


def _html_dns_section(dns_records: Dict[str, List[str]]) -> str:
    rows = ""
    for rtype, values in sorted(dns_records.items()):
        for v in values:
            rows += f"<tr><td>{html_mod.escape(rtype)}</td><td>{html_mod.escape(str(v))}</td></tr>"
    if not rows:
        return '<div class="section"><h2>📡 DNS Records</h2><p class="empty">No DNS records found.</p></div>'
    return f'''<div class="section"><h2>📡 DNS Records</h2>
    <table><tr><th>Type</th><th>Value</th></tr>{rows}</table></div>'''


def _html_whois_section(whois_data: Dict[str, Any]) -> str:
    if not whois_data:
        return ""
    rows = ""
    for key, val in whois_data.items():
        if val and str(val).strip():
            rows += f"<tr><td>{html_mod.escape(str(key).replace('_', ' ').title())}</td><td>{html_mod.escape(str(val))}</td></tr>"
    if not rows:
        return ""
    return f'''<div class="section"><h2>📋 WHOIS Information</h2>
    <table><tr><th>Field</th><th>Value</th></tr>{rows}</table></div>'''


def _html_tech_section(technologies: Dict[str, List[str]]) -> str:
    if not technologies:
        return ""
    content = ""
    for category, items in technologies.items():
        if items:
            tags = "".join(
                f'<span class="tag{"security" if category == "security_headers" else ""}">{html_mod.escape(i)}</span>'
                for i in items
            )
            content += f"<p><strong>{html_mod.escape(category.replace('_', ' ').title())}:</strong> {tags}</p>"
    if not content:
        return ""
    return f'<div class="section"><h2>🛠️ Technologies Detected</h2>{content}</div>'


def _html_ports_section(open_ports: List[Dict[str, Any]], target_ip: Optional[str] = None) -> str:
    if not open_ports:
        return ""
    ip_line = f"<p>Target IP: <strong>{html_mod.escape(str(target_ip))}</strong></p>" if target_ip else ""
    rows = ""
    for p in open_ports:
        rows += f'<tr><td>{p.get("port", "")}</td><td>{html_mod.escape(str(p.get("service", "")))}</td><td class="open">OPEN</td></tr>'
    return f'''<div class="section"><h2>🔌 Open Ports</h2>{ip_line}
    <table><tr><th>Port</th><th>Service</th><th>State</th></tr>{rows}</table></div>'''


def _html_ssl_section(ssl_info: Dict[str, Any]) -> str:
    if not ssl_info:
        return ""
    grade = ssl_info.get("grade", "?")
    rows = ""
    display_fields = ["issuer", "subject", "not_before", "not_after", "days_until_expiry", "serial_number", "signature_algorithm"]
    for field in display_fields:
        val = ssl_info.get(field)
        if val is not None:
            rows += f"<tr><td>{html_mod.escape(field.replace('_', ' ').title())}</td><td>{html_mod.escape(str(val))}</td></tr>"
    return f'''<div class="section"><h2>🔒 SSL/TLS Certificate</h2>
    <p>Grade: <span class="grade grade-{html_mod.escape(grade)}">{html_mod.escape(grade)}</span></p>
    <table><tr><th>Field</th><th>Value</th></tr>{rows}</table></div>'''


def _html_wayback_section(wayback_data: Dict[str, Any]) -> str:
    if not wayback_data:
        return ""
    rows = ""
    for key in ("total_urls", "unique_subdomains_count", "first_seen", "last_seen"):
        val = wayback_data.get(key)
        if val is not None:
            rows += f"<tr><td>{html_mod.escape(key.replace('_', ' ').title())}</td><td>{html_mod.escape(str(val))}</td></tr>"
    if not rows:
        return ""
    return f'''<div class="section"><h2>🕰️ Wayback Machine History</h2>
    <table><tr><th>Metric</th><th>Value</th></tr>{rows}</table></div>'''


def _html_warnings_section(warnings: List[str]) -> str:
    if not warnings:
        return ""
    items = "".join(f'<li><span class="tag warning">{html_mod.escape(w)}</span></li>' for w in warnings)
    return f'<div class="section"><h2>⚠️ Warnings</h2><ul>{items}</ul></div>'


def export_html(filepath: str, **kwargs: Any) -> None:
    """Export scan results to a self-contained HTML report."""
    data = _build_result_dict(**kwargs)

    subdomains = kwargs.get("subdomains", {})
    emails_list = sorted(kwargs.get("emails", []))
    dns_rec = kwargs.get("dns_records", {})
    warnings = kwargs.get("warnings", [])
    whois_d = kwargs.get("whois_data", {}) or {}
    tech = kwargs.get("technologies", {}) or {}
    ports = kwargs.get("open_ports", []) or []
    wb = kwargs.get("wayback_data", {}) or {}
    ssl_i = kwargs.get("ssl_info", {}) or {}
    target_ip = kwargs.get("target_ip", None)

    dns_count = sum(len(v) for v in dns_rec.values())
    tech_count = sum(len(v) for v in tech.values()) if tech else 0

    sections = "".join([
        _html_subdomains_section(subdomains),
        _html_emails_section(emails_list),
        _html_dns_section(dns_rec),
        _html_whois_section(whois_d),
        _html_tech_section(tech),
        _html_ports_section(ports, target_ip),
        _html_ssl_section(ssl_i),
        _html_wayback_section(wb),
        _html_warnings_section(warnings),
    ])

    page = _HTML_TEMPLATE.format(
        domain=html_mod.escape(kwargs.get("target", "")),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=round(kwargs.get("scan_duration", 0.0), 2),
        status=html_mod.escape(kwargs.get("status", "SUCCESS")),
        sub_count=len(subdomains),
        email_count=len(emails_list),
        dns_count=dns_count,
        port_count=len(ports),
        tech_count=tech_count,
        sections=sections,
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(page)
