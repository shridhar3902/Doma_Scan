"""DNS enumeration with expanded wordlist, zone-transfer attempts, and threaded brute-force."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from utils.output import verbose_print
from utils.validator import quick_resolve

# ── Expanded wordlist (150+ entries) ──────────────────────────────────────────

WORDLIST = (
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "portal", "vpn",
    "admin", "administrator", "dev", "development", "staging", "stage", "test",
    "testing", "qa", "uat", "api", "api2", "api3", "app", "apps", "mobile", "m",
    "beta", "alpha", "demo", "sandbox", "preview", "internal", "intranet",
    "extranet", "gateway", "proxy", "reverse", "cdn", "static", "assets", "media",
    "img", "images", "video", "download", "downloads", "upload", "uploads", "ftp2",
    "sftp", "ssh", "git", "gitlab", "github", "svn", "jenkins", "ci", "cd",
    "build", "deploy", "monitor", "monitoring", "grafana", "kibana", "elastic",
    "log", "logs", "syslog", "nagios", "zabbix", "status", "health", "dashboard",
    "panel", "cpanel", "whm", "plesk", "webmin", "phpmyadmin", "db", "database",
    "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis", "memcached",
    "rabbitmq", "kafka", "queue", "search", "elasticsearch", "solr", "cache",
    "varnish", "lb", "loadbalancer", "haproxy", "firewall", "waf", "sso", "auth",
    "oauth", "login", "signup", "register", "account", "accounts", "profile",
    "user", "users", "customer", "clients", "partner", "partners", "support",
    "help", "helpdesk", "ticket", "tickets", "jira", "confluence", "wiki", "docs",
    "documentation", "blog", "news", "press", "shop", "store", "ecommerce", "cart",
    "checkout", "pay", "payment", "billing", "invoice", "crm", "erp", "hr",
    "mail2", "email", "exchange", "owa", "autodiscover", "autoconfig", "imap",
    "pop3", "calendar", "meet", "meeting", "zoom", "teams", "slack", "chat",
    "forum", "community", "social", "analytics", "tracking", "pixel", "ad", "ads",
    "advertising", "marketing", "campaign", "seo", "sitemap", "rss", "feed", "xml",
    "json", "graphql", "rest", "soap", "wsdl", "v1", "v2", "v3", "old", "new",
    "legacy", "backup", "bak", "temp", "tmp", "archive", "dr", "disaster",
    "recovery", "vpn2", "remote", "rdp", "citrix", "terminal", "ts", "bastion",
    "jump", "relay", "edge", "node", "cluster", "k8s", "kubernetes", "docker",
    "container", "cloud", "aws", "azure", "gcp", "s3", "storage", "blob", "bucket",
    "lambda", "function", "serverless", "microservice", "service", "svc", "ws",
    "websocket", "socket", "stream", "live", "realtime", "push", "notify",
    "notification", "alert", "alarm", "cron", "scheduler", "worker", "job", "task",
    "batch", "report", "reports", "bi", "data", "datawarehouse", "dw", "etl",
    "lake", "spark", "hadoop", "airflow", "mlflow", "ml", "ai", "model", "predict",
    "recommend", "feature", "flag", "config", "configuration", "settings", "env",
    "environment", "vault", "secret", "key", "cert", "certificate", "pki", "ca",
    "ocsp", "crl", "acme", "letsencrypt",
)


def _resolve_record(
    domain: str, record_type: str, warnings: List[str], verbose: bool
) -> List[str]:
    """Resolve a single DNS record type and return the values as strings."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)

        if record_type == "SOA":
            values = []
            for rdata in answers:
                values.append(
                    f"{rdata.mname} {rdata.rname} (serial={rdata.serial})"
                )
            verbose_print(verbose, f"Resolved {record_type} for {domain}: {values}")
            return values

        if record_type == "TXT":
            values = []
            for rdata in answers:
                # TXT records can have multiple strings per record
                txt_value = " ".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                values.append(txt_value)
            verbose_print(verbose, f"Resolved {record_type} for {domain}: {len(values)} records")
            return values

        values = [str(answer).rstrip(".") for answer in answers]
        verbose_print(verbose, f"Resolved {record_type} for {domain}: {values}")
        return values

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        verbose_print(verbose, f"No {record_type} records found for {domain}")
        return []
    except dns.resolver.NoNameservers:
        verbose_print(verbose, f"No nameservers available for {record_type} on {domain}")
        return []
    except Exception as exc:
        warnings.append(f"DNS {record_type} lookup failed for {domain}: {exc}")
        return []


def _attempt_zone_transfer(
    domain: str, nameservers: List[str], warnings: List[str], verbose: bool
) -> List[str]:
    """Try an AXFR zone transfer against each nameserver.  Usually fails."""
    discovered: List[str] = []

    for ns in nameservers:
        try:
            verbose_print(verbose, f"Attempting zone transfer (AXFR) on {ns}")
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=10))
            for name, _node in zone.nodes.items():
                fqdn = f"{name}.{domain}".rstrip(".")
                if fqdn != domain:
                    discovered.append(fqdn)
            verbose_print(
                verbose,
                f"Zone transfer succeeded on {ns}: {len(discovered)} records",
            )
        except Exception as exc:
            verbose_print(verbose, f"Zone transfer failed on {ns}: {exc}")

    return discovered


def _brute_check(candidate: str) -> str | None:
    """Return the candidate hostname if it resolves, otherwise None."""
    return candidate if quick_resolve(candidate) else None


def enumerate_dns(domain: str, verbose: bool = False) -> Dict[str, object]:
    """Perform comprehensive DNS enumeration on *domain*.

    Resolves A, AAAA, MX, NS, TXT, SOA, and CNAME records, attempts zone
    transfers, and brute-forces subdomains with a 150+ entry wordlist.

    Returns
    -------
    dict
        ``subdomains``   – list of discovered subdomains.
        ``emails``       – empty list (placeholder).
        ``dns_records``  – dict keyed by record type.
        ``warnings``     – list of warning strings.
    """
    warnings: List[str] = []

    # ── Standard record resolution ────────────────────────────────────────
    verbose_print(verbose, f"Starting DNS enumeration for {domain}")

    a_records = _resolve_record(domain, "A", warnings, verbose)
    aaaa_records = _resolve_record(domain, "AAAA", warnings, verbose)
    mx_records = _resolve_record(domain, "MX", warnings, verbose)
    ns_records = _resolve_record(domain, "NS", warnings, verbose)
    txt_records = _resolve_record(domain, "TXT", warnings, verbose)
    soa_records = _resolve_record(domain, "SOA", warnings, verbose)
    cname_records = _resolve_record(domain, "CNAME", warnings, verbose)

    # ── Zone transfer attempt ─────────────────────────────────────────────
    axfr_subdomains = _attempt_zone_transfer(domain, ns_records, warnings, verbose)

    # ── Threaded brute-force ──────────────────────────────────────────────
    candidates = [f"{prefix}.{domain}" for prefix in WORDLIST]
    brute_forced: List[str] = []

    verbose_print(verbose, f"Brute-forcing {len(candidates)} candidates with 30 threads")

    with ThreadPoolExecutor(max_workers=30) as executor:
        future_map = {
            executor.submit(_brute_check, candidate): candidate
            for candidate in candidates
        }
        for future in as_completed(future_map):
            try:
                result = future.result()
                if result is not None:
                    brute_forced.append(result)
                    verbose_print(verbose, f"Brute-force discovered {result}")
            except Exception:
                pass

    # ── Combine all subdomains ────────────────────────────────────────────
    all_subdomains = sorted(set(brute_forced + axfr_subdomains))

    verbose_print(
        verbose,
        f"DNS enumeration complete: {len(all_subdomains)} subdomains, "
        f"{sum(len(v) for v in [a_records, aaaa_records, mx_records, ns_records, txt_records, soa_records, cname_records])} DNS records",
    )

    return {
        "subdomains": all_subdomains,
        "emails": [],
        "dns_records": {
            "A": a_records,
            "AAAA": aaaa_records,
            "MX": mx_records,
            "NS": ns_records,
            "TXT": txt_records,
            "SOA": soa_records,
            "CNAME": cname_records,
        },
        "warnings": warnings,
    }
