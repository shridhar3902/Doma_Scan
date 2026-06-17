<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">🔍 DomaScan</h1>
<h3 align="center"><em>Domain Intelligence. Reimagined.</em></h3>

<p align="center">
  A powerful CLI-based OSINT domain intelligence tool that gathers subdomains, emails, DNS records, WHOIS data, technology stacks, open ports, SSL certificates, and historical data — all from public sources with built-in retry logic, validation, and beautiful reporting.
</p>

<p align="center">
  <strong>Developed by <a href="https://github.com/shridharkirtane">Shridhar Kirtane</a></strong>
</p>

---

## ⚡ Features

| Module | Description |
|--------|-------------|
| 🌐 **Subdomain Enumeration** | Certificate Transparency (crt.sh), DNS brute-force (150+ wordlist), Wayback Machine, DuckDuckGo scraping, SSL SANs |
| 📧 **Email Harvesting** | Homepage + deep crawling, DuckDuckGo search, JavaScript file parsing |
| 📡 **DNS Enumeration** | A, AAAA, MX, NS, TXT, SOA, CNAME records + zone transfer attempts |
| 📋 **WHOIS Lookup** | Registrar, creation/expiry dates, name servers, registrant info |
| 🛠️ **Technology Detection** | Web servers, CMS, JS frameworks, CDNs, security headers, analytics — zero API keys needed |
| 🔌 **Port Scanning** | 22 common TCP ports with service identification |
| 🔒 **SSL/TLS Analysis** | Certificate details, SAN extraction, SSL grading (A/B/C/F) |
| 🕰️ **Wayback Machine** | Historical URL discovery, domain timeline (first/last seen) |
| ✅ **Subdomain Validation** | DNS resolution + wildcard detection to flag false positives |
| 📊 **Rich Reporting** | JSON, HTML (dark-themed), and TXT export formats |

## 🎯 What Makes DomaScan Different

- **Zero API Keys** — Every module works out of the box using public data sources
- **Parallel Execution** — All modules run concurrently for maximum speed
- **Graceful Failures** — If one source is down, the rest keep running
- **Wildcard Detection** — Automatically detects and warns about wildcard DNS
- **Beautiful Output** — Rich-powered tables, colored sections, and a stunning ASCII banner
- **Export Everything** — JSON for automation, HTML for reports, TXT for notes
- **Proxy & Rate Limiting** — Built-in support for proxies and request throttling

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/shridharkirtane/DomaScan.git
cd DomaScan

# Install dependencies
pip install -r requirements.txt
```

### Install as CLI Tool (Optional)

```bash
pip install .
# Now you can run 'domascan' from anywhere
```

### Kali Linux

```bash
sudo apt update && sudo apt install -y python3 python3-pip
git clone https://github.com/shridharkirtane/DomaScan.git
cd DomaScan
pip3 install -r requirements.txt
```

---

## 📖 Usage

### Basic Syntax

```bash
python3 domascan.py -d <target-domain> [options]
```

### Quick Start Examples

```bash
# Run ALL modules on a target
python3 domascan.py -d example.com -a

# Subdomain enumeration only
python3 domascan.py -d example.com -s

# Email harvesting only
python3 domascan.py -d example.com -e

# DNS + WHOIS + SSL analysis
python3 domascan.py -d example.com -dns -w --ssl

# Technology detection + port scanning
python3 domascan.py -d example.com -t -p

# Full scan with JSON and HTML reports
python3 domascan.py -d example.com -a --json report.json --html report.html

# Scan through a proxy with rate limiting
python3 domascan.py -d example.com -a --proxy http://127.0.0.1:8080 --rate-limit 1.0

# Verbose mode for debugging
python3 domascan.py -d example.com -a -v
```

---

## 🎛️ CLI Reference

### Module Selection

| Flag | Description |
|------|-------------|
| `-d, --domain` | **Required.** Target domain (e.g., `example.com`) |
| `-a, --all` | Run all modules |
| `-s, --subdomains` | Subdomain enumeration (crt.sh, DNS brute, DuckDuckGo) |
| `-e, --emails` | Email extraction (crawler, DuckDuckGo) |
| `-dns, --dns` | DNS record enumeration |
| `-w, --whois` | WHOIS domain lookup |
| `-t, --tech` | Technology/framework detection |
| `-p, --ports` | TCP port scanning |
| `--wayback` | Wayback Machine historical data |
| `--ssl` | SSL/TLS certificate analysis |

### Output Options

| Flag | Description |
|------|-------------|
| `-o, --output FILE` | Save results to plain text file |
| `--json FILE` | Export results as structured JSON |
| `--html FILE` | Generate self-contained HTML report (dark theme) |

### Tuning Options

| Flag | Default | Description |
|------|---------|-------------|
| `-v, --verbose` | Off | Show debug output for all modules |
| `--timeout SECS` | 10 | HTTP request timeout in seconds |
| `--threads N` | 10 | Maximum concurrent threads |
| `--depth N` | 2 | Web crawler depth (levels of links to follow) |
| `--proxy URL` | None | HTTP/SOCKS proxy (e.g., `http://127.0.0.1:8080`) |
| `--rate-limit SECS` | 0 | Delay between HTTP requests in seconds |

---

## 📊 Sample Output

```
  ██████╗  ██████╗ ███╗   ███╗ █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ██║██║   ██║██╔████╔██║███████║███████╗██║     ███████║██╔██╗ ██║
  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  Domain Intelligence. Reimagined.
  v2.0.0 | Developed by Shridhar Kirtane

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [TARGET]  example.com
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ╭──────────────── 🌐 Subdomains ─────────────────╮
  │ Subdomain                       │    Status     │
  │ api.example.com                 │   ✓ VALID     │
  │ mail.example.com                │   ✓ VALID     │
  │ test.example.com                │   ✗ INVALID   │
  ╰─────────────────────────────────────────────────╯

  ╭──────────── 📡 DNS Records ────────────────────╮
  │ Type     │ Value                                │
  │ A        │ 93.184.216.34                        │
  │ MX       │ mail.example.com                     │
  │ NS       │ ns1.example.com                      │
  ╰────────────────────────────────────────────────╯

  ╭──────────────── Scan Summary ──────────────────╮
  │ 3 subdomains (2 valid) · 2 emails · 5 DNS      │
  │ Scan completed in 12.34s · Status: SUCCESS      │
  ╰────────────────────────────────────────────────╯
```

---

## 🏗️ Architecture

```
DomaScan/
├── domascan.py              # Entry point
├── modules/
│   ├── cli.py               # CLI orchestration & scan engine
│   ├── crt.py               # Certificate Transparency (crt.sh)
│   ├── dns_enum.py          # DNS enumeration & brute-force
│   ├── crawler.py           # Web crawler for emails & subdomains
│   ├── duckduckgo.py        # DuckDuckGo HTML search
│   ├── whois_lookup.py      # WHOIS domain data
│   ├── tech_detect.py       # Technology fingerprinting
│   ├── port_scanner.py      # TCP port scanning
│   ├── wayback.py           # Wayback Machine CDX API
│   └── ssl_info.py          # SSL/TLS certificate analysis
├── utils/
│   ├── http.py              # HTTP client (session pooling, backoff, UA rotation)
│   ├── cleaner.py           # Data normalization & extraction
│   ├── validator.py         # Subdomain validation & wildcard detection
│   ├── output.py            # Rich CLI output & banner
│   └── exporter.py          # JSON / HTML / TXT export
├── requirements.txt
├── setup.py
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## ⚠️ Legal Disclaimer

DomaScan is designed for **authorized security testing** and **educational purposes** only. All data sources used are **publicly available**. Always ensure you have proper authorization before scanning any domain. The author is not responsible for any misuse of this tool.

---

## 🤝 Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Shridhar Kirtane**

- GitHub: [@shridharkirtane](https://github.com/shridharkirtane)

---

<p align="center">
  <strong>⭐ If DomaScan helped you, give it a star on GitHub! ⭐</strong>
</p>
