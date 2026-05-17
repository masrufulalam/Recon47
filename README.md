# Recon47

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║╚════██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║    ██╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║   ██╔╝ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ██║   ██║  
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═╝   ╚═╝  
```

**Automated Reconnaissance & Vulnerability Assessment Framework**  
Author: `0xMasruful` | Version: `1.0.0`

> ⚠️ **Legal Disclaimer**: Only scan targets you own or have explicit written authorization to test. Unauthorized scanning is illegal and unethical.

---

## Features

| Module | Description |
|--------|-------------|
| 🌐 **DNS Recon** | A/AAAA/MX/NS/TXT/SOA records, zone transfer, SPF/DMARC/DKIM, WHOIS |
| 🔍 **Subdomain Enum** | crt.sh, HackerTarget, Wayback Machine, AlienVault OTX + active brute-force |
| 🔓 **Port Scanner** | Async TCP scan of top ports + banner grabbing + TLS detection |
| ⚙️ **Tech Detection** | Wappalyzer-style fingerprinting, WAF/CDN detection |
| 🛡️ **Header Audit** | Security header checks, CORS, cookie flags, info disclosure |
| 🗺️ **Web Crawler** | Async recursive BFS crawler with form extraction |
| 🔑 **JS Extractor** | Secret detection (API keys, tokens, passwords), endpoint hunting |
| 📂 **Dir Brute-Force** | 80+ common path wordlist with status-code analysis |
| 🎯 **Nikto** | Integrated Nikto web server scanner |
| ☢️ **Nuclei** | Integrated Nuclei with CVE/misconfiguration/exposure templates |
| 🤖 **AI Summary** | Claude-powered executive security summary |

**Bonus features**: Stealth mode • Multi-threading/async • Smart deduplication • Docker support • HTML hacker-theme report • AI analysis

---

## Installation

### Prerequisites
- Python 3.9+
- Optional: `nikto` (apt install nikto)
- Optional: `nuclei` (go install)
- Optional: Anthropic API key (for AI summary)

### Quick Install
```bash
git clone https://github.com/0xMasruful/recon47
cd recon47
pip install -e .
```

### Docker (All tools included)
```bash
docker build -t recon47 .
docker run --rm -v $(pwd)/reports:/app/reports recon47 example.com --full
```

---

## Usage

```bash
# Full scan (recommended)
recon47 example.com

# Recon only, no vuln scan
recon47 example.com --recon-only

# With AI summary (requires ANTHROPIC_API_KEY)
recon47 example.com --ai-summary --ai-key sk-ant-...

# Stealth mode (rate-limited, random UA)
recon47 example.com --stealth --rate-limit 5

# Deep crawl
recon47 example.com --depth 5 --threads 100

# Custom output directory
recon47 example.com -o ./my_reports/

# Skip Nikto (faster)
recon47 example.com --no-nikto

# Automation (skip auth prompt)
recon47 example.com --accept-risk --no-report
```

### All Options
```
Arguments:
  TARGET                 Domain, URL, subdomain, or IP

Options:
  --recon-only           Skip vulnerability scanning
  --vuln-only            Skip recon, vuln scan only
  --depth INT            Crawl depth [default: 3]
  --threads INT          Concurrent tasks [default: 50]
  --rate-limit FLOAT     Requests/sec for stealth [default: 10]
  --timeout INT          Per-request timeout [default: 10]
  -o, --output PATH      Output directory
  --stealth              Stealth mode (slow, quiet)
  --no-nikto             Skip Nikto
  --no-nuclei            Skip Nuclei
  --active-subs          Active DNS brute-force
  --ai-summary           AI-assisted summary
  --ai-key TEXT          Anthropic API key
  --full-ports           Scan all 65535 ports
  --ignore-robots        Ignore robots.txt
  --no-report            Skip HTML report
  --accept-risk          Skip authorization prompt
  -v, --verbose          Verbose output
  -V, --version          Show version
  -h, --help             Show help
```

---

## Output

```
reports/
└── example_com/
    ├── recon47_report.html     ← Hacker-theme interactive HTML report
    └── recon47_results.json    ← Machine-readable JSON (all findings)
```

The HTML report features:
- Dark cybersecurity theme with terminal aesthetics
- Interactive vulnerability filter (by severity)
- Collapsible sections
- Severity-coded findings (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Overall risk badge
- Navigation sidebar
- Self-contained (single file, works offline)

---

## Architecture

```
recon47/
├── recon47/          Core package
│   ├── cli.py        Entry point (Click)
│   ├── engine.py     Pipeline orchestrator
│   ├── context.py    Shared state
│   └── reporter.py   HTML report generator
├── modules/          Pluggable scan modules
│   ├── dns_recon.py
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── tech_detect.py
│   ├── crawler.py
│   ├── js_extractor.py
│   ├── param_extractor.py
│   ├── nikto_runner.py
│   ├── nuclei_runner.py
│   └── ai_summarizer.py
├── utils/
│   ├── output.py     Rich terminal UI
│   └── http_client.py
├── setup.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## Requirements

```
click>=8.1.0          CLI framework
rich>=13.0.0          Terminal UI
httpx[http2]>=0.25.0  Async HTTP client
beautifulsoup4        HTML parsing
lxml                  HTML parser
dnspython             DNS lookups
python-whois          WHOIS queries
jinja2                HTML templating
tldextract            Domain parsing
anthropic>=0.25.0     AI summary (optional)
```

---

## Ethical Use

This tool is built for **Educational and Research purposes**. By running Recon47, you agree to:

1. Only target systems you own or have explicit written permission to test
2. Not use this tool for any malicious or illegal purposes
3. Follow responsible disclosure practices for any findings
4. Comply with all applicable laws in your jurisdiction.
   
Please use Recon47 responsibly. You are responsible for your actions. Misuse of this tool can lead to potential legal consequences. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

---

*Recon47 v1.0.0 — 0xMasruful*
