# Recon47 — Product Requirements Document
**Author:** 0xMasruful | **Version:** 1.0.0 | **Status:** Final

## 1. Overview
Recon47 is a modular CLI-based automated reconnaissance and vulnerability assessment framework for security professionals. One command orchestrates the full recon → scan → report pipeline and emits a hacker-aesthetic HTML report.

## 2. Architecture
recon47/ (package root)
├── cli.py           — Click entry point
├── config.py        — Constants & config
├── engine.py        — Orchestration engine
├── banner.py        — ASCII art & rich UI
└── modules/
    ├── base.py          — BaseModule ABC
    ├── dns_enum.py      — DNS records + zone xfer
    ├── subdomain.py     — Passive + active subdomain enum
    ├── port_scan.py     — Async TCP port scanner
    ├── tech_detect.py   — Technology fingerprinting
    ├── http_headers.py  — Security header audit
    ├── crawler.py       — Async recursive web crawler
    ├── js_extractor.py  — JS file & secret extraction
    ├── param_extractor.py — Parameter & form discovery
    ├── vuln_nikto.py    — Nikto wrapper
    ├── vuln_nuclei.py   — Nuclei wrapper
    └── ai_summary.py    — AI-assisted findings summary

## 3. CLI Usage
  recon47 TARGET [OPTIONS]
  --full | --recon-only | --vuln-only
  --depth INT (crawl depth, default 3)
  --threads INT (default 50)
  --stealth (rate-limit + random UA)
  --output PATH
  --format html,json
  --ai-summary [--ai-key KEY]
  --no-nikto | --no-nuclei

## 4. Bonus Features
- Recursive async crawling (BFS)
- Multi-threading + asyncio throughout
- Smart URL deduplication & normalization
- HTML report (dark hacker theme)
- Docker support
- AI summary (OpenAI / rule-based fallback)
- Stealth mode (rate limit, jitter, UA rotation)
- JS secret scanning
