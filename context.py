"""
recon47/context.py — Shared scan context and state management
Author: 0xMasruful
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanContext:
    """
    Central state object shared across all modules.
    Every module reads config from here and writes findings here.
    """

    # --- Target ---
    target: str = ""
    scheme: str = "https"
    host: str = ""
    port: int = 443
    base_url: str = ""

    # --- Config ---
    output_dir: Path = Path(".")
    threads: int = 10
    rate_limit: float = 20.0       # req/s per host
    timeout: int = 10
    depth: int = 3
    stealth: bool = False
    verbose: bool = False
    no_vuln: bool = False
    no_report: bool = False
    ai_summary_enabled: bool = False
    ignore_robots: bool = False
    full_ports: bool = False
    active_subdomain: bool = False
    wordlist: str | None = None

    # --- Timing ---
    start_time: float = field(default_factory=time.time)

    # --- Findings ---
    dns: dict[str, Any] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    subdomains: list[dict] = field(default_factory=list)
    ports: dict[int, dict] = field(default_factory=dict)
    technologies: list[dict] = field(default_factory=list)
    waf: str | None = None
    cdn: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    header_issues: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    js_findings: list[dict] = field(default_factory=list)
    directories: list[dict] = field(default_factory=list)

    # --- Vulnerability findings ---
    nikto_findings: list[dict] = field(default_factory=list)
    nuclei_findings: list[dict] = field(default_factory=list)

    # --- AI output ---
    ai_summary: str = ""

    # --- Module status ---
    module_status: dict[str, str] = field(default_factory=dict)

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def elapsed_str(self) -> str:
        secs = int(self.elapsed())
        m, s = divmod(secs, 60)
        return f"{m}m {s}s" if m else f"{s}s"

    def all_vulnerabilities(self) -> list[dict]:
        """Aggregate all vulnerability findings across sources."""
        vulns = []
        for v in self.nikto_findings:
            v.setdefault("source", "Nikto")
            vulns.append(v)
        for v in self.nuclei_findings:
            v.setdefault("source", "Nuclei")
            vulns.append(v)
        for v in self.header_issues:
            v.setdefault("source", "Header Analysis")
            vulns.append(v)
        for v in self.js_findings:
            v.setdefault("source", "JS Extractor")
            vulns.append(v)
        return vulns

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in self.all_vulnerabilities():
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "meta": {
                "target": self.target,
                "host": self.host,
                "base_url": self.base_url,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time)),
                "duration": self.elapsed_str(),
                "tool": "Recon47",
                "author": "0xMasruful",
                "version": "1.0.0",
            },
            "dns": self.dns,
            "whois": self.whois,
            "subdomains": self.subdomains,
            "ports": {str(k): v for k, v in self.ports.items()},
            "technologies": self.technologies,
            "waf": self.waf,
            "cdn": self.cdn,
            "headers": self.headers,
            "header_issues": self.header_issues,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "forms": self.forms,
            "js_files": self.js_files,
            "js_findings": self.js_findings,
            "directories": self.directories,
            "vulnerabilities": {
                "nikto": self.nikto_findings,
                "nuclei": self.nuclei_findings,
                "header_issues": self.header_issues,
                "js_secrets": [f for f in self.js_findings if f.get("type") == "secret"],
            },
            "severity_counts": self.severity_counts(),
            "ai_summary": self.ai_summary,
            "module_status": self.module_status,
        }
