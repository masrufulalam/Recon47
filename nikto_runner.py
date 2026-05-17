"""
modules/nikto_runner.py — Nikto integration wrapper
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile

from utils.output import print_module_header, print_info, print_warning, print_success, print_finding


def _parse_nikto_output(text: str) -> list[dict]:
    """Parse Nikto plaintext output into structured findings."""
    findings = []
    # Nikto output lines that start with "+" are findings
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue
        # Skip metadata lines
        if any(skip in line for skip in ["Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:", "Scan terminated"]):
            continue

        detail = line.lstrip("+ ").strip()
        if not detail:
            continue

        # Determine severity heuristically
        severity = "INFO"
        if any(kw in detail.lower() for kw in ["critical", "vulnerab", "exploit", "cve-", "injection", "xss", "sqli"]):
            severity = "HIGH"
        elif any(kw in detail.lower() for kw in ["allowed", "method", "outdated", "version", "default", "backup"]):
            severity = "MEDIUM"
        elif any(kw in detail.lower() for kw in ["header", "cookie", "directory", "index"]):
            severity = "LOW"

        # Extract CVE if present
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", detail, re.IGNORECASE)

        findings.append({
            "title": detail[:120],
            "description": detail,
            "severity": severity,
            "cves": cves,
            "source": "Nikto",
        })
    return findings


async def run_nikto(ctx) -> None:
    """Run Nikto scanner against the target."""
    print_module_header("Nikto Scanner", ctx.base_url)

    if not shutil.which("nikto"):
        print_warning("nikto not found in PATH — skipping (install: apt install nikto)")
        ctx.module_status["nikto"] = "skip"
        return

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        outfile = tmp.name

    try:
        cmd = [
            "nikto",
            "-h", ctx.base_url,
            "-output", outfile,
            "-Format", "txt",
            "-timeout", str(ctx.timeout),
            "-nointeractive",
        ]
        if ctx.stealth:
            cmd += ["-pause", "1"]

        print_info(f"Running: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            print_warning("Nikto timed out after 5 minutes")
            ctx.module_status["nikto"] = "warn"
            return

        output_text = stdout.decode("utf-8", errors="replace")
        if os.path.exists(outfile):
            with open(outfile) as f:
                output_text = f.read()
            os.unlink(outfile)

        findings = _parse_nikto_output(output_text)
        ctx.nikto_findings = findings
        ctx.module_status["nikto"] = "ok"
        print_success(f"Nikto complete — {len(findings)} findings")
        for f in findings[:10]:
            print_finding(f["title"][:80], f["severity"])

    except Exception as e:
        print_warning(f"Nikto error: {e}")
        ctx.module_status["nikto"] = "error"
    finally:
        if os.path.exists(outfile):
            try:
                os.unlink(outfile)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
"""
modules/nuclei_runner.py — Nuclei integration wrapper
Author: 0xMasruful
"""


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse Nuclei JSONL output."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            sev = item.get("info", {}).get("severity", "info").upper()
            finding = {
                "title": item.get("info", {}).get("name", "Unknown"),
                "description": item.get("info", {}).get("description", ""),
                "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO",
                "template_id": item.get("template-id", ""),
                "matched_url": item.get("matched-at", ""),
                "cves": item.get("info", {}).get("classification", {}).get("cve-id", []),
                "tags": item.get("info", {}).get("tags", []),
                "reference": item.get("info", {}).get("reference", []),
                "source": "Nuclei",
            }
            findings.append(finding)
        except json.JSONDecodeError:
            # Try plain text line
            if ":" in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    findings.append({
                        "title": line[:120],
                        "description": line,
                        "severity": "INFO",
                        "source": "Nuclei",
                    })
    return findings


async def run_nuclei(ctx) -> None:
    """Run Nuclei scanner against the target."""
    print_module_header("Nuclei Scanner", ctx.base_url)

    if not shutil.which("nuclei"):
        print_warning("nuclei not found in PATH — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
        ctx.module_status["nuclei"] = "skip"
        return

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tmp:
        outfile = tmp.name

    try:
        # Build command
        tags = ["cves", "vulnerabilities", "misconfigurations", "exposures", "technologies"]
        cmd = [
            "nuclei",
            "-u", ctx.base_url,
            "-o", outfile,
            "-jsonl",
            "-silent",
            "-timeout", str(ctx.timeout),
            "-rate-limit", str(int(ctx.rate_limit)),
            "-tags", ",".join(tags),
        ]
        if ctx.stealth:
            cmd += ["-rate-limit", "5"]

        print_info(f"Running Nuclei with tags: {', '.join(tags)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            print_warning("Nuclei timed out after 10 minutes")
            ctx.module_status["nuclei"] = "warn"
            return

        output_text = ""
        if os.path.exists(outfile):
            with open(outfile) as f:
                output_text = f.read()
            os.unlink(outfile)

        findings = _parse_nuclei_jsonl(output_text)

        # Dedup by template_id + matched_url
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('template_id')}:{f.get('matched_url')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        ctx.nuclei_findings = unique
        ctx.module_status["nuclei"] = "ok"
        print_success(f"Nuclei complete — {len(unique)} findings")
        for f in unique[:15]:
            print_finding(f["title"][:80], f["severity"], f.get("matched_url", "")[:60])

    except Exception as e:
        print_warning(f"Nuclei error: {e}")
        ctx.module_status["nuclei"] = "error"
    finally:
        if os.path.exists(outfile):
            try:
                os.unlink(outfile)
            except Exception:
                pass
