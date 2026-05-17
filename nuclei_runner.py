"""
modules/nuclei_runner.py — Nuclei integration wrapper
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile

from utils.output import print_module_header, print_info, print_warning, print_success, print_finding


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse Nuclei JSONL output into structured findings."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            sev = item.get("info", {}).get("severity", "info").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                sev = "INFO"
            finding = {
                "title": item.get("info", {}).get("name", "Unknown"),
                "description": item.get("info", {}).get("description", ""),
                "severity": sev,
                "template_id": item.get("template-id", ""),
                "matched_url": item.get("matched-at", ""),
                "cves": item.get("info", {}).get("classification", {}).get("cve-id", []),
                "tags": item.get("info", {}).get("tags", []),
                "reference": item.get("info", {}).get("reference", []),
                "recommendation": "Review the finding details and apply relevant patches/configurations.",
                "source": "Nuclei",
            }
            findings.append(finding)
        except json.JSONDecodeError:
            if line and ":" in line:
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
        print_warning(
            "nuclei not found in PATH — skipping\n"
            "   Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
        ctx.module_status["nuclei"] = "skip"
        return

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tmp:
        outfile = tmp.name

    try:
        tags = ["cves", "vulnerabilities", "misconfigurations", "exposures", "technologies", "default-logins"]
        rate = 5 if ctx.stealth else int(ctx.rate_limit)
        cmd = [
            "nuclei",
            "-u", ctx.base_url,
            "-o", outfile,
            "-jsonl",
            "-silent",
            "-timeout", str(ctx.timeout),
            "-rate-limit", str(rate),
            "-tags", ",".join(tags),
            "-follow-redirects",
        ]

        print_info(f"Nuclei tags: {', '.join(tags)}")
        print_info(f"Rate limit: {rate} req/s")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            print_warning("Nuclei timed out after 10 minutes — saving partial results")
            ctx.module_status["nuclei"] = "warn"
            # Still parse what we have
            if os.path.exists(outfile):
                with open(outfile) as f:
                    text = f.read()
                ctx.nuclei_findings = _parse_nuclei_jsonl(text)
            return

        output_text = ""
        if os.path.exists(outfile):
            with open(outfile) as f:
                output_text = f.read()
            os.unlink(outfile)

        findings = _parse_nuclei_jsonl(output_text)

        # Smart deduplication by template_id + matched_url
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
