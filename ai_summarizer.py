"""
modules/ai_summarizer.py — AI-assisted findings summary via Claude API
Author: 0xMasruful
"""

from __future__ import annotations

import json
import os

from utils.output import print_module_header, print_info, print_warning, print_success


def _build_prompt(ctx) -> str:
    sc = ctx.severity_counts()
    vulns = ctx.all_vulnerabilities()[:30]  # limit tokens

    vuln_summary = "\n".join(
        f"- [{v.get('severity','INFO')}] {v.get('title','?')} ({v.get('source','?')})"
        for v in vulns
    )
    tech_summary = ", ".join(t["name"] for t in ctx.technologies[:10]) or "Unknown"
    subdomain_count = len(ctx.subdomains)
    port_list = ", ".join(str(p) for p in list(ctx.ports.keys())[:15])

    return f"""You are a senior penetration tester writing an executive security report.
Analyze the following reconnaissance & vulnerability scan results for: {ctx.target}

SCAN SUMMARY:
- Target: {ctx.base_url}
- Subdomains discovered: {subdomain_count}
- Open ports: {port_list}
- Technologies detected: {tech_summary}
- Total vulnerabilities: {sum(sc.values())} (CRITICAL:{sc.get('CRITICAL',0)}, HIGH:{sc.get('HIGH',0)}, MEDIUM:{sc.get('MEDIUM',0)}, LOW:{sc.get('LOW',0)})

TOP FINDINGS:
{vuln_summary if vuln_summary else "No critical vulnerabilities found."}

Write a concise (300-400 word) executive summary covering:
1. Overall risk assessment and attack surface overview
2. Most critical findings and their business impact
3. Key remediation priorities (top 3-5 actions)
4. Positive security findings (if any)

Use clear, professional language suitable for both technical and non-technical stakeholders."""


async def run_ai_summarizer(ctx) -> None:
    """Generate AI-assisted security summary using Claude API."""
    print_module_header("AI Summarizer", "Claude-powered security analysis")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if not api_key:
        print_warning("ANTHROPIC_API_KEY not set — generating rule-based summary")
        ctx.ai_summary = _rule_based_summary(ctx)
        ctx.module_status["ai"] = "warn"
        print_success("Rule-based summary generated")
        return

    try:
        import httpx
        prompt = _build_prompt(ctx)

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            data = resp.json()
            summary = data["content"][0]["text"]
            ctx.ai_summary = summary
            ctx.module_status["ai"] = "ok"
            print_success("AI summary generated")
            # Preview first 200 chars
            print_info(summary[:200] + "...")

    except Exception as e:
        print_warning(f"AI summary failed: {e} — falling back to rule-based")
        ctx.ai_summary = _rule_based_summary(ctx)
        ctx.module_status["ai"] = "warn"


def _rule_based_summary(ctx) -> str:
    """Generate a rule-based summary without AI."""
    sc = ctx.severity_counts()
    total = sum(sc.values())

    # Overall risk
    if sc.get("CRITICAL", 0) > 0:
        risk = "CRITICAL"
        risk_desc = "critical vulnerabilities require immediate remediation"
    elif sc.get("HIGH", 0) >= 3:
        risk = "HIGH"
        risk_desc = "multiple high-severity issues present a significant attack surface"
    elif sc.get("HIGH", 0) > 0 or sc.get("MEDIUM", 0) >= 5:
        risk = "MEDIUM"
        risk_desc = "moderate security concerns were identified"
    else:
        risk = "LOW"
        risk_desc = "the target demonstrates a reasonable security posture"

    techs = ", ".join(t["name"] for t in ctx.technologies[:5]) or "undetermined stack"
    open_ports = len(ctx.ports)
    subs = len(ctx.subdomains)

    top_vulns = [v for v in ctx.all_vulnerabilities() if v.get("severity") in ("CRITICAL", "HIGH")][:5]
    vuln_lines = "\n".join(f"  • {v['title']}" for v in top_vulns) or "  • No critical/high findings"

    return f"""EXECUTIVE SECURITY SUMMARY — {ctx.target}
{'=' * 60}

OVERALL RISK: {risk}
The assessment of {ctx.base_url} reveals that {risk_desc}.

ATTACK SURFACE:
  • {subs} subdomains discovered
  • {open_ports} open ports identified
  • Technology stack: {techs}
  • {len(ctx.endpoints)} endpoints crawled
  • {total} total security findings

TOP FINDINGS:
{vuln_lines}

SEVERITY BREAKDOWN:
  Critical: {sc.get('CRITICAL',0)}  |  High: {sc.get('HIGH',0)}  |  Medium: {sc.get('MEDIUM',0)}  |  Low: {sc.get('LOW',0)}  |  Info: {sc.get('INFO',0)}

REMEDIATION PRIORITIES:
  1. Address all CRITICAL and HIGH findings immediately
  2. Review security headers and implement missing controls
  3. Remove sensitive information from JavaScript files
  4. Restrict access to administrative interfaces
  5. Enable HTTPS and proper TLS configuration across all services

NOTE: This summary was generated automatically. Manual verification of all 
findings is recommended before remediation. Always follow responsible 
disclosure practices.

Generated by Recon47 v1.0.0 | Author: 0xMasruful"""
