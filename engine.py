"""
recon47/engine.py — Async scan orchestration pipeline
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.output import console, print_info, print_warning, print_success, print_summary_table


async def run_pipeline(ctx) -> None:
    """
    Execute the full recon + vuln scan pipeline.
    Modules are run in logical order with async parallelism where safe.
    """
    from modules.dns_recon import run_dns_recon
    from modules.subdomain_enum import run_subdomain_enum
    from modules.port_scanner import run_port_scanner
    from modules.tech_detect import run_tech_detect, run_header_analyzer
    from modules.crawler import run_crawler
    from modules.js_extractor import run_js_extractor, run_dir_bruteforce
    from modules.param_extractor import run_param_extractor
    from modules.nikto_runner import run_nikto
    from modules.nuclei_runner import run_nuclei
    from modules.ai_summarizer import run_ai_summarizer

    console.print(Panel.fit(
        f"[bold bright_green]Target:[/bold bright_green] [bright_cyan]{ctx.target}[/bright_cyan]\n"
        f"[dim]Base URL: {ctx.base_url}[/dim]\n"
        f"[dim]Output:   {ctx.output_dir}[/dim]",
        title="[bold]Recon47 Scan Starting[/bold]",
        border_style="bright_green",
    ))
    console.print()

    # ── Phase 1: DNS & Subdomains (parallel) ─────────────────────────────────
    _phase("Phase 1", "DNS Recon & Subdomain Enumeration")
    await asyncio.gather(
        _safe_run("dns", run_dns_recon, ctx),
        _safe_run("subdomains", run_subdomain_enum, ctx),
    )
    console.print()

    # ── Phase 2: Port Scan + Tech Detection (parallel) ───────────────────────
    _phase("Phase 2", "Port Scan & Technology Detection")
    await asyncio.gather(
        _safe_run("ports", run_port_scanner, ctx),
        _safe_run("tech", run_tech_detect, ctx),
    )
    console.print()

    # ── Phase 3: Header Analysis ──────────────────────────────────────────────
    _phase("Phase 3", "HTTP Security Header Analysis")
    await _safe_run("headers", run_header_analyzer, ctx)
    console.print()

    # ── Phase 4: Web Crawling ─────────────────────────────────────────────────
    _phase("Phase 4", "Web Crawling & Endpoint Discovery")
    await _safe_run("crawler", run_crawler, ctx)
    console.print()

    # ── Phase 5: JS Extraction + Directory Brute-Force + Param Extract ───────
    _phase("Phase 5", "JS Extraction, Directory Discovery & Parameter Analysis")
    await asyncio.gather(
        _safe_run("js", run_js_extractor, ctx),
        _safe_run("dirbust", run_dir_bruteforce, ctx),
        _safe_run("params", run_param_extractor, ctx),
    )
    console.print()

    # ── Phase 6: Vulnerability Scanning ──────────────────────────────────────
    if not ctx.no_vuln:
        _phase("Phase 6", "Vulnerability Scanning (Nikto + Nuclei)")
        await asyncio.gather(
            _safe_run("nikto", run_nikto, ctx),
            _safe_run("nuclei", run_nuclei, ctx),
        )
        console.print()

    # ── Phase 7: AI Summary (optional) ───────────────────────────────────────
    if ctx.ai_summary_enabled:
        _phase("Phase 7", "AI-Assisted Security Summary")
        await _safe_run("ai", run_ai_summarizer, ctx)
        console.print()

    # ── Save JSON results ─────────────────────────────────────────────────────
    _save_results(ctx)

    # ── Generate HTML report ──────────────────────────────────────────────────
    if not ctx.no_report:
        from recon47.reporter import generate_html_report
        try:
            report_path = generate_html_report(ctx)
            print_success(f"HTML report → {report_path}")
        except Exception as e:
            print_warning(f"Report generation failed: {e}")

    # ── Final summary ─────────────────────────────────────────────────────────
    print_summary_table(ctx)


def _phase(tag: str, description: str) -> None:
    console.rule(
        f"[bold bright_green]{tag}[/bold bright_green] [dim]─ {description}[/dim]",
        style="dim green",
    )


async def _safe_run(name: str, func, ctx) -> None:
    """Run a module safely, catching all exceptions."""
    try:
        await func(ctx)
    except Exception as e:
        print_warning(f"Module '{name}' encountered an error: {e}")
        ctx.module_status[name] = "error"
        if ctx.verbose:
            console.print_exception()


def _save_results(ctx) -> None:
    """Save JSON results to output directory."""
    out_path = ctx.output_dir / "recon47_results.json"
    try:
        with open(out_path, "w") as f:
            json.dump(ctx.to_dict(), f, indent=2, default=str)
        print_success(f"JSON results → {out_path}")
    except Exception as e:
        print_warning(f"Could not save JSON results: {e}")
