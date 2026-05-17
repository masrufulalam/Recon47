"""
utils/output.py — Rich console output helpers for Recon47
Author: 0xMasruful
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)

# ── Theme ─────────────────────────────────────────────────────────────────────
RECON47_THEME = Theme(
    {
        "banner": "bold bright_green",
        "module": "bold cyan",
        "info": "bright_white",
        "success": "bold bright_green",
        "warning": "bold yellow",
        "error": "bold red",
        "critical": "bold bright_red on black",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold blue",
        "infolevel": "dim white",
        "target": "bold bright_cyan",
        "dim": "dim white",
        "accent": "bright_magenta",
    }
)

console = Console(theme=RECON47_THEME, highlight=False)

# ── ASCII Banner ───────────────────────────────────────────────────────────────
BANNER = r"""
[banner]
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║╚════██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║    ██╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║   ██╔╝ 
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ██║   ██║  
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═╝   ╚═╝  
[/banner]
[dim]    Automated Recon & Vulnerability Assessment Framework[/dim]
[dim]    Author: [accent]0xMasruful[/accent]  │  v1.0.0  │  Use Responsibly[/dim]
"""


def print_banner() -> None:
    console.print(BANNER)
    console.rule(style="bright_green dim")
    console.print()


def print_module_header(name: str, description: str = "") -> None:
    title = Text()
    title.append("▶ ", style="bright_green")
    title.append(name, style="bold cyan")
    if description:
        title.append(f"  {description}", style="dim white")
    console.print(title)


def print_success(msg: str) -> None:
    console.print(f"[success]  ✓  {msg}[/success]")


def print_info(msg: str) -> None:
    console.print(f"[info]  ·  {msg}[/info]")


def print_warning(msg: str) -> None:
    console.print(f"[warning]  ⚠  {msg}[/warning]")


def print_error(msg: str) -> None:
    console.print(f"[error]  ✗  {msg}[/error]")


def print_finding(title: str, severity: str, detail: str = "", source: str = "") -> None:
    sev = severity.upper()
    sev_color = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "infolevel",
    }.get(sev, "infolevel")

    row = Text()
    row.append(f"  [{sev:^8}] ", style=sev_color)
    row.append(title, style="bright_white")
    if source:
        row.append(f"  ({source})", style="dim")
    console.print(row)
    if detail:
        console.print(f"           [dim]{detail}[/dim]")


def severity_badge(sev: str) -> str:
    """Return coloured severity string for Rich."""
    colors = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "infolevel",
    }
    c = colors.get(sev.upper(), "infolevel")
    return f"[{c}]{sev.upper()}[/{c}]"


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bright_green"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="bright_green", complete_style="bright_green"),
        TextColumn("[dim]{task.fields[status]}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def print_summary_table(ctx) -> None:
    """Print a final summary table of findings."""
    console.print()
    console.rule("[bold bright_green] SCAN SUMMARY [/bold bright_green]", style="bright_green")
    console.print()

    t = Table(
        box=box.SIMPLE_HEAVY,
        border_style="bright_green",
        header_style="bold cyan",
        show_header=True,
    )
    t.add_column("Module", style="bright_white", width=28)
    t.add_column("Findings", justify="right", style="bright_green", width=12)
    t.add_column("Status", width=12)

    status_map = {
        "ok": "[success]  DONE  [/success]",
        "warn": "[warning]  WARN  [/warning]",
        "skip": "[dim]  SKIP  [/dim]",
        "error": "[error]  FAIL  [/error]",
    }

    rows = [
        ("DNS Recon", len(ctx.dns), ctx.module_status.get("dns", "ok")),
        ("Subdomain Enumeration", len(ctx.subdomains), ctx.module_status.get("subdomains", "ok")),
        ("Port Scanning", len(ctx.ports), ctx.module_status.get("ports", "ok")),
        ("Technology Detection", len(ctx.technologies), ctx.module_status.get("tech", "ok")),
        ("Header Analysis", len(ctx.header_issues), ctx.module_status.get("headers", "ok")),
        ("Web Crawler", len(ctx.endpoints), ctx.module_status.get("crawler", "ok")),
        ("JS Extractor", len(ctx.js_findings), ctx.module_status.get("js", "ok")),
        ("Directory Brute-Force", len(ctx.directories), ctx.module_status.get("dirbust", "ok")),
        ("Nikto", len(ctx.nikto_findings), ctx.module_status.get("nikto", "ok")),
        ("Nuclei", len(ctx.nuclei_findings), ctx.module_status.get("nuclei", "ok")),
    ]

    for name, count, status in rows:
        t.add_row(name, str(count), status_map.get(status, status))

    console.print(t)

    # Severity summary
    sc = ctx.severity_counts()
    console.print()
    sev_t = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    sev_t.add_column(width=14)
    sev_t.add_column(width=6)
    for sev, count in sc.items():
        if count > 0:
            sev_t.add_row(severity_badge(sev), str(count))
    console.print("  Vulnerability Counts:")
    console.print(sev_t)
    console.print()
    console.print(
        f"  [dim]Duration:[/dim] [bright_white]{ctx.elapsed_str()}[/bright_white]"
        f"   [dim]Output:[/dim] [bright_cyan]{ctx.output_dir}[/bright_cyan]"
    )
    console.print()
