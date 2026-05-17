"""
recon47/cli.py — CLI entry point using Click
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import click

# Ensure package root is on PYTHONPATH when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.output import console, print_banner, print_info, print_warning, print_error


def _parse_target(target: str):
    """Parse target into scheme, host, port, base_url."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or target
    port = parsed.port or (443 if scheme == "https" else 80)
    base_url = f"{scheme}://{host}" + (f":{port}" if parsed.port else "")
    return scheme, host, port, base_url


def _check_tools():
    """Check for optional external tools and warn if missing."""
    import shutil
    tools = {"nikto": "apt install nikto", "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
    for tool, install in tools.items():
        if not shutil.which(tool):
            print_warning(f"[dim]{tool}[/dim] not found — install with: [cyan]{install}[/cyan]")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--full/--no-full", default=True, help="Run all modules (default: on)")
@click.option("--recon-only", is_flag=True, help="Skip vulnerability scanning")
@click.option("--vuln-only", is_flag=True, help="Skip recon, only run vuln scan")
@click.option("--depth", default=3, show_default=True, help="Crawl depth")
@click.option("--threads", default=50, show_default=True, help="Concurrent threads/tasks")
@click.option("--rate-limit", default=10.0, show_default=True, help="Requests per second (stealth)")
@click.option("--timeout", default=10, show_default=True, help="Per-request timeout (seconds)")
@click.option("--output", "-o", default=None, help="Output directory (default: ./reports/<target>)")
@click.option("--stealth", is_flag=True, help="Enable stealth mode (slower, quieter)")
@click.option("--no-nikto", is_flag=True, help="Skip Nikto scan")
@click.option("--no-nuclei", is_flag=True, help="Skip Nuclei scan")
@click.option("--active-subs", is_flag=True, help="Active DNS brute-force for subdomains")
@click.option("--wordlist", default=None, help="Custom subdomain wordlist path")
@click.option("--ai-summary", is_flag=True, help="Enable AI-assisted findings summary")
@click.option("--ai-key", default=None, envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
@click.option("--full-ports", is_flag=True, help="Scan all 65535 ports (slow!)")
@click.option("--ignore-robots", is_flag=True, help="Ignore robots.txt when crawling")
@click.option("--no-report", is_flag=True, help="Skip HTML report generation")
@click.option("--accept-risk", is_flag=True, help="Skip authorization prompt (for automation)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.version_option("1.0.0", "-V", "--version", prog_name="Recon47")
def main(
    target, full, recon_only, vuln_only, depth, threads, rate_limit, timeout,
    output, stealth, no_nikto, no_nuclei, active_subs, wordlist, ai_summary,
    ai_key, full_ports, ignore_robots, no_report, accept_risk, verbose,
):
    """
    \b
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║╚════██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║    ██╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║   ██╔╝
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║     ██║   ██║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═╝   ╚═╝

    Automated Reconnaissance & Vulnerability Assessment Framework
    Author: 0xMasruful | Use only on authorized targets!

    TARGET: Domain, subdomain, URL, or IP address
    """
    print_banner()

    # Authorization prompt
    if not accept_risk:
        console.print(
            "[bold yellow]⚠  IMPORTANT:[/bold yellow] Only scan targets you own or have "
            "explicit written authorization to test.\n"
            "   Unauthorized scanning is illegal and unethical.\n"
        )
        try:
            confirm = input("  I confirm this target is authorized for security testing [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = "n"
        if confirm not in ("y", "yes"):
            print_error("Scan aborted. Please confirm authorization before proceeding.")
            sys.exit(0)
        console.print()

    # Check optional tools
    _check_tools()
    console.print()

    # Parse target
    try:
        scheme, host, port, base_url = _parse_target(target)
    except Exception as e:
        print_error(f"Invalid target: {e}")
        sys.exit(1)

    print_info(f"Target  → [bright_cyan]{base_url}[/bright_cyan]")
    print_info(f"Host    → {host}")
    print_info(f"Mode    → {'Recon only' if recon_only else 'Vuln only' if vuln_only else 'Full scan'}")
    if stealth:
        print_info("[yellow]Stealth mode enabled[/yellow]")
    console.print()

    # Output directory
    safe_host = host.replace(".", "_").replace(":", "_")
    out_dir = Path(output) if output else Path("reports") / safe_host
    out_dir.mkdir(parents=True, exist_ok=True)
    print_info(f"Output  → {out_dir.resolve()}")
    console.print()

    # Build context
    from recon47.context import ScanContext
    ctx = ScanContext(
        target=target,
        scheme=scheme,
        host=host,
        port=port,
        base_url=base_url,
        output_dir=out_dir,
        threads=threads,
        rate_limit=rate_limit,
        timeout=timeout,
        depth=depth,
        stealth=stealth,
        verbose=verbose,
        no_vuln=(recon_only or no_nikto and no_nuclei),
        no_report=no_report,
        ai_summary_enabled=ai_summary,
        ignore_robots=ignore_robots,
        full_ports=full_ports,
        active_subdomain=active_subs,
        wordlist=wordlist,
    )

    if ai_key:
        os.environ["ANTHROPIC_API_KEY"] = ai_key

    # Handle vuln-only: skip recon
    if vuln_only:
        ctx.no_vuln = False

    # Run the pipeline
    try:
        from recon47.engine import run_pipeline
        asyncio.run(run_pipeline(ctx))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        # Still try to save partial results
        try:
            from recon47.reporter import generate_html_report
            if not no_report and len(ctx.all_vulnerabilities()) + len(ctx.endpoints) > 0:
                report_path = generate_html_report(ctx)
                console.print(f"[dim]Partial report saved → {report_path}[/dim]")
        except Exception:
            pass
        sys.exit(130)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
