"""
modules/subdomain_enum.py — Passive (& active) subdomain enumeration
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import Set

from utils.output import console, print_module_header, print_info, print_warning, print_success
from utils.http_client import build_client, safe_get


BUILT_IN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "dev", "staging",
    "test", "api", "app", "admin", "portal", "intranet", "extranet", "secure", "login",
    "blog", "shop", "store", "cdn", "assets", "static", "media", "img", "images",
    "uploads", "files", "download", "docs", "support", "help", "forum", "community",
    "status", "monitor", "dashboard", "panel", "manage", "management", "cms", "wp",
    "webmail", "mx", "mail2", "ns1", "ns2", "dns", "gateway", "proxy", "firewall",
    "db", "database", "mysql", "postgres", "redis", "cache", "queue", "mq",
    "gitlab", "github", "jenkins", "ci", "cd", "deploy", "build",
    "beta", "alpha", "demo", "qa", "uat", "prod", "production", "preprod",
    "internal", "corp", "office", "workspace", "cloud", "aws", "azure", "gcp",
    "auth", "oauth", "sso", "id", "identity", "accounts", "account",
    "mobile", "m", "wap", "api2", "v1", "v2", "v3",
]


async def _query_crtsh(client, domain: str) -> Set[str]:
    """Query crt.sh certificate transparency logs."""
    subs: Set[str] = set()
    try:
        resp = await safe_get(client, f"https://crt.sh/?q=%.{domain}&output=json", retries=2)
        if resp and resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subs.add(sub.lower())
    except Exception:
        pass
    return subs


async def _query_hackertarget(client, domain: str) -> Set[str]:
    """Query HackerTarget subdomain finder."""
    subs: Set[str] = set()
    try:
        resp = await safe_get(client, f"https://api.hackertarget.com/hostsearch/?q={domain}", retries=2)
        if resp and resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(f".{domain}"):
                        subs.add(sub)
    except Exception:
        pass
    return subs


async def _query_wayback(client, domain: str) -> Set[str]:
    """Query Wayback Machine CDX API for subdomains."""
    subs: Set[str] = set()
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=5000"
        resp = await safe_get(client, url, retries=2)
        if resp and resp.status_code == 200:
            pattern = re.compile(r"https?://([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")")
            for m in pattern.finditer(resp.text):
                subs.add(m.group(1).lower())
    except Exception:
        pass
    return subs


async def _query_alienvault(client, domain: str) -> Set[str]:
    """Query AlienVault OTX passive DNS."""
    subs: Set[str] = set()
    try:
        resp = await safe_get(
            client,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            retries=2,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
    except Exception:
        pass
    return subs


def _resolve_host(hostname: str) -> str | None:
    """Resolve a hostname to IP. Returns None if NXDOMAIN."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


async def run_subdomain_enum(ctx) -> None:
    """Enumerate subdomains via passive OSINT sources."""
    print_module_header("Subdomain Enumeration", f"passive OSINT for {ctx.host}")

    all_subs: Set[str] = set()
    all_subs.add(ctx.host)

    async with build_client(timeout=15, stealth=ctx.stealth) as client:
        tasks = [
            _query_crtsh(client, ctx.host),
            _query_hackertarget(client, ctx.host),
            _query_wayback(client, ctx.host),
            _query_alienvault(client, ctx.host),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, set):
                all_subs |= r

    print_info(f"Raw subdomains discovered: {len(all_subs)}")

    # --- Active DNS brute-force (opt-in) ---
    if ctx.active_subdomain:
        print_info("Running active DNS brute-force...")
        for word in BUILT_IN_WORDLIST:
            candidate = f"{word}.{ctx.host}"
            ip = await asyncio.get_event_loop().run_in_executor(None, _resolve_host, candidate)
            if ip:
                all_subs.add(candidate)

    # --- Resolve and filter live subdomains ---
    resolved = []
    loop = asyncio.get_event_loop()

    sem = asyncio.Semaphore(ctx.threads)

    async def check_sub(sub: str):
        async with sem:
            ip = await loop.run_in_executor(None, _resolve_host, sub)
            if ip:
                resolved.append({"subdomain": sub, "ip": ip})
                if ctx.verbose:
                    print_info(f"  LIVE  {sub:45} → {ip}")

    await asyncio.gather(*[check_sub(s) for s in all_subs])

    ctx.subdomains = resolved
    ctx.module_status["subdomains"] = "ok"
    print_success(f"Subdomain enum complete — {len(resolved)} live subdomains")
    for sub in resolved[:10]:
        print_info(f"  {sub['subdomain']:45} → {sub['ip']}")
    if len(resolved) > 10:
        print_info(f"  ... and {len(resolved) - 10} more")
