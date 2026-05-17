"""
modules/js_extractor.py — JavaScript secret hunter & directory brute-forcer
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from utils.output import print_module_header, print_info, print_warning, print_success, print_finding
from utils.http_client import build_client, safe_get

# ── Secret detection patterns ─────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}",                             "HIGH"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    ("GitHub Token",        r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}", "CRITICAL"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}",                      "HIGH"),
    ("Stripe Secret",       r"sk_live_[0-9a-zA-Z]{24}",                     "CRITICAL"),
    ("Stripe Publishable",  r"pk_live_[0-9a-zA-Z]{24}",                     "MEDIUM"),
    ("Slack Token",         r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",            "HIGH"),
    ("SendGrid API Key",    r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "HIGH"),
    ("JWT Token",           r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", "MEDIUM"),
    ("Private Key",         r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY",    "CRITICAL"),
    ("Password in code",    r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"\s]{6,}['\"]", "HIGH"),
    ("API Key generic",     r"(?i)api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9\-_]{16,}['\"]", "MEDIUM"),
    ("Bearer Token",        r"(?i)bearer\s+[a-zA-Z0-9\-_=.]{20,}",         "MEDIUM"),
    ("Internal URL",        r"(?i)https?://(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\S+", "LOW"),
    ("Source Map",          r"//[#@]\s*sourceMappingURL=(.+\.map)",          "LOW"),
    ("Internal Endpoint",   r"(?i)/(?:admin|internal|debug|config|backup|test|dev)/\S+", "MEDIUM"),
]

# ── Directory wordlist (built-in) ─────────────────────────────────────────────
DIR_WORDLIST = [
    "admin", "administrator", "login", "panel", "dashboard", "control",
    "wp-admin", "wp-login.php", "phpmyadmin", "adminer", "cpanel",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "openapi.json",
    "backup", "backups", ".git", ".env", ".htaccess", "config", "configuration",
    "upload", "uploads", "files", "media", "static", "assets",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known", ".well-known/security.txt",
    "test", "dev", "debug", "trace", "status", "health", "metrics",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "console", "shell", "terminal", "exec",
    "install", "setup", "install.php", "setup.php",
    "phpinfo.php", "info.php", "test.php",
    "server-status", "server-info",
    "web.config", "app.config", "settings.py", "config.php", "config.yml",
    "README.md", "README", "CHANGELOG", "CHANGELOG.md",
    "old", "bak", "orig", "copy", "tmp", "temp",
    "cgi-bin", "perl", "bin",
    "logout", "register", "signup", "signin", "user", "users", "profile",
    "account", "accounts", "password", "forgot", "reset",
    "search", "sitemap", "feed", "rss",
    "docs", "doc", "documentation", "help", "faq",
    "images", "img", "css", "js", "vendor",
]


async def run_js_extractor(ctx) -> None:
    """Find JS files and scan them for secrets and endpoints."""
    print_module_header("JS Extractor", "hunting secrets & endpoints")

    # Collect JS file URLs from endpoints
    js_urls = {
        ep for ep in ctx.endpoints
        if ep.endswith(".js") or ".js?" in ep
    }

    # Also look for script tags in already-crawled pages (heuristic)
    if not js_urls and ctx.base_url:
        for path in ["/", "/app.js", "/main.js", "/bundle.js", "/static/js/main.js"]:
            js_urls.add(ctx.base_url.rstrip("/") + path)

    findings: list[dict] = []
    found_js: list[str] = []

    async with build_client(timeout=ctx.timeout, stealth=ctx.stealth) as client:
        sem = asyncio.Semaphore(ctx.threads)

        async def analyze_js(url: str):
            async with sem:
                resp = await safe_get(client, url)
                if not resp or resp.status_code != 200:
                    return
                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    return  # Skip HTML pages

                found_js.append(url)
                try:
                    content = resp.text
                except Exception:
                    return

                for name, pattern, severity in SECRET_PATTERNS:
                    for match in re.finditer(pattern, content):
                        snippet = match.group(0)[:100]
                        finding = {
                            "title": f"{name} found in {url.split('/')[-1]}",
                            "description": f"Pattern: {snippet}",
                            "severity": severity,
                            "type": "secret",
                            "source": "JS Extractor",
                            "url": url,
                            "recommendation": f"Remove hardcoded {name} from source code. Use environment variables.",
                        }
                        findings.append(finding)
                        print_finding(finding["title"][:80], severity)

        tasks = [asyncio.create_task(analyze_js(url)) for url in js_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    ctx.js_files = list(found_js)
    ctx.js_findings = findings
    ctx.module_status["js"] = "ok"
    print_success(f"JS extraction complete — {len(found_js)} JS files, {len(findings)} findings")


async def run_dir_bruteforce(ctx) -> None:
    """Brute-force common directories and paths."""
    print_module_header("Directory Brute-Force", f"{len(DIR_WORDLIST)} paths to check")

    results: list[dict] = []
    base = ctx.base_url.rstrip("/")

    sem = asyncio.Semaphore(min(ctx.threads, 30))

    async def check_path(path: str, client):
        url = f"{base}/{path}"
        async with sem:
            if ctx.stealth:
                import random
                await asyncio.sleep(random.uniform(0.05, 0.3))
            resp = await safe_get(client, url)
            if not resp:
                return
            if resp.status_code in (200, 201, 204, 301, 302, 307, 308, 403, 401):
                # Extract page title
                title = ""
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text[:4000], "lxml")
                    title_tag = soup.find("title")
                    if title_tag:
                        title = title_tag.get_text()[:60]
                except Exception:
                    pass

                severity = "INFO"
                if resp.status_code in (200, 201):
                    if any(kw in path for kw in ["admin", "panel", "phpmyadmin", ".git", ".env", "backup", "config", "shell", "debug", "actuator"]):
                        severity = "HIGH"
                    elif any(kw in path for kw in ["login", "console", "api", "graphql", "swagger"]):
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                elif resp.status_code == 403:
                    severity = "INFO"  # Exists but forbidden
                elif resp.status_code in (301, 302, 307, 308):
                    severity = "INFO"

                entry = {
                    "path": f"/{path}",
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "title": title,
                    "severity": severity,
                }
                results.append(entry)

                if severity in ("HIGH", "MEDIUM"):
                    print_finding(f"[{resp.status_code}] /{path}", severity, title)
                elif ctx.verbose:
                    print_info(f"  [{resp.status_code}] /{path}")

    async with build_client(timeout=ctx.timeout, stealth=ctx.stealth) as client:
        tasks = [asyncio.create_task(check_path(p, client)) for p in DIR_WORDLIST]
        await asyncio.gather(*tasks, return_exceptions=True)

    ctx.directories = results
    ctx.module_status["dirbust"] = "ok"
    high_value = [r for r in results if r["severity"] in ("HIGH", "MEDIUM")]
    print_success(f"Directory scan complete — {len(results)} found, {len(high_value)} interesting")
