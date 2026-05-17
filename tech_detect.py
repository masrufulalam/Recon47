"""
modules/tech_detect.py — Technology & WAF/CDN fingerprinting
Author: 0xMasruful
"""

from __future__ import annotations

import re
from typing import Any

from utils.output import print_module_header, print_info, print_warning, print_success
from utils.http_client import build_client, safe_get

# ── WAF Signatures ─────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": [
        ("header", "server", "cloudflare"),
        ("header", "cf-ray", None),
        ("header", "cf-cache-status", None),
    ],
    "Akamai": [
        ("header", "x-check-cacheable", None),
        ("header", "akamai-origin-hop", None),
        ("header", "x-akamai-transformed", None),
    ],
    "AWS WAF": [
        ("header", "x-amzn-requestid", None),
        ("header", "x-amz-cf-id", None),
    ],
    "ModSecurity": [
        ("header", "server", "mod_security"),
        ("body", None, "mod_security"),
    ],
    "Sucuri": [
        ("header", "x-sucuri-id", None),
        ("header", "server", "sucuri"),
    ],
    "Imperva": [
        ("header", "x-iinfo", None),
        ("header", "x-cdn", "imperva"),
    ],
    "F5 BIG-IP": [
        ("header", "server", "bigip"),
        ("header", "x-wa-info", None),
    ],
}

# ── CDN Signatures ─────────────────────────────────────────────────────────────
CDN_SIGNATURES = {
    "Cloudflare": [("header", "cf-ray", None)],
    "Fastly": [("header", "x-fastly-request-id", None)],
    "Varnish": [("header", "via", "varnish")],
    "Nginx": [("header", "server", "nginx")],
    "Apache": [("header", "server", "apache")],
    "Vercel": [("header", "x-vercel-id", None)],
    "Netlify": [("header", "server", "netlify")],
    "AWS CloudFront": [("header", "x-amz-cf-id", None)],
}

# ── Technology Patterns ────────────────────────────────────────────────────────
TECH_PATTERNS = {
    "WordPress": [
        ("body", r"wp-content|wp-includes|/wp-login\.php"),
        ("header", "x-powered-by", r"wp"),
    ],
    "Drupal": [
        ("body", r"drupal|/sites/default/files"),
        ("header", "x-generator", r"drupal"),
    ],
    "Joomla": [
        ("body", r"/components/com_|joomla"),
    ],
    "React": [
        ("body", r"_react|ReactDOM|__REACT|data-reactroot"),
    ],
    "Vue.js": [
        ("body", r"vue\.js|vuejs|__vue__"),
    ],
    "Angular": [
        ("body", r"ng-version|angular\.js|angular/core"),
    ],
    "Next.js": [
        ("body", r"__NEXT_DATA__|_next/static"),
    ],
    "Laravel": [
        ("header", "set-cookie", r"laravel_session"),
        ("body", r"laravel"),
    ],
    "Django": [
        ("header", "x-frame-options", r"SAMEORIGIN"),
        ("header", "set-cookie", r"csrftoken"),
    ],
    "Ruby on Rails": [
        ("header", "x-powered-by", r"phusion passenger"),
        ("header", "set-cookie", r"_session"),
    ],
    "PHP": [
        ("header", "x-powered-by", r"php"),
        ("header", "set-cookie", r"PHPSESSID"),
    ],
    "ASP.NET": [
        ("header", "x-powered-by", r"asp\.net"),
        ("header", "x-aspnet-version", None),
        ("header", "set-cookie", r"ASP\.NET_SessionId"),
    ],
    "Java/Spring": [
        ("header", "set-cookie", r"JSESSIONID"),
    ],
    "Bootstrap": [
        ("body", r"bootstrap\.min|twitter-bootstrap|class=\"[^\"]*col-md"),
    ],
    "jQuery": [
        ("body", r"jquery\.min|jQuery\.fn\.jquery"),
    ],
    "Tailwind CSS": [
        ("body", r"tailwind"),
    ],
    "Nginx": [
        ("header", "server", r"nginx"),
    ],
    "Apache": [
        ("header", "server", r"apache"),
    ],
    "IIS": [
        ("header", "server", r"microsoft-iis"),
    ],
    "Cloudflare": [
        ("header", "server", r"cloudflare"),
    ],
    "Node.js": [
        ("header", "x-powered-by", r"express|node"),
    ],
    "Elasticsearch": [
        ("body", r"\"tagline\" : \"You Know, for Search\""),
    ],
    "Swagger/OpenAPI": [
        ("body", r"swagger-ui|openapi"),
    ],
}


def _match_signature(headers: dict, body: str, rule_type: str, key: str | None, pattern: str | None) -> bool:
    if rule_type == "header":
        val = headers.get(key.lower(), "") if key else ""
        if pattern is None:
            return bool(val)
        return bool(re.search(pattern, val, re.IGNORECASE))
    elif rule_type == "body":
        return bool(re.search(key or pattern, body, re.IGNORECASE))
    return False


async def run_tech_detect(ctx) -> None:
    """Detect technologies, WAF, and CDN from HTTP responses."""
    print_module_header("Technology Detection", ctx.base_url)

    detected: list[dict] = []

    async with build_client(timeout=ctx.timeout, stealth=ctx.stealth) as client:
        resp = await safe_get(client, ctx.base_url)
        if not resp:
            print_warning("Could not reach target for tech detection")
            ctx.module_status["tech"] = "warn"
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text
        except Exception:
            pass

        # Server / X-Powered-By quick display
        if "server" in headers:
            print_info(f"Server       → {headers['server']}")
        if "x-powered-by" in headers:
            print_info(f"X-Powered-By → {headers['x-powered-by']}")

        # --- WAF Detection ---
        for waf_name, sigs in WAF_SIGNATURES.items():
            for rule_type, key, pattern in sigs:
                if _match_signature(headers, body, rule_type, key, pattern):
                    ctx.waf = waf_name
                    print_info(f"WAF          → [yellow]{waf_name}[/yellow]")
                    break

        # --- CDN Detection ---
        for cdn_name, sigs in CDN_SIGNATURES.items():
            for rule_type, key, pattern in sigs:
                if _match_signature(headers, body, rule_type, key, pattern):
                    ctx.cdn = cdn_name
                    if ctx.verbose:
                        print_info(f"CDN          → {cdn_name}")
                    break

        # --- Technology Stack ---
        for tech_name, patterns in TECH_PATTERNS.items():
            for rule_type, key, pattern in patterns:
                if _match_signature(headers, body, rule_type, key, pattern):
                    version = _extract_version(headers, body, tech_name)
                    detected.append({
                        "name": tech_name,
                        "version": version,
                        "confidence": "medium",
                    })
                    break

    ctx.technologies = detected
    ctx.module_status["tech"] = "ok"
    print_success(f"Tech detection complete — {len(detected)} technologies found")
    for t in detected:
        ver = f" {t['version']}" if t.get("version") else ""
        print_info(f"  {t['name']}{ver}")


def _extract_version(headers: dict, body: str, tech: str) -> str:
    """Attempt to extract version number for a technology."""
    version_patterns = {
        "PHP": r"PHP/([0-9\.]+)",
        "Nginx": r"nginx/([0-9\.]+)",
        "Apache": r"Apache/([0-9\.]+)",
        "IIS": r"IIS/([0-9\.]+)",
        "WordPress": r"WordPress ([0-9\.]+)",
        "jQuery": r"jquery[/-]([0-9\.]+)",
    }
    pattern = version_patterns.get(tech)
    if not pattern:
        return ""
    for text in [str(headers), body[:5000]]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


# ══════════════════════════════════════════════════════════════════════════════
"""
modules/header_analyzer.py — HTTP Security Header Audit
Author: 0xMasruful
"""

SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "HIGH",
        "recommendation": "Implement a restrictive CSP policy.",
    },
    "x-frame-options": {
        "description": "X-Frame-Options (Clickjacking protection)",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options (MIME sniffing)",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "description": "Referrer-Policy",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Permissions-Policy",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=()",
    },
    "x-xss-protection": {
        "description": "X-XSS-Protection",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (legacy browsers)",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-Origin-Opener-Policy",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-Origin-Resource-Policy",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}


async def run_header_analyzer(ctx) -> None:
    """Audit HTTP security headers."""
    print_module_header("Header Analyzer", ctx.base_url)

    issues: list[dict] = []

    async with build_client(timeout=ctx.timeout, stealth=ctx.stealth) as client:
        resp = await safe_get(client, ctx.base_url)
        if not resp:
            print_warning("Could not reach target for header analysis")
            ctx.module_status["headers"] = "warn"
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        ctx.headers = dict(resp.headers)

        # Missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                issues.append({
                    "title": f"Missing Header: {header}",
                    "description": info["description"],
                    "severity": info["severity"],
                    "recommendation": info["recommendation"],
                    "type": "missing_header",
                })
                if ctx.verbose:
                    print_warning(f"  Missing: {header}")

        # CORS misconfiguration
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            issues.append({
                "title": "Permissive CORS: Access-Control-Allow-Origin: *",
                "description": "Any origin can make cross-origin requests",
                "severity": "HIGH",
                "recommendation": "Restrict CORS to specific trusted origins",
                "type": "cors_misconfiguration",
            })

        # Cookie analysis
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            if "secure" not in set_cookie.lower():
                issues.append({
                    "title": "Cookie missing Secure flag",
                    "description": f"Cookie: {set_cookie[:80]}",
                    "severity": "MEDIUM",
                    "recommendation": "Add Secure flag to all cookies",
                    "type": "cookie_flag",
                })
            if "httponly" not in set_cookie.lower():
                issues.append({
                    "title": "Cookie missing HttpOnly flag",
                    "description": f"Cookie: {set_cookie[:80]}",
                    "severity": "MEDIUM",
                    "recommendation": "Add HttpOnly flag to all cookies",
                    "type": "cookie_flag",
                })
            if "samesite" not in set_cookie.lower():
                issues.append({
                    "title": "Cookie missing SameSite attribute",
                    "description": f"Cookie: {set_cookie[:80]}",
                    "severity": "LOW",
                    "recommendation": "Add SameSite=Strict or SameSite=Lax",
                    "type": "cookie_flag",
                })

        # Information disclosure
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if h in headers:
                issues.append({
                    "title": f"Server Information Disclosure via {h}",
                    "description": f"Header reveals: {headers[h]}",
                    "severity": "LOW",
                    "recommendation": f"Remove or obfuscate the {h} header",
                    "type": "info_disclosure",
                })

    ctx.header_issues = issues
    ctx.module_status["headers"] = "ok"
    print_success(f"Header analysis complete — {len(issues)} issues found")
