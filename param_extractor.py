"""
modules/param_extractor.py — URL parameter & HTML form extractor
Author: 0xMasruful
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from utils.output import print_module_header, print_info, print_warning, print_success

# Parameter names that are interesting for security testing
INTERESTING_PARAMS = {
    # Injection-prone
    "id", "user", "username", "uid", "userid", "account", "acct",
    "query", "q", "search", "s", "keyword", "term",
    "url", "uri", "path", "file", "filename", "filepath", "dir", "directory",
    "redirect", "return", "returnurl", "next", "back", "forward", "goto",
    "token", "auth", "key", "apikey", "api_key", "secret", "password", "pass",
    "cmd", "command", "exec", "execute", "shell", "run",
    "include", "require", "load", "template", "lang", "language",
    "debug", "test", "admin", "mode", "action", "type",
    "email", "mail", "to", "from", "subject", "message", "content",
    "page", "p", "pg", "offset", "limit", "count", "num",
    "format", "output", "callback", "jsonp",
    "ref", "referrer", "origin", "host",
    "sort", "order", "orderby", "column", "field", "filter",
}

FORM_INPUT_TYPES_OF_INTEREST = {
    "text", "password", "hidden", "search", "email", "url", "tel", "number"
}


async def run_param_extractor(ctx) -> None:
    """Extract GET parameters and HTML forms from crawled endpoints."""
    print_module_header("Parameter Extractor", f"{len(ctx.endpoints)} endpoints to analyze")

    params_found: list[dict] = []
    forms_found: list[dict] = []
    interesting: list[str] = []

    # --- Extract from URL query strings ---
    for url in ctx.endpoints:
        try:
            parsed = urlparse(url)
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for param_name, values in qs.items():
                    entry = {
                        "url": url,
                        "param": param_name,
                        "type": "GET",
                        "value_sample": values[0][:50] if values else "",
                        "interesting": param_name.lower() in INTERESTING_PARAMS,
                    }
                    params_found.append(entry)
                    if entry["interesting"]:
                        interesting.append(f"{param_name} @ {url[:70]}")
        except Exception:
            pass

    # --- Parse HTML forms from crawled content (if available in ctx) ---
    # Forms are expected to have been populated by the crawler
    if hasattr(ctx, "forms") and ctx.forms:
        for form in ctx.forms:
            form_fields = form.get("fields", [])
            for field in form_fields:
                fname = field.get("name", "").lower()
                if fname in INTERESTING_PARAMS:
                    interesting.append(f"FORM:{fname} @ {form.get('action','?')[:60]}")
            forms_found.append(form)

    # Smart deduplication: unique param names per URL
    seen = set()
    unique_params = []
    for p in params_found:
        key = f"{p['url']}:{p['param']}"
        if key not in seen:
            seen.add(key)
            unique_params.append(p)

    ctx.parameters = unique_params
    ctx.module_status["params"] = "ok"

    print_success(f"Parameter extraction complete — {len(unique_params)} unique params, {len(interesting)} interesting")
    for note in interesting[:20]:
        print_info(f"  [yellow]★[/yellow] {note}")
    if not unique_params:
        print_info("  No parameters found (run with deeper crawl for more coverage)")
