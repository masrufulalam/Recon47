"""
modules/crawler.py — Async recursive web crawler with smart deduplication
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse

from utils.output import print_module_header, print_info, print_warning, print_success, make_progress
from utils.http_client import build_client, safe_get

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# Common paths to try even without robots/sitemap
BOOTSTRAP_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/api", "/api/v1", "/graphql",
    "/swagger", "/openapi.json", "/api-docs",
]

# URL patterns that indicate interesting/dynamic endpoints
DYNAMIC_PATTERN = re.compile(r"[?&=]|/\d+(/|$)|/[a-f0-9]{8,}")

def _normalize_url(url: str) -> str:
    """Normalize URL: remove fragment, sort-consistent params."""
    try:
        p = urlparse(url)
        # Drop fragment, trailing slash normalization
        normalized = urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", p.params, p.query, ""))
        return normalized
    except Exception:
        return url


def _is_in_scope(url: str, host: str) -> bool:
    """Check if a URL belongs to the target host."""
    try:
        parsed = urlparse(url)
        return parsed.netloc == host or parsed.netloc == "" or parsed.netloc.endswith("." + host)
    except Exception:
        return False


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extract all links from HTML using BeautifulSoup or regex fallback."""
    links = []
    if BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "lxml")
            tags = (
                [(t, "href") for t in soup.find_all(["a", "link"])] +
                [(t, "src") for t in soup.find_all(["script", "img", "iframe", "frame"])] +
                [(t, "action") for t in soup.find_all("form")]
            )
            for tag, attr in tags:
                val = tag.get(attr, "")
                if val and not val.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                    links.append(urljoin(base_url, val))

            # Extract forms too
            return links
        except Exception:
            pass

    # Regex fallback
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\'#>]+)["\']', html, re.IGNORECASE):
        href = m.group(1)
        if not href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            links.append(urljoin(base_url, href))
    return links


def _extract_forms(html: str, page_url: str) -> list[dict]:
    """Extract forms from HTML."""
    forms = []
    if not BS4_AVAILABLE:
        return forms
    try:
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = urljoin(page_url, action) if action else page_url
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                fname = inp.get("name", "")
                ftype = inp.get("type", "text")
                if fname:
                    fields.append({"name": fname, "type": ftype})
            forms.append({"action": action_url, "method": method, "fields": fields, "page": page_url})
    except Exception:
        pass
    return forms


async def run_crawler(ctx) -> None:
    """Async BFS web crawler with configurable depth."""
    print_module_header("Web Crawler", f"depth={ctx.depth} threads={ctx.threads}")

    visited: set[str] = set()
    endpoints: list[str] = []
    forms: list[dict] = []
    queue: deque[tuple[str, int]] = deque()

    # Seed URLs
    for path in BOOTSTRAP_PATHS:
        seed = ctx.base_url.rstrip("/") + path
        queue.append((seed, 0))

    sem = asyncio.Semaphore(ctx.threads)
    lock = asyncio.Lock()

    async def crawl_url(url: str, depth: int, client) -> None:
        norm = _normalize_url(url)
        async with lock:
            if norm in visited or len(visited) > 5000:
                return
            visited.add(norm)

        if depth > ctx.depth:
            return

        resp = await safe_get(client, url, stealth=ctx.stealth)
        if not resp:
            return

        # Add to endpoints
        async with lock:
            if url not in endpoints:
                endpoints.append(url)

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type and "text" not in content_type:
            return

        try:
            html = resp.text
        except Exception:
            return

        # Extract & queue links
        links = _extract_links(html, url)
        page_forms = _extract_forms(html, url)
        async with lock:
            forms.extend(page_forms)

        for link in links:
            norm_link = _normalize_url(link)
            async with lock:
                already = norm_link in visited
            if not already and _is_in_scope(link, ctx.host):
                queue.append((link, depth + 1))

    async def worker(client):
        while queue:
            try:
                url, depth = queue.popleft()
            except IndexError:
                break
            async with sem:
                await crawl_url(url, depth, client)

    async with build_client(timeout=ctx.timeout, stealth=ctx.stealth) as client:
        # Run workers concurrently
        tasks = [asyncio.create_task(worker(client)) for _ in range(min(ctx.threads, 20))]

        # Keep filling workers while queue has items
        max_iter = 1000
        while any(not t.done() for t in tasks) and max_iter > 0:
            await asyncio.sleep(0.1)
            max_iter -= 1
            if not queue:
                break

        # Wait for remaining tasks
        await asyncio.gather(*tasks, return_exceptions=True)

    ctx.endpoints = list(dict.fromkeys(endpoints))  # preserve order, dedup
    ctx.forms = forms
    ctx.module_status["crawler"] = "ok"
    print_success(f"Crawl complete — {len(ctx.endpoints)} endpoints, {len(forms)} forms discovered")
    for ep in ctx.endpoints[:8]:
        marker = "[yellow]★[/yellow]" if DYNAMIC_PATTERN.search(ep) else " "
        print_info(f"  {marker} {ep[:90]}")
    if len(ctx.endpoints) > 8:
        print_info(f"  ... and {len(ctx.endpoints) - 8} more")
