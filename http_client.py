"""
utils/http_client.py — Shared async HTTP client
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


def build_client(timeout: int = 10, stealth: bool = False, verify: bool = False) -> httpx.AsyncClient:
    """Build a configured async HTTP client."""
    headers = dict(DEFAULT_HEADERS)
    if stealth:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    else:
        headers["User-Agent"] = USER_AGENTS[0]

    return httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        verify=verify,
        http2=True,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    stealth: bool = False,
    retries: int = 2,
    **kwargs: Any,
) -> httpx.Response | None:
    """GET with retry + optional stealth jitter."""
    for attempt in range(retries + 1):
        try:
            if stealth:
                await asyncio.sleep(random.uniform(0.3, 1.5))
            resp = await client.get(url, **kwargs)
            return resp
        except (httpx.RequestError, httpx.HTTPStatusError):
            if attempt == retries:
                return None
            await asyncio.sleep(2 ** attempt * 0.5)
    return None
