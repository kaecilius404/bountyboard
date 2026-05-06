"""GitHub code search — finds hardcoded subdomains in public repos."""

from __future__ import annotations

import asyncio
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class GitHubDiscovery(BaseDiscovery):
    name = "github"
    requires_key = False  # Works without key, but heavily rate-limited

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "BountyBoard-Recon/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"token {self.api_key}"

        # Search code for domain mentions
        queries = [
            f'"{domain}" extension:yml',
            f'"{domain}" extension:yaml',
            f'"{domain}" extension:json',
            f'"{domain}" extension:conf',
            f'"{domain}" extension:env',
            f'"{domain}" extension:txt filename:.env',
        ]

        for query in queries:
            url = "https://api.github.com/search/code"
            params = {"q": query, "per_page": 100}

            try:
                async with self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as r:
                    if r.status == 403:
                        # Rate limited
                        logger.warning("[github] Rate limited, pausing 60s")
                        await asyncio.sleep(60)
                        continue
                    if r.status == 422:
                        # Query too complex
                        continue
                    if r.status != 200:
                        continue

                    data = await r.json()
                    items = data.get("items", [])

                    for item in items:
                        # Extract subdomains from file content URL and path
                        path = item.get("path", "")
                        html_url = item.get("html_url", "")
                        subdomains.update(extract_subdomains(path, domain))
                        subdomains.update(extract_subdomains(html_url, domain))

                        # Fetch raw content to search within
                        raw_url = item.get("url", "").replace(
                            "https://api.github.com/repos/",
                            "https://raw.githubusercontent.com/"
                        ).replace("/contents/", "/")

                        # Extract repo/branch from URL structure
                        content_url = item.get("url", "")
                        if content_url:
                            raw_content = await self._get_text(
                                content_url, headers=headers
                            )
                            subdomains.update(extract_subdomains(raw_content, domain))

            except Exception as e:
                logger.debug(f"[github] query failed: {e}")

            # Rate limit: 30 req/min unauthenticated, 100/min with token
            delay = 2 if not self.api_key else 0.6
            await asyncio.sleep(delay)

        return subdomains


# Fix missing import
import aiohttp
