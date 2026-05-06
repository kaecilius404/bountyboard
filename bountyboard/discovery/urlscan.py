"""URLScan.io discovery — finds subdomains from scanned URLs."""

from __future__ import annotations

import asyncio
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class URLScanDiscovery(BaseDiscovery):
    name = "urlscan"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key

        # Search for domain in page domains AND hostnames
        queries = [
            f"domain:{domain}",
            f"page.domain:{domain}",
        ]

        for query in queries:
            url = f"https://urlscan.io/api/v1/search/?q={query}&size=10000&fields=page.domain"
            data = await self._get_json(url, headers=headers)

            if not data or not isinstance(data, dict):
                continue

            results = data.get("results", [])
            for result in results:
                page = result.get("page", {})
                hostname = page.get("domain", "") or page.get("apexDomain", "")
                if hostname:
                    subdomains.update(extract_subdomains(hostname, domain))

                # Also check task URL
                task = result.get("task", {})
                task_url = task.get("url", "")
                if task_url:
                    subdomains.update(extract_subdomains(task_url, domain))

            await asyncio.sleep(0.5)

        return subdomains
