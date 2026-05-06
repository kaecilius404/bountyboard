"""CommonCrawl index discovery — finds historical URLs."""

from __future__ import annotations

import json
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class CommonCrawlDiscovery(BaseDiscovery):
    name = "commoncrawl"
    requires_key = False

    # Most recent CommonCrawl index (update periodically)
    INDEX_LIST_URL = "https://index.commoncrawl.org/collinfo.json"
    COLLINFO_FALLBACK = ["CC-MAIN-2024-10", "CC-MAIN-2023-50", "CC-MAIN-2023-40"]

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        # Get available indexes
        indexes = await self._get_available_indexes()

        # Use only the 3 most recent indexes to avoid too many requests
        for index in indexes[:3]:
            url = (
                f"https://index.commoncrawl.org/{index}-index"
                f"?url=*.{domain}/*"
                f"&output=json"
                f"&limit=50000"
                f"&fields=url"
            )
            text = await self._get_text(url)
            if not text:
                continue

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    found_url = entry.get("url", "")
                    if found_url:
                        subdomains.update(extract_subdomains(found_url, domain))
                except json.JSONDecodeError:
                    subdomains.update(extract_subdomains(line, domain))

        return subdomains

    async def _get_available_indexes(self) -> list[str]:
        """Fetch the list of available CommonCrawl indexes."""
        data = await self._get_json(self.INDEX_LIST_URL)
        if data and isinstance(data, list):
            return [entry.get("id", "") for entry in data if entry.get("id")]
        return self.COLLINFO_FALLBACK
