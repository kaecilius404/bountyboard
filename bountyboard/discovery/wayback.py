"""Wayback Machine CDX API — finds historically exposed subdomains."""

from __future__ import annotations

import json
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class WaybackDiscovery(BaseDiscovery):
    name = "wayback"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        # CDX API query — *.domain.com/* — collapse by URL key to avoid duplicates
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*"
            f"&output=json"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&limit=100000"
            f"&showResumeKey=true"
        )

        text = await self._get_text(url)
        if not text:
            return subdomains

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return subdomains

        # First row is the header ["original"]
        for row in data[1:]:
            if isinstance(row, list) and row:
                original_url = row[0]
                subdomains.update(extract_subdomains(original_url, domain))

        # Also search for the domain itself to catch www variants
        url2 = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*"
            f"&output=json"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&limit=10000"
        )
        text2 = await self._get_text(url2)
        if text2:
            try:
                data2 = json.loads(text2)
                for row in data2[1:]:
                    if isinstance(row, list) and row:
                        subdomains.update(extract_subdomains(row[0], domain))
            except json.JSONDecodeError:
                pass

        return subdomains
