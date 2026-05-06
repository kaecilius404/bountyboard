"""HackerTarget free API discovery."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class HackerTargetDiscovery(BaseDiscovery):
    name = "hackertarget"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = await self._get_text(url)

        if text and "error" not in text.lower()[:50]:
            for line in text.splitlines():
                line = line.strip()
                if "," in line:
                    hostname = line.split(",")[0].strip()
                    subdomains.update(extract_subdomains(hostname, domain))
                else:
                    subdomains.update(extract_subdomains(line, domain))

        return subdomains
