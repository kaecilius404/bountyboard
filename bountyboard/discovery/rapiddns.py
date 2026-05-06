"""RapidDNS passive DNS discovery."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class RapidDNSDiscovery(BaseDiscovery):
    name = "rapiddns"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        url = f"https://rapiddns.io/subdomain/{domain}?full=1&down=1"
        text = await self._get_text(url)
        if text:
            subdomains.update(extract_subdomains(text, domain))

        # Also try their API
        api_url = f"https://rapiddns.io/api/subdomain/{domain}"
        data = await self._get_json(api_url)
        if isinstance(data, dict):
            for record in data.get("data", []):
                name = record.get("name", "")
                if name:
                    subdomains.update(extract_subdomains(name, domain))

        return subdomains
