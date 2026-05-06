"""Chaos by ProjectDiscovery — public subdomain dataset."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class ChaosDiscovery(BaseDiscovery):
    name = "chaos"
    requires_key = True

    async def discover(self, domain: str) -> Set[str]:
        if not self.api_key:
            return set()

        subdomains: Set[str] = set()
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": self.api_key}

        data = await self._get_json(url, headers=headers)

        if isinstance(data, dict):
            for sub in data.get("subdomains", []):
                full = f"{sub}.{domain}" if not sub.endswith(domain) else sub
                subdomains.add(full.lower())

        return subdomains
