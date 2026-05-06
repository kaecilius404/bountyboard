"""AlienVault OTX passive DNS discovery."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class AlienVaultDiscovery(BaseDiscovery):
    name = "alienvault"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        page = 1

        while True:
            url = (f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/"
                   f"passive_dns?limit=500&page={page}")

            headers = {}
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key

            data = await self._get_json(url, headers=headers)

            if not data or not isinstance(data, dict):
                break

            passive_dns = data.get("passive_dns", [])
            if not passive_dns:
                break

            for record in passive_dns:
                hostname = record.get("hostname", "")
                if hostname:
                    subdomains.update(extract_subdomains(hostname, domain))

            # Check if there's a next page
            if not data.get("next") or len(passive_dns) < 500:
                break

            page += 1
            if page > 20:  # Safety limit
                break

        return subdomains
