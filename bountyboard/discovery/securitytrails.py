"""SecurityTrails API discovery (requires API key)."""

from __future__ import annotations

import asyncio
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class SecurityTrailsDiscovery(BaseDiscovery):
    name = "securitytrails"
    requires_key = True

    async def discover(self, domain: str) -> Set[str]:
        if not self.api_key:
            return set()

        subdomains: Set[str] = set()
        headers = {"APIKEY": self.api_key, "Accept": "application/json"}

        # Get subdomain list
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
        data = await self._get_json(url, headers=headers)

        if isinstance(data, dict):
            for sub in data.get("subdomains", []):
                full = f"{sub}.{domain}"
                subdomains.add(full)

        await asyncio.sleep(1)

        # Get historical DNS
        hist_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        hist_data = await self._get_json(hist_url, headers=headers)

        if isinstance(hist_data, dict):
            for record in hist_data.get("records", []):
                # Historical A records — IP ranges reveal cloud usage
                pass  # IPs handled by DNS phase

        return subdomains
