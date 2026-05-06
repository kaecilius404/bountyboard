"""CertSpotter CT log discovery — complements crt.sh."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class CertSpotterDiscovery(BaseDiscovery):
    name = "certspotter"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = await self._get_json(url, headers=headers)

        if isinstance(data, list):
            for cert in data:
                dns_names = cert.get("dns_names", [])
                for name in dns_names:
                    name = name.lstrip("*.")
                    subdomains.update(extract_subdomains(name, domain))

        return subdomains
