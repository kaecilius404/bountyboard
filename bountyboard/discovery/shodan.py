"""Shodan discovery — finds hosts by SSL cert and org name."""

from __future__ import annotations

import asyncio
import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class ShodanDiscovery(BaseDiscovery):
    name = "shodan"
    requires_key = True

    async def discover(self, domain: str) -> Set[str]:
        if not self.api_key:
            return set()

        subdomains: Set[str] = set()

        # Search for SSL certs matching the domain
        queries = [
            f"ssl:{domain}",
            f"hostname:{domain}",
        ]

        for query in queries:
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "facets": "ip",
                "minify": "true",
            }

            data = await self._get_json(url, params=params)

            if not isinstance(data, dict):
                continue

            for match in data.get("matches", []):
                # Extract hostnames from SSL cert
                ssl_data = match.get("ssl", {})
                cert = ssl_data.get("cert", {})
                subject = cert.get("subject", {})
                cn = subject.get("CN", "")
                if cn:
                    subdomains.update(extract_subdomains(cn, domain))

                # Extract from SAN extensions
                extensions = cert.get("extensions", [])
                for ext in extensions:
                    if ext.get("name") == "subjectAltName":
                        data_str = ext.get("data", "")
                        subdomains.update(extract_subdomains(data_str, domain))

                # Extract hostnames field
                hostnames = match.get("hostnames", [])
                for h in hostnames:
                    subdomains.update(extract_subdomains(h, domain))

            await asyncio.sleep(1)  # Shodan rate limit: 1 req/sec

        return subdomains
