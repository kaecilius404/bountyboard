"""BufferOver.run passive DNS discovery."""

from __future__ import annotations

import logging
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class BufferOverDiscovery(BaseDiscovery):
    name = "bufferover"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        # BufferOver free endpoint
        endpoints = [
            f"https://dns.bufferover.run/dns?q=.{domain}",
            f"https://tls.bufferover.run/dns?q=.{domain}",
        ]

        for url in endpoints:
            data = await self._get_json(url)
            if not data or not isinstance(data, dict):
                continue

            # Results are in FDNS_A (forward DNS A records) and RDNS (reverse)
            for key in ["FDNS_A", "RDNS", "Results"]:
                records = data.get(key, []) or []
                for record in records:
                    # Format: "IP,hostname"
                    if isinstance(record, str):
                        parts = record.split(",")
                        for part in parts:
                            subdomains.update(extract_subdomains(part, domain))
                    elif isinstance(record, dict):
                        for v in record.values():
                            if isinstance(v, str):
                                subdomains.update(extract_subdomains(v, domain))

        return subdomains
