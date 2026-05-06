"""crt.sh Certificate Transparency log discovery."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class CrtshDiscovery(BaseDiscovery):
    name = "crt.sh"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        # Query 1: %.domain.com (direct subdomains)
        # Query 2: %.%.domain.com (sub-subdomains)
        queries = [f"%.{domain}", f"%.%.{domain}"]

        for q in queries:
            url = f"https://crt.sh/?q={q}&output=json"
            data = await self._get_json(url)

            if isinstance(data, list):
                for entry in data:
                    name_value = entry.get("name_value", "")
                    common_name = entry.get("common_name", "")
                    for name in [name_value, common_name]:
                        # Handle multi-line name_value (SANs separated by newlines)
                        for part in name.split("\n"):
                            part = part.strip().lstrip("*.")
                            if part:
                                subdomains.update(extract_subdomains(part, domain))

            # Polite rate limiting
            await asyncio.sleep(1)

        # Also query HTML table for entries that may only appear there
        html_url = f"https://crt.sh/?q=%.{domain}"
        html = await self._get_text(html_url)
        if html:
            # Extract subdomains from HTML table
            matches = re.findall(r'<TD[^>]*>([\w\.\-\*]+\.' + re.escape(domain) + r')</TD>',
                                 html, re.IGNORECASE)
            for m in matches:
                m = m.lstrip("*.")
                subdomains.update(extract_subdomains(m, domain))

        return subdomains
