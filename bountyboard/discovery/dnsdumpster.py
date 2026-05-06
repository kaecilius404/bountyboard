"""DNSDumpster discovery via scraping."""

from __future__ import annotations

import logging
import re
from typing import Set

from .base import BaseDiscovery, extract_subdomains

logger = logging.getLogger(__name__)


class DNSDumpsterDiscovery(BaseDiscovery):
    name = "dnsdumpster"
    requires_key = False

    async def discover(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()

        # Get CSRF token first
        base_url = "https://dnsdumpster.com/"
        html = await self._get_text(base_url)

        csrf_token = ""
        if html:
            match = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', html)
            if match:
                csrf_token = match.group(1)

        if not csrf_token:
            # Try header-based CSRF extraction
            try:
                async with self.session.get(base_url) as r:
                    csrf_token = r.cookies.get("csrftoken", {})
                    if hasattr(csrf_token, "value"):
                        csrf_token = csrf_token.value
                    else:
                        csrf_token = str(csrf_token)
            except Exception:
                pass

        if not csrf_token:
            logger.debug("[dnsdumpster] Could not get CSRF token")
            return subdomains

        # Post search request
        try:
            async with self.session.post(
                base_url,
                data={
                    "csrfmiddlewaretoken": csrf_token,
                    "targetip": domain,
                    "user": "free",
                },
                headers={
                    "Referer": base_url,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ) as r:
                if r.status == 200:
                    result_html = await r.text()
                    subdomains.update(extract_subdomains(result_html, domain))
        except Exception as e:
            logger.debug(f"[dnsdumpster] POST failed: {e}")

        return subdomains
