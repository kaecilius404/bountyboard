"""Base class for all discovery sources."""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Set

import aiohttp

logger = logging.getLogger(__name__)

SUBDOMAIN_REGEX = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
    re.IGNORECASE,
)


def extract_subdomains(text: str, domain: str) -> Set[str]:
    """Extract valid subdomains of domain from arbitrary text."""
    domain = domain.lower()
    found = set()
    for match in SUBDOMAIN_REGEX.finditer(text.lower()):
        sub = match.group(0).rstrip(".")
        if sub.endswith("." + domain) or sub == domain:
            found.add(sub)
    return found


def clean_subdomain(sub: str) -> str:
    """Normalize a subdomain string."""
    return sub.lower().strip().rstrip(".")


class BaseDiscovery(ABC):
    """Abstract base class for all discovery modules."""

    name: str = "base"
    requires_key: bool = False

    def __init__(self, session: aiohttp.ClientSession, api_key: str = ""):
        self.session = session
        self.api_key = api_key

    @abstractmethod
    async def discover(self, domain: str) -> Set[str]:
        """Return set of discovered subdomains for domain."""
        ...

    async def safe_discover(self, domain: str) -> tuple[str, Set[str]]:
        """Wrapper that catches all errors and returns (source_name, subdomains)."""
        try:
            subs = await self.discover(domain)
            subs = {clean_subdomain(s) for s in subs if s}
            subs = {s for s in subs if s.endswith("." + domain) or s == domain}
            logger.info(f"[{self.name}] {domain}: found {len(subs)} subdomains")
            return self.name, subs
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] {domain}: timeout")
            return self.name, set()
        except aiohttp.ClientError as e:
            logger.warning(f"[{self.name}] {domain}: HTTP error: {e}")
            return self.name, set()
        except Exception as e:
            logger.warning(f"[{self.name}] {domain}: unexpected error: {e}")
            return self.name, set()

    async def _get_json(self, url: str, **kwargs) -> dict | list | None:
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=20), **kwargs) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
        except Exception as e:
            logger.debug(f"[{self.name}] GET {url} failed: {e}")
        return None

    async def _get_text(self, url: str, **kwargs) -> str:
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=20), **kwargs) as r:
                if r.status == 200:
                    return await r.text()
        except Exception as e:
            logger.debug(f"[{self.name}] GET {url} failed: {e}")
        return ""
