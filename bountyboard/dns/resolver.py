"""Async DNS resolution engine with full record type support."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype

logger = logging.getLogger(__name__)

# Known CDN/Cloud IP prefixes (simplified — full list in cdn_ranges.json)
CDN_CNAME_PATTERNS = {
    "cloudflare": ["cloudflare.com", "cloudflare.net"],
    "cloudfront": ["cloudfront.net"],
    "akamai": ["akamaized.net", "akamai.net", "edgesuite.net", "edgekey.net"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "incapsula": ["incapsula.com", "imperva.com"],
    "sucuri": ["sucuri.net"],
    "netlify": ["netlify.app", "netlify.com"],
    "vercel": ["vercel.app", "vercel.com", "now.sh"],
    "heroku": ["herokuapp.com", "herokussl.com"],
    "github": ["github.io", "githubusercontent.com"],
    "amazonaws": ["amazonaws.com", "aws.amazon.com"],
    "azure": ["azurewebsites.net", "azurefd.net", "cloudapp.azure.com"],
    "gcp": ["appspot.com", "run.app", "cloudfunctions.net"],
}


def classify_ip(ip: str) -> str:
    """Classify an IP address into categories."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            if ip.startswith("10."):
                return "INTERNAL_10"
            elif ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31:
                return "INTERNAL_172"
            elif ip.startswith("192.168."):
                return "INTERNAL_192"
            return "INTERNAL"
        elif addr.is_loopback:
            return "LOOPBACK"
        elif addr.is_link_local:
            return "LINK_LOCAL"
        else:
            return "PUBLIC"
    except ValueError:
        return "UNKNOWN"


def classify_cname(cname: str) -> str:
    """Classify a CNAME target into CDN/cloud categories."""
    cname_lower = cname.lower()
    for provider, patterns in CDN_CNAME_PATTERNS.items():
        if any(cname_lower.endswith("." + p) or cname_lower == p for p in patterns):
            return provider.upper()
    return "EXTERNAL"


@dataclass
class DNSResult:
    subdomain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ip_classification: str = "UNKNOWN"
    cname_classification: str = ""
    is_wildcard: bool = False
    resolves: bool = False
    error: Optional[str] = None

    @property
    def primary_ip(self) -> Optional[str]:
        return self.a_records[0] if self.a_records else None

    @property
    def all_ips(self) -> list[str]:
        return list(set(self.a_records + self.aaaa_records))


class DNSResolver:
    """Async DNS resolver with full record type support."""

    def __init__(self, concurrency: int = 200, timeout: float = 5.0,
                 nameservers: Optional[list[str]] = None):
        self.concurrency = concurrency
        self.timeout = timeout
        self.nameservers = nameservers or ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
        self._semaphore = asyncio.Semaphore(concurrency)
        self._wildcard_cache: dict[str, bool] = {}

    def _make_resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        r.nameservers = self.nameservers
        r.timeout = self.timeout
        r.lifetime = self.timeout * 2
        return r

    async def check_wildcard(self, domain: str) -> bool:
        """Check if domain has wildcard DNS."""
        if domain in self._wildcard_cache:
            return self._wildcard_cache[domain]

        probe = f"thisdoesnotexist-bountyboard-{domain.replace('.', '')}.{domain}"
        resolver = self._make_resolver()
        try:
            await resolver.resolve(probe, "A")
            self._wildcard_cache[domain] = True
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                asyncio.TimeoutError, Exception):
            self._wildcard_cache[domain] = False
            return False

    async def resolve_one(self, subdomain: str) -> DNSResult:
        """Resolve all record types for a single subdomain."""
        result = DNSResult(subdomain=subdomain)
        resolver = self._make_resolver()

        async def query(rtype: str) -> list[str]:
            try:
                answers = await resolver.resolve(subdomain, rtype)
                return [str(r) for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.resolver.NoMetaqueries):
                return []
            except (asyncio.TimeoutError, dns.exception.Timeout):
                return []
            except Exception:
                return []

        # Resolve all record types concurrently
        a, aaaa, cname, mx, ns, txt = await asyncio.gather(
            query("A"),
            query("AAAA"),
            query("CNAME"),
            query("MX"),
            query("NS"),
            query("TXT"),
        )

        result.a_records = [r.rstrip(".") for r in a]
        result.aaaa_records = [r.rstrip(".") for r in aaaa]
        result.cname_records = [r.rstrip(".") for r in cname]
        result.mx_records = [r.rstrip(".") for r in mx]
        result.ns_records = [r.rstrip(".") for r in ns]
        result.txt_records = txt

        result.resolves = bool(result.a_records or result.aaaa_records or result.cname_records)

        # Classify
        if result.a_records:
            result.ip_classification = classify_ip(result.a_records[0])
        if result.cname_records:
            result.cname_classification = classify_cname(result.cname_records[0])

        return result

    async def resolve_batch(self, subdomains: list[str]) -> list[DNSResult]:
        """Resolve a batch of subdomains concurrently."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def bounded_resolve(sub: str) -> DNSResult:
            async with semaphore:
                return await self.resolve_one(sub)

        tasks = [bounded_resolve(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for i, r in enumerate(results):
            if isinstance(r, DNSResult):
                output.append(r)
            else:
                output.append(DNSResult(subdomain=subdomains[i], error=str(r)))

        return output

    async def resolve_all(self, subdomains: list[str],
                           batch_size: int = 500) -> list[DNSResult]:
        """Resolve all subdomains in batches with progress logging."""
        total = len(subdomains)
        all_results: list[DNSResult] = []

        for i in range(0, total, batch_size):
            batch = subdomains[i: i + batch_size]
            results = await self.resolve_batch(batch)
            all_results.extend(results)
            resolved = sum(1 for r in results if r.resolves)
            logger.info(f"[dns] resolved {i + len(batch)}/{total} "
                        f"({resolved} live in this batch)")

        return all_results
