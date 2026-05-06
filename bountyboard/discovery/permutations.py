"""Permutation engine — generates subdomain mutations from discovered subdomains."""

from __future__ import annotations

import asyncio
import logging
from typing import Set

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

MUTATION_WORDS = [
    "admin", "api", "dev", "test", "old", "new", "backup", "legacy",
    "v2", "v3", "internal", "staging", "stage", "prod", "production",
    "demo", "beta", "alpha", "sandbox", "uat", "qa",
    "secure", "corp", "ext", "int", "pub", "private",
    "1", "2", "01", "02",
]

REGION_SUFFIXES = [
    "us", "eu", "ap", "us-east", "us-west", "eu-west", "eu-central",
    "ap-south", "ap-southeast", "us-east-1", "eu-west-1",
]


class PermutationEngine:
    """Generate and resolve subdomain permutations."""

    def __init__(self, concurrency: int = 200, timeout: float = 3.0,
                 max_per_subdomain: int = 50):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_per_subdomain = max_per_subdomain

    def generate(self, subdomain: str, domain: str) -> Set[str]:
        """Generate permutations of a given subdomain."""
        candidates: Set[str] = set()

        # Extract the subdomain prefix (without the main domain)
        if subdomain == domain:
            prefix = "www"
        elif subdomain.endswith("." + domain):
            prefix = subdomain[: -(len(domain) + 1)]
        else:
            return set()

        # Split prefix by dots and hyphens for mutation
        parts = prefix.replace("-", ".").split(".")
        base = parts[-1] if parts else prefix

        # Pattern 1: word-{prefix} and {prefix}-word
        for word in MUTATION_WORDS[: self.max_per_subdomain // 4]:
            candidates.add(f"{word}-{prefix}.{domain}")
            candidates.add(f"{prefix}-{word}.{domain}")
            candidates.add(f"{word}.{prefix}.{domain}")
            candidates.add(f"{prefix}.{word}.{domain}")

        # Pattern 2: hyphen ↔ dot
        if "-" in prefix:
            candidates.add(f"{prefix.replace('-', '.')}.{domain}")
        if "." in prefix:
            candidates.add(f"{prefix.replace('.', '-')}.{domain}")

        # Pattern 3: number suffixes
        for i in range(1, 5):
            candidates.add(f"{prefix}{i}.{domain}")
            candidates.add(f"{prefix}0{i}.{domain}")
            candidates.add(f"{prefix}-{i}.{domain}")

        # Pattern 4: region suffixes
        for region in REGION_SUFFIXES:
            candidates.add(f"{prefix}-{region}.{domain}")
            candidates.add(f"{region}-{prefix}.{domain}")

        # Pattern 5: dev/staging variants of base
        for word in ["dev", "staging", "test", "old", "new"]:
            candidates.add(f"{word}-{base}.{domain}")
            candidates.add(f"{base}-{word}.{domain}")
            candidates.add(f"{word}{base}.{domain}")

        # Remove the original
        candidates.discard(subdomain)
        # Remove duplicates and invalid
        candidates = {c for c in candidates if "." in c and len(c) < 253}

        return candidates

    async def resolve_all(self, domain: str,
                          known_subdomains: Set[str]) -> Set[str]:
        """Generate and resolve all permutations of known subdomains."""
        all_candidates: Set[str] = set()

        for sub in known_subdomains:
            generated = self.generate(sub, domain)
            all_candidates.update(generated)

        # Remove already-known subdomains
        all_candidates -= known_subdomains

        logger.info(f"[permutations] {domain}: testing {len(all_candidates)} permutations")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        semaphore = asyncio.Semaphore(self.concurrency)

        resolved: Set[str] = set()

        async def check(candidate: str) -> str | None:
            async with semaphore:
                try:
                    answers = await resolver.resolve(candidate, "A")
                    if answers:
                        return candidate.lower()
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout,
                        asyncio.TimeoutError, Exception):
                    pass
            return None

        tasks = [check(c) for c in all_candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, str):
                resolved.add(r)

        logger.info(f"[permutations] {domain}: {len(resolved)} permutations resolved")
        return resolved
