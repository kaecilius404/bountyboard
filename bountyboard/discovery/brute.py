"""DNS brute-force module — only use with explicit permission."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Set

import dns.asyncresolver
import dns.exception

from .base import clean_subdomain

logger = logging.getLogger(__name__)

# Built-in wordlist (subset — full list is in data/subdomain_wordlist.txt)
BUILTIN_WORDS = [
    "www", "mail", "ftp", "admin", "dev", "test", "staging", "prod", "api",
    "app", "portal", "login", "auth", "sso", "vpn", "remote", "secure",
    "internal", "corp", "intranet", "extranet", "partner", "vendor", "client",
    "customer", "billing", "payments", "cdn", "static", "assets", "media",
    "images", "files", "docs", "help", "support", "status", "monitor",
    "analytics", "tracking", "blog", "news", "shop", "store", "cart",
    "checkout", "account", "profile", "settings", "dashboard", "panel",
    "console", "manage", "adminpanel", "control", "master", "node", "cluster",
    "lb", "loadbalancer", "proxy", "gateway", "api-gateway", "ws",
    "database", "db", "sql", "mysql", "postgres", "redis", "elastic",
    "kibana", "grafana", "prometheus", "jenkins", "gitlab", "jira", "wiki",
    "dev1", "dev2", "dev3", "stage", "staging1", "staging2", "uat", "qa",
    "test1", "test2", "demo", "preview", "beta", "alpha", "sandbox", "poc",
    "k8s", "docker", "registry", "ci", "cd", "cicd", "build", "artifact",
    "security", "soc", "vpn2", "backup", "restore", "archive", "storage",
    "voip", "sip", "pbx", "net", "network", "iot", "scada", "camera",
    "s3", "ec2", "rds", "smtp", "imap", "exchange", "ldap", "kerberos",
    "old", "new", "v2", "v3", "legacy", "deprecated", "retired", "archive",
    "us", "eu", "ap", "us-east", "eu-west", "ap-south",
]


class BruteForceDiscovery:
    """DNS brute-force subdomain discovery."""

    name = "bruteforce"

    def __init__(self, wordlist_path: str | None = None,
                 concurrency: int = 200, timeout: float = 3.0):
        self.wordlist_path = wordlist_path
        self.concurrency = concurrency
        self.timeout = timeout

    def _load_wordlist(self) -> list[str]:
        """Load wordlist from file or use built-in."""
        words = list(BUILTIN_WORDS)

        # Try data directory
        if not self.wordlist_path:
            data_path = Path(__file__).parent.parent / "data" / "subdomain_wordlist.txt"
            if data_path.exists():
                self.wordlist_path = str(data_path)

        if self.wordlist_path and Path(self.wordlist_path).exists():
            with open(self.wordlist_path) as f:
                file_words = [line.strip() for line in f if line.strip()
                              and not line.startswith("#")]
            words = list(set(words + file_words))

        return words

    async def discover(self, domain: str) -> Set[str]:
        """Brute force subdomains using DNS resolution."""
        words = self._load_wordlist()
        resolved: Set[str] = set()

        logger.info(f"[bruteforce] {domain}: testing {len(words)} words")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_word(word: str) -> str | None:
            candidate = f"{word}.{domain}"
            async with semaphore:
                try:
                    answers = await resolver.resolve(candidate, "A")
                    if answers:
                        return clean_subdomain(candidate)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout,
                        asyncio.TimeoutError, Exception):
                    pass
            return None

        # First check for wildcard
        wildcard_candidate = f"thisdoesnotexist-zz99.{domain}"
        is_wildcard = False
        try:
            await resolver.resolve(wildcard_candidate, "A")
            is_wildcard = True
            logger.warning(f"[bruteforce] {domain}: wildcard DNS detected, results unreliable")
        except Exception:
            pass

        if is_wildcard:
            logger.warning(f"[bruteforce] {domain}: skipping brute force (wildcard DNS)")
            return set()

        tasks = [check_word(w) for w in words]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, str) and r:
                resolved.add(r)

        logger.info(f"[bruteforce] {domain}: resolved {len(resolved)} subdomains")
        return resolved
