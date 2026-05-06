"""Exposure scanning engine — checks all live services for sensitive exposures."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

from .checks import ALL_CHECKS, ExposureCheck

logger = logging.getLogger(__name__)


@dataclass
class ExposureResult:
    """Result of a single exposure check."""
    check_name: str
    url: str
    base_url: str
    status_code: int
    response_size: int
    response_snippet: str
    severity: str
    description: str
    confirmed: bool = False
    error: Optional[str] = None


def _make_ssl_context():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _check_one(session: aiohttp.ClientSession, base_url: str,
                     check: ExposureCheck, timeout: int = 10) -> Optional[ExposureResult]:
    """Perform a single exposure check against a base URL."""
    url = base_url.rstrip("/") + check.path
    is_https = url.startswith("https://")

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            ssl=_make_ssl_context() if is_https else False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; BountyBoard/1.0)",
                **check.extra_headers,
            },
        ) as resp:
            if resp.status not in check.valid_status_codes:
                return None

            # Read body (max 10KB for validation)
            try:
                body_bytes = await resp.content.read(10240)
                body = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body = ""

            size = len(body_bytes) if "body_bytes" in dir() else 0

            # Minimum size check
            if size < check.min_size:
                return None

            # Body contains check
            if check.body_contains and check.body_contains.lower() not in body.lower():
                return None

            # Body NOT contains check (false positive filter)
            if check.body_not_contains and check.body_not_contains.lower() in body.lower():
                return None

            snippet = body[:500].replace("\n", " ").replace("\r", "").strip()

            return ExposureResult(
                check_name=check.name,
                url=url,
                base_url=base_url,
                status_code=resp.status,
                response_size=size,
                response_snippet=snippet,
                severity=check.severity,
                description=check.description,
                confirmed=True,
            )

    except asyncio.TimeoutError:
        return None
    except aiohttp.ClientConnectorError:
        return None
    except aiohttp.ClientSSLError:
        return None
    except Exception as e:
        logger.debug(f"[exposure] {url}: {e}")
        return None


class ExposureScanner:
    """Scans live HTTP services for sensitive exposures."""

    def __init__(self, concurrency: int = 50, timeout: int = 10,
                 checks: Optional[list[ExposureCheck]] = None):
        self.concurrency = concurrency
        self.timeout = timeout
        self.checks = checks or ALL_CHECKS

    async def scan_service(self, base_url: str) -> list[ExposureResult]:
        """Run all exposure checks against a single service URL."""
        findings = []
        semaphore = asyncio.Semaphore(self.concurrency)

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.concurrency,
            force_close=True,
            enable_cleanup_closed=True,
        )

        async def bounded_check(check: ExposureCheck) -> Optional[ExposureResult]:
            async with semaphore:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers={"User-Agent": "Mozilla/5.0 (compatible; BountyBoard/1.0)"},
                ) as session:
                    return await _check_one(session, base_url, check, self.timeout)

        tasks = [bounded_check(c) for c in self.checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, ExposureResult):
                findings.append(r)
                logger.info(
                    f"[{r.severity}] {r.check_name} @ {r.url}"
                )

        return findings

    async def scan_all(self, service_urls: list[str],
                        batch_size: int = 20) -> dict[str, list[ExposureResult]]:
        """
        Scan all service URLs for exposures.
        Returns dict mapping base_url -> list of findings.
        """
        all_findings: dict[str, list[ExposureResult]] = {}
        total = len(service_urls)

        for i in range(0, total, batch_size):
            batch = service_urls[i: i + batch_size]
            batch_tasks = [self.scan_service(url) for url in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            for url, result in zip(batch, batch_results):
                if isinstance(result, list):
                    if result:
                        all_findings[url] = result
                        severities = {}
                        for f in result:
                            severities[f.severity] = severities.get(f.severity, 0) + 1
                        logger.info(
                            f"[exposure] {url}: {len(result)} findings — {severities}"
                        )
                else:
                    logger.debug(f"[exposure] {url}: scan error: {result}")

            logger.info(
                f"[exposure] scanned {i + len(batch)}/{total} services, "
                f"{sum(len(v) for v in all_findings.values())} total findings"
            )

        return all_findings
