"""Async HTTP probing engine — probes all ports and collects full service metadata."""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

PROBE_PORTS = [80, 443, 8008, 8080, 8443, 3000, 4443, 5000, 5443,
               7001, 8000, 8888, 9000, 9090, 9200, 9443, 10000, 10443]

HTTPS_PORTS = {443, 4443, 5443, 8443, 9443, 10443}


@dataclass
class ProbeResult:
    url: str
    subdomain: str
    ip_address: str
    port: int
    is_https: bool
    status_code: Optional[int] = None
    response_headers: dict = field(default_factory=dict)
    response_size: int = 0
    response_time_ms: int = 0
    server_header: str = ""
    content_type: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    ssl_cert_subject: str = ""
    ssl_cert_issuer: str = ""
    ssl_cert_expiry: Optional[str] = None
    ssl_cert_self_signed: bool = False
    ssl_expired: bool = False
    error: Optional[str] = None
    body_preview: str = ""
    title: str = ""


def _make_ssl_context() -> ssl.SSLContext:
    """Create permissive SSL context that accepts self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _extract_cert_info(conn_info) -> dict:
    """Extract SSL certificate details from a connection."""
    info = {
        "subject": "",
        "issuer": "",
        "expiry": None,
        "self_signed": False,
        "expired": False,
    }
    try:
        if hasattr(conn_info, "get_extra_info"):
            transport = conn_info
        else:
            return info

        # aiohttp exposes SSL object
        ssl_obj = conn_info
        if ssl_obj is None:
            return info

        cert = ssl_obj.getpeercert()
        if not cert:
            # Self-signed or no cert info
            info["self_signed"] = True
            return info

        subject_parts = dict(x[0] for x in cert.get("subject", []))
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))

        info["subject"] = subject_parts.get("commonName", "")
        info["issuer"] = issuer_parts.get("commonName", "")

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info["expiry"] = expiry.isoformat()
                info["expired"] = expiry < datetime.utcnow()
            except ValueError:
                pass

        # Self-signed: subject == issuer
        if info["subject"] and info["subject"] == info["issuer"]:
            info["self_signed"] = True

    except Exception as e:
        logger.debug(f"SSL cert extraction error: {e}")

    return info


async def _probe_url(session: aiohttp.ClientSession, url: str,
                      timeout: int = 10) -> ProbeResult:
    """Probe a single URL and return full metadata."""
    parsed = url.split("://")
    is_https = parsed[0].lower() == "https"
    host_part = parsed[1].split(":")[0] if "://" in url else url
    port_part = url.split(":")[-1].split("/")[0] if ":" in url.split("://")[-1] else (
        "443" if is_https else "80"
    )

    try:
        port = int(port_part)
    except ValueError:
        port = 443 if is_https else 80

    result = ProbeResult(
        url=url,
        subdomain=host_part,
        ip_address="",
        port=port,
        is_https=is_https,
    )

    start = time.monotonic()
    redirect_chain = []

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            max_redirects=3,
            ssl=_make_ssl_context() if is_https else False,
        ) as resp:
            elapsed = int((time.monotonic() - start) * 1000)
            result.response_time_ms = elapsed
            result.status_code = resp.status
            result.response_headers = dict(resp.headers)
            result.server_header = resp.headers.get("Server", "")
            result.content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()

            # Collect redirect chain
            for hist in resp.history:
                redirect_chain.append(str(hist.url))
            result.redirect_chain = redirect_chain

            # Read body for fingerprinting (max 50KB)
            try:
                body = await resp.content.read(51200)
                result.response_size = len(body)
                result.body_preview = body[:2000].decode("utf-8", errors="replace")

                # Extract page title
                import re
                title_match = re.search(
                    rb"<title[^>]*>(.*?)</title>", body[:4096], re.IGNORECASE | re.DOTALL
                )
                if title_match:
                    result.title = title_match.group(1).decode("utf-8", errors="replace").strip()
            except Exception:
                pass

    except aiohttp.ClientConnectorError:
        result.error = "connection_refused"
    except asyncio.TimeoutError:
        result.error = "timeout"
    except aiohttp.TooManyRedirects:
        result.error = "too_many_redirects"
    except aiohttp.ClientSSLError:
        result.error = "ssl_error"
    except Exception as e:
        result.error = f"error:{type(e).__name__}"

    return result


class HTTPProber:
    """Async HTTP prober for all subdomains and ports."""

    def __init__(self, concurrency: int = 100, timeout: int = 10,
                 ports: Optional[list[int]] = None):
        self.concurrency = concurrency
        self.timeout = timeout
        self.ports = ports or PROBE_PORTS

    async def probe_subdomain(self, subdomain: str, ip: str) -> list[ProbeResult]:
        """Probe all configured ports on a subdomain."""
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ssl=False,
            force_close=True,
        )

        results = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_port(port: int) -> list[ProbeResult]:
            port_results = []
            schemes = []

            if port in HTTPS_PORTS:
                schemes = ["https", "http"]  # Try HTTPS first on HTTPS ports
            elif port == 80:
                schemes = ["http", "https"]
            else:
                schemes = ["http", "https"]  # Try both on ambiguous ports

            for scheme in schemes:
                url = f"{scheme}://{subdomain}:{port}"
                # Simplify: don't include port for standard ports
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    url = f"{scheme}://{subdomain}"

                async with semaphore:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False),
                        headers={"User-Agent": "Mozilla/5.0 (compatible; BountyBoard/1.0)"},
                    ) as session:
                        r = await _probe_url(session, url, self.timeout)
                        r.ip_address = ip
                        if r.status_code is not None:
                            port_results.append(r)
                            break  # Found something, don't try other scheme

            return port_results

        tasks = [probe_port(p) for p in self.ports]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in batch_results:
            if isinstance(batch, list):
                results.extend(batch)

        return results

    async def probe_all(self, targets: list[tuple[str, str]],
                         batch_size: int = 50) -> list[ProbeResult]:
        """
        Probe all (subdomain, ip) pairs.
        Returns all successful probe results.
        """
        all_results: list[ProbeResult] = []
        total = len(targets)

        for i in range(0, total, batch_size):
            batch = targets[i: i + batch_size]
            batch_tasks = [self.probe_subdomain(sub, ip) for sub, ip in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            live_count = 0
            for res in batch_results:
                if isinstance(res, list):
                    live_in_batch = [r for r in res if r.status_code is not None]
                    all_results.extend(live_in_batch)
                    live_count += len(live_in_batch)

            logger.info(f"[probing] {i + len(batch)}/{total} probed, "
                        f"{live_count} live services this batch, "
                        f"{len(all_results)} total")

        return all_results
