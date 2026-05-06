"""Screenshot capture engine using Playwright headless Chromium."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """Captures screenshots of live HTTP services using Playwright."""

    def __init__(self, output_dir: str = "screenshots",
                 timeout: int = 20, concurrency: int = 5):
        self.output_dir = Path(output_dir)
        self.timeout = timeout * 1000  # Playwright uses milliseconds
        self.concurrency = concurrency
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _url_to_filename(self, url: str) -> str:
        """Convert URL to safe filename."""
        import re
        safe = re.sub(r"[^\w\-.]", "_", url.replace("://", "_"))
        return safe[:200]  # Filesystem limit

    async def capture(self, url: str) -> Optional[str]:
        """
        Capture screenshot of URL.
        Returns path to screenshot or None on failure.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
            return None

        filename = self._url_to_filename(url) + ".png"
        thumb_filename = self._url_to_filename(url) + "_thumb.png"
        output_path = self.output_dir / filename
        thumb_path = self.output_dir / thumb_filename

        if output_path.exists():
            return str(output_path)

        console_errors = []
        network_requests = []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--ignore-certificate-errors",
                        "--ignore-ssl-errors",
                    ],
                )
                context = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                )
                page = await context.new_page()

                # Capture console errors
                page.on("console", lambda msg: console_errors.append({
                    "type": msg.type,
                    "text": msg.text,
                }) if msg.type == "error" else None)

                # Capture network requests (for API endpoint discovery)
                page.on("request", lambda req: network_requests.append(req.url)
                        if req.resource_type in ["fetch", "xhr"] else None)

                try:
                    await page.goto(url, wait_until="load", timeout=self.timeout)
                except Exception:
                    # Try with domcontentloaded if load times out
                    try:
                        await page.goto(url, wait_until="domcontentloaded",
                                        timeout=self.timeout // 2)
                    except Exception:
                        pass

                # Wait for JS rendering
                await asyncio.sleep(3)

                # Full page screenshot
                await page.screenshot(
                    path=str(output_path),
                    full_page=True,
                    type="png",
                )

                await browser.close()

            # Generate thumbnail
            if output_path.exists():
                await self._make_thumbnail(str(output_path), str(thumb_path))
                return str(output_path)

        except asyncio.TimeoutError:
            logger.debug(f"[screenshot] timeout: {url}")
        except Exception as e:
            logger.debug(f"[screenshot] error for {url}: {e}")

        return None

    async def _make_thumbnail(self, source: str, dest: str) -> None:
        """Create a 400px-wide thumbnail."""
        try:
            from PIL import Image
            with Image.open(source) as img:
                ratio = 400 / img.width
                new_height = int(img.height * ratio)
                thumb = img.resize((400, new_height), Image.LANCZOS)
                thumb.save(dest, "PNG", optimize=True)
        except ImportError:
            logger.debug("Pillow not installed, skipping thumbnail")
        except Exception as e:
            logger.debug(f"Thumbnail error: {e}")

    async def capture_batch(self, urls: list[str]) -> dict[str, Optional[str]]:
        """Capture screenshots for multiple URLs concurrently."""
        semaphore = asyncio.Semaphore(self.concurrency)
        results: dict[str, Optional[str]] = {}

        async def bounded_capture(url: str) -> tuple[str, Optional[str]]:
            async with semaphore:
                path = await self.capture(url)
                return url, path

        tasks = [bounded_capture(u) for u in urls]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for outcome in outcomes:
            if isinstance(outcome, tuple):
                url, path = outcome
                results[url] = path
                if path:
                    logger.info(f"[screenshot] captured: {url}")
                else:
                    logger.debug(f"[screenshot] failed: {url}")

        return results
