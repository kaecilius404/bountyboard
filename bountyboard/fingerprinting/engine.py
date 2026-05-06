"""Wappalyzer-style technology fingerprinting engine."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SIGNATURES_PATH = Path(__file__).parent / "signatures.json"


class FingerprintEngine:
    """Detects technologies from HTTP response data."""

    def __init__(self):
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> dict:
        try:
            with open(SIGNATURES_PATH) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load fingerprint signatures: {e}")
            return {}

    def detect(self, headers: dict, body: str, cookies: list[str] = None,
               url: str = "") -> list[str]:
        """
        Detect technologies from response data.

        Args:
            headers: Response headers dict
            body: Response body text (first 50KB recommended)
            cookies: List of cookie names
            url: Request URL (for path-based detection)

        Returns:
            List of detected technology names
        """
        detected = set()
        cookies = cookies or []

        # Normalize headers for case-insensitive matching
        norm_headers = {k.lower(): v for k, v in headers.items()}
        body_lower = body.lower()

        for tech_name, sig in self.signatures.items():
            if self._matches(sig, norm_headers, body_lower, body, cookies, url):
                detected.add(tech_name)

        return sorted(detected)

    def _matches(self, sig: dict, headers: dict, body_lower: str,
                 body_orig: str, cookies: list[str], url: str) -> bool:
        """Check if a signature matches the response data."""

        # Header matching
        sig_headers = sig.get("headers", {})
        for header_name, pattern in sig_headers.items():
            header_val = headers.get(header_name.lower(), "")
            if not header_val:
                continue
            if pattern == "":
                return True  # Any non-empty value matches
            if pattern.lower() in header_val.lower():
                return True

        # Cookie matching
        sig_cookies = sig.get("cookies", [])
        for cookie_pattern in sig_cookies:
            if any(cookie_pattern.lower() in c.lower() for c in cookies):
                return True

        # Body pattern matching
        body_patterns = sig.get("body_patterns", [])
        for pattern in body_patterns:
            if pattern.lower() in body_lower:
                return True

        # Meta tag matching
        meta_patterns = sig.get("meta", {})
        for meta_name, meta_val in meta_patterns.items():
            meta_re = re.compile(
                rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+'
                rf'content=["\']?([^"\'>\s]+)',
                re.IGNORECASE
            )
            m = meta_re.search(body_orig[:8192])
            if m and meta_val.lower() in m.group(1).lower():
                return True

        # Path matching (check if URL contains any of these paths)
        path_patterns = sig.get("paths", [])
        if url and path_patterns:
            url_lower = url.lower()
            if any(p.lower() in url_lower for p in path_patterns):
                return True

        return False

    def detect_from_probe(self, probe_result) -> list[str]:
        """Detect technologies from a ProbeResult object."""
        from bountyboard.probing.http_probe import ProbeResult

        headers = probe_result.response_headers or {}

        # Extract cookie names from Set-Cookie header
        cookie_names = []
        set_cookie = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        if set_cookie:
            for cookie_line in set_cookie.split(","):
                name_part = cookie_line.split("=")[0].strip()
                if name_part:
                    cookie_names.append(name_part)

        return self.detect(
            headers=headers,
            body=probe_result.body_preview,
            cookies=cookie_names,
            url=probe_result.url,
        )

    def get_categories(self, technologies: list[str]) -> dict[str, list[str]]:
        """Group technologies by category."""
        categories: dict[str, list[str]] = {}
        for tech in technologies:
            sig = self.signatures.get(tech, {})
            cat = sig.get("category", "Other")
            categories.setdefault(cat, []).append(tech)
        return categories
