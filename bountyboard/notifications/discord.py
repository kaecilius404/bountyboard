"""Discord webhook notifications for critical findings."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": 0xEF4444,
    "HIGH": 0xF59E0B,
    "MEDIUM": 0x3B82F6,
    "LOW": 0x6B7280,
}

SEVERITY_EMOJIS = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️",
    "MEDIUM": "🔵",
    "LOW": "⬜",
}


async def send_discord_finding(webhook_url: str, finding: dict,
                                program_name: str = "") -> bool:
    """Send a single finding to Discord as an embed."""
    if not webhook_url:
        return False

    sev = finding.get("severity", "LOW")
    check = finding.get("check_name", "")
    url = finding.get("url", "")
    snippet = (finding.get("response_snippet") or "")[:500]
    emoji = SEVERITY_EMOJIS.get(sev, "")

    embed = {
        "title": f"{emoji} [{sev}] {check}",
        "color": SEVERITY_COLORS.get(sev, 0x6B7280),
        "description": finding.get("description", ""),
        "fields": [
            {"name": "URL", "value": f"`{url[:200]}`", "inline": False},
            {"name": "Status Code", "value": str(finding.get("status_code", "")), "inline": True},
            {"name": "Response Size", "value": f"{finding.get('response_size', 0):,} bytes", "inline": True},
        ],
        "footer": {"text": f"BountyBoard{' — ' + program_name if program_name else ''}"},
        "timestamp": finding.get("found_at", ""),
    }

    if snippet:
        embed["fields"].append({
            "name": "Evidence",
            "value": f"```{snippet[:300]}```",
            "inline": False,
        })

    payload = {
        "username": "BountyBoard",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [embed],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status in (200, 204):
                    return True
                else:
                    logger.warning(f"[discord] HTTP {resp.status}: {await resp.text()}")
                    return False
    except Exception as e:
        logger.error(f"[discord] Failed to send notification: {e}")
        return False


async def send_discord_summary(webhook_url: str, stats: dict,
                                new_findings: int = 0) -> bool:
    """Send a scan summary to Discord."""
    if not webhook_url:
        return False

    embed = {
        "title": "📊 BountyBoard Scan Complete",
        "color": 0x00D4AA,
        "fields": [
            {"name": "Subdomains", "value": f"{stats.get('total_subdomains', 0):,}", "inline": True},
            {"name": "Live Services", "value": f"{stats.get('total_services', 0):,}", "inline": True},
            {"name": "New Findings", "value": str(new_findings), "inline": True},
            {"name": "Critical", "value": str(stats.get("findings_critical", 0)), "inline": True},
            {"name": "High", "value": str(stats.get("findings_high", 0)), "inline": True},
            {"name": "Medium", "value": str(stats.get("findings_medium", 0)), "inline": True},
        ],
    }

    payload = {"username": "BountyBoard", "embeds": [embed]}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status in (200, 204)
    except Exception as e:
        logger.error(f"[discord] Summary failed: {e}")
        return False
