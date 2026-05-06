"""Slack webhook notifications."""

from __future__ import annotations

import logging

import aiohttp

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f59e0b",
    "MEDIUM": "#3b82f6",
    "LOW": "#6b7280",
}


async def send_slack_finding(webhook_url: str, finding: dict,
                              program_name: str = "") -> bool:
    """Send a finding to Slack using Block Kit."""
    if not webhook_url:
        return False

    sev = finding.get("severity", "LOW")
    check = finding.get("check_name", "")
    url = finding.get("url", "")
    snippet = (finding.get("response_snippet") or "")[:300]
    emojis = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔵", "LOW": "⬜"}
    emoji = emojis.get(sev, "")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} [{sev}] {check}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*URL:*\n`{url[:150]}`"},
                {"type": "mrkdwn", "text": f"*Status:*\n{finding.get('status_code', '')}"},
            ],
        },
    ]

    if snippet:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Evidence:*\n```{snippet}```"},
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"BountyBoard{' | ' + program_name if program_name else ''} | {finding.get('found_at', '')[:16]}"}],
    })

    payload = {
        "attachments": [{"color": SEVERITY_COLORS.get(sev, "#6b7280"), "blocks": blocks}]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
    except Exception as e:
        logger.error(f"[slack] Failed: {e}")
        return False


async def send_slack_summary(webhook_url: str, stats: dict) -> bool:
    """Send a scan summary to Slack."""
    if not webhook_url:
        return False

    payload = {
        "text": (
            f"✅ *BountyBoard Scan Complete*\n"
            f"Subdomains: {stats.get('total_subdomains', 0):,} | "
            f"Services: {stats.get('total_services', 0):,} | "
            f"🚨 Critical: {stats.get('findings_critical', 0)} | "
            f"⚠️ High: {stats.get('findings_high', 0)}"
        )
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return resp.status == 200
    except Exception as e:
        logger.error(f"[slack] Summary failed: {e}")
        return False
