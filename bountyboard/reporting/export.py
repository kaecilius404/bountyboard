"""Export findings in multiple formats: JSON, CSV, Markdown."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path


def export_json(findings: list[dict], output_path: str) -> str:
    """Export findings as JSON."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    export_data = {
        "generated_at": datetime.utcnow().isoformat(),
        "total": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.get("severity") == sev])
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        "findings": findings,
    }

    output.write_text(json.dumps(export_data, indent=2, default=str), encoding="utf-8")
    return str(output)


def export_csv(findings: list[dict], output_path: str) -> str:
    """Export findings as CSV."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "severity", "check_name", "url", "subdomain", "status_code",
        "response_size", "response_snippet", "found_at", "still_present",
    ]

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow({k: finding.get(k, "") for k in fields})

    return str(output)


def export_markdown(findings: list[dict], output_path: str,
                     program_name: str = "Bug Bounty Target") -> str:
    """Export findings as a professional Markdown report."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        f"# BountyBoard Reconnaissance Report",
        f"",
        f"**Target:** {program_name}  ",
        f"**Generated:** {now}  ",
        f"**Total Findings:** {len(findings)}  ",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🚨 CRITICAL | {sev_counts.get('CRITICAL', 0)} |",
        f"| ⚠️ HIGH | {sev_counts.get('HIGH', 0)} |",
        f"| 🔵 MEDIUM | {sev_counts.get('MEDIUM', 0)} |",
        f"| ⬜ LOW | {sev_counts.get('LOW', 0)} |",
        f"",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        icon = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔵", "LOW": "⬜"}.get(sev, "")
        lines.append(f"## {icon} {sev} Findings ({len(sev_findings)})")
        lines.append("")

        for i, finding in enumerate(sev_findings, 1):
            check = finding.get("check_name", "")
            url = finding.get("url", "")
            status = finding.get("status_code", "")
            size = finding.get("response_size", 0)
            found_at = finding.get("found_at", "")[:16]
            snippet = (finding.get("response_snippet") or "")[:200]
            subdomain = finding.get("subdomain", "")

            lines += [
                f"### {i}. `{check}` on `{subdomain}`",
                f"",
                f"- **URL:** [{url}]({url})",
                f"- **Status:** {status}",
                f"- **Response Size:** {size:,} bytes",
                f"- **Found:** {found_at}",
                f"",
            ]

            if snippet:
                lines += [
                    f"**Evidence (first 200 bytes):**",
                    f"```",
                    snippet,
                    f"```",
                    f"",
                ]

            lines += [
                f"**Reproduction:**",
                f"```bash",
                f"curl -sk '{url}' | head -c 2000",
                f"```",
                f"",
                "---",
                f"",
            ]

    output.write_text("\n".join(lines), encoding="utf-8")
    return str(output)


def export_nuclei_targets(services: list[dict], output_path: str) -> str:
    """Export live service URLs as targets for Nuclei scanner."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    urls = sorted(set(s.get("url", "") for s in services if s.get("url")))
    output.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return str(output)


def export_subdomains_list(subdomains: list[dict], output_path: str) -> str:
    """Export subdomain list (one per line) for use with other tools."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    subs = sorted(set(s.get("subdomain", "") for s in subdomains if s.get("subdomain")))
    output.write_text("\n".join(subs) + "\n", encoding="utf-8")
    return str(output)
