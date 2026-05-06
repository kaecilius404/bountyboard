"""Finding prioritization engine — scores and ranks findings for maximum bounty impact."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Scoring matrix: (check_name pattern, public-facing, has-auth, has-sensitive) -> score boost
PRIORITY_RULES = {
    # Instant critical
    "git_head": ("CRITICAL", "Git repo exposed — full source code accessible"),
    "git_config": ("CRITICAL", "Git config with credentials exposed"),
    "git_objects": ("CRITICAL", "Git pack files — entire repo downloadable"),
    "env_file": ("CRITICAL", ".env file with credentials exposed"),
    "env_backup": ("CRITICAL", ".env backup with credentials"),
    "env_production": ("CRITICAL", "Production .env file exposed"),
    "aws_credentials": ("CRITICAL", "AWS credentials exposed — immediate account compromise"),
    "gcp_credentials": ("CRITICAL", "GCP service account key exposed"),
    "gcp_service_account": ("CRITICAL", "GCP service account exposed"),
    "ssh_rsa": ("CRITICAL", "SSH private key exposed"),
    "ssh_ed25519": ("CRITICAL", "SSH private key exposed"),
    "ssh_dir_rsa": ("CRITICAL", "SSH private key exposed"),
    "backup_sql": ("CRITICAL", "Database backup with all data exposed"),
    "dump_sql": ("CRITICAL", "Database dump exposed"),
    "sqlite_db": ("CRITICAL", "SQLite database exposed"),
    "django_sqlite": ("CRITICAL", "Django database exposed"),
    "docker_config_json": ("CRITICAL", "Docker registry credentials exposed"),
    "htpasswd": ("CRITICAL", "Password hashes exposed"),
    "actuator_env": ("CRITICAL", "All environment variables exposed via Spring Actuator"),
    "actuator_heapdump": ("CRITICAL", "JVM heap dump — all memory including secrets"),
    "jenkins_script": ("CRITICAL", "Jenkins script console — potential RCE"),
    "jenkins_script_bare": ("CRITICAL", "Jenkins script console — potential RCE"),
    "symfony_profiler": ("CRITICAL", "Symfony profiler — all request data visible"),
    "yii_debug": ("CRITICAL", "Yii debug panel exposed"),
    "private_pem": ("CRITICAL", "Private key/certificate exposed"),
    "private_key": ("CRITICAL", "Private key exposed"),
    "wp_config": ("CRITICAL", "WordPress DB credentials exposed"),
    "wp_config_bak": ("CRITICAL", "WordPress config backup exposed"),
    "backup_zip": ("CRITICAL", "Backup archive exposed"),
    "backup_tar": ("CRITICAL", "Backup archive exposed"),
    "rails_db_config": ("CRITICAL", "Database credentials in config"),
    "laravel_log": ("CRITICAL", "Laravel log with session tokens"),
    "svn_entries": ("HIGH", "SVN repository entries exposed"),
    "svn_wc": ("HIGH", "SVN working copy database exposed"),
}


@dataclass
class PrioritizedFinding:
    """A finding with enhanced priority context."""
    check_name: str
    url: str
    severity: str
    description: str
    response_snippet: str
    status_code: int
    response_size: int
    score: int  # 0-100, higher = more urgent
    manual_test_note: str
    is_forgotten_service: bool = False
    is_internal_exposed: bool = False
    is_expired_cert: bool = False
    subdomain: str = ""
    found_at: str = ""


def _is_internal_subdomain(subdomain: str) -> bool:
    """Check if subdomain name suggests internal/forgotten service."""
    internal_keywords = [
        "internal", "dev", "staging", "stage", "test", "qa", "uat",
        "beta", "alpha", "sandbox", "poc", "demo", "preview", "old",
        "legacy", "backup", "admin", "corp", "intranet", "extranet",
        "vpn", "remote", "secure", "private", "backend",
    ]
    sub_lower = subdomain.lower()
    return any(kw in sub_lower for kw in internal_keywords)


def _compute_score(finding: dict) -> int:
    """Compute a priority score 0-100 for a finding."""
    score = 0

    severity = finding.get("severity", "LOW")
    severity_scores = {"CRITICAL": 80, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
    score += severity_scores.get(severity, 0)

    # Boost for internal-looking subdomains with critical findings
    subdomain = finding.get("subdomain", "")
    if _is_internal_subdomain(subdomain) and severity in ("CRITICAL", "HIGH"):
        score += 15  # Internal services are often forgotten

    # Boost for non-standard ports (more likely forgotten)
    url = finding.get("url", "")
    non_standard_port = any(f":{p}" in url for p in [
        "8080", "8443", "3000", "4443", "5000", "7001",
        "8000", "8888", "9000", "9090", "9200", "10000"
    ])
    if non_standard_port:
        score += 5

    # Boost if it's a small response (not a default page)
    if 10 < finding.get("response_size", 0) < 5000:
        score += 3

    return min(score, 100)


def _get_manual_test_note(check_name: str, url: str, subdomain: str) -> str:
    """Generate a specific manual testing recommendation."""
    notes = {
        "git_head": (
            f"Run: git clone {url.rsplit('/.git/', 1)[0]}/.git/ /tmp/repo "
            f"or use GitTools/git-dumper to extract full source. "
            f"Look for hardcoded credentials, internal hostnames, API keys."
        ),
        "env_file": (
            f"curl {url}/.env — look for DB_PASSWORD, SECRET_KEY, API_KEY, "
            f"AWS_ACCESS_KEY_ID, STRIPE_SECRET, etc."
        ),
        "actuator_env": (
            f"curl {url}/actuator/env | jq . — look for database passwords, "
            f"API keys in property sources. Also try /actuator/heapdump."
        ),
        "actuator_heapdump": (
            f"curl -O {url}/actuator/heapdump && "
            f"java -jar jhat heapdump — search for passwords, tokens, secrets in memory."
        ),
        "jenkins_script": (
            f"Navigate to {url} — if Groovy console is accessible without auth, "
            f"try: println 'id'.execute().text for RCE. Also check /env and /credentials."
        ),
        "graphql_introspection": (
            f"curl -X POST {url}/graphql "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' "
            f"— check if introspection is enabled and map the full schema."
        ),
        "elasticsearch_cluster": (
            f"curl {url}/_cat/indices?v — list all indices. "
            f"Then: curl '{url}/INDEX_NAME/_search?size=10' to dump records. "
            f"Look for user data, PII, credentials."
        ),
        "symfony_profiler": (
            f"Navigate to {url}/_profiler — look at recent requests, "
            f"especially POST requests with form data, cookies, session tokens."
        ),
        "aws_credentials": (
            f"curl {url}/.aws/credentials — if real keys, immediately test: "
            f"aws sts get-caller-identity --profile=leaked "
            f"Report immediately, do NOT use for anything."
        ),
        "backup_sql": (
            f"curl -O {url}/backup.sql — examine for user tables, "
            f"password hashes, PII data, API keys stored in DB."
        ),
    }
    note = notes.get(check_name, "")
    if not note:
        note = (
            f"Manually verify: curl -I {url}/{check_name.replace('_', '-')} "
            f"— confirm the exposure and assess what data is accessible."
        )
    return note


def prioritize_findings(raw_findings: list[dict]) -> list[PrioritizedFinding]:
    """
    Take raw findings from DB and return prioritized list.

    Args:
        raw_findings: List of finding dicts from database

    Returns:
        Sorted list of PrioritizedFinding objects
    """
    prioritized = []

    for f in raw_findings:
        check_name = f.get("check_name", "")
        url = f.get("url", "")
        subdomain = f.get("subdomain", "")
        severity = f.get("severity", "LOW")

        score = _compute_score(f)
        note = _get_manual_test_note(check_name, url, subdomain)

        pf = PrioritizedFinding(
            check_name=check_name,
            url=url,
            severity=severity,
            description=f.get("description", PRIORITY_RULES.get(check_name, (severity, ""))[1]),
            response_snippet=f.get("response_snippet", "")[:200],
            status_code=f.get("status_code", 0),
            response_size=f.get("response_size", 0),
            score=score,
            manual_test_note=note,
            is_forgotten_service=_is_internal_subdomain(subdomain),
            subdomain=subdomain,
            found_at=f.get("found_at", ""),
        )
        prioritized.append(pf)

    # Sort: severity first, then score, then recency
    prioritized.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.severity, 99),
            -x.score,
        )
    )

    return prioritized


def generate_recommendations(findings: list[PrioritizedFinding],
                              new_subdomains: list[str],
                              dead_subdomains: list[str]) -> list[str]:
    """Generate human-readable recommendations for the morning brief."""
    recs = []

    # Critical findings first
    critical = [f for f in findings if f.severity == "CRITICAL"]
    for f in critical[:5]:  # Top 5 critical
        recs.append(
            f"🚨 CRITICAL: {f.check_name} @ {f.url} — {f.description[:80]}. "
            f"Manual test: {f.manual_test_note[:120]}"
        )

    # High findings
    high = [f for f in findings if f.severity == "HIGH"]
    for f in high[:3]:
        recs.append(
            f"⚠️  HIGH: {f.check_name} @ {f.url} — {f.description[:80]}"
        )

    # New subdomains
    if new_subdomains:
        forgotten_new = [s for s in new_subdomains if _is_internal_subdomain(s)]
        if forgotten_new:
            recs.append(
                f"🔍 NEW: {len(forgotten_new)} internal-looking subdomains appeared: "
                f"{', '.join(forgotten_new[:5])}"
            )

    # Dead subdomains
    if dead_subdomains:
        recs.append(
            f"💀 {len(dead_subdomains)} subdomains disappeared — "
            f"takeover opportunity? Check: {', '.join(dead_subdomains[:3])}"
        )

    return recs
