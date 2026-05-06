"""
BountyBoard Orchestration Engine

Chains all 7 phases:
  1. Subdomain Discovery
  2. DNS Resolution
  3. HTTP Probing
  4. Technology Fingerprinting
  5. Screenshot Capture
  6. Exposure Scanning
  7. Finding Prioritization
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp

from bountyboard.config import Config, Program, Settings
from bountyboard.database import Database
from bountyboard.discovery.base import BaseDiscovery
from bountyboard.discovery.permutations import PermutationEngine
from bountyboard.dns.resolver import DNSResolver
from bountyboard.exposures.scanner import ExposureScanner
from bountyboard.fingerprinting.engine import FingerprintEngine
from bountyboard.notifications.discord import send_discord_finding, send_discord_summary
from bountyboard.notifications.slack import send_slack_finding, send_slack_summary
from bountyboard.prioritization.engine import generate_recommendations, prioritize_findings
from bountyboard.probing.http_probe import HTTPProber
from bountyboard.reporting.export import export_csv, export_json, export_markdown
from bountyboard.reporting.html_report import generate_html_report
from bountyboard.reporting.terminal import print_morning_brief

logger = logging.getLogger(__name__)

SEVERITY_MIN = {
    "critical": ["CRITICAL"],
    "high": ["CRITICAL", "HIGH"],
    "medium": ["CRITICAL", "HIGH", "MEDIUM"],
    "low": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
}


def _build_discovery_sources(session: aiohttp.ClientSession,
                               settings: Settings) -> list[BaseDiscovery]:
    """Build all configured discovery sources."""
    from bountyboard.discovery.crtsh import CrtshDiscovery
    from bountyboard.discovery.alienvault import AlienVaultDiscovery
    from bountyboard.discovery.urlscan import URLScanDiscovery
    from bountyboard.discovery.wayback import WaybackDiscovery
    from bountyboard.discovery.github_search import GitHubDiscovery
    from bountyboard.discovery.commoncrawl import CommonCrawlDiscovery
    from bountyboard.discovery.rapiddns import RapidDNSDiscovery
    from bountyboard.discovery.bufferover import BufferOverDiscovery
    from bountyboard.discovery.certspotter import CertSpotterDiscovery
    from bountyboard.discovery.dnsdumpster import DNSDumpsterDiscovery
    from bountyboard.discovery.hackertarget import HackerTargetDiscovery
    from bountyboard.discovery.securitytrails import SecurityTrailsDiscovery
    from bountyboard.discovery.chaos import ChaosDiscovery
    from bountyboard.discovery.shodan import ShodanDiscovery

    sources: list[BaseDiscovery] = [
        # Free sources — always enabled
        CrtshDiscovery(session),
        AlienVaultDiscovery(session, settings.alienvault_otx_key),
        URLScanDiscovery(session, settings.urlscan_api_key),
        RapidDNSDiscovery(session),
        BufferOverDiscovery(session),
        CertSpotterDiscovery(session),
        HackerTargetDiscovery(session),
        DNSDumpsterDiscovery(session),
    ]

    if settings.check_wayback:
        sources.append(WaybackDiscovery(session))

    if settings.check_commoncrawl:
        sources.append(CommonCrawlDiscovery(session))

    sources.append(GitHubDiscovery(session, settings.github_token))

    # Premium sources — only if keys provided
    if settings.securitytrails_api_key:
        sources.append(SecurityTrailsDiscovery(session, settings.securitytrails_api_key))
    if settings.chaos_api_key:
        sources.append(ChaosDiscovery(session, settings.chaos_api_key))
    if settings.shodan_api_key:
        sources.append(ShodanDiscovery(session, settings.shodan_api_key))

    return sources


class ScanStats:
    def __init__(self):
        self.programs_scanned = 0
        self.subdomains_total = 0
        self.subdomains_new = 0
        self.services_total = 0
        self.services_new = 0
        self.findings_critical = 0
        self.findings_high = 0
        self.findings_medium = 0
        self.findings_low = 0

    def to_dict(self) -> dict:
        return {
            "programs_scanned": self.programs_scanned,
            "subdomains_total": self.subdomains_total,
            "subdomains_new": self.subdomains_new,
            "services_total": self.services_total,
            "services_new": self.services_new,
            "findings_critical": self.findings_critical,
            "findings_high": self.findings_high,
            "findings_medium": self.findings_medium,
            "findings_low": self.findings_low,
        }


class BountyBoardEngine:
    """Main orchestration engine for BountyBoard."""

    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self.settings = config.settings
        self.stats = ScanStats()
        self._run_id: Optional[int] = None

    # ================================================================
    # PHASE 1: SUBDOMAIN DISCOVERY
    # ================================================================

    async def _discover_subdomains(self, program: Program,
                                    program_id: int) -> dict[str, set[str]]:
        """
        Discover subdomains from all sources.
        Returns dict of {source_name: set of subdomains}.
        """
        logger.info(f"[phase1] Starting subdomain discovery for {program.name}")
        all_found: dict[str, set[str]] = {}

        connector = aiohttp.TCPConnector(
            limit=50, ssl=False, enable_cleanup_closed=True,
        )
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BountyBoard/1.0)",
            "Accept": "application/json, text/html, */*",
        }

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            sources = _build_discovery_sources(session, self.settings)

            for domain in program.domains:
                logger.info(f"[phase1] Discovering for domain: {domain}")

                # Run all sources concurrently per domain
                tasks = [src.safe_discover(domain) for src in sources]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, tuple):
                        source_name, subs = result
                        key = f"{source_name}:{domain}"
                        all_found.setdefault(key, set()).update(subs)
                    else:
                        logger.debug(f"[phase1] Source error: {result}")

                # Permutation engine
                if self.settings.permutation_engine:
                    logger.info(f"[phase1] Running permutation engine for {domain}")
                    all_subs_so_far: set[str] = set()
                    for subs in all_found.values():
                        all_subs_so_far.update(subs)

                    perm_engine = PermutationEngine(
                        concurrency=self.settings.dns_threads,
                        max_per_subdomain=self.settings.max_permutations_per_subdomain,
                    )
                    perm_subs = await perm_engine.resolve_all(domain, all_subs_so_far)
                    if perm_subs:
                        all_found[f"permutations:{domain}"] = perm_subs
                        logger.info(f"[phase1] Permutations: {len(perm_subs)} new subdomains")

                # DNS brute force
                if self.settings.brute_force_enabled:
                    from bountyboard.discovery.brute import BruteForceDiscovery
                    logger.info(f"[phase1] DNS brute force for {domain}")
                    brute = BruteForceDiscovery(
                        concurrency=self.settings.dns_threads,
                    )
                    brute_subs = await brute.discover(domain)
                    if brute_subs:
                        all_found[f"bruteforce:{domain}"] = brute_subs
                        logger.info(f"[phase1] Brute force: {len(brute_subs)} subdomains")

        # Store all discovered subdomains to DB
        new_count = 0
        total_count = 0
        all_unique: dict[str, str] = {}  # subdomain -> source

        for source_key, subs in all_found.items():
            source_name = source_key.split(":")[0]
            for sub in subs:
                if sub not in all_unique:
                    all_unique[sub] = source_name

        for sub, source in all_unique.items():
            if not program.is_in_scope(sub):
                continue
            if total_count >= self.settings.max_subdomains_per_domain:
                logger.warning(f"[phase1] Hit max subdomain limit for {program.name}")
                break
            _, is_new = self.db.upsert_subdomain(program_id, sub, source)
            total_count += 1
            if is_new:
                new_count += 1

        self.stats.subdomains_total += total_count
        self.stats.subdomains_new += new_count
        logger.info(
            f"[phase1] {program.name}: {total_count} total, {new_count} new subdomains"
        )

        return all_found

    # ================================================================
    # PHASE 2: DNS RESOLUTION
    # ================================================================

    async def _resolve_dns(self, program_id: int) -> list[dict]:
        """Resolve DNS for all subdomains of a program."""
        logger.info("[phase2] Starting DNS resolution")

        subdomains = self.db.get_subdomains(program_id)
        resolver = DNSResolver(
            concurrency=self.settings.dns_threads,
            timeout=self.settings.dns_timeout,
        )

        sub_names = [s["subdomain"] for s in subdomains]
        results = await resolver.resolve_all(sub_names, batch_size=self.settings.batch_size)

        live_subs = []
        for dns_result in results:
            # Find subdomain record
            sub_records = [s for s in subdomains if s["subdomain"] == dns_result.subdomain]
            if not sub_records:
                continue
            sub_id = sub_records[0]["id"]

            if not dns_result.resolves:
                self.db.mark_subdomain_gone(dns_result.subdomain)
                continue

            # Store DNS records
            for ip in dns_result.a_records:
                self.db.upsert_dns_record(sub_id, "A", ip)
            for ip in dns_result.aaaa_records:
                self.db.upsert_dns_record(sub_id, "AAAA", ip)
            for cname in dns_result.cname_records:
                self.db.upsert_dns_record(sub_id, "CNAME", cname)
            for txt in dns_result.txt_records:
                self.db.upsert_dns_record(sub_id, "TXT", txt[:500])
            for mx in dns_result.mx_records:
                self.db.upsert_dns_record(sub_id, "MX", mx)

            if dns_result.a_records:
                live_subs.append({
                    "subdomain_id": sub_id,
                    "subdomain": dns_result.subdomain,
                    "ip": dns_result.a_records[0],
                    "all_ips": dns_result.all_ips,
                    "cnames": dns_result.cname_records,
                    "ip_classification": dns_result.ip_classification,
                    "cname_classification": dns_result.cname_classification,
                })

        logger.info(f"[phase2] {len(live_subs)}/{len(sub_names)} subdomains resolve")
        return live_subs

    # ================================================================
    # PHASE 3: HTTP PROBING
    # ================================================================

    async def _probe_http(self, live_subs: list[dict], program_id: int) -> list[dict]:
        """Probe HTTP on all resolved subdomains."""
        logger.info(f"[phase3] Probing {len(live_subs)} subdomains")

        prober = HTTPProber(
            concurrency=self.settings.threads,
            timeout=self.settings.http_timeout,
            ports=self.settings.http_ports,
        )

        targets = [(s["subdomain"], s["ip"]) for s in live_subs]
        probe_results = await prober.probe_all(targets, batch_size=50)

        # Store services to DB
        live_services = []
        fingerprinter = FingerprintEngine()

        for probe in probe_results:
            # Find subdomain_id
            sub_match = [s for s in live_subs if s["subdomain"] == probe.subdomain]
            if not sub_match:
                continue
            sub_id = sub_match[0]["subdomain_id"]

            # Fingerprint technologies
            techs = fingerprinter.detect_from_probe(probe)

            service_data = {
                "ip_address": probe.ip_address,
                "port": probe.port,
                "is_https": probe.is_https,
                "status_code": probe.status_code,
                "response_headers": probe.response_headers,
                "response_size": probe.response_size,
                "response_time_ms": probe.response_time_ms,
                "server_header": probe.server_header,
                "content_type": probe.content_type,
                "technologies": techs,
                "ssl_cert_subject": probe.ssl_cert_subject,
                "ssl_cert_issuer": probe.ssl_cert_issuer,
                "ssl_cert_expiry": probe.ssl_cert_expiry,
                "ssl_cert_self_signed": probe.ssl_cert_self_signed,
            }

            svc_id, is_new = self.db.upsert_service(sub_id, probe.url, service_data)

            if is_new:
                self.stats.services_new += 1

            live_services.append({
                "service_id": svc_id,
                "url": probe.url,
                "subdomain": probe.subdomain,
                "ip": probe.ip_address,
                "port": probe.port,
                "status_code": probe.status_code,
                "technologies": techs,
            })

        self.stats.services_total += len(live_services)
        logger.info(f"[phase3] {len(live_services)} live HTTP services found")
        return live_services

    # ================================================================
    # PHASE 5: SCREENSHOT CAPTURE
    # ================================================================

    async def _capture_screenshots(self, services: list[dict]) -> None:
        """Capture screenshots for live services."""
        if not self.settings.screenshot_enabled:
            return

        from bountyboard.screenshot.capture import ScreenshotCapture

        logger.info("[phase5] Starting screenshot capture")

        capturer = ScreenshotCapture(
            output_dir=self.settings.screenshot_dir,
            timeout=self.settings.screenshot_timeout,
            concurrency=3,
        )

        # Prioritize: screenshot unique looking pages first
        urls_to_capture = [
            s["url"] for s in services
            if s.get("status_code") not in (301, 302, 303, 307, 308)
        ][:self.settings.max_screenshots_per_run]

        results = await capturer.capture_batch(urls_to_capture)

        captured = 0
        for url, path in results.items():
            if path:
                svc = self.db.get_service_by_url(url)
                if svc:
                    self.db.update_service_screenshot(svc["id"], path)
                captured += 1

        logger.info(f"[phase5] Captured {captured}/{len(urls_to_capture)} screenshots")

    # ================================================================
    # PHASE 6: EXPOSURE SCANNING
    # ================================================================

    async def _scan_exposures(self, services: list[dict]) -> list[dict]:
        """Scan all services for sensitive exposures."""
        logger.info(f"[phase6] Scanning {len(services)} services for exposures")

        scanner = ExposureScanner(concurrency=50, timeout=self.settings.http_timeout)

        base_urls = list(set(s["url"] for s in services))
        findings = await scanner.scan_all(base_urls, batch_size=20)

        all_findings = []
        notify_severities = SEVERITY_MIN.get(
            self.settings.notify_severity.lower(), ["CRITICAL"]
        )

        for base_url, url_findings in findings.items():
            # Find service_id
            svc_match = [s for s in services if s["url"] == base_url]
            svc_id = svc_match[0]["service_id"] if svc_match else None
            subdomain = svc_match[0]["subdomain"] if svc_match else ""

            for finding in url_findings:
                finding_data = {
                    "status_code": finding.status_code,
                    "response_size": finding.response_size,
                    "response_snippet": finding.response_snippet,
                    "severity": finding.severity,
                }

                if svc_id:
                    finding_id, is_new = self.db.upsert_finding(
                        svc_id, finding.check_name, finding.url, finding_data
                    )
                else:
                    finding_id, is_new = None, False

                # Count by severity
                if finding.severity == "CRITICAL":
                    self.stats.findings_critical += 1
                elif finding.severity == "HIGH":
                    self.stats.findings_high += 1
                elif finding.severity == "MEDIUM":
                    self.stats.findings_medium += 1
                else:
                    self.stats.findings_low += 1

                finding_dict = {
                    "id": finding_id,
                    "check_name": finding.check_name,
                    "url": finding.url,
                    "severity": finding.severity,
                    "description": finding.description,
                    "status_code": finding.status_code,
                    "response_size": finding.response_size,
                    "response_snippet": finding.response_snippet,
                    "subdomain": subdomain,
                    "found_at": datetime.utcnow().isoformat(),
                    "is_new": is_new,
                }
                all_findings.append(finding_dict)

                # Send notifications for new findings
                if is_new and finding.severity in notify_severities:
                    if finding_id:
                        self.db.mark_finding_notified(finding_id)
                    await self._notify(finding_dict)

        logger.info(f"[phase6] {len(all_findings)} total findings across all services")
        return all_findings

    # ================================================================
    # NOTIFICATIONS
    # ================================================================

    async def _notify(self, finding: dict) -> None:
        """Send finding to configured notification channels."""
        coros = []
        if self.settings.discord_webhook:
            coros.append(send_discord_finding(
                self.settings.discord_webhook, finding
            ))
        if self.settings.slack_webhook:
            coros.append(send_slack_finding(
                self.settings.slack_webhook, finding
            ))
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    # ================================================================
    # MAIN SCAN ENTRY POINT
    # ================================================================

    async def scan_program(self, program: Program) -> None:
        """Run complete pipeline for a single program."""
        logger.info(f"[engine] === Starting scan for: {program.name} ===")

        # Ensure program exists in DB
        program_id = self.db.upsert_program(
            name=program.name,
            platform=program.platform,
            domains=program.domains,
            wildcard_scopes=program.wildcard_scope,
            exclusions=program.exclude,
            notes=program.notes,
        )

        try:
            # Phase 1: Discovery
            await self._discover_subdomains(program, program_id)

            # Phase 2: DNS Resolution
            live_subs = await self._resolve_dns(program_id)

            if not live_subs:
                logger.warning(f"[engine] No live subdomains for {program.name}")
                return

            # Phase 3: HTTP Probing + Phase 4: Fingerprinting (combined)
            live_services = await self._probe_http(live_subs, program_id)

            if not live_services:
                logger.warning(f"[engine] No live HTTP services for {program.name}")
                return

            # Phase 5: Screenshots
            await self._capture_screenshots(live_services)

            # Phase 6: Exposure Scanning
            await self._scan_exposures(live_services)

            self.stats.programs_scanned += 1
            logger.info(f"[engine] === Completed scan for: {program.name} ===")

        except Exception as e:
            logger.error(f"[engine] Fatal error scanning {program.name}: {e}", exc_info=True)

    async def run(self, program_filter: Optional[str] = None) -> None:
        """Run scans for all configured programs (or a specific one)."""
        self._run_id = self.db.start_scan_run()

        programs = self.config.programs
        if program_filter:
            programs = [p for p in programs if p.name.lower() == program_filter.lower()]
            if not programs:
                logger.error(f"Program '{program_filter}' not found in config")
                return

        try:
            for program in programs:
                await self.scan_program(program)

            self.db.finish_scan_run(self._run_id, self.stats.to_dict())
            logger.info(f"[engine] All scans complete: {self.stats.to_dict()}")

            # Summary notifications
            if self.settings.discord_webhook:
                db_stats = self.db.get_stats()
                await send_discord_summary(self.settings.discord_webhook, db_stats)
            if self.settings.slack_webhook:
                db_stats = self.db.get_stats()
                await send_slack_summary(self.settings.slack_webhook, db_stats)

        except Exception as e:
            logger.error(f"[engine] Fatal scan error: {e}", exc_info=True)
            if self._run_id:
                self.db.fail_scan_run(self._run_id)

    # ================================================================
    # REPORTING
    # ================================================================

    def generate_brief(self, output_dir: str = "reports") -> dict:
        """Generate morning brief data from database."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        stats = self.db.get_stats()
        last_run = self.db.get_last_scan_run()
        findings = self.db.get_findings(only_present=True)
        all_subs = self.db.get_subdomains()
        all_services = self.db.get_services()

        # New subdomains since last run
        new_subs = []
        if last_run:
            last_run_time = last_run.get("started_at", "")
            new_subs = [s for s in all_subs
                        if (s.get("first_seen") or "") >= last_run_time]

        # Dead subdomains
        dead_subs = [s["subdomain"] for s in self.db.get_subdomains(still_exists=False)]

        # Generate recommendations
        prioritized = prioritize_findings(findings)
        recs = generate_recommendations(
            prioritized,
            [s.get("subdomain", "") for s in new_subs],
            dead_subs[:10],
        )

        # Per-program stats
        program_stats = {}
        for prog in self.config.programs:
            prog_id = self.db.get_program_id(prog.name)
            if not prog_id:
                continue
            prog_stats = self.db.get_stats(prog_id)

            # Technology breakdown
            prog_services = self.db.get_services(prog_id)
            tech_counts: dict[str, int] = {}
            ip_set: set[str] = set()
            for svc in prog_services:
                techs = json.loads(svc.get("technologies", "[]") or "[]")
                for t in techs:
                    tech_counts[t] = tech_counts.get(t, 0) + 1
                if svc.get("ip_address"):
                    ip_set.add(svc["ip_address"])

            prog_stats["technologies"] = tech_counts
            prog_stats["unique_ips"] = len(ip_set)
            program_stats[prog.name] = prog_stats

        # Annotate stats with run info
        stats["subdomains_new"] = len(new_subs)
        stats["last_run_time"] = last_run.get("completed_at") if last_run else None

        brief_data = {
            "stats": stats,
            "last_run": last_run,
            "findings": [dict(f) for f in findings],
            "subdomains": [dict(s) for s in all_subs],
            "services": [dict(s) for s in all_services],
            "new_subdomains": [dict(s) for s in new_subs],
            "dead_subdomains": dead_subs,
            "recommendations": recs,
            "program_stats": program_stats,
            "programs": [p.name for p in self.config.programs],
            "screenshots": self._get_screenshot_data(all_services),
        }

        return brief_data

    def _get_screenshot_data(self, services: list[dict]) -> list[dict]:
        """Get screenshot path data for HTML report."""
        screenshots = []
        for svc in services:
            path = svc.get("screenshot_path")
            if path and Path(path).exists():
                thumb = path.replace(".png", "_thumb.png")
                screenshots.append({
                    "url": svc.get("url", ""),
                    "path": path,
                    "thumb_path": thumb if Path(thumb).exists() else path,
                })
        return screenshots

    def generate_html_report(self, output_dir: str = "reports") -> str:
        """Generate and save HTML report."""
        brief_data = self.generate_brief(output_dir)
        output_path = str(Path(output_dir) / "bountyboard_report.html")
        return generate_html_report(brief_data, output_path)

    def export_findings(self, fmt: str, output_path: str,
                         severity: Optional[str] = None) -> str:
        """Export findings in the requested format."""
        findings = self.db.get_findings(severity=severity)

        if fmt == "json":
            return export_json(findings, output_path)
        elif fmt == "csv":
            return export_csv(findings, output_path)
        elif fmt == "markdown":
            return export_markdown(findings, output_path)
        else:
            raise ValueError(f"Unknown format: {fmt}")
