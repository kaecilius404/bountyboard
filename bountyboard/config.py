"""Configuration loading, validation, and program management."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path("config.yaml")

DEFAULT_HTTP_PORTS = [80, 443, 8008, 8080, 8443, 3000, 4443, 5000, 5443,
                      7001, 8000, 8888, 9000, 9090, 9200, 9443, 10000, 10443]


@dataclass
class Program:
    name: str
    platform: str = "private"
    domains: list[str] = field(default_factory=list)
    wildcard_scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    notes: str = ""

    def is_in_scope(self, subdomain: str) -> bool:
        """Check if a subdomain is in scope for this program."""
        subdomain = subdomain.lower().rstrip(".")

        # Check exclusions first
        for pattern in self.exclude:
            pattern = pattern.lower().lstrip("*.")
            if subdomain == pattern or subdomain.endswith("." + pattern):
                return False

        # Check wildcard scope
        for pattern in self.wildcard_scope:
            pattern = pattern.lower().lstrip("*.")
            if subdomain == pattern or subdomain.endswith("." + pattern):
                return True

        # Check direct domains
        for domain in self.domains:
            domain = domain.lower()
            if subdomain == domain or subdomain.endswith("." + domain):
                return True

        return False


@dataclass
class Settings:
    threads: int = 100
    dns_threads: int = 200
    http_timeout: int = 10
    dns_timeout: int = 5
    screenshot_timeout: int = 20
    batch_size: int = 500

    screenshot_enabled: bool = True
    brute_force_enabled: bool = False
    permutation_engine: bool = True
    check_wayback: bool = True
    check_commoncrawl: bool = True

    chaos_api_key: str = ""
    securitytrails_api_key: str = ""
    shodan_api_key: str = ""
    github_token: str = ""
    urlscan_api_key: str = ""
    alienvault_otx_key: str = ""

    database_path: str = "bountyboard.db"
    screenshot_dir: str = "screenshots"
    output_dir: str = "reports"
    wordlist_dir: str = "wordlists"

    discord_webhook: str = ""
    slack_webhook: str = ""
    notify_severity: str = "critical"

    scan_interval_hours: int = 12

    max_subdomains_per_domain: int = 50000
    max_screenshots_per_run: int = 200
    max_permutations_per_subdomain: int = 50

    http_ports: list[int] = field(default_factory=lambda: list(DEFAULT_HTTP_PORTS))


@dataclass
class Config:
    programs: list[Program] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)

    def get_program(self, name: str) -> Program | None:
        for p in self.programs:
            if p.name.lower() == name.lower():
                return p
        return None


def load_config(path: Path | str | None = None) -> Config:
    """Load and parse the YAML configuration file."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        # Try to find config in the package directory
        pkg_config = Path(__file__).parent.parent / "config.yaml"
        if pkg_config.exists():
            config_path = pkg_config
        else:
            print(f"[ERROR] Config file not found at {config_path}")
            print("  Create one with: cp config.yaml.example config.yaml")
            sys.exit(1)

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    # Parse programs
    programs = []
    for p in raw.get("programs", []):
        programs.append(Program(
            name=p.get("name", "unnamed"),
            platform=p.get("platform", "private"),
            domains=p.get("domains", []),
            wildcard_scope=p.get("wildcard_scope", []),
            exclude=p.get("exclude", []),
            notes=p.get("notes", ""),
        ))

    # Parse settings (merge with defaults)
    raw_settings = raw.get("settings", {})
    settings = Settings()

    for key, val in raw_settings.items():
        if hasattr(settings, key):
            setattr(settings, key, val)

    # Override with environment variables (for CI/CD)
    env_map = {
        "BOUNTYBOARD_CHAOS_KEY": "chaos_api_key",
        "BOUNTYBOARD_SECURITYTRAILS_KEY": "securitytrails_api_key",
        "BOUNTYBOARD_SHODAN_KEY": "shodan_api_key",
        "BOUNTYBOARD_GITHUB_TOKEN": "github_token",
        "BOUNTYBOARD_DISCORD_WEBHOOK": "discord_webhook",
        "BOUNTYBOARD_SLACK_WEBHOOK": "slack_webhook",
    }
    for env_var, attr in env_map.items():
        val = os.environ.get(env_var, "")
        if val:
            setattr(settings, attr, val)

    return Config(programs=programs, settings=settings)


def validate_config(config: Config) -> list[str]:
    """Validate configuration and return list of warnings."""
    warnings = []

    if not config.programs:
        warnings.append("No programs defined. Add at least one program to config.yaml.")

    for p in config.programs:
        if not p.domains:
            warnings.append(f"Program '{p.name}' has no domains defined.")
        for domain in p.domains:
            if not domain or "." not in domain:
                warnings.append(f"Program '{p.name}': suspicious domain '{domain}'")

    s = config.settings
    if s.threads > 500:
        warnings.append("threads > 500 may cause rate limiting or connection errors")
    if s.dns_threads > 1000:
        warnings.append("dns_threads > 1000 may overwhelm local DNS resolver")
    if s.brute_force_enabled:
        warnings.append("DNS brute force is enabled — ensure you have explicit scope permission")

    return warnings


def save_program(config: Config, program: Program, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Add or update a program in the config file."""
    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    programs = raw.get("programs", [])
    # Remove existing entry with same name
    programs = [p for p in programs if p.get("name") != program.name]
    programs.append({
        "name": program.name,
        "platform": program.platform,
        "domains": program.domains,
        "wildcard_scope": program.wildcard_scope,
        "exclude": program.exclude,
        "notes": program.notes,
    })
    raw["programs"] = programs

    with open(config_path, "w") as f:
        yaml.dump(raw, f, default_flow_style=False, allow_unicode=True)
