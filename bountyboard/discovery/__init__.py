"""Subdomain discovery engine — all passive and active discovery sources."""

from .crtsh import CrtshDiscovery
from .alienvault import AlienVaultDiscovery
from .urlscan import URLScanDiscovery
from .wayback import WaybackDiscovery
from .github_search import GitHubDiscovery
from .commoncrawl import CommonCrawlDiscovery
from .rapiddns import RapidDNSDiscovery
from .bufferover import BufferOverDiscovery
from .certspotter import CertSpotterDiscovery
from .dnsdumpster import DNSDumpsterDiscovery
from .hackertarget import HackerTargetDiscovery
from .securitytrails import SecurityTrailsDiscovery
from .chaos import ChaosDiscovery
from .shodan import ShodanDiscovery
from .permutations import PermutationEngine

__all__ = [
    "CrtshDiscovery",
    "AlienVaultDiscovery",
    "URLScanDiscovery",
    "WaybackDiscovery",
    "GitHubDiscovery",
    "CommonCrawlDiscovery",
    "RapidDNSDiscovery",
    "BufferOverDiscovery",
    "CertSpotterDiscovery",
    "DNSDumpsterDiscovery",
    "HackerTargetDiscovery",
    "SecurityTrailsDiscovery",
    "ChaosDiscovery",
    "ShodanDiscovery",
    "PermutationEngine",
]
