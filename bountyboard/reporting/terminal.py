"""Terminal morning brief — rich, color-coded output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import print as rprint
from rich.rule import Rule

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold cyan",
    "LOW": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️ ",
    "MEDIUM": "🔵",
    "LOW": "⬜",
}


def _time_ago(ts_str: Optional[str]) -> str:
    if not ts_str:
        return "never"
    try:
        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = now - ts
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s ago"
        elif seconds < 3600:
            return f"{seconds // 60}m ago"
        elif seconds < 86400:
            return f"{seconds // 3600}h ago"
        else:
            return f"{seconds // 86400}d ago"
    except Exception:
        return ts_str


def print_banner():
    """Print BountyBoard ASCII banner."""
    banner = """[bold green]
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
[/bold green][dim]██████╗  ██████╗  █████╗ ██████╗ ██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
██████╔╝██║   ██║███████║██████╔╝██║  ██║
██╔══██╗██║   ██║██╔══██║██╔══██╗██║  ██║
██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝[/dim]
[dim italic]Professional-grade automated bug bounty reconnaissance[/dim italic]
"""
    console.print(banner)


def print_executive_dashboard(stats: dict, last_run: Optional[dict] = None):
    """Print the executive dashboard panel."""
    console.print(Rule("[bold]EXECUTIVE DASHBOARD[/bold]", style="green"))

    # Stats grid
    stats_table = Table.grid(expand=True)
    stats_table.add_column(ratio=1)
    stats_table.add_column(ratio=1)
    stats_table.add_column(ratio=1)
    stats_table.add_column(ratio=1)

    stats_table.add_row(
        Panel(
            f"[bold white]{stats.get('total_subdomains', 0):,}[/bold white]\n"
            f"[dim]Total Subdomains[/dim]",
            border_style="blue",
        ),
        Panel(
            f"[bold white]{stats.get('total_services', 0):,}[/bold white]\n"
            f"[dim]Live Services[/dim]",
            border_style="blue",
        ),
        Panel(
            f"[bold white]{stats.get('subdomains_new', 0):,}[/bold white]\n"
            f"[dim]New This Run[/dim]",
            border_style="green" if stats.get("subdomains_new", 0) > 0 else "blue",
        ),
        Panel(
            f"[dim]Last scan:[/dim] {_time_ago(stats.get('last_run_time'))}\n"
            f"[dim]Status:[/dim] [green]{'✓ Done' if last_run else 'Never'}[/green]",
            border_style="blue",
        ),
    )
    console.print(stats_table)

    # Findings summary
    findings_table = Table.grid(expand=True)
    findings_table.add_column(ratio=1)
    findings_table.add_column(ratio=1)
    findings_table.add_column(ratio=1)
    findings_table.add_column(ratio=1)

    critical = stats.get("findings_critical", 0)
    high = stats.get("findings_high", 0)
    medium = stats.get("findings_medium", 0)
    low = stats.get("findings_low", 0)

    findings_table.add_row(
        Panel(
            f"[bold red]{critical}[/bold red]\n[dim]CRITICAL[/dim]",
            border_style="red" if critical > 0 else "dim",
        ),
        Panel(
            f"[bold yellow]{high}[/bold yellow]\n[dim]HIGH[/dim]",
            border_style="yellow" if high > 0 else "dim",
        ),
        Panel(
            f"[bold cyan]{medium}[/bold cyan]\n[dim]MEDIUM[/dim]",
            border_style="cyan" if medium > 0 else "dim",
        ),
        Panel(
            f"[white]{low}[/white]\n[dim]LOW[/dim]",
            border_style="dim",
        ),
    )
    console.print(findings_table)


def print_findings_table(findings: list[dict], title: str = "FINDINGS",
                          limit: int = 50):
    """Print a rich findings table."""
    if not findings:
        console.print(f"[dim]No findings to show.[/dim]")
        return

    console.print(Rule(f"[bold]{title}[/bold]", style="green"))

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        expand=True,
    )

    table.add_column("SEV", style="bold", width=8, no_wrap=True)
    table.add_column("CHECK", width=20, no_wrap=True)
    table.add_column("URL", no_wrap=False)
    table.add_column("STATUS", width=6, justify="right")
    table.add_column("SIZE", width=8, justify="right")
    table.add_column("FOUND", width=10, no_wrap=True)

    for finding in findings[:limit]:
        sev = finding.get("severity", "LOW")
        color = SEVERITY_COLORS.get(sev, "white")
        icon = SEVERITY_ICONS.get(sev, "")

        table.add_row(
            Text(f"{icon} {sev}", style=color),
            finding.get("check_name", "")[:20],
            finding.get("url", "")[:80],
            str(finding.get("status_code", "")),
            _fmt_size(finding.get("response_size", 0)),
            _time_ago(finding.get("found_at")),
        )

    console.print(table)

    if len(findings) > limit:
        console.print(f"[dim]... and {len(findings) - limit} more. "
                      f"Use --limit to show more.[/dim]")


def print_new_subdomains(new_subs: list[dict], limit: int = 20):
    """Print newly discovered subdomains."""
    if not new_subs:
        return

    console.print(Rule("[bold]NEW SUBDOMAINS[/bold]", style="green"))

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.SIMPLE_HEAD,
        expand=True,
    )
    table.add_column("SUBDOMAIN")
    table.add_column("SOURCE", width=15)
    table.add_column("FIRST SEEN", width=12)

    for sub in new_subs[:limit]:
        table.add_row(
            sub.get("subdomain", ""),
            sub.get("source", ""),
            _time_ago(sub.get("first_seen")),
        )

    console.print(table)

    if len(new_subs) > limit:
        console.print(f"[dim]... and {len(new_subs) - limit} more.[/dim]")


def print_recommendations(recs: list[str]):
    """Print actionable recommendations."""
    if not recs:
        return

    console.print(Rule("[bold]RECOMMENDATIONS[/bold]", style="green"))

    for i, rec in enumerate(recs, 1):
        console.print(f"  [bold]{i}.[/bold] {rec}")
        console.print()


def print_program_summary(program_name: str, stats: dict):
    """Print per-program attack surface summary."""
    console.print(Rule(f"[bold]PROGRAM: {program_name.upper()}[/bold]", style="blue"))

    techs = stats.get("technologies", {})
    tech_str = ", ".join(f"{k}: {v}" for k, v in sorted(techs.items(), key=lambda x: -x[1]))

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column()
    grid.add_column()

    grid.add_row("[dim]Subdomains:[/dim]", f"[bold]{stats.get('total_subdomains', 0):,}[/bold]")
    grid.add_row("[dim]Live Services:[/dim]", f"[bold]{stats.get('total_services', 0):,}[/bold]")
    grid.add_row("[dim]Unique IPs:[/dim]", f"[bold]{stats.get('unique_ips', 0):,}[/bold]")
    grid.add_row("[dim]Technologies:[/dim]", tech_str or "[dim]none detected[/dim]")

    console.print(grid)
    console.print()


def print_morning_brief(data: dict):
    """Print the complete morning brief."""
    print_banner()

    last_run = data.get("last_run")
    stats = data.get("stats", {})
    findings = data.get("findings", [])
    new_subs = data.get("new_subdomains", [])
    recs = data.get("recommendations", [])
    program_stats = data.get("program_stats", {})

    # Executive dashboard
    print_executive_dashboard(stats, last_run)

    # New subdomains section
    if new_subs:
        print_new_subdomains(new_subs)

    # Critical + High findings
    critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if critical_high:
        print_findings_table(critical_high, "CRITICAL & HIGH FINDINGS")

    # Per-program summary
    for prog_name, prog_stats in program_stats.items():
        print_program_summary(prog_name, prog_stats)

    # Recommendations
    print_recommendations(recs)

    console.print(Rule(style="dim"))
    console.print(
        f"[dim]Run [bold]bountyboard findings --severity critical[/bold] "
        f"to see all critical findings | "
        f"[bold]bountyboard scan[/bold] to run a new scan[/dim]"
    )


def _fmt_size(size: int) -> str:
    """Format file size for display."""
    if size < 1024:
        return f"{size}B"
    elif size < 1048576:
        return f"{size // 1024}KB"
    else:
        return f"{size // 1048576}MB"
