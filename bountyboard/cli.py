"""BountyBoard CLI — complete command-line interface."""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Confirm, Prompt

console = Console()


def _setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(
            console=console,
            rich_tracebacks=True,
            markup=True,
            show_path=verbose,
        )],
    )
    # Quiet noisy libraries
    for lib in ["aiohttp", "asyncio", "playwright", "urllib3"]:
        logging.getLogger(lib).setLevel(logging.WARNING)


def _get_engine(config_path: Optional[str] = None):
    """Initialize engine from config."""
    from bountyboard.config import load_config
    from bountyboard.database import Database
    from bountyboard.engine import BountyBoardEngine

    cfg = load_config(config_path)
    db = Database(cfg.settings.database_path)
    return BountyBoardEngine(cfg, db), cfg, db


@click.group()
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def main(ctx, config, verbose):
    """
    \b
    ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
    ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝

    Professional-grade automated bug bounty reconnaissance pipeline.
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ================================================================
# bountyboard scan
# ================================================================

@main.command()
@click.option("--program", "-p", default=None, help="Scan specific program by name")
@click.option("--domain", "-d", default=None, help="Quick scan a single domain")
@click.option("--quick", "-q", is_flag=True, help="Quick mode: skip screenshots and brute force")
@click.option("--no-screenshots", is_flag=True, help="Skip screenshot capture")
@click.option("--only-exposures", is_flag=True, help="Skip discovery, only run exposure scan")
@click.pass_context
def scan(ctx, program, domain, quick, no_screenshots, only_exposures):
    """Run the full reconnaissance pipeline."""
    from bountyboard.config import load_config, Program, Settings
    from bountyboard.database import Database
    from bountyboard.engine import BountyBoardEngine
    from bountyboard.reporting.terminal import print_morning_brief, print_banner

    cfg = load_config(ctx.obj.get("config"))

    # Override settings for quick/flag modes
    if quick:
        cfg.settings.screenshot_enabled = False
        cfg.settings.brute_force_enabled = False
        cfg.settings.permutation_engine = False
        cfg.settings.check_commoncrawl = False

    if no_screenshots:
        cfg.settings.screenshot_enabled = False

    # Quick domain scan
    if domain:
        cfg.programs = [Program(
            name=domain, platform="private",
            domains=[domain],
            wildcard_scope=[f"*.{domain}"],
        )]

    db = Database(cfg.settings.database_path)
    engine = BountyBoardEngine(cfg, db)

    print_banner()
    console.print(f"[bold green]Starting scan[/bold green] — "
                  f"{len(cfg.programs)} program(s) | "
                  f"{'Quick mode' if quick else 'Full mode'}")

    try:
        asyncio.run(engine.run(program_filter=program))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted. Run [bold]bountyboard resume[/bold] to continue.[/yellow]")
        sys.exit(0)

    # Show morning brief after scan
    brief_data = engine.generate_brief(cfg.settings.output_dir)
    print_morning_brief(brief_data)

    # Generate HTML report
    html_path = engine.generate_html_report(cfg.settings.output_dir)
    console.print(f"\n[bold]HTML report:[/bold] file://{Path(html_path).absolute()}")


# ================================================================
# bountyboard brief
# ================================================================

@main.command()
@click.option("--date", default=None, help="Show brief for specific date (YYYY-MM-DD)")
@click.option("--html", "as_html", is_flag=True, help="Generate and open HTML report")
@click.pass_context
def brief(ctx, date, as_html):
    """Show the morning reconnaissance brief."""
    from bountyboard.reporting.terminal import print_morning_brief

    engine, cfg, db = _get_engine(ctx.obj.get("config"))
    brief_data = engine.generate_brief(cfg.settings.output_dir)
    print_morning_brief(brief_data)

    if as_html:
        html_path = engine.generate_html_report(cfg.settings.output_dir)
        console.print(f"[bold]Report:[/bold] file://{Path(html_path).absolute()}")
        try:
            import subprocess
            subprocess.Popen(["xdg-open", html_path])
        except Exception:
            pass


# ================================================================
# bountyboard findings
# ================================================================

@main.command()
@click.option("--severity", "-s", default=None,
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Filter by minimum severity")
@click.option("--program", "-p", default=None, help="Filter by program")
@click.option("--new", "only_new", is_flag=True, help="Show only unnotified findings")
@click.option("--limit", default=50, help="Maximum findings to show")
@click.pass_context
def findings(ctx, severity, program, only_new, limit):
    """List all findings with optional filters."""
    from bountyboard.reporting.terminal import print_findings_table

    engine, cfg, db = _get_engine(ctx.obj.get("config"))

    prog_id = None
    if program:
        prog_id = db.get_program_id(program)
        if not prog_id:
            console.print(f"[red]Program '{program}' not found[/red]")
            return

    all_findings = db.get_findings(
        program_id=prog_id,
        severity=severity.upper() if severity else None,
        only_new=only_new,
    )

    if not all_findings:
        console.print("[dim]No findings match your filters.[/dim]")
        return

    title = f"FINDINGS ({len(all_findings)} total)"
    if severity:
        title += f" — {severity.upper()}+"
    if only_new:
        title += " — NEW ONLY"

    print_findings_table(all_findings, title=title, limit=limit)
    console.print(f"\n[dim]Showing {min(limit, len(all_findings))} of {len(all_findings)} findings[/dim]")


# ================================================================
# bountyboard export
# ================================================================

@main.command()
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv", "markdown"], case_sensitive=False),
              default="json", help="Export format")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--severity", "-s", default=None,
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False))
@click.pass_context
def export(ctx, fmt, output, severity):
    """Export findings in various formats."""
    engine, cfg, _ = _get_engine(ctx.obj.get("config"))

    ext_map = {"json": "json", "csv": "csv", "markdown": "md"}
    if not output:
        output = str(Path(cfg.settings.output_dir) / f"findings.{ext_map[fmt]}")

    path = engine.export_findings(fmt, output, severity=severity)
    console.print(f"[green]✓[/green] Exported to: [bold]{path}[/bold]")


# ================================================================
# bountyboard discover / probe / exposures
# ================================================================

@main.command()
@click.option("--program", "-p", default=None, help="Specific program to discover for")
@click.pass_context
def discover(ctx, program):
    """Run only Phase 1 (subdomain discovery) for existing programs."""
    from bountyboard.config import load_config
    from bountyboard.database import Database
    from bountyboard.engine import BountyBoardEngine

    cfg = load_config(ctx.obj.get("config"))
    cfg.settings.screenshot_enabled = False

    db = Database(cfg.settings.database_path)
    engine = BountyBoardEngine(cfg, db)

    programs = cfg.programs
    if program:
        programs = [p for p in programs if p.name.lower() == program.lower()]

    async def run():
        for prog in programs:
            prog_id = db.upsert_program(
                prog.name, prog.platform, prog.domains,
                prog.wildcard_scope, prog.exclude, prog.notes
            )
            await engine._discover_subdomains(prog, prog_id)

    console.print(f"[bold]Running discovery for {len(programs)} program(s)...[/bold]")
    asyncio.run(run())
    console.print("[green]✓[/green] Discovery complete")


@main.command()
@click.option("--program", "-p", default=None, help="Specific program")
@click.pass_context
def probe(ctx, program):
    """Run only Phase 3 (HTTP probing) on existing subdomains."""
    from bountyboard.config import load_config
    from bountyboard.database import Database
    from bountyboard.engine import BountyBoardEngine

    cfg = load_config(ctx.obj.get("config"))
    db = Database(cfg.settings.database_path)
    engine = BountyBoardEngine(cfg, db)

    async def run():
        for prog in cfg.programs:
            if program and prog.name.lower() != program.lower():
                continue
            prog_id = db.get_program_id(prog.name)
            if not prog_id:
                continue
            live_subs = await engine._resolve_dns(prog_id)
            await engine._probe_http(live_subs, prog_id)

    console.print("[bold]Running HTTP probing...[/bold]")
    asyncio.run(run())
    console.print("[green]✓[/green] Probing complete")


@main.command()
@click.option("--program", "-p", default=None, help="Specific program")
@click.pass_context
def exposures(ctx, program):
    """Run only Phase 6 (exposure scanning) on existing services."""
    from bountyboard.config import load_config
    from bountyboard.database import Database
    from bountyboard.engine import BountyBoardEngine

    cfg = load_config(ctx.obj.get("config"))
    db = Database(cfg.settings.database_path)
    engine = BountyBoardEngine(cfg, db)

    async def run():
        for prog in cfg.programs:
            if program and prog.name.lower() != program.lower():
                continue
            prog_id = db.get_program_id(prog.name)
            if not prog_id:
                continue
            services = db.get_services(prog_id)
            svc_list = [
                {"service_id": s["id"], "url": s["url"],
                 "subdomain": "", "technologies": []}
                for s in services
            ]
            await engine._scan_exposures(svc_list)

    console.print("[bold]Running exposure scanning...[/bold]")
    asyncio.run(run())
    console.print("[green]✓[/green] Exposure scanning complete")


# ================================================================
# bountyboard add-program
# ================================================================

@main.command("add-program")
@click.pass_context
def add_program(ctx, **kwargs):
    """Interactively add a new bug bounty program."""
    from bountyboard.config import load_config, Program, save_program

    console.print("[bold]Add New Program[/bold]")
    console.print()

    name = Prompt.ask("Program name")
    platform = Prompt.ask(
        "Platform",
        choices=["hackerone", "bugcrowd", "intigriti", "private", "yeswehack"],
        default="private",
    )

    console.print("\nEnter root domains (one per line, empty to finish):")
    domains = []
    while True:
        d = Prompt.ask("  Domain", default="")
        if not d:
            break
        domains.append(d.strip())

    console.print("\nEnter wildcard scopes (e.g. *.example.com, empty to finish):")
    wildcards = []
    while True:
        w = Prompt.ask("  Wildcard scope", default="")
        if not w:
            break
        wildcards.append(w.strip())

    # Auto-generate wildcards from domains
    if not wildcards:
        wildcards = [f"*.{d}" for d in domains]
        console.print(f"[dim]Auto-generated wildcard scopes: {wildcards}[/dim]")

    console.print("\nEnter exclusions (e.g. *.cdn.example.com, empty to finish):")
    exclusions = []
    while True:
        e = Prompt.ask("  Exclude", default="")
        if not e:
            break
        exclusions.append(e.strip())

    notes = Prompt.ask("\nNotes (optional)", default="")

    program = Program(
        name=name,
        platform=platform,
        domains=domains,
        wildcard_scope=wildcards,
        exclude=exclusions,
        notes=notes,
    )

    cfg_path = ctx.obj.get("config") or "config.yaml"
    cfg = load_config(cfg_path)
    save_program(cfg, program, Path(cfg_path))

    console.print(f"\n[green]✓[/green] Program '[bold]{name}[/bold]' saved to {cfg_path}")
    console.print(f"  Domains: {domains}")
    console.print(f"  Wildcard scope: {wildcards}")
    console.print(f"\nRun: [bold]bountyboard scan --program \"{name}\"[/bold]")


# ================================================================
# bountyboard list-programs
# ================================================================

@main.command("list-programs")
@click.pass_context
def list_programs(ctx):
    """List all tracked programs."""
    from rich.table import Table

    _, cfg, db = _get_engine(ctx.obj.get("config"))

    table = Table(title="Programs", show_header=True, header_style="bold")
    table.add_column("Name", style="bold")
    table.add_column("Platform")
    table.add_column("Domains")
    table.add_column("Subdomains")
    table.add_column("Services")
    table.add_column("Findings")

    for prog in cfg.programs:
        prog_id = db.get_program_id(prog.name)
        subs = db.count_subdomains(prog_id) if prog_id else 0
        services = len(db.get_services(prog_id)) if prog_id else 0
        sev = db.count_findings_by_severity(prog_id) if prog_id else {}
        finding_str = (
            f"[red]{sev.get('CRITICAL', 0)}C[/red] "
            f"[yellow]{sev.get('HIGH', 0)}H[/yellow] "
            f"[blue]{sev.get('MEDIUM', 0)}M[/blue]"
        )
        table.add_row(
            prog.name,
            prog.platform,
            ", ".join(prog.domains[:2]),
            str(subs),
            str(services),
            finding_str,
        )

    console.print(table)


# ================================================================
# bountyboard stats
# ================================================================

@main.command()
@click.option("--program", "-p", default=None, help="Stats for specific program")
@click.pass_context
def stats(ctx, program):
    """Show reconnaissance statistics."""
    from rich.table import Table

    engine, cfg, db = _get_engine(ctx.obj.get("config"))

    prog_id = None
    if program:
        prog_id = db.get_program_id(program)

    s = db.get_stats(prog_id)

    console.print("[bold]Statistics[/bold]")
    console.print()

    grid = Table.grid(padding=(0, 4))
    grid.add_column()
    grid.add_column()

    grid.add_row("[dim]Total Subdomains:[/dim]", f"[bold]{s['total_subdomains']:,}[/bold]")
    grid.add_row("[dim]Live Services:[/dim]", f"[bold]{s['total_services']:,}[/bold]")
    grid.add_row("[dim]Critical Findings:[/dim]", f"[bold red]{s['findings_critical']}[/bold red]")
    grid.add_row("[dim]High Findings:[/dim]", f"[bold yellow]{s['findings_high']}[/bold yellow]")
    grid.add_row("[dim]Medium Findings:[/dim]", f"[bold cyan]{s['findings_medium']}[/bold cyan]")
    grid.add_row("[dim]Low Findings:[/dim]", f"[dim]{s['findings_low']}[/dim]")

    last = s.get("last_run")
    if last:
        grid.add_row("[dim]Last Scan:[/dim]", last.get("completed_at", "")[:16])
        grid.add_row("[dim]Scan Status:[/dim]", f"[green]{last.get('status', '')}[/green]")

    console.print(grid)

    # Scan history
    runs = db.get_scan_runs(limit=5)
    if runs:
        console.print()
        console.print("[dim]Recent Scan History:[/dim]")
        hist = Table(show_header=True, header_style="bold dim", box=None)
        hist.add_column("Started", style="dim")
        hist.add_column("Duration")
        hist.add_column("Subdomains")
        hist.add_column("Services")
        hist.add_column("Findings")
        hist.add_column("Status")

        for run in runs:
            started = (run.get("started_at") or "")[:16]
            completed = run.get("completed_at") or ""

            duration = ""
            if completed and run.get("started_at"):
                try:
                    d = datetime.fromisoformat(completed) - datetime.fromisoformat(run["started_at"])
                    mins = int(d.total_seconds() / 60)
                    duration = f"{mins}m"
                except Exception:
                    pass

            findings_str = (
                f"[red]{run.get('findings_critical', 0)}C[/red] "
                f"[yellow]{run.get('findings_high', 0)}H[/yellow]"
            )
            status_color = "green" if run.get("status") == "completed" else "red"

            hist.add_row(
                started, duration,
                str(run.get("subdomains_total", 0)),
                str(run.get("services_total", 0)),
                findings_str,
                f"[{status_color}]{run.get('status', '')}[/{status_color}]",
            )
        console.print(hist)


# ================================================================
# bountyboard watch
# ================================================================

@main.command()
@click.option("--interval", default="12h", help="Scan interval (e.g. 6h, 30m)")
@click.option("--program", "-p", default=None, help="Watch specific program")
@click.pass_context
def watch(ctx, interval, program):
    """Continuous mode — run scans on schedule."""
    import time
    import re

    # Parse interval
    m = re.match(r"(\d+)(h|m)", interval)
    if not m:
        console.print(f"[red]Invalid interval format: {interval}. Use '6h' or '30m'[/red]")
        return

    value, unit = int(m.group(1)), m.group(2)
    seconds = value * 3600 if unit == "h" else value * 60

    console.print(f"[bold]Watch mode[/bold] — scanning every {interval}")
    console.print("Press Ctrl+C to stop.")

    run_count = 0
    while True:
        run_count += 1
        console.print(f"\n[bold green]Starting run #{run_count}[/bold green] — "
                      f"{datetime.now().strftime('%Y-%m-%d %H:%M')}")

        try:
            ctx.invoke(scan, program=program)
        except Exception as e:
            console.print(f"[red]Scan error: {e}[/red]")

        console.print(f"\n[dim]Next scan in {interval} — {datetime.now().strftime('%H:%M')}[/dim]")
        try:
            time.sleep(seconds)
        except KeyboardInterrupt:
            console.print("\n[yellow]Watch mode stopped.[/yellow]")
            break


# ================================================================
# bountyboard validate-config
# ================================================================

@main.command("validate-config")
@click.pass_context
def validate_config(ctx):
    """Validate the configuration file."""
    from bountyboard.config import load_config, validate_config as _validate

    try:
        cfg = load_config(ctx.obj.get("config"))
        warnings = _validate(cfg)

        console.print(f"[green]✓[/green] Config loaded: "
                      f"{len(cfg.programs)} programs")

        for prog in cfg.programs:
            console.print(f"  • {prog.name} ({prog.platform}): {prog.domains}")

        if warnings:
            console.print()
            console.print("[yellow]Warnings:[/yellow]")
            for w in warnings:
                console.print(f"  ⚠️  {w}")
        else:
            console.print("[green]No warnings.[/green]")

        # Test API keys
        console.print()
        console.print("[dim]API Key Status:[/dim]")
        s = cfg.settings
        keys = [
            ("GitHub Token", bool(s.github_token)),
            ("SecurityTrails", bool(s.securitytrails_api_key)),
            ("Shodan", bool(s.shodan_api_key)),
            ("Chaos", bool(s.chaos_api_key)),
            ("URLScan", bool(s.urlscan_api_key)),
        ]
        for name, configured in keys:
            status = "[green]✓ configured[/green]" if configured else "[dim]not set[/dim]"
            console.print(f"  {name}: {status}")

    except SystemExit:
        console.print("[red]Config file not found or invalid.[/red]")


# ================================================================
# bountyboard resume
# ================================================================

@main.command()
@click.pass_context
def resume(ctx):
    """Resume an interrupted scan (re-runs exposure scanning on existing services)."""
    _, cfg, db = _get_engine(ctx.obj.get("config"))

    # Find the last incomplete scan
    runs = db.get_scan_runs(limit=5)
    running = [r for r in runs if r.get("status") == "running"]

    if not running:
        console.print("[yellow]No interrupted scans found. Starting fresh scan...[/yellow]")
        ctx.invoke(scan)
        return

    console.print(f"[bold]Resuming interrupted scan[/bold] from {running[0].get('started_at')}")
    # Re-run exposure scanning on existing services
    ctx.invoke(exposures)


if __name__ == "__main__":
    main()
