"""Click CLI for GrooveHub."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from groovehub.db import init_db, get_session
from groovehub.github import parse_repo_url, fetch_metadata, clone_repo
from groovehub.models import Server, Scan
from groovehub.scanner import score_directory
from groovehub.scorer import SecurityGrade

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="groovehub")
def main() -> None:
    """GrooveHub — MCP Server Registry with Security Scoring."""
    init_db()


@main.command()
@click.argument("repo_url")
def register(repo_url: str) -> None:
    """Register a new MCP server by GitHub URL."""
    owner, name = parse_repo_url(repo_url)

    with next(get_session()) as session:
        existing = session.query(Server).filter_by(repo_url=repo_url).first()
        if existing:
            console.print(f"[yellow]Server {existing.full_name} is already registered.[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(description=f"Fetching metadata for {owner}/{name}...", total=None)
            metadata = fetch_metadata(owner, name)

        server = Server(
            repo_url=metadata.html_url,
            owner=owner,
            name=name,
            description=metadata.description,
            stars=metadata.stars,
        )
        session.add(server)
        session.commit()

        console.print(f"[green]Registered {server.full_name} (⭐ {server.stars})[/green]")


@main.command()
@click.argument("repo_url")
def scan(repo_url: str) -> None:
    """Scan a GitHub repository for security issues."""
    owner, name = parse_repo_url(repo_url)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(description=f"Cloning {owner}/{name}...", total=None)
        temp_dir = Path(tempfile.mkdtemp(prefix=f"groovehub-{owner}-{name}-"))
        try:
            repo_path = clone_repo(owner, name, dest=temp_dir)
            progress.update(task, description=f"Scanning {owner}/{name}...")
            scan_result, score_result = score_directory(repo_path)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Display results
    grade = score_result.grade
    color = grade.color
    score_text = f"[{color}]{score_result.score}/100 — {grade.label}[/{color}]"

    panel_content = [
        f"Score: {score_text}",
        f"Files scanned: {scan_result.files_scanned}",
        f"Total findings: {len(scan_result.findings)}",
        f"Duration: {scan_result.duration_ms:.2f} ms",
        "",
    ]

    if score_result.deductions:
        panel_content.append("[red]Deductions:[/red]")
        for label, value in score_result.deductions.items():
            panel_content.append(f"  -{value}: {label}")

    if score_result.bonuses:
        panel_content.append("")
        panel_content.append("[green]Bonuses:[/green]")
        for label, value in score_result.bonuses.items():
            panel_content.append(f"  +{value}: {label}")

    console.print(Panel("\n".join(panel_content), title=f"Scan: {owner}/{name}"))

    # Show findings table
    if scan_result.findings:
        table = Table(title="Findings")
        table.add_column("Severity", style="red")
        table.add_column("Rule", style="cyan")
        table.add_column("File", style="magenta")
        table.add_column("Message", style="white")

        for f in sorted(scan_result.findings, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(x.severity) if x.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else 99):
            table.add_row(f.severity, f.rule_id, str(f.file), f.message[:60])
        console.print(table)

        sys.exit(1 if grade in (SecurityGrade.D, SecurityGrade.F) else 0)
    else:
        console.print("[green]No findings — clean bill of health![/green]")


@main.command()
@click.option("--limit", default=50, help="Max servers to show.")
def list(limit: int) -> None:
    """List all registered servers."""
    with next(get_session()) as session:
        servers = session.query(Server).limit(limit).all()

    if not servers:
        console.print("[yellow]No servers registered yet.[/yellow]")
        return

    table = Table(title="Registered MCP Servers")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Server", style="magenta")
    table.add_column("Stars", style="yellow", justify="right")
    table.add_column("Score", style="green", justify="right")
    table.add_column("Grade", style="red")
    table.add_column("Last Scanned", style="white")

    for server in servers:
        latest = server.latest_scan
        score = str(latest.score) if latest else "—"
        grade = latest.grade if latest else "—"
        scanned = server.last_scanned_at.strftime("%Y-%m-%d") if server.last_scanned_at else "—"
        table.add_row(
            str(server.id),
            server.full_name,
            str(server.stars),
            score,
            grade,
            scanned,
        )

    console.print(table)


@main.command()
@click.argument("server_id", type=int)
def score(server_id: int) -> None:
    """Show the latest security score for a registered server."""
    with next(get_session()) as session:
        server = session.get(Server, server_id)
        if not server:
            console.print(f"[red]Server {server_id} not found.[/red]")
            sys.exit(1)

        latest = server.latest_scan
        if not latest:
            console.print(f"[yellow]Server {server.full_name} has not been scanned yet.[/yellow]")
            return

    grade = SecurityGrade(latest.grade) if latest.grade in [g.value for g in SecurityGrade] else None
    color = grade.color if grade else "white"
    label = grade.label if grade else latest.grade

    panel = Panel(
        f"Score: [{color}]{latest.score}/100 — {label}[/{color}]\n"
        f"Findings: {latest.findings_count}\n"
        f"  Critical: {latest.critical_count}\n"
        f"  High: {latest.high_count}\n"
        f"  Medium: {latest.medium_count}\n"
        f"  Low: {latest.low_count}\n"
        f"  Info: {latest.info_count}\n"
        f"Scanned: {latest.scanned_at}",
        title=f"{server.full_name}",
    )
    console.print(panel)


@main.command(name="leaderboard")
@click.option("--limit", default=10, help="Number of top servers to show.")
def show_leaderboard(limit: int) -> None:
    """Show the security leaderboard."""
    from sqlalchemy import func

    with next(get_session()) as session:
        subq = (
            session.query(
                Scan.server_id,
                func.max(Scan.scanned_at).label("latest_scan_time"),
            )
            .group_by(Scan.server_id)
            .subquery()
        )

        latest_scans = (
            session.query(Scan)
            .join(subq, (Scan.server_id == subq.c.server_id) & (Scan.scanned_at == subq.c.latest_scan_time))
            .order_by(Scan.score.desc())
            .limit(limit)
            .all()
        )

    if not latest_scans:
        console.print("[yellow]No scanned servers yet.[/yellow]")
        return

    table = Table(title="🏆 Security Leaderboard")
    table.add_column("Rank", style="cyan", justify="center")
    table.add_column("Server", style="magenta")
    table.add_column("Score", style="green", justify="right")
    table.add_column("Grade", style="red")
    table.add_column("Findings", style="yellow", justify="right")

    for i, scan in enumerate(latest_scans, 1):
        medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(i, f"#{i}")
        grade = SecurityGrade(scan.grade) if scan.grade in [g.value for g in SecurityGrade] else None
        label = grade.label if grade else scan.grade
        table.add_row(medal, scan.server.full_name, str(scan.score), label, str(scan.findings_count))

    console.print(table)


@main.command()
def serve() -> None:
    """Start the GrooveHub API server."""
    import uvicorn
    console.print("[green]Starting GrooveHub API on http://127.0.0.1:8000[/green]")
    uvicorn.run("groovehub.api:app", host="127.0.0.1", port=8000, reload=False)


@main.command(name="artifacts")
@click.argument("server_id", type=int)
@click.option("--type", "artifact_type", default="all", help="Filter by type: mitre, sigma, atomic, gap, all")
def show_artifacts(server_id: int, artifact_type: str) -> None:
    """Show PurpleForge artifacts for a server's latest scan."""
    with next(get_session()) as session:
        server = session.get(Server, server_id)
        if not server:
            console.print(f"[red]Server {server_id} not found.[/red]")
            sys.exit(1)

        latest = server.latest_scan
        if not latest:
            console.print(f"[yellow]Server {server.full_name} has not been scanned yet.[/yellow]")
            return

        query = session.query(Artifact).filter_by(scan_id=latest.id)
        if artifact_type != "all":
            query = query.filter_by(artifact_type=artifact_type)

        artifacts = query.all()

    if not artifacts:
        console.print(f"[yellow]No artifacts found for {server.full_name}.[/yellow]")
        return

    console.print(f"[cyan]Artifacts for {server.full_name} (scan #{latest.id})[/cyan]")
    for a in artifacts:
        color = {"mitre": "blue", "sigma": "green", "atomic": "yellow", "gap": "magenta"}.get(a.artifact_type, "white")
        console.print(f"\n[{color}]{a.artifact_type.upper()}: {a.filename}[/{color}]")
        console.print(a.content[:800] + "..." if len(a.content) > 800 else a.content)


if __name__ == "__main__":
    main()
