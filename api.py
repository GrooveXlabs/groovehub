"""FastAPI REST API for GrooveHub."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from groovehub.db import get_session
from groovehub.github import parse_repo_url, fetch_metadata, clone_repo
from groovehub.models import Server, Scan, Finding
from groovehub.scanner import scan_directory, score_directory
from groovehub.scorer import SecurityGrade

app = FastAPI(
    title="GrooveHub API",
    description="MCP Server Registry with Security Scoring",
    version="0.1.0",
)


def _server_to_dict(server: Server) -> dict[str, Any]:
    latest = server.latest_scan
    return {
        "id": server.id,
        "full_name": server.full_name,
        "repo_url": server.repo_url,
        "description": server.description,
        "stars": server.stars,
        "registered_at": server.registered_at.isoformat() if server.registered_at else None,
        "last_scanned_at": server.last_scanned_at.isoformat() if server.last_scanned_at else None,
        "latest_scan": _scan_to_dict(latest) if latest else None,
    }


def _scan_to_dict(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "score": scan.score,
        "grade": scan.grade,
        "grade_label": SecurityGrade(scan.grade).label if scan.grade in [g.value for g in SecurityGrade] else scan.grade,
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "duration_ms": scan.duration_ms,
        "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
    }


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "GrooveHub", "version": "0.1.0"}


@app.get("/servers")
def list_servers(
    skip: int = 0,
    limit: int = 50,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """List all registered MCP servers."""
    servers = session.query(Server).offset(skip).limit(limit).all()
    return [_server_to_dict(s) for s in servers]


@app.get("/servers/{server_id}")
def get_server(
    server_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Get details for a specific server."""
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return _server_to_dict(server)


@app.post("/servers")
def register_server(
    repo_url: str,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Register a new MCP server by GitHub URL."""
    owner, name = parse_repo_url(repo_url)

    # Check if already registered
    existing = session.query(Server).filter_by(repo_url=repo_url).first()
    if existing:
        raise HTTPException(status_code=409, detail="Server already registered")

    # Fetch metadata
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
    session.refresh(server)

    return _server_to_dict(server)


@app.post("/servers/{server_id}/scan")
def scan_server(
    server_id: int,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Trigger a security scan for a registered server."""
    import shutil
    import tempfile
    from pathlib import Path

    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    temp_dir = Path(tempfile.mkdtemp(prefix=f"groovehub-api-{server.owner}-{server.name}-"))
    try:
        repo_path = clone_repo(server.owner, server.name, dest=temp_dir)
        scan_result, score_result = score_directory(repo_path)

        # Count findings by severity
        severity_counts: dict[str, int] = {}
        for finding in scan_result.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        # Create scan record
        scan = Scan(
            server_id=server.id,
            score=score_result.score,
            grade=score_result.grade.value,
            findings_count=len(scan_result.findings),
            critical_count=severity_counts.get("CRITICAL", 0),
            high_count=severity_counts.get("HIGH", 0),
            medium_count=severity_counts.get("MEDIUM", 0),
            low_count=severity_counts.get("LOW", 0),
            info_count=severity_counts.get("INFO", 0),
            duration_ms=scan_result.duration_ms,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # Create finding records
        for finding in scan_result.findings:
            db_finding = Finding(
                scan_id=scan.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                message=finding.message,
                file=str(finding.file) if finding.file else None,
                line=finding.line,
            )
            session.add(db_finding)

        # Update server last_scanned_at
        server.last_scanned_at = datetime.now(timezone.utc)
        session.commit()

        return _scan_to_dict(scan)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/servers/{server_id}/scans")
def list_scans(
    server_id: int,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """List all scans for a server."""
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return [_scan_to_dict(s) for s in server.scans]


@app.get("/servers/{server_id}/scans/{scan_id}/findings")
def get_findings(
    server_id: int,
    scan_id: int,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """Get findings for a specific scan."""
    scan = session.get(Scan, scan_id)
    if not scan or scan.server_id != server_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "message": f.message,
            "file": f.file,
            "line": f.line,
        }
        for f in scan.findings
    ]


@app.get("/leaderboard")
def leaderboard(
    limit: int = 10,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """Get top servers by security score."""
    from sqlalchemy import func

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

    result = []
    for scan in latest_scans:
        server = scan.server
        result.append({
            "rank": len(result) + 1,
            "server": _server_to_dict(server),
            "score": scan.score,
            "grade": scan.grade,
        })
    return result
