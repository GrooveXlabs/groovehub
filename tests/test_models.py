"""Tests for database models."""

from __future__ import annotations

from datetime import datetime, timezone

from groovehub.db import init_db, get_session
from groovehub.models import Server, Scan, Finding


class TestModels:
    def test_create_server(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            server = Server(
                repo_url="https://github.com/test/server",
                owner="test",
                name="server",
                description="Test server",
                stars=42,
            )
            session.add(server)
            session.commit()

            assert server.id is not None
            assert server.full_name == "test/server"
            assert server.latest_scan is None

    def test_server_with_scans(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            server = Server(repo_url="https://github.com/test/server", owner="test", name="server")
            session.add(server)
            session.commit()

            scan = Scan(
                server_id=server.id,
                score=85,
                grade="B",
                findings_count=3,
                critical_count=0,
                high_count=1,
                medium_count=2,
                low_count=0,
                info_count=0,
                duration_ms=150.0,
            )
            session.add(scan)
            session.commit()

            finding = Finding(
                scan_id=scan.id,
                rule_id="SEC-001",
                title="API Key",
                severity="HIGH",
                message="Found key",
                file="server.py",
                line=10,
            )
            session.add(finding)
            session.commit()

            # Refresh relationships
            session.refresh(server)
            session.refresh(scan)

            assert len(server.scans) == 1
            assert server.latest_scan.score == 85
            assert len(scan.findings) == 1
            assert scan.findings[0].rule_id == "SEC-001"

    def test_leaderboard_query(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            s1 = Server(repo_url="https://github.com/a/s1", owner="a", name="s1")
            s2 = Server(repo_url="https://github.com/b/s2", owner="b", name="s2")
            session.add_all([s1, s2])
            session.commit()

            scan1 = Scan(server_id=s1.id, score=95, grade="A", findings_count=0)
            scan2 = Scan(server_id=s2.id, score=80, grade="B", findings_count=3)
            session.add_all([scan1, scan2])
            session.commit()

            scans = session.query(Scan).order_by(Scan.score.desc()).all()
            assert scans[0].score == 95
            assert scans[1].score == 80
