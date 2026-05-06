"""Tests for PurpleForge integration."""

from __future__ import annotations

from groovehub.db import init_db, get_session
from groovehub.models import Server, Scan, Artifact
from groovehub.purpleforge import (
    generate_mitre_map,
    generate_sigma_rules,
    generate_atomic_tests,
    generate_gap_report,
    generate_all_artifacts,
)


class TestPurpleForgeCore:
    def test_generate_mitre_map(self) -> None:
        findings = [
            {"rule_id": "shell_execution", "severity": "CRITICAL"},
            {"rule_id": "hardcoded_secret", "severity": "HIGH"},
            {"rule_id": "unknown_finding", "severity": "MEDIUM"},
        ]
        mapped = generate_mitre_map(findings)
        assert len(mapped) == 3
        assert mapped[0]["mitre"]["technique_id"] == "T1059.004"
        assert mapped[1]["mitre"]["technique_id"] == "T1552.001"
        assert mapped[2]["mitre"]["technique_id"] == "T1595"

    def test_generate_sigma_rules(self) -> None:
        findings = [
            {"rule_id": "shell_execution", "severity": "CRITICAL"},
            {"rule_id": "ssrf", "severity": "HIGH"},
        ]
        rules = generate_sigma_rules(findings)
        assert len(rules) == 2
        assert rules[0]["filename"].endswith(".yml")
        assert "title:" in rules[0]["content"]
        assert "logsource:" in rules[0]["content"]

    def test_generate_sigma_rules_dedup(self) -> None:
        findings = [
            {"rule_id": "shell_execution", "severity": "CRITICAL"},
            {"rule_id": "shell_execution", "severity": "HIGH"},
        ]
        rules = generate_sigma_rules(findings)
        assert len(rules) == 1

    def test_generate_atomic_tests(self) -> None:
        findings = [
            {"rule_id": "shell_execution", "severity": "CRITICAL"},
            {"rule_id": "ssrf", "severity": "HIGH"},
        ]
        tests = generate_atomic_tests(findings)
        assert len(tests) == 2
        assert tests[0]["filename"].endswith(".ps1")
        assert "Atomic Test:" in tests[0]["content"]

    def test_generate_gap_report(self) -> None:
        findings = [
            {"rule_id": "shell_execution", "severity": "CRITICAL"},
            {"rule_id": "ssrf", "severity": "HIGH"},
        ]
        sigma = generate_sigma_rules(findings)
        atomic = generate_atomic_tests(findings)
        report = generate_gap_report(findings, sigma, atomic)
        assert "Purple Team Gap Analysis Report" in report
        assert "Coverage Rate" in report
        assert "shell_execution" in report

    def test_generate_all_artifacts(self) -> None:
        findings = [{"rule_id": "shell_execution", "severity": "CRITICAL"}]
        artifacts = generate_all_artifacts(findings)
        assert "mitre" in artifacts
        assert "sigma_rules" in artifacts
        assert "atomic_tests" in artifacts
        assert "gap_report" in artifacts


class TestPurpleForgeAPI:
    @classmethod
    def setup_class(cls) -> None:
        init_db(":memory:")
        cls.client = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(
            __import__("groovehub.api", fromlist=["app"]).app
        )

    def test_mitre_not_found(self) -> None:
        response = self.client.get("/servers/999/mitre")
        assert response.status_code == 404

    def test_sigma_not_found(self) -> None:
        response = self.client.get("/servers/999/sigma")
        assert response.status_code == 404

    def test_atomic_not_found(self) -> None:
        response = self.client.get("/servers/999/atomic")
        assert response.status_code == 404

    def test_gap_not_found(self) -> None:
        response = self.client.get("/servers/999/gap-report")
        assert response.status_code == 404


class TestArtifactModel:
    def test_create_artifact(self) -> None:
        init_db(":memory:")
        with next(get_session()) as session:
            server = Server(repo_url="https://github.com/test/server", owner="test", name="server")
            session.add(server)
            session.commit()

            scan = Scan(server_id=server.id, score=85, grade="B", findings_count=1)
            session.add(scan)
            session.commit()

            artifact = Artifact(
                scan_id=scan.id,
                artifact_type="mitre",
                filename="mitre_mapping.json",
                content='{"technique": "T1059"}',
            )
            session.add(artifact)
            session.commit()

            assert artifact.id is not None
            assert artifact.scan.server_id == server.id
            assert len(scan.artifacts) == 1
