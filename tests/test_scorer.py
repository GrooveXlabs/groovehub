"""Tests for the scoring engine."""

from __future__ import annotations

from pathlib import Path

from grooveguard.scanner import Finding, ScanResult
from groovehub.scorer import SecurityGrade, score_scan, SEVERITY_WEIGHTS


class TestSecurityGrade:
    def test_grade_a(self) -> None:
        assert SecurityGrade.from_score(95) == SecurityGrade.A
        assert SecurityGrade.from_score(90) == SecurityGrade.A
        assert SecurityGrade.from_score(100) == SecurityGrade.A

    def test_grade_b(self) -> None:
        assert SecurityGrade.from_score(89) == SecurityGrade.B
        assert SecurityGrade.from_score(80) == SecurityGrade.B

    def test_grade_c(self) -> None:
        assert SecurityGrade.from_score(79) == SecurityGrade.C
        assert SecurityGrade.from_score(60) == SecurityGrade.C

    def test_grade_d(self) -> None:
        assert SecurityGrade.from_score(59) == SecurityGrade.D
        assert SecurityGrade.from_score(40) == SecurityGrade.D

    def test_grade_f(self) -> None:
        assert SecurityGrade.from_score(39) == SecurityGrade.F
        assert SecurityGrade.from_score(0) == SecurityGrade.F

    def test_grade_labels(self) -> None:
        assert "Safe" in SecurityGrade.A.label
        assert "Dangerous" in SecurityGrade.F.label


class TestScoreScan:
    def test_clean_scan(self) -> None:
        result = ScanResult(findings=[], files_scanned=10, duration_ms=100.0)
        score = score_scan(result)
        assert score.score == 100
        assert score.grade == SecurityGrade.A
        assert score.total_deductions == 0

    def test_critical_finding(self) -> None:
        finding = Finding(
            rule_id="SEC-001",
            title="Hardcoded API Key",
            severity="CRITICAL",
            message="Found API key",
            file=Path("server.py"),
            line=10,
            column=0,
            snippet="api_key = 'sk-xxx'",
        )
        result = ScanResult(findings=[finding], files_scanned=1, duration_ms=50.0)
        score = score_scan(result)
        assert score.score == 100 - SEVERITY_WEIGHTS["CRITICAL"]
        assert score.score == 80
        assert score.grade == SecurityGrade.B

    def test_multiple_findings(self) -> None:
        findings = [
            Finding("SEC-001", "API Key", "CRITICAL", "msg", Path("a.py"), 1, 0, ""),
            Finding("SEC-002", "Token", "HIGH", "msg", Path("a.py"), 2, 0, ""),
            Finding("DNG-001", "Shell", "HIGH", "msg", Path("a.py"), 3, 0, ""),
        ]
        result = ScanResult(findings=findings, files_scanned=1, duration_ms=50.0)
        score = score_scan(result)
        expected = 100 - 20 - 10 - 10  # 60
        assert score.score == expected
        assert score.grade == SecurityGrade.C

    def test_score_floor_at_zero(self) -> None:
        findings = [Finding("SEC-001", "API Key", "CRITICAL", "msg", Path("a.py"), i, 0, "")
                    for i in range(10)]
        result = ScanResult(findings=findings, files_scanned=1, duration_ms=50.0)
        score = score_scan(result)
        assert score.score == 0
        assert score.grade == SecurityGrade.F

    def test_bonuses(self, tmp_path: Path) -> None:
        (tmp_path / "tests").mkdir()
        (tmp_path / "LICENSE").write_text("MIT")
        (tmp_path / "SECURITY.md").write_text("security")
        (tmp_path / "poetry.lock").write_text("lock")
        (tmp_path / ".github" / "workflows").mkdir(parents=True)

        result = ScanResult(findings=[], files_scanned=10, duration_ms=100.0)
        score = score_scan(result, repo_path=tmp_path)

        assert score.score == 100  # capped at 100
        assert score.score == 100
        assert "Has tests" in score.bonuses
        assert "Has LICENSE" in score.bonuses
        assert "Has SECURITY.md" in score.bonuses
        assert "Has lockfile" in score.bonuses
        assert "Has CI/CD" in score.bonuses
