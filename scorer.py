"""Security scoring engine for MCP servers."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

from grooveguard.scanner import ScanResult


class SecurityGrade(enum.Enum):
    """Letter grade based on security score."""

    A = "A"  # 90-100: Safe
    B = "B"  # 80-89: Good
    C = "C"  # 60-79: Caution
    D = "D"  # 40-59: Warning
    F = "F"  # 0-39: Dangerous

    @classmethod
    def from_score(cls, score: int) -> SecurityGrade:
        if score >= 90:
            return cls.A
        if score >= 80:
            return cls.B
        if score >= 60:
            return cls.C
        if score >= 40:
            return cls.D
        return cls.F

    @property
    def label(self) -> str:
        return {
            SecurityGrade.A: "🟢 Safe",
            SecurityGrade.B: "🟡 Good",
            SecurityGrade.C: "🟠 Caution",
            SecurityGrade.D: "🔴 Warning",
            SecurityGrade.F: "⛔ Dangerous",
        }[self]

    @property
    def color(self) -> str:
        return {
            SecurityGrade.A: "green",
            SecurityGrade.B: "yellow",
            SecurityGrade.C: "orange",
            SecurityGrade.D: "red",
            SecurityGrade.F: "bright_red",
        }[self]


@dataclass
class ScoreResult:
    """Result of scoring a server."""

    score: int
    grade: SecurityGrade
    base_score: int
    deductions: dict[str, int]
    bonuses: dict[str, int]
    total_deductions: int
    total_bonuses: int


# Severity weights for deductions
SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 1,
}


def score_scan(scan_result: ScanResult, repo_path: Path | None = None) -> ScoreResult:
    """Calculate a security score from a GrooveGuard scan result.

    Scoring:
    - Base: 100
    - Deductions: CRITICAL(-20), HIGH(-10), MEDIUM(-5), LOW(-2), INFO(-1)
    - Bonuses:
        + tests/ directory exists: +10
        + LICENSE file exists: +5
        + SECURITY.md exists: +5
        + Lockfile exists (poetry.lock/Pipfile.lock/package-lock.json): +5
        + CI/CD config (.github/workflows): +5
    """
    base_score = 100
    deductions: dict[str, int] = {}
    bonuses: dict[str, int] = {}

    # Count findings by severity
    severity_counts: dict[str, int] = {}
    for finding in scan_result.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    # Apply deductions
    total_deductions = 0
    for severity, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        deduction = count * weight
        deductions[f"{severity} ({count}x)"] = deduction
        total_deductions += deduction

    # Apply bonuses for repo hygiene
    total_bonuses = 0
    if repo_path and repo_path.exists():
        if any(repo_path.rglob("test_*.py")) or (repo_path / "tests").is_dir():
            bonuses["Has tests"] = 10
            total_bonuses += 10

        if any(repo_path.glob("LICENSE*")):
            bonuses["Has LICENSE"] = 5
            total_bonuses += 5

        if any(repo_path.glob("SECURITY*")):
            bonuses["Has SECURITY.md"] = 5
            total_bonuses += 5

        if any(
            f.exists()
            for f in [
                repo_path / "poetry.lock",
                repo_path / "Pipfile.lock",
                repo_path / "package-lock.json",
                repo_path / "uv.lock",
            ]
        ):
            bonuses["Has lockfile"] = 5
            total_bonuses += 5

        if (repo_path / ".github" / "workflows").is_dir():
            bonuses["Has CI/CD"] = 5
            total_bonuses += 5

    # Calculate final score
    raw_score = base_score - total_deductions + total_bonuses
    score = max(0, min(100, raw_score))
    grade = SecurityGrade.from_score(score)

    return ScoreResult(
        score=score,
        grade=grade,
        base_score=base_score,
        deductions=deductions,
        bonuses=bonuses,
        total_deductions=total_deductions,
        total_bonuses=total_bonuses,
    )
