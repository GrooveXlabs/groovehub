"""GrooveGuard integration for scanning MCP servers."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Scanner, ScanResult
from grooveguard.rules import build_rules

from groovehub.scorer import ScoreResult, score_scan


def scan_directory(path: Path) -> ScanResult:
    """Run GrooveGuard on a local directory.

    Excludes common non-source directories and test files.
    """
    rules = build_rules()
    scanner = Scanner(
        rules=rules,
        exclude_patterns=[
            "*/.git/*",
            "*/__pycache__/*",
            "*/venv/*",
            "*/node_modules/*",
            "*/tests/*",
            "*/test_*.py",
            "*/dist/*",
            "*/build/*",
        ],
    )
    return scanner.scan_target(str(path))


def score_directory(path: Path) -> tuple[ScanResult, ScoreResult]:
    """Scan and score a local directory.

    Returns (scan_result, score_result).
    """
    scan_result = scan_directory(path)
    score_result = score_scan(scan_result, repo_path=path)
    return scan_result, score_result


def scan_repo(owner: str, name: str) -> tuple[Path, ScanResult, ScoreResult]:
    """Clone a repo, scan it, and return results.

    The cloned directory is returned so the caller can clean it up.
    """
    from groovehub.github import clone_repo

    temp_dir = Path(tempfile.mkdtemp(prefix=f"groovehub-scan-{owner}-{name}-"))
    try:
        repo_path = clone_repo(owner, name, dest=temp_dir)
        scan_result, score_result = score_directory(repo_path)
        return repo_path, scan_result, score_result
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
