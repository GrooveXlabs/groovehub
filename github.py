"""GitHub repository fetching and metadata extraction."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

GITHUB_API_BASE = "https://api.github.com"


@dataclass
class RepoMetadata:
    """Metadata extracted from a GitHub repository."""

    owner: str
    name: str
    description: str | None
    stars: int
    language: str | None
    license: str | None
    topics: list[str]
    default_branch: str
    html_url: str
    clone_url: str


def parse_repo_url(url: str) -> tuple[str, str]:
    """Parse owner and repo name from a GitHub URL.

    Supports:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - github.com/owner/repo
    - owner/repo
    """
    url = url.strip().rstrip("/").rstrip(".git")
    if url.startswith("https://"):
        url = url[len("https://"):]
    if url.startswith("http://"):
        url = url[len("http://"):]

    match = re.match(r"(?:github\.com/)?(\w[\w.-]*)/(\w[\w.-]*)", url)
    if not match:
        raise ValueError(f"Cannot parse GitHub repo URL: {url}")

    return match.group(1), match.group(2)


def fetch_metadata(owner: str, name: str, token: str | None = None) -> RepoMetadata:
    """Fetch repository metadata from GitHub API."""
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"{GITHUB_API_BASE}/repos/{owner}/{name}"
    response = httpx.get(url, headers=headers, timeout=30.0)
    response.raise_for_status()
    data: dict[str, Any] = response.json()

    license_info = data.get("license")
    return RepoMetadata(
        owner=owner,
        name=name,
        description=data.get("description"),
        stars=data.get("stargazers_count", 0),
        language=data.get("language"),
        license=license_info.get("spdx_id") if license_info else None,
        topics=data.get("topics", []),
        default_branch=data.get("default_branch", "main"),
        html_url=data.get("html_url", f"https://github.com/{owner}/{name}"),
        clone_url=data.get("clone_url", f"https://github.com/{owner}/{name}.git"),
    )


def clone_repo(owner: str, name: str, dest: Path | None = None) -> Path:
    """Clone a GitHub repository to a local path.

    Returns the path to the cloned repository.
    If dest is not provided, uses a temporary directory.
    """
    clone_url = f"https://github.com/{owner}/{name}.git"

    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix=f"groovehub-{owner}-{name}-"))
    else:
        dest = Path(dest)
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to clone {clone_url}: {result.stderr}")

    return dest


def fetch_repo(owner: str, name: str, token: str | None = None) -> tuple[RepoMetadata, Path]:
    """Fetch metadata and clone a repository.

    Returns (metadata, local_path).
    """
    metadata = fetch_metadata(owner, name, token)
    path = clone_repo(owner, name)
    return metadata, path
