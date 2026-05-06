"""Tests for GitHub integration."""

from __future__ import annotations

import pytest

from groovehub.github import parse_repo_url


class TestParseRepoUrl:
    def test_full_https_url(self) -> None:
        owner, name = parse_repo_url("https://github.com/GrooveXlabs/grooveguard")
        assert owner == "GrooveXlabs"
        assert name == "grooveguard"

    def test_url_with_git_suffix(self) -> None:
        owner, name = parse_repo_url("https://github.com/GrooveXlabs/grooveguard.git")
        assert owner == "GrooveXlabs"
        assert name == "grooveguard"

    def test_short_form(self) -> None:
        owner, name = parse_repo_url("owner/repo")
        assert owner == "owner"
        assert name == "repo"

    def test_trailing_slash(self) -> None:
        owner, name = parse_repo_url("https://github.com/owner/repo/")
        assert owner == "owner"
        assert name == "repo"

    def test_invalid_url_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_repo_url("not-a-url")
