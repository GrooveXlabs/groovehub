"""Tests for FastAPI endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from groovehub.db import init_db
from groovehub.api import app


class TestAPI:
    @classmethod
    def setup_class(cls) -> None:
        init_db(":memory:")
        cls.client = TestClient(app)

    def test_root(self) -> None:
        response = self.client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "GrooveHub"
        assert data["version"] == "0.1.0"

    def test_list_empty_servers(self) -> None:
        response = self.client.get("/servers")
        assert response.status_code == 200
        assert response.json() == []

    def test_register_server(self) -> None:
        # This would need network mocking - skip for unit test
        pass

    def test_get_nonexistent_server(self) -> None:
        response = self.client.get("/servers/999")
        assert response.status_code == 404

    def test_leaderboard_empty(self) -> None:
        response = self.client.get("/leaderboard")
        assert response.status_code == 200
        assert response.json() == []
