"""API authentication, authorization, and dashboard integration tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_registration_login_csrf_and_dashboard(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEPGUARD_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    from depguard.api.app import app
    from depguard.api.routes import scans as scan_routes
    from depguard.config import get_settings
    from depguard.db.session import engine as database_engine
    from depguard.models import Finding, Severity

    monkeypatch.setattr(get_settings(), "allow_private_targets", True)

    async def fake_scan(*args, **kwargs):
        del args, kwargs
        return [
            Finding(
                "Missing policy",
                Severity.MEDIUM,
                "HEADER",
                "No CSP",
                "Set a CSP",
                risk_score=55,
            )
        ]

    monkeypatch.setattr(scan_routes, "scan_url", fake_scan)

    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        registered = client.post(
            "/api/v1/auth/register",
            json={
                "username": "analyst",
                "email": "analyst@example.test",
                "password": "long-password-123",
            },
        )
        assert registered.status_code == 201
        assert (
            client.post(
                "/api/v1/auth/register",
                json={
                    "username": "analyst",
                    "email": "other@example.test",
                    "password": "long-password-123",
                },
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "analyst", "password": "incorrect-password"}
            ).status_code
            == 401
        )
        login = client.post(
            "/api/v1/auth/login", json={"username": "analyst", "password": "long-password-123"}
        )
        assert login.status_code == 200
        csrf = login.json()["csrf_token"]
        assert client.get("/api/v1/auth/me").json()["username"] == "analyst"
        denied = client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "authorization_confirmed": True},
        )
        assert denied.status_code == 403
        refused = client.post(
            "/api/v1/scans",
            headers={"X-CSRF-Token": csrf},
            json={"target_url": "https://example.com", "authorization_confirmed": False},
        )
        assert refused.status_code == 400
        created = client.post(
            "/api/v1/scans",
            headers={"X-CSRF-Token": csrf},
            json={
                "target_url": "http://127.0.0.1:8080",
                "authorization_confirmed": True,
                "profile": "quick",
            },
        )
        assert created.status_code == 202
        scan_id = created.json()["scan_id"]
        detail = client.get(f"/api/v1/scans/{scan_id}").json()
        assert detail["status"] == "completed"
        assert len(detail["findings"]) == 1
        result_id = detail["findings"][0]["result_id"]
        updated = client.patch(
            f"/api/v1/scans/{scan_id}/findings/{result_id}/false-positive",
            headers={"X-CSRF-Token": csrf},
            json={"false_positive": True},
        )
        assert updated.status_code == 200
        assert client.get(f"/api/v1/scans/{scan_id}").json()["risk_score"] == 0
        assert (
            client.post(
                f"/api/v1/scans/{scan_id}/cancel", headers={"X-CSRF-Token": csrf}
            ).status_code
            == 409
        )
        assert len(client.get("/api/v1/scans").json()) == 1
        assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 401
    database_engine.dispose()
