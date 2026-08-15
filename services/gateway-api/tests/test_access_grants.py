from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    from gateway_api import config, database

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(
        settings.database_url,
        pool_pre_ping=True,
        **database._engine_args(settings.database_url),
    )
    database.SessionLocal.configure(bind=database.engine)

    from gateway_api.main import create_app
    from gateway_api.schema_migrations import run_schema_migrations

    run_schema_migrations(database.engine)
    with TestClient(create_app()) as test_client:
        yield test_client


def test_access_grant_revoke_is_idempotent(client: TestClient) -> None:
    created = client.post(
        "/api/access/grants",
        json={
            "grantee_subject": "research-unattended-approver",
            "resource_type": "autonomy_approval",
            "resource_id": "policy-rk-write-200",
            "scopes": ["approve"],
        },
    )
    assert created.status_code == 201
    grant = created.json()
    assert grant["status"] == "active"

    revoked = client.post(f"/api/access/grants/{grant['id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    replay = client.post(f"/api/access/grants/{grant['id']}/revoke")
    assert replay.status_code == 200
    assert replay.json()["id"] == grant["id"]
    assert replay.json()["status"] == "revoked"


def test_access_grant_revoke_unknown_id_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/access/grants/00000000-0000-0000-0000-000000000000/revoke"
    )
    assert response.status_code == 404


def test_static_openapi_documents_access_grant_revoke() -> None:
    root = Path(__file__).resolve().parents[3]
    text = (root / "openapi" / "gateway.openapi.yaml").read_text(encoding="utf-8")
    assert "  /api/access/grants/{grant_id}/revoke:\n" in text
    assert "      operationId: revokeAccessGrant\n" in text
