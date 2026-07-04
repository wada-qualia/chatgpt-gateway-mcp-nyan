from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    import gateway_api.config as config
    import gateway_api.database as database

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(settings.database_url, pool_pre_ping=True, **database._engine_args(settings.database_url))
    database.SessionLocal.configure(bind=database.engine)

    from gateway_api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def test_auth_me_dev_user(client: TestClient) -> None:
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "darius"


def test_oauth_facade_pkce_flow(client: TestClient) -> None:
    register = client.post(
        "/oauth/register",
        json={"redirect_uris": ["http://localhost:3000/callback"], "client_name": "test"},
    )
    assert register.status_code == 201
    client_id = register.json()["client_id"]
    verifier = "abcdefghijklmnopqrstuvwxyz0123456789"
    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": "workspace:read",
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 307
    code = parse_qs(urlparse(authorize.headers["location"]).query)["code"][0]
    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:3000/callback",
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200
    assert token.json()["token_type"] == "Bearer"


def test_device_registration_encrypts_secret(client: TestClient) -> None:
    response = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.5:2222", "auth_type": "password", "password": "plain-password"},
    )
    assert response.status_code == 201
    assert response.json()["host"] == "10.0.0.5"

    from gateway_api.database import SessionLocal
    from gateway_api.models import SecretBlob

    with SessionLocal() as db:
        secret = db.query(SecretBlob).one()
        assert "plain-password" not in secret.ciphertext


def test_docker_workspace_allowlist_and_simulated_create(client: TestClient) -> None:
    images = client.get("/api/docker/images")
    assert images.status_code == 200
    assert "ubuntu:24.04" in images.json()["images"]
    created = client.post("/api/docker/workspaces", json={"name": "lab", "image": "ubuntu:24.04"})
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    denied = client.post("/api/docker/workspaces", json={"name": "bad", "image": "alpine:latest"})
    assert denied.status_code == 400


def test_thin_client_device_code_registration(client: TestClient) -> None:
    code = client.post("/api/thin-clients/device-code")
    assert code.status_code == 201
    token = client.post("/api/thin-clients/token", json={"device_code": code.json()["device_code"]})
    assert token.status_code == 200
    registered = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project"},
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    assert registered.status_code == 201
    assert registered.json()["hostname"] == "workstation"


def test_mcp_tools_list(client: TestClient) -> None:
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    names = [tool["name"] for tool in response.json()["result"]["tools"]]
    assert "workspace_info" in names
