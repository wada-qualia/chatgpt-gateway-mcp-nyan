from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

EXTENSION_CLIENT_ID = "atlas-chatgpt-browser-extension"
EXTENSION_SCOPES = ["workspace:read", "chat-context:write"]


def configure_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv(
        "GATEWAY_SECRET_KEY",
        "chat-context-http-test-secret-000000000000000000000000",
    )
    monkeypatch.setenv(
        "GATEWAY_JWT_SECRET",
        "chat-context-http-test-jwt-000000000000000000000000000",
    )
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    monkeypatch.setenv(
        "COMMAND_SESSION_SPOOL_ROOT",
        str(tmp_path / "command-sessions"),
    )
    monkeypatch.setenv("GATEWAY_CHAT_CONTEXT_ENABLED", "true")
    monkeypatch.setenv(
        "GATEWAY_CHAT_CONTEXT_HMAC_KEY",
        "chat-context-http-hmac-key-0000000000000000000000000000",
    )

    from gateway_api import config, database
    from gateway_api.main import create_app
    from gateway_api.schema_migrations import run_schema_migrations

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(
        settings.database_url,
        pool_pre_ping=True,
        **database._engine_args(settings.database_url),
    )
    database.SessionLocal.configure(bind=database.engine)
    run_schema_migrations(database.engine)
    return TestClient(create_app())


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    with configure_client(tmp_path, monkeypatch) as test_client:
        yield test_client


def token(
    *,
    subject: str = "browser-extension-owner",
    scopes: list[str] | None = None,
    client_id: str = EXTENSION_CLIENT_ID,
) -> str:
    from gateway_api.auth import create_jwt

    return create_jwt(
        subject=subject,
        username=subject,
        roles=["gateway-user"],
        scopes=scopes if scopes is not None else EXTENSION_SCOPES,
        token_type="access",
        ttl_seconds=300,
        extra={"client_id": client_id},
    )


def auth_headers(**kwargs) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(**kwargs)}"}


def test_chat_context_http_requires_pinned_extension_scope(client: TestClient) -> None:
    payload = {"client_nonce": "scope-test-nonce", "project_ref": "g-p-scope"}

    missing = client.post("/api/chat-contexts/v1/contexts", json=payload)
    assert missing.status_code == 401

    old_scope = client.post(
        "/api/chat-contexts/v1/contexts",
        json=payload,
        headers=auth_headers(scopes=["workspace:read"]),
    )
    assert old_scope.status_code == 403
    assert old_scope.json()["detail"] == "Policy denied"

    wrong_client = client.post(
        "/api/chat-contexts/v1/contexts",
        json=payload,
        headers=auth_headers(client_id="another-public-client"),
    )
    assert wrong_client.status_code == 403
    assert wrong_client.json()["detail"] == "Policy denied"

    accepted = client.post(
        "/api/chat-contexts/v1/contexts",
        json=payload,
        headers=auth_headers(),
    )
    assert accepted.status_code == 200
    assert accepted.json()["chat_context"].isalnum()
    assert len(accepted.json()["chat_context"]) == 4


def test_provisional_create_bind_resolve_is_idempotent_and_owner_scoped(
    client: TestClient,
) -> None:
    headers = auth_headers()
    create_payload = {
        "client_nonce": "tab-41-project-alpha",
        "project_ref": "g-p-alpha",
    }
    first = client.post(
        "/api/chat-contexts/v1/contexts",
        json=create_payload,
        headers=headers,
    )
    assert first.status_code == 200
    lease = first.json()

    replay = client.post(
        "/api/chat-contexts/v1/contexts",
        json=create_payload,
        headers=headers,
    )
    assert replay.status_code == 200
    assert replay.json()["context_id"] == lease["context_id"]
    assert replay.json()["chat_context"] == lease["chat_context"]

    second_tab = client.post(
        "/api/chat-contexts/v1/contexts",
        json={"client_nonce": "tab-42-project-alpha", "project_ref": "g-p-alpha"},
        headers=headers,
    )
    assert second_tab.status_code == 200
    assert second_tab.json()["context_id"] != lease["context_id"]
    assert second_tab.json()["chat_context"] != lease["chat_context"]

    conversation_ref = "chatgpt-conversation-raw-value-must-not-persist"
    bound = client.post(
        f"/api/chat-contexts/v1/contexts/{lease['context_id']}/bind",
        json={"conversation_ref": conversation_ref},
        headers=headers,
    )
    assert bound.status_code == 200
    assert bound.json() == {
        "context_id": lease["context_id"],
        "key_version": 1,
        "newly_bound": True,
    }

    rebound = client.post(
        f"/api/chat-contexts/v1/contexts/{lease['context_id']}/bind",
        json={"conversation_ref": conversation_ref},
        headers=headers,
    )
    assert rebound.status_code == 200
    assert rebound.json()["newly_bound"] is False

    resolved = client.post(
        "/api/chat-contexts/v1/resolve",
        json={"conversation_ref": conversation_ref},
        headers=headers,
    )
    assert resolved.status_code == 200
    assert resolved.json()["context_id"] == lease["context_id"]
    assert resolved.json()["chat_context"] == lease["chat_context"]

    from gateway_api.database import SessionLocal
    from gateway_api.models import ChatContext, ChatContextEvent

    with SessionLocal() as db:
        context = db.get(ChatContext, lease["context_id"])
        assert context is not None
        assert context.conversation_ref_hmac is not None
        assert context.conversation_ref_hmac != conversation_ref
        assert conversation_ref not in context.conversation_ref_hmac
        events = (
            db.query(ChatContextEvent)
            .filter(ChatContextEvent.context_id == lease["context_id"])
            .all()
        )
        assert conversation_ref not in repr([event.event_metadata for event in events])

    foreign_headers = auth_headers(subject="browser-extension-other-owner")
    foreign_resolve = client.post(
        "/api/chat-contexts/v1/resolve",
        json={"conversation_ref": conversation_ref},
        headers=foreign_headers,
    )
    assert foreign_resolve.status_code == 404

    foreign_bind = client.post(
        f"/api/chat-contexts/v1/contexts/{lease['context_id']}/bind",
        json={"conversation_ref": "different-conversation"},
        headers=foreign_headers,
    )
    assert foreign_bind.status_code == 404


def test_chat_context_contracts_are_versioned_and_dynamic_routes_exist(
    client: TestClient,
) -> None:
    root = Path(__file__).resolve().parents[3]
    chat_contract = yaml.safe_load(
        (root / "contracts" / "chat-context" / "v1" / "openapi.yaml").read_text()
    )
    auth_v1 = yaml.safe_load(
        (
            root / "contracts" / "browser-extension-auth" / "v1" / "openapi.yaml"
        ).read_text()
    )
    auth_v2 = yaml.safe_load(
        (
            root / "contracts" / "browser-extension-auth" / "v2" / "openapi.yaml"
        ).read_text()
    )

    assert chat_contract["info"]["version"] == "1.0.0"
    assert set(chat_contract["paths"]) == {
        "/api/chat-contexts/v1/contexts",
        "/api/chat-contexts/v1/contexts/{context_id}/bind",
        "/api/chat-contexts/v1/resolve",
    }
    assert (
        auth_v1["components"]["schemas"]["TokenResponse"]["properties"]["scope"][
            "const"
        ]
        == "workspace:read"
    )
    assert (
        auth_v2["components"]["schemas"]["ExtensionScope"]["const"]
        == "workspace:read chat-context:write"
    )

    dynamic_paths = client.get("/openapi.json").json()["paths"]
    assert set(chat_contract["paths"]).issubset(dynamic_paths)
