from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_AGENT_ALLOW_UNVERIFIED_GIT_CONTEXT", "true")
    monkeypatch.setenv(
        "GATEWAY_SSH_KNOWN_HOSTS_PATH", str(tmp_path / "ssh" / "known_hosts")
    )
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    monkeypatch.setenv("COMMAND_SESSION_SPOOL_ROOT", str(tmp_path / "command-sessions"))

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
    with TestClient(create_app()) as test_client:
        yield test_client


def seed_predecessor(
    *,
    client_id: str,
    redirect_uri: str,
    subject: str,
    mode: str = "required",
    generation: int = 5,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient, OAuthCode, utcnow

    with SessionLocal() as db:
        db.add(
            OAuthClient(
                client_id=client_id,
                client_name="ChatGPT",
                redirect_uris=[redirect_uri],
                scope="workspace:read",
                presentation_profile="chatgpt-stable",
                presentation_policy_generation=generation,
                presentation_mode="native_projected",
                chat_context_mode=mode,
                presentation_capabilities=["native_tools"],
                workspace_plan="none",
                allowed_tool_names=[],
            )
        )
        db.add(
            OAuthCode(
                code=f"historic-{client_id}",
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge="historic-challenge",
                scope="workspace:read",
                subject=subject,
                expires_at=utcnow() + timedelta(minutes=5),
                consumed=True,
            )
        )
        db.commit()


def register_and_authorize(
    client: TestClient,
    *,
    client_id: str,
    redirect_uri: str,
    verifier: str,
    scope: str,
) -> str:
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": client_id,
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri],
            "scope": scope,
        },
    )
    assert registered.status_code == 201
    authorized = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": scope,
        },
        follow_redirects=False,
    )
    assert authorized.status_code == 307
    return parse_qs(urlparse(authorized.headers["location"]).query)["code"][0]


def exchange(
    client: TestClient,
    *,
    client_id: str,
    redirect_uri: str,
    verifier: str,
    code: str,
):
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": verifier,
        },
    )


def test_chatgpt_replacement_inherits_policy_only_after_pkce(
    client: TestClient,
) -> None:
    from gateway_api.auth import decode_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient, OAuthCode

    redirect_uri = "https://chatgpt.com/connector/oauth/policy-lineage-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-policy-predecessor",
        redirect_uri=redirect_uri,
        subject=subject,
    )
    verifier = "chatgpt-policy-replacement-verifier-0123456789"
    code = register_and_authorize(
        client,
        client_id="chatgpt-policy-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        scope="workspace:read chat-context:write",
    )

    with SessionLocal() as db:
        replacement = db.get(OAuthClient, "chatgpt-policy-replacement")
        assert replacement is not None
        assert replacement.chat_context_mode == "off"
        assert replacement.presentation_policy_generation == 1

    token = exchange(
        client,
        client_id="chatgpt-policy-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        code=code,
    )
    assert token.status_code == 200
    claims = decode_jwt(token.json()["access_token"])
    assert claims["chat_context_mode"] == "required"
    assert claims["presentation_policy_generation"] == 2

    with SessionLocal() as db:
        predecessor = db.get(OAuthClient, "chatgpt-policy-predecessor")
        replacement = db.get(OAuthClient, "chatgpt-policy-replacement")
        exchanged_code = db.get(OAuthCode, code)
        assert predecessor is not None
        assert replacement is not None
        assert exchanged_code is not None
        assert predecessor.chat_context_mode == "off"
        assert predecessor.presentation_policy_generation == 6
        assert replacement.chat_context_mode == "required"
        assert replacement.presentation_policy_generation == 2
        assert exchanged_code.consumed is True


def test_chatgpt_replacement_does_not_inherit_foreign_subject_policy(
    client: TestClient,
) -> None:
    from gateway_api.auth import decode_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient

    redirect_uri = "https://chatgpt.com/connector/oauth/foreign-subject-test"
    seed_predecessor(
        client_id="chatgpt-foreign-predecessor",
        redirect_uri=redirect_uri,
        subject="different-owner-subject",
    )
    verifier = "chatgpt-foreign-replacement-verifier-0123456789"
    code = register_and_authorize(
        client,
        client_id="chatgpt-foreign-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        scope="workspace:read chat-context:write",
    )
    token = exchange(
        client,
        client_id="chatgpt-foreign-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        code=code,
    )
    assert token.status_code == 200
    claims = decode_jwt(token.json()["access_token"])
    assert claims["chat_context_mode"] == "off"
    assert claims["presentation_policy_generation"] == 1

    with SessionLocal() as db:
        predecessor = db.get(OAuthClient, "chatgpt-foreign-predecessor")
        replacement = db.get(OAuthClient, "chatgpt-foreign-replacement")
        assert predecessor is not None
        assert replacement is not None
        assert predecessor.chat_context_mode == "required"
        assert predecessor.presentation_policy_generation == 5
        assert replacement.chat_context_mode == "off"
        assert replacement.presentation_policy_generation == 1


def test_chatgpt_replacement_fails_closed_for_ambiguous_predecessors(
    client: TestClient,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient, OAuthCode

    redirect_uri = "https://chatgpt.com/connector/oauth/ambiguous-lineage-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-ambiguous-predecessor-a",
        redirect_uri=redirect_uri,
        subject=subject,
        mode="required",
    )
    seed_predecessor(
        client_id="chatgpt-ambiguous-predecessor-b",
        redirect_uri=redirect_uri,
        subject=subject,
        mode="optional",
    )
    verifier = "chatgpt-ambiguous-replacement-verifier-0123456789"
    code = register_and_authorize(
        client,
        client_id="chatgpt-ambiguous-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        scope="workspace:read chat-context:write",
    )
    token = exchange(
        client,
        client_id="chatgpt-ambiguous-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        code=code,
    )
    assert token.status_code == 409
    assert token.json()["detail"]["code"] == "MCP_PRESENTATION_POLICY_LINEAGE_AMBIGUOUS"

    with SessionLocal() as db:
        exchanged_code = db.get(OAuthCode, code)
        replacement = db.get(OAuthClient, "chatgpt-ambiguous-replacement")
        predecessor_a = db.get(OAuthClient, "chatgpt-ambiguous-predecessor-a")
        predecessor_b = db.get(OAuthClient, "chatgpt-ambiguous-predecessor-b")
        assert exchanged_code is not None
        assert replacement is not None
        assert predecessor_a is not None
        assert predecessor_b is not None
        assert exchanged_code.consumed is False
        assert replacement.chat_context_mode == "off"
        assert replacement.presentation_policy_generation == 1
        assert predecessor_a.chat_context_mode == "required"
        assert predecessor_b.chat_context_mode == "optional"


def test_non_chatgpt_replacement_does_not_inherit_policy(client: TestClient) -> None:
    from gateway_api.auth import decode_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient

    redirect_uri = "http://localhost:3000/policy-lineage-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="local-policy-predecessor",
        redirect_uri=redirect_uri,
        subject=subject,
    )
    verifier = "local-policy-replacement-verifier-0123456789"
    code = register_and_authorize(
        client,
        client_id="local-policy-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        scope="workspace:read",
    )
    token = exchange(
        client,
        client_id="local-policy-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        code=code,
    )
    assert token.status_code == 200
    claims = decode_jwt(token.json()["access_token"])
    assert claims["chat_context_mode"] == "off"
    assert claims["presentation_policy_generation"] == 1

    with SessionLocal() as db:
        predecessor = db.get(OAuthClient, "local-policy-predecessor")
        replacement = db.get(OAuthClient, "local-policy-replacement")
        assert predecessor is not None
        assert replacement is not None
        assert predecessor.chat_context_mode == "required"
        assert predecessor.presentation_policy_generation == 5
        assert replacement.chat_context_mode == "off"
        assert replacement.presentation_policy_generation == 1


def test_chatgpt_replacement_with_multiple_redirects_does_not_inherit(
    client: TestClient,
) -> None:
    from gateway_api.auth import decode_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient

    redirect_uri = "https://chatgpt.com/connector/oauth/multi-redirect-lineage-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-multi-redirect-predecessor",
        redirect_uri=redirect_uri,
        subject=subject,
    )
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": "chatgpt-multi-redirect-replacement",
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri, "http://localhost:3000/callback"],
            "scope": "workspace:read chat-context:write",
        },
    )
    assert registered.status_code == 201

    verifier = "chatgpt-multi-redirect-verifier-0123456789"
    authorized = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "chatgpt-multi-redirect-replacement",
            "redirect_uri": redirect_uri,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": "workspace:read chat-context:write",
        },
        follow_redirects=False,
    )
    assert authorized.status_code == 307
    code = parse_qs(urlparse(authorized.headers["location"]).query)["code"][0]
    token = exchange(
        client,
        client_id="chatgpt-multi-redirect-replacement",
        redirect_uri=redirect_uri,
        verifier=verifier,
        code=code,
    )
    assert token.status_code == 200
    claims = decode_jwt(token.json()["access_token"])
    assert claims["chat_context_mode"] == "off"
    assert claims["presentation_policy_generation"] == 1

    with SessionLocal() as db:
        predecessor = db.get(OAuthClient, "chatgpt-multi-redirect-predecessor")
        replacement = db.get(OAuthClient, "chatgpt-multi-redirect-replacement")
        assert predecessor is not None
        assert replacement is not None
        assert predecessor.chat_context_mode == "required"
        assert predecessor.presentation_policy_generation == 5
        assert replacement.chat_context_mode == "off"
        assert replacement.presentation_policy_generation == 1


def resolve_registered_presentation(client: TestClient, client_id: str):
    from gateway_api.auth import create_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.mcp_presentation import resolve_presentation_context
    from gateway_api.models import OAuthClient, User
    from starlette.requests import Request

    subject = client.get("/auth/me").json()["subject"]
    with SessionLocal() as db:
        user = db.query(User).filter(User.subject == subject).one()
        oauth_client = db.get(OAuthClient, client_id)
        assert oauth_client is not None
        token = create_jwt(
            subject=user.subject,
            username=user.username,
            roles=user.roles,
            scopes=["workspace:read"],
            token_type="access",
            ttl_seconds=300,
            extra={
                "client_id": oauth_client.client_id,
                "presentation_profile": oauth_client.presentation_profile,
                "presentation_policy_generation": oauth_client.presentation_policy_generation,
                "presentation_mode": oauth_client.presentation_mode,
                "chat_context_mode": oauth_client.chat_context_mode,
                "presentation_capabilities": list(
                    oauth_client.presentation_capabilities or []
                ),
                "workspace_plan": oauth_client.workspace_plan,
                "allowed_tool_names": list(oauth_client.allowed_tool_names or []),
            },
        )
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/mcp",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        return resolve_presentation_context(request, db, user)


def test_default_chatgpt_replacement_bearer_requires_reauthorization(
    client: TestClient,
) -> None:
    from fastapi import HTTPException

    redirect_uri = "https://chatgpt.com/connector/oauth/reauth-challenge-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-reauth-predecessor",
        redirect_uri=redirect_uri,
        subject=subject,
    )
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": "chatgpt-reauth-replacement",
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri],
            "scope": "workspace:read chat-context:write",
        },
    )
    assert registered.status_code == 201

    with pytest.raises(HTTPException) as denied:
        resolve_registered_presentation(client, "chatgpt-reauth-replacement")
    assert denied.value.status_code == 401
    assert denied.value.detail["code"] == "MCP_PRESENTATION_REAUTH_REQUIRED"


def test_default_chatgpt_replacement_bearer_ignores_foreign_subject_lineage(
    client: TestClient,
) -> None:
    redirect_uri = "https://chatgpt.com/connector/oauth/reauth-foreign-test"
    seed_predecessor(
        client_id="chatgpt-reauth-foreign-predecessor",
        redirect_uri=redirect_uri,
        subject="another-user-subject",
    )
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": "chatgpt-reauth-foreign-replacement",
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri],
            "scope": "workspace:read",
        },
    )
    assert registered.status_code == 201

    context = resolve_registered_presentation(
        client, "chatgpt-reauth-foreign-replacement"
    )
    assert context.chat_context_mode == "off"
    assert context.policy_generation == 1


def test_default_chatgpt_replacement_bearer_fails_closed_for_ambiguous_lineage(
    client: TestClient,
) -> None:
    from fastapi import HTTPException

    redirect_uri = "https://chatgpt.com/connector/oauth/reauth-ambiguous-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-reauth-ambiguous-a",
        redirect_uri=redirect_uri,
        subject=subject,
        mode="required",
    )
    seed_predecessor(
        client_id="chatgpt-reauth-ambiguous-b",
        redirect_uri=redirect_uri,
        subject=subject,
        mode="optional",
    )
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": "chatgpt-reauth-ambiguous-replacement",
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri],
            "scope": "workspace:read",
        },
    )
    assert registered.status_code == 201

    with pytest.raises(HTTPException) as denied:
        resolve_registered_presentation(client, "chatgpt-reauth-ambiguous-replacement")
    assert denied.value.status_code == 409
    assert denied.value.detail["code"] == "MCP_PRESENTATION_POLICY_LINEAGE_AMBIGUOUS"


def test_default_chatgpt_replacement_bearer_does_not_challenge_multi_redirect(
    client: TestClient,
) -> None:
    redirect_uri = "https://chatgpt.com/connector/oauth/reauth-multi-test"
    subject = client.get("/auth/me").json()["subject"]
    seed_predecessor(
        client_id="chatgpt-reauth-multi-predecessor",
        redirect_uri=redirect_uri,
        subject=subject,
    )
    registered = client.post(
        "/oauth/register",
        json={
            "client_id": "chatgpt-reauth-multi-replacement",
            "client_name": "ChatGPT",
            "redirect_uris": [redirect_uri, "http://localhost:3000/callback"],
            "scope": "workspace:read",
        },
    )
    assert registered.status_code == 201

    context = resolve_registered_presentation(
        client, "chatgpt-reauth-multi-replacement"
    )
    assert context.chat_context_mode == "off"
    assert context.policy_generation == 1
