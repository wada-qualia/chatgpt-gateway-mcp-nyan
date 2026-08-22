from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

EXTENSION_CLIENT_ID = "atlas-chatgpt-browser-extension"
EXTENSION_REDIRECT = "https://cgaalfflopmcbaodnlphklclnnhmdhcn.chromiumapp.org/oauth2"


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def configure_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    dev_auth: bool,
) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv(
        "GATEWAY_SECRET_KEY",
        "browser-extension-oauth-test-secret-0000000000000000",
    )
    monkeypatch.setenv(
        "GATEWAY_JWT_SECRET",
        "browser-extension-oauth-test-jwt-0000000000000000",
    )
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true" if dev_auth else "false")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))
    monkeypatch.setenv(
        "COMMAND_SESSION_SPOOL_ROOT",
        str(tmp_path / "command-sessions"),
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
    with configure_client(tmp_path, monkeypatch, dev_auth=True) as test_client:
        yield test_client


def register_extension(client: TestClient):
    return client.post(
        "/oauth/register",
        json={
            "client_id": EXTENSION_CLIENT_ID,
            "client_name": "ATLAS ChatGPT Browser Extension",
            "redirect_uris": [EXTENSION_REDIRECT],
            "scope": "workspace:read",
        },
    )


def authorize_extension(
    client: TestClient,
    verifier: str,
    *,
    scope: str = "workspace:read",
    state: str = "state-value",
):
    return client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uri": EXTENSION_REDIRECT,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": scope,
            "state": state,
        },
        follow_redirects=False,
    )


def exchange_extension(
    client: TestClient,
    code: str,
    verifier: str,
    *,
    redirect_uri: str = EXTENSION_REDIRECT,
):
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": verifier,
        },
    )


def test_extension_registration_is_exact_public_and_least_privilege(
    client: TestClient,
) -> None:
    registered = register_extension(client)
    assert registered.status_code == 201
    payload = registered.json()
    assert payload["client_id"] == EXTENSION_CLIENT_ID
    assert payload["redirect_uris"] == [EXTENSION_REDIRECT]
    assert payload["scope"] == "workspace:read"
    assert payload["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in payload

    wildcard = client.post(
        "/oauth/register",
        json={
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uris": ["https://*.chromiumapp.org/oauth2"],
            "scope": "workspace:read",
        },
    )
    assert wildcard.status_code == 400

    wrong_client = client.post(
        "/oauth/register",
        json={
            "client_id": "other-extension",
            "redirect_uris": [EXTENSION_REDIRECT],
            "scope": "workspace:read",
        },
    )
    assert wrong_client.status_code == 400

    elevated = client.post(
        "/oauth/register",
        json={
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uris": [EXTENSION_REDIRECT],
            "scope": "workspace:read workspace:write",
        },
    )
    assert elevated.status_code == 400


def test_extension_pkce_state_token_ttl_and_replay(client: TestClient) -> None:
    assert register_extension(client).status_code == 201
    verifier = "browser-extension-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    state = "state +/&?= unicode-allowed"

    authorized = authorize_extension(client, verifier, state=state)
    assert authorized.status_code == 307
    location = urlparse(authorized.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == EXTENSION_REDIRECT
    query = parse_qs(location.query)
    assert query["state"] == [state]
    code = query["code"][0]

    token = exchange_extension(client, code, verifier)
    assert token.status_code == 200
    assert token.json()["token_type"] == "Bearer"
    assert token.json()["scope"] == "workspace:read"
    assert token.json()["expires_in"] == 3600

    from gateway_api.auth import decode_jwt

    claims = decode_jwt(token.json()["access_token"])
    assert claims["client_id"] == EXTENSION_CLIENT_ID
    assert claims["scope"] == "workspace:read"
    assert claims["exp"] - claims["iat"] == 3600

    replay = exchange_extension(client, code, verifier)
    assert replay.status_code == 400
    assert replay.json()["detail"] == "Invalid authorization code"


def test_bad_verifier_and_redirect_do_not_consume_authorization_code(
    client: TestClient,
) -> None:
    assert register_extension(client).status_code == 201
    verifier = "browser-extension-verifier-do-not-consume-0123456789"
    authorized = authorize_extension(client, verifier)
    code = parse_qs(urlparse(authorized.headers["location"]).query)["code"][0]

    wrong_redirect = exchange_extension(
        client,
        code,
        verifier,
        redirect_uri="http://localhost:3000/callback",
    )
    assert wrong_redirect.status_code == 400

    wrong_verifier = exchange_extension(client, code, "definitely-wrong-verifier")
    assert wrong_verifier.status_code == 400
    assert wrong_verifier.json()["detail"] == "Invalid PKCE verifier"

    non_ascii = exchange_extension(client, code, "verifier-не-ascii")
    assert non_ascii.status_code == 400
    assert non_ascii.json()["detail"] == "Invalid PKCE verifier"

    correct = exchange_extension(client, code, verifier)
    assert correct.status_code == 200


def test_authorize_rejects_scope_elevation_non_s256_and_identity_mismatch(
    client: TestClient,
) -> None:
    assert register_extension(client).status_code == 201
    verifier = "browser-extension-verifier-policy-0123456789"

    elevated = authorize_extension(
        client,
        verifier,
        scope="workspace:read workspace:write",
    )
    assert elevated.status_code == 400
    assert elevated.json()["detail"] == "Invalid OAuth scope"

    non_s256 = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uri": EXTENSION_REDIRECT,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "plain",
            "scope": "workspace:read",
        },
        follow_redirects=False,
    )
    assert non_s256.status_code == 400

    wrong_redirect = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uri": "https://other.chromiumapp.org/oauth2",
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": "workspace:read",
        },
        follow_redirects=False,
    )
    assert wrong_redirect.status_code == 400


def test_registered_extension_policy_drift_fails_closed(client: TestClient) -> None:
    assert register_extension(client).status_code == 201

    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient

    with SessionLocal() as db:
        oauth_client = db.get(OAuthClient, EXTENSION_CLIENT_ID)
        assert oauth_client is not None
        oauth_client.scope = "workspace:read workspace:write"
        db.commit()

    authorize = authorize_extension(
        client,
        "browser-extension-verifier-policy-drift-0123456789",
    )
    assert authorize.status_code == 400
    assert "scope configuration mismatch" in authorize.json()["detail"]


def test_unauthenticated_authorize_resumes_through_keycloak_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.routers import auth as auth_router

    with configure_client(tmp_path, monkeypatch, dev_auth=False) as client:
        verifier = "browser-extension-verifier-login-resume-0123456789"
        params = {
            "response_type": "code",
            "client_id": EXTENSION_CLIENT_ID,
            "redirect_uri": EXTENSION_REDIRECT,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "scope": "workspace:read",
            "state": "resume-state",
        }
        first = client.get(
            "/oauth/authorize",
            params=params,
            follow_redirects=False,
        )
        assert first.status_code == 307
        login_url = urlparse(first.headers["location"])
        assert login_url.path == "/auth/login"
        next_path = parse_qs(login_url.query)["next"][0]
        assert next_path.startswith("/oauth/authorize?")
        assert parse_qs(urlparse(next_path).query)["client_id"] == [EXTENSION_CLIENT_ID]

        login = client.get(first.headers["location"], follow_redirects=False)
        assert login.status_code == 307
        keycloak_query = parse_qs(urlparse(login.headers["location"]).query)

        from gateway_api import config
        from gateway_api.auth import decode_jwt

        settings = config.get_settings()
        flow_cookie = login.cookies[f"{settings.gateway_session_cookie}_oauth_state"]
        flow = decode_jwt(flow_cookie)
        assert flow["next"] == next_path

        async def fake_exchange(
            code: str,
            redirect_uri: str,
            code_verifier: str,
        ) -> dict[str, object]:
            assert code == "keycloak-code"
            assert redirect_uri == "http://testserver/auth/callback"
            assert code_verifier == flow["code_verifier"]
            return {
                "sub": "keycloak:extension-user",
                "preferred_username": "extension-user",
                "email": "extension-user@k-lab.local",
                "realm_access": {"roles": ["gateway-user"]},
            }

        monkeypatch.setattr(
            auth_router,
            "exchange_keycloak_code",
            fake_exchange,
        )
        callback = client.get(
            "/auth/callback",
            params={
                "code": "keycloak-code",
                "state": keycloak_query["state"][0],
            },
            follow_redirects=False,
        )
        assert callback.status_code == 307
        assert callback.headers["location"] == next_path

        resumed = client.get(next_path, follow_redirects=False)
        assert resumed.status_code == 307
        resumed_location = urlparse(resumed.headers["location"])
        assert (
            f"{resumed_location.scheme}://{resumed_location.netloc}{resumed_location.path}"
            == EXTENSION_REDIRECT
        )
        assert parse_qs(resumed_location.query)["state"] == ["resume-state"]


def test_prompt_facade_still_requires_gateway_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with configure_client(tmp_path, monkeypatch, dev_auth=False) as client:
        response = client.get("/api/prompts/v1/releases/dev/manifest")
        assert response.status_code == 401
