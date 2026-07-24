from __future__ import annotations

import asyncio
import json
import base64
import hashlib
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


class NoteError(AssertionError):
    pass


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    dev_auth = getattr(request, "param", True)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true" if dev_auth else "false")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_AGENT_ALLOW_UNVERIFIED_GIT_CONTEXT", "true")
    monkeypatch.setenv(
        "GATEWAY_SSH_KNOWN_HOSTS_PATH", str(tmp_path / "ssh" / "known_hosts")
    )
    monkeypatch.setenv("MAX_COMMAND_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("COMMAND_BACKGROUND_AFTER_SECONDS", "1")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    import gateway_api.config as config
    import gateway_api.database as database

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(settings.database_url, pool_pre_ping=True, **database._engine_args(settings.database_url),
    )
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


def test_account_ssh_command_profile_defaults_and_override(client: TestClient) -> None:
    current = client.get("/api/account/settings")
    assert current.status_code == 200
    assert current.json() == {
        "ui_language": "en",
        "ssh_command_profile": "unrestricted",
        "ssh_command_profile_override": None,
        "ssh_command_profile_default": "unrestricted",
        "raw_commands_enabled": True,
        "deny_patterns_enabled": False,
    }

    russian = client.patch(
        "/api/account/settings",
        json={"ui_language": "ru"},
    )
    assert russian.status_code == 200
    assert russian.json()["ui_language"] == "ru"
    assert russian.json()["ssh_command_profile"] == "unrestricted"
    persisted = client.get("/api/account/settings")
    assert persisted.status_code == 200
    assert persisted.json()["ui_language"] == "ru"

    restricted = client.patch(
        "/api/account/settings",
        json={"ssh_command_profile": "restricted"},
    )
    assert restricted.status_code == 200
    assert restricted.json()["ssh_command_profile"] == "restricted"
    assert restricted.json()["ssh_command_profile_override"] == "restricted"
    assert restricted.json()["raw_commands_enabled"] is False

    inherited = client.patch(
        "/api/account/settings",
        json={"ssh_command_profile": "inherit"},
    )
    assert inherited.status_code == 200
    assert inherited.json()["ssh_command_profile"] == "unrestricted"
    assert inherited.json()["ssh_command_profile_override"] is None
    assert inherited.json()["raw_commands_enabled"] is True


@pytest.mark.parametrize("client", [False], indirect=True)
def test_keycloak_login_uses_pkce_and_signed_state(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from gateway_api import config
    from gateway_api.auth import decode_jwt
    from gateway_api.routers import auth as auth_router

    login = client.get("/auth/login", params={"next": "/devices"}, follow_redirects=False)
    assert login.status_code == 307
    authorize_query = parse_qs(urlparse(login.headers["location"]).query)
    assert authorize_query["code_challenge_method"] == ["S256"]
    assert authorize_query["state"]

    settings = config.get_settings()
    flow_cookie_name = f"{settings.gateway_session_cookie}_oauth_state"
    flow = decode_jwt(login.cookies[flow_cookie_name])
    assert flow["typ"] == "oauth_state"
    assert flow["next"] == "/devices"
    assert authorize_query["code_challenge"] == [pkce_challenge(flow["code_verifier"])]

    exchanged: dict[str, str] = {}

    async def fake_exchange(code: str, redirect_uri: str, code_verifier: str) -> dict[str, object]:
        exchanged.update(code=code, redirect_uri=redirect_uri, code_verifier=code_verifier)
        return {
            "sub": "keycloak:gateway-admin",
            "preferred_username": "gateway-admin",
            "email": "gateway-admin@k-lab.local",
            "realm_access": {"roles": ["gateway-admin", "gateway-user", "gateway-auditor"]},
        }

    monkeypatch.setattr(auth_router, "exchange_keycloak_code", fake_exchange)
    mismatch = client.get("/auth/callback", params={"code": "test-code", "state": "wrong"}, follow_redirects=False)
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == "OAuth state mismatch"
    assert not exchanged

    callback = client.get(
        "/auth/callback",
        params={"code": "test-code", "state": authorize_query["state"][0]},
        follow_redirects=False,
    )
    assert callback.status_code == 307
    assert callback.headers["location"] == "/devices"
    assert exchanged == {
        "code": "test-code",
        "redirect_uri": "http://testserver/auth/callback",
        "code_verifier": flow["code_verifier"],
    }
    assert client.get("/auth/me").json()["username"] == "gateway-admin"


def test_oauth_facade_pkce_flow(client: TestClient) -> None:
    register = client.post(
        "/oauth/register",
        json={"redirect_uris": ["http://localhost:3000/callback"], "client_name": "test",
        },
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
    assert token.json()["expires_in"] == 864000
    from gateway_api.auth import decode_jwt

    claims = decode_jwt(token.json()["access_token"])
    assert claims["exp"] - claims["iat"] == 864000


def test_device_registration_encrypts_secret(client: TestClient) -> None:
    response = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.5:2222", "auth_type": "password", "password": "plain-password",
        },
    )
    assert response.status_code == 201
    assert response.json()["host"] == "10.0.0.5"

    from gateway_api.database import SessionLocal
    from gateway_api.models import SecretBlob

    with SessionLocal() as db:
        secret = db.query(SecretBlob).one()
        assert "plain-password" not in secret.ciphertext


def test_ssh_secret_payload_parser_supports_json_and_legacy_shapes() -> None:
    from gateway_api.adapters.ssh import parse_ssh_secret_payload, serialize_ssh_secret

    parsed = parse_ssh_secret_payload(serialize_ssh_secret("json-value", "json-passphrase"), auth_type="password")
    assert parsed.auth_type == "password"
    assert parsed.secret == "json-value"
    assert parsed.passphrase == "json-passphrase"

    legacy = parse_ssh_secret_payload("{'secret': 'legacy-value', 'passphrase': None}", auth_type="private_key")
    assert legacy.auth_type == "private_key"
    assert legacy.secret == "legacy-value"
    assert legacy.passphrase is None


def test_device_registration_stores_json_secret_payload(client: TestClient) -> None:
    response = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.7:2222", "auth_type": "password", "password": "json-secret-value",
        },
    )
    assert response.status_code == 201

    from gateway_api.adapters.ssh import load_device_credentials
    from gateway_api.crypto import decrypt_text
    from gateway_api.database import SessionLocal
    from gateway_api.models import Device, SecretBlob

    with SessionLocal() as db:
        device = db.query(Device).one()
        secret = db.query(SecretBlob).one()
        raw_payload = decrypt_text(secret.ciphertext)
        assert raw_payload.startswith("{")
        assert "'secret'" not in raw_payload
        credentials = load_device_credentials(device, db)
        assert credentials.auth_type == "password"
        assert credentials.secret == "json-secret-value"



def test_ssh_host_key_policy_accepts_new_keys_into_managed_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from gateway_api import config
    from gateway_api.adapters.ssh import _configure_host_key_verification

    known_hosts = tmp_path / "ssh" / "known_hosts"
    monkeypatch.setenv("GATEWAY_SSH_KNOWN_HOSTS_PATH", str(known_hosts))
    monkeypatch.setenv("GATEWAY_SSH_KNOWN_HOSTS_POLICY", "accept-new")
    config.get_settings.cache_clear()

    class AutoAddPolicy:
        pass

    class RejectPolicy:
        pass

    fake_paramiko = SimpleNamespace(
        AutoAddPolicy=AutoAddPolicy,
        RejectPolicy=RejectPolicy,
    )

    class FakeClient:
        def __init__(self) -> None:
            self.loaded_system_keys = False
            self.loaded_host_keys: str | None = None
            self.policy = None

        def load_system_host_keys(self) -> None:
            self.loaded_system_keys = True

        def load_host_keys(self, filename: str) -> None:
            self.loaded_host_keys = filename

        def set_missing_host_key_policy(self, policy) -> None:
            self.policy = policy

    client = FakeClient()
    _configure_host_key_verification(client, fake_paramiko)

    assert client.loaded_system_keys is True
    assert client.loaded_host_keys == str(known_hosts)
    assert isinstance(client.policy, AutoAddPolicy)
    assert known_hosts.is_file()
    assert known_hosts.stat().st_mode & 0o777 == 0o600
    config.get_settings.cache_clear()


def test_device_registration_verifies_password_and_trusts_new_host_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway_api.routers.devices as devices_router

    observed: dict[str, object] = {}
    monkeypatch.setattr(
        devices_router, "check_ssh_tcp_connection", lambda target: "reachable"
    )

    def verify(device, credentials):
        observed.update(
            host=device.host,
            port=device.port,
            username=device.username,
            auth_type=credentials.auth_type,
            secret=credentials.secret,
        )
        return "verified"

    monkeypatch.setattr(devices_router, "verify_ssh_connection", verify)
    response = client.post(
        "/api/devices",
        json={
            "name": "auto-trusted-box",
            "target": "robot@192.0.2.81:22",
            "auth_type": "password",
            "password": "valid-password",
            "verify_connection": True,
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "verified"
    assert observed == {
        "host": "192.0.2.81",
        "port": 22,
        "username": "robot",
        "auth_type": "password",
        "secret": "valid-password",
    }


def test_ssh_adapter_uses_backend_credentials_with_mock_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from gateway_api import config
    from gateway_api.adapters.ssh import SshCredentials, run_ssh_command, verify_ssh_connection

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.0.2.10 ssh-ed25519 test-key\n", encoding="utf-8")
    monkeypatch.setenv("GATEWAY_SSH_KNOWN_HOSTS_PATH", str(known_hosts))
    config.get_settings.cache_clear()

    class FakeChannel:
        def recv_exit_status(self) -> int:
            return 0

    class FakeStream:
        channel = FakeChannel()

        def __init__(self, data: str) -> None:
            self.data = data

        def read(self) -> str:
            return self.data

    class FakeClient:
        def __init__(self) -> None:
            self.connect_kwargs: dict | None = None
            self.commands: list[str] = []
            self.closed = False
            self.loaded_host_keys: str | None = None

        def set_missing_host_key_policy(self, policy) -> None:
            pass

        def load_system_host_keys(self) -> None:
            pass

        def load_host_keys(self, filename: str) -> None:
            self.loaded_host_keys = filename

        def connect(self, **kwargs) -> None:
            self.connect_kwargs = kwargs

        def exec_command(self, command: str, timeout=None):
            self.commands.append(command)
            return None, FakeStream("remote-output\n"), FakeStream("")

        def close(self) -> None:
            self.closed = True

    clients: list[FakeClient] = []

    def factory() -> FakeClient:
        client = FakeClient()
        clients.append(client)
        return client

    device = SimpleNamespace(host="192.0.2.10", port=2222, username="robot", auth_type="password")
    credentials = SshCredentials(auth_type="password", secret="backend-only-secret")

    assert (
        verify_ssh_connection(device, credentials, timeout_seconds=7, client_factory=factory) == "verified"
    )
    result = run_ssh_command(device, credentials, command="whoami", timeout_seconds=7, client_factory=factory)

    assert result.exit_code == 0
    assert result.stdout == "remote-output\n"
    assert len(clients) == 2
    assert clients[0].connect_kwargs == {
        "hostname": "192.0.2.10",
        "port": 2222,
        "username": "robot",
        "timeout": 7,
        "banner_timeout": 7,
        "auth_timeout": 7,
        "look_for_keys": False,
        "allow_agent": False,
        "password": "backend-only-secret",
    }
    assert clients[1].commands == ["whoami"]
    assert all(client.loaded_host_keys == str(known_hosts) for client in clients)
    assert all(client.closed for client in clients)
    config.get_settings.cache_clear()


def test_persistent_gateway_secret_key_is_reused(tmp_path: Path) -> None:
    from cryptography.fernet import Fernet

    from gateway_api.crypto import _load_or_create_fernet_key

    key_file = tmp_path / "gateway-secret.key"
    first = _load_or_create_fernet_key(None, str(key_file))
    second = _load_or_create_fernet_key(None, str(key_file))

    assert first == second
    Fernet(first)
    assert key_file.stat().st_mode & 0o777 == 0o600


def test_device_registration_flushes_secret_before_commit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.orm import Session as OrmSession

    assert client.get("/auth/me").status_code == 200

    events: list[tuple[str, tuple[str, ...]]] = []
    original_flush = OrmSession.flush
    original_commit = OrmSession.commit

    def tracked_flush(self, *args, **kwargs):
        events.append(("flush", tuple(sorted(type(obj).__name__ for obj in self.new))))
        return original_flush(self, *args, **kwargs)

    def tracked_commit(self, *args, **kwargs):
        events.append(("commit", tuple()))
        return original_commit(self, *args, **kwargs)

    monkeypatch.setattr(OrmSession, "flush", tracked_flush)
    monkeypatch.setattr(OrmSession, "commit", tracked_commit)

    response = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.6:2222", "auth_type": "password", "password": "plain-password",
        },
    )

    assert response.status_code == 201
    assert ("flush", ("SecretBlob",)) in events
    assert any(event == "commit" for event, _ in events)


def test_device_detail_actions_update_test_and_delete(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.5:2222", "auth_type": "password", "password": "plain-password",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    updated = client.patch(
        f"/api/devices/{device_id}",
        json={"name": "renamed-box", "target": "robot@10.0.0.6:2022"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "renamed-box"
    assert updated.json()["username"] == "robot"
    assert updated.json()["host"] == "10.0.0.6"
    assert updated.json()["port"] == 2022

    import gateway_api.routers.devices as devices_router

    monkeypatch.setattr(devices_router, "check_ssh_tcp_connection", lambda target: "reachable")
    monkeypatch.setattr(devices_router, "verify_ssh_connection", lambda device, credentials: "verified")
    tested = client.post(f"/api/devices/{device_id}/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "verified"

    deleted = client.delete(f"/api/devices/{device_id}")
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert client.get("/api/devices").json() == []


def test_device_connection_test_sets_auth_failed_on_ssh_auth_error(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.8:2222", "auth_type": "password", "password": "wrong-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    import gateway_api.routers.devices as devices_router

    monkeypatch.setattr(devices_router, "check_ssh_tcp_connection", lambda target: "reachable")

    def fail_auth(device, credentials):
        raise HTTPException(status_code=401, detail="SSH connection failed")

    monkeypatch.setattr(devices_router, "verify_ssh_connection", fail_auth)

    tested = client.post(f"/api/devices/{device_id}/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "auth_failed"


def test_device_connection_test_distinguishes_untrusted_host_key(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.8:2222", "auth_type": "password", "password": "valid-value"},
    )
    device_id = created.json()["id"]

    import gateway_api.routers.devices as devices_router

    monkeypatch.setattr(devices_router, "check_ssh_tcp_connection", lambda target: "reachable")

    def fail_host_key(device, credentials):
        raise HTTPException(status_code=409, detail="SSH host key is not trusted")

    monkeypatch.setattr(devices_router, "verify_ssh_connection", fail_host_key)
    tested = client.post(f"/api/devices/{device_id}/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "host_key_untrusted"


def test_device_connection_test_skips_auth_when_tcp_unreachable(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.9:2222", "auth_type": "password", "password": "unused-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    import gateway_api.routers.devices as devices_router

    calls = {"verified": 0}
    monkeypatch.setattr(devices_router, "check_ssh_tcp_connection", lambda target: "unreachable")

    def verify_should_not_run(device, credentials):
        calls["verified"] += 1
        return "verified"

    monkeypatch.setattr(devices_router, "verify_ssh_connection", verify_should_not_run)

    tested = client.post(f"/api/devices/{device_id}/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "unreachable"
    assert calls["verified"] == 0


def test_docker_workspace_allowlist_and_simulated_create(client: TestClient) -> None:
    images = client.get("/api/docker/images")
    assert images.status_code == 200
    assert "ubuntu:24.04" in images.json()["images"]
    created = client.post("/api/docker/workspaces", json={"name": "lab", "image": "ubuntu:24.04"})
    assert created.status_code == 201
    assert created.json()["status"] == "pending"
    denied = client.post("/api/docker/workspaces", json={"name": "bad", "image": "alpine:latest"})
    assert denied.status_code == 400

    updated = client.patch(
        f"/api/docker/workspaces/{created.json()['id']}",
        json={"name": "renamed-lab", "description": "Long running lab"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "renamed-lab"
    assert updated.json()["description"] == "Long running lab"
    assert updated.json()["container_name"].startswith("gw-darius-renamed-lab-")

    cleared = client.patch(
        f"/api/docker/workspaces/{created.json()['id']}",
        json={"description": None},
    )
    assert cleared.status_code == 200
    assert cleared.json()["description"] is None

    exec_response = client.post(f"/api/docker/workspaces/{created.json()['id']}/exec", json={"command": "pwd"})
    assert exec_response.status_code == 400
    assert "Docker execution disabled" in exec_response.text

    stopped = client.post(f"/api/docker/workspaces/{created.json()['id']}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"
    started = client.post(f"/api/docker/workspaces/{created.json()['id']}/start")
    assert started.status_code == 200
    assert started.json()["status"] == "pending"
    deleted = client.delete(f"/api/docker/workspaces/{created.json()['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True
    assert client.get("/api/docker/workspaces").json() == []


def test_thin_client_device_code_registration(client: TestClient) -> None:
    code = client.post("/api/thin-clients/device-code")
    assert code.status_code == 201
    token = client.post("/api/thin-clients/token", json={"device_code": code.json()["device_code"]})
    assert token.status_code == 200
    assert token.json()["expires_in"] == 2592000
    from gateway_api.auth import decode_jwt

    claims = decode_jwt(token.json()["access_token"])
    assert claims["exp"] - claims["iat"] == 2592000
    registered = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"},
        },
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    assert registered.status_code == 201
    assert registered.json()["hostname"] == "workstation"
    assert registered.json()["meta"]["labels"]["version"] == "0.2.0"
    client_id = registered.json()["id"]

    from gateway_api.database import SessionLocal
    from gateway_api.models import ThinClient

    with SessionLocal() as db:
        db.add(
            ThinClient(
                id="duplicate-thin-client",
                owner_subject="dev:local",
                hostname="workstation",
                directory="/tmp/project",
                agent_token_hash="old-token-hash",
                status="offline",
                meta={"labels": {"version": "old"}},
            )
        )
        db.commit()

    registered_again = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"},
        },
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    assert registered_again.status_code == 201
    assert registered_again.json()["id"] in {client_id, "duplicate-thin-client"}

    listed = client.get("/api/thin-clients")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    client_id = listed.json()[0]["id"]

    deleted = client.delete(f"/api/thin-clients/{client_id}")
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True
    assert client.get("/api/thin-clients").json() == []


def test_thin_client_activation_page_and_post(client: TestClient) -> None:
    page = client.get("/thin-clients/activate?user_code=abc-123")
    assert page.status_code == 200
    assert "Activate Thin Client" in page.text
    assert 'value="ABC123"' in page.text

    from gateway_api.database import SessionLocal
    from gateway_api.models import DeviceCode, utcnow

    client.get("/auth/me")
    with SessionLocal() as db:
        db.add(
            DeviceCode(
                device_code="pending-device",
                user_code="PENDING",
                subject="dev:local",
                scope="thin-client:register",
                status="pending",
                expires_at=utcnow() + timedelta(minutes=5),
            )
        )
        db.commit()

    activated = client.post("/thin-clients/activate", data={"user_code": "pending"})
    assert activated.status_code == 200
    assert "Thin Client Activated" in activated.text

    with SessionLocal() as db:
        assert db.get(DeviceCode, "pending-device").status == "approved"


@pytest.mark.parametrize("client", [False], indirect=True)
def test_production_device_code_is_public_and_binds_during_authenticated_activation(client: TestClient) -> None:
    issued = client.post("/api/thin-clients/device-code")
    assert issued.status_code == 201
    assert issued.json()["verification_uri"] == "http://testserver/thin-clients/activate"

    device_code = issued.json()["device_code"]
    user_code = issued.json()["user_code"]
    pending = client.post("/api/thin-clients/token", json={"device_code": device_code})
    assert pending.status_code == 428

    activation = client.get(
        "/thin-clients/activate",
        params={"user_code": user_code},
        follow_redirects=False,
    )
    assert activation.status_code == 303
    login_url = urlparse(activation.headers["location"])
    assert login_url.path == "/auth/login"
    assert parse_qs(login_url.query)["next"] == [f"/thin-clients/activate?user_code={user_code}"]

    from gateway_api import config
    from gateway_api.auth import create_jwt, ensure_user
    from gateway_api.database import SessionLocal
    from gateway_api.models import DeviceCode

    with SessionLocal() as db:
        user = ensure_user(
            db,
            subject="keycloak:test-user",
            username="test-user",
            email="test-user@example.com",
            roles=["gateway-user"],
            provider="keycloak",
        )
        session_token = create_jwt(
            subject=user.subject,
            username=user.username,
            roles=user.roles,
            scopes=["thin-client:register"],
            token_type="session",
            ttl_seconds=300,
        )
    client.cookies.set(config.get_settings().gateway_session_cookie, session_token)

    activated = client.post("/thin-clients/activate", data={"user_code": user_code})
    assert activated.status_code == 200
    assert "Thin Client Activated" in activated.text
    with SessionLocal() as db:
        stored = db.get(DeviceCode, device_code)
        assert stored.status == "approved"
        assert stored.subject == "keycloak:test-user"

    token = client.post("/api/thin-clients/token", json={"device_code": device_code})
    assert token.status_code == 200


def test_mcp_thin_client_tool_delegates_to_online_agent(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    code = client.post("/api/thin-clients/device-code")
    token = client.post("/api/thin-clients/token", json={"device_code": code.json()["device_code"]})
    registered = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"},
        },
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    client_id = registered.json()["id"]
    calls: list[dict] = []

    async def fake_request(client_id_arg: str, *, tool: str, arguments: dict, timeout_seconds: int) -> dict:
        calls.append({"client_id": client_id_arg, "tool": tool, "arguments": arguments, "timeout_seconds": timeout_seconds,
            })
        if tool == "run_monitored_command":
            from gateway_api.monitoring import monitoring_service

            monitoring_service.append_output(str(arguments["session_id"]), stream="stdout", text="ran arbitrary command\n",
            )
            monitoring_service.finish_session(str(arguments["session_id"]), status_value="completed", exit_code=0)
            return {"ok": True, "result": {"session_id": arguments["session_id"], "status": "running"},
            }
        return {"ok": True, "result": {"root": "/tmp/project", "entries": [{"path": "hello.txt", "kind": "file", "size": 5}],
            },
        }

    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setattr(mcp_router.thin_client_manager, "request", fake_request)

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "thin_client_list_files", "arguments": {"client_id": client_id, "path": "."},
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False
    assert response.json()["result"]["structuredContent"]["ok"] is True
    assert response.json()["result"]["structuredContent"]["client_id"] == client_id
    assert (
        response.json()["result"]["structuredContent"]["entries"][0]["path"] == "hello.txt"
    )
    assert "hello.txt" in response.json()["result"]["content"][0]["text"]
    command_response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "thin_client_run_command",
                "arguments": {"client_id": client_id, "command": "printf ok > file.txt", "cwd": ".", "timeout_seconds": 5,
                },
            },
        },
    )

    assert command_response.status_code == 200
    assert command_response.json()["result"]["isError"] is False
    assert command_response.json()["result"]["structuredContent"]["exit_code"] == 0
    assert (
        "ran arbitrary command" in command_response.json()["result"]["structuredContent"]["output"]
    )
    assert calls == [
        {"client_id": client_id, "tool": "list_files", "arguments": {"path": "."}, "timeout_seconds": 120,
        },
        {
            "client_id": client_id,
            "tool": "run_monitored_command",
            "arguments": {
                "session_id": command_response.json()["result"]["structuredContent"]["session_id"],
                "command": "printf ok > file.txt",
                "cwd": ".",
                "timeout_seconds": 5,
            },
            "timeout_seconds": 10,
        },
    ]


def test_mcp_long_command_auto_backgrounds_and_can_be_read(client: TestClient) -> None:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "run_cli_command",
                "arguments": {"command": "sleep 2; echo threshold-ok", "cwd": ".", "timeout_seconds": 5,
                },
            },
        },
    )

    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["ok"] is True
    assert structured["backgrounded"] is True
    assert structured["status"] == "running"
    assert structured["session_id"]
    assert "monitoring_read_output" in structured["recommendation"]

    session_id = structured["session_id"]
    for _ in range(30):
        session = client.get(f"/api/command-sessions/{session_id}")
        assert session.status_code == 200
        if session.json()["status"] == "completed":
            break
        time.sleep(0.1)

    output = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tools/call",
            "params": {"name": "monitoring_read_output", "arguments": {"session_id": session_id, "tail": 5},
            },
        },
    )
    assert output.status_code == 200
    output_structured = output.json()["result"]["structuredContent"]
    assert output_structured["ok"] is True
    assert output_structured["output"]["lines"][-1]["text"] == "threshold-ok"
    assert output_structured["output"]["lines"][-1]["agent_requested"] is True

    history = client.get(f"/api/command-sessions/{session_id}/tool-calls")
    assert history.status_code == 200
    assert {call["tool_name"] for call in history.json()} == {"run_cli_command"}


def test_mcp_missing_command_working_directory_is_a_recorded_failure(
    client: TestClient,
) -> None:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tools/call",
            "params": {
                "name": "run_cli_command",
                "arguments": {
                    "command": "pwd",
                    "cwd": "products/sc-drive",
                },
            },
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["isError"] is True
    structured = result["structuredContent"]
    assert structured["status"] == "failed"
    assert structured["exit_code"] == 127
    assert "Unable to start command" in structured["output"]
    assert "products/sc-drive" in structured["output"]

    session = client.get(f"/api/command-sessions/{structured['session_id']}")
    assert session.status_code == 200
    assert session.json()["status"] == "failed"
    assert session.json()["exit_code"] == 127


def test_nats_publish_retries_an_ack_timeout_with_the_same_message_id() -> None:
    from nats import errors as nats_errors

    from gateway_api.broker import NatsJetStreamBroker
    from gateway_api.config import Settings

    class FakeJetStream:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def publish(self, subject: str, payload: bytes, **kwargs):
            self.calls.append(
                {"subject": subject, "payload": payload, **kwargs}
            )
            if len(self.calls) == 1:
                raise nats_errors.TimeoutError
            return type(
                "Ack",
                (),
                {"stream": "GATEWAY_EVENTS", "seq": 42, "duplicate": True},
            )()

    settings = Settings(
        gateway_nats_publish_retry_attempts=2,
        gateway_nats_publish_retry_delay_seconds=0,
    )
    broker = NatsJetStreamBroker(settings, replica_id="test")
    jetstream = FakeJetStream()
    broker._jetstream = jetstream

    ack = asyncio.run(
        broker.publish(
            "gateway.events.test.v1",
            b"{}",
            message_id="event-1",
            headers={"traceparent": "trace-1"},
        )
    )

    assert ack.sequence == 42
    assert ack.duplicate is True
    assert len(jetstream.calls) == 2
    assert jetstream.calls[0]["headers"]["Nats-Msg-Id"] == "event-1"
    assert jetstream.calls[1]["headers"]["Nats-Msg-Id"] == "event-1"


def test_mcp_background_tails_and_termination(client: TestClient) -> None:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tools/call",
            "params": {
                "name": "run_cli_command",
                "arguments": {
                    "command": "printf 'line1\\nline2\\nline3\\nline4\\nline5\\nline6\\n'; sleep 30",
                    "background": True,
                    "session_name": "tail-test",
                },
            },
        },
    )

    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["backgrounded"] is True
    session_id = structured["session_id"]

    for _ in range(30):
        session = client.get(f"/api/command-sessions/{session_id}")
        assert session.status_code == 200
        if session.json()["line_count"] >= 6:
            break
        time.sleep(0.1)

    ping = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 47, "method": "tools/call", "params": {"name": "workspace_info", "arguments": {}},
        },
    )
    tails = ping.json()["result"]["structuredContent"]["background_session_tails"]
    tail = next(item for item in tails if item["session_id"] == session_id)
    assert [line["text"] for line in tail["lines"]] == ["line2", "line3", "line4", "line5", "line6",
    ]
    assert all(line["auto_sent"] for line in tail["lines"])

    window = client.get(f"/api/command-sessions/{session_id}/output", params={"start_line": 2, "limit": 2},
    )
    assert window.status_code == 200
    assert [line["text"] for line in window.json()["lines"]] == ["line2", "line3"]
    assert all(line["auto_sent"] for line in window.json()["lines"])

    terminated = client.post(f"/api/command-sessions/{session_id}/terminate", json={"force": True})
    assert terminated.status_code == 200
    assert terminated.json()["status"] == "terminated"


def test_thin_client_manager_returns_http_409_when_client_disconnects_during_request() -> (
    None
):
    from gateway_api.thin_client_control import ThinClientConnectionManager

    manager = ThinClientConnectionManager()

    class DisconnectingWebSocket:
        async def send_json(self, payload: dict) -> None:
            await manager.unregister("client-1")

    async def scenario() -> None:
        await manager.register("client-1", DisconnectingWebSocket())
        try:
            await manager.request("client-1", tool="run_command", arguments={"command": "sleep 10"}, timeout_seconds=5,
            )
        except HTTPException as exc:
            assert exc.status_code == 409
            assert "Thin client disconnected" in str(exc.detail)
        else:
            raise NoteError("disconnect did not become HTTP 409")

    asyncio.run(scenario())


def test_mcp_tools_list(client: TestClient) -> None:
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    names = [tool["name"] for tool in tools]
    browser_prefix = "thin_client_" + "browser_"
    browser_safe_names = {
        browser_prefix + "page_state",
        browser_prefix + "page_status",
        browser_prefix + "trace_export",
    }
    browser_hidden_names = {
        browser_prefix + "".join(chr(code) for code in [115, 110, 97, 112, 115, 104, 111, 116]),
        browser_prefix + "".join(chr(code) for code in [99, 111, 110, 115, 111, 108, 101]),
        browser_prefix + "".join(chr(code) for code in [115, 116, 111, 112, 95, 116, 114, 97, 99, 101]),
    }
    assert "workspace_info" in names
    assert "docker_workspace_stop" in names
    assert "docker_workspace_start" in names
    assert "docker_workspace_delete" in names
    assert "docker_workspace_update" in names
    assert "file_changes_list" in names
    assert "ssh_device_info" in names
    assert "ssh_device_check_connection" in names
    assert "ssh_device_run_action" in names
    assert "ssh_device_read_home" in names
    assert "ssh_device_run_command" in names
    assert browser_safe_names <= set(names)
    assert browser_hidden_names.isdisjoint(names)
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)
    assert all("annotations" in tool for tool in tools)
    assert all(tool["outputSchema"]["type"] == "object" for tool in tools)
    schemas = {tool["name"]: tool["inputSchema"] for tool in tools}
    output_schemas = {tool["name"]: tool["outputSchema"] for tool in tools}
    annotations = {tool["name"]: tool["annotations"] for tool in tools}
    assert schemas["run_cli_command"]["required"] == ["command"]
    assert schemas["run_cli_command"]["properties"]["command"]["type"] == "string"
    assert schemas["write_file"]["required"] == ["path", "content"]
    assert (
        output_schemas["thin_client_list_files"]["properties"]["entries"]["type"] == "array"
    )
    assert (
        output_schemas["thin_client_read_file"]["properties"]["content"]["type"] == "string"
    )
    assert "operation" in schemas["thin_client_write_file"]["properties"]
    assert "content_base64" in schemas["thin_client_write_file"]["properties"]
    assert "expected_replacements" in schemas["thin_client_write_file"]["properties"]
    assert "return_content" in schemas["thin_client_write_file"]["properties"]
    assert "diff" in schemas["thin_client_write_file"]["properties"]
    assert schemas["thin_client_write_file"]["required"] == ["client_id", "path"]
    assert (
        output_schemas["thin_client_write_file"]["properties"]["bytes"]["type"] == "integer"
    )
    assert (
        output_schemas["thin_client_write_file"]["properties"]["replacements"]["type"] == "integer"
    )
    assert output_schemas["thin_client_write_file"]["properties"]["content"]["type"] == ["string", "null"]
    assert output_schemas["thin_client_write_file"]["properties"]["diff"]["type"] == "object"
    assert output_schemas["thin_client_write_file"]["properties"]["diff"]["properties"]["hunks"]["type"] == "array"
    assert output_schemas["file_changes_list"]["properties"]["changes"]["type"] == "array"
    resource_properties = output_schemas["list_resources"]["properties"]
    assert resource_properties["ssh_devices"]["type"] == "array"
    assert resource_properties["ssh_devices"]["items"]["properties"]["device_id"]["type"] == "string"
    assert resource_properties["docker_workspace_items"]["items"]["properties"]["workspace_id"]["type"] == "string"
    assert resource_properties["thin_client_items"]["items"]["properties"]["client_id"]["type"] == "string"
    assert resource_properties["thin_client_items"]["items"]["properties"]["connected"]["type"] == "boolean"
    assert schemas["ssh_device_info"]["required"] == ["device_id"]
    assert schemas["ssh_device_info"]["additionalProperties"] is False
    assert schemas["ssh_device_check_connection"]["required"] == ["device_id"]
    assert schemas["ssh_device_run_action"]["required"] == ["device_id", "action"]
    assert set(schemas["ssh_device_run_action"]["properties"]["action"]["enum"]) >= {"whoami", "pwd", "home_list",
    }
    assert schemas["ssh_device_read_home"]["required"] == ["device_id"]
    for ssh_tool in ["ssh_device_info", "ssh_device_check_connection", "ssh_device_run_action", "ssh_device_read_home",
    ]:
        schema_text = json.dumps(schemas[ssh_tool]).lower()
        assert "password" not in schema_text
        assert "private_key" not in schema_text
        assert output_schemas[ssh_tool]["type"] == "object"
    assert (
        output_schemas["thin_client_run_command"]["properties"]["output"]["type"] == "string"
    )
    assert output_schemas[browser_prefix + "page_status"]["properties"]["page_status"]["type"] == ["object", "null"]
    assert annotations["workspace_info"]["readOnlyHint"] is True
    assert annotations["ssh_device_info"]["readOnlyHint"] is True
    assert annotations["ssh_device_check_connection"]["readOnlyHint"] is True
    assert annotations["ssh_device_run_action"]["readOnlyHint"] is False
    assert annotations["ssh_device_run_action"]["destructiveHint"] is True
    assert annotations["ssh_device_run_action"]["openWorldHint"] is True
    assert annotations["ssh_device_read_home"]["readOnlyHint"] is True
    assert annotations["list_files"]["readOnlyHint"] is True
    assert annotations["thin_client_run_command"]["readOnlyHint"] is False
    assert annotations["thin_client_run_command"]["destructiveHint"] is True
    assert annotations["thin_client_run_command"]["openWorldHint"] is True
    assert annotations["thin_client_write_file"]["readOnlyHint"] is False
    assert annotations["thin_client_write_file"]["openWorldHint"] is False
    assert annotations["docker_workspace_delete"]["destructiveHint"] is True


def test_mcp_list_resources_returns_owned_identifiers_and_safe_metadata(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import Device, DockerWorkspace, ThinClient
    from gateway_api.routers import mcp as mcp_router

    client.get("/auth/me")
    with SessionLocal() as db:
        db.add_all(
            [
                Device(
                    id="owned-device",
                    owner_subject="dev:local",
                    name="Owned SSH",
                    kind="ssh",
                    host="192.0.2.10",
                    port=22,
                    username="robot",
                    auth_type="password",
                    status="verified",
                ),
                Device(
                    id="foreign-device",
                    owner_subject="other:user",
                    name="Foreign SSH",
                    kind="ssh",
                    host="192.0.2.11",
                    port=22,
                    username="other",
                    auth_type="private_key",
                    status="verified",
                ),
                DockerWorkspace(
                    id="owned-workspace",
                    owner_subject="dev:local",
                    name="Owned Workspace",
                    image="ubuntu:24.04",
                    container_name="owned-workspace-container",
                    status="running",
                    meta={"description": "Primary workspace"},
                ),
                DockerWorkspace(
                    id="foreign-workspace",
                    owner_subject="other:user",
                    name="Foreign Workspace",
                    image="ubuntu:24.04",
                    container_name="foreign-workspace-container",
                    status="running",
                ),
                ThinClient(
                    id="owned-client",
                    owner_subject="dev:local",
                    hostname="owned-host",
                    directory="/srv/owned",
                    agent_token_hash="owned-token-hash",
                    status="online",
                ),
                ThinClient(
                    id="foreign-client",
                    owner_subject="other:user",
                    hostname="foreign-host",
                    directory="/srv/foreign",
                    agent_token_hash="foreign-token-hash",
                    status="online",
                ),
            ]
        )
        db.commit()

    monkeypatch.setattr(mcp_router.thin_client_manager, "is_connected", lambda client_id: client_id == "owned-client")
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 59,
            "method": "tools/call",
            "params": {"name": "list_resources", "arguments": {}},
        },
    )

    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["devices"] == 1
    assert structured["docker_workspaces"] == 1
    assert structured["thin_clients"] == 1
    assert structured["ssh_devices"] == [
        {
            "device_id": "owned-device",
            "name": "Owned SSH",
            "host": "192.0.2.10",
            "port": 22,
            "username": "robot",
            "auth_type": "password",
            "status": "verified",
        }
    ]
    assert structured["docker_workspace_items"] == [
        {
            "workspace_id": "owned-workspace",
            "name": "Owned Workspace",
            "description": "Primary workspace",
            "image": "ubuntu:24.04",
            "status": "running",
        }
    ]
    assert structured["thin_client_items"][0]["client_id"] == "owned-client"
    assert structured["thin_client_items"][0]["hostname"] == "owned-host"
    assert structured["thin_client_items"][0]["directory"] == "/srv/owned"
    assert structured["thin_client_items"][0]["connected"] is True
    serialized = json.dumps(structured)
    assert "foreign-device" not in serialized
    assert "foreign-workspace" not in serialized
    assert "foreign-client" not in serialized
    assert "credential_secret_id" not in serialized
    assert "agent_token_hash" not in serialized


def test_mcp_ssh_descriptors_respect_feature_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    import gateway_api.config as config
    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setenv("GATEWAY_SSH_ENABLED", "false")
    config.get_settings.cache_clear()
    try:
        names = [tool["name"] for tool in mcp_router._tools()]
        assert "ssh_device_info" not in names
        assert "ssh_device_run_action" not in names
    finally:
        config.get_settings.cache_clear()

    monkeypatch.setenv("GATEWAY_SSH_ENABLED", "true")
    monkeypatch.setenv("GATEWAY_SSH_ALLOW_RAW_COMMAND", "true")
    config.get_settings.cache_clear()
    try:
        tools = mcp_router._tools()
        names = [tool["name"] for tool in tools]
        assert "ssh_device_run_command" in names
        raw = next(tool for tool in tools if tool["name"] == "ssh_device_run_command")
        assert raw["annotations"]["destructiveHint"] is True
        assert raw["annotations"]["openWorldHint"] is True
    finally:
        config.get_settings.cache_clear()


def test_mcp_ssh_device_info_and_check_connection(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.20:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    info = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {"name": "ssh_device_info", "arguments": {"device_id": device_id},
            },
        },
    )
    assert info.status_code == 200
    structured = info.json()["result"]["structuredContent"]
    assert structured["device_id"] == device_id
    assert structured["name"] == "ssh-stage"
    assert structured["host"] == "192.0.2.20"
    assert structured["username"] == "robot"
    assert "stored-value" not in info.text

    import gateway_api.routers.mcp as mcp_router

    seen: dict[str, object] = {}

    def fake_verify(device, credentials, *, timeout_seconds=15):
        seen["device_id"] = device.id
        seen["timeout_seconds"] = timeout_seconds
        seen["auth_type"] = credentials.auth_type
        return "verified"

    monkeypatch.setattr(mcp_router, "verify_ssh_connection", fake_verify)

    checked = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 61,
            "method": "tools/call",
            "params": {
                "name": "ssh_device_check_connection",
                "arguments": {"device_id": device_id, "timeout_seconds": 9},
            },
        },
    )
    assert checked.status_code == 200
    checked_structured = checked.json()["result"]["structuredContent"]
    assert checked_structured["status"] == "verified"
    assert checked_structured["detail"] == "authenticated"
    assert seen == {"device_id": device_id, "timeout_seconds": 9, "auth_type": "password",
    }


def test_mcp_ssh_run_action_creates_monitored_session_and_output(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.21:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    import gateway_api.routers.mcp as mcp_router
    from gateway_api.adapters.ssh import SshCommandResult

    calls: list[dict[str, object]] = []

    def fake_run(device, credentials, *, command: str, timeout_seconds=30):
        calls.append({"device_id": device.id, "command": command, "timeout_seconds": timeout_seconds, "auth_type": credentials.auth_type,
            })
        return SshCommandResult(exit_code=0, stdout="robot\n", stderr="")

    monkeypatch.setattr(mcp_router, "run_ssh_command", fake_run)

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 62,
            "method": "tools/call",
            "params": {
                "name": "ssh_device_run_action",
                "arguments": {"device_id": device_id, "action": "whoami", "timeout_seconds": 5,
                },
            },
        },
    )
    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["ok"] is True
    assert structured["device_id"] == device_id
    assert structured["action"] == "whoami"
    assert structured["command"] == "whoami"
    assert structured["exit_code"] == 0
    assert structured["status"] == "completed"
    assert structured["backgrounded"] is False
    assert structured["output"] == "robot"
    assert calls == [{"device_id": device_id, "command": "whoami", "timeout_seconds": 5, "auth_type": "password",
        }]

    session_id = structured["session_id"]
    session = client.get(f"/api/command-sessions/{session_id}")
    assert session.status_code == 200
    assert session.json()["origin"] == "ssh"
    assert session.json()["resource_id"] == device_id

    output = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 63,
            "method": "tools/call",
            "params": {"name": "monitoring_read_output", "arguments": {"session_id": session_id, "tail": 5},
            },
        },
    )
    assert output.status_code == 200
    assert (
        output.json()["result"]["structuredContent"]["output"]["lines"][-1]["text"] == "robot"
    )


def test_mcp_ssh_run_action_rejects_unknown_action(client: TestClient) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.22:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 64,
            "method": "tools/call",
            "params": {
                "name": "ssh_device_run_action",
                "arguments": {"device_id": created.json()["id"], "action": "not_allowed",
                },
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == 400
    assert "Unsupported SSH action" in response.json()["error"]["message"]


def test_mcp_ssh_raw_command_can_be_restricted_per_account(client: TestClient) -> None:
    created = client.post(
        "/api/devices",
        json={
            "name": "ssh-stage",
            "target": "robot@192.0.2.23:2222",
            "auth_type": "password",
            "password": "stored-value",
        },
    )
    assert created.status_code == 201

    settings_response = client.patch(
        "/api/account/settings",
        json={"ssh_command_profile": "restricted"},
    )
    assert settings_response.status_code == 200
    assert settings_response.json()["ssh_command_profile"] == "restricted"
    assert settings_response.json()["raw_commands_enabled"] is False

    tools_response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 64, "method": "tools/list"},
    )
    tool_names = {tool["name"] for tool in tools_response.json()["result"]["tools"]}
    assert "ssh_device_run_command" not in tool_names

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 65,
            "method": "tools/call",
            "params": {
                "name": "ssh_device_run_command",
                "arguments": {"device_id": created.json()["id"], "command": "id"},
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == 404


def test_mcp_ssh_raw_command_enabled_runs_safe_single_line(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway_api.config as config
    import gateway_api.routers.mcp as mcp_router
    from gateway_api.adapters.ssh import SshCommandResult

    monkeypatch.setenv("GATEWAY_SSH_ALLOW_RAW_COMMAND", "true")
    monkeypatch.setenv("GATEWAY_SSH_RAW_COMMAND_MAX_CHARS", "80")
    config.get_settings.cache_clear()

    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.24:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    calls: list[dict[str, object]] = []

    def fake_run(device, credentials, *, command: str, timeout_seconds=30):
        calls.append({"device_id": device.id, "command": command, "timeout_seconds": timeout_seconds,
            })
        return SshCommandResult(exit_code=0, stdout="uid=1000(robot)\n", stderr="")

    monkeypatch.setattr(mcp_router, "run_ssh_command", fake_run)
    try:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 66,
                "method": "tools/call",
                "params": {
                    "name": "ssh_device_run_command",
                    "arguments": {"device_id": device_id, "command": "id", "timeout_seconds": 6,
                    },
                },
            },
        )
    finally:
        config.get_settings.cache_clear()

    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["ok"] is True
    assert structured["action"] == "raw_command"
    assert structured["command"] == "id"
    assert structured["status"] == "completed"
    assert structured["output"] == "uid=1000(robot)"
    assert calls == [{"device_id": device_id, "command": "id", "timeout_seconds": 6}]


def test_mcp_ssh_filtered_profile_blocks_denied_pattern(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway_api.config as config
    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setenv("GATEWAY_SSH_COMMAND_PROFILE_DEFAULT", "filtered")
    config.get_settings.cache_clear()

    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.25:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201

    calls = {"count": 0}

    def should_not_run(*args, **kwargs):
        calls["count"] += 1
        raise AssertionError("raw command policy should block before adapter execution")

    monkeypatch.setattr(mcp_router, "run_ssh_command", should_not_run)
    try:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 67,
                "method": "tools/call",
                "params": {
                    "name": "ssh_device_run_command",
                    "arguments": {"device_id": created.json()["id"], "command": "sudo id",
                    },
                },
            },
        )
    finally:
        config.get_settings.cache_clear()

    assert response.status_code == 200
    assert response.json()["error"]["code"] == 400
    assert "filtered-mode policy" in response.json()["error"]["message"]
    assert calls["count"] == 0


def test_mcp_ssh_raw_command_policy_blocks_multiline_and_overlength(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway_api.config as config

    monkeypatch.setenv("GATEWAY_SSH_ALLOW_RAW_COMMAND", "true")
    monkeypatch.setenv("GATEWAY_SSH_RAW_COMMAND_MAX_CHARS", "3")
    config.get_settings.cache_clear()

    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.26:2222", "auth_type": "password", "password": "stored-value",
        },
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    try:
        too_long = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 68,
                "method": "tools/call",
                "params": {
                    "name": "ssh_device_run_command",
                    "arguments": {"device_id": device_id, "command": "whoami"},
                },
            },
        )
        multiline = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 69,
                "method": "tools/call",
                "params": {
                    "name": "ssh_device_run_command",
                    "arguments": {"device_id": device_id, "command": "id\nwhoami"},
                },
            },
        )
    finally:
        config.get_settings.cache_clear()

    assert too_long.status_code == 200
    assert too_long.json()["error"]["code"] == 400
    assert "length limit" in too_long.json()["error"]["message"]
    assert multiline.status_code == 200
    assert multiline.json()["error"]["code"] == 400
    assert "single line" in multiline.json()["error"]["message"]


def test_mcp_browser_descriptors_are_safety_neutral(client: TestClient) -> None:
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    browser_tools = [tool for tool in tools if tool["name"].startswith("thin_client_browser_")]
    descriptor_text = json.dumps(browser_tools, ensure_ascii=False).lower()
    blocked_phrases = [
        "runtime events",
        "page error",
        "visual assert",
        "network diagnostics",
        "stop trace",
        "close session",
        "client messages",
    ]
    for phrase in blocked_phrases:
        assert phrase not in descriptor_text



def test_mcp_rejects_extra_or_secret_like_arguments(client: TestClient) -> None:
    extra = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_files", "arguments": {"path": ".", "AccessTokens": "glpat-redacted"},
            },
        },
    )
    assert extra.status_code == 200
    assert extra.json()["error"]["code"] == 400
    assert "Unsupported tool argument" in extra.json()["error"]["message"]

    secret_key = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "workspace_info", "arguments": {"token": "redacted"}},
        },
    )
    assert secret_key.status_code == 200
    assert secret_key.json()["error"]["code"] == 400


def test_mcp_tool_call_returns_structured_content(client: TestClient) -> None:
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "workspace_info", "arguments": {}},
        },
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["structuredContent"]["ok"] is True
    assert result["structuredContent"]["user"] == "darius"
    assert result["structuredContent"]["workspace"].endswith("/workspace/users/darius")
    assert '"workspace"' in result["content"][0]["text"]


def test_mcp_thin_client_write_file_forwards_aurum_style_payload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    code = client.post("/api/thin-clients/device-code")
    token = client.post("/api/thin-clients/token", json={"device_code": code.json()["device_code"]})
    registered = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.2"},
        },
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    client_id = registered.json()["id"]
    calls: list[dict] = []

    async def fake_request(client_id_arg: str, *, tool: str, arguments: dict, timeout_seconds: int) -> dict:
        calls.append({"client_id": client_id_arg, "tool": tool, "arguments": arguments, "timeout_seconds": timeout_seconds,
            })
        return {
            "ok": True,
            "result": {
                "path": "docs/policy.md",
                "operation": "replace",
                "bytes": 42,
                "bytes_before": 40,
                "bytes_after": 42,
                "encoding": "utf-8",
                "replacements": 1,
                "content": None,
                "diff": {
                    "format": "unified",
                    "suppressed": False,
                    "truncated": False,
                    "added_lines": 1,
                    "removed_lines": 1,
                    "hunks": [
                        {
                            "old_start": 1,
                            "old_count": 1,
                            "new_start": 1,
                            "new_count": 1,
                            "lines": [
                                {"kind": "delete", "text": "old"},
                                {"kind": "insert", "text": "updated"},
                            ],
                        }
                    ],
                },
            },
        }

    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setattr(mcp_router.thin_client_manager, "request", fake_request)

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "thin_client_write_file",
                "arguments": {
                    "client_id": client_id,
                    "path": "docs/policy.md",
                    "operation": "replace",
                    "old_text": "old",
                    "new_text": "updated",
                    "expected_replacements": 1,
                },
            },
        },
    )

    assert response.status_code == 200
    structured = response.json()["result"]["structuredContent"]
    assert structured["ok"] is True
    assert structured["operation"] == "replace"
    assert structured["replacements"] == 1
    assert structured["content"] is None
    assert structured["diff"]["added_lines"] == 1
    assert structured["diff"]["hunks"][0]["lines"][-1] == {"kind": "insert", "text": "updated",
    }
    assert structured["file_change_id"]

    changes_response = client.get("/api/file-changes?origin=thin_client")
    assert changes_response.status_code == 200
    changes = changes_response.json()
    assert len(changes) == 1
    assert changes[0]["id"] == structured["file_change_id"]
    assert changes[0]["path"] == "docs/policy.md"
    assert changes[0]["operation"] == "replace"
    assert changes[0]["added_lines"] == 1
    assert changes[0]["removed_lines"] == 1
    assert changes[0]["resource_id"] == client_id
    assert changes[0]["tool_call_id"]
    assert changes[0]["diff_json"]["hunks"][0]["lines"][-1] == {"kind": "insert", "text": "updated",
    }

    list_response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {"name": "file_changes_list", "arguments": {"origin": "thin_client", "limit": 10},
            },
        },
    )
    assert list_response.status_code == 200
    listed = list_response.json()["result"]["structuredContent"]["changes"]
    assert len(listed) == 1
    assert listed[0]["id"] == structured["file_change_id"]
    assert listed[0]["diff"]["added_lines"] == 1

    assert calls == [
        {
            "client_id": client_id,
            "tool": "write_file",
            "arguments": {
                "path": "docs/policy.md",
                "operation": "replace",
                "old_text": "old",
                "new_text": "updated",
                "expected_replacements": 1,
            },
            "timeout_seconds": 120,
        }
    ]


def _register_phase_zero_thin_client(client: TestClient) -> tuple[str, str]:
    code = client.post("/api/thin-clients/device-code")
    token_response = client.post(
        "/api/thin-clients/token", json={"device_code": code.json()["device_code"]}
    )
    access_token = token_response.json()["access_token"]
    registered = client.post(
        "/api/thin-clients/register",
        json={
            "hostname": "phase-zero-client",
            "directory": "/tmp/phase-zero",
            "labels": {"version": "phase-zero"},
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    return access_token, registered.json()["id"]


def test_tool_call_argument_redaction_is_recursive() -> None:
    from gateway_api.monitoring import redacted_arguments

    redacted = redacted_arguments(
        {
            "plain": "visible",
            "structured_payload": {
                "accessToken": "outer-token",
                "arguments": [
                    {"client_secret": "nested-secret", "path": "visible-path"},
                    {
                        "credentials": {
                            "username": "operator",
                            "password": "nested-password",
                        }
                    },
                ],
            },
            "tuple_payload": ({"privateKey": "private-key"}, "visible-value"),
        }
    )

    assert redacted["plain"] == "visible"
    assert redacted["structured_payload"]["accessToken"] == "[redacted]"
    assert redacted["structured_payload"]["arguments"][0] == {
        "client_secret": "[redacted]",
        "path": "visible-path",
    }
    assert redacted["structured_payload"]["arguments"][1]["credentials"] == "[redacted]"
    assert redacted["tuple_payload"] == ({"privateKey": "[redacted]"}, "visible-value")


def test_thin_client_websocket_scopes_all_session_events(client: TestClient) -> None:
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.models import CommandSession
    from gateway_api.monitoring import monitoring_service

    access_token, client_id = _register_phase_zero_thin_client(client)
    settings = get_settings()

    with SessionLocal() as db:
        owned = monitoring_service.create_session(
            db,
            owner_subject="dev:local",
            origin="thin_client",
            resource_id=client_id,
            command="owned",
            cwd=".",
            name="owned",
            settings=settings,
        )
        owned_snapshot = monitoring_service.create_session(
            db,
            owner_subject="dev:local",
            origin="thin_client",
            resource_id=client_id,
            command="owned-snapshot",
            cwd=".",
            name="owned-snapshot",
            settings=settings,
        )
        foreign_owner = monitoring_service.create_session(
            db,
            owner_subject="dev:other",
            origin="thin_client",
            resource_id=client_id,
            command="foreign-owner",
            cwd=".",
            name="foreign-owner",
            settings=settings,
        )
        foreign_resource = monitoring_service.create_session(
            db,
            owner_subject="dev:local",
            origin="thin_client",
            resource_id="different-client",
            command="foreign-resource",
            cwd=".",
            name="foreign-resource",
            settings=settings,
        )
        foreign_origin = monitoring_service.create_session(
            db,
            owner_subject="dev:local",
            origin="server",
            resource_id=client_id,
            command="foreign-origin",
            cwd=".",
            name="foreign-origin",
            settings=settings,
        )
        session_ids = {
            "owned": owned.id,
            "owned_snapshot": owned_snapshot.id,
            "foreign_owner": foreign_owner.id,
            "foreign_resource": foreign_resource.id,
            "foreign_origin": foreign_origin.id,
        }

    with client.websocket_connect(
        f"/api/thin-clients/ws/{client_id}?token={access_token}"
    ) as websocket:
        websocket.send_json(
            {
                "type": "session_output",
                "session_id": session_ids["foreign_owner"],
                "stream": "stdout",
                "text": "must-not-write\n",
            }
        )
        websocket.send_json(
            {
                "type": "session_finished",
                "session_id": session_ids["foreign_resource"],
                "status": "completed",
                "exit_code": 0,
            }
        )
        websocket.send_json(
            {
                "type": "session_failed",
                "session_id": session_ids["foreign_origin"],
                "error": "must-not-fail",
            }
        )
        websocket.send_json(
            {
                "type": "session_finished",
                "session_id": session_ids["owned_snapshot"],
                "status": "invented-status",
                "exit_code": "not-an-integer",
            }
        )
        websocket.send_json({"type": "session_snapshot", "sessions": "not-a-list"})
        websocket.send_json(
            {
                "type": "session_snapshot",
                "sessions": [
                    None,
                    {"session_id": session_ids["owned_snapshot"], "pid": "101"},
                    {"session_id": session_ids["foreign_owner"], "pid": "202"},
                    {"session_id": session_ids["foreign_resource"], "pid": "303"},
                    {"session_id": session_ids["foreign_origin"], "pid": "404"},
                ],
            }
        )
        hello = websocket.receive_json()
        assert hello["type"] == "mcp_gateway_hello"
        assert hello["protocol_version"] == "1.0"
        assert hello["connection_instance_id"]
        assert "mcp_runtime_v1" in hello["capabilities"]
        websocket.send_json({"type": "heartbeat", "version": "phase-zero"})
        assert websocket.receive_json()["type"] == "heartbeat_ack"

        with SessionLocal() as db:
            assert db.get(CommandSession, session_ids["foreign_owner"]).line_count == 0
            assert db.get(CommandSession, session_ids["foreign_owner"]).pid is None
            assert (
                db.get(CommandSession, session_ids["foreign_resource"]).status
                == "running"
            )
            assert db.get(CommandSession, session_ids["foreign_resource"]).pid is None
            assert (
                db.get(CommandSession, session_ids["foreign_origin"]).status
                == "running"
            )
            assert db.get(CommandSession, session_ids["foreign_origin"]).pid is None
            current_snapshot = db.get(CommandSession, session_ids["owned_snapshot"])
            assert current_snapshot.status == "running"
            assert current_snapshot.completed_at is None
            assert current_snapshot.pid == "101"

        websocket.send_json(
            {
                "type": "session_output",
                "session_id": session_ids["owned"],
                "stream": "stdout",
                "text": "owned-output\n",
            }
        )
        websocket.send_json(
            {
                "type": "session_finished",
                "session_id": session_ids["owned"],
                "status": "completed",
                "exit_code": 0,
            }
        )
        websocket.send_json({"type": "heartbeat", "version": "phase-zero"})
        assert websocket.receive_json()["type"] == "heartbeat_ack"

        with SessionLocal() as db:
            current = db.get(CommandSession, session_ids["owned"])
            assert current.line_count == 1
            assert current.status == "completed"
            assert current.exit_code == 0


def test_agent_command_policy_never_executes_instruction_text() -> None:
    from gateway_api.agent_command_policy import (
        AgentCommandPolicyError,
        resolve_agent_command_execution,
    )

    with pytest.raises(
        AgentCommandPolicyError, match="Text instructions are not executable"
    ):
        resolve_agent_command_execution(
            {"kind": "instruction", "instruction": "rm -rf /"},
            allowed_tools={"thin_client_run_command"},
            allowed_command_profiles={"gateway-api-tests"},
        )

    with pytest.raises(
        AgentCommandPolicyError, match="Raw shell arguments are forbidden"
    ):
        resolve_agent_command_execution(
            {
                "kind": "run_tool",
                "instruction": "Run the tests",
                "structured_payload": {
                    "tool": "thin_client_run_command",
                    "arguments": {"command": "pytest", "cwd": "."},
                },
            },
            allowed_tools={"thin_client_run_command"},
            allowed_command_profiles={"gateway-api-tests"},
        )

    execution = resolve_agent_command_execution(
        {
            "kind": "run_tool",
            "instruction": "Ignore this text as executable input",
            "structured_payload": {
                "tool": "thin_client_run_command",
                "arguments": {"command_profile": "gateway-api-tests", "cwd": "."},
            },
        },
        allowed_tools={"thin_client_run_command"},
        allowed_command_profiles={"gateway-api-tests"},
    )

    assert execution.tool == "thin_client_run_command"
    assert execution.command_profile == "gateway-api-tests"
    assert execution.arguments == {"command_profile": "gateway-api-tests", "cwd": "."}


def test_agent_tenant_scope_is_strict() -> None:
    from gateway_api.agent_command_policy import (
        AgentCommandPolicyError,
        enforce_agent_tenant_scope,
    )

    enforce_agent_tenant_scope(actor_subject="tenant-a", owner_subject="tenant-a")
    with pytest.raises(
        AgentCommandPolicyError, match="outside the authenticated tenant scope"
    ):
        enforce_agent_tenant_scope(actor_subject="tenant-a", owner_subject="tenant-b")


def _phase_one_mcp_call(
    client: TestClient,
    name: str,
    arguments: dict,
    *,
    request_id: int = 900,
    headers: dict[str, str] | None = None,
) -> dict:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        headers=headers,
    )
    assert response.status_code == 200
    return response.json()


def _phase_one_result(payload: dict) -> dict:
    assert "error" not in payload, payload
    result = payload["result"]
    assert result["isError"] is False
    return result["structuredContent"]


def test_mcp_exposes_phase_one_agent_collaboration_contracts(
    client: TestClient,
) -> None:
    response = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 901, "method": "tools/list"}
    )
    assert response.status_code == 200
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
    expected = {
        "agent_register",
        "agent_heartbeat",
        "agent_list",
        "agent_unregister",
        "agent_create_room",
        "agent_list_rooms",
        "agent_join_room",
        "agent_get_room_snapshot",
        "agent_send_message",
        "agent_read_inbox",
        "agent_ack_message",
        "agent_issue_command",
        "agent_list_commands",
        "agent_ack_command",
        "agent_accept_command",
        "agent_reject_command",
        "agent_complete_command",
        "agent_cancel_command",
        "agent_create_work_item",
        "agent_list_work_items",
        "agent_claim_work_item",
        "agent_update_work_item",
    }
    assert expected.issubset(tools)
    assert tools["agent_issue_command"]["inputSchema"]["required"] == [
        "room_id",
        "issuer_agent_id",
        "target_agent_id",
        "instruction",
    ]
    assert (
        tools["agent_read_inbox"]["inputSchema"]["properties"]["wait_seconds"][
            "maximum"
        ]
        == 30
    )
    assert tools["agent_claim_work_item"]["annotations"]["idempotentHint"] is False
    assert (
        "never executes instruction text automatically"
        in tools["agent_issue_command"]["description"].lower()
    )


def test_phase_one_durable_message_delivery_and_idempotency(client: TestClient) -> None:
    room_first = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": "Gateway Phase 1",
                "repository_identity": "products/chatgpt-mcp-ssh-gateway",
                "base_commit": "b11b870",
                "idempotency_key": "phase1-room-message-test",
            },
            request_id=902,
        )
    )["room"]
    room_second = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": "Ignored duplicate title",
                "idempotency_key": "phase1-room-message-test",
            },
            request_id=903,
        )
    )["room"]
    assert room_first["id"] == room_second["id"]

    sender = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "backend-agent",
                "instance_id": "phase1-backend-instance",
                "display_name": "Backend Agent",
                "capabilities": ["python", "api"],
                "room_id": room_first["id"],
            },
            request_id=904,
        )
    )["agent"]
    recipient = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "review-agent",
                "instance_id": "phase1-review-instance",
                "display_name": "Review Agent",
                "capabilities": ["review"],
                "room_id": room_first["id"],
            },
            request_id=905,
        )
    )["agent"]

    message_args = {
        "room_id": room_first["id"],
        "sender_agent_id": sender["id"],
        "recipient_agent_id": recipient["id"],
        "kind": "review_request",
        "body": "Review the Phase 1 mailbox contract.",
        "payload": {"artifact": "agent-collaboration-phase-1"},
        "correlation_id": "corr-phase1-message",
        "idempotency_key": "phase1-message-idempotency",
    }
    first_send = _phase_one_result(
        _phase_one_mcp_call(client, "agent_send_message", message_args, request_id=906)
    )
    second_send = _phase_one_result(
        _phase_one_mcp_call(client, "agent_send_message", message_args, request_id=907)
    )
    assert first_send["message"]["id"] == second_send["message"]["id"]
    assert first_send["recipient_count"] == 1

    first_inbox = _phase_one_result(
        _phase_one_mcp_call(
            client, "agent_read_inbox", {"agent_id": recipient["id"]}, request_id=908
        )
    )
    second_inbox = _phase_one_result(
        _phase_one_mcp_call(
            client, "agent_read_inbox", {"agent_id": recipient["id"]}, request_id=909
        )
    )
    assert [item["id"] for item in first_inbox["messages"]] == [
        first_send["message"]["id"]
    ]
    assert [item["id"] for item in second_inbox["messages"]] == [
        first_send["message"]["id"]
    ]
    assert first_inbox["messages"][0]["delivery"]["attempt_count"] == 1
    assert second_inbox["messages"][0]["delivery"]["attempt_count"] == 2

    acknowledged = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_ack_message",
            {"agent_id": recipient["id"], "message_id": first_send["message"]["id"]},
            request_id=910,
        )
    )
    assert acknowledged["status"] == "acknowledged"
    empty_inbox = _phase_one_result(
        _phase_one_mcp_call(
            client, "agent_read_inbox", {"agent_id": recipient["id"]}, request_id=911
        )
    )
    assert empty_inbox["messages"] == []


def test_phase_one_command_lifecycle_never_auto_executes(client: TestClient) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import CommandSession

    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {"title": "Command Room", "idempotency_key": "phase1-command-room"},
            request_id=912,
        )
    )["room"]
    issuer = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "coordinator",
                "instance_id": "phase1-coordinator",
                "room_id": room["id"],
            },
            request_id=913,
        )
    )["agent"]
    target = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "worker",
                "instance_id": "phase1-worker",
                "room_id": room["id"],
            },
            request_id=914,
        )
    )["agent"]

    with SessionLocal() as db:
        sessions_before = db.query(CommandSession).count()

    unsafe = _phase_one_mcp_call(
        client,
        "agent_issue_command",
        {
            "room_id": room["id"],
            "issuer_agent_id": issuer["id"],
            "target_agent_id": target["id"],
            "kind": "run_tool",
            "instruction": "Run tests",
            "structured_payload": {
                "tool": "thin_client_run_command",
                "arguments": {"command": "pytest", "cwd": "."},
            },
        },
        request_id=915,
    )
    assert unsafe["error"]["code"] == 400
    assert "Raw shell arguments are forbidden" in unsafe["error"]["message"]

    command_args = {
        "room_id": room["id"],
        "issuer_agent_id": issuer["id"],
        "target_agent_id": target["id"],
        "kind": "run_tool",
        "instruction": "Run the reviewed gateway API test profile.",
        "structured_payload": {
            "tool": "thin_client_run_command",
            "arguments": {"command_profile": "gateway-api-tests", "cwd": "."},
        },
        "idempotency_key": "phase1-command-idempotency",
    }
    issued_first = _phase_one_result(
        _phase_one_mcp_call(client, "agent_issue_command", command_args, request_id=916)
    )["command"]
    issued_second = _phase_one_result(
        _phase_one_mcp_call(client, "agent_issue_command", command_args, request_id=917)
    )["command"]
    assert issued_first["id"] == issued_second["id"]
    assert issued_first["status"] == "pending"

    delivered = _phase_one_result(
        _phase_one_mcp_call(
            client, "agent_list_commands", {"agent_id": target["id"]}, request_id=918
        )
    )["commands"]
    assert delivered[0]["id"] == issued_first["id"]
    assert delivered[0]["status"] == "delivered"

    acknowledged = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_ack_command",
            {"agent_id": target["id"], "command_id": issued_first["id"]},
            request_id=919,
        )
    )["command"]
    accepted = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_accept_command",
            {"agent_id": target["id"], "command_id": issued_first["id"]},
            request_id=920,
        )
    )["command"]
    completed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_complete_command",
            {
                "agent_id": target["id"],
                "command_id": issued_first["id"],
                "status": "completed",
                "result": {"tests": 42, "outcome": "passed"},
            },
            request_id=921,
        )
    )["command"]
    assert acknowledged["status"] == "acknowledged"
    assert accepted["status"] == "accepted"
    assert completed["status"] == "completed"
    assert completed["result"] == {"tests": 42, "outcome": "passed"}

    with SessionLocal() as db:
        assert db.query(CommandSession).count() == sessions_before


def test_phase_one_work_item_optimistic_claim_and_update(client: TestClient) -> None:
    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {"title": "Work Item Room", "idempotency_key": "phase1-work-room"},
            request_id=922,
        )
    )["room"]
    first_agent = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "worker-a",
                "instance_id": "phase1-work-a",
                "room_id": room["id"],
            },
            request_id=923,
        )
    )["agent"]
    second_agent = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "worker-b",
                "instance_id": "phase1-work-b",
                "room_id": room["id"],
            },
            request_id=924,
        )
    )["agent"]
    item = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Implement durable inbox",
                "acceptance_criteria": ["At-least-once delivery", "Explicit ACK"],
                "idempotency_key": "phase1-work-item",
            },
            request_id=925,
        )
    )["work_item"]
    assert item["version"] == 1
    assert item["status"] == "open"

    claimed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_claim_work_item",
            {
                "agent_id": first_agent["id"],
                "work_item_id": item["id"],
                "expected_version": 1,
            },
            request_id=926,
        )
    )["work_item"]
    assert claimed["status"] == "in_progress"
    assert claimed["version"] == 2
    assert claimed["assigned_agent_id"] == first_agent["id"]

    conflict = _phase_one_mcp_call(
        client,
        "agent_claim_work_item",
        {
            "agent_id": second_agent["id"],
            "work_item_id": item["id"],
            "expected_version": 1,
        },
        request_id=927,
    )
    assert conflict["error"]["code"] == 409
    assert "claim conflict" in conflict["error"]["message"]

    stale_update = _phase_one_mcp_call(
        client,
        "agent_update_work_item",
        {
            "agent_id": first_agent["id"],
            "work_item_id": item["id"],
            "expected_version": 1,
            "status": "review",
        },
        request_id=928,
    )
    assert stale_update["error"]["code"] == 409
    assert "version conflict" in stale_update["error"]["message"]

    reviewed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_update_work_item",
            {
                "agent_id": first_agent["id"],
                "work_item_id": item["id"],
                "expected_version": 2,
                "status": "review",
                "result": {"tests": "passed"},
            },
            request_id=929,
        )
    )["work_item"]
    completed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_update_work_item",
            {
                "agent_id": first_agent["id"],
                "work_item_id": item["id"],
                "expected_version": 3,
                "status": "completed",
                "result": {"tests": "passed", "review": "accepted"},
            },
            request_id=930,
        )
    )["work_item"]
    assert reviewed["version"] == 3
    assert completed["version"] == 4
    assert completed["status"] == "completed"


def test_phase_one_rejects_nested_secrets_and_cross_tenant_reads(
    client: TestClient,
) -> None:
    from gateway_api.auth import create_jwt

    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {"title": "Tenant Boundary Room", "idempotency_key": "phase1-tenant-room"},
            request_id=931,
        )
    )["room"]
    sender = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "tenant-a-sender",
                "instance_id": "phase1-tenant-a-sender",
                "room_id": room["id"],
            },
            request_id=932,
        )
    )["agent"]
    recipient = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_register",
            {
                "logical_agent_id": "tenant-a-recipient",
                "instance_id": "phase1-tenant-a-recipient",
                "room_id": room["id"],
            },
            request_id=933,
        )
    )["agent"]

    secret_message = _phase_one_mcp_call(
        client,
        "agent_send_message",
        {
            "room_id": room["id"],
            "sender_agent_id": sender["id"],
            "recipient_agent_id": recipient["id"],
            "body": "Payload must be rejected.",
            "payload": {"nested": {"clientSecret": "must-not-persist"}},
        },
        request_id=934,
    )
    assert secret_message["error"]["code"] == 400
    assert "Secret-like key" in secret_message["error"]["message"]
    assert "must-not-persist" not in json.dumps(secret_message)

    other_token = create_jwt(
        subject="tenant:other",
        username="other-user",
        roles=["gateway-user"],
        scopes=["workspace:read"],
        token_type="access",
        ttl_seconds=300,
    )
    foreign = _phase_one_mcp_call(
        client,
        "agent_get_room_snapshot",
        {"room_id": room["id"]},
        request_id=935,
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert foreign["error"]["code"] == 404
    assert foreign["error"]["message"] == "Collaboration room not found"


def test_phase_one_openapi_asyncapi_and_event_schema_contracts(
    client: TestClient,
) -> None:
    event_types = {
        "gateway.agent.registered.v1",
        "gateway.agent.heartbeat.v1",
        "gateway.agent.unregistered.v1",
        "gateway.collaboration.room.created.v1",
        "gateway.agent.room_joined.v1",
        "gateway.agent.message.sent.v1",
        "gateway.agent.message.acknowledged.v1",
        "gateway.agent.command.issued.v1",
        "gateway.agent.command.acknowledged.v1",
        "gateway.agent.command.accepted.v1",
        "gateway.agent.command.completed.v1",
        "gateway.agent.command.cancelled.v1",
        "gateway.work_item.created.v1",
        "gateway.work_item.claimed.v1",
        "gateway.work_item.updated.v1",
    }
    root = Path(__file__).resolve().parents[3]
    asyncapi_text = (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text(
        encoding="utf-8"
    )
    static_openapi_text = (root / "openapi" / "gateway.openapi.yaml").read_text(
        encoding="utf-8"
    )
    dynamic_paths = client.get("/openapi.json").json()["paths"]

    for event_type in event_types:
        schema_path = root / "schemas" / f"{event_type}.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["$id"] == event_type
        assert schema["additionalProperties"] is False
        assert {"event_id", "occurred_at"}.issubset(schema["required"])
        assert event_type in asyncapi_text
        assert f"../schemas/{event_type}.schema.json" in asyncapi_text

    required_paths = {
        "/api/agent-collaboration/agents",
        "/api/agent-collaboration/rooms",
        "/api/agent-collaboration/messages",
        "/api/agent-collaboration/messages/inbox",
        "/api/agent-collaboration/commands",
        "/api/agent-collaboration/commands/inbox",
        "/api/agent-collaboration/work-items",
    }
    assert required_paths.issubset(dynamic_paths)
    for path in required_paths:
        assert f"  {path}:" in static_openapi_text


def test_phase_one_rest_surface_smoke(client: TestClient) -> None:
    room_response = client.post(
        "/api/agent-collaboration/rooms",
        json={
            "title": "REST Pilot Room",
            "repository_identity": "products/chatgpt-mcp-ssh-gateway",
            "idempotency_key": "phase1-rest-room",
        },
    )
    assert room_response.status_code == 201
    room_id = room_response.json()["id"]

    agent_response = client.post(
        "/api/agent-collaboration/agents",
        json={
            "logical_agent_id": "rest-agent",
            "instance_id": "phase1-rest-agent-instance",
            "display_name": "REST Agent",
            "capabilities": ["rest"],
            "room_id": room_id,
            "ttl_seconds": 120,
        },
    )
    assert agent_response.status_code == 201
    agent = agent_response.json()
    assert agent["current_room_id"] == room_id

    heartbeat = client.post(
        f"/api/agent-collaboration/agents/{agent['id']}/heartbeat",
        json={"status": "idle", "ttl_seconds": 180},
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "idle"

    listed = client.get("/api/agent-collaboration/agents", params={"room_id": room_id})
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [agent["id"]]

    snapshot = client.get(f"/api/agent-collaboration/rooms/{room_id}/snapshot")
    assert snapshot.status_code == 200
    assert snapshot.json()["room"]["id"] == room_id


def _phase_two_room_agents(
    client: TestClient, *, suffix: str
) -> tuple[dict, dict, dict, dict]:
    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": f"Phase 2 {suffix}",
                "repository_identity": "products/chatgpt-mcp-ssh-gateway",
                "base_commit": "phase2-base",
                "policy": {},
                "idempotency_key": f"phase2-room-{suffix}",
            },
            request_id=2200,
        )
    )["room"]

    def register(name: str, capabilities: list[str] | None = None) -> dict:
        return _phase_one_result(
            _phase_one_mcp_call(
                client,
                "agent_register",
                {
                    "logical_agent_id": name,
                    "instance_id": f"phase2-{suffix}-{name}",
                    "display_name": name,
                    "capabilities": capabilities or [],
                    "room_id": room["id"],
                },
                request_id=2201,
            )
        )["agent"]

    return (
        room,
        register("writer-a"),
        register("writer-b"),
        register("coordinator", ["coordination:integrate"]),
    )


def test_mcp_exposes_phase_two_coordination_contracts(client: TestClient) -> None:
    response = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 2210, "method": "tools/list"}
    )
    assert response.status_code == 200
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
    expected = {
        "agent_acquire_lease",
        "agent_list_leases",
        "agent_renew_lease",
        "agent_release_lease",
        "agent_detect_conflicts",
        "agent_create_handoff",
        "agent_list_handoffs",
        "agent_mark_handoff_ready",
        "agent_accept_handoff",
        "agent_create_integration",
        "agent_list_integrations",
        "agent_complete_integration",
    }
    assert expected.issubset(tools)
    assert tools["agent_acquire_lease"]["annotations"]["idempotentHint"] is True
    assert tools["agent_release_lease"]["annotations"]["destructiveHint"] is True
    assert (
        "never performs a Git merge automatically"
        in tools["agent_create_integration"]["description"]
    )
    guarded = tools["write_file"]["inputSchema"]["properties"]
    assert {
        "lease_id",
        "fencing_token",
        "expected_sha256",
        "expected_absent",
        "branch_name",
        "worktree_path",
    }.issubset(guarded)


def test_phase_two_thin_client_sandbox_sha_and_cas(tmp_path: Path) -> None:
    from gateway_cli.sandbox import SandboxError, ThinClientSandbox

    sandbox = ThinClientSandbox(tmp_path)
    missing = sandbox.file_state("state.txt")
    assert missing == {
        "path": "state.txt",
        "exists": False,
        "kind": None,
        "size": None,
        "sha256": None,
    }

    created = sandbox.write_file(
        "state.txt",
        arguments={"operation": "write", "content": "alpha", "expected_absent": True},
    )
    assert created["before_sha256"] is None
    assert created["after_sha256"] == hashlib.sha256(b"alpha").hexdigest()
    assert sandbox.read_file("state.txt")["sha256"] == created["after_sha256"]

    with pytest.raises(SandboxError, match="sha256 mismatch"):
        sandbox.write_file(
            "state.txt",
            arguments={
                "operation": "write",
                "content": "beta",
                "expected_sha256": "0" * 64,
            },
        )

    updated = sandbox.write_file(
        "state.txt",
        arguments={
            "operation": "write",
            "content": "beta",
            "expected_sha256": created["after_sha256"],
        },
    )
    assert updated["before_sha256"] == created["after_sha256"]
    assert updated["after_sha256"] == hashlib.sha256(b"beta").hexdigest()


def test_phase_two_leases_fencing_and_guarded_server_write(client: TestClient) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import FileChangeSet

    room, writer_a, writer_b, _ = _phase_two_room_agents(client, suffix="fencing")
    baseline = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "write_file",
            {
                "path": ".worktrees/writer-a-fencing/phase2/guarded.txt",
                "content": "baseline",
            },
            request_id=2220,
        )
    )
    assert baseline["after_sha256"] == hashlib.sha256(b"baseline").hexdigest()

    lease_args = {
        "room_id": room["id"],
        "holder_agent_id": writer_a["id"],
        "origin": "server",
        "mode": "exclusive_write",
        "reservations": [
            {"kind": "path", "pattern": "phase2/guarded.txt", "recursive": False}
        ],
        "branch_name": "agent/writer-a/fencing",
        "worktree_path": ".worktrees/writer-a-fencing",
        "base_commit": "phase2-base",
        "expected_head": "phase2-base",
        "idempotency_key": "phase2-lease-fencing-a",
    }
    lease_a = _phase_one_result(
        _phase_one_mcp_call(client, "agent_acquire_lease", lease_args, request_id=2221)
    )["lease"]
    assert lease_a["fencing_token"] == 1

    conflict = _phase_one_mcp_call(
        client,
        "agent_acquire_lease",
        {
            **lease_args,
            "holder_agent_id": writer_b["id"],
            "origin": "thin_client",
            "resource_id": "phase2-other-client",
            "branch_name": "agent/writer-b/fencing",
            "worktree_path": ".worktrees/writer-b-fencing",
            "idempotency_key": "idem3-conflict",
        },
        request_id=2222,
    )
    assert conflict["error"]["code"] == 409
    assert "conflicts with active lease" in conflict["error"]["message"]

    missing_guard = _phase_one_mcp_call(
        client,
        "write_file",
        {
            "path": ".worktrees/writer-a-fencing/phase2/guarded.txt",
            "content": "unguarded",
        },
        request_id=2223,
    )
    assert missing_guard["error"]["code"] == 400
    assert missing_guard["error"]["message"] == "lease_id is required"

    guarded_args = {
        "path": ".worktrees/writer-a-fencing/phase2/guarded.txt",
        "content": "writer-a",
        "room_id": room["id"],
        "agent_id": writer_a["id"],
        "lease_id": lease_a["id"],
        "fencing_token": lease_a["fencing_token"],
        "expected_sha256": baseline["after_sha256"],
        "base_commit": lease_a["base_commit"],
        "branch_name": lease_a["branch_name"],
        "worktree_path": lease_a["worktree_path"],
    }
    guarded = _phase_one_result(
        _phase_one_mcp_call(client, "write_file", guarded_args, request_id=2224)
    )
    assert guarded["after_sha256"] == hashlib.sha256(b"writer-a").hexdigest()

    stale_hash = _phase_one_mcp_call(
        client, "write_file", guarded_args, request_id=2225
    )
    assert stale_hash["error"]["code"] == 409
    assert "sha256 mismatch" in stale_hash["error"]["message"]

    released = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_release_lease",
            {
                "lease_id": lease_a["id"],
                "actor_agent_id": writer_a["id"],
                "fencing_token": lease_a["fencing_token"],
            },
            request_id=2226,
        )
    )["lease"]
    assert released["status"] == "released"

    lease_b = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_acquire_lease",
            {
                **lease_args,
                "holder_agent_id": writer_b["id"],
                "branch_name": "agent/writer-b/fencing",
                "worktree_path": ".worktrees/writer-b-fencing",
                "idempotency_key": "idem3",
            },
            request_id=2227,
        )
    )["lease"]
    assert lease_b["fencing_token"] > lease_a["fencing_token"]

    stale_fence = _phase_one_mcp_call(
        client,
        "write_file",
        {
            **guarded_args,
            "content": "stale-fence",
            "expected_sha256": guarded["after_sha256"],
        },
        request_id=2228,
    )
    assert stale_fence["error"]["code"] == 409

    with SessionLocal() as db:
        change = db.get(FileChangeSet, guarded["file_change_id"])
        assert change is not None
        assert change.room_id == room["id"]
        assert change.agent_id == writer_a["id"]
        assert change.lease_id == lease_a["id"]
        assert change.fencing_token == lease_a["fencing_token"]
        assert change.before_sha256 == baseline["after_sha256"]
        assert change.after_sha256 == guarded["after_sha256"]


def test_phase_two_conflict_handoff_and_coordinator_integration(
    client: TestClient,
) -> None:
    room, writer_a, writer_b, coordinator = _phase_two_room_agents(
        client, suffix="handoff"
    )

    def baseline_and_guarded(
        path: str, holder: dict, branch: str, lease_key: str, content: str
    ) -> tuple[dict, dict]:
        worktree_path = f".worktrees/{lease_key}"
        physical_path = f"{worktree_path}/{path}"
        baseline = _phase_one_result(
            _phase_one_mcp_call(
                client,
                "write_file",
                {"path": physical_path, "content": "base"},
                request_id=2230,
            )
        )
        lease = _phase_one_result(
            _phase_one_mcp_call(
                client,
                "agent_acquire_lease",
                {
                    "room_id": room["id"],
                    "holder_agent_id": holder["id"],
                    "origin": "server",
                    "mode": "exclusive_write",
                    "reservations": [
                        {"kind": "path", "pattern": path, "recursive": False}
                    ],
                    "branch_name": branch,
                    "worktree_path": worktree_path,
                    "base_commit": "phase2-base",
                    "idempotency_key": lease_key,
                },
                request_id=2231,
            )
        )["lease"]
        change = _phase_one_result(
            _phase_one_mcp_call(
                client,
                "write_file",
                {
                    "path": physical_path,
                    "content": content,
                    "room_id": room["id"],
                    "agent_id": holder["id"],
                    "lease_id": lease["id"],
                    "fencing_token": lease["fencing_token"],
                    "expected_sha256": baseline["after_sha256"],
                    "base_commit": lease["base_commit"],
                    "branch_name": lease["branch_name"],
                    "worktree_path": lease["worktree_path"],
                },
                request_id=2232,
            )
        )
        return lease, change

    lease_a, change_a = baseline_and_guarded(
        "phase2/handoff-a.txt",
        writer_a,
        "agent/writer-a/handoff",
        "phase2-handoff-lease-a",
        "a-change",
    )
    lease_b, change_b = baseline_and_guarded(
        "phase2/handoff-b.txt",
        writer_b,
        "agent/writer-b/handoff",
        "phase2-handoff-lease-b",
        "b-change",
    )

    same_path_report = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_detect_conflicts",
            {
                "candidate_change_ids": [change_a["file_change_id"]],
                "comparison_change_ids": [change_a["file_change_id"]],
                "room_id": room["id"],
            },
            request_id=2233,
        )
    )["conflict_report"]
    assert same_path_report["safe"] is True

    handoff = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_handoff",
            {
                "room_id": room["id"],
                "source_agent_id": writer_a["id"],
                "target_agent_id": writer_b["id"],
                "lease_id": lease_a["id"],
                "expected_fencing_token": lease_a["fencing_token"],
                "required_change_ids": [change_a["file_change_id"]],
                "summary": "Transfer guarded file A",
                "idempotency_key": "phase2-handoff-a",
            },
            request_id=2234,
        )
    )["handoff"]
    ready = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_mark_handoff_ready",
            {"handoff_id": handoff["id"], "source_agent_id": writer_a["id"]},
            request_id=2235,
        )
    )["handoff"]
    assert ready["status"] == "ready"

    still_locked = _phase_one_mcp_call(
        client,
        "agent_accept_handoff",
        {
            "handoff_id": handoff["id"],
            "target_agent_id": writer_b["id"],
            "comparison_change_ids": [],
        },
        request_id=2236,
    )
    assert still_locked["error"]["code"] == 409
    assert "must be released" in still_locked["error"]["message"]

    _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_release_lease",
            {
                "lease_id": lease_a["id"],
                "actor_agent_id": writer_a["id"],
                "fencing_token": lease_a["fencing_token"],
            },
            request_id=2237,
        )
    )
    accepted = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_accept_handoff",
            {
                "handoff_id": handoff["id"],
                "target_agent_id": writer_b["id"],
                "comparison_change_ids": [],
            },
            request_id=2238,
        )
    )["handoff"]
    assert accepted["status"] == "accepted"

    _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_release_lease",
            {
                "lease_id": lease_b["id"],
                "actor_agent_id": writer_b["id"],
                "fencing_token": lease_b["fencing_token"],
            },
            request_id=2239,
        )
    )
    integration = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_integration",
            {
                "room_id": room["id"],
                "coordinator_agent_id": coordinator["id"],
                "target_branch": "main",
                "expected_target_head": "target-head-1",
                "candidate_change_ids": [change_b["file_change_id"]],
                "comparison_change_ids": [change_a["file_change_id"]],
                "source_lease_ids": [lease_b["id"]],
                "idempotency_key": "idem4",
            },
            request_id=2240,
        )
    )["integration"]
    assert integration["status"] == "review"
    assert integration["conflict_report"]["safe"] is True

    stale_head = _phase_one_mcp_call(
        client,
        "agent_complete_integration",
        {
            "integration_id": integration["id"],
            "coordinator_agent_id": coordinator["id"],
            "expected_version": 1,
            "status": "approved",
            "observed_target_head": "unexpected-target-head",
            "decision": {"review": "passed"},
        },
        request_id=2241,
    )
    assert stale_head["error"]["code"] == 409
    assert stale_head["error"]["message"] == "Integration target head is stale"

    approved = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_complete_integration",
            {
                "integration_id": integration["id"],
                "coordinator_agent_id": coordinator["id"],
                "expected_version": 1,
                "status": "approved",
                "observed_target_head": "target-head-1",
                "decision": {"review": "passed"},
            },
            request_id=2242,
        )
    )["integration"]
    assert approved["version"] == 2

    stale = _phase_one_mcp_call(
        client,
        "agent_complete_integration",
        {
            "integration_id": integration["id"],
            "coordinator_agent_id": coordinator["id"],
            "expected_version": 1,
            "status": "integrated",
            "observed_target_head": "target-head-1",
            "integrated_commit": "integrated-commit-1",
        },
        request_id=2243,
    )
    assert stale["error"]["code"] == 409
    assert stale["error"]["message"] == "Integration version conflict"

    completed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_complete_integration",
            {
                "integration_id": integration["id"],
                "coordinator_agent_id": coordinator["id"],
                "expected_version": 2,
                "status": "integrated",
                "observed_target_head": "target-head-1",
                "decision": {"method": "explicit-external-git-operation"},
                "integrated_commit": "integrated-commit-1",
            },
            request_id=2244,
        )
    )["integration"]
    assert completed["status"] == "integrated"
    assert completed["integrated_commit"] == "integrated-commit-1"


def test_phase_two_rest_surface_and_tenant_isolation(client: TestClient) -> None:
    from gateway_api.auth import create_jwt

    room, writer_a, _, _ = _phase_two_room_agents(client, suffix="rest")
    secret = client.post(
        "/api/agent-coordination/leases",
        json={
            "room_id": room["id"],
            "holder_agent_id": writer_a["id"],
            "origin": "server",
            "mode": "exclusive_write",
            "reservations": [
                {"kind": "path", "pattern": "phase2/rest.txt", "recursive": False}
            ],
            "branch_name": "agent/writer-a/rest",
            "worktree_path": ".worktrees/writer-a-rest",
            "base_commit": "phase2-base",
            "meta": {"nested": {"accessToken": "must-not-persist"}},
        },
    )
    assert secret.status_code == 400
    assert "Secret-like key" in secret.json()["detail"]
    assert "must-not-persist" not in json.dumps(secret.json())

    acquired = client.post(
        "/api/agent-coordination/leases",
        json={
            "room_id": room["id"],
            "holder_agent_id": writer_a["id"],
            "origin": "server",
            "mode": "exclusive_write",
            "reservations": [
                {"kind": "path", "pattern": "phase2/rest.txt", "recursive": False}
            ],
            "branch_name": "agent/writer-a/rest",
            "worktree_path": ".worktrees/writer-a-rest",
            "base_commit": "phase2-base",
            "idempotency_key": "phase2-rest-lease",
        },
    )
    assert acquired.status_code == 201
    lease = acquired.json()
    assert lease["fencing_token"] == 1

    listed = client.get(
        "/api/agent-coordination/leases", params={"room_id": room["id"]}
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [lease["id"]]

    other_token = create_jwt(
        subject="tenant:phase2-other",
        username="phase2-other",
        roles=["gateway-user"],
        scopes=["workspace:read"],
        token_type="access",
        ttl_seconds=300,
    )
    foreign = client.get(
        "/api/agent-coordination/leases",
        params={"room_id": room["id"]},
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert foreign.status_code == 404
    assert foreign.json()["detail"] == "Collaboration room not found"


def test_phase_two_openapi_asyncapi_and_event_schema_contracts(
    client: TestClient,
) -> None:
    event_types = {
        "gateway.resource_lease.acquired.v1",
        "gateway.resource_lease.renewed.v1",
        "gateway.resource_lease.released.v1",
        "gateway.agent.handoff.created.v1",
        "gateway.agent.handoff.ready.v1",
        "gateway.agent.handoff.accepted.v1",
        "gateway.agent.integration.created.v1",
        "gateway.agent.integration.updated.v1",
        "gateway.file_change.created.v1",
    }
    root = Path(__file__).resolve().parents[3]
    asyncapi_text = (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text(
        encoding="utf-8"
    )
    static_openapi_text = (root / "openapi" / "gateway.openapi.yaml").read_text(
        encoding="utf-8"
    )
    dynamic_paths = client.get("/openapi.json").json()["paths"]

    for event_type in event_types:
        schema = json.loads(
            (root / "schemas" / f"{event_type}.schema.json").read_text(encoding="utf-8")
        )
        assert schema["$id"] == event_type
        assert schema["additionalProperties"] is False
        assert {"event_id", "occurred_at"}.issubset(schema["required"])
        assert event_type in asyncapi_text
        assert f"../schemas/{event_type}.schema.json" in asyncapi_text

    required_paths = {
        "/api/agent-coordination/leases",
        "/api/agent-coordination/leases/{lease_id}/renew",
        "/api/agent-coordination/leases/{lease_id}/release",
        "/api/agent-coordination/conflicts/detect",
        "/api/agent-coordination/handoffs",
        "/api/agent-coordination/handoffs/{handoff_id}/ready",
        "/api/agent-coordination/handoffs/{handoff_id}/accept",
        "/api/agent-coordination/integrations",
        "/api/agent-coordination/integrations/{integration_id}",
    }
    assert required_paths.issubset(dynamic_paths)
    for path in required_paths:
        assert f"  {path}:" in static_openapi_text


def test_phase_two_conflicts_use_logical_paths_across_worktrees_and_resources(
    client: TestClient,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import FileChangeSet

    room, writer_a, writer_b, _ = _phase_two_room_agents(client, suffix="logical-conflict")
    candidate_id = str(uuid.uuid4())
    comparison_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add_all(
            [
                FileChangeSet(
                    id=candidate_id,
                    owner_subject="dev:local",
                    origin="thin_client",
                    resource_id="client-a",
                    room_id=room["id"],
                    agent_id=writer_a["id"],
                    path=".worktrees/a/src/service.py",
                    worktree_path=".worktrees/a",
                    operation="write",
                    before_sha256="1" * 64,
                    after_sha256="2" * 64,
                    diff_json={"suppressed": True, "hunks": []},
                    suppressed=True,
                ),
                FileChangeSet(
                    id=comparison_id,
                    owner_subject="dev:local",
                    origin="thin_client",
                    resource_id="client-b",
                    room_id=room["id"],
                    agent_id=writer_b["id"],
                    path=".worktrees/b/src/service.py",
                    worktree_path=".worktrees/b",
                    operation="write",
                    before_sha256="3" * 64,
                    after_sha256="4" * 64,
                    diff_json={"suppressed": True, "hunks": []},
                    suppressed=True,
                ),
            ]
        )
        db.commit()

    report = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_detect_conflicts",
            {
                "candidate_change_ids": [candidate_id],
                "comparison_change_ids": [comparison_id],
                "room_id": room["id"],
            },
            request_id=2250,
        )
    )["conflict_report"]
    assert report["safe"] is False
    assert report["hard_conflict_count"] == 1
    assert report["conflicts"][0]["path"] == "src/service.py"
    assert report["conflicts"][0]["comparison_path"] == "src/service.py"


def test_phase_two_additive_file_change_schema_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import create_engine, inspect, text

    from gateway_api import database, models
    from gateway_api.schema_migrations import run_schema_migrations

    upgrade_engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    models.Base.metadata.create_all(upgrade_engine)
    additive_columns = (
        "room_id",
        "agent_id",
        "lease_id",
        "fencing_token",
        "before_sha256",
        "after_sha256",
        "base_commit",
        "branch_name",
        "worktree_path",
        "session_id",
    )
    legacy_inspector = inspect(upgrade_engine)
    additive_indexes = [
        index["name"]
        for index in legacy_inspector.get_indexes("file_change_sets")
        if set(index["column_names"]) & set(additive_columns)
    ]
    with upgrade_engine.begin() as connection:
        for index_name in additive_indexes:
            connection.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))
        for column_name in additive_columns:
            connection.execute(
                text(f'ALTER TABLE file_change_sets DROP COLUMN "{column_name}"')
            )
    monkeypatch.setattr(database, "engine", upgrade_engine)
    run_schema_migrations()
    inspector = inspect(upgrade_engine)
    columns = {column["name"] for column in inspector.get_columns("file_change_sets")}
    indexes = {index["name"] for index in inspector.get_indexes("file_change_sets")}
    assert {
        "room_id",
        "agent_id",
        "lease_id",
        "fencing_token",
        "before_sha256",
        "after_sha256",
        "base_commit",
        "branch_name",
        "worktree_path",
        "session_id",
    }.issubset(columns)
    assert {
        "ix_file_change_sets_room_id",
        "ix_file_change_sets_agent_id",
        "ix_file_change_sets_lease_id",
        "ix_file_change_sets_fencing_token",
    }.issubset(indexes)


def test_phase_two_git_worktree_state_and_gateway_validation(tmp_path: Path) -> None:
    from gateway_api.agent_coordination import WriteLeaseContext
    from gateway_api.routers.mcp import _local_git_state, _validate_write_git_state
    from gateway_cli.sandbox import ThinClientSandbox

    source = tmp_path / "source"
    worktree = tmp_path / "worktrees" / "writer"
    source.mkdir()
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "phase2@example.test"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Phase 2 Test"], check=True)
    (source / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-m", "base"], check=True, capture_output=True)
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    worktree.parent.mkdir()
    subprocess.run(
        ["git", "-C", str(source), "worktree", "add", "-b", "agent/phase2/writer", str(worktree), head],
        check=True,
        capture_output=True,
    )

    sandbox = ThinClientSandbox(tmp_path)
    state = sandbox.git_state("worktrees/writer", head)
    assert state["toplevel"] == "worktrees/writer"
    assert state["branch_name"] == "agent/phase2/writer"
    assert state["head"] == head
    assert state["base_is_ancestor"] is True

    context = WriteLeaseContext(
        room_id="room",
        agent_id="agent",
        lease_id="lease",
        fencing_token=1,
        base_commit=head,
        branch_name="agent/phase2/writer",
        worktree_path="worktrees/writer",
        expected_head=head,
        expected_sha256=None,
        expected_absent=True,
    )
    local_state = _local_git_state(worktree, head)
    _validate_write_git_state(local_state, context)

    stale_context = WriteLeaseContext(
        **{**context.__dict__, "expected_head": "0" * 40}
    )
    with pytest.raises(HTTPException, match="HEAD is stale"):
        _validate_write_git_state(local_state, stale_context)


def test_phase_two_guarded_thin_client_write_verifies_git_and_file_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway_api.config import get_settings

    room, writer, _, _ = _phase_two_room_agents(client, suffix="thin-guard")
    _, thin_client_id = _register_phase_zero_thin_client(client)
    lease = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_acquire_lease",
            {
                "room_id": room["id"],
                "holder_agent_id": writer["id"],
                "origin": "thin_client",
                "resource_id": thin_client_id,
                "mode": "exclusive_write",
                "reservations": [
                    {"kind": "path", "pattern": "src/guarded.py", "recursive": False}
                ],
                "branch_name": "agent/phase2/thin-guard",
                "worktree_path": ".worktrees/thin-guard",
                "base_commit": "base-head",
                "expected_head": "base-head",
                "idempotency_key": "phase2-thin-guard-lease",
            },
            request_id=2260,
        )
    )["lease"]

    calls: list[dict] = []

    async def fake_request(
        client_id_arg: str,
        *,
        tool: str,
        arguments: dict,
        timeout_seconds: int,
    ) -> dict:
        calls.append(
            {
                "client_id": client_id_arg,
                "tool": tool,
                "arguments": arguments,
                "timeout_seconds": timeout_seconds,
            }
        )
        if tool == "git_state":
            return {
                "ok": True,
                "result": {
                    "toplevel": ".worktrees/thin-guard",
                    "branch_name": "agent/phase2/thin-guard",
                    "head": "base-head",
                    "base_commit": "base-head",
                    "base_is_ancestor": True,
                },
            }
        if tool == "file_state":
            return {
                "ok": True,
                "result": {
                    "path": ".worktrees/thin-guard/src/guarded.py",
                    "exists": True,
                    "kind": "file",
                    "size": 3,
                    "sha256": "1" * 64,
                },
            }
        assert tool == "write_file"
        return {
            "ok": True,
            "result": {
                "path": ".worktrees/thin-guard/src/guarded.py",
                "operation": "write",
                "bytes": 4,
                "bytes_before": 3,
                "bytes_after": 4,
                "encoding": "utf-8",
                "replacements": 0,
                "content": None,
                "before_sha256": "1" * 64,
                "after_sha256": "2" * 64,
                "diff": {
                    "format": "unified",
                    "suppressed": True,
                    "reason": "test",
                    "truncated": False,
                    "added_lines": 0,
                    "removed_lines": 0,
                    "hunks": [],
                },
            },
        }

    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setattr(get_settings(), "gateway_agent_allow_unverified_git_context", False)
    monkeypatch.setattr(mcp_router.thin_client_manager, "request", fake_request)
    structured = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "thin_client_write_file",
            {
                "client_id": thin_client_id,
                "path": ".worktrees/thin-guard/src/guarded.py",
                "operation": "write",
                "content": "next",
                "room_id": room["id"],
                "agent_id": writer["id"],
                "lease_id": lease["id"],
                "fencing_token": lease["fencing_token"],
                "expected_sha256": "1" * 64,
                "base_commit": lease["base_commit"],
                "branch_name": lease["branch_name"],
                "worktree_path": lease["worktree_path"],
            },
            request_id=2261,
        )
    )
    assert structured["before_sha256"] == "1" * 64
    assert structured["after_sha256"] == "2" * 64
    assert [call["tool"] for call in calls] == ["git_state", "file_state", "write_file"]
    remote_arguments = calls[-1]["arguments"]
    assert remote_arguments["expected_sha256"] == "1" * 64
    assert "lease_id" not in remote_arguments
    assert "fencing_token" not in remote_arguments
    assert "branch_name" not in remote_arguments


def test_phase_three_domain_audit_and_outbox_are_atomic(client: TestClient) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import AuditEvent, CollaborationRoom, OutboxEvent

    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": "Phase 3 atomic room",
                "idempotency_key": "phase3-atomic-room",
            },
            request_id=3000,
        )
    )["room"]
    with SessionLocal() as db:
        assert db.get(CollaborationRoom, room["id"]) is not None
        audit = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.event_type == "gateway.collaboration.room.created.v1",
                AuditEvent.resource_id == room["id"],
            )
            .one()
        )
        outbox = db.query(OutboxEvent).filter(OutboxEvent.audit_event_id == audit.id).one()
        assert outbox.status == "pending"
        assert outbox.payload["event_id"] == audit.id
        assert outbox.payload["room_id"] == room["id"]
        assert "payload" not in outbox.payload
        assert outbox.headers["X-Gateway-Event-Type"] == "gateway.collaboration.room.created.v1"
        assert outbox.headers["Nats-Msg-Id"] == audit.id


def test_phase_three_domain_rolls_back_when_event_envelope_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway_api import agent_collaboration
    from gateway_api.database import SessionLocal
    from gateway_api.models import AgentInstance

    def fail_event(*args, **kwargs):
        raise RuntimeError("outbox-envelope-failed")

    monkeypatch.setattr(agent_collaboration, "emit_event", fail_event)
    with SessionLocal() as db:
        with pytest.raises(RuntimeError, match="outbox-envelope-failed"):
            agent_collaboration.agent_collaboration_service.register_agent(
                db,
                owner_subject="dev:local",
                data={
                    "logical_agent_id": "phase3-rollback-agent",
                    "instance_id": "phase3-rollback-instance",
                },
            )
        db.rollback()
    with SessionLocal() as db:
        assert (
            db.query(AgentInstance)
            .filter(AgentInstance.instance_id == "phase3-rollback-instance")
            .count()
            == 0
        )


def test_phase_three_outbox_publish_ack_and_deduplication(client: TestClient) -> None:
    from gateway_api.broker import InMemoryBroker
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.events import emit_event
    from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent
    from gateway_api.outbox import OutboxService

    with SessionLocal() as db:
        audit = emit_event(
            db,
            event_type="gateway.phase3.publish.v1",
            actor_subject="dev:local",
            action="publish",
            resource_type="phase3_test",
            resource_id="publish-1",
            payload={"value": 1},
        )
        outbox_id = db.query(OutboxEvent.id).filter(OutboxEvent.audit_event_id == audit.id).scalar()

    settings = get_settings().model_copy(
        update={"gateway_broker_backend": "memory", "gateway_nats_stream": "PHASE3"}
    )
    broker = InMemoryBroker(stream="PHASE3")
    asyncio.run(broker.connect())
    service = OutboxService(
        session_factory=SessionLocal,
        broker=broker,
        settings=settings,
        replica_id="phase3-publisher-a",
    )
    result = asyncio.run(service.run_once(limit=10))
    assert result.published >= 1
    with SessionLocal() as db:
        event = db.get(OutboxEvent, outbox_id)
        assert event is not None
        assert event.status == "published"
        assert event.broker_stream == "PHASE3"
        assert event.broker_sequence is not None
        attempt = (
            db.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id == outbox_id)
            .one()
        )
        assert attempt.status == "published"
    published_ids = [item["message_id"] for item in broker.published]
    assert len(published_ids) == len(set(published_ids))


def test_phase_three_outbox_retry_dead_letter_and_replay(client: TestClient) -> None:
    from gateway_api.broker import BrokerPublishAck
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.events import emit_event
    from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent, utcnow
    from gateway_api.outbox import OutboxService

    class FailingBroker:
        healthy = False

        async def connect(self):
            return None

        async def close(self):
            return None

        async def subscribe(self, subject, callback):
            return None

        async def publish(self, subject, payload, *, message_id, headers) -> BrokerPublishAck:
            raise RuntimeError("broker-unavailable")

    with SessionLocal() as db:
        audit = emit_event(
            db,
            event_type="gateway.phase3.failure.v1",
            actor_subject="dev:local",
            action="fail",
            resource_type="phase3_test",
            resource_id="failure-1",
            payload={"value": 2},
        )
        event = db.query(OutboxEvent).filter(OutboxEvent.audit_event_id == audit.id).one()
        event.max_attempts = 2
        db.commit()
        event_id = event.id

    settings = get_settings().model_copy(
        update={
            "gateway_broker_backend": "memory",
            "gateway_outbox_retry_base_seconds": 0.01,
            "gateway_outbox_retry_max_seconds": 0.01,
        }
    )
    service = OutboxService(
        session_factory=SessionLocal,
        broker=FailingBroker(),
        settings=settings,
        replica_id="phase3-publisher-failing",
    )
    first = asyncio.run(service.run_once(limit=1))
    assert first.retried == 1
    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event is not None and event.status == "retry"
        event.available_at = utcnow()
        db.commit()
    second = asyncio.run(service.run_once(limit=1))
    assert second.dead_lettered == 1
    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event is not None and event.status == "dead_letter"
        assert event.attempt_count == 2
        assert "broker-unavailable" in str(event.last_error)
        assert (
            db.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id == event_id)
            .count()
            == 2
        )
        replayed = service.replay(db, event_id=event_id)
        assert replayed.status == "pending"
        assert replayed.replay_count == 1
        assert replayed.available_at is not None


def test_phase_three_stale_claim_release_and_processed_dedupe(client: TestClient) -> None:
    from gateway_api.broker import InMemoryBroker
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.events import emit_event
    from gateway_api.models import OutboxEvent, utcnow
    from gateway_api.outbox import OutboxService

    settings = get_settings().model_copy(
        update={"gateway_broker_backend": "memory", "gateway_outbox_lock_ttl_seconds": 1}
    )
    service = OutboxService(
        session_factory=SessionLocal,
        broker=InMemoryBroker(),
        settings=settings,
        replica_id="phase3-claim-recovery",
    )
    with SessionLocal() as db:
        audit = emit_event(
            db,
            event_type="gateway.phase3.claim.v1",
            actor_subject="dev:local",
            action="claim",
            resource_type="phase3_test",
            resource_id="claim-1",
            payload={},
        )
        event = db.query(OutboxEvent).filter(OutboxEvent.audit_event_id == audit.id).one()
        event.status = "processing"
        event.locked_by = "dead-replica"
        event.locked_at = utcnow() - timedelta(seconds=10)
        db.commit()
        assert service.release_stale_claims(db) == 1
        db.refresh(event)
        assert event.status == "retry"
        assert event.locked_by is None
        assert service.mark_processed(
            db,
            message_id="phase3-message-1",
            subject="gateway.events.test",
            payload=b"payload",
            stream="PHASE3",
            consumer="phase3-consumer",
        )
        assert not service.mark_processed(
            db,
            message_id="phase3-message-1",
            subject="gateway.events.test",
            payload=b"payload",
            stream="PHASE3",
            consumer="phase3-consumer",
        )


def test_phase_three_multi_replica_realtime_routing_and_dedupe(client: TestClient) -> None:
    from gateway_api.broker import InMemoryBroker
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.models import ProcessedBrokerMessage, RealtimeNotification
    from gateway_api.realtime import RealtimeService

    room, _, recipient_a, recipient_b = _phase_two_room_agents(client, suffix="phase3-routing")
    settings = get_settings().model_copy(
        update={"gateway_broker_backend": "memory", "gateway_nats_stream": "PHASE3"}
    )
    broker = InMemoryBroker(stream="PHASE3")
    asyncio.run(broker.connect())
    service_a = RealtimeService(
        session_factory=SessionLocal,
        broker=broker,
        settings=settings,
        replica_id="replica-a",
    )
    service_b = RealtimeService(
        session_factory=SessionLocal,
        broker=broker,
        settings=settings,
        replica_id="replica-b",
    )

    class FakeSocket:
        def __init__(self):
            self.messages = []

        async def send_json(self, payload):
            self.messages.append(payload)

    socket_a = FakeSocket()
    socket_b = FakeSocket()

    async def scenario():
        await service_a.start()
        await service_b.start()
        await service_a.hub.register(
            owner_subject="dev:local",
            target_kind="agent",
            target_id=recipient_a["id"],
            connection_id="conn-a",
            websocket=socket_a,
        )
        await service_b.hub.register(
            owner_subject="dev:local",
            target_kind="agent",
            target_id=recipient_b["id"],
            connection_id="conn-b",
            websocket=socket_b,
        )
        with SessionLocal() as db:
            service_a.register_route(
                db,
                owner_subject="dev:local",
                target_kind="agent",
                target_id=recipient_a["id"],
                connection_id="conn-a",
            )
            service_b.register_route(
                db,
                owner_subject="dev:local",
                target_kind="agent",
                target_id=recipient_b["id"],
                connection_id="conn-b",
            )
        envelope = {
            "event_id": "phase3-route-event",
            "occurred_at": "2026-07-19T13:00:00+00:00",
            "room_id": room["id"],
            "recipient_agent_ids": [recipient_a["id"], recipient_b["id"]],
        }
        payload = json.dumps(envelope).encode()
        await broker.publish(
            "gateway.events.gateway.agent.message.sent.v1",
            payload,
            message_id="phase3-route-event",
            headers={
                "Nats-Msg-Id": "phase3-route-event",
                "X-Gateway-Event-Type": "gateway.agent.message.sent.v1",
                "X-Gateway-Actor-Subject": "dev:local",
            },
        )
        await broker.publish(
            "gateway.events.gateway.agent.message.sent.v1",
            payload,
            message_id="phase3-route-event",
            headers={
                "Nats-Msg-Id": "phase3-route-event",
                "X-Gateway-Event-Type": "gateway.agent.message.sent.v1",
                "X-Gateway-Actor-Subject": "dev:local",
            },
        )
        await service_a.stop()
        await service_b.stop()

    asyncio.run(scenario())
    assert len(socket_a.messages) == 1
    assert len(socket_b.messages) == 1
    with SessionLocal() as db:
        assert (
            db.query(RealtimeNotification)
            .filter(RealtimeNotification.event_type == "gateway.agent.message.sent.v1")
            .count()
            == 2
        )
        assert (
            db.query(ProcessedBrokerMessage)
            .filter(ProcessedBrokerMessage.message_id.like("replica-%:phase3-route-event"))
            .count()
            == 2
        )


def test_phase_three_operations_metrics_and_realtime_websocket(client: TestClient) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import RealtimeRoute

    _, agent, _, _ = _phase_two_room_agents(client, suffix="phase3-websocket")
    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["broker_backend"] == "disabled"

    operations = client.get("/api/operations/metrics")
    assert operations.status_code == 200
    assert "pending_total" in operations.json()
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "gateway_outbox_events" in metrics.text
    assert "gateway_runtime_info" in metrics.text

    with client.websocket_connect(f"/api/agent-realtime/ws/{agent['id']}") as websocket:
        connected = websocket.receive_json()
        assert connected["type"] == "connected"
        connection_id = connected["connection_id"]
        websocket.send_json({"type": "heartbeat"})
        assert websocket.receive_json() == {"type": "heartbeat_ack"}
        with SessionLocal() as db:
            route = (
                db.query(RealtimeRoute)
                .filter(RealtimeRoute.connection_id == connection_id)
                .one()
            )
            assert route.status == "online"
    with SessionLocal() as db:
        route = db.query(RealtimeRoute).filter(RealtimeRoute.connection_id == connection_id).one()
        assert route.status == "offline"


def test_phase_three_openapi_asyncapi_schema_and_persistence_contracts(
    client: TestClient,
) -> None:
    from sqlalchemy import inspect
    import yaml

    from gateway_api.database import SessionLocal
    from gateway_api.models import OutboxEvent

    root = Path(__file__).resolve().parents[3]
    static_openapi = yaml.safe_load(
        (root / "openapi" / "gateway.openapi.yaml").read_text(encoding="utf-8")
    )
    events_asyncapi = yaml.safe_load(
        (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    realtime_asyncapi = yaml.safe_load(
        (root / "asyncapi" / "gateway-realtime.asyncapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    notification_schema = json.loads(
        (root / "schemas" / "gateway.realtime.notification.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    dynamic_paths = client.get("/openapi.json").json()["paths"]
    required_paths = {
        "/api/operations/outbox",
        "/api/operations/outbox/{event_id}",
        "/api/operations/outbox/{event_id}/attempts",
        "/api/operations/outbox/{event_id}/replay",
        "/api/operations/outbox/{event_id}/cancel",
        "/api/operations/outbox/drain",
        "/api/operations/metrics",
        "/api/operations/replicas",
        "/api/operations/realtime-routes",
        "/api/agent-realtime/notifications",
        "/api/agent-realtime/notifications/{notification_id}/ack",
        "/metrics",
    }
    assert required_paths.issubset(dynamic_paths)
    assert required_paths.issubset(static_openapi["paths"])
    assert events_asyncapi["info"]["version"] == "0.3.0"
    assert events_asyncapi["servers"]["jetstream"]["protocol"] == "nats"
    realtime_channel = realtime_asyncapi["channels"][
        "/api/agent-realtime/ws/{agent_id}"
    ]
    assert realtime_channel["subscribe"]["operationId"] == (
        "receiveAgentRealtimeNotifications"
    )
    assert realtime_channel["publish"]["operationId"] == "sendAgentRealtimeControl"
    assert notification_schema["$id"] == "gateway.realtime.notification.v1"
    assert notification_schema["additionalProperties"] is False
    assert set(notification_schema["required"]) == {
        "type",
        "notification_id",
        "event_type",
        "payload",
    }

    with SessionLocal() as db:
        tables = set(inspect(db.bind).get_table_names())
    assert {
        "outbox_events",
        "outbox_delivery_attempts",
        "processed_broker_messages",
        "gateway_replicas",
        "realtime_routes",
        "realtime_notifications",
    }.issubset(tables)

    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": "Phase 3 wire contract",
                "idempotency_key": "phase3-wire-contract-room",
            },
            request_id=3010,
        )
    )["room"]
    with SessionLocal() as db:
        event = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.event_type
                == "gateway.collaboration.room.created.v1",
                OutboxEvent.payload["room_id"].as_string() == room["id"],
            )
            .one()
        )
        schema = json.loads(
            (
                root
                / "schemas"
                / "gateway.collaboration.room.created.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        payload_keys = set(event.payload)
        assert set(schema["required"]).issubset(payload_keys)
        assert payload_keys.issubset(schema["properties"])
        assert event.subject == (
            "gateway.events.gateway.collaboration.room.created.v1"
        )
        assert event.headers["Nats-Msg-Id"] == event.audit_event_id
        assert event.headers["X-Gateway-Event-Type"] == event.event_type


def test_phase_three_claim_token_fences_stale_publisher_completion(
    client: TestClient,
) -> None:
    from gateway_api.broker import BrokerPublishAck, InMemoryBroker
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.events import emit_event
    from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent, utcnow
    from gateway_api.outbox import OutboxService

    with SessionLocal() as db:
        audit = emit_event(
            db,
            event_type="gateway.phase3.claim_fence.v1",
            actor_subject="dev:local",
            action="claim",
            resource_type="phase3_test",
            resource_id="claim-fence-1",
            payload={"value": 1},
        )
        event = (
            db.query(OutboxEvent)
            .filter(OutboxEvent.audit_event_id == audit.id)
            .one()
        )
        event.status = "processing"
        event.locked_by = "publisher-a"
        event.lock_token = "claim-token-a"
        event.locked_at = utcnow()
        db.commit()
        event_id = event.id

    settings = get_settings().model_copy(update={"gateway_broker_backend": "memory"})
    service = OutboxService(
        session_factory=SessionLocal,
        broker=InMemoryBroker(),
        settings=settings,
        replica_id="publisher-a",
    )

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event is not None
        event.locked_by = "publisher-b"
        event.lock_token = "claim-token-b"
        event.locked_at = utcnow()
        db.commit()

    with SessionLocal() as db:
        accepted = service._record_success(
            db,
            event_id=event_id,
            lock_token="claim-token-a",
            ack=BrokerPublishAck(stream="PHASE3", sequence=10),
        )
        assert accepted is False
        assert (
            service._record_failure(
                db,
                event_id=event_id,
                lock_token="claim-token-a",
                error=RuntimeError("late failure"),
            )
            == "stale"
        )

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.status == "processing"
        assert event.locked_by == "publisher-b"
        assert event.lock_token == "claim-token-b"
        assert event.attempt_count == 0
        assert (
            db.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id == event_id)
            .count()
            == 0
        )


def test_phase_three_replay_uses_new_delivery_id_and_preserves_business_event(
    client: TestClient,
) -> None:
    from gateway_api.broker import InMemoryBroker
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.events import emit_event
    from gateway_api.models import OutboxEvent
    from gateway_api.outbox import OutboxService

    with SessionLocal() as db:
        audit = emit_event(
            db,
            event_type="gateway.phase3.replay_delivery.v1",
            actor_subject="dev:local",
            action="replay",
            resource_type="phase3_test",
            resource_id="replay-delivery-1",
            payload={"value": 7},
        )
        event = (
            db.query(OutboxEvent)
            .filter(OutboxEvent.audit_event_id == audit.id)
            .one()
        )
        original_payload = dict(event.payload)
        original_delivery_id = event.headers["Nats-Msg-Id"]
        event.status = "dead_letter"
        event.attempt_count = 1
        db.commit()
        event_id = event.id

    settings = get_settings().model_copy(
        update={"gateway_broker_backend": "memory", "gateway_nats_stream": "PHASE3"}
    )
    broker = InMemoryBroker(stream="PHASE3")
    asyncio.run(broker.connect())
    service = OutboxService(
        session_factory=SessionLocal,
        broker=broker,
        settings=settings,
        replica_id="phase3-replay-publisher",
    )
    with SessionLocal() as db:
        replayed = service.replay(
            db,
            event_id=event_id,
            actor_subject="dev:local",
            reason="test replay delivery id",
        )
        replay_delivery_id = replayed.headers["Nats-Msg-Id"]
        assert replayed.payload == original_payload
        assert replayed.payload["event_id"] == audit.id
        assert replay_delivery_id != original_delivery_id
        assert replay_delivery_id == f"{audit.id}:replay:1"
        assert replayed.headers["X-Gateway-Event-Id"] == audit.id

    result = asyncio.run(service.run_once(limit=1000))
    assert result.published >= 1
    published = [
        item for item in broker.published if item["message_id"] == replay_delivery_id
    ]
    assert len(published) == 1
    assert json.loads(published[0]["payload"])["event_id"] == audit.id


def test_phase_three_broker_outage_starts_not_ready_and_keeps_runtime_alive(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway_api import runtime as runtime_module
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal
    from gateway_api.models import GatewayReplica

    class UnavailableBroker:
        def __init__(self) -> None:
            self.connect_attempts = 0
            self.close_attempts = 0

        @property
        def healthy(self) -> bool:
            return False

        async def connect(self) -> None:
            self.connect_attempts += 1
            raise RuntimeError("nats unavailable")

        async def close(self) -> None:
            self.close_attempts += 1

        async def publish(self, *args, **kwargs):
            raise RuntimeError("nats unavailable")

        async def subscribe(self, *args, **kwargs):
            raise RuntimeError("nats unavailable")

        async def subscribe_durable(self, *args, **kwargs):
            raise RuntimeError("nats unavailable")

    broker = UnavailableBroker()
    monkeypatch.setattr(runtime_module, "create_broker", lambda settings, replica_id: broker)
    settings = get_settings().model_copy(
        update={
            "gateway_broker_backend": "nats",
            "gateway_outbox_enabled": True,
            "gateway_outbox_poll_interval_seconds": 0.01,
            "gateway_replica_heartbeat_seconds": 60,
            "gateway_replica_id": "phase3-outage-replica",
        }
    )
    runtime = runtime_module.GatewayRuntime(
        settings=settings,
        session_factory=SessionLocal,
    )

    async def scenario() -> None:
        await runtime.start()
        assert runtime.started is True
        assert runtime.readiness()["status"] == "not_ready"
        await asyncio.sleep(0.05)
        assert broker.connect_attempts >= 1
        await runtime.stop()

    asyncio.run(scenario())
    with SessionLocal() as db:
        replica = db.get(GatewayReplica, "phase3-outage-replica")
        assert replica is not None
        assert replica.status == "offline"


def _phase_four_room_agents(
    client: TestClient, *, suffix: str
) -> tuple[dict, dict, dict, dict]:
    room = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_room",
            {
                "title": f"Phase 4 {suffix}",
                "repository_identity": "products/chatgpt-mcp-ssh-gateway",
                "base_commit": "phase4-base",
                "policy": {},
                "idempotency_key": f"phase4-room-{suffix}",
            },
            request_id=4000,
        )
    )["room"]

    def register(
        name: str,
        capabilities: list[str],
        labels: dict[str, str] | None = None,
    ) -> dict:
        return _phase_one_result(
            _phase_one_mcp_call(
                client,
                "agent_register",
                {
                    "logical_agent_id": name,
                    "instance_id": f"phase4-{suffix}-{name}",
                    "display_name": name,
                    "capabilities": capabilities,
                    "labels": labels or {},
                    "room_id": room["id"],
                },
                request_id=4001,
            )
        )["agent"]

    return (
        room,
        register("coordinator", ["coordination:integrate", "recovery:coordinate"]),
        register("python-worker", ["python", "tests"], {"zone": "core"}),
        register("general-worker", [], {"zone": "general"}),
    )


def _phase_four_policy(
    client: TestClient,
    *,
    room_id: str,
    suffix: str,
    coordinator_agent_id: str | None = None,
    assignment_mode: str = "manual",
    allowed_action_classes: list[str] | None = None,
    approval_rules: dict | None = None,
) -> dict:
    return _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_create_policy",
            {
                "room_id": room_id,
                "name": f"Phase 4 policy {suffix}",
                "assignment_mode": assignment_mode,
                "coordinator_agent_id": coordinator_agent_id,
                "allowed_action_classes": allowed_action_classes or ["read"],
                "allowed_tools": ["thin_client_run_command"],
                "allowed_command_profiles": ["gateway-api-tests"],
                "max_parallel_assignments": 2,
                "approval_rules": approval_rules or {},
                "recovery_policy": {
                    "max_attempts": 3,
                    "base_backoff_seconds": 1,
                    "max_backoff_seconds": 8,
                },
                "idempotency_key": f"phase4-policy-{suffix}",
            },
            request_id=4002,
        )
    )["policy"]


def test_phase_four_contracts_tables_and_disabled_worker_registration(
    client: TestClient,
) -> None:
    from sqlalchemy import inspect

    from gateway_api.database import SessionLocal

    tools_response = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 4010, "method": "tools/list"}
    )
    assert tools_response.status_code == 200
    tools = {tool["name"]: tool for tool in tools_response.json()["result"]["tools"]}
    expected_tools = {
        "agent_autonomy_create_policy",
        "agent_autonomy_list_policies",
        "agent_autonomy_run_assignment_cycle",
        "agent_autonomy_list_assignments",
        "agent_autonomy_apply_assignment",
        "agent_autonomy_request_approval",
        "agent_autonomy_list_approvals",
        "agent_autonomy_vote",
        "agent_autonomy_issue_permit",
        "agent_autonomy_claim_permit",
        "agent_autonomy_record_receipt",
        "agent_autonomy_create_recovery",
        "agent_autonomy_list_recoveries",
        "agent_autonomy_run_recovery_cycle",
        "agent_autonomy_record_recovery_outcome",
        "agent_autonomy_control",
        "agent_autonomy_override",
        "agent_autonomy_metrics",
    }
    assert expected_tools.issubset(tools)
    assert tools["agent_autonomy_control"]["annotations"]["destructiveHint"] is True
    assert tools["agent_autonomy_issue_permit"]["annotations"]["readOnlyHint"] is False
    work_item_schema = tools["agent_create_work_item"]["inputSchema"]["properties"]
    assert "required_capabilities" in work_item_schema
    assert "assignment_constraints" in work_item_schema

    openapi = client.get("/openapi.json").json()
    expected_paths = {
        "/api/agent-autonomy/policies",
        "/api/agent-autonomy/policies/{policy_id}",
        "/api/agent-autonomy/policies/{policy_id}/assignment-cycle",
        "/api/agent-autonomy/policies/{policy_id}/recovery-cycle",
        "/api/agent-autonomy/assignments",
        "/api/agent-autonomy/assignments/{assignment_id}/apply",
        "/api/agent-autonomy/controls",
        "/api/agent-autonomy/overrides",
        "/api/agent-autonomy/approvals",
        "/api/agent-autonomy/approvals/{request_id}/votes",
        "/api/agent-autonomy/approvals/{request_id}/permit",
        "/api/agent-autonomy/permits",
        "/api/agent-autonomy/permits/{permit_id}/claim",
        "/api/agent-autonomy/receipts",
        "/api/agent-autonomy/recoveries",
        "/api/agent-autonomy/recoveries/{loop_id}/outcome",
        "/api/agent-autonomy/metrics",
    }
    assert expected_paths.issubset(openapi["paths"])

    with SessionLocal() as db:
        tables = set(inspect(db.bind).get_table_names())
        columns = {
            column["name"] for column in inspect(db.bind).get_columns("agent_work_items")
        }
    assert {
        "autonomy_policies",
        "autonomy_control_states",
        "autonomy_overrides",
        "autonomy_assignments",
        "approval_requests",
        "approval_votes",
        "execution_permits",
        "action_receipts",
        "recovery_loops",
    }.issubset(tables)
    assert {"required_capabilities", "assignment_constraints"}.issubset(columns)

    readiness = client.get("/ready")
    assert readiness.status_code == 200
    assert readiness.json()["autonomy_enabled"] is False
    assert readiness.json()["autonomy_emergency_stop"] is False


def test_phase_four_automatic_assignment_respects_dependencies_capabilities_and_labels(
    client: TestClient,
) -> None:
    room, coordinator, python_worker, general_worker = _phase_four_room_agents(
        client, suffix="assignment"
    )
    heartbeat = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_heartbeat",
            {"agent_id": general_worker["id"], "status": "idle"},
            request_id=4020,
        )
    )["agent"]
    assert heartbeat["status"] == "idle"

    dependency = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Prepare inputs",
                "priority": 10,
                "idempotency_key": "idem5",
            },
            request_id=4021,
        )
    )["work_item"]
    target = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Run Python verification",
                "priority": 100,
                "dependencies": [dependency["id"]],
                "required_capabilities": ["python", "tests"],
                "assignment_constraints": {"labels": {"zone": "core"}},
                "idempotency_key": "phase4-assignment-target",
            },
            request_id=4022,
        )
    )["work_item"]
    assert target["required_capabilities"] == ["python", "tests"]
    assert target["assignment_constraints"] == {"labels": {"zone": "core"}}

    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="assignment",
        coordinator_agent_id=coordinator["id"],
        assignment_mode="automatic",
    )
    first_cycle = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_run_assignment_cycle",
            {"policy_id": policy["id"], "limit": 2},
            request_id=4023,
        )
    )["cycle"]
    assert first_cycle["assigned"] == 1
    assert first_cycle["skipped"] >= 1

    work_items = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_list_work_items",
            {"room_id": room["id"]},
            request_id=4024,
        )
    )["work_items"]
    by_id = {item["id"]: item for item in work_items}
    assert by_id[dependency["id"]]["assigned_agent_id"] == general_worker["id"]
    assert by_id[dependency["id"]]["status"] == "in_progress"
    assert by_id[target["id"]]["status"] == "open"
    assert by_id[target["id"]]["assigned_agent_id"] is None

    completed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_update_work_item",
            {
                "agent_id": general_worker["id"],
                "work_item_id": dependency["id"],
                "expected_version": 2,
                "status": "completed",
                "result": {"prepared": True},
            },
            request_id=4025,
        )
    )["work_item"]
    assert completed["status"] == "completed"

    second_cycle = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_run_assignment_cycle",
            {"policy_id": policy["id"], "limit": 2},
            request_id=4026,
        )
    )["cycle"]
    assert second_cycle["assigned"] == 1
    assignments = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_list_assignments",
            {"policy_id": policy["id"]},
            request_id=4027,
        )
    )["assignments"]
    target_assignment = next(
        item for item in assignments if item["work_item_id"] == target["id"]
    )
    assert target_assignment["selected_agent_id"] == python_worker["id"]
    assert target_assignment["status"] == "assigned"
    assert target_assignment["rationale"]["required_labels"] == {"zone": "core"}


def test_phase_four_independent_quorum_permit_receipt_and_completion_gate(
    client: TestClient,
) -> None:
    from gateway_api.agent_autonomy import agent_autonomy_service
    from gateway_api.database import SessionLocal
    from gateway_api.models import AccessGrant, ApprovalRequest, User, utcnow

    room, coordinator, executor, _ = _phase_four_room_agents(
        client, suffix="approval"
    )
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="approval",
        coordinator_agent_id=coordinator["id"],
        allowed_action_classes=["production"],
        approval_rules={
            "production": {
                "quorum": 2,
                "require_admin": True,
                "disallow_proposer": True,
            }
        },
    )
    command = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_issue_command",
            {
                "room_id": room["id"],
                "issuer_agent_id": coordinator["id"],
                "target_agent_id": executor["id"],
                "kind": "run_tool",
                "instruction": "Run the reviewed gateway test profile.",
                "structured_payload": {
                    "tool": "thin_client_run_command",
                    "arguments": {
                        "command_profile": "gateway-api-tests",
                        "cwd": ".",
                    },
                },
                "requires_approval": True,
                "idempotency_key": "phase4-production-command",
            },
            request_id=4030,
        )
    )["command"]
    approval = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_request_approval",
            {
                "policy_id": policy["id"],
                "command_id": command["id"],
                "executor_agent_id": executor["id"],
                "action_class": "production",
                "action_kind": "run_tool",
                "idempotency_key": "phase4-production-approval",
            },
            request_id=4031,
        )
    )["approval"]
    assert approval["status"] == "pending"
    assert approval["quorum_required"] == 2
    assert approval["require_admin_approval"] is True

    with SessionLocal() as db:
        reviewer = User(
            subject="reviewer:phase4",
            username="phase4-reviewer",
            roles=["gateway-user"],
            provider="test",
            created_at=utcnow(),
            last_seen_at=utcnow(),
        )
        admin = User(
            subject="admin:phase4",
            username="phase4-admin",
            roles=["gateway-admin"],
            provider="test",
            created_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.add_all([reviewer, admin])
        db.flush()
        proposer = User(
            subject="dev:local",
            username="darius",
            roles=["gateway-admin", "gateway-user", "gateway-auditor"],
            provider="dev",
            created_at=utcnow(),
            last_seen_at=utcnow(),
        )
        with pytest.raises(HTTPException) as proposer_error:
            agent_autonomy_service.cast_vote(
                db,
                request_id=approval["id"],
                user=proposer,
                decision="approve",
                reason="Self approval must be rejected",
            )
        assert proposer_error.value.status_code == 403
        db.add(
            AccessGrant(
                id=str(uuid.uuid4()),
                owner_subject="dev:local",
                grantee_subject=reviewer.subject,
                resource_type="autonomy_approval",
                resource_id=approval["id"],
                scopes=["approve"],
                status="active",
            )
        )
        db.commit()
        request = agent_autonomy_service.cast_vote(
            db,
            request_id=approval["id"],
            user=reviewer,
            decision="approve",
            reason="Independent technical review passed",
        )
        assert request.status == "pending"
        request = agent_autonomy_service.cast_vote(
            db,
            request_id=approval["id"],
            user=admin,
            decision="approve",
            reason="Production approval granted",
        )
        assert request.status == "approved"
        stored = db.get(ApprovalRequest, approval["id"])
        assert stored is not None and stored.approved_at is not None

    delivered = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_list_commands",
            {"agent_id": executor["id"]},
            request_id=4032,
        )
    )["commands"]
    assert delivered[0]["id"] == command["id"]
    _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_ack_command",
            {"agent_id": executor["id"], "command_id": command["id"]},
            request_id=4033,
        )
    )
    accepted = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_accept_command",
            {"agent_id": executor["id"], "command_id": command["id"]},
            request_id=4034,
        )
    )["command"]
    assert accepted["status"] == "accepted"

    permit = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_issue_permit",
            {"request_id": approval["id"], "ttl_seconds": 300},
            request_id=4035,
        )
    )["permit"]
    claimed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_claim_permit",
            {"permit_id": permit["id"], "executor_agent_id": executor["id"]},
            request_id=4036,
        )
    )["permit"]
    assert claimed["status"] == "claimed"
    assert claimed["use_count"] == 1

    premature = _phase_one_mcp_call(
        client,
        "agent_complete_command",
        {
            "agent_id": executor["id"],
            "command_id": command["id"],
            "status": "completed",
            "result": {"outcome": "passed"},
        },
        request_id=4037,
    )
    assert premature["error"]["code"] == 409
    assert "action receipt" in premature["error"]["message"]

    now = utcnow()
    receipt = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_record_receipt",
            {
                "permit_id": permit["id"],
                "executor_agent_id": executor["id"],
                "fencing_token": permit["fencing_token"],
                "status": "succeeded",
                "result_summary": {"tests": 108, "outcome": "passed"},
                "external_references": [{"kind": "test_run", "id": "phase4-4038"}],
                "started_at": now.isoformat(),
                "completed_at": (now + timedelta(seconds=1)).isoformat(),
                "idempotency_key": "phase4-production-receipt",
            },
            request_id=4038,
        )
    )["receipt"]
    assert receipt["status"] == "succeeded"
    assert receipt["input_hash"] == approval["payload_hash"]

    completed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_complete_command",
            {
                "agent_id": executor["id"],
                "command_id": command["id"],
                "status": "completed",
                "result": {"outcome": "passed"},
            },
            request_id=4039,
        )
    )["command"]
    assert completed["status"] == "completed"
    permits = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_metrics",
            {},
            request_id=4040,
        )
    )["metrics"]
    assert permits["permits"]["consumed"] == 1
    assert permits["receipts_total"] == 1


def test_phase_four_payload_tamper_kill_switch_and_tenant_secret_boundaries(
    client: TestClient,
) -> None:
    from gateway_api.auth import create_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import AgentCommand

    room, coordinator, executor, _ = _phase_four_room_agents(client, suffix="tamper")
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="tamper",
        coordinator_agent_id=coordinator["id"],
        allowed_action_classes=["read"],
        approval_rules={
            "read": {
                "quorum": 0,
                "require_admin": False,
                "disallow_proposer": False,
            }
        },
    )
    command = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_issue_command",
            {
                "room_id": room["id"],
                "issuer_agent_id": coordinator["id"],
                "target_agent_id": executor["id"],
                "kind": "run_tool",
                "instruction": "Run reviewed read-only diagnostics.",
                "structured_payload": {
                    "tool": "thin_client_run_command",
                    "arguments": {
                        "command_profile": "gateway-api-tests",
                        "cwd": ".",
                    },
                },
                "requires_approval": True,
                "idempotency_key": "phase4-tamper-command",
            },
            request_id=4050,
        )
    )["command"]
    approval = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_request_approval",
            {
                "policy_id": policy["id"],
                "command_id": command["id"],
                "executor_agent_id": executor["id"],
                "action_class": "read",
                "idempotency_key": "phase4-tamper-approval",
            },
            request_id=4051,
        )
    )["approval"]
    assert approval["status"] == "approved"

    with SessionLocal() as db:
        stored = db.get(AgentCommand, command["id"])
        assert stored is not None
        payload = dict(stored.structured_payload or {})
        payload["arguments"] = {
            "command_profile": "gateway-api-tests",
            "cwd": "changed-after-approval",
        }
        stored.structured_payload = payload
        db.commit()

    tampered = _phase_one_mcp_call(
        client,
        "agent_autonomy_issue_permit",
        {"request_id": approval["id"]},
        request_id=4052,
    )
    assert tampered["error"]["code"] == 409
    assert "payload changed" in tampered["error"]["message"]

    secret_policy = client.post(
        "/api/agent-autonomy/policies",
        json={
            "room_id": room["id"],
            "name": "Unsafe policy",
            "approval_rules": {"read": {"api_key": "must-not-persist"}},
        },
    )
    assert secret_policy.status_code == 400
    assert "secret-like" in secret_policy.json()["detail"].lower()

    killed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_control",
            {
                "scope_type": "room",
                "scope_id": room["id"],
                "state": "killed",
                "reason": "Operator emergency stop test",
            },
            request_id=4053,
        )
    )["control"]
    assert killed["state"] == "killed"
    blocked_cycle = _phase_one_mcp_call(
        client,
        "agent_autonomy_run_assignment_cycle",
        {"policy_id": policy["id"]},
        request_id=4054,
    )
    assert blocked_cycle["error"]["code"] == 423

    token = create_jwt(
        subject="tenant-phase4",
        username="tenant-phase4",
        roles=["gateway-user"],
        scopes=["workspace:read"],
        token_type="access",
        ttl_seconds=300,
    )
    other_headers = {"Authorization": f"Bearer {token}"}
    isolated = client.get("/api/agent-autonomy/policies", headers=other_headers)
    assert isolated.status_code == 200
    assert isolated.json() == []


def test_phase_four_bounded_recovery_never_exceeds_policy_attempt_limit(
    client: TestClient,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import RecoveryLoop, utcnow

    room, coordinator, executor, _ = _phase_four_room_agents(
        client, suffix="recovery"
    )
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="recovery",
        coordinator_agent_id=coordinator["id"],
    )
    source = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Recover transient operation",
                "idempotency_key": "phase4-recovery-source",
            },
            request_id=4060,
        )
    )["work_item"]
    loop = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_create_recovery",
            {
                "policy_id": policy["id"],
                "room_id": room["id"],
                "source_type": "work_item",
                "source_id": source["id"],
                "target_agent_id": executor["id"],
                "strategy": {
                    "kind": "instruction",
                    "instruction": "Inspect the failed operation and report recovery evidence.",
                    "priority": 80,
                },
                "max_attempts": 2,
                "base_backoff_seconds": 1,
                "idempotency_key": "phase4-recovery-loop",
            },
            request_id=4061,
        )
    )["recovery"]
    assert loop["max_attempts"] == 2

    first = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_run_recovery_cycle",
            {"policy_id": policy["id"], "limit": 10},
            request_id=4062,
        )
    )["cycle"]
    assert first["issued"] == 1
    current = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_list_recoveries",
            {"room_id": room["id"]},
            request_id=4063,
        )
    )["recoveries"][0]
    assert current["attempt_count"] == 1
    assert current["status"] == "waiting"

    failed_once = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_record_recovery_outcome",
            {
                "loop_id": loop["id"],
                "status": "failed",
                "command_id": current["last_command_id"],
                "error": "transient failure",
            },
            request_id=4064,
        )
    )["recovery"]
    assert failed_once["status"] == "planned"
    with SessionLocal() as db:
        stored = db.get(RecoveryLoop, loop["id"])
        assert stored is not None
        stored.next_attempt_at = utcnow() - timedelta(seconds=1)
        db.commit()

    second = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_run_recovery_cycle",
            {"policy_id": policy["id"], "limit": 10},
            request_id=4065,
        )
    )["cycle"]
    assert second["issued"] == 1
    current = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_list_recoveries",
            {"room_id": room["id"]},
            request_id=4066,
        )
    )["recoveries"][0]
    assert current["attempt_count"] == 2
    exhausted = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_record_recovery_outcome",
            {
                "loop_id": loop["id"],
                "status": "failed",
                "command_id": current["last_command_id"],
                "error": "persistent failure",
            },
            request_id=4067,
        )
    )["recovery"]
    assert exhausted["status"] == "exhausted"
    third = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_run_recovery_cycle",
            {"policy_id": policy["id"], "limit": 10},
            request_id=4068,
        )
    )["cycle"]
    assert third["issued"] == 0
    final = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_list_recoveries",
            {"room_id": room["id"]},
            request_id=4069,
        )
    )["recoveries"][0]
    assert final["attempt_count"] == 2
    assert final["status"] == "exhausted"


def test_phase_four_kill_revokes_active_permit_and_cancels_recovery(
    client: TestClient,
) -> None:
    room, coordinator, executor, _ = _phase_four_room_agents(client, suffix="kill-revoke")
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="kill-revoke",
        coordinator_agent_id=coordinator["id"],
        allowed_action_classes=["read"],
        approval_rules={
            "read": {
                "quorum": 0,
                "require_admin": False,
                "disallow_proposer": False,
            }
        },
    )
    command = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_issue_command",
            {
                "room_id": room["id"],
                "issuer_agent_id": coordinator["id"],
                "target_agent_id": executor["id"],
                "kind": "run_tool",
                "instruction": "Run reviewed diagnostics.",
                "structured_payload": {
                    "tool": "thin_client_run_command",
                    "arguments": {
                        "command_profile": "gateway-api-tests",
                        "cwd": ".",
                    },
                },
                "requires_approval": True,
                "idempotency_key": "phase4-kill-command",
            },
            request_id=4070,
        )
    )["command"]
    approval = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_request_approval",
            {
                "policy_id": policy["id"],
                "command_id": command["id"],
                "executor_agent_id": executor["id"],
                "action_class": "read",
                "idempotency_key": "idem6",
            },
            request_id=4071,
        )
    )["approval"]
    permit = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_issue_permit",
            {"request_id": approval["id"]},
            request_id=4072,
        )
    )["permit"]
    assert permit["status"] == "active"

    source = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Recovery source before kill",
                "idempotency_key": "phase4-kill-recovery-source",
            },
            request_id=4073,
        )
    )["work_item"]
    recovery = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_create_recovery",
            {
                "policy_id": policy["id"],
                "room_id": room["id"],
                "source_type": "work_item",
                "source_id": source["id"],
                "target_agent_id": executor["id"],
                "strategy": {
                    "kind": "instruction",
                    "instruction": "Inspect and report only.",
                },
                "max_attempts": 2,
                "idempotency_key": "phase4-kill-recovery",
            },
            request_id=4074,
        )
    )["recovery"]
    assert recovery["status"] == "planned"

    killed = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_control",
            {
                "scope_type": "room",
                "scope_id": room["id"],
                "state": "killed",
                "reason": "Stop all autonomous work in room",
            },
            request_id=4075,
        )
    )["control"]
    assert killed["state"] == "killed"

    permits = client.get("/api/agent-autonomy/permits").json()
    revoked = next(item for item in permits if item["id"] == permit["id"])
    assert revoked["status"] == "revoked"
    assert "autonomy killed" in revoked["revocation_reason"]
    recoveries = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_list_recoveries",
            {"room_id": room["id"]},
            request_id=4076,
        )
    )["recoveries"]
    cancelled = next(item for item in recoveries if item["id"] == recovery["id"])
    assert cancelled["status"] == "cancelled"
    assert cancelled["completed_at"] is not None

    duplicate_issue = _phase_one_mcp_call(
        client,
        "agent_autonomy_issue_permit",
        {"request_id": approval["id"]},
        request_id=4077,
    )
    assert duplicate_issue["error"]["code"] in {409, 423}

    overrides = client.get("/api/agent-autonomy/overrides").json()
    kill_override = next(item for item in overrides if item["action"] == "kill")
    assert kill_override["evidence"]["revoked_permits"] >= 1
    assert kill_override["evidence"]["affected_recoveries"] >= 1


def test_phase_four_policy_generation_change_revokes_permit_and_stales_approval(
    client: TestClient,
) -> None:
    room, coordinator, executor, _ = _phase_four_room_agents(
        client, suffix="generation"
    )
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="generation",
        coordinator_agent_id=coordinator["id"],
        allowed_action_classes=["read"],
        approval_rules={
            "read": {
                "quorum": 0,
                "require_admin": False,
                "disallow_proposer": False,
            }
        },
    )
    command = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_issue_command",
            {
                "room_id": room["id"],
                "issuer_agent_id": coordinator["id"],
                "target_agent_id": executor["id"],
                "kind": "run_tool",
                "instruction": "Run reviewed diagnostics.",
                "structured_payload": {
                    "tool": "thin_client_run_command",
                    "arguments": {
                        "command_profile": "gateway-api-tests",
                        "cwd": ".",
                    },
                },
                "requires_approval": True,
                "idempotency_key": "phase4-generation-command",
            },
            request_id=4080,
        )
    )["command"]
    approval = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_request_approval",
            {
                "policy_id": policy["id"],
                "command_id": command["id"],
                "executor_agent_id": executor["id"],
                "action_class": "read",
                "idempotency_key": "idem7",
            },
            request_id=4081,
        )
    )["approval"]
    permit = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_issue_permit",
            {"request_id": approval["id"]},
            request_id=4082,
        )
    )["permit"]

    updated = client.patch(
        f"/api/agent-autonomy/policies/{policy['id']}",
        json={
            "expected_version": policy["version"],
            "name": "Generation updated policy",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["generation"] == policy["generation"] + 1
    assert updated.json()["version"] == policy["version"] + 1

    permits = client.get("/api/agent-autonomy/permits").json()
    revoked = next(item for item in permits if item["id"] == permit["id"])
    assert revoked["status"] == "revoked"
    assert revoked["revocation_reason"] == "policy generation changed"

    stale = _phase_one_mcp_call(
        client,
        "agent_autonomy_issue_permit",
        {"request_id": approval["id"]},
        request_id=4083,
    )
    assert stale["error"]["code"] == 409


def test_phase_four_operator_force_assign_and_revoke_assignment_override(
    client: TestClient,
) -> None:
    room, coordinator, worker, _ = _phase_four_room_agents(client, suffix="override")
    heartbeat = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_heartbeat",
            {"agent_id": worker["id"], "status": "idle"},
            request_id=4090,
        )
    )["agent"]
    assert heartbeat["status"] == "idle"
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="override",
        coordinator_agent_id=coordinator["id"],
        assignment_mode="manual",
    )
    work_item = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_create_work_item",
            {
                "room_id": room["id"],
                "title": "Operator-selected work item",
                "required_capabilities": ["python"],
                "idempotency_key": "phase4-override-work-item",
            },
            request_id=4091,
        )
    )["work_item"]

    forced = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_override",
            {
                "action": "force_assign",
                "reason": "Operator selected the validated worker",
                "policy_id": policy["id"],
                "work_item_id": work_item["id"],
                "agent_id": worker["id"],
                "evidence": {"ticket": "OPS-4092"},
            },
            request_id=4092,
        )
    )["override"]
    assignment_id = forced["evidence"]["assignment_id"]
    assigned_items = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_list_work_items",
            {"room_id": room["id"]},
            request_id=4093,
        )
    )["work_items"]
    assigned = next(item for item in assigned_items if item["id"] == work_item["id"])
    assert assigned["status"] == "in_progress"
    assert assigned["assigned_agent_id"] == worker["id"]

    revoked = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_autonomy_override",
            {
                "action": "revoke_assignment",
                "reason": "Operator returned work to the queue",
                "assignment_id": assignment_id,
                "evidence": {"ticket": "OPS-4094"},
            },
            request_id=4094,
        )
    )["override"]
    assert revoked["new_state"] == "revoked"
    open_items = _phase_one_result(
        _phase_one_mcp_call(
            client,
            "agent_list_work_items",
            {"room_id": room["id"]},
            request_id=4095,
        )
    )["work_items"]
    reopened = next(item for item in open_items if item["id"] == work_item["id"])
    assert reopened["status"] == "open"
    assert reopened["assigned_agent_id"] is None


def test_phase_four_static_contracts_event_payload_and_prometheus_metrics(
    client: TestClient,
) -> None:
    import yaml

    from gateway_api.database import SessionLocal
    from gateway_api.models import OutboxEvent

    root = Path(__file__).resolve().parents[3]
    static_openapi = yaml.safe_load(
        (root / "openapi" / "gateway.openapi.yaml").read_text(encoding="utf-8")
    )
    asyncapi = yaml.safe_load(
        (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text(
            encoding="utf-8"
        )
    )
    dynamic_paths = client.get("/openapi.json").json()["paths"]
    phase_four_paths = {
        path for path in dynamic_paths if path.startswith("/api/agent-autonomy")
    }
    assert len(phase_four_paths) == 17
    assert phase_four_paths.issubset(static_openapi["paths"])
    assert asyncapi["info"]["version"] == "0.3.0"
    channels = {
        name for name in asyncapi["channels"] if name.startswith("gateway.autonomy.")
    }
    assert len(channels) == 14
    messages = {
        name
        for name in asyncapi["components"]["messages"]
        if name.startswith("Autonomy")
    }
    assert len(messages) == 14
    schema_paths = sorted(
        (root / "schemas").glob("gateway.autonomy.*.schema.json")
    )
    assert len(schema_paths) == 14
    for schema_path in schema_paths:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["additionalProperties"] is False
        assert {"event_id", "occurred_at"}.issubset(schema["required"])

    room, coordinator, _, _ = _phase_four_room_agents(
        client, suffix="contract-event"
    )
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="contract-event",
        coordinator_agent_id=coordinator["id"],
    )
    with SessionLocal() as db:
        outbox = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.event_type == "gateway.autonomy.policy.created.v1",
                OutboxEvent.payload["policy_id"].as_string() == policy["id"],
            )
            .one()
        )
        schema = json.loads(
            (
                root
                / "schemas"
                / "gateway.autonomy.policy.created.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        payload_keys = set(outbox.payload)
        assert set(schema["required"]) == payload_keys
        assert payload_keys == set(schema["properties"])
        assert outbox.headers["X-Gateway-Event-Type"] == outbox.event_type
        assert outbox.headers["Nats-Msg-Id"] == outbox.audit_event_id

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    text = metrics.text
    assert 'gateway_autonomy_policies{status="active"}' in text
    assert 'gateway_autonomy_approvals{status="pending"}' in text
    assert 'gateway_autonomy_permits{status="active"}' in text
    assert 'gateway_autonomy_recoveries{status="planned"}' in text
    assert "gateway_autonomy_worker_enabled 0" in text
    assert "gateway_autonomy_emergency_stop 0" in text


def test_phase_four_environment_emergency_stop_overrides_database_controls(
    client: TestClient,
) -> None:
    from gateway_api.agent_autonomy import AgentAutonomyService
    from gateway_api.config import get_settings
    from gateway_api.database import SessionLocal

    room, coordinator, _, _ = _phase_four_room_agents(
        client, suffix="environment-stop"
    )
    policy = _phase_four_policy(
        client,
        room_id=room["id"],
        suffix="environment-stop",
        coordinator_agent_id=coordinator["id"],
        assignment_mode="automatic",
    )
    service = AgentAutonomyService(
        get_settings().model_copy(
            update={
                "gateway_autonomy_enabled": True,
                "gateway_autonomy_emergency_stop": True,
            }
        )
    )
    with SessionLocal() as db:
        stored_policy = service._policy(
            db, owner_subject="dev:local", policy_id=policy["id"]
        )
        snapshot = service.control_snapshot(
            db,
            owner_subject="dev:local",
            room_id=room["id"],
            policy_id=policy["id"],
        )
        assert snapshot["effective_state"] == "killed"
        assert snapshot["reason"] == "GATEWAY_AUTONOMY_EMERGENCY_STOP"
        with pytest.raises(HTTPException) as blocked:
            service.assert_enabled(
                db,
                owner_subject="dev:local",
                room_id=room["id"],
                policy=stored_policy,
            )
        assert blocked.value.status_code == 423


def test_release_metadata_and_blue_green_deployment_artifacts(
    client: TestClient,
) -> None:
    import yaml

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "service": "gateway-api",
        "version": "0.3.6",
        "revision": "",
        "slot": "local",
        "initialization_status": "ready",
        "database_at_head": True,
        "database_revision": "20260725_0003",
        "database_head": "20260725_0003",
    }
    ready = client.get("/ready")
    assert ready.status_code == 200
    readiness = ready.json()
    assert readiness["release_version"] == "0.3.6"
    assert readiness["release_revision"] == ""
    assert readiness["deployment_slot"] == "local"

    root = Path(__file__).resolve().parents[3]
    deployment = yaml.safe_load(
        (root / "deploy" / "compose.production.yaml").read_text(encoding="utf-8")
    )
    assert {
        "postgres",
        "nats",
        "gateway-blue",
        "gateway-green",
        "candidate-router",
        "router",
    }.issubset(deployment["services"])
    assert (
        deployment["services"]["gateway-blue"]["environment"][
            "GATEWAY_REPLICA_ID"
        ]
        == "gateway-blue"
    )
    assert (
        deployment["services"]["gateway-green"]["environment"][
            "GATEWAY_REPLICA_ID"
        ]
        == "gateway-green"
    )
    assert (
        deployment["services"]["gateway-blue"]["environment"][
            "GATEWAY_BROKER_BACKEND"
        ]
        == "nats"
    )
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    assert "nats-py>=2.15,<3" in requirements

    deployment_script = root / "deploy" / "deploy-blue-green.sh"
    smoke_script = root / "deploy" / "smoke.sh"
    submit_script = root / "scripts" / "submit-thin-client-compatibility.sh"
    verifier = root / "deploy" / "verify-thin-client-compatibility.py"
    evidence_generator = root / "scripts" / "generate-release-evidence.py"
    for script in (deployment_script, smoke_script, submit_script, verifier, evidence_generator):
        assert script.stat().st_mode & 0o111
    script_text = deployment_script.read_text(encoding="utf-8")
    assert "RELEASE_VERSION" in script_text
    assert "chatgpt-gateway-nats" in script_text
    assert "active-slot" in script_text
    assert "prepare <git-commit>" in script_text
    assert "restart-candidate <git-commit>" in script_text
    assert "verify-compatibility <git-commit>" in script_text
    assert "promote <git-commit>" in script_text
    assert "cleanup-candidate <git-commit>" in script_text
    assert "deploy-blue-green.sh rollback" in script_text
    assert "Signed thin-client compatibility report is missing" in script_text
    assert "compatibility report predates the Jenkins candidate restart" in verifier.read_text(encoding="utf-8")
    assert "Immutable image" in script_text
    assert "Jenkins must transfer it before prepare" in script_text
    assert "Candidate container image identity changed after prepare" in script_text
    assert "Candidate image tag identity changed after prepare" in script_text
    assert 'if [[ -n "${lock_dir:-}" ]]' in script_text

    candidate_router = deployment["services"]["candidate-router"]
    assert candidate_router["ports"] == [
        "127.0.0.1:${GATEWAY_CANDIDATE_HTTP_PORT:-18036}:8080"
    ]
    assert candidate_router["volumes"] == [
        "${DEPLOY_ROOT}/runtime/candidate-nginx:/etc/nginx/conf.d:ro"
    ]

    jenkinsfile = (root / "Jenkinsfile").read_text(encoding="utf-8")
    for stage in (
        "Checkout exact GitLab prod",
        "CI: tests and production image",
        "Publish exact image and release to MKS",
        "CD: prepare inactive slot",
        "Candidate smoke",
        "Thin-client reconnect exercise",
        "Thin-client compatibility gate",
        "CD: promote candidate",
        "Post-deploy smoke",
    ):
        assert stage in jenkinsfile
    assert "docker build --platform linux/amd64 --target production" in jenkinsfile
    assert (
        '''test "$(docker image inspect "chatgpt-mcp-gateway:${GIT_COMMIT}" --format '{{.Architecture}}')" = "amd64"'''
        in jenkinsfile
    )
    assert "docker image save" in jenkinsfile
    assert "gzip -1n" in jenkinsfile
    assert "ssh-keygen -Y sign" in jenkinsfile
    assert "Jenkins MKS credential does not match the pinned release signing key" in jenkinsfile
    assert "restart-candidate" in jenkinsfile
    assert "verify-compatibility" in jenkinsfile
    assert "cleanup-candidate" in jenkinsfile
    assert "deploy-blue-green.sh' rollback" in jenkinsfile
    assert "bash deploy/smoke.sh https://gateway.example.com" in jenkinsfile


def test_p0_registry_routes_are_published(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    registry_paths = sorted(path for path in paths if path.startswith("/api/registry/"))
    p0_prefixes = (
        "/api/registry/activity/",
        "/api/registry/collaboration/",
        "/api/registry/coordination/",
        "/api/registry/autonomy/",
    )
    p0_paths = {path for path in registry_paths if path.startswith(p0_prefixes)}
    assert len(p0_paths) == 21
    assert "/api/registry/activity/sessions" in p0_paths
    assert "/api/registry/collaboration/messages" in p0_paths
    assert "/api/registry/coordination/leases" in p0_paths
    assert "/api/registry/autonomy/approvals" in p0_paths
    import yaml

    root = Path(__file__).resolve().parents[3]
    static_paths = yaml.safe_load(
        (root / "openapi" / "gateway.openapi.yaml").read_text(encoding="utf-8")
    )["paths"]
    assert p0_paths.issubset(static_paths)


def test_p0_registry_command_session_cursor_is_stable_and_redacted(
    client: TestClient, tmp_path: Path
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import CommandSession

    base = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        for index in range(5):
            timestamp = base + timedelta(minutes=index)
            db.add(
                CommandSession(
                    id=f"registry-session-{index}",
                    owner_subject="dev:local",
                    origin="thin_client",
                    resource_id="registry-thin",
                    name=f"registry command {index}",
                    command=f"echo {index}",
                    cwd="/workspace",
                    status="completed",
                    exit_code=0,
                    output_path=str(tmp_path / f"registry-session-{index}.jsonl"),
                    line_count=index + 1,
                    truncated=False,
                    meta={"password": "must-not-leak", "fencing_token": index + 1},
                    created_at=timestamp,
                    started_at=timestamp,
                    completed_at=timestamp,
                    updated_at=timestamp,
                )
            )
        db.commit()

    first = client.get("/api/registry/activity/sessions", params={"limit": 2})
    assert first.status_code == 200
    first_page = first.json()
    assert [item["id"] for item in first_page["items"]] == [
        "registry-session-4",
        "registry-session-3",
    ]
    assert first_page["has_more"] is True
    assert first_page["next_cursor"]
    assert first_page["items"][0]["meta"]["password"] == "[REDACTED]"
    assert first_page["items"][0]["meta"]["fencing_token"] == 5

    second = client.get(
        "/api/registry/activity/sessions",
        params={"limit": 2, "cursor": first_page["next_cursor"]},
    )
    assert second.status_code == 200
    second_page = second.json()
    assert [item["id"] for item in second_page["items"]] == [
        "registry-session-2",
        "registry-session-1",
    ]
    assert not (
        {item["id"] for item in first_page["items"]}
        & {item["id"] for item in second_page["items"]}
    )

    third = client.get(
        "/api/registry/activity/sessions",
        params={"limit": 2, "cursor": second_page["next_cursor"]},
    )
    assert third.status_code == 200
    assert [item["id"] for item in third.json()["items"]] == ["registry-session-0"]
    assert third.json()["has_more"] is False
    assert third.json()["next_cursor"] is None

    invalid = client.get(
        "/api/registry/activity/sessions", params={"cursor": "not-a-cursor"}
    )
    assert invalid.status_code == 400


def test_p0_collaboration_registry_includes_delivery_history_and_is_tenant_scoped(
    client: TestClient,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import (
        AgentInstance,
        AgentMessage,
        AgentMessageDelivery,
        CollaborationRoom,
    )

    now = datetime(2026, 7, 22, 13, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        room = CollaborationRoom(
            id="registry-room",
            owner_subject="dev:local",
            title="P0 Registry Room",
            project_path="/workspace/project",
            repository_identity="project.git",
            status="active",
            policy={},
            created_at=now,
            updated_at=now,
        )
        foreign_room = CollaborationRoom(
            id="foreign-room",
            owner_subject="other-tenant",
            title="Foreign Room",
            status="active",
            policy={},
            created_at=now,
            updated_at=now,
        )
        db.add_all([room, foreign_room])
        db.flush()
        sender = AgentInstance(
            id="registry-agent-sender",
            owner_subject="dev:local",
            logical_agent_id="sender",
            instance_id="sender-1",
            display_name="Sender",
            status="active",
            capabilities=[],
            labels={},
            current_room_id=room.id,
            last_heartbeat_at=now,
            created_at=now,
            updated_at=now,
        )
        recipient = AgentInstance(
            id="registry-agent-recipient",
            owner_subject="dev:local",
            logical_agent_id="recipient",
            instance_id="recipient-1",
            display_name="Recipient",
            status="active",
            capabilities=[],
            labels={},
            current_room_id=room.id,
            last_heartbeat_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add_all([sender, recipient])
        db.flush()
        message = AgentMessage(
            id="registry-message",
            owner_subject="dev:local",
            room_id=room.id,
            sender_agent_id=sender.id,
            recipient_agent_id=recipient.id,
            kind="information",
            body="Registry delivery evidence",
            payload={"access_token": "must-not-leak", "result": "visible"},
            priority=50,
            sequence_number=1,
            created_at=now,
        )
        db.add(message)
        db.flush()
        db.add(
            AgentMessageDelivery(
                id="registry-delivery",
                owner_subject="dev:local",
                message_id=message.id,
                recipient_agent_id=recipient.id,
                status="acknowledged",
                attempt_count=2,
                delivered_at=now,
                acknowledged_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()

    rooms = client.get("/api/registry/collaboration/rooms")
    assert rooms.status_code == 200
    room_ids = {item["id"] for item in rooms.json()["items"]}
    assert "registry-room" in room_ids
    assert "foreign-room" not in room_ids

    messages = client.get(
        "/api/registry/collaboration/messages", params={"room_id": "registry-room"}
    )
    assert messages.status_code == 200
    record = messages.json()["items"][0]
    assert record["id"] == "registry-message"
    assert record["payload"] == {
        "access_token": "[REDACTED]",
        "result": "visible",
    }
    assert record["deliveries"] == [
        {
            "id": "registry-delivery",
            "message_id": "registry-message",
            "recipient_agent_id": "registry-agent-recipient",
            "status": "acknowledged",
            "attempt_count": 2,
            "delivered_at": now.replace(tzinfo=None).isoformat(),
            "acknowledged_at": now.replace(tzinfo=None).isoformat(),
            "visibility_deadline": None,
            "created_at": now.replace(tzinfo=None).isoformat(),
            "updated_at": now.replace(tzinfo=None).isoformat(),
        }
    ]


def test_p0_autonomy_registry_embeds_approval_votes(client: TestClient) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import (
        AgentInstance,
        ApprovalRequest,
        ApprovalVote,
        AutonomyPolicy,
        CollaborationRoom,
    )

    now = datetime(2026, 7, 22, 14, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        room = CollaborationRoom(
            id="approval-room",
            owner_subject="dev:local",
            title="Approval Room",
            status="active",
            policy={},
            created_at=now,
            updated_at=now,
        )
        db.add(room)
        db.flush()
        executor = AgentInstance(
            id="approval-executor",
            owner_subject="dev:local",
            logical_agent_id="executor",
            instance_id="executor-1",
            display_name="Executor",
            status="active",
            capabilities=["tool:execute"],
            labels={},
            current_room_id=room.id,
            last_heartbeat_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(executor)
        db.flush()
        policy = AutonomyPolicy(
            id="approval-policy",
            owner_subject="dev:local",
            room_id=room.id,
            name="Production Gate",
            status="active",
            assignment_mode="manual",
            allowed_action_classes=["production"],
            allowed_tools=["deploy_release"],
            allowed_command_profiles=[],
            max_parallel_assignments=1,
            approval_rules={},
            recovery_policy={},
            generation=1,
            version=1,
            created_by_subject="dev:local",
            created_at=now,
            updated_at=now,
        )
        db.add(policy)
        db.flush()
        request = ApprovalRequest(
            id="approval-request",
            owner_subject="dev:local",
            room_id=room.id,
            policy_id=policy.id,
            executor_agent_id=executor.id,
            action_kind="deploy",
            action_class="production",
            tool="deploy_release",
            payload_hash="a" * 64,
            payload_summary={"credential": "must-not-leak", "release": "0.3.0"},
            quorum_required=2,
            require_admin_approval=True,
            disallow_proposer_vote=True,
            status="pending",
            policy_generation=1,
            version=1,
            created_by_subject="dev:local",
            expires_at=now + timedelta(hours=1),
            created_at=now,
            updated_at=now,
        )
        db.add(request)
        db.flush()
        db.add(
            ApprovalVote(
                id="approval-vote",
                owner_subject="dev:local",
                request_id=request.id,
                voter_subject="auditor:one",
                voter_roles=["gateway-auditor"],
                decision="approve",
                reason="Evidence verified",
                created_at=now,
            )
        )
        db.commit()

    response = client.get(
        "/api/registry/autonomy/approvals", params={"status": "pending"}
    )
    assert response.status_code == 200
    approval = response.json()["items"][0]
    assert approval["id"] == "approval-request"
    assert approval["payload_summary"] == {
        "credential": "[REDACTED]",
        "release": "0.3.0",
    }
    assert approval["votes"] == [
        {
            "id": "approval-vote",
            "request_id": "approval-request",
            "voter_subject": "auditor:one",
            "voter_roles": ["gateway-auditor"],
            "decision": "approve",
            "reason": "Evidence verified",
            "created_at": now.replace(tzinfo=None).isoformat(),
        }
    ]


def test_p1_registry_routes_are_published(client: TestClient) -> None:
    import yaml

    root = Path(__file__).resolve().parents[3]
    dynamic_paths = client.get("/openapi.json").json()["paths"]
    registry_paths = {
        path for path in dynamic_paths if path.startswith("/api/registry/")
    }
    p1_paths = {
        "/api/registry/operations/outbox",
        "/api/registry/operations/outbox-attempts",
        "/api/registry/operations/replicas",
        "/api/registry/operations/realtime-routes",
        "/api/registry/operations/notifications",
        "/api/registry/operations/broker-diagnostics",
        "/api/registry/administration/users",
        "/api/registry/administration/oauth-clients",
    }
    assert len(registry_paths) == 29
    assert p1_paths.issubset(registry_paths)
    static_paths = yaml.safe_load(
        (root / "openapi" / "gateway.openapi.yaml").read_text(encoding="utf-8")
    )["paths"]
    assert p1_paths.issubset(static_paths)


def test_p1_operations_registry_redacts_batches_and_aggregates(
    client: TestClient,
) -> None:
    from gateway_api.database import SessionLocal
    from gateway_api.models import (
        AuditEvent,
        GatewayReplica,
        OutboxDeliveryAttempt,
        OutboxEvent,
        ProcessedBrokerMessage,
        RealtimeNotification,
        RealtimeRoute,
    )

    now = datetime(2026, 7, 22, 15, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        audit = AuditEvent(
            id="p1-audit",
            event_type="gateway.p1.test.v1",
            actor_subject="dev:local",
            action="publish",
            resource_type="registry",
            resource_id="p1",
            status="success",
            payload={},
            created_at=now,
        )
        db.add(audit)
        db.flush()
        outbox = OutboxEvent(
            id="p1-outbox",
            audit_event_id=audit.id,
            owner_subject="dev:local",
            event_type="gateway.p1.test.v1",
            subject="gateway.registry.p1",
            payload={"credential": "must-not-leak", "result": "visible"},
            headers={"authorization": "Bearer must-not-leak", "trace": "visible"},
            status="retry",
            attempt_count=2,
            max_attempts=10,
            available_at=now,
            last_error="temporary broker error",
            created_at=now,
            updated_at=now,
        )
        db.add(outbox)
        db.flush()
        db.add_all(
            [
                OutboxDeliveryAttempt(
                    id="p1-attempt-1",
                    outbox_event_id=outbox.id,
                    attempt_number=1,
                    replica_id="gateway-a",
                    status="failed",
                    error="broker unavailable",
                    started_at=now,
                    completed_at=now + timedelta(seconds=1),
                ),
                OutboxDeliveryAttempt(
                    id="p1-attempt-2",
                    outbox_event_id=outbox.id,
                    attempt_number=2,
                    replica_id="gateway-b",
                    status="published",
                    broker_stream="GATEWAY_EVENTS",
                    broker_sequence=42,
                    started_at=now + timedelta(seconds=2),
                    completed_at=now + timedelta(seconds=3),
                ),
                GatewayReplica(
                    id="gateway-a",
                    hostname="gateway-a.local",
                    process_id=101,
                    status="online",
                    meta={"slot": "blue"},
                    started_at=now - timedelta(minutes=10),
                    last_heartbeat_at=now,
                    expires_at=now + timedelta(seconds=30),
                ),
                RealtimeRoute(
                    id="p1-route",
                    owner_subject="dev:local",
                    target_kind="agent",
                    target_id="agent-p1",
                    connection_id="connection-p1",
                    replica_id="gateway-a",
                    status="online",
                    meta={"transport": "websocket"},
                    connected_at=now - timedelta(minutes=2),
                    last_seen_at=now,
                    expires_at=now + timedelta(seconds=90),
                ),
                RealtimeNotification(
                    id="p1-notification",
                    owner_subject="dev:local",
                    target_kind="agent",
                    target_id="agent-p1",
                    event_type="gateway.agent.message.sent.v1",
                    payload={"access_token": "must-not-leak", "message_id": "visible"},
                    status="pending",
                    replica_id="gateway-a",
                    outbox_event_id=outbox.id,
                    attempt_count=1,
                    expires_at=now + timedelta(hours=1),
                    created_at=now,
                    updated_at=now,
                ),
                ProcessedBrokerMessage(
                    message_id="p1-message-1",
                    stream="GATEWAY_EVENTS",
                    consumer="gateway-realtime-gateway-a",
                    subject="gateway.events.message",
                    payload_sha256="a" * 64,
                    processed_at=now,
                ),
                ProcessedBrokerMessage(
                    message_id="p1-message-2",
                    stream="GATEWAY_EVENTS",
                    consumer="gateway-realtime-gateway-a",
                    subject="gateway.events.command",
                    payload_sha256="b" * 64,
                    processed_at=now + timedelta(seconds=1),
                ),
            ]
        )
        db.commit()

    response = client.get(
        "/api/registry/operations/outbox",
        params={"search": "p1.test", "status": "retry"},
    )
    assert response.status_code == 200
    event = next(item for item in response.json()["items"] if item["id"] == "p1-outbox")
    assert event["payload"] == {
        "credential": "[REDACTED]",
        "result": "visible",
    }
    assert event["headers"] == {
        "authorization": "[REDACTED]",
        "trace": "visible",
    }
    assert [attempt["id"] for attempt in event["attempts"]] == [
        "p1-attempt-1",
        "p1-attempt-2",
    ]

    attempts = client.get(
        "/api/registry/operations/outbox-attempts",
        params={"search": "gateway-b", "status": "published"},
    )
    assert attempts.status_code == 200
    assert attempts.json()["items"][0]["broker_sequence"] == 42

    replicas = client.get(
        "/api/registry/operations/replicas", params={"search": "gateway-a.local"}
    )
    assert replicas.status_code == 200
    assert any(item["id"] == "gateway-a" for item in replicas.json()["items"])

    routes = client.get(
        "/api/registry/operations/realtime-routes", params={"search": "agent-p1"}
    )
    assert routes.status_code == 200
    assert routes.json()["items"][0]["connection_id"] == "connection-p1"

    notifications = client.get(
        "/api/registry/operations/notifications", params={"search": "agent-p1"}
    )
    assert notifications.status_code == 200
    assert notifications.json()["items"][0]["payload"] == {
        "access_token": "[REDACTED]",
        "message_id": "visible",
    }

    diagnostics = client.get(
        "/api/registry/operations/broker-diagnostics",
        params={"search": "gateway-realtime-gateway-a"},
    )
    assert diagnostics.status_code == 200
    diagnostic = diagnostics.json()["items"][0]
    assert diagnostic["message_count"] == 2
    assert diagnostic["mode"] == "aggregate-only"
    assert "message_id" not in diagnostic
    assert "payload_sha256" not in diagnostic


def test_p1_administration_registry_is_safe_and_admin_only(
    client: TestClient,
) -> None:
    from gateway_api.auth import create_jwt
    from gateway_api.database import SessionLocal
    from gateway_api.models import OAuthClient, User

    now = datetime(2026, 7, 22, 16, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    subject="keycloak:operator",
                    username="operator",
                    email="operator@example.test",
                    roles=["gateway-user", "gateway-auditor"],
                    provider="keycloak",
                    created_at=now - timedelta(days=2),
                    last_seen_at=now,
                ),
                OAuthClient(
                    client_id="p1-safe-client",
                    client_name="P1 Safe Connector",
                    redirect_uris=["https://chat.openai.com/aip/callback"],
                    scope="workspace:read audit:read",
                    created_at=now,
                ),
            ]
        )
        db.commit()

    users = client.get(
        "/api/registry/administration/users",
        params={"search": "operator", "provider": "keycloak"},
    )
    assert users.status_code == 200
    operator = next(
        item for item in users.json()["items"] if item["id"] == "keycloak:operator"
    )
    assert operator["roles"] == ["gateway-user", "gateway-auditor"]
    assert operator["email"] == "operator@example.test"
    assert "password" not in operator
    assert "token" not in operator

    clients = client.get(
        "/api/registry/administration/oauth-clients",
        params={"search": "P1 Safe"},
    )
    assert clients.status_code == 200
    oauth_client = clients.json()["items"][0]
    assert oauth_client == {
        "id": "p1-safe-client",
        "client_id": "p1-safe-client",
        "client_name": "P1 Safe Connector",
        "redirect_uris": ["https://chat.openai.com/aip/callback"],
        "scopes": ["workspace:read", "audit:read"],
        "created_at": now.replace(tzinfo=None).isoformat(),
    }

    user_token = create_jwt(
        subject="keycloak:plain-user",
        username="plain-user",
        roles=["gateway-user"],
        scopes=["workspace:read"],
        token_type="access",
        ttl_seconds=300,
    )
    headers = {"Authorization": f"Bearer {user_token}"}
    assert (
        client.get("/api/registry/operations/outbox", headers=headers).status_code
        == 403
    )
    assert (
        client.get("/api/registry/administration/users", headers=headers).status_code
        == 403
    )
def test_mcp_federation_phase_three_broker_tools_are_stable_and_dispatch(
    client: TestClient,
) -> None:
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 7300, "method": "tools/list"},
    )
    assert response.status_code == 200
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
    expected = {
        "mcp_catalog_search",
        "mcp_tool_describe",
        "mcp_call_read",
        "mcp_action_prepare",
        "mcp_action_execute",
    }
    assert expected.issubset(tools)
    assert tools["mcp_catalog_search"]["annotations"]["readOnlyHint"] is True
    assert tools["mcp_call_read"]["annotations"]["readOnlyHint"] is True
    assert tools["mcp_action_prepare"]["annotations"]["readOnlyHint"] is False
    assert tools["mcp_action_execute"]["annotations"]["idempotentHint"] is True
    assert tools["mcp_action_execute"]["annotations"]["destructiveHint"] is True
    assert "idempotency_key" in tools["mcp_action_prepare"]["inputSchema"]["required"]
    assert not any(name in tools for name in {"mcp_call", "mcp_invoke", "mcp_execute"})

    search = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 7301,
            "method": "tools/call",
            "params": {
                "name": "mcp_catalog_search",
                "arguments": {"query": "no-reviewed-tool-exists", "limit": 5},
            },
        },
    )
    assert search.status_code == 200
    result = search.json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["count"] == 0
    assert result["structuredContent"]["results"] == []
