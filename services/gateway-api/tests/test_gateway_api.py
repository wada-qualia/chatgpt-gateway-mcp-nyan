from __future__ import annotations

import asyncio
import json
import base64
import hashlib
import time
from datetime import timedelta
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
    monkeypatch.setenv("MAX_COMMAND_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("COMMAND_BACKGROUND_AFTER_SECONDS", "1")
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
        json={"name": "stage-box", "target": "ubuntu@10.0.0.7:2222", "auth_type": "password", "password": "json-secret-value"},
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

    assert verify_ssh_connection(device, credentials, timeout_seconds=7, client_factory=factory) == "verified"
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
        json={"name": "stage-box", "target": "ubuntu@10.0.0.6:2222", "auth_type": "password", "password": "plain-password"},
    )

    assert response.status_code == 201
    assert ("flush", ("SecretBlob",)) in events
    assert any(event == "commit" for event, _ in events)


def test_device_detail_actions_update_test_and_delete(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "stage-box", "target": "ubuntu@10.0.0.5:2222", "auth_type": "password", "password": "plain-password"},
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
        json={"name": "stage-box", "target": "ubuntu@10.0.0.8:2222", "auth_type": "password", "password": "wrong-value"},
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
        json={"name": "stage-box", "target": "ubuntu@10.0.0.9:2222", "auth_type": "password", "password": "unused-value"},
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
    registered = client.post(
        "/api/thin-clients/register",
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"}},
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
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"}},
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
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.0"}},
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    client_id = registered.json()["id"]
    calls: list[dict] = []

    async def fake_request(client_id_arg: str, *, tool: str, arguments: dict, timeout_seconds: int) -> dict:
        calls.append({"client_id": client_id_arg, "tool": tool, "arguments": arguments, "timeout_seconds": timeout_seconds})
        if tool == "run_monitored_command":
            from gateway_api.monitoring import monitoring_service

            monitoring_service.append_output(str(arguments["session_id"]), stream="stdout", text="ran arbitrary command\n")
            monitoring_service.finish_session(str(arguments["session_id"]), status_value="completed", exit_code=0)
            return {"ok": True, "result": {"session_id": arguments["session_id"], "status": "running"}}
        return {"ok": True, "result": {"root": "/tmp/project", "entries": [{"path": "hello.txt", "kind": "file", "size": 5}]}}

    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setattr(mcp_router.thin_client_manager, "request", fake_request)

    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "thin_client_list_files", "arguments": {"client_id": client_id, "path": "."}},
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False
    assert response.json()["result"]["structuredContent"]["ok"] is True
    assert response.json()["result"]["structuredContent"]["client_id"] == client_id
    assert response.json()["result"]["structuredContent"]["entries"][0]["path"] == "hello.txt"
    assert "hello.txt" in response.json()["result"]["content"][0]["text"]
    command_response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "thin_client_run_command",
                "arguments": {"client_id": client_id, "command": "printf ok > file.txt", "cwd": ".", "timeout_seconds": 5},
            },
        },
    )

    assert command_response.status_code == 200
    assert command_response.json()["result"]["isError"] is False
    assert command_response.json()["result"]["structuredContent"]["exit_code"] == 0
    assert "ran arbitrary command" in command_response.json()["result"]["structuredContent"]["output"]
    assert calls == [
        {"client_id": client_id, "tool": "list_files", "arguments": {"path": "."}, "timeout_seconds": 120},
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
                "arguments": {"command": "sleep 2; echo threshold-ok", "cwd": ".", "timeout_seconds": 5},
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
            "params": {"name": "monitoring_read_output", "arguments": {"session_id": session_id, "tail": 5}},
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
        json={"jsonrpc": "2.0", "id": 47, "method": "tools/call", "params": {"name": "workspace_info", "arguments": {}}},
    )
    tails = ping.json()["result"]["structuredContent"]["background_session_tails"]
    tail = next(item for item in tails if item["session_id"] == session_id)
    assert [line["text"] for line in tail["lines"]] == ["line2", "line3", "line4", "line5", "line6"]
    assert all(line["auto_sent"] for line in tail["lines"])

    window = client.get(f"/api/command-sessions/{session_id}/output", params={"start_line": 2, "limit": 2})
    assert window.status_code == 200
    assert [line["text"] for line in window.json()["lines"]] == ["line2", "line3"]
    assert all(line["auto_sent"] for line in window.json()["lines"])

    terminated = client.post(f"/api/command-sessions/{session_id}/terminate", json={"force": True})
    assert terminated.status_code == 200
    assert terminated.json()["status"] == "terminated"


def test_thin_client_manager_returns_http_409_when_client_disconnects_during_request() -> None:
    from gateway_api.thin_client_control import ThinClientConnectionManager

    manager = ThinClientConnectionManager()

    class DisconnectingWebSocket:
        async def send_json(self, payload: dict) -> None:
            await manager.unregister("client-1")

    async def scenario() -> None:
        await manager.register("client-1", DisconnectingWebSocket())
        try:
            await manager.request("client-1", tool="run_command", arguments={"command": "sleep 10"}, timeout_seconds=5)
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
    assert "ssh_device_run_command" not in names
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
    assert output_schemas["thin_client_list_files"]["properties"]["entries"]["type"] == "array"
    assert output_schemas["thin_client_read_file"]["properties"]["content"]["type"] == "string"
    assert "operation" in schemas["thin_client_write_file"]["properties"]
    assert "content_base64" in schemas["thin_client_write_file"]["properties"]
    assert "expected_replacements" in schemas["thin_client_write_file"]["properties"]
    assert "return_content" in schemas["thin_client_write_file"]["properties"]
    assert "diff" in schemas["thin_client_write_file"]["properties"]
    assert schemas["thin_client_write_file"]["required"] == ["client_id", "path"]
    assert output_schemas["thin_client_write_file"]["properties"]["bytes"]["type"] == "integer"
    assert output_schemas["thin_client_write_file"]["properties"]["replacements"]["type"] == "integer"
    assert output_schemas["thin_client_write_file"]["properties"]["content"]["type"] == ["string", "null"]
    assert output_schemas["thin_client_write_file"]["properties"]["diff"]["type"] == "object"
    assert output_schemas["thin_client_write_file"]["properties"]["diff"]["properties"]["hunks"]["type"] == "array"
    assert output_schemas["file_changes_list"]["properties"]["changes"]["type"] == "array"
    assert schemas["ssh_device_info"]["required"] == ["device_id"]
    assert schemas["ssh_device_info"]["additionalProperties"] is False
    assert schemas["ssh_device_check_connection"]["required"] == ["device_id"]
    assert schemas["ssh_device_run_action"]["required"] == ["device_id", "action"]
    assert set(schemas["ssh_device_run_action"]["properties"]["action"]["enum"]) >= {"whoami", "pwd", "home_list"}
    assert schemas["ssh_device_read_home"]["required"] == ["device_id"]
    for ssh_tool in ["ssh_device_info", "ssh_device_check_connection", "ssh_device_run_action", "ssh_device_read_home"]:
        schema_text = json.dumps(schemas[ssh_tool]).lower()
        assert "password" not in schema_text
        assert "private_key" not in schema_text
        assert output_schemas[ssh_tool]["type"] == "object"
    assert output_schemas["thin_client_run_command"]["properties"]["output"]["type"] == "string"
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
        json={"name": "ssh-stage", "target": "robot@192.0.2.20:2222", "auth_type": "password", "password": "stored-value"},
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    info = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 60,
            "method": "tools/call",
            "params": {"name": "ssh_device_info", "arguments": {"device_id": device_id}},
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
    assert seen == {"device_id": device_id, "timeout_seconds": 9, "auth_type": "password"}


def test_mcp_ssh_run_action_creates_monitored_session_and_output(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.21:2222", "auth_type": "password", "password": "stored-value"},
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    import gateway_api.routers.mcp as mcp_router
    from gateway_api.adapters.ssh import SshCommandResult

    calls: list[dict[str, object]] = []

    def fake_run(device, credentials, *, command: str, timeout_seconds=30):
        calls.append({"device_id": device.id, "command": command, "timeout_seconds": timeout_seconds, "auth_type": credentials.auth_type})
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
                "arguments": {"device_id": device_id, "action": "whoami", "timeout_seconds": 5},
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
    assert calls == [{"device_id": device_id, "command": "whoami", "timeout_seconds": 5, "auth_type": "password"}]

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
            "params": {"name": "monitoring_read_output", "arguments": {"session_id": session_id, "tail": 5}},
        },
    )
    assert output.status_code == 200
    assert output.json()["result"]["structuredContent"]["output"]["lines"][-1]["text"] == "robot"


def test_mcp_ssh_run_action_rejects_unknown_action(client: TestClient) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.22:2222", "auth_type": "password", "password": "stored-value"},
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
                "arguments": {"device_id": created.json()["id"], "action": "not_allowed"},
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == 400
    assert "Unsupported SSH action" in response.json()["error"]["message"]


def test_mcp_ssh_raw_command_disabled_by_default(client: TestClient) -> None:
    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.23:2222", "auth_type": "password", "password": "stored-value"},
    )
    assert created.status_code == 201

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
        json={"name": "ssh-stage", "target": "robot@192.0.2.24:2222", "auth_type": "password", "password": "stored-value"},
    )
    assert created.status_code == 201
    device_id = created.json()["id"]

    calls: list[dict[str, object]] = []

    def fake_run(device, credentials, *, command: str, timeout_seconds=30):
        calls.append({"device_id": device.id, "command": command, "timeout_seconds": timeout_seconds})
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
                    "arguments": {"device_id": device_id, "command": "id", "timeout_seconds": 6},
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


def test_mcp_ssh_raw_command_policy_blocks_denied_pattern(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway_api.config as config
    import gateway_api.routers.mcp as mcp_router

    monkeypatch.setenv("GATEWAY_SSH_ALLOW_RAW_COMMAND", "true")
    config.get_settings.cache_clear()

    created = client.post(
        "/api/devices",
        json={"name": "ssh-stage", "target": "robot@192.0.2.25:2222", "auth_type": "password", "password": "stored-value"},
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
                    "arguments": {"device_id": created.json()["id"], "command": "sudo id"},
                },
            },
        )
    finally:
        config.get_settings.cache_clear()

    assert response.status_code == 200
    assert response.json()["error"]["code"] == 400
    assert "raw-mode policy" in response.json()["error"]["message"]
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
        json={"name": "ssh-stage", "target": "robot@192.0.2.26:2222", "auth_type": "password", "password": "stored-value"},
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
            "params": {"name": "list_files", "arguments": {"path": ".", "AccessTokens": "glpat-redacted"}},
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
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "workspace_info", "arguments": {}}},
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
        json={"hostname": "workstation", "directory": "/tmp/project", "labels": {"version": "0.2.2"}},
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    client_id = registered.json()["id"]
    calls: list[dict] = []

    async def fake_request(client_id_arg: str, *, tool: str, arguments: dict, timeout_seconds: int) -> dict:
        calls.append({"client_id": client_id_arg, "tool": tool, "arguments": arguments, "timeout_seconds": timeout_seconds})
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
    assert structured["diff"]["hunks"][0]["lines"][-1] == {"kind": "insert", "text": "updated"}
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
    assert changes[0]["diff_json"]["hunks"][0]["lines"][-1] == {"kind": "insert", "text": "updated"}

    list_response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {"name": "file_changes_list", "arguments": {"origin": "thin_client", "limit": 10}},
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
