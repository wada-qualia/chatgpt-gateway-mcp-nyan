from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
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
            raise AssertionError("disconnect did not become HTTP 409")

    asyncio.run(scenario())


def test_mcp_tools_list(client: TestClient) -> None:
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    names = [tool["name"] for tool in tools]
    assert "workspace_info" in names
    assert "docker_workspace_stop" in names
    assert "docker_workspace_start" in names
    assert "docker_workspace_delete" in names
    assert "docker_workspace_update" in names
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
    assert schemas["thin_client_write_file"]["required"] == ["client_id", "path"]
    assert output_schemas["thin_client_write_file"]["properties"]["bytes"]["type"] == "integer"
    assert output_schemas["thin_client_write_file"]["properties"]["replacements"]["type"] == "integer"
    assert output_schemas["thin_client_write_file"]["properties"]["content"]["type"] == ["string", "null"]
    assert output_schemas["thin_client_run_command"]["properties"]["output"]["type"] == "string"
    assert annotations["workspace_info"]["readOnlyHint"] is True
    assert annotations["list_files"]["readOnlyHint"] is True
    assert annotations["thin_client_run_command"]["readOnlyHint"] is False
    assert annotations["thin_client_run_command"]["destructiveHint"] is True
    assert annotations["thin_client_run_command"]["openWorldHint"] is True
    assert annotations["thin_client_write_file"]["readOnlyHint"] is False
    assert annotations["thin_client_write_file"]["openWorldHint"] is False
    assert annotations["docker_workspace_delete"]["destructiveHint"] is True


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
                "content": "updated",
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
    assert structured["content"] == "updated"
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
