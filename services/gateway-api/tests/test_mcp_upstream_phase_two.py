from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import socket
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from gateway_api.auth import get_current_user
from gateway_api.config import get_settings
from gateway_api.crypto import decrypt_text, encrypt_text
from gateway_api.database import get_db
from gateway_api.mcp_federation import mcp_federation_service
from gateway_api.mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from gateway_api.mcp_upstream_credentials import (
    complete_oauth_authorization,
    create_credential_material,
    revoke_credential_material,
    rotate_credential_material,
    start_oauth_authorization,
)
from gateway_api.mcp_upstream_dto import (
    McpCredentialMaterialCreate,
    McpCredentialMaterialRotate,
    McpOAuthAuthorizationStart,
)
from gateway_api.models import (
    Base,
    McpCredentialBinding,
    McpInvocation,
    McpOAuthAuthorizationState,
    McpOAuthDiscoverySnapshot,
    McpTool,
    McpToolRevision,
    SecretBlob,
    User,
    utcnow,
)
from gateway_api.routers.mcp_federation import router as federation_router
from gateway_api.routers.mcp_upstream import router as upstream_router
from httpx import ASGITransport
from mcp.server import MCPServer
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.asynccontextmanager
async def _running_server() -> AsyncIterator[str]:
    server = MCPServer(
        name="phase-two-upstream",
        log_level="WARNING",
    )

    @server.tool()
    async def add(left: int, right: int) -> dict[str, int]:
        return {"total": left + right}

    @server.tool()
    async def slow(delay_seconds: float) -> str:
        await asyncio.sleep(delay_seconds)
        return "done"

    @server.tool()
    async def large(size: int) -> str:
        return "x" * size

    port = _free_port()
    runner = uvicorn.Server(
        uvicorn.Config(
            server.streamable_http_app(
                streamable_http_path="/mcp",
                stateless_http=True,
                json_response=True,
                host="127.0.0.1",
            ),
            host="127.0.0.1",
            port=port,
            lifespan="on",
            log_level="critical",
            timeout_graceful_shutdown=1,
        )
    )
    task = asyncio.create_task(runner.serve())
    try:
        for _ in range(300):
            if runner.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("phase-two MCP server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, timeout=5)


@contextlib.asynccontextmanager
async def _running_oauth_server() -> AsyncIterator[tuple[str, list[dict[str, str]]]]:
    app = FastAPI()
    exchanges: list[dict[str, str]] = []

    @app.post("/token")
    async def token(request: Request):
        body = parse_qs((await request.body()).decode())
        payload = {key: values[-1] for key, values in body.items()}
        exchanges.append(payload)
        if payload.get("grant_type") == "authorization_code":
            if payload.get("code") != "accepted-code":
                raise HTTPException(status_code=400, detail="invalid code")
            return {
                "access_token": "oauth-access-token",
                "refresh_token": "oauth-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            }
        if payload.get("grant_type") == "refresh_token":
            if payload.get("refresh_token") != "oauth-refresh-token":
                raise HTTPException(status_code=400, detail="invalid refresh token")
            return {
                "access_token": "oauth-refreshed-access-token",
                "refresh_token": "oauth-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            }
        raise HTTPException(status_code=400, detail="unsupported grant")

    port = _free_port()
    runner = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            lifespan="on",
            log_level="critical",
            timeout_graceful_shutdown=1,
        )
    )
    task = asyncio.create_task(runner.serve())
    try:
        for _ in range(300):
            if runner.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("phase-two OAuth server did not start")
        yield f"http://127.0.0.1:{port}", exchanges
    finally:
        runner.should_exit = True
        await asyncio.wait_for(task, timeout=5)


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()
    get_settings.cache_clear()


def _server(db: Session, endpoint: str, binding_id: str | None = None):
    return mcp_federation_service.create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="operator-a",
        idempotency_key=f"server-{endpoint}-{binding_id}",
        data={
            "display_name": "Remote MCP",
            "origin": "gateway",
            "transport": "streamable_http",
            "endpoint_url": endpoint,
            "thin_client_id": None,
            "runtime_id": None,
            "credential_binding_id": binding_id,
        },
    )


def _oauth_discovery_snapshot(
    db: Session,
    *,
    server_id: str,
    resource: str,
    issuer: str,
    authorization_endpoint: str,
    token_endpoint: str,
    response_iss_supported: bool,
) -> McpOAuthDiscoverySnapshot:
    now = utcnow()
    snapshot = McpOAuthDiscoverySnapshot(
        id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{server_id}:{issuer}")),
        owner_subject="tenant-a",
        server_id=server_id,
        resource=resource,
        resource_metadata_url=f"{resource.rstrip('/')}/.well-known/oauth-protected-resource",
        authorization_server=issuer,
        authorization_server_metadata_url=(
            f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server"
        ),
        discovery_mechanism="rfc8414",
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        registration_endpoint=None,
        protected_resource_metadata={
            "resource": resource,
            "authorization_servers": [issuer],
        },
        authorization_server_metadata={
            "issuer": issuer,
            "authorization_response_iss_parameter_supported": response_iss_supported,
        },
        requested_scopes=["mcp:read"],
        proposed_scopes=["mcp:read"],
        metadata_hash=hashlib.sha256(f"{server_id}:{issuer}".encode()).hexdigest(),
        created_by_subject="operator-a",
        expires_at=now + timedelta(minutes=10),
        created_at=now,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def test_private_networks_are_rejected_by_default() -> None:
    manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")
    with pytest.raises(UpstreamMcpError, match="non-public"):
        asyncio.run(manager.validate_endpoint("https://127.0.0.1/mcp"))


def test_exact_trusted_internal_origin_allows_private_http_without_global_flags() -> (
    None
):
    manager = UpstreamMcpManager(
        public_base_url="https://gateway.example.test",
        trusted_internal_endpoints={"http://127.0.0.1:8765"},
    )
    resolution = asyncio.run(manager.validate_endpoint("http://127.0.0.1:8765/mcp"))
    assert resolution.scheme == "http"
    assert resolution.hostname == "127.0.0.1"
    assert resolution.port == 8765
    assert resolution.addresses == frozenset({"127.0.0.1"})

    with pytest.raises(UpstreamMcpError, match="Insecure upstream HTTP"):
        asyncio.run(manager.validate_endpoint("http://127.0.0.1:8766/mcp"))
    with pytest.raises(UpstreamMcpError, match="non-public"):
        asyncio.run(manager.validate_endpoint("https://127.0.0.1:8765/mcp"))


def test_trusted_internal_endpoint_configuration_requires_exact_origin() -> None:
    with pytest.raises(ValueError, match="absolute HTTP\\(S\\) origins"):
        UpstreamMcpManager(
            public_base_url="https://gateway.example.test",
            trusted_internal_endpoints={"http://127.0.0.1:8765/mcp"},
        )


def test_service_account_material_is_encrypted_and_resolved(db: Session) -> None:
    payload = McpCredentialMaterialCreate(
        binding_type="service_account",
        mode="header",
        header_name="X-Upstream-Key",
        header_value=SecretStr("secret-value"),
    )
    binding = create_credential_material(
        db,
        owner_subject="tenant-a",
        actor_subject="operator-a",
        idempotency_key="credential-1",
        payload=payload,
    )
    server = _server(db, "https://mcp.example.test/mcp", binding.id)
    manager = UpstreamMcpManager(public_base_url="https://gateway.example.test")
    headers = asyncio.run(manager.credentials.headers_for_server(db, server))
    assert headers == {"X-Upstream-Key": "secret-value"}
    assert "secret-value" not in binding.meta.values()


def test_refresh_and_exact_revision_call(db: Session) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint:
            server = _server(db, endpoint)
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )
            health = await manager.test_server(
                db, owner_subject="tenant-a", server_id=server.id
            )
            assert health["status"] == "online"
            assert health["tool_count"] == 3
            refreshed = await manager.refresh_server(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
            )
            assert refreshed.catalog_generation == 1
            tools = db.query(McpTool).filter(McpTool.server_id == server.id).all()
            assert {tool.upstream_name for tool in tools} == {"add", "slow", "large"}
            add_tool = next(tool for tool in tools if tool.upstream_name == "add")
            revision = db.get(McpToolRevision, add_tool.current_revision_id)
            result = await manager.call_exact_revision(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                revision_id=revision.id,
                arguments={"left": 2, "right": 5},
                idempotency_key="call-add-1",
            )
            assert result.payload["structuredContent"] == {"total": 7}
            replay = await manager.call_exact_revision(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                revision_id=revision.id,
                arguments={"left": 2, "right": 5},
                idempotency_key="call-add-1",
            )
            assert replay.replayed is True
            assert replay.invocation_id == result.invocation_id
            assert replay.is_error is False
            assert replay.payload["structuredContent"]["gatewayReplay"][
                "invocationId"
            ] == result.invocation_id
            assert (
                db.query(McpInvocation)
                .filter(McpInvocation.idempotency_key == "call-add-1")
                .count()
                == 1
            )
            with pytest.raises(UpstreamMcpError) as conflict:
                await manager.call_exact_revision(
                    db,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    revision_id=revision.id,
                    arguments={"left": 3, "right": 5},
                    idempotency_key="call-add-1",
                )
            assert conflict.value.code == "MCP_IDEMPOTENCY_CONFLICT"
            assert conflict.value.http_status == 409
            assert (
                db.query(McpInvocation)
                .filter(McpInvocation.idempotency_key == "call-add-1")
                .count()
                == 1
            )
            invocation = db.get(McpInvocation, result.invocation_id)
            invocation.outcome = "running"
            invocation.completed_at = None
            db.commit()
            with pytest.raises(UpstreamMcpError) as in_progress:
                await manager.call_exact_revision(
                    db,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    revision_id=revision.id,
                    arguments={"left": 2, "right": 5},
                    idempotency_key="call-add-1",
                )
            assert in_progress.value.code == "MCP_INVOCATION_IN_PROGRESS"
            assert in_progress.value.http_status == 409
            assert in_progress.value.retryable is True
            assert in_progress.value.metadata == {
                "invocation_id": result.invocation_id,
                "outcome": "running",
            }
            await manager.stop()

    asyncio.run(scenario())


def test_timeout_and_result_limit_are_normalized(db: Session) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint:
            server = _server(db, endpoint)
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
                cancellation_grace_seconds=1,
                max_result_bytes=900,
            )
            await manager.refresh_server(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
            )
            tools = {
                tool.upstream_name: tool
                for tool in db.query(McpTool).filter(McpTool.server_id == server.id)
            }
            slow_revision = db.get(McpToolRevision, tools["slow"].current_revision_id)
            with pytest.raises(UpstreamMcpError) as timeout_error:
                await manager.call_exact_revision(
                    db,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    revision_id=slow_revision.id,
                    arguments={"delay_seconds": 2},
                    timeout_seconds=0.05,
                    idempotency_key="call-slow-1",
                )
            assert timeout_error.value.code == "MCP_CALL_TIMEOUT"
            timeout_invocation = (
                db.query(McpInvocation)
                .filter(McpInvocation.idempotency_key == "call-slow-1")
                .one()
            )
            with pytest.raises(UpstreamMcpError) as timeout_replay:
                await manager.call_exact_revision(
                    db,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    revision_id=slow_revision.id,
                    arguments={"delay_seconds": 2},
                    timeout_seconds=0.05,
                    idempotency_key="call-slow-1",
                )
            assert timeout_replay.value.code == "MCP_CALL_TIMEOUT"
            assert timeout_replay.value.http_status == 409
            assert timeout_replay.value.metadata == {
                "invocation_id": timeout_invocation.id,
                "outcome": "unknown",
                "replayed": True,
                "normalized_error_code": "MCP_CALL_TIMEOUT",
            }
            assert (
                db.query(McpInvocation)
                .filter(McpInvocation.idempotency_key == "call-slow-1")
                .count()
                == 1
            )

            large_revision = db.get(McpToolRevision, tools["large"].current_revision_id)
            with pytest.raises(UpstreamMcpError) as size_error:
                await manager.call_exact_revision(
                    db,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    revision_id=large_revision.id,
                    arguments={"size": 4000},
                    idempotency_key="call-large-1",
                )
            assert size_error.value.code == "MCP_RESULT_TOO_LARGE"
            await manager.stop()

    asyncio.run(scenario())


def test_oauth_pkce_exchange_is_audience_bound_and_single_use(db: Session) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint, _running_oauth_server() as oauth:
            oauth_base, exchanges = oauth
            server = _server(db, endpoint)
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )
            audience = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}/"
            started = await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-start-1",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    authorization_endpoint=f"{oauth_base}/authorize",
                    token_endpoint=f"{oauth_base}/token",
                    client_id="gateway-client",
                    client_secret="gateway-client-secret",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=["mcp:read", "mcp:call"],
                    audience=audience,
                    extra_authorization_parameters={},
                ),
            )
            replayed = await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-start-1",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    authorization_endpoint=f"{oauth_base}/authorize",
                    token_endpoint=f"{oauth_base}/token",
                    client_id="gateway-client",
                    client_secret="gateway-client-secret",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=["mcp:read", "mcp:call"],
                    audience=audience,
                    extra_authorization_parameters={},
                ),
            )
            assert replayed == started
            assert db.query(McpOAuthAuthorizationState).count() == 1

            authorization = urlparse(started["authorization_url"])
            parameters = parse_qs(authorization.query)
            assert parameters["code_challenge_method"] == ["S256"]
            assert parameters["resource"] == [audience]
            assert parameters["state"] == [started["state"]]
            assert parameters["code_challenge"][0]

            flow = db.query(McpOAuthAuthorizationState).one()
            assert flow.state_sha256 != started["state"]
            assert started["state"] not in flow.state_sha256
            pending = db.get(SecretBlob, flow.secret_blob_id)
            assert pending is not None
            assert "gateway-client-secret" not in pending.ciphertext
            assert "code_verifier" not in pending.ciphertext

            binding = await complete_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                state=started["state"],
                code="accepted-code",
            )
            assert binding.status == "active"
            assert binding.audience == audience
            assert exchanges == [
                {
                    "grant_type": "authorization_code",
                    "code": "accepted-code",
                    "redirect_uri": "https://gateway.example.test/mcp-connections",
                    "client_id": "gateway-client",
                    "code_verifier": exchanges[0]["code_verifier"],
                    "resource": audience,
                }
            ]
            assert exchanges[0]["code_verifier"]
            token_secret = db.get(SecretBlob, binding.secret_blob_id)
            assert token_secret is not None
            assert "oauth-access-token" not in token_secret.ciphertext

            replayed_binding = await complete_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                state=started["state"],
                code="accepted-code",
            )
            assert replayed_binding.id == binding.id
            assert len(exchanges) == 1
            await manager.stop()

    asyncio.run(scenario())


def test_rest_api_enrolls_tests_and_refreshes_remote_server(db: Session) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint:
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )
            app = FastAPI()
            app.state.upstream_mcp_manager = manager
            app.include_router(federation_router)
            app.include_router(upstream_router)
            principal = User(
                subject="tenant-a",
                username="admin",
                roles=["gateway-admin", "gateway-auditor"],
            )

            async def current_user_override() -> User:
                return principal

            def db_override():
                yield db

            app.dependency_overrides[get_current_user] = current_user_override
            app.dependency_overrides[get_db] = db_override
            async with httpx.AsyncClient(
                transport=ASGITransport(app=app), base_url="http://gateway.test"
            ) as client:
                credential = await client.post(
                    "/api/mcp/credential-bindings/material",
                    headers={"Idempotency-Key": "rest-upstream-credential-1"},
                    json={
                        "binding_type": "service_account",
                        "mode": "header",
                        "header_name": "X-Upstream-Key",
                        "header_value": "rest-secret-value",
                        "scopes": [],
                    },
                )
                assert credential.status_code == 201, credential.text
                credential_payload = credential.json()
                assert "rest-secret-value" not in credential.text
                assert credential_payload["meta"] == {
                    "mode": "header",
                    "backend_reference": True,
                }

                created = await client.post(
                    "/api/mcp/servers",
                    headers={"Idempotency-Key": "rest-upstream-server-1"},
                    json={
                        "display_name": "REST Remote MCP",
                        "origin": "gateway",
                        "transport": "streamable_http",
                        "endpoint_url": endpoint,
                        "credential_binding_id": credential_payload["id"],
                    },
                )
                assert created.status_code == 201, created.text
                server = created.json()

                tested = await client.post(f"/api/mcp/servers/{server['id']}/test")
                assert tested.status_code == 200, tested.text
                assert tested.json()["tool_count"] == 3

                listed = await client.get("/api/mcp/servers")
                current = next(
                    item for item in listed.json() if item["id"] == server["id"]
                )
                refreshed = await client.post(
                    f"/api/mcp/servers/{server['id']}/refresh",
                    headers={"Idempotency-Key": "rest-upstream-refresh-1"},
                    json={"expected_version": current["version"]},
                )
                assert refreshed.status_code == 200, refreshed.text
                assert refreshed.json()["catalog_generation"] == 1
                assert "rest-secret-value" not in refreshed.text
            await manager.stop()

    asyncio.run(scenario())


def test_service_account_rotation_replay_and_revocation_fail_closed(
    db: Session,
) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint:
            created = create_credential_material(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                idempotency_key="credential-rotation-create",
                payload=McpCredentialMaterialCreate(
                    binding_type="service_account",
                    mode="header",
                    header_name="X-Upstream-Key",
                    header_value=SecretStr("old-value"),
                ),
            )
            server = _server(db, endpoint, created.id)
            rotation = McpCredentialMaterialRotate(
                binding_type="service_account",
                mode="header",
                header_name="X-Upstream-Key",
                header_value=SecretStr("new-value"),
                expected_version=created.version,
            )
            rotated = rotate_credential_material(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                binding_id=created.id,
                idempotency_key="credential-rotation-1",
                payload=rotation,
            )
            replayed = rotate_credential_material(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                binding_id=created.id,
                idempotency_key="credential-rotation-1",
                payload=rotation,
            )
            assert replayed.id == rotated.id
            assert replayed.version == rotated.version
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )
            assert await manager.credentials.headers_for_server(db, server) == {
                "X-Upstream-Key": "new-value"
            }
            revoked = revoke_credential_material(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                binding_id=created.id,
                expected_version=rotated.version,
            )
            assert revoked.status == "revoked"
            with pytest.raises(UpstreamMcpError) as auth_error:
                await manager.test_server(
                    db, owner_subject="tenant-a", server_id=server.id
                )
            assert auth_error.value.code == "MCP_AUTH_REQUIRED"
            db.refresh(server)
            assert server.status == "auth_required"
            await manager.stop()

    asyncio.run(scenario())


def test_oauth_authorization_response_issuer_is_checked_before_redemption(
    db: Session,
) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint, _running_oauth_server() as oauth:
            oauth_base, exchanges = oauth
            server = _server(db, endpoint)
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )
            audience = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}/"
            issuer_a = f"{oauth_base}/issuer-a"
            snapshot_a = _oauth_discovery_snapshot(
                db,
                server_id=server.id,
                resource=audience,
                issuer=issuer_a,
                authorization_endpoint=f"{oauth_base}/authorize-a",
                token_endpoint=f"{oauth_base}/token",
                response_iss_supported=True,
            )
            started = await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-issuer-start-a",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    discovery_snapshot_id=snapshot_a.id,
                    client_id="gateway-client",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=[],
                ),
            )

            flow = db.query(McpOAuthAuthorizationState).one()
            pending = db.get(SecretBlob, flow.secret_blob_id)
            assert pending is not None
            pending_data = json.loads(decrypt_text(pending.ciphertext))
            assert pending_data["expected_issuer"] == issuer_a
            assert pending_data["authorization_response_iss_required"] is True

            with pytest.raises(UpstreamMcpError) as mismatch:
                await complete_oauth_authorization(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    state=started["state"],
                    code="accepted-code",
                    iss=f"{oauth_base}/issuer-b",
                )
            assert mismatch.value.code == "MCP_AUTH_REQUIRED"
            assert "issuer mismatch" in mismatch.value.message
            assert exchanges == []

            with pytest.raises(UpstreamMcpError) as non_exact:
                await complete_oauth_authorization(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    state=started["state"],
                    code="accepted-code",
                    iss=f"{issuer_a}#spoof",
                )
            assert non_exact.value.code == "MCP_AUTH_REQUIRED"
            assert "issuer mismatch" in non_exact.value.message
            assert exchanges == []

            with pytest.raises(UpstreamMcpError) as missing:
                await complete_oauth_authorization(
                    db,
                    manager=manager,
                    owner_subject="tenant-a",
                    actor_subject="operator-a",
                    state=started["state"],
                    code="accepted-code",
                )
            assert missing.value.code == "MCP_AUTH_REQUIRED"
            assert "omitted required issuer" in missing.value.message
            assert exchanges == []

            binding = await complete_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                state=started["state"],
                code="accepted-code",
                iss=issuer_a,
            )
            assert len(exchanges) == 1
            assert binding.meta["oauth_issuer"] == issuer_a
            token_secret = db.get(SecretBlob, binding.secret_blob_id)
            assert token_secret is not None
            token_material = json.loads(decrypt_text(token_secret.ciphertext))
            assert token_material["issuer"] == issuer_a

            token_material["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
            token_secret.ciphertext = encrypt_text(
                json.dumps(token_material, separators=(",", ":"), sort_keys=True)
            )
            db.commit()
            headers = await manager.credentials.headers_for_server(db, server)
            assert headers == {"Authorization": "Bearer oauth-refreshed-access-token"}
            assert len(exchanges) == 2
            assert exchanges[1]["grant_type"] == "refresh_token"
            assert exchanges[1]["refresh_token"] == "oauth-refresh-token"
            assert exchanges[1]["resource"] == audience
            assert exchanges[1]["scope"] == "mcp:read"
            db.refresh(binding)
            refreshed_secret = db.get(SecretBlob, binding.secret_blob_id)
            assert refreshed_secret is not None
            refreshed_material = json.loads(decrypt_text(refreshed_secret.ciphertext))
            assert refreshed_material["issuer"] == issuer_a

            db.refresh(server)
            issuer_b = f"{oauth_base}/issuer-b"
            snapshot_b = _oauth_discovery_snapshot(
                db,
                server_id=server.id,
                resource=audience,
                issuer=issuer_b,
                authorization_endpoint=f"{oauth_base}/authorize-b",
                token_endpoint=f"{oauth_base}/token",
                response_iss_supported=True,
            )
            started_b = await start_oauth_authorization(
                db,
                manager=manager,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                server_id=server.id,
                idempotency_key="oauth-issuer-start-b",
                payload=McpOAuthAuthorizationStart(
                    expected_version=server.version,
                    discovery_snapshot_id=snapshot_b.id,
                    client_id="gateway-client",
                    redirect_uri="https://gateway.example.test/mcp-connections",
                    scopes=[],
                ),
            )
            assert started_b["binding_id"] != binding.id
            binding_b = db.get(McpCredentialBinding, started_b["binding_id"])
            assert binding_b is not None
            assert binding_b.meta["oauth_issuer"] == issuer_b
            assert binding.meta["oauth_issuer"] == issuer_a
            await manager.stop()

    asyncio.run(scenario())


def test_legacy_unstamped_oauth_refresh_fails_closed_without_exchange(
    db: Session,
) -> None:
    async def scenario() -> None:
        async with _running_server() as endpoint, _running_oauth_server() as oauth:
            oauth_base, exchanges = oauth
            audience = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}/"
            binding = create_credential_material(
                db,
                owner_subject="tenant-a",
                actor_subject="operator-a",
                idempotency_key="legacy-oauth-unbound",
                payload=McpCredentialMaterialCreate(
                    binding_type="oauth",
                    mode="oauth",
                    audience=audience,
                    access_token=SecretStr("fixture-" + uuid.uuid4().hex),
                    refresh_token=SecretStr("fixture-" + uuid.uuid4().hex),
                    token_endpoint=f"{oauth_base}/token",
                    client_id="legacy-client",
                    expires_at=utcnow() - timedelta(minutes=1),
                ),
            )
            server = _server(db, endpoint, binding.id)
            manager = UpstreamMcpManager(
                public_base_url="https://gateway.example.test",
                allow_private_networks=True,
                allow_insecure_http=True,
            )

            with pytest.raises(UpstreamMcpError) as auth_required:
                await manager.credentials.headers_for_server(db, server)
            assert auth_required.value.code == "MCP_AUTH_REQUIRED"
            assert "issuer-bound credential" in auth_required.value.message
            assert exchanges == []
            db.refresh(binding)
            db.refresh(server)
            assert binding.status == "auth_required"
            assert server.status == "auth_required"
            await manager.stop()

    asyncio.run(scenario())
