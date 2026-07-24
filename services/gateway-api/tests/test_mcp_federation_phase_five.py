from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.auth import create_jwt
from gateway_api.config import get_settings
from gateway_api.mcp_federation import (
    classify_revision,
    create_server,
    reconcile_catalog_snapshot,
    upsert_exposure,
)
from gateway_api.mcp_presentation import (
    PresentationContext,
    create_candidate_generation,
    generation_tools,
    publish_generation,
    record_projection_verification,
    resolve_presentation_context,
    update_oauth_client_profile,
)
from gateway_api.mcp_tool_registry import (
    ToolDispatchTarget,
    ToolRegistry,
    ToolRegistryCollision,
)
from gateway_api.mcp_upstream import UpstreamCallResult
from gateway_api.models import (
    Base,
    McpProjectionTool,
    McpServer,
    McpTool,
    McpToolRevision,
    OAuthClient,
    User,
)
from gateway_api.routers.mcp import _call_tool, _tool_registry


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


def _user(db: Session) -> User:
    user = User(
        subject="tenant-a",
        username="operator-a",
        email="operator@example.test",
        roles=["gateway-admin", "gateway-user"],
        preferences={},
        provider="test",
    )
    db.add(user)
    db.commit()
    return user


def _native_tool(db: Session) -> tuple[McpServer, McpTool, McpToolRevision]:
    server = create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        idempotency_key="phase5-server",
        data={
            "display_name": "Phase 5 Remote MCP",
            "origin": "gateway",
            "transport": "streamable_http",
            "endpoint_url": "https://mcp.example.test/mcp",
            "thin_client_id": None,
            "runtime_id": None,
            "credential_binding_id": None,
        },
    )
    server.trust_level = "approved"
    server.status = "online"
    db.commit()
    reconcile_catalog_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server.id,
        catalog_generation=1,
        protocol_version="2025-11-25",
        max_tools=20,
        tools_list_changed_seen=False,
        tools=[
            {
                "upstream_name": "sum_values",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "left": {"type": "integer"},
                        "right": {"type": "integer"},
                    },
                    "required": ["left", "right"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"total": {"type": "integer"}},
                    "required": ["total"],
                    "additionalProperties": False,
                },
                "title": "Sum values",
                "description": "Add two reviewed integers.\u0000",
                "annotations": {"readOnlyHint": True},
            }
        ],
    )
    tool = db.query(McpTool).filter(McpTool.server_id == server.id).one()
    revision = db.get(McpToolRevision, tool.current_revision_id)
    revision = classify_revision(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        revision_id=revision.id,
        idempotency_key="phase5-classify",
        expected_version=revision.version,
        action_class="read",
        read_only_status="verified",
    )
    upsert_exposure(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        tool_id=tool.id,
        idempotency_key="phase5-exposure",
        expected_version=0,
        data={
            "revision_id": revision.id,
            "mode": "native_projected",
            "enabled": True,
            "projected_name": "phase5_sum_values",
            "required_role": None,
            "required_scope": None,
            "approval_class": "none",
            "projection_generation": 0,
        },
    )
    return server, tool, revision


class StubUpstream:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def call_exact_revision(self, db: Session, **kwargs):
        self.calls.append(kwargs)
        arguments = kwargs["arguments"]
        return UpstreamCallResult(
            payload={
                "content": [{"type": "text", "text": "3"}],
                "structuredContent": {"total": arguments["left"] + arguments["right"]},
                "isError": False,
            },
            truncated=False,
            serialized_bytes=64,
            invocation_id="phase5-invocation",
            is_error=False,
        )


def test_tool_registry_preserves_order_and_rejects_collisions() -> None:
    registry = ToolRegistry()
    registry.register("gateway", [{"name": "b"}, {"name": "a"}], start_order=10)
    registry.register("broker", [{"name": "c"}], start_order=30)
    assert registry.names() == ("b", "a", "c")
    assert registry.target("c").provider == "broker"
    with pytest.raises(ToolRegistryCollision):
        registry.register("native_projection", [{"name": "a"}])


def test_projection_generation_is_immutable_and_requires_evidence(db: Session) -> None:
    _user(db)
    _, _, revision = _native_tool(db)
    candidate = create_candidate_generation(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        profile_id="chatgpt-stable",
        reserved_names={"workspace_info", "mcp_catalog_search"},
    )
    tools = generation_tools(db, generation_id=candidate.id)
    assert len(tools) == 1
    snapshot = tools[0]
    assert snapshot.public_name == "phase5_sum_values"
    assert snapshot.revision_id == revision.id
    assert "\u0000" not in snapshot.sanitized_description
    original_schema = dict(snapshot.input_schema)

    active = publish_generation(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        generation_id=candidate.id,
    )
    assert active.status == "active"
    assert active.chatgpt_refresh_state == "pending"
    assert active.tools_list_changed_state == "not_required"

    revision.input_schema = {
        "type": "object",
        "properties": {"changed": {"type": "string"}},
    }
    db.commit()
    assert db.get(McpProjectionTool, snapshot.id).input_schema == original_schema

    with pytest.raises(HTTPException) as mismatch:
        record_projection_verification(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            generation_id=active.id,
            verification_kind="chatgpt_actions",
            observed_schema_hash="0" * 64,
            evidence={"source": "manual"},
        )
    assert mismatch.value.status_code == 409
    assert db.get(type(active), active.id).chatgpt_refresh_state == "pending"

    record_projection_verification(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        generation_id=active.id,
        verification_kind="chatgpt_actions",
        observed_schema_hash=active.schema_hash,
        evidence={"source": "operator-observed-actions"},
    )
    assert db.get(type(active), active.id).chatgpt_refresh_state == "verified"


def test_oauth_profile_change_requires_new_policy_generation(db: Session) -> None:
    client = OAuthClient(
        client_id="chatgpt-client",
        client_name="ChatGPT",
        redirect_uris=["https://chat.openai.com/aip/plugin-callback"],
        scope="mcp:read",
    )
    db.add(client)
    db.commit()
    assert client.presentation_policy_generation == 1
    updated = update_oauth_client_profile(
        db,
        client_id=client.client_id,
        profile_id="agent-restricted",
        allowed_tool_names=["workspace_info", "phase5_sum_values", "workspace_info"],
    )
    assert updated.presentation_policy_generation == 2
    assert updated.allowed_tool_names == ["phase5_sum_values", "workspace_info"]


def test_stale_oauth_presentation_token_requires_reauthorization(db: Session) -> None:
    user = _user(db)
    client = OAuthClient(
        client_id="chatgpt-client",
        client_name="ChatGPT",
        redirect_uris=["https://chat.openai.com/aip/plugin-callback"],
        scope="mcp:read",
        presentation_profile="chatgpt-stable",
        presentation_policy_generation=2,
    )
    db.add(client)
    db.commit()
    token = create_jwt(
        subject=user.subject,
        username=user.username,
        roles=user.roles,
        scopes=["mcp:read"],
        token_type="access",
        ttl_seconds=300,
        extra={
            "client_id": client.client_id,
            "presentation_profile": "chatgpt-stable",
            "presentation_policy_generation": 1,
            "allowed_tool_names": [],
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
    with pytest.raises(HTTPException) as denied:
        resolve_presentation_context(request, db, user)
    assert denied.value.status_code == 401
    assert denied.value.detail["code"] == "MCP_PRESENTATION_REAUTH_REQUIRED"


def test_registry_and_dispatch_use_exact_active_projection(db: Session) -> None:
    user = _user(db)
    server, _, revision = _native_tool(db)
    candidate = create_candidate_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        profile_id="developer-dynamic",
        reserved_names={
            tool["name"]
            for tool in _tool_registry(get_settings(), "restricted").tools()
        },
    )
    active = publish_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=candidate.id,
    )
    context = PresentationContext(
        profile_id="developer-dynamic",
        client_id="developer-client",
        policy_generation=1,
        scopes=frozenset(),
        allowed_tool_names=None,
    )
    registry = _tool_registry(
        get_settings(),
        "restricted",
        db=db,
        user=user,
        presentation=context,
    )
    assert "phase5_sum_values" in registry.names()
    target: ToolDispatchTarget = registry.target("phase5_sum_values")
    assert target.revision_id == revision.id
    assert target.generation_id == active.id

    upstream = StubUpstream()
    result = asyncio.run(
        _call_tool(
            "phase5_sum_values",
            {"left": 1, "right": 2},
            user,
            db,
            get_settings(),
            upstream=upstream,
            tool_call_id="gateway-call-phase5",
            dispatch_target=target,
            presentation=context,
        )
    )
    assert result["structuredContent"] == {"total": 3}
    assert upstream.calls[0]["revision_id"] == revision.id

    server.status = "offline"
    db.commit()
    with pytest.raises(HTTPException) as unavailable:
        asyncio.run(
            _call_tool(
                "phase5_sum_values",
                {"left": 1, "right": 2},
                user,
                db,
                get_settings(),
                upstream=upstream,
                dispatch_target=target,
                presentation=context,
            )
        )
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail["code"] == "MCP_PROJECTED_TOOL_UNAVAILABLE"
