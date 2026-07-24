from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.agent_autonomy import agent_autonomy_service
from gateway_api.config import get_settings
from gateway_api.dto import (
    McpActionExecuteInput,
    McpActionPrepareInput,
    McpCallReadInput,
    McpCatalogSearchInput,
    McpToolDescribeInput,
)
from gateway_api.mcp_federation import (
    classify_revision,
    create_server,
    reconcile_catalog_snapshot,
    upsert_exposure,
    upsert_policy,
)
from gateway_api.mcp_federation_broker import (
    call_read,
    describe_tool,
    execute_action,
    prepare_action,
    search_catalog,
)
from gateway_api.mcp_upstream import UpstreamCallResult
from gateway_api.models import (
    ActionReceipt,
    AgentCommand,
    Base,
    McpActionPreparation,
    McpServer,
    McpTool,
    McpToolRevision,
    SecretBlob,
    User,
)


@pytest.fixture
def db(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "false")
    monkeypatch.setenv("GATEWAY_AUTONOMY_ENABLED", "true")
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
        preferences={"scopes": ["mcp:read", "mcp:write"]},
        provider="test",
    )
    db.add(user)
    db.commit()
    return user


def _server(db: Session) -> McpServer:
    return create_server(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        idempotency_key="phase3-server",
        data={
            "display_name": "Phase 3 Remote MCP",
            "origin": "gateway",
            "transport": "streamable_http",
            "endpoint_url": "https://mcp.example.test/mcp",
            "thin_client_id": None,
            "runtime_id": None,
            "credential_binding_id": None,
        },
    )


def _snapshot(*, include_write: bool = False) -> list[dict]:
    tools = [
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
            },
            "title": "Sum values",
            "description": "Read two values and return their sum.\u0000",
            "annotations": {"readOnlyHint": True},
        }
    ]
    if include_write:
        tools.append(
            {
                "upstream_name": "publish_release",
                "input_schema": {
                    "type": "object",
                    "properties": {"version": {"type": "string"}},
                    "required": ["version"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"published": {"type": "boolean"}},
                },
                "title": "Publish release",
                "description": "Publish one reviewed release version.",
                "annotations": {"destructiveHint": False},
            }
        )
    return tools


def _configure_policy(db: Session, server: McpServer) -> None:
    upsert_policy(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server.id,
        idempotency_key="idem2",
        expected_version=0,
        data={
            "trust_level": "approved",
            "allowed_action_classes": ["read", "write", "destructive", "production"],
            "required_roles": [],
            "required_scopes": [],
            "approval_mapping": {},
            "tool_allowlist": [],
            "tool_denylist": [],
            "status": "active",
        },
    )


def _classify_and_expose(
    db: Session,
    tool: McpTool,
    *,
    action_class: str,
    read_only_status: str,
    approval_class: str,
) -> McpToolRevision:
    revision = db.get(McpToolRevision, tool.current_revision_id)
    revision = classify_revision(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        revision_id=revision.id,
        idempotency_key=f"classify-{tool.upstream_name}",
        expected_version=revision.version,
        action_class=action_class,
        read_only_status=read_only_status,
    )
    upsert_exposure(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        tool_id=tool.id,
        idempotency_key=f"expose-{tool.upstream_name}",
        expected_version=0,
        data={
            "revision_id": revision.id,
            "mode": "catalog_only",
            "enabled": True,
            "projected_name": None,
            "required_role": None,
            "required_scope": None,
            "approval_class": approval_class,
            "projection_generation": 0,
        },
    )
    return revision


class StubUpstream:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def call_exact_revision(self, db: Session, **kwargs):
        self.calls.append(kwargs)
        arguments = kwargs["arguments"]
        if "left" in arguments:
            payload = {
                "content": [
                    {
                        "type": "text",
                        "text": str(arguments["left"] + arguments["right"]),
                    }
                ],
                "structuredContent": {"total": arguments["left"] + arguments["right"]},
                "isError": False,
                "_gateway": {"truncated": False},
            }
        else:
            payload = {
                "content": [{"type": "text", "text": "published"}],
                "structuredContent": {"published": True},
                "isError": False,
                "_gateway": {"truncated": False},
            }
        return UpstreamCallResult(
            payload=payload,
            truncated=False,
            serialized_bytes=128,
            invocation_id=f"invocation-{len(self.calls)}",
            is_error=False,
        )


def test_transactional_catalog_reconciliation_rolls_back_and_marks_missing(
    db: Session,
) -> None:
    _user(db)
    server = _server(db)
    result = reconcile_catalog_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server.id,
        catalog_generation=1,
        protocol_version="2025-11-25",
        tools=_snapshot(),
    )
    assert result["tool_count"] == 1
    tool = db.query(McpTool).filter(McpTool.server_id == server.id).one()
    revision = db.get(McpToolRevision, tool.current_revision_id)
    assert revision.sanitized_description == "Read two values and return their sum."
    assert "left" in revision.search_text

    invalid = _snapshot()
    invalid.append(
        {
            "upstream_name": "invalid_schema",
            "input_schema": {"type": "definitely-not-a-json-schema-type"},
            "output_schema": None,
            "title": "Invalid",
            "description": "Invalid",
            "annotations": {},
        }
    )
    with pytest.raises(Exception):
        reconcile_catalog_snapshot(
            db,
            owner_subject="tenant-a",
            actor_subject="tenant-a",
            server_id=server.id,
            catalog_generation=2,
            protocol_version="2025-11-25",
            tools=invalid,
        )
    db.expire_all()
    server = db.get(McpServer, server.id)
    assert server.catalog_generation == 1
    assert db.query(McpTool).filter(McpTool.server_id == server.id).count() == 1

    missing = reconcile_catalog_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server.id,
        catalog_generation=2,
        protocol_version="2025-11-25",
        tools=[],
    )
    assert missing["missing_tool_count"] == 1
    db.refresh(tool)
    assert tool.lifecycle_state == "missing"

    reconcile_catalog_snapshot(
        db,
        owner_subject="tenant-a",
        actor_subject="tenant-a",
        server_id=server.id,
        catalog_generation=3,
        protocol_version="2025-11-25",
        tools=_snapshot(),
    )
    db.refresh(tool)
    assert tool.lifecycle_state == "active"


def test_catalog_read_and_guarded_action_lifecycle(db: Session) -> None:
    user = _user(db)
    server = _server(db)
    reconcile_catalog_snapshot(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server.id,
        catalog_generation=1,
        protocol_version="2025-11-25",
        tools=_snapshot(include_write=True),
    )
    _configure_policy(db, server)
    tools = {
        tool.upstream_name: tool
        for tool in db.query(McpTool).filter(McpTool.server_id == server.id).all()
    }
    read_revision = _classify_and_expose(
        db,
        tools["sum_values"],
        action_class="read",
        read_only_status="verified",
        approval_class="none",
    )
    write_revision = _classify_and_expose(
        db,
        tools["publish_release"],
        action_class="write",
        read_only_status="unverified",
        approval_class="operator",
    )
    read_ref = f"mcp-tool://{server.id}/{tools['sum_values'].id}/{read_revision.id}"
    write_ref = (
        f"mcp-tool://{server.id}/{tools['publish_release'].id}/{write_revision.id}"
    )

    searched = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(query="left sum", limit=20),
    )
    assert searched["count"] == 1
    assert searched["results"][0]["tool_ref"] == read_ref
    described = describe_tool(
        db,
        user=user,
        payload=McpToolDescribeInput(
            tool_ref=read_ref, schema_hash=read_revision.schema_hash
        ),
    )
    assert described["tool"]["input_schema"]["required"] == ["left", "right"]

    upstream = StubUpstream()
    read_result = asyncio.run(
        call_read(
            db,
            user=user,
            payload=McpCallReadInput(
                tool_ref=read_ref,
                schema_hash=read_revision.schema_hash,
                arguments={"left": 2, "right": 5},
            ),
            upstream=upstream,
            gateway_tool_call_id="read-call-1",
        )
    )
    assert read_result["result"]["structuredContent"] == {"total": 7}

    prepared = prepare_action(
        db,
        user=user,
        payload=McpActionPrepareInput(
            tool_ref=write_ref,
            schema_hash=write_revision.schema_hash,
            arguments={"version": "1.2.3"},
            justification="Publish the reviewed release.",
            idempotency_key="publish-1-2-3",
        ),
        preparation_ttl_seconds=900,
    )
    preparation_id = prepared["preparation"]["preparation_id"]
    preparation = db.get(McpActionPreparation, preparation_id)
    secret = db.get(SecretBlob, preparation.arguments_secret_id)
    command = db.get(AgentCommand, preparation.command_id)
    assert "1.2.3" not in secret.ciphertext
    assert "1.2.3" not in str(command.structured_payload)
    assert (
        prepare_action(
            db,
            user=user,
            payload=McpActionPrepareInput(
                tool_ref=write_ref,
                schema_hash=write_revision.schema_hash,
                arguments={"version": "1.2.3"},
                justification="Publish the reviewed release.",
                idempotency_key="publish-1-2-3",
            ),
            preparation_ttl_seconds=900,
        )["replayed"]
        is True
    )

    approval = agent_autonomy_service.cast_vote(
        db,
        request_id=preparation.approval_request_id,
        user=user,
        decision="approve",
        reason="Reviewed release is approved.",
    )
    assert approval.status == "approved"
    permit = agent_autonomy_service.issue_permit(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        request_id=approval.id,
        ttl_seconds=300,
    )
    executed = asyncio.run(
        execute_action(
            db,
            user=user,
            payload=McpActionExecuteInput(
                preparation_id=preparation.id,
                permit_id=permit.id,
                expected_schema_hash=write_revision.schema_hash,
            ),
            upstream=upstream,
            gateway_tool_call_id="write-call-1",
        )
    )
    assert executed["receipt_status"] == "succeeded"
    assert executed["result"]["structuredContent"] == {"published": True}
    assert (
        db.query(ActionReceipt).filter(ActionReceipt.permit_id == permit.id).count()
        == 1
    )
    assert len(upstream.calls) == 2

    replay = asyncio.run(
        execute_action(
            db,
            user=user,
            payload=McpActionExecuteInput(
                preparation_id=preparation.id,
                permit_id=permit.id,
                expected_schema_hash=write_revision.schema_hash,
            ),
            upstream=upstream,
            gateway_tool_call_id="write-call-2",
        )
    )
    assert replay["replayed"] is True
    assert len(upstream.calls) == 2


def test_read_tool_rejects_write_revision_and_secret_shaped_arguments(
    db: Session,
) -> None:
    user = _user(db)
    server = _server(db)
    reconcile_catalog_snapshot(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server.id,
        catalog_generation=1,
        protocol_version="2025-11-25",
        tools=_snapshot(include_write=True),
    )
    _configure_policy(db, server)
    tool = db.query(McpTool).filter(McpTool.upstream_name == "publish_release").one()
    revision = _classify_and_expose(
        db,
        tool,
        action_class="write",
        read_only_status="unverified",
        approval_class="operator",
    )
    ref = f"mcp-tool://{server.id}/{tool.id}/{revision.id}"
    with pytest.raises(HTTPException, match="verified read-only"):
        asyncio.run(
            call_read(
                db,
                user=user,
                payload=McpCallReadInput(
                    tool_ref=ref,
                    schema_hash=revision.schema_hash,
                    arguments={"version": "1.2.3"},
                ),
                upstream=StubUpstream(),
                gateway_tool_call_id=None,
            )
        )
    read_tool = db.query(McpTool).filter(McpTool.upstream_name == "sum_values").one()
    read_revision = _classify_and_expose(
        db,
        read_tool,
        action_class="read",
        read_only_status="verified",
        approval_class="none",
    )
    read_ref = f"mcp-tool://{server.id}/{read_tool.id}/{read_revision.id}"
    with pytest.raises(Exception, match="Secret-shaped"):
        asyncio.run(
            call_read(
                db,
                user=user,
                payload=McpCallReadInput(
                    tool_ref=read_ref,
                    schema_hash=read_revision.schema_hash,
                    arguments={"left": 1, "right": 2, "access_token": "forbidden"},
                ),
                upstream=StubUpstream(),
                gateway_tool_call_id=None,
            )
        )
