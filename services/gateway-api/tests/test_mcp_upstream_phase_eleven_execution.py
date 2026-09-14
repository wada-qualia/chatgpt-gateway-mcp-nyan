from __future__ import annotations

import asyncio
import contextlib
from types import SimpleNamespace
from typing import Any

import pytest
from gateway_api.mcp_federation_policy import sha256_json
from gateway_api.mcp_prompt_federation import normalize_prompt_descriptor
from gateway_api.mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from mcp import types


class _Dumpable:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return dict(self.payload)


class _PromptExecutionSession:
    def __init__(self, descriptor: dict[str, Any]) -> None:
        self.descriptor = descriptor
        self.prompt_calls: list[tuple[str, dict[str, str], bool]] = []
        self.completion_calls: list[tuple[Any, dict[str, str], dict[str, str]]] = []

    async def list_prompts(self, *, params: Any = None) -> Any:
        assert params is None
        return SimpleNamespace(
            prompts=[_Dumpable(self.descriptor)],
            next_cursor=None,
        )

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, str] | None = None,
        *,
        allow_input_required: bool = False,
        **_: Any,
    ) -> _Dumpable:
        self.prompt_calls.append((name, dict(arguments or {}), allow_input_required))
        return _Dumpable(
            {
                "resultType": "complete",
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": "review"}}
                ],
            }
        )

    async def complete(
        self,
        ref: Any,
        argument: dict[str, str],
        context_arguments: dict[str, str] | None = None,
    ) -> _Dumpable:
        self.completion_calls.append((ref, dict(argument), dict(context_arguments or {})))
        return _Dumpable(
            {
                "resultType": "complete",
                "completion": {"values": ["prod"], "total": 1, "hasMore": False},
            }
        )


class _ThinTransport:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    async def request_mcp_prompt(self, _client_id: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return dict(self.response)


def _binding(descriptor: dict[str, Any], *, origin: str = "gateway") -> tuple[Any, Any, Any]:
    name_hash, normalized, argument_schema, content_metadata = normalize_prompt_descriptor(
        descriptor
    )
    schema_hash = sha256_json(
        {
            "entity_kind": "prompt",
            "descriptor": normalized,
            "argument_schema": argument_schema,
            "content_metadata": content_metadata,
        }
    )
    server = SimpleNamespace(
        id="server-1",
        owner_subject="owner-1",
        origin=origin,
        status="online",
        thin_client_id="client-1" if origin == "thin_client" else None,
        runtime_id="runtime-1" if origin == "thin_client" else None,
        local_server_id="local-server-1" if origin == "thin_client" else None,
    )
    entity = SimpleNamespace(
        id="entity-1",
        owner_subject="owner-1",
        server_id="server-1",
        current_revision_id="revision-1",
        entity_kind="prompt",
        lifecycle_state="active",
        upstream_key=name_hash,
    )
    revision = SimpleNamespace(
        id="revision-1",
        owner_subject="owner-1",
        server_id="server-1",
        entity_id="entity-1",
        entity_kind="prompt",
        schema_hash=schema_hash,
        argument_schema=argument_schema,
        catalog_generation=7,
        protocol_version="2025-11-25",
    )
    return server, entity, revision


def _manager(**kwargs: Any) -> UpstreamMcpManager:
    return UpstreamMcpManager(
        public_base_url="https://gateway.example.test",
        calls_per_minute_per_server=0,
        calls_per_minute_per_tenant=0,
        **kwargs,
    )


def test_direct_prompt_and_completion_use_exact_live_prompt_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = {
        "name": "review.release",
        "arguments": [{"name": "environment", "required": True}],
    }
    server, entity, revision = _binding(descriptor)
    session = _PromptExecutionSession(descriptor)
    manager = _manager()

    @contextlib.asynccontextmanager
    async def fake_bounded(_server: Any):
        yield

    @contextlib.asynccontextmanager
    async def fake_session(_db: Any, _server: Any, **_: Any):
        yield session, SimpleNamespace(protocolVersion="2025-11-25"), None

    monkeypatch.setattr(manager, "_bounded", fake_bounded)
    monkeypatch.setattr(manager, "_session", fake_session)

    prompt_result = asyncio.run(
        manager.get_exact_prompt(
            None,
            owner_subject="owner-1",
            server=server,
            entity=entity,
            revision=revision,
            arguments={"environment": "prod"},
        )
    )
    assert session.prompt_calls == [
        ("review.release", {"environment": "prod"}, False)
    ]
    assert prompt_result["messages"][0]["role"] == "user"

    completion_result = asyncio.run(
        manager.complete_exact_reference(
            None,
            owner_subject="owner-1",
            server=server,
            entity=entity,
            revision=revision,
            argument={"name": "environment", "value": "pr"},
            context_arguments={"environment": "prod"},
        )
    )
    assert len(session.completion_calls) == 1
    reference, argument, context = session.completion_calls[0]
    assert isinstance(reference, types.PromptReference)
    assert reference.name == "review.release"
    assert argument == {"name": "environment", "value": "pr"}
    assert context == {"environment": "prod"}
    assert completion_result["completion"]["values"] == ["prod"]


def test_direct_prompt_rejects_live_descriptor_revision_drift_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = {
        "name": "review.release",
        "description": "v1",
        "arguments": [{"name": "environment", "required": True}],
    }
    server, entity, revision = _binding(selected)
    session = _PromptExecutionSession(
        {
            "name": "review.release",
            "description": "v2",
            "arguments": [{"name": "environment", "required": True}],
        }
    )
    manager = _manager()

    @contextlib.asynccontextmanager
    async def fake_bounded(_server: Any):
        yield

    @contextlib.asynccontextmanager
    async def fake_session(_db: Any, _server: Any, **_: Any):
        yield session, SimpleNamespace(protocolVersion="2025-11-25"), None

    monkeypatch.setattr(manager, "_bounded", fake_bounded)
    monkeypatch.setattr(manager, "_session", fake_session)

    with pytest.raises(UpstreamMcpError) as exc_info:
        asyncio.run(
            manager.get_exact_prompt(
                None,
                owner_subject="owner-1",
                server=server,
                entity=entity,
                revision=revision,
                arguments={"environment": "prod"},
            )
        )
    assert exc_info.value.code == "MCP_PROMPT_SCHEMA_CHANGED"
    assert session.prompt_calls == []


def test_thin_client_prompt_result_revalidates_descriptor_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = {
        "name": "review.release",
        "arguments": [{"name": "environment", "required": True}],
    }
    server, entity, revision = _binding(descriptor, origin="thin_client")
    response = {
        "type": "mcp_prompt_get_result",
        "schema_hash": revision.schema_hash,
        "catalog_generation": 7,
        "descriptor": descriptor,
        "result": {
            "resultType": "complete",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "review"}}
            ],
        },
    }
    transport = _ThinTransport(response)
    manager = _manager(thin_client_transport=transport)

    @contextlib.asynccontextmanager
    async def fake_bounded(_server: Any):
        yield

    monkeypatch.setattr(manager, "_bounded", fake_bounded)
    monkeypatch.setattr(
        manager,
        "_exact_thin_client_connection",
        lambda _db, *, server: SimpleNamespace(connection_instance_id="connection-1"),
    )

    result = asyncio.run(
        manager.get_exact_prompt(
            None,
            owner_subject="owner-1",
            server=server,
            entity=entity,
            revision=revision,
            arguments={"environment": "prod"},
        )
    )
    assert result["messages"][0]["content"]["text"] == "review"
    assert len(transport.calls) == 1
    assert transport.calls[0]["prompt_name_sha256"] == entity.upstream_key
    assert "prompt_name" not in transport.calls[0]

    transport.response["descriptor"] = {
        "name": "review.release",
        "description": "drifted",
        "arguments": [{"name": "environment", "required": True}],
    }
    with pytest.raises(UpstreamMcpError) as exc_info:
        asyncio.run(
            manager.get_exact_prompt(
                None,
                owner_subject="owner-1",
                server=server,
                entity=entity,
                revision=revision,
                arguments={"environment": "prod"},
            )
        )
    assert exc_info.value.code == "MCP_PROMPT_SCHEMA_CHANGED"
