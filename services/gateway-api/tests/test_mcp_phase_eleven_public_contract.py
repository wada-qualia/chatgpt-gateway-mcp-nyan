from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient


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
    monkeypatch.setenv(
        "COMMAND_SESSION_SPOOL_ROOT", str(tmp_path / "command-sessions")
    )

    from gateway_api import config, database

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(settings.database_url, pool_pre_ping=True, **database._engine_args(settings.database_url),
    )
    database.SessionLocal.configure(bind=database.engine)

    from gateway_api.main import create_app
    from gateway_api.schema_migrations import run_schema_migrations

    run_schema_migrations(database.engine)
    with TestClient(create_app()) as test_client:
        yield test_client



def _seed(session_factory, owner: str) -> tuple[str, str]:
    from gateway_api.mcp_prompt_federation import (
        public_prompt_name,
        reconcile_prompt_catalog,
        upsert_prompt_exposure,
    )
    from gateway_api.mcp_resource_federation import (
        public_resource_template_uri,
        reconcile_resource_catalog,
        upsert_resource_exposure,
    )
    from gateway_api.models import (
        McpCapabilityEntity,
        McpCapabilityEntityRevision,
        McpServer,
    )

    server_id = "33333333-3333-4333-8333-333333333333"
    with session_factory() as db:
        server = McpServer(
            id=server_id,
            owner_subject=owner,
            origin="gateway",
            display_name="Phase 11 public contract",
            normalized_slug="phase-11-public-contract",
            transport="streamable_http",
            status="online",
            trust_level="restricted",
            capabilities={},
            catalog_generation=0,
            policy_generation=1,
            version=1,
        )
        db.add(server)
        db.flush([server])
        reconcile_prompt_catalog(
            db,
            owner_subject=owner,
            server_id=server_id,
            protocol_version="2025-11-25",
            catalog_generation=1,
            prompts=[
                {
                    "name": "review.release",
                    "title": "Release review",
                    "description": "Reviewed release prompt",
                    "arguments": [
                        {"name": "environment", "required": True},
                        {"name": "summary", "required": False},
                    ],
                }
            ],
        )
        prompt_entity = db.query(McpCapabilityEntity).filter_by(
            owner_subject=owner, server_id=server_id, entity_kind="prompt"
        ).one()
        prompt_revision = db.query(McpCapabilityEntityRevision).filter_by(
            id=prompt_entity.current_revision_id
        ).one()
        upsert_prompt_exposure(
            db,
            owner_subject=owner,
            actor_subject=owner,
            entity_id=prompt_entity.id,
            idempotency_key="phase11-public-prompt",
            expected_version=0,
            revision_id=prompt_revision.id,
            mode="catalog_only",
            enabled=True,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        reconcile_resource_catalog(
            db,
            owner_subject=owner,
            server_id=server_id,
            protocol_version="2025-11-25",
            catalog_generation=2,
            resources=[],
            resource_templates=[
                {
                    "uriTemplate": "https://provider.example/users/{user}/records{?format}",
                    "name": "User records",
                    "description": "Reviewed user records",
                    "mimeType": "application/json",
                }
            ],
        )
        template_entity = db.query(McpCapabilityEntity).filter_by(
            owner_subject=owner, server_id=server_id, entity_kind="resource_template"
        ).one()
        template_revision = db.query(McpCapabilityEntityRevision).filter_by(
            id=template_entity.current_revision_id
        ).one()
        upsert_resource_exposure(
            db,
            owner_subject=owner,
            actor_subject=owner,
            entity_id=template_entity.id,
            idempotency_key="phase11-public-resource-template",
            expected_version=0,
            revision_id=template_revision.id,
            mode="catalog_only",
            enabled=True,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        return (
            public_prompt_name(prompt_entity.id, prompt_revision.id),
            public_resource_template_uri(
                template_entity.id,
                template_revision.id,
                template_revision.argument_schema,
            ),
        )


def _call(client, request_id: str, method: str, params=None):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return client.post(
        "/mcp",
        headers={"MCP-Protocol-Version": "2025-11-25"},
        json=payload,
    )


def test_public_prompt_and_completion_contract_is_exact_and_fail_closed(client) -> None:
    from gateway_api import config, database

    before = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": "initialize-before",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "phase11-test", "version": "1"},
            },
        },
    )
    assert before.status_code == 200
    assert "prompts" not in before.json()["result"]["capabilities"]
    assert "completions" not in before.json()["result"]["capabilities"]
    unavailable = _call(client, "prompts-before", "prompts/list")
    assert unavailable.status_code == 200
    assert unavailable.json()["error"]["code"] == -32601

    settings = config.get_settings()
    public_prompt, public_template = _seed(database.SessionLocal, settings.gateway_dev_subject)
    get_prompt = AsyncMock(
        return_value={
            "description": "Reviewed result",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "Review prod"}}
            ],
        }
    )
    complete = AsyncMock(
        return_value={"completion": {"values": ["prod"], "total": 1, "hasMore": False}}
    )
    client.app.state.upstream_mcp_manager.get_exact_prompt = get_prompt
    client.app.state.upstream_mcp_manager.complete_exact_reference = complete

    initialized = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": "initialize-after",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "phase11-test", "version": "1"},
            },
        },
    )
    capabilities = initialized.json()["result"]["capabilities"]
    assert capabilities["prompts"] == {}
    assert capabilities["completions"] == {}
    assert "listChanged" not in capabilities["prompts"]

    listed = _call(client, "prompts-list", "prompts/list")
    prompts = listed.json()["result"]["prompts"]
    assert [item["name"] for item in prompts] == [public_prompt]
    assert prompts[0]["name"] != "review.release"
    assert [item["name"] for item in prompts[0]["arguments"]] == ["environment", "summary"]

    prompt_result = _call(
        client,
        "prompt-get",
        "prompts/get",
        {"name": public_prompt, "arguments": {"environment": "prod"}},
    )
    assert prompt_result.status_code == 200
    assert prompt_result.json()["result"]["messages"][0]["content"]["text"] == "Review prod"
    assert get_prompt.await_args.kwargs["arguments"] == {"environment": "prod"}
    assert get_prompt.await_args.kwargs["revision"].entity_kind == "prompt"

    upstream_name = _call(
        client,
        "prompt-upstream-name",
        "prompts/get",
        {"name": "review.release", "arguments": {"environment": "prod"}},
    )
    assert upstream_name.status_code == 404
    assert upstream_name.json()["error"]["code"] == -32012
    assert get_prompt.await_count == 1

    prompt_completion = _call(
        client,
        "completion-prompt",
        "completion/complete",
        {
            "ref": {"type": "ref/prompt", "name": public_prompt},
            "argument": {"name": "environment", "value": "pr"},
            "context": {"arguments": {"summary": "release"}},
        },
    )
    assert prompt_completion.status_code == 200
    assert complete.await_args.kwargs["revision"].entity_kind == "prompt"
    assert complete.await_args.kwargs["context_arguments"] == {"summary": "release"}

    template_completion = _call(
        client,
        "completion-template",
        "completion/complete",
        {
            "ref": {"type": "ref/resource", "uri": public_template},
            "argument": {"name": "user", "value": "4"},
            "context": {"arguments": {"format": "json"}},
        },
    )
    assert template_completion.status_code == 200
    assert complete.await_count == 2
    assert complete.await_args.kwargs["revision"].entity_kind == "resource_template"

    arbitrary_resource = _call(
        client,
        "completion-upstream-resource",
        "completion/complete",
        {
            "ref": {
                "type": "ref/resource",
                "uri": "https://provider.example/users/{user}/records{?format}",
            },
            "argument": {"name": "user", "value": "4"},
        },
    )
    assert arbitrary_resource.status_code == 404
    assert arbitrary_resource.json()["error"]["code"] == -32022
    assert complete.await_count == 2
