from __future__ import annotations

import json

import pytest
from gateway_api.database import Base
from gateway_api.mcp_prompt_federation import (
    McpPromptFederationError,
    normalize_completion_result,
    normalize_prompt_descriptor,
    normalize_prompt_get_result,
    parse_public_prompt_name,
    prompt_name_sha256,
    public_prompt_catalog,
    public_prompt_name,
    reconcile_prompt_catalog,
    resolve_public_prompt_binding,
    upsert_prompt_exposure,
    validate_completion_request,
    validate_prompt_arguments,
    validate_prompt_name,
)
from gateway_api.models import (
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
    McpServer,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

OWNER = "phase11-owner"
SERVER_ID = "22222222-2222-4222-8222-222222222222"
PROTOCOL = "2025-11-25"


def _db() -> tuple[object, Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, Session(engine)


def _server(db: Session, trust: str = "restricted") -> McpServer:
    server = McpServer(
        id=SERVER_ID,
        owner_subject=OWNER,
        origin="gateway",
        display_name="Phase 11",
        normalized_slug="phase-11",
        transport="streamable_http",
        status="online",
        trust_level=trust,
        capabilities={},
        catalog_generation=0,
        policy_generation=1,
        version=1,
    )
    db.add(server)
    db.flush([server])
    return server


def _catalog(db: Session, generation: int = 1):
    reconcile_prompt_catalog(
        db,
        owner_subject=OWNER,
        server_id=SERVER_ID,
        protocol_version=PROTOCOL,
        catalog_generation=generation,
        prompts=[
            {
                "name": "review.release",
                "title": "Release review",
                "description": "Untrusted upstream prompt metadata",
                "arguments": [
                    {
                        "name": "environment",
                        "description": "Target environment",
                        "required": True,
                    },
                    {
                        "name": "summary",
                        "required": False,
                    },
                ],
                "_meta": {
                    "credential": "must-not-be-persisted",
                    "authority": "provider-claimed",
                },
            }
        ],
    )
    entity = db.query(McpCapabilityEntity).filter_by(
        owner_subject=OWNER,
        server_id=SERVER_ID,
        entity_kind="prompt",
    ).one()
    revision = db.query(McpCapabilityEntityRevision).filter_by(
        id=entity.current_revision_id
    ).one()
    return entity, revision


def test_prompt_descriptor_is_bounded_immutable_and_advisory() -> None:
    assert validate_prompt_name("release.review/v1") == "release.review/v1"
    for invalid in ("", "bad name", "../bad", "a" * 161):
        with pytest.raises(McpPromptFederationError):
            validate_prompt_name(invalid)

    name_hash, descriptor, schema, metadata = normalize_prompt_descriptor(
        {
            "name": "review.release",
            "title": "Release review",
            "description": "Provider supplied",
            "arguments": [
                {"name": "environment", "required": True},
                {"name": "summary", "required": False},
            ],
            "_meta": {"token": "secret", "authority": "provider"},
        }
    )
    assert name_hash == prompt_name_sha256("review.release")
    assert descriptor["component_meta_present"] is True
    assert descriptor["upstream_name"] == "review.release"
    assert schema["required"] == ["environment"]
    assert schema["additionalProperties"] is False
    assert metadata["prompt_name_sha256"] == name_hash
    persisted = json.dumps(
        {"descriptor": descriptor, "schema": schema, "metadata": metadata},
        sort_keys=True,
    )
    assert "secret" not in persisted
    assert "\"token\"" not in persisted
    assert "\"authority\"" not in persisted

    _engine, db = _db()
    try:
        _server(db)
        entity, revision = _catalog(db)
        first_revision = revision.id
        unchanged = reconcile_prompt_catalog(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            protocol_version=PROTOCOL,
            catalog_generation=2,
            prompts=[
                {
                    "name": "review.release",
                    "title": "Release review",
                    "description": "Untrusted upstream prompt metadata",
                    "arguments": [
                        {
                            "name": "environment",
                            "description": "Target environment",
                            "required": True,
                        },
                        {"name": "summary", "required": False},
                    ],
                    "_meta": {"different": "still-not-persisted"},
                }
            ],
        )
        db.refresh(entity)
        assert unchanged["created_revisions"] == 0
        assert entity.current_revision_id == first_revision

        changed = reconcile_prompt_catalog(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            protocol_version=PROTOCOL,
            catalog_generation=3,
            prompts=[
                {
                    "name": "review.release",
                    "title": "Release review",
                    "description": "Changed advisory description",
                    "arguments": [
                        {"name": "environment", "required": True},
                    ],
                }
            ],
        )
        db.refresh(entity)
        assert changed["created_revisions"] == 1
        assert entity.current_revision_id != first_revision
        assert db.query(McpCapabilityEntityRevision).filter_by(
            entity_id=entity.id
        ).count() == 2
    finally:
        db.close()


def test_prompt_exposure_and_public_binding_are_exact_revision_fenced() -> None:
    _engine, db = _db()
    try:
        server = _server(db, "restricted")
        entity, revision = _catalog(db)
        assert db.query(McpCapabilityExposure).count() == 0
        exposure = upsert_prompt_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase11-admin",
            entity_id=entity.id,
            idempotency_key="prompt-exposure-create",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:prompts:read",
            approval_class="none",
        )
        replay = upsert_prompt_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase11-admin",
            entity_id=entity.id,
            idempotency_key="prompt-exposure-create",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:prompts:read",
            approval_class="none",
        )
        assert replay.id == exposure.id

        public_name = public_prompt_name(entity.id, revision.id)
        assert parse_public_prompt_name(public_name) == (entity.id, revision.id)
        with pytest.raises(McpPromptFederationError) as denied:
            resolve_public_prompt_binding(
                db,
                owner_subject=OWNER,
                name=public_name,
                roles=set(),
                scopes={"mcp:prompts:read"},
            )
        assert denied.value.code == "MCP_PROMPT_NOT_AUTHORIZED"

        resolved = resolve_public_prompt_binding(
            db,
            owner_subject=OWNER,
            name=public_name,
            roles={"gateway-reader"},
            scopes={"mcp:prompts:read"},
        )
        assert (resolved[0].id, resolved[1].id, resolved[2].id, resolved[3].id) == (
            SERVER_ID,
            entity.id,
            revision.id,
            exposure.id,
        )
        catalog = public_prompt_catalog(
            db,
            owner_subject=OWNER,
            roles={"gateway-reader"},
            scopes={"mcp:prompts:read"},
        )
        assert len(catalog) == 1
        assert catalog[0]["name"] == public_name
        assert catalog[0]["name"] != revision.descriptor["upstream_name"]
        assert catalog[0]["arguments"][0]["name"] == "environment"

        server.policy_generation += 1
        db.commit()
        with pytest.raises(McpPromptFederationError) as stale_policy:
            resolve_public_prompt_binding(
                db,
                owner_subject=OWNER,
                name=public_name,
                roles={"gateway-reader"},
                scopes={"mcp:prompts:read"},
            )
        assert stale_policy.value.code == "MCP_PROMPT_NOT_AUTHORIZED"

        server.policy_generation = 1
        db.commit()
        reconcile_prompt_catalog(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            protocol_version=PROTOCOL,
            catalog_generation=2,
            prompts=[
                {
                    "name": "review.release",
                    "description": "Changed descriptor creates a new revision",
                    "arguments": [{"name": "environment", "required": True}],
                }
            ],
        )
        with pytest.raises(McpPromptFederationError) as stale_revision:
            resolve_public_prompt_binding(
                db,
                owner_subject=OWNER,
                name=public_name,
                roles={"gateway-reader"},
                scopes={"mcp:prompts:read"},
            )
        assert stale_revision.value.code == "MCP_PROMPT_UNAVAILABLE"
    finally:
        db.close()


def test_prompt_exposure_constraint_accepts_prompt_and_rejects_other_kinds() -> None:
    _engine, db = _db()
    try:
        _server(db)
        entity, revision = _catalog(db)
        exposure = McpCapabilityExposure(
            id="33333333-3333-4333-8333-333333333333",
            owner_subject=OWNER,
            server_id=SERVER_ID,
            entity_id=entity.id,
            revision_id=revision.id,
            entity_kind="prompt",
            mode="hidden",
            enabled=False,
            approval_class="none",
            projection_generation=99,
            policy_generation=1,
            version=1,
        )
        db.add(exposure)
        db.commit()
        assert db.query(McpCapabilityExposure).filter_by(
            entity_kind="prompt"
        ).count() == 1
    finally:
        db.close()

def test_prompt_execution_arguments_are_exact_schema_bounded() -> None:
    _engine, db = _db()
    try:
        _server(db)
        _entity, revision = _catalog(db)
        assert validate_prompt_arguments(
            revision,
            {"environment": "production", "summary": "release"},
        ) == {"environment": "production", "summary": "release"}
        for invalid in (
            {},
            {"environment": "production", "unknown": "x"},
            {"environment": 42},
            {"environment": "x" * 8193},
        ):
            with pytest.raises(McpPromptFederationError) as exc:
                validate_prompt_arguments(revision, invalid)
            assert exc.value.code == "MCP_PROMPT_ARGUMENTS_INVALID"

        argument, context = validate_completion_request(
            revision,
            {"name": "environment", "value": "pro"},
            {"summary": "release"},
        )
        assert argument == {"name": "environment", "value": "pro"}
        assert context == {"summary": "release"}
        with pytest.raises(McpPromptFederationError) as unknown_completion:
            validate_completion_request(
                revision,
                {"name": "unknown", "value": "x"},
                {},
            )
        assert unknown_completion.value.code == "MCP_COMPLETION_ARGUMENT_INVALID"
    finally:
        db.close()


def test_prompt_get_result_is_bounded_sanitized_and_noninteractive() -> None:
    normalized = normalize_prompt_get_result(
        {
            "resultType": "complete",
            "description": "Provider description",
            "_meta": {"credential": "must-not-leak"},
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": "Review this release",
                        "_meta": {"provider": "advisory"},
                    },
                },
                {
                    "role": "assistant",
                    "content": {
                        "type": "resource_link",
                        "name": "Runbook",
                        "uri": "https://docs.example.test/runbook",
                    },
                },
            ],
        },
        max_text_bytes=4096,
        max_result_bytes=16384,
        max_content_items=8,
    )
    assert normalized["description"] == "Provider description"
    assert normalized["messages"][0]["content"] == {
        "type": "text",
        "text": "Review this release",
    }
    assert normalized["messages"][1]["content"]["uri"] == "https://docs.example.test/runbook"
    assert "_meta" not in json.dumps(normalized)
    assert "_gateway" not in json.dumps(normalized)
    assert "must-not-leak" not in json.dumps(normalized)

    with pytest.raises(McpPromptFederationError) as secret_meta:
        normalize_prompt_get_result(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Review",
                            "_meta": {"credential": "must-not-leak"},
                        },
                    }
                ]
            },
            max_text_bytes=4096,
            max_result_bytes=16384,
            max_content_items=8,
        )
    assert secret_meta.value.code == "MCP_SECRET_MATERIAL_REJECTED"

    with pytest.raises(McpPromptFederationError) as unsafe_uri:
        normalize_prompt_get_result(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "resource_link",
                            "name": "Local",
                            "uri": "file:///etc/passwd",
                        },
                    }
                ]
            },
            max_text_bytes=4096,
            max_result_bytes=16384,
            max_content_items=8,
        )
    assert unsafe_uri.value.code == "MCP_RESOURCE_INVALID"

    with pytest.raises(McpPromptFederationError) as interactive:
        normalize_prompt_get_result(
            {"resultType": "input_required", "messages": []},
            max_text_bytes=4096,
            max_result_bytes=16384,
            max_content_items=8,
        )
    assert interactive.value.code == "MCP_PROMPT_INTERACTION_UNSUPPORTED"

    with pytest.raises(McpPromptFederationError) as invalid_role:
        normalize_prompt_get_result(
            {
                "messages": [
                    {"role": "system", "content": {"type": "text", "text": "no"}}
                ]
            },
            max_text_bytes=4096,
            max_result_bytes=16384,
            max_content_items=8,
        )
    assert invalid_role.value.code == "MCP_PROTOCOL_MISMATCH"


def test_completion_result_is_bounded_and_noninteractive() -> None:
    normalized = normalize_completion_result(
        {
            "resultType": "complete",
            "_meta": {"authority": "ignored"},
            "completion": {
                "values": ["production", "prod-eu"],
                "total": 2,
                "hasMore": False,
            },
        },
        max_result_bytes=16384,
    )
    assert normalized == {
        "completion": {
            "values": ["production", "prod-eu"],
            "total": 2,
            "hasMore": False,
        }
    }

    with pytest.raises(McpPromptFederationError) as interactive:
        normalize_completion_result(
            {
                "resultType": "input_required",
                "completion": {"values": []},
            },
            max_result_bytes=16384,
        )
    assert interactive.value.code == "MCP_COMPLETION_INTERACTION_UNSUPPORTED"

    with pytest.raises(McpPromptFederationError) as too_many:
        normalize_completion_result(
            {"completion": {"values": ["x"] * 101}},
            max_result_bytes=16384,
        )
    assert too_many.value.code == "MCP_COMPLETION_RESULT_TOO_LARGE"

    with pytest.raises(McpPromptFederationError) as invalid_total:
        normalize_completion_result(
            {"completion": {"values": [], "total": True}},
            max_result_bytes=16384,
        )
    assert invalid_total.value.code == "MCP_PROTOCOL_MISMATCH"
