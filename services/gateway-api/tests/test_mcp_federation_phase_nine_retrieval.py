from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.config import get_settings
from gateway_api.dto import McpCatalogSearchInput
from gateway_api.mcp_catalog_retrieval import (
    TokenHashEmbeddingProvider,
    _QueryEmbeddingCache,
    activate_index_generation,
    build_index_generation,
    get_index_generation,
    list_index_generations,
    register_embedding_provider,
    rollback_index_generation,
    unregister_embedding_provider,
)
from gateway_api.mcp_federation import (
    classify_revision,
    create_server,
    reconcile_catalog_snapshot,
    upsert_exposure,
    upsert_policy,
)
from gateway_api.mcp_federation_broker import (
    _postgresql_lexical_scores,
    search_catalog,
)
from gateway_api.models import (
    AuditEvent,
    Base,
    McpCatalogEmbedding,
    McpCatalogIndexGeneration,
    McpServer,
    McpTool,
    McpToolExposure,
    McpToolRevision,
    User,
)


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


def _user(db: Session, subject: str) -> User:
    user = User(
        subject=subject,
        username=f"operator-{subject}",
        email=f"{subject}@example.test",
        roles=["gateway-admin", "gateway-user"],
        preferences={"scopes": ["mcp:read", "mcp:write"]},
        provider="test",
    )
    db.add(user)
    db.commit()
    return user


def _snapshot(*, include_write: bool = True, include_status: bool = False) -> list[dict]:
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
            },
            "title": "Sum values",
            "description": "Read two values and return their arithmetic sum.",
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
    if include_status:
        tools.append(
            {
                "upstream_name": "deployment_status",
                "input_schema": {
                    "type": "object",
                    "properties": {"environment": {"type": "string"}},
                    "required": ["environment"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string"}},
                },
                "title": "Deployment status",
                "description": "Read the current deployment status.",
                "annotations": {"readOnlyHint": True},
            }
        )
    return tools


def _configure_catalog(
    db: Session,
    *,
    owner_subject: str,
    generation: int = 1,
    include_status: bool = False,
) -> tuple[User, McpServer, dict[str, McpToolRevision]]:
    user = db.get(User, owner_subject) or _user(db, owner_subject)
    server = create_server(
        db,
        owner_subject=owner_subject,
        actor_subject=owner_subject,
        idempotency_key=f"server-{owner_subject}",
        data={
            "display_name": f"Remote MCP {owner_subject}",
            "origin": "gateway",
            "transport": "streamable_http",
            "endpoint_url": f"https://{owner_subject}.example.test/mcp",
            "thin_client_id": None,
            "runtime_id": None,
            "credential_binding_id": None,
        },
    )
    reconcile_catalog_snapshot(
        db,
        owner_subject=owner_subject,
        actor_subject=owner_subject,
        server_id=server.id,
        catalog_generation=generation,
        protocol_version="2025-11-25",
        tools=_snapshot(include_status=include_status),
    )
    upsert_policy(
        db,
        owner_subject=owner_subject,
        actor_subject=owner_subject,
        server_id=server.id,
        idempotency_key=f"policy-{owner_subject}",
        expected_version=0,
        data={
            "trust_level": "approved",
            "allowed_action_classes": ["read", "write"],
            "required_roles": [],
            "required_scopes": [],
            "approval_mapping": {},
            "tool_allowlist": [],
            "tool_denylist": [],
            "status": "active",
        },
    )
    revisions: dict[str, McpToolRevision] = {}
    tools = db.query(McpTool).filter(McpTool.server_id == server.id).all()
    for tool in tools:
        revision = db.get(McpToolRevision, tool.current_revision_id)
        is_read = tool.upstream_name != "publish_release"
        revision = classify_revision(
            db,
            owner_subject=owner_subject,
            actor_subject=owner_subject,
            revision_id=revision.id,
            idempotency_key=f"classify-{owner_subject}-{tool.upstream_name}-{generation}",
            expected_version=revision.version,
            action_class="read" if is_read else "write",
            read_only_status="verified" if is_read else "unverified",
        )
        existing_exposure = (
            db.query(McpToolExposure)
            .filter(McpToolExposure.tool_id == tool.id)
            .one_or_none()
        )
        upsert_exposure(
            db,
            owner_subject=owner_subject,
            actor_subject=owner_subject,
            tool_id=tool.id,
            idempotency_key=f"expose-{owner_subject}-{tool.upstream_name}-{generation}",
            expected_version=existing_exposure.version if existing_exposure else 0,
            data={
                "revision_id": revision.id,
                "mode": "catalog_only",
                "enabled": True,
                "projected_name": None,
                "required_role": None,
                "required_scope": None,
                "approval_class": "none" if is_read else "operator",
                "projection_generation": 0,
            },
        )
        revisions[tool.upstream_name] = revision
    return user, server, revisions


class _FakeDialect:
    name = "postgresql"


class _FakeBind:
    dialect = _FakeDialect()


class _FakeRow:
    def __init__(self, revision_id: str, score: float) -> None:
        self.id = revision_id
        self.lexical_score = score


class _FakeResult:
    def all(self) -> list[_FakeRow]:
        return [_FakeRow("revision-a", 0.75)]


class _FakePostgresSession:
    bind = _FakeBind()

    def __init__(self) -> None:
        self.statement = None
        self.parameters = None

    def execute(self, statement, parameters):
        self.statement = statement
        self.parameters = parameters
        return _FakeResult()


def test_postgresql_lexical_query_is_tenant_and_revision_bounded() -> None:
    db = _FakePostgresSession()
    scores = _postgresql_lexical_scores(
        db,
        owner_subject="tenant-a",
        query_text="deployment status",
        revision_ids=["revision-a", "revision-b"],
    )
    rendered = str(db.statement)
    assert "websearch_to_tsquery('simple'" in rendered
    assert "owner_subject = :owner_subject" in rendered
    assert "id IN" in rendered
    assert db.parameters == {
        "owner_subject": "tenant-a",
        "mcp_catalog_query": "deployment status",
        "revision_ids": ["revision-a", "revision-b"],
    }
    assert scores == {"revision-a": 0.75}


def test_phase_nine_hybrid_retrieval_machine_contract() -> None:
    import json
    from pathlib import Path

    import yaml

    contract = yaml.safe_load(
        Path("configs/mcp-federation/phase-9-hybrid-retrieval.yaml").read_text()
    )
    assert contract["task_id"] == "CMG-FED-870"
    assert contract["release_version"] == "0.7.0"
    assert contract["database_head"] == "20260727_0010"
    assert contract["security"] == {
        "tenant_key": "owner_subject",
        "policy_filter_before_ranking": True,
        "policy_filter_after_ranking": True,
        "cache_partitioned_by_tenant": True,
        "query_cache": {
            "maximum_tenants": 256,
            "maximum_entries_per_tenant": 256,
            "ttl_seconds": 60,
        },
        "vector_rows_partitioned_by_tenant": True,
        "provider_errors_disclosed": False,
        "raw_arguments_indexed": False,
        "raw_results_indexed": False,
    }
    assert contract["retrieval"]["reranker"]["maximum_candidates"] == 200
    assert contract["lifecycle"]["maximum_retrieval_candidates"] == 2000
    assert contract["lifecycle"]["one_active_generation_per_tenant"] is True

    asyncapi = yaml.safe_load(
        Path("asyncapi/gateway-events.asyncapi.yaml").read_text()
    )
    for event_type, message_name, schema_name in (
        (
            "gateway.mcp.catalog.index_built.v1",
            "McpCatalogIndexBuilt",
            "gateway.mcp.catalog.index_built.v1.schema.json",
        ),
        (
            "gateway.mcp.catalog.index_activated.v1",
            "McpCatalogIndexActivated",
            "gateway.mcp.catalog.index_activated.v1.schema.json",
        ),
    ):
        assert event_type in asyncapi["channels"]
        message = asyncapi["components"]["messages"][message_name]
        assert message["name"] == event_type
        schema = json.loads(Path("schemas", schema_name).read_text())
        assert schema["$id"] == event_type
        assert schema["additionalProperties"] is False


def test_lexical_fallback_applies_structured_filters_and_double_policy_fence(
    db: Session,
) -> None:
    user, _, _ = _configure_catalog(db, owner_subject="tenant-a")
    result = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(
            query="left arithmetic sum",
            action_class="read",
            read_only_status="verified",
            exposure_mode="catalog_only",
            approval_class="none",
            retrieval_mode="auto",
            limit=10,
        ),
    )
    assert result["count"] == 1
    assert result["results"][0]["name"] == "sum_values"
    assert result["retrieval"]["mode_used"] == "lexical"
    assert result["retrieval"]["lexical_backend"] == "deterministic_lexical_fallback"
    assert result["retrieval"]["semantic"]["reason"] == "no_active_index"
    assert result["retrieval"]["policy_filtering"] == {
        "before_ranking": True,
        "after_ranking": True,
    }


def test_index_generation_is_deterministic_versioned_and_rollback_safe(
    db: Session,
) -> None:
    user, server, _ = _configure_catalog(db, owner_subject="tenant-a")
    first = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    assert first.status == "ready"
    assert first.document_count == 2
    built_event = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "gateway.mcp.catalog.index_built.v1")
        .order_by(AuditEvent.created_at.desc())
        .first()
    )
    assert built_event.payload["source_catalog_sha256"] == first.source_catalog_sha256
    assert built_event.payload["document_count"] == 2
    repeated = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    assert repeated.id == first.id
    first = activate_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=first.id,
        expected_version=first.version,
    )
    assert first.status == "active"
    hybrid = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(query="summation", retrieval_mode="hybrid"),
    )
    assert hybrid["retrieval"]["mode_used"] == "hybrid"
    assert hybrid["retrieval"]["semantic"]["generation_id"] == first.id

    reconcile_catalog_snapshot(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server.id,
        catalog_generation=2,
        protocol_version="2025-11-25",
        tools=_snapshot(include_status=True),
    )
    tools = {
        tool.upstream_name: tool
        for tool in db.query(McpTool).filter(McpTool.server_id == server.id).all()
    }
    status_tool = tools["deployment_status"]
    status_revision = db.get(McpToolRevision, status_tool.current_revision_id)
    status_revision = classify_revision(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        revision_id=status_revision.id,
        idempotency_key="classify-status-generation-2",
        expected_version=status_revision.version,
        action_class="read",
        read_only_status="verified",
    )
    upsert_exposure(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        tool_id=status_tool.id,
        idempotency_key="expose-status-generation-2",
        expected_version=0,
        data={
            "revision_id": status_revision.id,
            "mode": "catalog_only",
            "enabled": True,
            "projected_name": None,
            "required_role": None,
            "required_scope": None,
            "approval_class": "none",
            "projection_generation": 0,
        },
    )
    second = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    assert second.id != first.id
    assert second.generation == first.generation + 1
    assert second.document_count == 3
    second = activate_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=second.id,
        expected_version=second.version,
    )
    db.refresh(first)
    assert first.status == "retired"
    assert second.status == "active"
    first = rollback_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=first.id,
        expected_version=first.version,
    )
    db.refresh(second)
    assert first.status == "active"
    assert second.status == "retired"


def test_index_rows_and_management_are_tenant_scoped(db: Session) -> None:
    user_a, _, revisions_a = _configure_catalog(db, owner_subject="tenant-a")
    user_b, _, revisions_b = _configure_catalog(db, owner_subject="tenant-b")
    generation_a = build_index_generation(
        db,
        owner_subject=user_a.subject,
        actor_subject=user_a.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    generation_b = build_index_generation(
        db,
        owner_subject=user_b.subject,
        actor_subject=user_b.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    assert generation_a.id != generation_b.id
    assert [item.id for item in list_index_generations(db, owner_subject="tenant-a")] == [
        generation_a.id
    ]
    with pytest.raises(HTTPException) as exc_info:
        get_index_generation(
            db,
            owner_subject="tenant-a",
            generation_id=generation_b.id,
        )
    assert exc_info.value.status_code == 404
    rows_a = (
        db.query(McpCatalogEmbedding)
        .filter(McpCatalogEmbedding.generation_id == generation_a.id)
        .all()
    )
    assert {row.owner_subject for row in rows_a} == {"tenant-a"}
    assert {row.revision_id for row in rows_a} == {
        revision.id for revision in revisions_a.values()
    }
    assert not {row.revision_id for row in rows_a}.intersection(
        revision.id for revision in revisions_b.values()
    )


def test_server_scoped_index_only_applies_to_matching_search_scope(
    db: Session,
) -> None:
    user, server, _ = _configure_catalog(db, owner_subject="tenant-a")
    generation = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
        server_id=server.id,
    )
    generation = activate_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=generation.id,
        expected_version=generation.version,
    )
    unscoped = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(
            query="arithmetic sum",
            retrieval_mode="hybrid",
        ),
    )
    assert unscoped["retrieval"]["mode_used"] == "lexical"
    assert unscoped["retrieval"]["semantic"]["reason"] == "index_scope_mismatch"
    scoped = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(
            query="arithmetic sum",
            server_id=server.id,
            retrieval_mode="hybrid",
        ),
    )
    assert scoped["retrieval"]["mode_used"] == "hybrid"
    assert scoped["retrieval"]["semantic"]["generation_id"] == generation.id


def test_provider_outage_falls_back_to_lexical_without_cross_mode_failure(
    db: Session,
) -> None:
    user, _, _ = _configure_catalog(db, owner_subject="tenant-a")
    generation = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    activate_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=generation.id,
        expected_version=generation.version,
    )
    unregister_embedding_provider("gateway-token-hash", "1")
    try:
        result = search_catalog(
            db,
            user=user,
            payload=McpCatalogSearchInput(query="arithmetic sum", retrieval_mode="auto"),
        )
        assert result["count"] == 1
        assert result["retrieval"]["mode_used"] == "lexical"
        assert result["retrieval"]["semantic"]["reason"] == "provider_unavailable"
    finally:
        register_embedding_provider(TokenHashEmbeddingProvider())


class ConstantEmbeddingProvider:
    model_key = "constant-test"
    model_version = "1"
    dimensions = 2

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0] for _ in texts]


class FailingEmbeddingProvider:
    model_key = "constant-test"
    model_version = "1"
    dimensions = 2

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        raise RuntimeError("provider unavailable")


def test_runtime_provider_failure_falls_back_without_error_disclosure(
    db: Session,
) -> None:
    register_embedding_provider(ConstantEmbeddingProvider())
    try:
        user, _, _ = _configure_catalog(db, owner_subject="tenant-a")
        generation = build_index_generation(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            model_key="constant-test",
            model_version="1",
        )
        activate_index_generation(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            generation_id=generation.id,
            expected_version=generation.version,
        )
        register_embedding_provider(FailingEmbeddingProvider())
        result = search_catalog(
            db,
            user=user,
            payload=McpCatalogSearchInput(
                query="arithmetic sum",
                retrieval_mode="auto",
            ),
        )
        assert result["count"] == 1
        assert result["retrieval"]["mode_used"] == "lexical"
        assert result["retrieval"]["semantic"]["reason"] == "provider_error"
        assert "provider unavailable" not in str(result)
    finally:
        unregister_embedding_provider("constant-test", "1")


def test_query_embedding_cache_is_partitioned_by_tenant() -> None:
    cache = _QueryEmbeddingCache(max_entries=1, ttl_seconds=60, max_tenants=2)
    cache.put(("tenant-a", "generation-a", "query-a"), [1.0, 0.0])
    cache.put(("tenant-b", "generation-b", "query-b"), [0.0, 1.0])
    assert cache.get(("tenant-a", "generation-a", "query-a")) == [1.0, 0.0]
    assert cache.get(("tenant-b", "generation-b", "query-b")) == [0.0, 1.0]
    cache.clear("tenant-a")
    assert cache.get(("tenant-a", "generation-a", "query-a")) is None
    assert cache.get(("tenant-b", "generation-b", "query-b")) == [0.0, 1.0]


def test_query_embedding_cache_evicts_least_recent_tenant_partition() -> None:
    cache = _QueryEmbeddingCache(max_entries=1, ttl_seconds=60, max_tenants=1)
    cache.put(("tenant-a", "generation-a", "query-a"), [1.0, 0.0])
    cache.put(("tenant-b", "generation-b", "query-b"), [0.0, 1.0])
    assert cache.get(("tenant-a", "generation-a", "query-a")) is None
    assert cache.get(("tenant-b", "generation-b", "query-b")) == [0.0, 1.0]


def test_static_policy_prefilter_runs_before_candidate_limit(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, _, _ = _configure_catalog(db, owner_subject="tenant-a")
    hidden_tool = (
        db.query(McpTool)
        .filter(
            McpTool.owner_subject == user.subject,
            McpTool.upstream_name == "publish_release",
        )
        .one()
    )
    exposure = (
        db.query(McpToolExposure)
        .filter(McpToolExposure.tool_id == hidden_tool.id)
        .one()
    )
    upsert_exposure(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        tool_id=hidden_tool.id,
        idempotency_key="hide-publish-release",
        expected_version=exposure.version,
        data={
            "revision_id": exposure.revision_id,
            "mode": "hidden",
            "enabled": False,
            "projected_name": None,
            "required_role": None,
            "required_scope": None,
            "approval_class": "operator",
            "projection_generation": exposure.projection_generation,
        },
    )
    monkeypatch.setenv("GATEWAY_MCP_CATALOG_RETRIEVAL_MAX_CANDIDATES", "1")
    get_settings.cache_clear()
    result = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(
            query="arithmetic sum",
            retrieval_mode="lexical",
        ),
    )
    assert result["count"] == 1
    assert result["results"][0]["name"] == "sum_values"


def test_semantic_results_require_exact_current_schema_binding(db: Session) -> None:
    register_embedding_provider(ConstantEmbeddingProvider())
    try:
        user, _, revisions = _configure_catalog(db, owner_subject="tenant-a")
        generation = build_index_generation(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            model_key="constant-test",
            model_version="1",
        )
        activate_index_generation(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            generation_id=generation.id,
            expected_version=generation.version,
        )
        query = McpCatalogSearchInput(query="opaque-semantic-query", retrieval_mode="hybrid")
        before = search_catalog(db, user=user, payload=query)
        assert before["count"] == 2
        row = (
            db.query(McpCatalogEmbedding)
            .filter(
                McpCatalogEmbedding.generation_id == generation.id,
                McpCatalogEmbedding.revision_id == revisions["sum_values"].id,
            )
            .one()
        )
        row.schema_hash = "0" * 64
        db.commit()
        after = search_catalog(db, user=user, payload=query)
        assert after["count"] == 1
        assert revisions["sum_values"].id not in after["results"][0]["tool_ref"]
    finally:
        unregister_embedding_provider("constant-test", "1")


def test_policy_is_revalidated_after_ranking(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    user, _, revisions = _configure_catalog(db, owner_subject="tenant-a")
    import gateway_api.mcp_federation_broker as broker

    original_rank = broker.rank_candidates

    def revoke_after_rank(*args, **kwargs):
        ranked = original_rank(*args, **kwargs)
        exposure = (
            db.query(McpToolExposure)
            .filter(McpToolExposure.revision_id == revisions["sum_values"].id)
            .one()
        )
        exposure.enabled = False
        exposure.version += 1
        db.commit()
        return ranked

    monkeypatch.setattr(broker, "rank_candidates", revoke_after_rank)
    result = search_catalog(
        db,
        user=user,
        payload=McpCatalogSearchInput(query="left arithmetic sum", retrieval_mode="lexical"),
    )
    assert result["count"] == 0


def test_partial_generation_schema_is_rejected_by_migration(tmp_path) -> None:
    from alembic import command
    from sqlalchemy import text

    from gateway_api.schema_migrations import alembic_config

    database_url = f"sqlite:///{tmp_path / 'partial.db'}"
    engine = create_engine(database_url)
    config = alembic_config(database_url)
    command.upgrade(config, "head")
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE mcp_catalog_embeddings"))
        connection.execute(
            text(
                "UPDATE alembic_version "
                "SET version_num = '20260726_0009'"
            )
        )
    with pytest.raises(RuntimeError, match="partial hybrid retrieval schema"):
        command.upgrade(config, "head")
    engine.dispose()


def test_only_one_active_generation_is_enforced_per_tenant(db: Session) -> None:
    user, _, _ = _configure_catalog(db, owner_subject="tenant-a")
    first = build_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        model_key="gateway-token-hash",
        model_version="1",
    )
    activate_index_generation(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        generation_id=first.id,
        expected_version=first.version,
    )
    active = (
        db.query(McpCatalogIndexGeneration)
        .filter(
            McpCatalogIndexGeneration.owner_subject == user.subject,
            McpCatalogIndexGeneration.status == "active",
        )
        .all()
    )
    assert [generation.id for generation in active] == [first.id]
