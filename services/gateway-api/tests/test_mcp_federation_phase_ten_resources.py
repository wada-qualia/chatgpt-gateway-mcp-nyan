from __future__ import annotations

import base64
import hashlib
import json

import pytest
from gateway_api.database import Base
from gateway_api.mcp_resource_federation import (
    McpResourceFederationError,
    authorize_resource_access,
    citation_safe_uri_hint,
    normalize_resource_read_result,
    parse_public_resource_uri,
    public_resource_catalog,
    public_resource_template_uri,
    public_resource_uri,
    reconcile_resource_catalog,
    record_resource_content_revision,
    resolve_live_resource_uri,
    resolve_public_resource_binding,
    resource_provenance,
    resource_uri_sha256,
    revoke_resource_subscriptions_for_thin_client,
    subscribe_resource,
    upsert_resource_exposure,
    validate_resource_uri,
)
from gateway_api.models import (
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
    McpCapabilitySubscription,
    McpServer,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

OWNER = "phase10-owner"
SERVER_ID = "11111111-1111-4111-8111-111111111111"
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
        display_name="Phase 10",
        normalized_slug="phase-10",
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


def _catalog(db: Session, uri: str, generation: int = 1):
    reconcile_resource_catalog(
        db,
        owner_subject=OWNER,
        server_id=SERVER_ID,
        protocol_version=PROTOCOL,
        catalog_generation=generation,
        resources=[{
            "uri": uri,
            "name": "Resource",
            "title": "Reviewed",
            "description": "Untrusted upstream metadata",
            "mimeType": "text/plain",
            "size": 128,
            "_meta": {"ui": {"resourceUri": "ui://not-forwarded/app.html"}, "private": "drop-me"},
        }],
        resource_templates=[],
    )
    entity = db.query(McpCapabilityEntity).filter_by(
        owner_subject=OWNER,
        server_id=SERVER_ID,
        entity_kind="resource",
    ).one()
    revision = db.query(McpCapabilityEntityRevision).filter_by(
        id=entity.current_revision_id
    ).one()
    return entity, revision


def test_uri_and_catalog_storage_boundaries() -> None:
    assert validate_resource_uri("urn:example:42") == "urn:example:42"
    assert citation_safe_uri_hint("file:///C:/Users/example/private/a.txt") == "file://…"
    for invalid in (
        "",
        "relative/path",
        "data:text/plain,x",
        "javascript:alert(1)",
        "https://user:secret@provider.example/a",
        "https://provider.example/a b",
        "https://provider.example/{id}",
    ):
        with pytest.raises(McpResourceFederationError):
            validate_resource_uri(invalid)

    _engine, db = _db()
    raw_uri = "file:///C:/Users/example/private/quarterly-plan.txt"
    try:
        _server(db)
        entity, revision = _catalog(db, raw_uri)
        expected = resource_uri_sha256(raw_uri)
        assert entity.upstream_key == expected
        assert entity.normalized_key == expected
        persisted = json.dumps(
            {"descriptor": revision.descriptor, "content": revision.content_metadata},
            sort_keys=True,
        )
        assert raw_uri not in persisted
        assert "C:/Users/example/private" not in persisted
        assert "ui://not-forwarded/app.html" not in persisted
        assert "drop-me" not in persisted
        assert revision.descriptor["uri_sha256"] == expected
        assert revision.descriptor["uri_hint"] == "file://…"
        assert revision.descriptor["component_meta_present"] is True
    finally:
        db.close()


def test_exposure_is_separate_versioned_idempotent_and_trust_fenced() -> None:
    _engine, db = _db()
    uri = "https://provider.example/resources/42"
    try:
        _server(db, "restricted")
        entity, revision = _catalog(db, uri)
        assert db.query(McpCapabilityExposure).count() == 0
        exposure = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="create-exposure",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:resources:read",
            approval_class="none",
        )
        replay = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="create-exposure",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:resources:read",
            approval_class="none",
        )
        assert replay.id == exposure.id
        assert db.query(McpCapabilityExposure).count() == 1

        with pytest.raises(McpResourceFederationError) as denied:
            authorize_resource_access(
                db,
                owner_subject=OWNER,
                server_id=SERVER_ID,
                uri=uri,
                roles=set(),
                scopes={"mcp:resources:read"},
            )
        assert denied.value.code == "MCP_RESOURCE_ROLE_REQUIRED"
        server, got_entity, got_revision, got_exposure = authorize_resource_access(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            uri=uri,
            roles={"gateway-reader"},
            scopes={"mcp:resources:read"},
        )
        assert (server.id, got_entity.id, got_revision.id, got_exposure.id) == (
            SERVER_ID,
            entity.id,
            revision.id,
            exposure.id,
        )

        with pytest.raises(McpResourceFederationError) as native:
            upsert_resource_exposure(
                db,
                owner_subject=OWNER,
                actor_subject="phase10-admin",
                entity_id=entity.id,
                idempotency_key="native-rejected",
                expected_version=0,
                revision_id=revision.id,
                mode="native_projected",
                enabled=True,
                required_role=None,
                required_scope=None,
                approval_class="operator",
                projection_generation=1,
            )
        assert native.value.code == "MCP_RESOURCE_TRUST_REQUIRED"
    finally:
        db.close()


def test_read_content_is_exact_bounded_and_persistence_is_evidence_only() -> None:
    _engine, db = _db()
    uri = "https://provider.example/resources/42"
    body = "citation body must remain transient"
    try:
        server = _server(db)
        entity, catalog_revision = _catalog(db, uri)
        normalized = normalize_resource_read_result(
            requested_uri=uri,
            contents=[
                {"uri": uri, "mimeType": "text/plain", "text": body},
                {
                    "uri": uri,
                    "mimeType": "image/png",
                    "blob": base64.b64encode(b"png-bytes").decode("ascii"),
                },
            ],
        )
        assert normalized["contents"][0]["text"] == body
        metadata = normalized["content_metadata"]
        assert metadata["items"][0]["sha256"] == hashlib.sha256(body.encode()).hexdigest()
        content_revision = record_resource_content_revision(
            db,
            owner_subject=OWNER,
            entity_id=entity.id,
            protocol_version=PROTOCOL,
            catalog_generation=1,
            content_metadata=metadata,
        )
        persisted = json.dumps(content_revision.content_metadata, sort_keys=True)
        assert body not in persisted
        assert base64.b64encode(b"png-bytes").decode("ascii") not in persisted
        assert entity.current_revision_id == catalog_revision.id
        provenance = resource_provenance(
            server=server,
            entity=entity,
            catalog_revision=catalog_revision,
            content_revision=content_revision,
        )
        assert provenance["uri_sha256"] == resource_uri_sha256(uri)
        assert provenance["uri_hint"] == "https://provider.example/…"
        assert provenance["mime_types"] == ["image/png", "text/plain"]

        with pytest.raises(McpResourceFederationError) as mismatch:
            normalize_resource_read_result(
                requested_uri=uri,
                contents=[{"uri": uri + "x", "mimeType": "text/plain", "text": "x"}],
            )
        assert mismatch.value.code == "MCP_RESOURCE_URI_MISMATCH"
        with pytest.raises(McpResourceFederationError) as html:
            normalize_resource_read_result(
                requested_uri=uri,
                contents=[{"uri": uri, "mimeType": "text/html", "text": "<script/>"}],
            )
        assert html.value.code == "MCP_RESOURCE_MIME_UNSUPPORTED"
    finally:
        db.close()


def test_subscription_stores_hash_hint_and_cleanup_revokes_missing_resource() -> None:
    _engine, db = _db()
    uri = "file:///C:/Users/example/private/subscribed.txt"
    try:
        _server(db)
        entity, _revision = _catalog(db, uri)
        subscription = subscribe_resource(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            uri=uri,
        )
        assert subscription.uri_sha256 == resource_uri_sha256(uri)
        assert subscription.uri_hint == "file://…"
        assert uri not in json.dumps({
            "key": subscription.subscription_key,
            "hash": subscription.uri_sha256,
            "hint": subscription.uri_hint,
        })
        reconcile_resource_catalog(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            protocol_version=PROTOCOL,
            catalog_generation=2,
            resources=[],
            resource_templates=[],
        )
        db.refresh(entity)
        db.refresh(subscription)
        assert entity.lifecycle_state == "missing"
        assert subscription.status == "revoked"
        assert subscription.version == 2
        assert db.query(McpCapabilitySubscription).count() == 1
    finally:
        db.close()


def test_disabling_resource_exposure_revokes_subscription() -> None:
    _engine, db = _db()
    uri = "https://provider.example/resources/revocable"
    try:
        _server(db)
        entity, revision = _catalog(db, uri)
        exposure = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="revoke-exposure-create",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        subscription = subscribe_resource(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            uri=uri,
        )
        upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="revoke-exposure-disable",
            expected_version=exposure.version,
            revision_id=revision.id,
            mode="hidden",
            enabled=False,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        db.refresh(subscription)
        assert subscription.status == "revoked"
        assert subscription.version == 2
    finally:
        db.close()


def test_thin_client_disconnect_revokes_only_bound_server_subscriptions() -> None:
    _engine, db = _db()
    client_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    client_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    server_a = "22222222-2222-4222-8222-222222222222"
    server_b = "33333333-3333-4333-8333-333333333333"
    uri_a = "mcp://local-a/resources/report"
    uri_b = "mcp://local-b/resources/report"
    try:
        for server_id, client_id, slug, local_server_id in (
            (server_a, client_a, "phase-10-client-a", "local-a"),
            (server_b, client_b, "phase-10-client-b", "local-b"),
        ):
            db.add(
                McpServer(
                    id=server_id,
                    owner_subject=OWNER,
                    origin="thin_client",
                    thin_client_id=client_id,
                    runtime_id=f"runtime-{local_server_id}",
                    local_server_id=local_server_id,
                    display_name=slug,
                    normalized_slug=slug,
                    transport="stdio",
                    status="online",
                    trust_level="restricted",
                    capabilities={},
                    catalog_generation=0,
                    policy_generation=1,
                    version=1,
                )
            )
        db.flush()
        for server_id, uri in ((server_a, uri_a), (server_b, uri_b)):
            reconcile_resource_catalog(
                db,
                owner_subject=OWNER,
                server_id=server_id,
                protocol_version=PROTOCOL,
                catalog_generation=1,
                resources=[{"uri": uri, "name": "Report", "mimeType": "text/plain"}],
                resource_templates=[],
            )
        subscription_a = subscribe_resource(
            db, owner_subject=OWNER, server_id=server_a, uri=uri_a
        )
        subscription_b = subscribe_resource(
            db, owner_subject=OWNER, server_id=server_b, uri=uri_b
        )
        assert revoke_resource_subscriptions_for_thin_client(
            db, owner_subject=OWNER, thin_client_id=client_a
        ) == 1
        db.commit()
        db.refresh(subscription_a)
        db.refresh(subscription_b)
        assert (subscription_a.status, subscription_a.version) == ("revoked", 2)
        assert (subscription_b.status, subscription_b.version) == ("active", 1)
    finally:
        db.close()


def test_public_resource_binding_is_opaque_exact_and_live_verified() -> None:
    _engine, db = _db()
    upstream_uri = "file:///Users/example/private/research-notes.txt"
    try:
        _server(db)
        entity, revision = _catalog(db, upstream_uri)
        exposure = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="public-binding",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        public_uri = public_resource_uri(entity.id, revision.id)
        assert public_uri.startswith("mcp://gateway/resources/")
        assert "research-notes" not in public_uri
        assert "/Users/example/private" not in public_uri
        kind, parsed_entity, parsed_revision, arguments = parse_public_resource_uri(
            public_uri
        )
        assert (kind, parsed_entity, parsed_revision, arguments) == (
            "resource",
            entity.id,
            revision.id,
            {},
        )
        server, bound_entity, bound_revision, bound_exposure, args = (
            resolve_public_resource_binding(
                db,
                owner_subject=OWNER,
                uri=public_uri,
            )
        )
        assert (server.id, bound_entity.id, bound_revision.id, bound_exposure.id) == (
            SERVER_ID,
            entity.id,
            revision.id,
            exposure.id,
        )
        assert args == {}
        catalog = public_resource_catalog(
            db,
            owner_subject=OWNER,
            entity_kind="resource",
        )
        assert catalog[0]["uri"] == public_uri
        assert upstream_uri not in json.dumps(catalog)
        raw = {
            "uri": upstream_uri,
            "name": "Resource",
            "title": "Reviewed",
            "description": "Untrusted upstream metadata",
            "mimeType": "text/plain",
            "size": 128,
            "_meta": {
                "ui": {"resourceUri": "ui://not-forwarded/app.html"},
                "private": "drop-me",
            },
        }
        assert resolve_live_resource_uri(raw_descriptor=raw, revision=revision) == upstream_uri
        changed = dict(raw)
        changed["description"] = "changed after approval"
        with pytest.raises(McpResourceFederationError) as drift:
            resolve_live_resource_uri(raw_descriptor=changed, revision=revision)
        assert drift.value.code == "MCP_RESOURCE_SCHEMA_CHANGED"
    finally:
        db.close()


def test_public_resource_catalog_filters_role_scope_and_approval() -> None:
    _engine, db = _db()
    uri = "https://provider.example/resources/restricted"
    try:
        _server(db)
        entity, revision = _catalog(db, uri)
        exposure = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="policy-filter-create",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:resources:read",
            approval_class="none",
        )
        assert public_resource_catalog(
            db, owner_subject=OWNER, entity_kind="resource"
        ) == []
        allowed = public_resource_catalog(
            db,
            owner_subject=OWNER,
            entity_kind="resource",
            roles={"gateway-reader"},
            scopes={"mcp:resources:read"},
        )
        assert len(allowed) == 1
        updated = upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="policy-filter-approval",
            expected_version=exposure.version,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role="gateway-reader",
            required_scope="mcp:resources:read",
            approval_class="operator",
        )
        assert updated.approval_class == "operator"
        assert public_resource_catalog(
            db,
            owner_subject=OWNER,
            entity_kind="resource",
            roles={"gateway-reader"},
            scopes={"mcp:resources:read"},
        ) == []
    finally:
        db.close()


def test_resource_template_public_binding_uses_sdk_expansion_contract() -> None:
    _engine, db = _db()
    upstream_template = "https://provider.example/users/{user}/records{?format}"
    try:
        _server(db)
        reconcile_resource_catalog(
            db,
            owner_subject=OWNER,
            server_id=SERVER_ID,
            protocol_version=PROTOCOL,
            catalog_generation=1,
            resources=[],
            resource_templates=[
                {
                    "uriTemplate": upstream_template,
                    "name": "User records",
                    "description": "Scoped records",
                    "mimeType": "application/json",
                }
            ],
        )
        entity = db.query(McpCapabilityEntity).filter_by(
            owner_subject=OWNER,
            server_id=SERVER_ID,
            entity_kind="resource_template",
        ).one()
        revision = db.query(McpCapabilityEntityRevision).filter_by(
            id=entity.current_revision_id
        ).one()
        upsert_resource_exposure(
            db,
            owner_subject=OWNER,
            actor_subject="phase10-admin",
            entity_id=entity.id,
            idempotency_key="template-public",
            expected_version=0,
            revision_id=revision.id,
            mode="catalog_only",
            enabled=True,
            required_role=None,
            required_scope=None,
            approval_class="none",
        )
        public_template = public_resource_template_uri(
            entity.id, revision.id, revision.argument_schema
        )
        assert upstream_template not in public_template
        assert public_template.endswith("{?format,user}")
        expanded_public = public_template.replace(
            "{?format,user}", "?format=json&user=42"
        )
        server, got_entity, got_revision, _exposure, arguments = (
            resolve_public_resource_binding(
                db,
                owner_subject=OWNER,
                uri=expanded_public,
            )
        )
        assert server.id == SERVER_ID
        assert got_entity.id == entity.id
        assert got_revision.id == revision.id
        assert arguments == {"format": "json", "user": "42"}
        live_uri = resolve_live_resource_uri(
            raw_descriptor={
                "uriTemplate": upstream_template,
                "name": "User records",
                "description": "Scoped records",
                "mimeType": "application/json",
            },
            revision=revision,
            arguments=arguments,
        )
        assert live_uri == "https://provider.example/users/42/records?format=json"
    finally:
        db.close()
