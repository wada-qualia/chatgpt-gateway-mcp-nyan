from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from gateway_api.mcp_root_federation import (
    McpRootFederationError,
    approved_root_grants,
    normalize_root_candidate,
    reconcile_runtime_root_candidates,
    review_root_grant,
    root_grant_set_sha256,
    root_sync_set_sha256,
    thin_root_sync_payload,
)
from gateway_api.models import Base, McpRootGrant, McpRuntimeConnection, McpServer
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fixture(db: Session, *, owner: str = "root-owner") -> tuple[McpServer, McpRuntimeConnection]:
    server = McpServer(
        id="11111111-1111-4111-8111-111111111111",
        owner_subject=owner,
        origin="thin_client",
        thin_client_id="22222222-2222-4222-8222-222222222222",
        runtime_id="runtime-a",
        local_server_id="local-a",
        display_name="Root fixture",
        normalized_slug="root-fixture",
        transport="stdio",
        status="online",
        trust_level="restricted",
        capabilities={},
        catalog_generation=4,
        policy_generation=3,
        version=1,
    )
    db.add(server)
    db.flush([server])
    runtime = McpRuntimeConnection(
        id="33333333-3333-4333-8333-333333333333",
        owner_subject=owner,
        server_id=server.id,
        thin_client_id=server.thin_client_id,
        runtime_id=server.runtime_id,
        connection_instance_id="connection-a",
        supported_transports=["stdio"],
        supported_protocol_versions=["2025-11-25"],
        state="online",
        acknowledged_catalog_generation=4,
        meta={},
    )
    db.add(runtime)
    db.flush([runtime])
    return server, runtime


def _candidate(uri: str, *, name: str = "Workspace") -> dict[str, str]:
    digest = _digest(uri)
    return {
        "root_uri_sha256": digest,
        "root_uri_hint": f"local-root:{digest[:12]}",
        "root_name": name,
    }


def test_root_candidate_is_hash_only_and_rejects_host_path_leakage() -> None:
    candidate = _candidate("file:///home/user/project")
    normalized = normalize_root_candidate(candidate)
    assert normalized == candidate
    assert "file:" not in repr(normalized)

    with pytest.raises(McpRootFederationError, match="unsupported fields") as extra:
        normalize_root_candidate({**candidate, "uri": "file:///home/user/project"})
    assert extra.value.code == "MCP_ROOT_DESCRIPTOR_INVALID"

    with pytest.raises(McpRootFederationError, match="path separators"):
        normalize_root_candidate({**candidate, "root_name": r"C:\\Users\\secret"})

    with pytest.raises(McpRootFederationError, match="hash-derived"):
        normalize_root_candidate({**candidate, "root_uri_hint": "local-root:aaaaaaaaaaaa"})


def test_reconcile_is_runtime_bound_and_revokes_disappeared_candidates() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server, runtime = _fixture(db)
        first = _candidate("file:///project/a", name="Project A")
        second = _candidate("file:///project/b", name="Project B")

        grants = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
            candidates=[first, second],
        )
        assert [grant.status for grant in grants] == ["pending", "pending"]
        assert all(grant.runtime_connection_id == runtime.id for grant in grants)
        assert all("file:" not in repr({
            "root_uri_sha256": grant.root_uri_sha256,
            "root_uri_hint": grant.root_uri_hint,
            "root_name": grant.root_name,
        }) for grant in grants)

        with pytest.raises(McpRootFederationError, match="duplicate identities"):
            reconcile_runtime_root_candidates(
                db,
                owner_subject=server.owner_subject,
                server=server,
                runtime=runtime,
                candidates=[first, first],
            )

        reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
            candidates=[second],
        )
        stale = (
            db.query(McpRootGrant)
            .filter(McpRootGrant.root_uri_sha256 == first["root_uri_sha256"])
            .one()
        )
        assert stale.status == "revoked"


def test_approved_grant_is_fenced_by_policy_and_runtime_reconnect() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server, runtime = _fixture(db)
        candidate = _candidate("file:///project/a")
        grant = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
            candidates=[candidate],
        )[0]
        grant = review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="approved",
        )
        assert grant.status == "approved"
        assert approved_root_grants(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
        ) == [grant]

        runtime.state = "stale"
        replacement = McpRuntimeConnection(
            id="44444444-4444-4444-8444-444444444444",
            owner_subject=server.owner_subject,
            server_id=server.id,
            thin_client_id=server.thin_client_id,
            runtime_id=server.runtime_id,
            connection_instance_id="connection-b",
            supported_transports=["stdio"],
            supported_protocol_versions=["2025-11-25"],
            state="online",
            acknowledged_catalog_generation=4,
            meta={},
        )
        db.add(replacement)
        db.flush([runtime, replacement])
        rebound = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=replacement,
            candidates=[candidate],
        )[0]
        assert rebound.id == grant.id
        assert rebound.status == "pending"
        assert rebound.runtime_connection_id == replacement.id
        assert rebound.granted_by_subject is None
        assert rebound.granted_at is None
        assert approved_root_grants(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=replacement,
        ) == []

        version = rebound.version
        server.policy_generation += 1
        db.flush([server])
        rebound = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=replacement,
            candidates=[candidate],
        )[0]
        assert rebound.status == "pending"
        assert rebound.policy_generation == server.policy_generation
        assert rebound.version == version + 1


def test_review_and_sync_fail_closed_for_stale_or_expired_authority() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server, runtime = _fixture(db)
        grant = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
            candidates=[_candidate("file:///project/a")],
        )[0]

        with pytest.raises(McpRootFederationError, match="optimistic version conflict"):
            review_root_grant(
                db,
                owner_subject=server.owner_subject,
                actor_subject="gateway-admin",
                grant_id=grant.id,
                expected_version=grant.version + 1,
                decision="approved",
            )

        grant = review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="approved",
        )
        grant.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.flush([grant])
        assert approved_root_grants(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
        ) == []

        grant.expires_at = None
        db.flush([grant])
        approved = approved_root_grants(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
        )
        payload = thin_root_sync_payload(server=server, runtime=runtime, grants=approved)
        assert payload["type"] == "mcp_roots_update"
        assert payload["connection_instance_id"] == runtime.connection_instance_id
        assert payload["runtime_id"] == server.runtime_id
        assert payload["local_server_id"] == server.local_server_id
        assert payload["policy_generation"] == server.policy_generation
        assert payload["root_set_sha256"] == root_sync_set_sha256(
            policy_generation=server.policy_generation, roots=payload["roots"]
        )
        assert payload["root_set_sha256"] != root_grant_set_sha256(approved)
        assert payload["roots"] == [
            {
                "root_uri_sha256": grant.root_uri_sha256,
                "root_name": grant.root_name,
                "version": grant.version,
            }
        ]
        assert "file:" not in repr(payload)
        assert "uri" not in payload["roots"][0]


def test_revocation_survives_stale_policy_and_runtime() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        server, runtime = _fixture(db)
        grant = reconcile_runtime_root_candidates(
            db,
            owner_subject=server.owner_subject,
            server=server,
            runtime=runtime,
            candidates=[_candidate("file:///project/a")],
        )[0]
        grant = review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="approved",
        )
        runtime.state = "closed"
        server.policy_generation += 1
        db.flush([runtime, server])
        revoked = review_root_grant(
            db,
            owner_subject=server.owner_subject,
            actor_subject="gateway-admin",
            grant_id=grant.id,
            expected_version=grant.version,
            decision="revoked",
        )
        assert revoked.status == "revoked"
        assert revoked.granted_by_subject is None
        assert revoked.granted_at is None
