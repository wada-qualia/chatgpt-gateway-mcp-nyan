from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
import socket
import time

import httpx
from mcp import types
import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from gateway_api.config import get_settings
from gateway_api.events import emit_event
from gateway_api.mcp_federation_runtime import (
    EndpointResolution,
    FederationBoundaryError,
    SlidingWindowLimiter,
    assert_pinned_peer,
    new_traceparent,
    parse_recursion_context,
    resolve_endpoint,
    sanitize_untrusted,
)
from gateway_api.mcp_presentation import (
    create_candidate_generation,
    publish_generation,
    record_projection_verification,
    rollback_generation,
)
from gateway_api.mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from gateway_api.realtime import RealtimeService
from gateway_api.models import (
    AuditEvent,
    Base,
    McpServer,
    OutboxEvent,
    RealtimeRoute,
    utcnow,
)


class _PeerStream:
    def __init__(self, address: str | None) -> None:
        self.address = address

    def get_extra_info(self, name: str):
        if name == "server_addr" and self.address is not None:
            return (self.address, 443)
        return None


def _manager(**overrides) -> UpstreamMcpManager:
    values = {
        "public_base_url": "https://gateway.example.test",
        "allow_private_networks": False,
        "allow_insecure_http": False,
        "gateway_instance_id": "gateway-a",
    }
    values.update(overrides)
    return UpstreamMcpManager(**values)


def _server(*, server_id: str = "server-a", owner: str = "tenant-a") -> McpServer:
    return McpServer(
        id=server_id,
        owner_subject=owner,
        origin="gateway",
        display_name="Phase 6 upstream",
        normalized_slug=server_id,
        transport="streamable_http",
        endpoint_url="https://mcp.example.test/mcp",
        status="online",
        trust_level="approved",
        capabilities={},
        catalog_generation=1,
        policy_generation=1,
        version=1,
    )


def _database(monkeypatch: pytest.MonkeyPatch) -> tuple[object, Session]:
    monkeypatch.setenv("GATEWAY_OUTBOX_ENABLED", "true")
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, Session(engine, expire_on_commit=False)


def test_resolve_endpoint_rejects_any_mixed_private_dns_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(FederationBoundaryError) as caught:
        asyncio.run(
            resolve_endpoint(
                "https://mcp.example.test/mcp",
                public_base_url="https://gateway.example.test",
                allow_private_networks=False,
                allow_insecure_http=False,
            )
        )
    assert caught.value.code == "MCP_SERVER_QUARANTINED"


def test_resolve_endpoint_rejects_self_recursion_before_dns() -> None:
    with pytest.raises(FederationBoundaryError) as caught:
        asyncio.run(
            resolve_endpoint(
                "https://gateway.example.test/mcp",
                public_base_url="https://gateway.example.test",
                allow_private_networks=False,
                allow_insecure_http=False,
            )
        )
    assert caught.value.code == "MCP_RECURSION_DETECTED"


def test_connection_peer_must_match_prevalidated_dns_answer_set() -> None:
    resolution = EndpointResolution(
        endpoint="https://mcp.example.test/mcp",
        scheme="https",
        hostname="mcp.example.test",
        port=443,
        addresses=frozenset({"93.184.216.34"}),
    )
    accepted = httpx.Response(
        200, extensions={"network_stream": _PeerStream("93.184.216.34")}
    )
    assert_pinned_peer(accepted, resolution)

    rebound = httpx.Response(
        200, extensions={"network_stream": _PeerStream("10.0.0.7")}
    )
    with pytest.raises(FederationBoundaryError) as caught:
        assert_pinned_peer(rebound, resolution)
    assert caught.value.code == "MCP_DNS_REBINDING_DETECTED"

    unverifiable = httpx.Response(200, extensions={"network_stream": _PeerStream(None)})
    with pytest.raises(FederationBoundaryError) as caught:
        assert_pinned_peer(unverifiable, resolution)
    assert caught.value.http_status == 502


def test_traceparent_continuity_and_recursion_envelope() -> None:
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    child = new_traceparent(parent)
    assert child.startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    assert child != parent

    context = parse_recursion_context(
        {
            "X-Gateway-MCP-Instance": "gateway-b",
            "X-Gateway-MCP-Hop": "1",
            "X-Gateway-MCP-Visited": "gateway-b",
        },
        instance_id="gateway-a",
        max_hops=4,
    )
    outbound = context.outbound_headers("gateway-a", child)
    assert outbound["traceparent"] == child
    assert outbound["X-Gateway-MCP-Hop"] == "2"
    assert outbound["X-Gateway-MCP-Visited"] == "gateway-b,gateway-a"

    with pytest.raises(FederationBoundaryError) as caught:
        parse_recursion_context(
            {
                "X-Gateway-MCP-Instance": "gateway-b",
                "X-Gateway-MCP-Hop": "2",
                "X-Gateway-MCP-Visited": "gateway-b,gateway-a",
            },
            instance_id="gateway-a",
            max_hops=4,
        )
    assert caught.value.code == "MCP_RECURSION_DETECTED"


def test_recursion_hop_limit_is_fail_closed() -> None:
    with pytest.raises(FederationBoundaryError) as caught:
        parse_recursion_context(
            {"X-Gateway-MCP-Hop": "4"},
            instance_id="gateway-a",
            max_hops=4,
        )
    assert caught.value.code == "MCP_RECURSION_DETECTED"
    assert caught.value.http_status == 409


def test_untrusted_metadata_is_bounded_and_control_characters_are_removed() -> None:
    nested: object = "leaf"
    for _ in range(12):
        nested = {"next": nested}
    sanitized = sanitize_untrusted(
        {
            "title\u0000": "  unsafe\u0000 title  ",
            "long": "x" * 100,
            "items": list(range(150)),
            "nested": nested,
        },
        max_string=12,
    )
    assert sanitized["title"] == "unsafe  titl"
    assert sanitized["long"] == "x" * 12
    assert len(sanitized["items"]) == 100
    assert "[depth-limited]" in repr(sanitized["nested"])


def test_sliding_window_quota_recovers_after_window() -> None:
    limiter = SlidingWindowLimiter(window_seconds=10)
    assert limiter.acquire("tenant-a", 2, now=100)
    assert limiter.acquire("tenant-a", 2, now=101)
    assert not limiter.acquire("tenant-a", 2, now=102)
    assert limiter.acquire("tenant-a", 2, now=111)
    assert limiter.acquire("tenant-b", 2, now=102)


def test_manager_enforces_emergency_disable_and_tenant_rate_quota() -> None:
    server = _server()
    disabled = _manager(federation_enabled=False)

    async def disabled_call() -> None:
        async with disabled._bounded(server):
            raise AssertionError("disabled federation must not execute")

    with pytest.raises(UpstreamMcpError) as caught:
        asyncio.run(disabled_call())
    assert caught.value.code == "MCP_FEDERATION_DISABLED"

    limited = _manager(
        calls_per_minute_per_server=10,
        calls_per_minute_per_tenant=1,
    )

    async def accepted_call() -> None:
        async with limited._bounded(server):
            assert limited.telemetry.active_calls == 1

    asyncio.run(accepted_call())
    assert limited.telemetry.active_calls == 0
    with pytest.raises(UpstreamMcpError) as caught:
        asyncio.run(accepted_call())
    assert caught.value.code == "MCP_QUOTA_EXCEEDED"
    assert caught.value.http_status == 429


def test_circuit_breaker_is_per_server_and_uses_exponential_open_intervals() -> None:
    manager = _manager(
        circuit_failure_threshold=1,
        circuit_open_seconds=1,
        circuit_max_open_seconds=8,
    )
    error = UpstreamMcpError(
        "MCP_SERVER_OFFLINE", "offline", retryable=True, http_status=503
    )

    before = time.monotonic()
    manager._record_failure("server-a", error)
    first = manager._circuits["server-a"]
    first_delay = first.open_until_monotonic - before
    assert first.state == "open"
    assert 0.8 <= first_delay <= 1.5
    assert manager.circuit_state("server-b") == "closed"

    first.open_until_monotonic = 0
    before = time.monotonic()
    manager._record_failure("server-a", error)
    second_delay = first.open_until_monotonic - before
    assert 1.8 <= second_delay <= 2.5

    manager._record_success("server-a")
    assert manager.circuit_state("server-a") == "closed"


def test_optional_upstream_health_is_reported_without_becoming_readiness_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, db = _database(monkeypatch)
    try:
        server = _server()
        server.status = "offline"
        server.last_catalog_refreshed_at = None
        db.add(server)
        db.commit()

        snapshot = _manager(catalog_stale_after_seconds=60).readiness_snapshot(db)
        assert snapshot["servers"] == {"offline": 1}
        assert snapshot["circuits"] == {"closed": 1}
        assert snapshot["stale_catalogs"] == 1
        assert "status" not in snapshot
    finally:
        db.close()
        engine.dispose()
        get_settings.cache_clear()


def test_prometheus_metrics_use_bounded_low_cardinality_dimensions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, db = _database(monkeypatch)
    try:
        db.add(_server())
        db.commit()
        manager = _manager()
        manager.telemetry.increment("quota_rejected", scope="tenant")
        manager.telemetry.observe_latency("tool_call", "succeeded", 0.25)
        metrics = "\n".join(manager.prometheus_lines(db))
        assert 'gateway_mcp_servers{status="online"} 1' in metrics
        assert 'gateway_mcp_circuits{state="closed"} 1' in metrics
        assert 'event="quota_rejected",scope="tenant"' in metrics
        assert 'operation="tool_call",outcome="succeeded"' in metrics
        assert "tenant-a" not in metrics
        assert "server-a" not in metrics
    finally:
        db.close()
        engine.dispose()
        get_settings.cache_clear()


def test_audit_and_outbox_are_atomic_tenant_scoped_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, db = _database(monkeypatch)
    try:
        emit_event(
            db,
            event_type="gateway.mcp.invocation.completed.v1",
            actor_subject="operator-a",
            owner_subject="tenant-a",
            action="mcp.invocation.completed",
            resource_type="mcp_invocation",
            resource_id="invocation-a",
            payload={
                "invocation_id": "invocation-a",
                "server_id": "server-a",
                "revision_id": "revision-a",
                "schema_hash": "a" * 64,
                "outcome": "succeeded",
                "serialized_bytes": 128,
                "truncated": False,
            },
            commit=False,
        )
        db.rollback()
        assert db.scalar(select(AuditEvent)) is None
        assert db.scalar(select(OutboxEvent)) is None

        emit_event(
            db,
            event_type="gateway.mcp.invocation.completed.v1",
            actor_subject="operator-a",
            owner_subject="tenant-a",
            action="mcp.invocation.completed",
            resource_type="mcp_invocation",
            resource_id="invocation-a",
            payload={
                "invocation_id": "invocation-a",
                "server_id": "server-a",
                "revision_id": "revision-a",
                "schema_hash": "a" * 64,
                "outcome": "succeeded",
                "serialized_bytes": 128,
                "truncated": False,
            },
            commit=False,
        )
        db.commit()

        audit = db.scalar(select(AuditEvent))
        outbox = db.scalar(select(OutboxEvent))
        assert audit is not None
        assert outbox is not None
        assert outbox.audit_event_id == audit.id
        assert outbox.owner_subject == "tenant-a"
        assert outbox.headers["Nats-Msg-Id"] == audit.id
        assert outbox.payload["event_id"] == audit.id
        serialized = repr(outbox.payload).lower()
        assert "credential" not in serialized
        assert "authorization" not in serialized
        assert "tool_result" not in serialized
    finally:
        db.close()
        engine.dispose()
        get_settings.cache_clear()


def test_projection_lifecycle_events_are_transactional_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, db = _database(monkeypatch)
    try:
        first = create_candidate_generation(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            profile_id="developer-dynamic",
            reserved_names=[],
        )
        publish_generation(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            generation_id=first.id,
        )
        record_projection_verification(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            generation_id=first.id,
            verification_kind="generic_tools_list_changed",
            observed_schema_hash=first.schema_hash,
            evidence={"raw_probe_output": "must-not-enter-outbox"},
        )
        second = create_candidate_generation(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            profile_id="developer-dynamic",
            reserved_names=[],
        )
        publish_generation(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            generation_id=second.id,
        )
        rollback_generation(
            db,
            owner_subject="tenant-a",
            actor_subject="operator-a",
            generation_id=first.id,
        )

        expected = {
            "gateway.mcp.projection.candidate_created.v1",
            "gateway.mcp.projection.published.v1",
            "gateway.mcp.projection.verified.v1",
            "gateway.mcp.projection.rolled_back.v1",
        }
        audit_types = set(db.scalars(select(AuditEvent.event_type)).all())
        assert expected.issubset(audit_types)
        rows = db.scalars(
            select(OutboxEvent).where(OutboxEvent.event_type.in_(expected))
        ).all()
        assert rows
        assert all(row.owner_subject == "tenant-a" for row in rows)
        assert all(row.headers["X-Gateway-Owner-Subject"] == "tenant-a" for row in rows)
        repository_root = Path(__file__).resolve().parents[3]
        for row in rows:
            schema_path = repository_root / "schemas" / f"{row.event_type}.schema.json"
            schema = json.loads(schema_path.read_text())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(row.payload)
        verification = next(
            row
            for row in rows
            if row.event_type == "gateway.mcp.projection.verified.v1"
        )
        assert verification.payload["evidence_field_count"] == 1
        serialized = repr(verification.payload)
        assert "raw_probe_output" not in serialized
        assert "must-not-enter-outbox" not in serialized
    finally:
        db.close()
        engine.dispose()
        get_settings.cache_clear()


def test_federation_realtime_fanout_is_tenant_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, db = _database(monkeypatch)
    try:
        now = utcnow()
        db.add_all(
            [
                RealtimeRoute(
                    id="route-a",
                    owner_subject="tenant-a",
                    target_kind="agent",
                    target_id="agent-a",
                    connection_id="connection-a",
                    replica_id="replica-a",
                    status="online",
                    meta={},
                    connected_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(minutes=5),
                ),
                RealtimeRoute(
                    id="route-b",
                    owner_subject="tenant-b",
                    target_kind="agent",
                    target_id="agent-b",
                    connection_id="connection-b",
                    replica_id="replica-a",
                    status="online",
                    meta={},
                    connected_at=now,
                    last_seen_at=now,
                    expires_at=now + timedelta(minutes=5),
                ),
            ]
        )
        db.commit()
        targets = RealtimeService._target_agent_ids(
            db,
            {
                "event_type": "gateway.mcp.catalog.refreshed.v1",
                "actor_subject": "platform-admin",
                "owner_subject": "tenant-a",
                "payload": {"server_id": "server-a"},
            },
            "replica-a",
        )
        assert targets == ["agent-a"]
    finally:
        db.close()
        engine.dispose()
        get_settings.cache_clear()


def test_oversized_results_are_truncated_then_rejected_at_hard_limit() -> None:
    truncating = _manager(
        max_result_bytes=4096,
        max_text_bytes=5,
        max_content_items=1,
    )
    bounded = truncating._limit_result(
        types.CallToolResult(
            content=[
                types.TextContent(type="text", text="abcdefghij"),
                types.TextContent(type="text", text="second"),
            ]
        )
    )
    assert bounded.truncated is True
    assert bounded.payload["content"] == [
        {
            "type": "text",
            "text": "abcde",
            "annotations": None,
            "_meta": None,
        }
    ]
    assert bounded.payload["_gateway"]["truncated"] is True

    rejecting = _manager(
        max_result_bytes=80,
        max_text_bytes=4096,
        max_content_items=4,
    )
    with pytest.raises(UpstreamMcpError) as captured:
        rejecting._limit_result(
            types.CallToolResult(
                content=[types.TextContent(type="text", text="x" * 256)]
            )
        )
    assert captured.value.code == "MCP_RESULT_TOO_LARGE"
    assert captured.value.http_status == 413


def test_disabled_global_federation_allows_only_explicit_pilot_tenant() -> None:
    manager = _manager(
        federation_enabled=False,
        pilot_owner_subjects={"tenant-a"},
        calls_per_minute_per_server=0,
        calls_per_minute_per_tenant=0,
    )

    async def scenario() -> None:
        assert manager.federation_enabled_for("tenant-a") is True
        assert manager.federation_enabled_for("tenant-b") is False
        async with manager._bounded(_server(owner="tenant-a")):
            pass
        with pytest.raises(UpstreamMcpError) as captured:
            async with manager._bounded(_server(owner="tenant-b")):
                pass
        assert captured.value.code == "MCP_FEDERATION_DISABLED"
        assert captured.value.http_status == 503

    asyncio.run(scenario())
