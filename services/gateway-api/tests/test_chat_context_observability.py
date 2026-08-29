from __future__ import annotations

from pathlib import Path

import pytest
from gateway_api.chat_context import ChatContextNotFound, ChatContextService
from gateway_api.chat_context_telemetry import ChatContextTelemetry
from gateway_api.config import Settings
from gateway_api.mcp_chat_context import (
    McpChatContextAdmissionError,
    admit_chat_context,
)
from gateway_api.metrics_cache import GatewayMetricsCache
from gateway_api.models import ChatContextEvent
from gateway_api.schema_migrations import run_schema_migrations
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

TEST_HMAC_KEY = "test-hmac-key-000000000000000000"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        gateway_chat_context_enabled=True,
        gateway_chat_context_hmac_key=TEST_HMAC_KEY,
        gateway_chat_context_ttl_seconds=300,
        gateway_chat_context_renew_threshold_seconds=60,
        gateway_chat_context_quarantine_seconds=3600,
        gateway_chat_context_allocation_attempts=8,
        gateway_storage_monitor_path=str(tmp_path),
    )


def _factory(*values: str):
    iterator = iter(values)
    return lambda: next(iterator)


def _session_factory(tmp_path: Path) -> tuple[sessionmaker, object]:
    engine = create_engine(f"sqlite:///{tmp_path / 'observability.sqlite'}")
    run_schema_migrations(engine)
    return sessionmaker(bind=engine, expire_on_commit=False), engine


def test_telemetry_accepts_only_fixed_bounded_dimensions() -> None:
    telemetry = ChatContextTelemetry()
    telemetry.record_allocation("success", retries=2)
    telemetry.record_resolution("success")
    telemetry.record_rejection("required")
    telemetry.record_rotation()

    assert telemetry.snapshot() == {
        "allocations": {"success": 1, "exhausted": 0},
        "allocation_retries": 2,
        "resolutions": {
            "success": 1,
            "not_found": 0,
            "expired": 0,
            "closed": 0,
            "invalid": 0,
        },
        "rejections": {
            "required": 1,
            "invalid": 0,
            "unknown": 0,
            "expired": 0,
            "revoked": 0,
            "allocation_exhausted": 0,
        },
        "rotations": 1,
    }

    with pytest.raises(ValueError, match="unsupported"):
        telemetry.record_allocation("owner-controlled")
    with pytest.raises(ValueError, match="unsupported"):
        telemetry.record_resolution("AAAA")
    with pytest.raises(ValueError, match="unsupported"):
        telemetry.record_rejection("user@example.test")


def test_collision_retries_and_rejections_are_counted_without_sensitive_labels(
    tmp_path: Path,
) -> None:
    factory, engine = _session_factory(tmp_path)
    settings = _settings(tmp_path)
    telemetry = ChatContextTelemetry()
    try:
        with factory() as db:
            first = ChatContextService(
                settings,
                code_factory=_factory("AAAA"),
                telemetry=telemetry,
            ).start_context(db, owner_subject="owner-a")
            db.commit()

            second = ChatContextService(
                settings,
                code_factory=_factory("AAAA", "BBBB"),
                telemetry=telemetry,
            ).start_context(db, owner_subject="owner-b")
            db.commit()

            assert first.code == "AAAA"
            assert second.code == "BBBB"

            service = ChatContextService(settings, telemetry=telemetry)
            assert service.resolve_alias(
                db, owner_subject="owner-b", code="BBBB"
            ).context_id == second.context_id
            with pytest.raises(ChatContextNotFound):
                service.resolve_alias(db, owner_subject="owner-b", code="CCCC")

            with pytest.raises(McpChatContextAdmissionError):
                admit_chat_context(
                    db,
                    settings,
                    owner_subject="owner-b",
                    tool_name="thin_client_read_file",
                    arguments={},
                    mode="required",
                    telemetry=telemetry,
                )

            issued = db.scalars(
                select(ChatContextEvent).where(
                    ChatContextEvent.context_id == second.context_id,
                    ChatContextEvent.action == "issued",
                )
            ).one()
            assert issued.event_metadata["allocation_retries"] == 1

        snapshot = telemetry.snapshot()
        assert snapshot["allocations"] == {"success": 2, "exhausted": 0}
        assert snapshot["allocation_retries"] == 1
        assert snapshot["resolutions"]["success"] == 1
        assert snapshot["resolutions"]["not_found"] == 1
        assert snapshot["rejections"]["required"] == 1
        assert "owner-a" not in repr(snapshot)
        assert "owner-b" not in repr(snapshot)
        assert "AAAA" not in repr(snapshot)
        assert "BBBB" not in repr(snapshot)
    finally:
        engine.dispose()


def test_metrics_cache_exports_only_aggregate_chat_context_metrics(
    tmp_path: Path,
) -> None:
    factory, engine = _session_factory(tmp_path)
    settings = _settings(tmp_path)
    telemetry = ChatContextTelemetry()

    class FakeOutbox:
        replica_id = "test-replica"

        @staticmethod
        def metrics(_db: Session) -> dict:
            return {
                "replica_id": "test-replica",
                "broker_backend": "database",
                "outbox": {},
                "outbox_counts_estimated": False,
                "oldest_pending_age_seconds": 0.0,
                "dead_letter_total": 0,
                "online_replicas": 1,
                "online_realtime_routes": 0,
            }

    class FakeFederationTelemetry:
        @staticmethod
        def prometheus_lines() -> list[str]:
            return []

    class FakeUpstream:
        telemetry = FakeFederationTelemetry()

        @staticmethod
        def readiness_snapshot(_db: Session) -> dict:
            return {"servers": {}, "circuits": {}, "stale_catalogs": 0}

    try:
        with factory() as db:
            ChatContextService(
                settings,
                code_factory=_factory("AAAA"),
                telemetry=telemetry,
            ).start_context(db, owner_subject="owner-a")
            db.commit()

        cache = GatewayMetricsCache(
            settings=settings,
            session_factory=factory,
            outbox=FakeOutbox(),
            upstream_mcp_manager=FakeUpstream(),
            chat_context_telemetry=telemetry,
        )
        assert cache.refresh_sync() is True
        output = cache.prometheus()

        for metric in (
            "gateway_chat_context_allocations_total",
            "gateway_chat_context_allocation_retries_total",
            "gateway_chat_context_resolution_total",
            "gateway_chat_context_rejections_total",
            "gateway_chat_context_rotations_total",
            "gateway_chat_context_active_count 1",
        ):
            assert metric in output
        for forbidden in ("owner-a", "AAAA", "chat_context_id="):
            assert forbidden not in output
    finally:
        engine.dispose()
