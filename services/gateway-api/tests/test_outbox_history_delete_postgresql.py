from __future__ import annotations

import importlib.util
import json
import os
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from gateway_api.models import AuditEvent, OutboxDeliveryAttempt, OutboxEvent
from gateway_api.schema_migrations import run_schema_migrations
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv("GATEWAY_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="GATEWAY_TEST_POSTGRES_URL is required for PostgreSQL offload tests",
)


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pg_engine() -> Iterator[Engine]:
    assert POSTGRES_URL is not None
    base_url = make_url(POSTGRES_URL)
    database_name = f"gateway_offload_{uuid.uuid4().hex}"
    admin_engine = create_engine(
        base_url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
    )
    quoted_name = admin_engine.dialect.identifier_preparer.quote(database_name)
    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f"CREATE DATABASE {quoted_name}")
    target_engine = create_engine(base_url.set(database=database_name))
    try:
        run_schema_migrations(target_engine)
        yield target_engine
    finally:
        target_engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(f"DROP DATABASE {quoted_name}")
        admin_engine.dispose()


def test_postgresql_exact_batch_offload_is_transactional_and_audited(
    pg_engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_factory = sessionmaker(bind=pg_engine, expire_on_commit=False)
    created_at = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    with session_factory() as session:
        session.add(
            AuditEvent(
                id="pg-offload-audit",
                event_type="gateway.history.offload.pg-test.v1",
                actor_subject="test:producer",
                action="publish",
                resource_type="outbox",
                resource_id="pg-offload-event",
                status="success",
                payload={},
                created_at=created_at,
            )
        )
        session.add(
            OutboxEvent(
                id="pg-offload-event",
                audit_event_id="pg-offload-audit",
                owner_subject="test:owner",
                event_type="gateway.history.offload.pg-test.v1",
                subject="gateway.events.pg-offload-event",
                payload={"source": "postgresql"},
                headers={"trace": "pg-offload"},
                status="published",
                attempt_count=1,
                max_attempts=10,
                available_at=created_at,
                published_at=created_at + timedelta(seconds=1),
                broker_stream="GATEWAY_EVENTS",
                broker_sequence=701,
                replay_count=0,
                created_at=created_at,
                updated_at=created_at + timedelta(seconds=1),
            )
        )
        session.flush()
        session.add(
            OutboxDeliveryAttempt(
                id="pg-offload-attempt",
                outbox_event_id="pg-offload-event",
                attempt_number=1,
                replica_id="gateway-green",
                status="published",
                broker_stream="GATEWAY_EVENTS",
                broker_sequence=701,
                started_at=created_at,
                completed_at=created_at + timedelta(seconds=1),
            )
        )
        session.commit()

    scripts = Path(__file__).resolve().parents[3] / "scripts"
    exporter = load_script("pg_offload_exporter", scripts / "export_outbox_history_batch.py")
    deleter = load_script("pg_offload_deleter", scripts / "delete_outbox_history_batch.py")
    monkeypatch.setattr(exporter, "SessionLocal", session_factory)
    monkeypatch.setattr(deleter, "SessionLocal", session_factory)

    batch_id = str(uuid.uuid4())
    batch_path, _, manifest = exporter.export_batch(
        output_dir=tmp_path / "batch",
        before=created_at + timedelta(days=1),
        limit=1,
        batch_id=batch_id,
        gateway_revision="c" * 40,
    )
    snapshot = deleter.load_batch_snapshot(
        batch_path=batch_path,
        manifest=manifest,
        max_events=10,
    )
    receipt: dict[str, Any] = {
        "schema": "gateway.outbox.history.receipt.v1",
        "batch_id": batch_id,
        "durable": True,
        "queryable": True,
        "event_count": 1,
        "attempt_count": 1,
        "realtime_reference_count": 0,
        "plaintext_sha256": manifest["plaintext"]["sha256"],
        "ciphertext_sha256": "d" * 64,
        "ciphertext_size_bytes": int(manifest["plaintext"]["size_bytes"]) + 35,
        "encryption": "AES-256-GCM",
        "key_id": "gateway-history-pg-test",
        "imported_at": "2026-08-21T00:00:00+00:00",
    }
    evidence = tmp_path / "offload-evidence.json"

    result = deleter.validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision="c" * 40,
        actor_subject="test:operator",
        execute=True,
        evidence_output=evidence,
    )

    assert result["status"] == "offloaded"
    assert evidence.stat().st_mode & 0o777 == 0o600
    evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert evidence_payload["status"] == "offloaded"
    with session_factory() as session:
        assert session.get(OutboxEvent, "pg-offload-event") is None
        assert session.get(OutboxDeliveryAttempt, "pg-offload-attempt") is None
        assert session.get(AuditEvent, "pg-offload-audit") is not None
        offload_audit = (
            session.query(AuditEvent)
            .filter(
                AuditEvent.event_type == deleter.OFFLOAD_AUDIT_EVENT,
                AuditEvent.resource_id == batch_id,
            )
            .one()
        )
        assert offload_audit.id == result["audit_event_id"]
        assert offload_audit.payload["ciphertext_sha256"] == receipt["ciphertext_sha256"]
