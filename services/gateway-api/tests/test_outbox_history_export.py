from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def test_export_outbox_history_batch_is_terminal_complete_and_non_mutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'gateway.db'}")
    monkeypatch.setenv("GATEWAY_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GATEWAY_JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("GATEWAY_DEV_AUTH", "true")
    monkeypatch.setenv("GATEWAY_DOCKER_ENABLED", "false")

    from gateway_api import config, database
    from gateway_api.schema_migrations import run_schema_migrations

    config.get_settings.cache_clear()
    settings = config.get_settings()
    database.engine.dispose()
    database.engine = database.create_engine(
        settings.database_url,
        pool_pre_ping=True,
        **database._engine_args(settings.database_url),
    )
    database.SessionLocal.configure(bind=database.engine)
    run_schema_migrations(database.engine)

    from gateway_api.models import (
        AuditEvent,
        OutboxDeliveryAttempt,
        OutboxEvent,
        RealtimeNotification,
    )

    script_path = Path(__file__).resolve().parents[3] / "scripts" / "export_outbox_history_batch.py"
    spec = importlib.util.spec_from_file_location("export_outbox_history_batch", script_path)
    assert spec is not None and spec.loader is not None
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    monkeypatch.setattr(exporter, "SessionLocal", database.SessionLocal)
    old_time = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    recent_time = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    cutoff = datetime(2026, 8, 1, 0, 0, tzinfo=UTC)

    with database.SessionLocal() as session:
        session.add_all(
            [
                AuditEvent(
                    id="audit-export-published",
                    event_type="gateway.history.test.v1",
                    actor_subject="dev:local",
                    action="publish",
                    resource_type="outbox",
                    resource_id="export-published",
                    status="success",
                    payload={},
                    created_at=old_time,
                ),
                AuditEvent(
                    id="audit-export-published-z",
                    event_type="gateway.history.test.v1",
                    actor_subject="dev:local",
                    action="publish",
                    resource_type="outbox",
                    resource_id="export-published-z",
                    status="success",
                    payload={},
                    created_at=old_time,
                ),
                AuditEvent(
                    id="audit-export-pending",
                    event_type="gateway.history.test.v1",
                    actor_subject="dev:local",
                    action="enqueue",
                    resource_type="outbox",
                    resource_id="export-pending",
                    status="success",
                    payload={},
                    created_at=old_time,
                ),
                AuditEvent(
                    id="audit-export-recent",
                    event_type="gateway.history.test.v1",
                    actor_subject="dev:local",
                    action="publish",
                    resource_type="outbox",
                    resource_id="export-recent",
                    status="success",
                    payload={},
                    created_at=recent_time,
                ),
            ]
        )
        session.add_all(
            [
                OutboxEvent(
                    id="export-published",
                    audit_event_id="audit-export-published",
                    owner_subject="dev:local",
                    event_type="gateway.history.test.v1",
                    subject="gateway.events.export-published",
                    payload={"tier": "archive", "value": 1},
                    headers={"trace": "published"},
                    status="published",
                    attempt_count=1,
                    max_attempts=10,
                    available_at=old_time,
                    published_at=old_time + timedelta(seconds=2),
                    broker_stream="GATEWAY_EVENTS",
                    broker_sequence=101,
                    replay_count=0,
                    created_at=old_time,
                    updated_at=old_time + timedelta(seconds=2),
                ),
                OutboxEvent(
                    id="export-published-z",
                    audit_event_id="audit-export-published-z",
                    owner_subject="dev:local",
                    event_type="gateway.history.test.v1",
                    subject="gateway.events.export-published-z",
                    payload={"tier": "archive", "value": 2},
                    headers={"trace": "published-z"},
                    status="published",
                    attempt_count=0,
                    max_attempts=10,
                    available_at=old_time,
                    published_at=old_time + timedelta(seconds=4),
                    replay_count=0,
                    created_at=old_time,
                    updated_at=old_time + timedelta(seconds=4),
                ),
                OutboxEvent(
                    id="export-pending",
                    audit_event_id="audit-export-pending",
                    owner_subject="dev:local",
                    event_type="gateway.history.test.v1",
                    subject="gateway.events.export-pending",
                    payload={"tier": "hot"},
                    headers={},
                    status="pending",
                    attempt_count=0,
                    max_attempts=10,
                    available_at=old_time,
                    replay_count=0,
                    created_at=old_time,
                    updated_at=old_time,
                ),
                OutboxEvent(
                    id="export-recent",
                    audit_event_id="audit-export-recent",
                    owner_subject="dev:local",
                    event_type="gateway.history.test.v1",
                    subject="gateway.events.export-recent",
                    payload={"tier": "hot"},
                    headers={},
                    status="published",
                    attempt_count=0,
                    max_attempts=10,
                    available_at=recent_time,
                    published_at=recent_time,
                    replay_count=0,
                    created_at=recent_time,
                    updated_at=recent_time,
                ),
            ]
        )
        session.flush()
        session.add(
            OutboxDeliveryAttempt(
                id="export-attempt",
                outbox_event_id="export-published",
                attempt_number=1,
                replica_id="gateway-green",
                status="published",
                broker_stream="GATEWAY_EVENTS",
                broker_sequence=101,
                started_at=old_time + timedelta(seconds=1),
                completed_at=old_time + timedelta(seconds=2),
            )
        )
        session.add(
            RealtimeNotification(
                id="export-notification",
                owner_subject="dev:local",
                target_kind="agent",
                target_id="agent-1",
                event_type="gateway.history.test.v1",
                payload={"event_id": "export-published"},
                status="delivered",
                replica_id="gateway-green",
                outbox_event_id="export-published",
                attempt_count=1,
                delivered_at=old_time + timedelta(seconds=3),
                created_at=old_time + timedelta(seconds=2),
                updated_at=old_time + timedelta(seconds=3),
            )
        )
        session.commit()
        before_event_count = session.query(OutboxEvent).count()
        before_attempt_count = session.query(OutboxDeliveryAttempt).count()
        before_notification_count = session.query(RealtimeNotification).count()

    batch_id = str(uuid.uuid4())
    batch_path, manifest_path, manifest = exporter.export_batch(
        output_dir=tmp_path / "export",
        before=cutoff,
        limit=1,
        batch_id=batch_id,
        gateway_revision="1" * 40,
    )

    assert manifest["schema"] == "gateway.outbox.history.batch.v1"
    assert manifest["batch_id"] == batch_id
    assert manifest["event_count"] == 1
    assert manifest["attempt_count"] == 1
    assert manifest["realtime_reference_count"] == 1
    assert manifest["selection"]["after"] is None
    assert manifest["resume_after"] == {
        "created_at": old_time.isoformat(),
        "id": "export-published",
    }
    assert manifest["event_created_at"] == {
        "min": old_time.isoformat(),
        "max": old_time.isoformat(),
    }
    assert manifest["attempt_started_at"] == {
        "min": (old_time + timedelta(seconds=1)).isoformat(),
        "max": (old_time + timedelta(seconds=1)).isoformat(),
    }
    assert manifest["plaintext"]["size_bytes"] == batch_path.stat().st_size
    assert manifest["plaintext"]["sha256"] == hashlib.sha256(batch_path.read_bytes()).hexdigest()
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest

    connection = sqlite3.connect(batch_path)
    connection.row_factory = sqlite3.Row
    events = connection.execute("SELECT * FROM events ORDER BY created_at,id").fetchall()
    attempts = connection.execute("SELECT * FROM attempts ORDER BY attempt_number,id").fetchall()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    connection.close()
    assert integrity == "ok"
    assert [row["id"] for row in events] == ["export-published"]
    assert json.loads(events[0]["payload_json"]) == {"tier": "archive", "value": 1}
    assert [row["id"] for row in attempts] == ["export-attempt"]
    assert attempts[0]["outbox_event_id"] == "export-published"

    next_batch_path, _, next_manifest = exporter.export_batch(
        output_dir=tmp_path / "export",
        before=cutoff,
        limit=1,
        batch_id=str(uuid.uuid4()),
        gateway_revision="1" * 40,
        after_created_at=old_time,
        after_id="export-published",
    )
    assert next_manifest["selection"]["after"] == {
        "created_at": old_time.isoformat(),
        "id": "export-published",
    }
    assert next_manifest["resume_after"] == {
        "created_at": old_time.isoformat(),
        "id": "export-published-z",
    }
    assert next_manifest["event_count"] == 1
    assert next_manifest["attempt_count"] == 0
    assert next_manifest["realtime_reference_count"] == 0
    next_connection = sqlite3.connect(next_batch_path)
    next_events = next_connection.execute(
        "SELECT id FROM events ORDER BY created_at,id"
    ).fetchall()
    next_connection.close()
    assert [row[0] for row in next_events] == ["export-published-z"]

    with database.SessionLocal() as session:
        assert session.query(OutboxEvent).count() == before_event_count
        assert session.query(OutboxDeliveryAttempt).count() == before_attempt_count
        assert session.query(RealtimeNotification).count() == before_notification_count
        assert db_event_status(session, OutboxEvent, "export-published") == "published"
        assert db_event_status(session, OutboxEvent, "export-published-z") == "published"
        assert db_event_status(session, OutboxEvent, "export-pending") == "pending"
        assert db_event_status(session, OutboxEvent, "export-recent") == "published"


def db_event_status(session, model, event_id: str) -> str:
    row = session.get(model, event_id)
    assert row is not None
    return str(row.status)
