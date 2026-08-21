from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def configure_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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
    return database


def seed_events(database: Any, *, count: int = 1) -> tuple[datetime, list[str]]:
    from gateway_api.models import AuditEvent, OutboxDeliveryAttempt, OutboxEvent

    created_at = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    event_ids: list[str] = []
    with database.SessionLocal() as session:
        for index in range(count):
            event_id = f"offload-event-{index}"
            audit_id = f"offload-audit-{index}"
            event_ids.append(event_id)
            session.add(
                AuditEvent(
                    id=audit_id,
                    event_type="gateway.history.offload.test.v1",
                    actor_subject="test:producer",
                    action="publish",
                    resource_type="outbox",
                    resource_id=event_id,
                    status="success",
                    payload={"index": index},
                    created_at=created_at + timedelta(seconds=index),
                )
            )
            session.add(
                OutboxEvent(
                    id=event_id,
                    audit_event_id=audit_id,
                    owner_subject="test:owner",
                    event_type="gateway.history.offload.test.v1",
                    subject=f"gateway.events.{event_id}",
                    payload={"index": index, "secret": "retained-in-cold"},
                    headers={"trace": f"trace-{index}"},
                    status="published",
                    attempt_count=1,
                    max_attempts=10,
                    available_at=created_at + timedelta(seconds=index),
                    published_at=created_at + timedelta(seconds=index + 1),
                    broker_stream="GATEWAY_EVENTS",
                    broker_sequence=100 + index,
                    replay_count=0,
                    created_at=created_at + timedelta(seconds=index),
                    updated_at=created_at + timedelta(seconds=index + 1),
                )
            )
        session.flush()
        for index, event_id in enumerate(event_ids):
            session.add(
                OutboxDeliveryAttempt(
                    id=f"offload-attempt-{index}",
                    outbox_event_id=event_id,
                    attempt_number=1,
                    replica_id="gateway-green",
                    status="published",
                    broker_stream="GATEWAY_EVENTS",
                    broker_sequence=100 + index,
                    started_at=created_at + timedelta(seconds=index),
                    completed_at=created_at + timedelta(seconds=index + 1),
                )
            )
        session.commit()
    return created_at, event_ids


def make_batch(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    count: int = 1,
):
    database = configure_database(tmp_path, monkeypatch)
    created_at, event_ids = seed_events(database, count=count)
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    exporter = load_script("offload_exporter", scripts / "export_outbox_history_batch.py")
    deleter = load_script("offload_deleter", scripts / "delete_outbox_history_batch.py")
    monkeypatch.setattr(exporter, "SessionLocal", database.SessionLocal)
    monkeypatch.setattr(deleter, "SessionLocal", database.SessionLocal)
    batch_id = str(uuid.uuid4())
    batch_path, manifest_path, manifest = exporter.export_batch(
        output_dir=tmp_path / "batch",
        before=created_at + timedelta(days=1),
        limit=count,
        batch_id=batch_id,
        gateway_revision="a" * 40,
    )
    snapshot = deleter.load_batch_snapshot(
        batch_path=batch_path,
        manifest=manifest,
        max_events=100,
    )
    receipt = {
        "schema": "gateway.outbox.history.receipt.v1",
        "batch_id": batch_id,
        "durable": True,
        "queryable": True,
        "event_count": manifest["event_count"],
        "attempt_count": manifest["attempt_count"],
        "realtime_reference_count": 0,
        "plaintext_sha256": manifest["plaintext"]["sha256"],
        "ciphertext_sha256": "b" * 64,
        "ciphertext_size_bytes": int(manifest["plaintext"]["size_bytes"]) + 35,
        "encryption": "AES-256-GCM",
        "key_id": "gateway-history-test-key",
        "imported_at": "2026-08-21T00:00:00+00:00",
    }
    return database, deleter, batch_path, manifest_path, manifest, snapshot, receipt, event_ids


def test_dry_run_validates_exact_batch_without_mutating_hot_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import AuditEvent, OutboxDeliveryAttempt, OutboxEvent

    database, deleter, _, _, manifest, snapshot, receipt, event_ids = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    result = deleter.validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision="a" * 40,
        actor_subject="test:operator",
        execute=False,
        evidence_output=None,
    )
    assert result == {
        "status": "validated",
        "batch_id": manifest["batch_id"],
        "event_count": 1,
        "attempt_count": 1,
    }
    with database.SessionLocal() as session:
        assert session.get(OutboxEvent, event_ids[0]) is not None
        assert session.query(OutboxDeliveryAttempt).count() == 1
        assert session.query(AuditEvent).count() == 1


def test_execute_offloads_exact_rows_preserves_source_audit_and_writes_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import AuditEvent, OutboxDeliveryAttempt, OutboxEvent

    database, deleter, _, _, manifest, snapshot, receipt, event_ids = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    evidence = tmp_path / "evidence" / "offload.json"
    result = deleter.validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision="a" * 40,
        actor_subject="test:operator",
        execute=True,
        evidence_output=evidence,
    )
    assert result["status"] == "offloaded"
    assert result["event_count"] == 1
    assert result["attempt_count"] == 1
    assert evidence.exists()
    assert evidence.stat().st_mode & 0o777 == 0o600
    evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert evidence_payload["status"] == "offloaded"
    assert evidence_payload["event_ids"] == event_ids
    assert "payload" not in evidence_payload
    assert evidence_payload["plaintext_sha256"] == manifest["plaintext"]["sha256"]
    assert evidence_payload["ciphertext_sha256"] == receipt["ciphertext_sha256"]

    with database.SessionLocal() as session:
        assert session.get(OutboxEvent, event_ids[0]) is None
        assert session.query(OutboxDeliveryAttempt).count() == 0
        assert session.get(AuditEvent, "offload-audit-0") is not None
        offload_audit = (
            session.query(AuditEvent)
            .filter(AuditEvent.event_type == deleter.OFFLOAD_AUDIT_EVENT)
            .one()
        )
        assert offload_audit.id == result["audit_event_id"]
        assert offload_audit.resource_id == manifest["batch_id"]
        assert offload_audit.payload["plaintext_sha256"] == manifest["plaintext"]["sha256"]


def test_execute_retry_reconciles_already_offloaded_batch_without_duplicate_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import AuditEvent

    database, deleter, _, _, manifest, snapshot, receipt, _ = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    evidence = tmp_path / "offload.json"
    first = deleter.validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision="a" * 40,
        actor_subject="test:operator",
        execute=True,
        evidence_output=evidence,
    )
    second = deleter.validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision="a" * 40,
        actor_subject="test:retry-operator",
        execute=True,
        evidence_output=evidence,
    )
    assert first["status"] == "offloaded"
    assert second == {
        "status": "already_offloaded",
        "batch_id": manifest["batch_id"],
        "event_count": 1,
        "attempt_count": 1,
        "audit_event_id": first["audit_event_id"],
    }
    reconciled_evidence = json.loads(evidence.read_text(encoding="utf-8"))
    assert reconciled_evidence["status"] == "reconciled"
    assert reconciled_evidence["actor_subject"] == "test:operator"
    with database.SessionLocal() as session:
        assert (
            session.query(AuditEvent)
            .filter(AuditEvent.event_type == deleter.OFFLOAD_AUDIT_EVENT)
            .count()
            == 1
        )


def test_hot_snapshot_drift_fails_closed_and_preserves_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent

    database, deleter, _, _, manifest, snapshot, receipt, event_ids = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    with database.SessionLocal() as session:
        row = session.get(OutboxEvent, event_ids[0])
        assert row is not None
        row.payload = {"index": 0, "changed_after_export": True}
        session.commit()

    with pytest.raises(ValueError, match="no longer matches"):
        deleter.validate_and_offload(
            manifest=manifest,
            snapshot=snapshot,
            receipt=receipt,
            expected_gateway_revision="a" * 40,
            actor_subject="test:operator",
            execute=True,
            evidence_output=tmp_path / "offload.json",
        )
    with database.SessionLocal() as session:
        assert session.get(OutboxEvent, event_ids[0]) is not None
        assert session.query(OutboxDeliveryAttempt).count() == 1


def test_live_realtime_reference_added_after_export_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import OutboxEvent, RealtimeNotification

    database, deleter, _, _, manifest, snapshot, receipt, event_ids = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    now = datetime(2026, 7, 2, 0, 0, tzinfo=UTC)
    with database.SessionLocal() as session:
        session.add(
            RealtimeNotification(
                id="late-realtime-reference",
                owner_subject="test:owner",
                target_kind="agent",
                target_id="agent-1",
                event_type="gateway.history.offload.test.v1",
                payload={},
                status="delivered",
                outbox_event_id=event_ids[0],
                attempt_count=1,
                delivered_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()

    with pytest.raises(ValueError, match="realtime notifications"):
        deleter.validate_and_offload(
            manifest=manifest,
            snapshot=snapshot,
            receipt=receipt,
            expected_gateway_revision="a" * 40,
            actor_subject="test:operator",
            execute=True,
            evidence_output=tmp_path / "offload.json",
        )
    with database.SessionLocal() as session:
        assert session.get(OutboxEvent, event_ids[0]) is not None
        assert session.query(RealtimeNotification).count() == 1


def test_missing_hot_rows_without_matching_offload_audit_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent

    database, deleter, _, _, manifest, snapshot, receipt, event_ids = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    with database.SessionLocal() as session:
        session.query(OutboxDeliveryAttempt).filter(
            OutboxDeliveryAttempt.outbox_event_id == event_ids[0]
        ).delete()
        session.query(OutboxEvent).filter(OutboxEvent.id == event_ids[0]).delete()
        session.commit()

    with pytest.raises(ValueError, match="no unique matching offload audit"):
        deleter.validate_and_offload(
            manifest=manifest,
            snapshot=snapshot,
            receipt=receipt,
            expected_gateway_revision="a" * 40,
            actor_subject="test:operator",
            execute=True,
            evidence_output=tmp_path / "offload.json",
        )


def test_fetch_remote_binding_rejects_manifest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, deleter, _, _, manifest, _, receipt, _ = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    remote_manifest = dict(manifest)
    remote_manifest["event_count"] = int(manifest["event_count"]) + 1

    class FakeResponse:
        def __init__(self, payload: dict[str, Any]) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.payload

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def get(self, path: str) -> FakeResponse:
            if path.endswith("/manifest"):
                return FakeResponse(remote_manifest)
            return FakeResponse(receipt)

    monkeypatch.setattr(deleter, "build_ssl_context", lambda **kwargs: object())
    monkeypatch.setattr(deleter.httpx, "Client", FakeClient)
    with pytest.raises(ValueError, match="does not exactly match"):
        deleter.fetch_remote_binding(
            base_url="https://history.example",
            manifest=manifest,
            ca_cert_path=Path("ca.crt"),
            client_cert_path=Path("reader.crt"),
            client_key_path=Path("reader.key"),
            timeout_seconds=10.0,
        )


def test_batch_with_export_time_realtime_reference_is_never_eligible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = configure_database(tmp_path, monkeypatch)
    created_at, event_ids = seed_events(database)
    from gateway_api.models import RealtimeNotification

    with database.SessionLocal() as session:
        session.add(
            RealtimeNotification(
                id="existing-realtime-reference",
                owner_subject="test:owner",
                target_kind="agent",
                target_id="agent-1",
                event_type="gateway.history.offload.test.v1",
                payload={},
                status="delivered",
                outbox_event_id=event_ids[0],
                attempt_count=1,
                delivered_at=created_at,
                created_at=created_at,
                updated_at=created_at,
            )
        )
        session.commit()

    scripts = Path(__file__).resolve().parents[3] / "scripts"
    exporter = load_script("referenced_exporter", scripts / "export_outbox_history_batch.py")
    deleter = load_script("referenced_deleter", scripts / "delete_outbox_history_batch.py")
    monkeypatch.setattr(exporter, "SessionLocal", database.SessionLocal)
    batch_path, _, manifest = exporter.export_batch(
        output_dir=tmp_path / "batch",
        before=created_at + timedelta(days=1),
        limit=1,
        batch_id=str(uuid.uuid4()),
        gateway_revision="a" * 40,
    )
    assert manifest["realtime_reference_count"] == 1
    with pytest.raises(ValueError, match="manifest contains realtime notification references"):
        deleter.load_batch_snapshot(
            batch_path=batch_path,
            manifest=manifest,
            max_events=100,
        )


def test_execute_requires_exact_active_runtime_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, deleter, _, _, _, _, _, _ = make_batch(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    monkeypatch.delenv("GATEWAY_RELEASE_REVISION", raising=False)
    with pytest.raises(ValueError, match="requires GATEWAY_RELEASE_REVISION"):
        deleter.validate_runtime_revision(
            execute=True,
            expected_gateway_revision="a" * 40,
        )
    monkeypatch.setenv("GATEWAY_RELEASE_REVISION", "b" * 40)
    with pytest.raises(ValueError, match="does not match"):
        deleter.validate_runtime_revision(
            execute=True,
            expected_gateway_revision="a" * 40,
        )
    monkeypatch.setenv("GATEWAY_RELEASE_REVISION", "a" * 40)
    deleter.validate_runtime_revision(
        execute=True,
        expected_gateway_revision="a" * 40,
    )
    monkeypatch.delenv("GATEWAY_RELEASE_REVISION")
    deleter.validate_runtime_revision(
        execute=False,
        expected_gateway_revision="a" * 40,
    )
