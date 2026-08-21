from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import httpx
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_API = ROOT / "services" / "gateway-api"
SCRIPTS = ROOT / "scripts"
for path in (GATEWAY_API, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from export_outbox_history_batch import (  # noqa: E402
    TERMINAL_STATUSES,
    attempt_values,
    event_values,
)
from gateway_api.database import SessionLocal  # noqa: E402
from gateway_api.models import (  # noqa: E402
    AuditEvent,
    OutboxDeliveryAttempt,
    OutboxEvent,
    RealtimeNotification,
)
from upload_outbox_history_batch import (  # noqa: E402
    build_ssl_context,
    load_manifest,
    verify_batch_file,
    verify_receipt,
)

OFFLOAD_SCHEMA = "gateway.outbox.history.offload.v1"
OFFLOAD_AUDIT_EVENT = "gateway.outbox.history.offloaded.v1"
EVENT_COLUMNS = (
    "id",
    "audit_event_id",
    "owner_subject",
    "event_type",
    "subject",
    "payload_json",
    "headers_json",
    "status",
    "attempt_count",
    "max_attempts",
    "available_at",
    "locked_by",
    "locked_at",
    "published_at",
    "broker_stream",
    "broker_sequence",
    "last_error",
    "replay_count",
    "replayed_from_id",
    "created_at",
    "updated_at",
)
ATTEMPT_COLUMNS = (
    "id",
    "outbox_event_id",
    "attempt_number",
    "replica_id",
    "status",
    "error",
    "broker_stream",
    "broker_sequence",
    "started_at",
    "completed_at",
)
DB_CHUNK_SIZE = 500


@dataclass(frozen=True)
class BatchSnapshot:
    events: tuple[tuple[Any, ...], ...]
    attempts: tuple[tuple[Any, ...], ...]

    @property
    def event_ids(self) -> list[str]:
        return [str(row[0]) for row in self.events]

    @property
    def audit_event_ids(self) -> list[str]:
        return [str(row[1]) for row in self.events]


def _chunks(values: list[str], size: int = DB_CHUNK_SIZE) -> Iterable[list[str]]:
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def _table_columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))


def load_batch_snapshot(
    *,
    batch_path: Path,
    manifest: dict[str, Any],
    max_events: int,
) -> BatchSnapshot:
    verify_batch_file(manifest, batch_path)
    connection = sqlite3.connect(f"file:{batch_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError(f"history batch SQLite integrity check failed: {integrity}")
        if _table_columns(connection, "events") != EVENT_COLUMNS:
            raise ValueError("history batch events schema does not match the v1 contract")
        if _table_columns(connection, "attempts") != ATTEMPT_COLUMNS:
            raise ValueError("history batch attempts schema does not match the v1 contract")
        events = tuple(
            tuple(row[column] for column in EVENT_COLUMNS)
            for row in connection.execute("SELECT * FROM events ORDER BY created_at,id")
        )
        attempts = tuple(
            tuple(row[column] for column in ATTEMPT_COLUMNS)
            for row in connection.execute(
                "SELECT * FROM attempts ORDER BY outbox_event_id,attempt_number,id"
            )
        )
    finally:
        connection.close()

    if not events:
        raise ValueError("history batch contains no events")
    if len(events) > max_events:
        raise ValueError(
            f"history batch has {len(events)} events, exceeding --max-events={max_events}"
        )
    if len(events) != int(manifest.get("event_count") or 0):
        raise ValueError("history batch event count does not match manifest")
    if len(attempts) != int(manifest.get("attempt_count") or 0):
        raise ValueError("history batch attempt count does not match manifest")
    event_ids = {str(row[0]) for row in events}
    if len(event_ids) != len(events):
        raise ValueError("history batch contains duplicate event ids")
    if any(str(row[7]) not in TERMINAL_STATUSES for row in events):
        raise ValueError("history batch contains a non-terminal outbox event")
    if any(str(row[1]) not in event_ids for row in attempts):
        raise ValueError("history batch contains an attempt for an unknown event")
    if int(manifest.get("realtime_reference_count") or 0) != 0:
        raise ValueError("history batch manifest contains realtime notification references")
    return BatchSnapshot(events=events, attempts=attempts)


def fetch_remote_binding(
    *,
    base_url: str,
    manifest: dict[str, Any],
    ca_cert_path: Path,
    client_cert_path: Path,
    client_key_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    ssl_context = build_ssl_context(
        ca_cert_path=ca_cert_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
    )
    batch_id = str(manifest["batch_id"])
    with httpx.Client(
        base_url=base_url.rstrip("/"),
        verify=ssl_context,
        timeout=httpx.Timeout(
            connect=min(timeout_seconds, 10.0),
            read=timeout_seconds,
            write=timeout_seconds,
            pool=min(timeout_seconds, 10.0),
        ),
        follow_redirects=False,
    ) as client:
        manifest_response = client.get(f"/v1/batches/{batch_id}/manifest")
        manifest_response.raise_for_status()
        remote_manifest = manifest_response.json()
        if not isinstance(remote_manifest, dict) or remote_manifest != manifest:
            raise ValueError("history store manifest does not exactly match local manifest")
        receipt_response = client.get(f"/v1/batches/{batch_id}/receipt")
        receipt_response.raise_for_status()
        receipt = receipt_response.json()
    if not isinstance(receipt, dict):
        raise TypeError("history store receipt payload is invalid")
    return verify_receipt(manifest, receipt)


def _set_transaction_timeouts(session: Any) -> None:
    if session.bind is None or session.bind.dialect.name != "postgresql":
        return
    session.execute(text("SET LOCAL lock_timeout = '5s'"))
    session.execute(text("SET LOCAL statement_timeout = '30s'"))


def _load_locked_events(session: Any, event_ids: list[str]) -> list[OutboxEvent]:
    rows: list[OutboxEvent] = []
    for event_chunk in _chunks(event_ids):
        rows.extend(
            session.query(OutboxEvent)
            .filter(OutboxEvent.id.in_(event_chunk))
            .with_for_update()
            .all()
        )
    return rows


def _load_locked_attempts(session: Any, event_ids: list[str]) -> list[OutboxDeliveryAttempt]:
    rows: list[OutboxDeliveryAttempt] = []
    for event_chunk in _chunks(event_ids):
        rows.extend(
            session.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id.in_(event_chunk))
            .order_by(
                OutboxDeliveryAttempt.outbox_event_id.asc(),
                OutboxDeliveryAttempt.attempt_number.asc(),
                OutboxDeliveryAttempt.id.asc(),
            )
            .with_for_update()
            .all()
        )
    return rows


def _count_realtime_references(session: Any, event_ids: list[str]) -> int:
    total = 0
    for event_chunk in _chunks(event_ids):
        total += int(
            session.query(RealtimeNotification)
            .filter(RealtimeNotification.outbox_event_id.in_(event_chunk))
            .count()
        )
    return total


def _count_original_audits(session: Any, audit_event_ids: list[str]) -> int:
    total = 0
    for audit_chunk in _chunks(audit_event_ids):
        total += int(
            session.query(AuditEvent).filter(AuditEvent.id.in_(audit_chunk)).count()
        )
    return total


def _existing_offload_audits(session: Any, batch_id: str) -> list[AuditEvent]:
    return (
        session.query(AuditEvent)
        .filter(
            AuditEvent.event_type == OFFLOAD_AUDIT_EVENT,
            AuditEvent.resource_type == "outbox_history_batch",
            AuditEvent.resource_id == batch_id,
        )
        .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        .all()
    )


def _audit_matches_binding(
    audit: AuditEvent,
    *,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
) -> bool:
    payload = audit.payload or {}
    return (
        payload.get("plaintext_sha256") == manifest["plaintext"]["sha256"]
        and payload.get("ciphertext_sha256") == receipt["ciphertext_sha256"]
        and int(payload.get("event_count") or -1) == int(manifest["event_count"])
        and int(payload.get("attempt_count") or -1) == int(manifest["attempt_count"])
        and payload.get("history_imported_at") == receipt["imported_at"]
    )


def _delete_rows(session: Any, model: Any, column: Any, values: list[str]) -> int:
    total = 0
    for value_chunk in _chunks(values):
        total += int(
            session.query(model)
            .filter(column.in_(value_chunk))
            .delete(synchronize_session=False)
        )
    return total


def _evidence_payload(
    *,
    status: str,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    snapshot: BatchSnapshot,
    actor_subject: str,
    audit_event_id: str,
) -> dict[str, Any]:
    return {
        "schema": OFFLOAD_SCHEMA,
        "status": status,
        "batch_id": manifest["batch_id"],
        "actor_subject": actor_subject,
        "event_ids": snapshot.event_ids,
        "event_count": len(snapshot.events),
        "attempt_count": len(snapshot.attempts),
        "realtime_reference_count": 0,
        "plaintext_sha256": manifest["plaintext"]["sha256"],
        "ciphertext_sha256": receipt["ciphertext_sha256"],
        "ciphertext_size_bytes": receipt["ciphertext_size_bytes"],
        "imported_at": receipt["imported_at"],
        "source": manifest["source"],
        "selection": manifest["selection"],
        "audit_event_id": audit_event_id,
        "updated_at": datetime.now(UTC).isoformat(),
    }


def atomic_write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def validate_and_offload(
    *,
    manifest: dict[str, Any],
    snapshot: BatchSnapshot,
    receipt: dict[str, Any],
    expected_gateway_revision: str,
    actor_subject: str,
    execute: bool,
    evidence_output: Path | None,
) -> dict[str, Any]:
    if str(manifest.get("source", {}).get("gateway_revision") or "") != expected_gateway_revision:
        raise ValueError("history batch gateway revision does not match expected revision")
    event_ids = snapshot.event_ids
    audit_event_ids = snapshot.audit_event_ids
    archived_events = {str(row[0]): row for row in snapshot.events}
    archived_attempts = tuple(snapshot.attempts)
    batch_id = str(manifest["batch_id"])

    with SessionLocal() as session:
        _set_transaction_timeouts(session)
        database_revision = str(
            session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        )
        if database_revision != str(manifest.get("source", {}).get("database_revision") or ""):
            raise ValueError("database revision does not match history batch source revision")
        hot_events = _load_locked_events(session, event_ids)
        hot_attempts = _load_locked_attempts(session, event_ids)
        realtime_reference_count = _count_realtime_references(session, event_ids)
        audit_count = _count_original_audits(session, audit_event_ids)
        if audit_count != len(audit_event_ids):
            raise ValueError("one or more original audit events are unavailable")
        if realtime_reference_count != 0:
            raise ValueError("live realtime notifications still reference the history batch")

        if not hot_events:
            if hot_attempts:
                raise ValueError("history batch is partially offloaded: attempts remain without hot events")
            audits = _existing_offload_audits(session, batch_id)
            matching = [
                audit
                for audit in audits
                if _audit_matches_binding(audit, manifest=manifest, receipt=receipt)
            ]
            if len(matching) != 1:
                raise ValueError(
                    "history batch is absent hot but has no unique matching offload audit"
                )
            result = {
                "status": "already_offloaded",
                "batch_id": batch_id,
                "event_count": len(snapshot.events),
                "attempt_count": len(snapshot.attempts),
                "audit_event_id": matching[0].id,
            }
            if execute and evidence_output is not None:
                atomic_write_evidence(
                    evidence_output,
                    _evidence_payload(
                        status="reconciled",
                        manifest=manifest,
                        receipt=receipt,
                        snapshot=snapshot,
                        actor_subject=matching[0].actor_subject,
                        audit_event_id=matching[0].id,
                    ),
                )
            session.rollback()
            return result

        if len(hot_events) != len(snapshot.events):
            raise ValueError("history batch is partially offloaded or missing hot events")
        if len(hot_attempts) != len(snapshot.attempts):
            raise ValueError("hot delivery attempts do not match the archived batch")
        hot_event_map = {str(row.id): row for row in hot_events}
        for event_id, archived_values in archived_events.items():
            hot_event = hot_event_map[event_id]
            if hot_event.lock_token is not None:
                raise ValueError("hot outbox event still has a claim lock token")
            if event_values(hot_event) != archived_values:
                raise ValueError("hot outbox event no longer matches the archived snapshot")
        current_attempts = tuple(
            attempt_values(row)
            for row in sorted(
                hot_attempts,
                key=lambda row: (row.outbox_event_id, row.attempt_number, row.id),
            )
        )
        if current_attempts != archived_attempts:
            raise ValueError("hot delivery attempts no longer match the archived snapshot")

        if not execute:
            session.rollback()
            return {
                "status": "validated",
                "batch_id": batch_id,
                "event_count": len(snapshot.events),
                "attempt_count": len(snapshot.attempts),
            }
        if evidence_output is None:
            raise ValueError("evidence output is required for execute mode")
        if _existing_offload_audits(session, batch_id):
            raise ValueError("history batch already has an offload audit while hot rows still exist")

        audit_event_id = str(uuid.uuid4())
        atomic_write_evidence(
            evidence_output,
            _evidence_payload(
                status="prepared",
                manifest=manifest,
                receipt=receipt,
                snapshot=snapshot,
                actor_subject=actor_subject,
                audit_event_id=audit_event_id,
            ),
        )
        deleted_attempts = _delete_rows(
            session,
            OutboxDeliveryAttempt,
            OutboxDeliveryAttempt.outbox_event_id,
            event_ids,
        )
        if deleted_attempts != len(snapshot.attempts):
            session.rollback()
            raise RuntimeError("delivery-attempt delete count does not match archived batch")
        deleted_events = _delete_rows(session, OutboxEvent, OutboxEvent.id, event_ids)
        if deleted_events != len(snapshot.events):
            session.rollback()
            raise RuntimeError("outbox-event delete count does not match archived batch")
        session.add(
            AuditEvent(
                id=audit_event_id,
                event_type=OFFLOAD_AUDIT_EVENT,
                actor_subject=actor_subject,
                action="outbox_history_offload",
                resource_type="outbox_history_batch",
                resource_id=batch_id,
                status="success",
                payload={
                    "event_count": len(snapshot.events),
                    "attempt_count": len(snapshot.attempts),
                    "plaintext_sha256": manifest["plaintext"]["sha256"],
                    "ciphertext_sha256": receipt["ciphertext_sha256"],
                    "history_imported_at": receipt["imported_at"],
                },
            )
        )
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise

    atomic_write_evidence(
        evidence_output,
        _evidence_payload(
            status="offloaded",
            manifest=manifest,
            receipt=receipt,
            snapshot=snapshot,
            actor_subject=actor_subject,
            audit_event_id=audit_event_id,
        ),
    )
    return {
        "status": "offloaded",
        "batch_id": batch_id,
        "event_count": len(snapshot.events),
        "attempt_count": len(snapshot.attempts),
        "audit_event_id": audit_event_id,
    }


def validate_runtime_revision(*, execute: bool, expected_gateway_revision: str) -> None:
    if not execute:
        return
    runtime_revision = str(os.environ.get("GATEWAY_RELEASE_REVISION") or "").strip()
    if not runtime_revision:
        raise ValueError("execute mode requires GATEWAY_RELEASE_REVISION from the active runtime")
    if runtime_revision != expected_gateway_revision:
        raise ValueError("active runtime revision does not match --expected-gateway-revision")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--client-cert", required=True)
    parser.add_argument("--client-key", required=True)
    parser.add_argument("--expected-gateway-revision", required=True)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-batch-id")
    parser.add_argument("--actor-subject")
    parser.add_argument("--evidence-output")
    args = parser.parse_args()

    if not args.base_url.startswith("https://"):
        raise SystemExit("--base-url must use HTTPS")
    if args.max_events < 1 or args.max_events > 10_000:
        raise SystemExit("--max-events must be between 1 and 10000")
    if args.timeout_seconds < 1.0:
        raise SystemExit("--timeout-seconds must be at least 1")

    manifest_path = Path(args.manifest)
    batch_path = Path(args.batch)
    manifest = load_manifest(manifest_path)
    snapshot = load_batch_snapshot(
        batch_path=batch_path,
        manifest=manifest,
        max_events=args.max_events,
    )
    if args.execute:
        if args.confirm_batch_id != manifest["batch_id"]:
            raise SystemExit("--confirm-batch-id must exactly match the manifest batch id")
        if not str(args.actor_subject or "").strip():
            raise SystemExit("--actor-subject is required with --execute")
        if not args.evidence_output:
            raise SystemExit("--evidence-output is required with --execute")
    validate_runtime_revision(
        execute=args.execute,
        expected_gateway_revision=args.expected_gateway_revision,
    )

    receipt = fetch_remote_binding(
        base_url=args.base_url,
        manifest=manifest,
        ca_cert_path=Path(args.ca_cert),
        client_cert_path=Path(args.client_cert),
        client_key_path=Path(args.client_key),
        timeout_seconds=args.timeout_seconds,
    )
    result = validate_and_offload(
        manifest=manifest,
        snapshot=snapshot,
        receipt=receipt,
        expected_gateway_revision=args.expected_gateway_revision,
        actor_subject=str(args.actor_subject or "dry-run"),
        execute=args.execute,
        evidence_output=Path(args.evidence_output) if args.evidence_output else None,
    )
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
