from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import and_, or_, text

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_API = ROOT / "services" / "gateway-api"
if str(GATEWAY_API) not in sys.path:
    sys.path.insert(0, str(GATEWAY_API))

from gateway_api.database import SessionLocal
from gateway_api.models import OutboxDeliveryAttempt, OutboxEvent, RealtimeNotification

SCHEMA = "gateway.outbox.history.batch.v1"
TERMINAL_STATUSES = ("published", "dead_letter", "cancelled")
DEFAULT_LIMIT = 100_000
CHUNK_SIZE = 5_000


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def create_batch_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.executescript(
        """
        CREATE TABLE events (
            id TEXT PRIMARY KEY,
            audit_event_id TEXT NOT NULL,
            owner_subject TEXT NOT NULL,
            event_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            headers_json TEXT NOT NULL,
            status TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            max_attempts INTEGER NOT NULL,
            available_at TEXT NOT NULL,
            locked_by TEXT,
            locked_at TEXT,
            published_at TEXT,
            broker_stream TEXT,
            broker_sequence INTEGER,
            last_error TEXT,
            replay_count INTEGER NOT NULL,
            replayed_from_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE attempts (
            id TEXT PRIMARY KEY,
            outbox_event_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            replica_id TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            broker_stream TEXT,
            broker_sequence INTEGER,
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE INDEX ix_batch_events_created ON events(created_at DESC,id DESC);
        CREATE INDEX ix_batch_attempts_event ON attempts(outbox_event_id,attempt_number);
        CREATE INDEX ix_batch_attempts_started ON attempts(started_at DESC,id DESC);
        """
    )
    return connection


def event_values(row: OutboxEvent) -> tuple[Any, ...]:
    return (
        row.id,
        row.audit_event_id,
        row.owner_subject,
        row.event_type,
        row.subject,
        json.dumps(row.payload or {}, separators=(",", ":"), sort_keys=True),
        json.dumps(row.headers or {}, separators=(",", ":"), sort_keys=True),
        row.status,
        int(row.attempt_count or 0),
        int(row.max_attempts or 0),
        iso(row.available_at),
        row.locked_by,
        iso(row.locked_at),
        iso(row.published_at),
        row.broker_stream,
        row.broker_sequence,
        row.last_error,
        int(row.replay_count or 0),
        row.replayed_from_id,
        iso(row.created_at),
        iso(row.updated_at),
    )


def attempt_values(row: OutboxDeliveryAttempt) -> tuple[Any, ...]:
    return (
        row.id,
        row.outbox_event_id,
        int(row.attempt_number),
        row.replica_id,
        row.status,
        row.error,
        row.broker_stream,
        row.broker_sequence,
        iso(row.started_at),
        iso(row.completed_at),
    )


def chunks(values: list[str], size: int = CHUNK_SIZE):
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]


def export_batch(
    *,
    output_dir: Path,
    before: datetime,
    limit: int,
    batch_id: str,
    gateway_revision: str,
    after_created_at: datetime | None = None,
    after_id: str | None = None,
) -> tuple[Path, Path, dict[str, Any]]:
    if (after_created_at is None) != (after_id is None):
        raise ValueError("after_created_at and after_id must be provided together")
    output_dir.mkdir(parents=True, exist_ok=True)
    batch_path = output_dir / f"{batch_id}.sqlite3"
    manifest_path = output_dir / f"{batch_id}.manifest.json"
    if batch_path.exists() or manifest_path.exists():
        raise FileExistsError("history batch output already exists")
    database = create_batch_database(batch_path)
    event_ids: list[str] = []
    resume_after_created_at: str | None = None
    resume_after_id: str | None = None
    realtime_reference_count = 0
    database_revision = "unknown"
    try:
        with SessionLocal() as session:
            database_revision = str(
                session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            )
            filters = [
                OutboxEvent.status.in_(TERMINAL_STATUSES),
                OutboxEvent.created_at < before,
            ]
            if after_created_at is not None and after_id is not None:
                filters.append(
                    or_(
                        OutboxEvent.created_at > after_created_at,
                        and_(
                            OutboxEvent.created_at == after_created_at,
                            OutboxEvent.id > after_id,
                        ),
                    )
                )
            query = (
                session.query(OutboxEvent)
                .filter(*filters)
                .order_by(OutboxEvent.created_at.asc(), OutboxEvent.id.asc())
                .limit(limit)
            )
            for row in query.yield_per(1000):
                database.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    event_values(row),
                )
                event_ids.append(str(row.id))
                resume_after_created_at = iso(row.created_at)
                resume_after_id = str(row.id)
            database.commit()
            for event_chunk in chunks(event_ids):
                attempts = (
                    session.query(OutboxDeliveryAttempt)
                    .filter(OutboxDeliveryAttempt.outbox_event_id.in_(event_chunk))
                    .order_by(
                        OutboxDeliveryAttempt.outbox_event_id.asc(),
                        OutboxDeliveryAttempt.attempt_number.asc(),
                        OutboxDeliveryAttempt.id.asc(),
                    )
                    .all()
                )
                database.executemany(
                    "INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?)",
                    [attempt_values(row) for row in attempts],
                )
                realtime_reference_count += int(
                    session.query(RealtimeNotification)
                    .filter(RealtimeNotification.outbox_event_id.in_(event_chunk))
                    .count()
                )
            database.commit()
        integrity = database.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"history batch SQLite integrity check failed: {integrity}")
        event_count = int(database.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        attempt_count = int(database.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
        event_range = database.execute(
            "SELECT MIN(created_at),MAX(created_at) FROM events"
        ).fetchone()
        attempt_range = database.execute(
            "SELECT MIN(started_at),MAX(started_at) FROM attempts"
        ).fetchone()
        database.commit()
    finally:
        database.close()
    size_bytes = batch_path.stat().st_size
    plaintext_sha256 = sha256_file(batch_path)
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "created_at": datetime.now(UTC).isoformat(),
        "source": {
            "gateway_revision": gateway_revision,
            "database_revision": database_revision,
        },
        "selection": {
            "terminal_statuses": list(TERMINAL_STATUSES),
            "before": before.isoformat(),
            "limit": limit,
            "after": (
                None
                if after_created_at is None or after_id is None
                else {"created_at": iso(after_created_at), "id": after_id}
            ),
        },
        "resume_after": (
            None
            if resume_after_created_at is None or resume_after_id is None
            else {"created_at": resume_after_created_at, "id": resume_after_id}
        ),
        "event_count": event_count,
        "attempt_count": attempt_count,
        "realtime_reference_count": realtime_reference_count,
        "event_created_at": {
            "min": event_range[0],
            "max": event_range[1],
        },
        "attempt_started_at": {
            "min": attempt_range[0],
            "max": attempt_range[1],
        },
        "plaintext": {
            "sha256": plaintext_sha256,
            "size_bytes": size_bytes,
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return batch_path, manifest_path, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", required=True)
    parser.add_argument("--after-created-at")
    parser.add_argument("--after-id")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--batch-id", default=str(uuid.uuid4()))
    parser.add_argument(
        "--gateway-revision",
        default=os.environ.get("GATEWAY_RELEASE_REVISION", "local"),
    )
    args = parser.parse_args()
    before = parse_timestamp(args.before)
    if bool(args.after_created_at) != bool(args.after_id):
        raise SystemExit("--after-created-at and --after-id must be provided together")
    after_created_at = (
        parse_timestamp(args.after_created_at) if args.after_created_at else None
    )
    if args.limit < 1 or args.limit > 1_000_000:
        raise SystemExit("--limit must be between 1 and 1000000")
    try:
        uuid.UUID(args.batch_id)
    except ValueError as exc:
        raise SystemExit("--batch-id must be a UUID") from exc
    batch_path, manifest_path, manifest = export_batch(
        output_dir=Path(args.output_dir),
        before=before,
        limit=args.limit,
        batch_id=args.batch_id,
        gateway_revision=args.gateway_revision,
        after_created_at=after_created_at,
        after_id=args.after_id,
    )
    print(
        json.dumps(
            {
                "batch": str(batch_path),
                "manifest": str(manifest_path),
                "batch_id": manifest["batch_id"],
                "event_count": manifest["event_count"],
                "attempt_count": manifest["attempt_count"],
                "realtime_reference_count": manifest["realtime_reference_count"],
                "plaintext_sha256": manifest["plaintext"]["sha256"],
                "plaintext_size_bytes": manifest["plaintext"]["size_bytes"],
                "resume_after": manifest["resume_after"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
