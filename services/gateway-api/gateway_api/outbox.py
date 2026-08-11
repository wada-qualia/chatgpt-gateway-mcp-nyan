from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass
from datetime import UTC, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .broker import BrokerPublishAck, EventBroker
from .config import Settings
from .events import emit_event
from .models import (
    GatewayReplica,
    OutboxDeliveryAttempt,
    OutboxEvent,
    ProcessedBrokerMessage,
    RealtimeRoute,
    utcnow,
)

logger = logging.getLogger(__name__)

OUTBOX_ACTIVE_STATUSES = {"pending", "retry", "processing"}
OUTBOX_TERMINAL_STATUSES = {"published", "dead_letter", "cancelled"}
OUTBOX_STATUSES = (
    "pending",
    "retry",
    "processing",
    "published",
    "dead_letter",
    "cancelled",
)


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def resolve_replica_id(settings: Settings) -> str:
    configured = settings.gateway_replica_id.strip()
    if configured:
        return configured
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class OutboxRunResult:
    claimed: int = 0
    published: int = 0
    retried: int = 0
    dead_lettered: int = 0


class OutboxService:
    def __init__(
        self,
        *,
        session_factory: sessionmaker,
        broker: EventBroker,
        settings: Settings,
        replica_id: str,
    ) -> None:
        self.session_factory = session_factory
        self.broker = broker
        self.settings = settings
        self.replica_id = replica_id

    def register_replica(self, db: Session) -> GatewayReplica:
        now = utcnow()
        replica = db.get(GatewayReplica, self.replica_id)
        if replica is None:
            replica = GatewayReplica(
                id=self.replica_id,
                hostname=socket.gethostname(),
                process_id=os.getpid(),
                status="online",
                meta={"broker_backend": self.settings.gateway_broker_backend},
                started_at=now,
                last_heartbeat_at=now,
                expires_at=now + timedelta(seconds=self.settings.gateway_replica_ttl_seconds),
            )
            db.add(replica)
        else:
            replica.hostname = socket.gethostname()
            replica.process_id = os.getpid()
            replica.status = "online"
            replica.last_heartbeat_at = now
            replica.expires_at = now + timedelta(seconds=self.settings.gateway_replica_ttl_seconds)
            replica.stopped_at = None
        db.commit()
        db.refresh(replica)
        return replica

    def heartbeat_replica(self, db: Session) -> GatewayReplica:
        now = utcnow()
        replica = db.get(GatewayReplica, self.replica_id)
        if replica is None:
            return self.register_replica(db)
        replica.status = "online"
        replica.last_heartbeat_at = now
        replica.expires_at = now + timedelta(seconds=self.settings.gateway_replica_ttl_seconds)
        db.commit()
        db.refresh(replica)
        self.expire_stale_replicas_and_routes(db)
        return replica

    def stop_replica(self, db: Session) -> None:
        now = utcnow()
        replica = db.get(GatewayReplica, self.replica_id)
        if replica is not None:
            replica.status = "offline"
            replica.stopped_at = now
            replica.expires_at = now
        routes = (
            db.query(RealtimeRoute)
            .filter(
                RealtimeRoute.replica_id == self.replica_id,
                RealtimeRoute.status == "online",
            )
            .all()
        )
        for route in routes:
            route.status = "offline"
            route.disconnected_at = now
            route.expires_at = now
        db.commit()

    def expire_stale_replicas_and_routes(self, db: Session) -> tuple[int, int]:
        now = utcnow()
        replicas = (
            db.query(GatewayReplica)
            .filter(
                GatewayReplica.status == "online",
                GatewayReplica.expires_at <= now,
            )
            .all()
        )
        for replica in replicas:
            replica.status = "expired"
            replica.stopped_at = now
        routes = (
            db.query(RealtimeRoute)
            .filter(
                RealtimeRoute.status == "online",
                RealtimeRoute.expires_at <= now,
            )
            .all()
        )
        for route in routes:
            route.status = "expired"
            route.disconnected_at = now
        if replicas or routes:
            db.commit()
        return len(replicas), len(routes)

    def release_stale_claims(self, db: Session) -> int:
        cutoff = utcnow() - timedelta(seconds=max(1, self.settings.gateway_outbox_lock_ttl_seconds))
        rows = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.status == "processing",
                OutboxEvent.locked_at.is_not(None),
                OutboxEvent.locked_at <= cutoff,
            )
            .all()
        )
        now = utcnow()
        for row in rows:
            row.status = "retry"
            row.available_at = now
            row.locked_by = None
            row.lock_token = None
            row.locked_at = None
            row.last_error = "stale publisher claim released"
            row.updated_at = now
        if rows:
            db.commit()
        return len(rows)

    def claim_batch(self, db: Session, *, limit: int | None = None) -> list[OutboxEvent]:
        self.release_stale_claims(db)
        now = utcnow()
        bounded_limit = max(1, min(int(limit or self.settings.gateway_outbox_batch_size), 1000))
        query = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.status.in_(["pending", "retry"]),
                OutboxEvent.available_at <= now,
            )
            .order_by(OutboxEvent.available_at, OutboxEvent.created_at, OutboxEvent.id)
        )
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        rows = query.limit(bounded_limit).all()
        for row in rows:
            row.status = "processing"
            row.locked_by = self.replica_id
            row.lock_token = str(uuid.uuid4())
            row.locked_at = now
            row.updated_at = now
        if rows:
            db.commit()
            for row in rows:
                db.refresh(row)
        return rows

    def _record_success(
        self,
        db: Session,
        *,
        event_id: str,
        lock_token: str,
        ack: BrokerPublishAck,
    ) -> bool:
        event = db.get(OutboxEvent, event_id)
        if (
            event is None
            or event.status != "processing"
            or event.locked_by != self.replica_id
            or event.lock_token != lock_token
        ):
            return False
        now = utcnow()
        started_at = event.locked_at or now
        event.attempt_count = int(event.attempt_count or 0) + 1
        event.status = "published"
        event.published_at = now
        event.broker_stream = ack.stream
        event.broker_sequence = ack.sequence
        event.last_error = None
        event.locked_by = None
        event.lock_token = None
        event.locked_at = None
        event.updated_at = now
        db.add(
            OutboxDeliveryAttempt(
                id=str(uuid.uuid4()),
                outbox_event_id=event.id,
                attempt_number=event.attempt_count,
                replica_id=self.replica_id,
                status="duplicate" if ack.duplicate else "published",
                broker_stream=ack.stream,
                broker_sequence=ack.sequence,
                started_at=started_at,
                completed_at=now,
            )
        )
        db.commit()
        return True

    def _record_failure(
        self,
        db: Session,
        *,
        event_id: str,
        lock_token: str,
        error: Exception,
    ) -> str:
        event = db.get(OutboxEvent, event_id)
        if (
            event is None
            or event.status != "processing"
            or event.locked_by != self.replica_id
            or event.lock_token != lock_token
        ):
            return "stale"
        now = utcnow()
        started_at = event.locked_at or now
        event.attempt_count = int(event.attempt_count or 0) + 1
        error_text = str(error)[:10000] or error.__class__.__name__
        terminal = event.attempt_count >= max(1, int(event.max_attempts or 1))
        if terminal:
            event.status = "dead_letter"
            status = "dead_letter"
        else:
            event.status = "retry"
            delay = min(
                float(self.settings.gateway_outbox_retry_max_seconds),
                float(self.settings.gateway_outbox_retry_base_seconds)
                * (2 ** max(0, event.attempt_count - 1)),
            )
            event.available_at = now + timedelta(seconds=max(0.01, delay))
            status = "retry"
        event.last_error = error_text
        event.locked_by = None
        event.lock_token = None
        event.locked_at = None
        event.updated_at = now
        db.add(
            OutboxDeliveryAttempt(
                id=str(uuid.uuid4()),
                outbox_event_id=event.id,
                attempt_number=event.attempt_count,
                replica_id=self.replica_id,
                status=status,
                error=error_text,
                started_at=started_at,
                completed_at=now,
            )
        )
        if terminal:
            emit_event(
                db,
                event_type="gateway.outbox.dead_lettered.v1",
                actor_subject=f"system:{self.replica_id}",
                action="dead_lettered",
                resource_type="outbox_event",
                resource_id=event.id,
                payload={
                    "outbox_event_id": event.id,
                    "audit_event_id": event.audit_event_id,
                    "event_type": event.event_type,
                    "attempt_count": event.attempt_count,
                    "last_error": error_text,
                },
                status="warning",
                commit=False,
                enqueue_outbox=False,
            )
        db.commit()
        return status

    def _claim_batch_in_new_session(
        self, *, limit: int | None = None
    ) -> list[OutboxEvent]:
        with self.session_factory() as db:
            return self.claim_batch(db, limit=limit)

    def _record_success_in_new_session(
        self,
        *,
        event_id: str,
        lock_token: str,
        ack: BrokerPublishAck,
    ) -> bool:
        with self.session_factory() as db:
            return self._record_success(
                db,
                event_id=event_id,
                lock_token=lock_token,
                ack=ack,
            )

    def _record_failure_in_new_session(
        self,
        *,
        event_id: str,
        lock_token: str,
        error: Exception,
    ) -> str:
        with self.session_factory() as db:
            return self._record_failure(
                db,
                event_id=event_id,
                lock_token=lock_token,
                error=error,
            )

    async def run_once(self, *, limit: int | None = None) -> OutboxRunResult:
        rows = await asyncio.to_thread(
            self._claim_batch_in_new_session,
            limit=limit,
        )
        published = 0
        retried = 0
        dead_lettered = 0
        for row in rows:
            try:
                payload = json.dumps(
                    row.payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
                headers = {
                    str(key): str(value)
                    for key, value in dict(row.headers or {}).items()
                }
                delivery_id = str(
                    headers.get("Nats-Msg-Id") or row.audit_event_id
                )
                headers["Nats-Msg-Id"] = delivery_id
                ack = await self.broker.publish(
                    row.subject,
                    payload,
                    message_id=delivery_id,
                    headers=headers,
                )
                accepted = await asyncio.to_thread(
                    self._record_success_in_new_session,
                    event_id=row.id,
                    lock_token=str(row.lock_token or ""),
                    ack=ack,
                )
                if accepted:
                    published += 1
            except Exception as exc:
                logger.exception("outbox_publish_failed", extra={"outbox_event_id": row.id})
                result = await asyncio.to_thread(
                    self._record_failure_in_new_session,
                    event_id=row.id,
                    lock_token=str(row.lock_token or ""),
                    error=exc,
                )
                if result == "dead_letter":
                    dead_lettered += 1
                elif result == "retry":
                    retried += 1
        return OutboxRunResult(
            claimed=len(rows),
            published=published,
            retried=retried,
            dead_lettered=dead_lettered,
        )

    def replay(
        self,
        db: Session,
        *,
        event_id: str,
        actor_subject: str | None = None,
        reason: str | None = None,
    ) -> OutboxEvent:
        event = db.get(OutboxEvent, event_id)
        if event is None:
            raise LookupError("Outbox event not found")
        if event.status not in {"dead_letter", "cancelled", "published"}:
            raise ValueError("Only terminal outbox events can be replayed")
        now = utcnow()
        event.status = "pending"
        event.available_at = now
        event.max_attempts = max(
            int(event.max_attempts or 0),
            int(event.attempt_count or 0) + max(1, self.settings.gateway_outbox_max_attempts),
        )
        event.replay_count = int(event.replay_count or 0) + 1
        headers = dict(event.headers or {})
        headers["Nats-Msg-Id"] = (
            f"{event.audit_event_id}:replay:{event.replay_count}"
        )
        headers["X-Gateway-Replay-Count"] = str(event.replay_count)
        event.headers = headers
        event.published_at = None
        event.broker_stream = None
        event.broker_sequence = None
        event.last_error = None
        event.locked_by = None
        event.lock_token = None
        event.locked_at = None
        event.updated_at = now
        emit_event(
            db,
            event_type="gateway.outbox.replayed.v1",
            actor_subject=actor_subject or f"system:{self.replica_id}",
            action="replayed",
            resource_type="outbox_event",
            resource_id=event.id,
            payload={
                "outbox_event_id": event.id,
                "audit_event_id": event.audit_event_id,
                "event_type": event.event_type,
                "replay_count": event.replay_count,
                "delivery_id": headers["Nats-Msg-Id"],
                "reason": (reason or "")[:1000] or None,
            },
            commit=False,
            enqueue_outbox=False,
        )
        db.commit()
        db.refresh(event)
        return event

    def cancel(
        self,
        db: Session,
        *,
        event_id: str,
        actor_subject: str | None = None,
    ) -> OutboxEvent:
        event = db.get(OutboxEvent, event_id)
        if event is None:
            raise LookupError("Outbox event not found")
        if event.status == "published":
            raise ValueError("Published outbox events cannot be cancelled")
        event.status = "cancelled"
        event.locked_by = None
        event.lock_token = None
        event.locked_at = None
        event.updated_at = utcnow()
        emit_event(
            db,
            event_type="gateway.outbox.cancelled.v1",
            actor_subject=actor_subject or f"system:{self.replica_id}",
            action="cancelled",
            resource_type="outbox_event",
            resource_id=event.id,
            payload={
                "outbox_event_id": event.id,
                "audit_event_id": event.audit_event_id,
                "event_type": event.event_type,
            },
            status="warning",
            commit=False,
            enqueue_outbox=False,
        )
        db.commit()
        db.refresh(event)
        return event

    def mark_processed(
        self,
        db: Session,
        *,
        message_id: str,
        subject: str,
        payload: bytes,
        stream: str | None = None,
        consumer: str | None = None,
    ) -> bool:
        if db.get(ProcessedBrokerMessage, message_id) is not None:
            return False
        db.add(
            ProcessedBrokerMessage(
                message_id=message_id,
                stream=stream,
                consumer=consumer,
                subject=subject,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return False
        return True

    def _status_counts_for_metrics(
        self, db: Session
    ) -> tuple[dict[str, int], bool]:
        bind = db.get_bind()
        if bind.dialect.name != "postgresql":
            return (
                {
                    status: int(
                        db.scalar(
                            select(func.count())
                            .select_from(OutboxEvent)
                            .where(OutboxEvent.status == status)
                        )
                        or 0
                    )
                    for status in OUTBOX_STATUSES
                },
                False,
            )

        counts: dict[str, int] = {}
        for status in OUTBOX_STATUSES:
            plan = db.execute(
                text(
                    "EXPLAIN (FORMAT JSON) "
                    "SELECT 1 FROM outbox_events WHERE status = :status"
                ),
                {"status": status},
            ).scalar_one()
            try:
                estimate = plan[0]["Plan"]["Plan Rows"]
            except (IndexError, KeyError, TypeError) as error:
                raise RuntimeError(
                    "invalid PostgreSQL planner estimate for outbox metrics"
                ) from error
            counts[status] = max(0, int(estimate))
        return counts, True

    def metrics(self, db: Session) -> dict[str, Any]:
        now = utcnow()
        counts, counts_estimated = self._status_counts_for_metrics(db)
        oldest = (
            db.query(func.min(OutboxEvent.created_at))
            .filter(OutboxEvent.status.in_(["pending", "retry", "processing"]))
            .scalar()
        )
        online_replicas = (
            db.query(func.count(GatewayReplica.id))
            .filter(GatewayReplica.status == "online", GatewayReplica.expires_at > now)
            .scalar()
            or 0
        )
        online_routes = (
            db.query(func.count(RealtimeRoute.id))
            .filter(RealtimeRoute.status == "online", RealtimeRoute.expires_at > now)
            .scalar()
            or 0
        )
        return {
            "replica_id": self.replica_id,
            "broker_backend": self.settings.gateway_broker_backend,
            "outbox": counts,
            "outbox_counts_estimated": counts_estimated,
            "outbox_counts_source": (
                "postgres_planner_estimate" if counts_estimated else "exact"
            ),
            "pending_total": sum(counts.get(value, 0) for value in ("pending", "retry", "processing")),
            "dead_letter_total": counts.get("dead_letter", 0),
            "oldest_pending_age_seconds": max(
                0.0, (now - _aware(oldest)).total_seconds()
            )
            if oldest
            else 0.0,
            "online_replicas": int(online_replicas),
            "online_realtime_routes": int(online_routes),
        }


class OutboxWorker:
    def __init__(self, service: OutboxService) -> None:
        self.service = service
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._stopping.clear()
        await asyncio.to_thread(self._register_replica)
        if (
            self.service.settings.gateway_outbox_enabled
            and self.service.settings.gateway_broker_backend != "disabled"
        ):
            self._task = asyncio.create_task(
                self._run(), name="gateway-outbox-publisher"
            )
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat(), name="gateway-replica-heartbeat"
        )

    async def stop(self) -> None:
        self._stopping.set()
        for task in (self._task, self._heartbeat_task):
            if task is not None:
                task.cancel()
        for task in (self._task, self._heartbeat_task):
            if task is not None:
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        await asyncio.to_thread(self._stop_replica)

    def _register_replica(self) -> None:
        with self.service.session_factory() as db:
            self.service.register_replica(db)

    def _heartbeat_replica(self) -> None:
        with self.service.session_factory() as db:
            self.service.heartbeat_replica(db)

    def _stop_replica(self) -> None:
        with self.service.session_factory() as db:
            self.service.stop_replica(db)

    async def _run(self) -> None:
        interval = max(
            0.05, float(self.service.settings.gateway_outbox_poll_interval_seconds)
        )
        while not self._stopping.is_set():
            if not self.service.broker.healthy:
                await asyncio.sleep(interval)
                continue
            await self.service.run_once()
            # Always yield a bounded idle window between batches. A sustained
            # backlog must not monopolize the API process with publisher and
            # subscriber callbacks.
            await asyncio.sleep(interval)

    async def _heartbeat(self) -> None:
        interval = max(1, int(self.service.settings.gateway_replica_heartbeat_seconds))
        while not self._stopping.is_set():
            await asyncio.to_thread(self._heartbeat_replica)
            await asyncio.sleep(interval)
