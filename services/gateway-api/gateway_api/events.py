from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditEvent, OutboxEvent, utcnow

logger = logging.getLogger(__name__)


def event_subject(event_type: str) -> str:
    settings = get_settings()
    prefix = settings.gateway_nats_subject_prefix.strip(".")
    return f"{prefix}.{event_type}" if prefix else event_type


def emit_event(
    db: Session,
    *,
    event_type: str,
    actor_subject: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    payload: dict[str, Any],
    status: str = "success",
    commit: bool = True,
    enqueue_outbox: bool = True,
) -> AuditEvent:
    settings = get_settings()
    now = utcnow()
    event = AuditEvent(
        id=str(uuid.uuid4()),
        event_type=event_type,
        actor_subject=actor_subject,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        payload=payload,
        created_at=now,
    )
    db.add(event)
    if enqueue_outbox and settings.gateway_outbox_enabled:
        envelope = {
            **payload,
            "event_id": event.id,
            "occurred_at": now.isoformat(),
        }
        db.add(
            OutboxEvent(
                id=str(uuid.uuid4()),
                audit_event_id=event.id,
                owner_subject=actor_subject,
                event_type=event_type,
                subject=event_subject(event_type),
                payload=envelope,
                headers={
                    "Content-Type": "application/json",
                    "Nats-Msg-Id": event.id,
                    "X-Gateway-Event-Id": event.id,
                    "X-Gateway-Event-Type": event_type,
                    "X-Gateway-Actor-Subject": actor_subject,
                    "X-Gateway-Action": action,
                    "X-Gateway-Resource-Type": resource_type,
                    "X-Gateway-Resource-Id": resource_id or "",
                    "X-Gateway-Status": status,
                },
                status="pending",
                max_attempts=max(1, int(settings.gateway_outbox_max_attempts)),
                available_at=now,
                created_at=now,
                updated_at=now,
            )
        )
    if commit:
        db.commit()
        db.refresh(event)
    else:
        db.flush()
    logger.info(
        "gateway_event_enqueued",
        extra={"event_type": event_type, "resource_id": resource_id, "event_id": event.id},
    )
    return event
