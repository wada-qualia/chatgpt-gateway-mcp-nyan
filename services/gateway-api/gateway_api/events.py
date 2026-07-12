from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditEvent

logger = logging.getLogger(__name__)


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
) -> AuditEvent:
    event = AuditEvent(
        id=str(uuid.uuid4()),
        event_type=event_type,
        actor_subject=actor_subject,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        payload=payload,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info("galaxy_event", extra={"event_type": event_type, "resource_id": resource_id})
    return event
