from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..dto import AuditEventOut
from ..models import AuditEvent, User
from ..policy import enforce

router = APIRouter(prefix="/api/audit/events", tags=["audit"])


@router.get("", response_model=list[AuditEventOut])
async def list_audit_events(user: User = Depends(get_current_user), db: Session = Depends(get_db), limit: int = 100) -> list[AuditEvent]:
    enforce(user, action="read_audit")
    return db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(limit, 500)).all()
