from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..dto import AccessGrantCreate, AccessGrantOut
from ..events import emit_event
from ..models import AccessGrant, User
from ..policy import enforce

router = APIRouter(prefix="/api/access/grants", tags=["access"])


@router.get("", response_model=list[AccessGrantOut])
async def list_grants(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[AccessGrant]:
    enforce(user, action="read")
    query = db.query(AccessGrant).order_by(AccessGrant.created_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(AccessGrant.owner_subject == user.subject)
    return query.all()


@router.post("", response_model=AccessGrantOut, status_code=201)
async def create_grant(payload: AccessGrantCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> AccessGrant:
    enforce(user, action="create", owner_subject=user.subject)
    grant = AccessGrant(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        grantee_subject=payload.grantee_subject,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        scopes=payload.scopes,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)
    emit_event(
        db,
        event_type="gateway.access_grant.changed.v1",
        actor_subject=user.subject,
        action="created",
        resource_type="access_grant",
        resource_id=grant.id,
        payload={"grant_id": grant.id, "resource_type": grant.resource_type, "resource_id": grant.resource_id},
    )
    return grant
