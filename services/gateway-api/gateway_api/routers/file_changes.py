from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..dto import FileChangeSetOut
from ..models import FileChangeSet, User
from ..policy import enforce

router = APIRouter(prefix="/api/file-changes", tags=["file-changes"])


@router.get("", response_model=list[FileChangeSetOut])
async def list_file_changes(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 100,
    origin: str | None = None,
    resource_id: str | None = None,
) -> list[FileChangeSet]:
    enforce(user, action="read")
    safe_limit = min(max(int(limit), 1), 500)
    query = db.query(FileChangeSet).order_by(FileChangeSet.created_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(FileChangeSet.owner_subject == user.subject)
    if origin:
        query = query.filter(FileChangeSet.origin == origin)
    if resource_id:
        query = query.filter(FileChangeSet.resource_id == resource_id)
    return query.limit(safe_limit).all()
