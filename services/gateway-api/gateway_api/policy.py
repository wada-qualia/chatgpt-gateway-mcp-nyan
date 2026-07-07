from __future__ import annotations

from fastapi import HTTPException, status

from .models import User


def enforce(user: User, *, action: str, owner_subject: str | None = None) -> None:
    roles = set(user.roles or [])
    if "gateway-admin" in roles:
        return
    if action in {"read", "create", "update", "delete"} and "gateway-user" in roles:
        if owner_subject is None or owner_subject == user.subject:
            return
    if action == "read_audit" and "gateway-auditor" in roles:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Galaxy policy denied")
