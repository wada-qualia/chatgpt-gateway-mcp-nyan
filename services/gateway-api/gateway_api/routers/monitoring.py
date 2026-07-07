from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..dto import AgentToolCallOut, CommandSessionOutputOut, CommandSessionOut, CommandSessionTerminate
from ..models import AgentToolCall, CommandSession, User
from ..monitoring import monitoring_service
from ..policy import enforce
from ..thin_client_control import thin_client_manager

router = APIRouter(prefix="/api/command-sessions", tags=["command-sessions"])


def _owned_session(db: Session, user: User, session_id: str) -> CommandSession:
    session = db.get(CommandSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Command session not found")
    enforce(user, action="read", owner_subject=session.owner_subject)
    return session


@router.get("", response_model=list[CommandSessionOut])
async def list_command_sessions(
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CommandSession]:
    enforce(user, action="read")
    query = db.query(CommandSession).order_by(CommandSession.updated_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(CommandSession.owner_subject == user.subject)
    if status:
        query = query.filter(CommandSession.status == status)
    return query.limit(100).all()


@router.get("/{session_id}", response_model=CommandSessionOut)
async def get_command_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CommandSession:
    return _owned_session(db, user, session_id)


@router.get("/{session_id}/output", response_model=CommandSessionOutputOut)
async def get_command_session_output(
    session_id: str,
    start_line: int | None = Query(default=None, ge=1),
    limit: int | None = Query(default=200, ge=1, le=1000),
    tail: int | None = Query(default=None, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    session = _owned_session(db, user, session_id)
    return monitoring_service.output_window(
        db,
        session=session,
        start_line=start_line,
        limit=limit,
        tail=tail,
        owner_subject=user.subject,
        reason=None,
    )


@router.post("/{session_id}/terminate", response_model=CommandSessionOut)
async def terminate_command_session(
    session_id: str,
    payload: CommandSessionTerminate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CommandSession:
    session = _owned_session(db, user, session_id)
    enforce(user, action="update", owner_subject=session.owner_subject)
    if session.origin == "thin_client" and session.resource_id:
        try:
            await thin_client_manager.request(
                session.resource_id,
                tool="terminate_session",
                arguments={"session_id": session.id, "force": payload.force},
                timeout_seconds=10,
            )
        except HTTPException as exc:
            monitoring_service.finish_session(
                session.id,
                status_value="lost",
                exit_code=None,
                meta={"terminate_error": str(exc.detail)},
            )
            db.expire_all()
            session = db.get(CommandSession, session.id)
            if session is None:
                raise HTTPException(status_code=404, detail="Command session not found") from exc
            return session
    return await monitoring_service.terminate(db, session=session, force=payload.force)


@router.get("/{session_id}/tool-calls", response_model=list[AgentToolCallOut])
async def list_session_tool_calls(
    session_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AgentToolCall]:
    session = _owned_session(db, user, session_id)
    query = (
        db.query(AgentToolCall)
        .filter(AgentToolCall.owner_subject == session.owner_subject)
        .filter(AgentToolCall.session_id == session.id)
        .order_by(AgentToolCall.created_at.desc())
    )
    return query.limit(100).all()
