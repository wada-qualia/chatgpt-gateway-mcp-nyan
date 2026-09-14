from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from ..auth import decode_jwt, get_current_user
from ..chat_context import (
    ChatContextAllocationExhausted,
    ChatContextBindingConflict,
    ChatContextClosed,
    ChatContextDisabled,
    ChatContextError,
    ChatContextExpired,
    ChatContextLease,
    ChatContextNotFound,
    ChatContextService,
    ChatContextValidationError,
)
from ..config import Settings, get_settings
from ..database import get_db
from ..models import (
    AgentToolCall,
    ChatContext,
    ChatContextAlias,
    CommandSession,
    FileChangeSet,
    User,
)
from ..policy import enforce

router = APIRouter(prefix="/api/chat-contexts/v1", tags=["chat-context"])


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class CreateChatContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_nonce: str = Field(min_length=1, max_length=128)
    project_ref: str | None = Field(default=None, max_length=255)


class BindChatContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_ref: str = Field(min_length=1, max_length=512)


class ResolveChatContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_ref: str = Field(min_length=1, max_length=512)


class ChatContextLeaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_id: str
    chat_context: str = Field(pattern=r"^[A-Za-z0-9]{4}$")
    generation: int = Field(ge=1)
    expires_at: datetime


class ChatContextBindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_id: str
    key_version: int = Field(ge=1)
    newly_bound: bool


class ChatContextOperatorSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_id: str
    state: str
    host_kind: str
    project_ref: str | None = None
    chat_context: str | None = Field(default=None, pattern=r"^[A-Za-z0-9]{4}$")
    generation: int = Field(ge=0)
    alias_expires_at: datetime | None = None
    bound: bool
    created_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    tool_call_count: int = Field(ge=0)
    command_session_count: int = Field(ge=0)
    file_change_count: int = Field(ge=0)


async def require_browser_extension_chat_context_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Browser extension bearer authentication is required",
        )
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
        )
    try:
        claims = decode_jwt(token)
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
        ) from error
    if claims.get("typ") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
        )
    if claims.get("client_id") != settings.gateway_browser_extension_client_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Policy denied"
        )
    scopes = {
        value
        for value in str(claims.get("scope") or "").replace(",", " ").split()
        if value
    }
    if "chat-context:write" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Policy denied"
        )
    return await get_current_user(request, db=db, settings=settings)


def _raise_chat_context_error(error: ChatContextError) -> None:
    if isinstance(error, ChatContextDisabled):
        raise HTTPException(
            status_code=503, detail="Chat context service is unavailable"
        ) from error
    if isinstance(error, ChatContextValidationError):
        raise HTTPException(status_code=422, detail=str(error)) from error
    if isinstance(error, ChatContextNotFound):
        raise HTTPException(
            status_code=404, detail="Chat context was not found"
        ) from error
    if isinstance(error, ChatContextBindingConflict):
        raise HTTPException(status_code=409, detail=str(error)) from error
    if isinstance(error, (ChatContextClosed, ChatContextExpired)):
        raise HTTPException(status_code=409, detail=str(error)) from error
    if isinstance(error, ChatContextAllocationExhausted):
        raise HTTPException(
            status_code=503, detail="Chat context allocation is unavailable"
        ) from error
    raise HTTPException(
        status_code=500, detail="Chat context operation failed"
    ) from error


def _lease_response(lease: ChatContextLease) -> ChatContextLeaseResponse:
    return ChatContextLeaseResponse(
        context_id=lease.context_id,
        chat_context=lease.code,
        generation=lease.generation,
        expires_at=lease.expires_at,
    )


@router.get(
    "/operator/contexts",
    response_model=list[ChatContextOperatorSummaryResponse],
)
def list_operator_contexts(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[ChatContextOperatorSummaryResponse]:
    enforce(user, action="read")

    tool_call_count = (
        select(func.count())
        .where(
            AgentToolCall.owner_subject == user.subject,
            AgentToolCall.chat_context_id == ChatContext.id,
        )
        .correlate(ChatContext)
        .scalar_subquery()
    )
    command_session_count = (
        select(func.count())
        .where(
            CommandSession.owner_subject == user.subject,
            CommandSession.chat_context_id == ChatContext.id,
        )
        .correlate(ChatContext)
        .scalar_subquery()
    )
    file_change_count = (
        select(func.count())
        .where(
            FileChangeSet.owner_subject == user.subject,
            FileChangeSet.chat_context_id == ChatContext.id,
        )
        .correlate(ChatContext)
        .scalar_subquery()
    )

    rows = (
        db.query(
            ChatContext,
            ChatContextAlias,
            tool_call_count.label("tool_call_count"),
            command_session_count.label("command_session_count"),
            file_change_count.label("file_change_count"),
        )
        .outerjoin(
            ChatContextAlias,
            and_(
                ChatContextAlias.context_id == ChatContext.id,
                ChatContextAlias.owner_subject == ChatContext.owner_subject,
                ChatContextAlias.status == "active",
            ),
        )
        .filter(ChatContext.owner_subject == user.subject)
        .order_by(ChatContext.last_seen_at.desc(), ChatContext.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        ChatContextOperatorSummaryResponse(
            context_id=context.id,
            state=context.state,
            host_kind=context.host_kind,
            project_ref=context.project_ref,
            chat_context=alias.code if alias is not None else None,
            generation=context.generation,
            alias_expires_at=_as_utc(alias.expires_at) if alias is not None else None,
            bound=context.conversation_ref_hmac is not None,
            created_at=_as_utc(context.created_at),
            last_seen_at=_as_utc(context.last_seen_at),
            updated_at=_as_utc(context.updated_at),
            tool_call_count=int(tool_calls or 0),
            command_session_count=int(command_sessions or 0),
            file_change_count=int(file_changes or 0),
        )
        for context, alias, tool_calls, command_sessions, file_changes in rows
    ]


@router.post("/contexts", response_model=ChatContextLeaseResponse)
async def create_context(
    payload: CreateChatContextRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    user: Annotated[User, Depends(require_browser_extension_chat_context_principal)],
) -> ChatContextLeaseResponse:
    try:
        lease = ChatContextService(settings, telemetry=request.app.state.chat_context_telemetry).create_provisional(
            db,
            owner_subject=user.subject,
            client_nonce=payload.client_nonce,
            project_ref=payload.project_ref,
            actor_kind="browser_extension",
        )
        db.commit()
        return _lease_response(lease)
    except ChatContextError as error:
        db.rollback()
        _raise_chat_context_error(error)
        raise AssertionError("unreachable")


@router.post(
    "/contexts/{context_id}/bind",
    response_model=ChatContextBindingResponse,
)
async def bind_context(
    context_id: str,
    payload: BindChatContextRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    user: Annotated[User, Depends(require_browser_extension_chat_context_principal)],
) -> ChatContextBindingResponse:
    try:
        binding = ChatContextService(settings, telemetry=request.app.state.chat_context_telemetry).bind_conversation(
            db,
            owner_subject=user.subject,
            context_id=context_id,
            conversation_reference=payload.conversation_ref,
            actor_kind="browser_extension",
        )
        db.commit()
        return ChatContextBindingResponse(
            context_id=binding.context_id,
            key_version=binding.key_version,
            newly_bound=binding.newly_bound,
        )
    except ChatContextError as error:
        db.rollback()
        _raise_chat_context_error(error)
        raise AssertionError("unreachable")


@router.post("/resolve", response_model=ChatContextLeaseResponse)
async def resolve_context(
    payload: ResolveChatContextRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    user: Annotated[User, Depends(require_browser_extension_chat_context_principal)],
) -> ChatContextLeaseResponse:
    try:
        lease = ChatContextService(settings, telemetry=request.app.state.chat_context_telemetry).resolve_conversation_lease(
            db,
            owner_subject=user.subject,
            conversation_reference=payload.conversation_ref,
            actor_kind="browser_extension",
        )
        db.commit()
        return _lease_response(lease)
    except ChatContextError as error:
        db.rollback()
        _raise_chat_context_error(error)
        raise AssertionError("unreachable")
