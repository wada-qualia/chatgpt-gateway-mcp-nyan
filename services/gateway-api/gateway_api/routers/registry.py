from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Text, func, or_
from sqlalchemy.orm import Session

from ..agent_autonomy import (
    agent_autonomy_service,
    approval_payload,
    assignment_payload,
    control_payload,
    override_payload,
    permit_payload,
    policy_payload,
    receipt_payload,
    recovery_payload,
)
from ..agent_collaboration import (
    agent_payload,
    command_payload,
    message_payload,
    room_payload,
    work_item_payload,
)
from ..agent_coordination import handoff_payload, integration_payload, lease_payload
from ..auth import get_current_user, require_role
from ..cold_history import (
    ColdHistoryClient,
    ColdHistoryProtocolError,
    ColdHistoryUnavailable,
    merge_history_pages,
)
from ..database import get_db
from ..dto import AgentToolCallOut, AuditEventOut, CommandSessionOut, FileChangeSetOut
from ..models import (
    ActionReceipt,
    AgentCommand,
    AgentHandoffBarrier,
    AgentInstance,
    AgentIntegrationRecord,
    AgentMessage,
    AgentMessageDelivery,
    AgentToolCall,
    AgentWorkItem,
    ApprovalRequest,
    ApprovalVote,
    AuditEvent,
    AutonomyAssignment,
    AutonomyControlState,
    AutonomyOverride,
    AutonomyPolicy,
    CollaborationRoom,
    CommandSession,
    CommandSessionDelivery,
    ExecutionPermit,
    FileChangeSet,
    GatewayReplica,
    OAuthClient,
    OutboxDeliveryAttempt,
    OutboxEvent,
    ProcessedBrokerMessage,
    RealtimeNotification,
    RealtimeRoute,
    RecoveryLoop,
    ResourceLease,
    User,
)
from ..pagination import CursorPage, decode_cursor, encode_cursor, page_desc
from ..policy import enforce

router = APIRouter(prefix="/api/registry", tags=["registry"])


_DISPLAY_SECRET_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "private_key",
    "refresh_token",
    "access_token",
    "secret",
}


def _redact_for_display(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _DISPLAY_SECRET_KEYS or normalized.endswith("_secret"):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = _redact_for_display(item)
        return result
    if isinstance(value, list):
        return [_redact_for_display(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_for_display(item) for item in value]
    return value


def _page(
    rows: list[Any],
    serializer: Callable[[Any], dict[str, Any]],
    next_cursor: str | None,
    has_more: bool,
) -> CursorPage:
    return CursorPage(
        items=[_redact_for_display(serializer(row)) for row in rows],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def _page_payloads(
    items: list[dict[str, Any]],
    next_cursor: str | None,
    has_more: bool,
) -> CursorPage:
    return CursorPage(
        items=[_redact_for_display(item) for item in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def _cold_history(request: Request) -> ColdHistoryClient | None:
    client = getattr(request.app.state, "cold_history_client", None)
    if client is None:
        return None
    if not isinstance(client, ColdHistoryClient):
        raise HTTPException(status_code=503, detail="Cold history client is unavailable")
    return client


def _cold_history_unavailable(_error: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail="Cold outbox history is temporarily unavailable")


def _cursor_boundary(cursor: str | None) -> tuple[str | None, str | None]:
    if not cursor:
        return None, None
    timestamp, item_id = decode_cursor(cursor)
    return timestamp.isoformat(), item_id


def _merged_next_cursor(
    items: list[dict[str, Any]],
    *,
    has_more: bool,
    timestamp_key: str,
) -> str | None:
    if not has_more or not items:
        return None
    last = items[-1]
    value = last.get(timestamp_key)
    if not isinstance(value, str):
        raise HTTPException(status_code=502, detail="Cold history pagination payload is invalid")
    return encode_cursor(datetime.fromisoformat(value), str(last["id"]))


def _owned_query(db: Session, model: Any, user: User):
    query = db.query(model)
    if hasattr(model, "owner_subject"):
        query = query.filter(model.owner_subject == user.subject)
    return query


def _session_payload(row: CommandSession) -> dict[str, Any]:
    return CommandSessionOut.model_validate(row).model_dump(mode="json")


def _tool_call_payload(row: AgentToolCall) -> dict[str, Any]:
    return AgentToolCallOut.model_validate(row).model_dump(mode="json")


def _file_change_payload(row: FileChangeSet) -> dict[str, Any]:
    return FileChangeSetOut.model_validate(row).model_dump(mode="json")


def _audit_payload(row: AuditEvent) -> dict[str, Any]:
    return AuditEventOut.model_validate(row).model_dump(mode="json")


def _delivery_payload(row: CommandSessionDelivery) -> dict[str, Any]:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "reason": row.reason,
        "start_line": row.start_line,
        "end_line": row.end_line,
        "tool_call_id": row.tool_call_id,
        "created_at": row.created_at.isoformat(),
    }


def _message_delivery_payload(row: AgentMessageDelivery) -> dict[str, Any]:
    return {
        "id": row.id,
        "message_id": row.message_id,
        "recipient_agent_id": row.recipient_agent_id,
        "status": row.status,
        "attempt_count": row.attempt_count,
        "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
        "acknowledged_at": row.acknowledged_at.isoformat()
        if row.acknowledged_at
        else None,
        "visibility_deadline": row.visibility_deadline.isoformat()
        if row.visibility_deadline
        else None,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


@router.get("/activity/sessions", response_model=CursorPage)
async def activity_sessions(
    status: str | None = None,
    origin: str | None = None,
    resource_id: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = db.query(CommandSession)
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(CommandSession.owner_subject == user.subject)
    if status:
        query = query.filter(CommandSession.status == status)
    if origin:
        query = query.filter(CommandSession.origin == origin)
    if resource_id:
        query = query.filter(CommandSession.resource_id == resource_id)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                CommandSession.name.ilike(pattern),
                CommandSession.command.ilike(pattern),
                CommandSession.cwd.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=CommandSession.updated_at,
        id_column=CommandSession.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _session_payload, next_cursor, has_more)


@router.get("/activity/tool-calls", response_model=CursorPage)
async def activity_tool_calls(
    session_id: str | None = None,
    status: str | None = None,
    tool_name: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = db.query(AgentToolCall)
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(AgentToolCall.owner_subject == user.subject)
    if session_id:
        query = query.filter(AgentToolCall.session_id == session_id)
    if status:
        query = query.filter(AgentToolCall.status == status)
    if tool_name:
        query = query.filter(AgentToolCall.tool_name.ilike(f"%{tool_name.strip()}%"))
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentToolCall.created_at,
        id_column=AgentToolCall.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _tool_call_payload, next_cursor, has_more)


@router.get("/activity/deliveries", response_model=CursorPage)
async def activity_deliveries(
    session_id: str | None = None,
    reason: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, CommandSessionDelivery, user)
    if session_id:
        query = query.filter(CommandSessionDelivery.session_id == session_id)
    if reason:
        query = query.filter(CommandSessionDelivery.reason == reason)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=CommandSessionDelivery.created_at,
        id_column=CommandSessionDelivery.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _delivery_payload, next_cursor, has_more)


@router.get("/activity/file-changes", response_model=CursorPage)
async def activity_file_changes(
    room_id: str | None = None,
    agent_id: str | None = None,
    lease_id: str | None = None,
    tool_call_id: str | None = None,
    origin: str | None = None,
    resource_id: str | None = None,
    operation: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = db.query(FileChangeSet)
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(FileChangeSet.owner_subject == user.subject)
    filters = {
        "room_id": room_id,
        "agent_id": agent_id,
        "lease_id": lease_id,
        "tool_call_id": tool_call_id,
        "origin": origin,
        "resource_id": resource_id,
        "operation": operation,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(FileChangeSet, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=FileChangeSet.created_at,
        id_column=FileChangeSet.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _file_change_payload, next_cursor, has_more)


@router.get("/activity/audit-events", response_model=CursorPage)
async def activity_audit_events(
    status: str | None = None,
    event_type: str | None = None,
    actor_subject: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read_audit")
    query = db.query(AuditEvent)
    filters = {
        "status": status,
        "event_type": event_type,
        "actor_subject": actor_subject,
        "resource_type": resource_type,
        "resource_id": resource_id,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(AuditEvent, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AuditEvent.created_at,
        id_column=AuditEvent.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _audit_payload, next_cursor, has_more)


@router.get("/collaboration/rooms", response_model=CursorPage)
async def collaboration_rooms(
    status: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, CollaborationRoom, user)
    if status:
        query = query.filter(CollaborationRoom.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                CollaborationRoom.title.ilike(pattern),
                CollaborationRoom.project_path.ilike(pattern),
                CollaborationRoom.repository_identity.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=CollaborationRoom.updated_at,
        id_column=CollaborationRoom.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, room_payload, next_cursor, has_more)


@router.get("/collaboration/agents", response_model=CursorPage)
async def collaboration_agents(
    room_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentInstance, user)
    if room_id:
        query = query.filter(AgentInstance.current_room_id == room_id)
    if status:
        query = query.filter(AgentInstance.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AgentInstance.display_name.ilike(pattern),
                AgentInstance.logical_agent_id.ilike(pattern),
                AgentInstance.instance_id.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentInstance.updated_at,
        id_column=AgentInstance.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, agent_payload, next_cursor, has_more)


@router.get("/collaboration/messages", response_model=CursorPage)
async def collaboration_messages(
    room_id: str | None = None,
    sender_agent_id: str | None = None,
    recipient_agent_id: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentMessage, user)
    filters = {
        "room_id": room_id,
        "sender_agent_id": sender_agent_id,
        "recipient_agent_id": recipient_agent_id,
        "kind": kind,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(AgentMessage, field) == value)
    if search:
        query = query.filter(AgentMessage.body.ilike(f"%{search.strip()}%"))
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentMessage.created_at,
        id_column=AgentMessage.id,
        limit=limit,
        cursor=cursor,
    )
    deliveries_by_message: dict[str, list[AgentMessageDelivery]] = defaultdict(list)
    if rows:
        deliveries = (
            db.query(AgentMessageDelivery)
            .filter(
                AgentMessageDelivery.owner_subject == user.subject,
                AgentMessageDelivery.message_id.in_([row.id for row in rows]),
            )
            .order_by(AgentMessageDelivery.created_at, AgentMessageDelivery.id)
            .all()
        )
        for delivery in deliveries:
            deliveries_by_message[delivery.message_id].append(delivery)

    def serialize(row: AgentMessage) -> dict[str, Any]:
        payload = message_payload(row)
        payload["deliveries"] = [
            _message_delivery_payload(delivery)
            for delivery in deliveries_by_message.get(row.id, [])
        ]
        return payload

    return _page(rows, serialize, next_cursor, has_more)


@router.get("/collaboration/commands", response_model=CursorPage)
async def collaboration_commands(
    room_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentCommand, user)
    if room_id:
        query = query.filter(AgentCommand.room_id == room_id)
    if agent_id:
        query = query.filter(
            or_(
                AgentCommand.issuer_agent_id == agent_id,
                AgentCommand.target_agent_id == agent_id,
            )
        )
    if status:
        query = query.filter(AgentCommand.status == status)
    if kind:
        query = query.filter(AgentCommand.kind == kind)
    if search:
        query = query.filter(AgentCommand.instruction.ilike(f"%{search.strip()}%"))
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentCommand.created_at,
        id_column=AgentCommand.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, command_payload, next_cursor, has_more)


@router.get("/collaboration/work-items", response_model=CursorPage)
async def collaboration_work_items(
    room_id: str | None = None,
    assigned_agent_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentWorkItem, user)
    if room_id:
        query = query.filter(AgentWorkItem.room_id == room_id)
    if assigned_agent_id:
        query = query.filter(AgentWorkItem.assigned_agent_id == assigned_agent_id)
    if status:
        query = query.filter(AgentWorkItem.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AgentWorkItem.title.ilike(pattern),
                AgentWorkItem.description.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentWorkItem.updated_at,
        id_column=AgentWorkItem.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, work_item_payload, next_cursor, has_more)


@router.get("/coordination/leases", response_model=CursorPage)
async def coordination_leases(
    room_id: str | None = None,
    holder_agent_id: str | None = None,
    status: str | None = None,
    origin: str | None = None,
    resource_id: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, ResourceLease, user)
    filters = {
        "room_id": room_id,
        "holder_agent_id": holder_agent_id,
        "status": status,
        "origin": origin,
        "resource_id": resource_id,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(ResourceLease, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=ResourceLease.created_at,
        id_column=ResourceLease.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, lease_payload, next_cursor, has_more)


@router.get("/coordination/handoffs", response_model=CursorPage)
async def coordination_handoffs(
    room_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentHandoffBarrier, user)
    if room_id:
        query = query.filter(AgentHandoffBarrier.room_id == room_id)
    if agent_id:
        query = query.filter(
            or_(
                AgentHandoffBarrier.source_agent_id == agent_id,
                AgentHandoffBarrier.target_agent_id == agent_id,
            )
        )
    if status:
        query = query.filter(AgentHandoffBarrier.status == status)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentHandoffBarrier.created_at,
        id_column=AgentHandoffBarrier.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, handoff_payload, next_cursor, has_more)


@router.get("/coordination/integrations", response_model=CursorPage)
async def coordination_integrations(
    room_id: str | None = None,
    coordinator_agent_id: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AgentIntegrationRecord, user)
    if room_id:
        query = query.filter(AgentIntegrationRecord.room_id == room_id)
    if coordinator_agent_id:
        query = query.filter(
            AgentIntegrationRecord.coordinator_agent_id == coordinator_agent_id
        )
    if status:
        query = query.filter(AgentIntegrationRecord.status == status)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AgentIntegrationRecord.created_at,
        id_column=AgentIntegrationRecord.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, integration_payload, next_cursor, has_more)


@router.get("/autonomy/policies", response_model=CursorPage)
async def autonomy_policies(
    room_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AutonomyPolicy, user)
    if room_id:
        query = query.filter(AutonomyPolicy.room_id == room_id)
    if status:
        query = query.filter(AutonomyPolicy.status == status)
    if search:
        query = query.filter(AutonomyPolicy.name.ilike(f"%{search.strip()}%"))
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AutonomyPolicy.created_at,
        id_column=AutonomyPolicy.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, policy_payload, next_cursor, has_more)


@router.get("/autonomy/controls", response_model=CursorPage)
async def autonomy_controls(
    scope_type: str | None = None,
    state: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AutonomyControlState, user)
    if scope_type:
        query = query.filter(AutonomyControlState.scope_type == scope_type)
    if state:
        query = query.filter(AutonomyControlState.state == state)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AutonomyControlState.updated_at,
        id_column=AutonomyControlState.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, control_payload, next_cursor, has_more)


@router.get("/autonomy/overrides", response_model=CursorPage)
async def autonomy_overrides(
    scope_type: str | None = None,
    action: str | None = None,
    actor_subject: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read_audit")
    query = _owned_query(db, AutonomyOverride, user)
    filters = {
        "scope_type": scope_type,
        "action": action,
        "actor_subject": actor_subject,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(AutonomyOverride, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AutonomyOverride.created_at,
        id_column=AutonomyOverride.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, override_payload, next_cursor, has_more)


@router.get("/autonomy/assignments", response_model=CursorPage)
async def autonomy_assignments(
    room_id: str | None = None,
    policy_id: str | None = None,
    selected_agent_id: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, AutonomyAssignment, user)
    filters = {
        "room_id": room_id,
        "policy_id": policy_id,
        "selected_agent_id": selected_agent_id,
        "status": status,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(AutonomyAssignment, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=AutonomyAssignment.created_at,
        id_column=AutonomyAssignment.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, assignment_payload, next_cursor, has_more)


@router.get("/autonomy/approvals", response_model=CursorPage)
async def autonomy_approvals(
    room_id: str | None = None,
    policy_id: str | None = None,
    executor_agent_id: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = agent_autonomy_service.approval_visibility_query(db, user=user)
    filters = {
        "room_id": room_id,
        "policy_id": policy_id,
        "executor_agent_id": executor_agent_id,
        "status": status,
        "tool": tool,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(ApprovalRequest, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=ApprovalRequest.created_at,
        id_column=ApprovalRequest.id,
        limit=limit,
        cursor=cursor,
    )
    votes_by_request: dict[str, list[ApprovalVote]] = defaultdict(list)
    if rows:
        votes = (
            db.query(ApprovalVote)
            .filter(ApprovalVote.request_id.in_([row.id for row in rows]))
            .order_by(ApprovalVote.created_at, ApprovalVote.id)
            .all()
        )
        for vote in votes:
            votes_by_request[vote.request_id].append(vote)

    def serialize(row: ApprovalRequest) -> dict[str, Any]:
        votes = votes_by_request.get(row.id, [])
        result = approval_payload(row, votes)
        result["review"] = agent_autonomy_service.approval_review_projection(
            db, request=row, user=user, votes=votes
        )
        return result

    return _page(rows, serialize, next_cursor, has_more)


@router.get("/autonomy/permits", response_model=CursorPage)
async def autonomy_permits(
    policy_id: str | None = None,
    executor_agent_id: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, ExecutionPermit, user)
    filters = {
        "policy_id": policy_id,
        "executor_agent_id": executor_agent_id,
        "status": status,
        "tool": tool,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(ExecutionPermit, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=ExecutionPermit.created_at,
        id_column=ExecutionPermit.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, permit_payload, next_cursor, has_more)


@router.get("/autonomy/receipts", response_model=CursorPage)
async def autonomy_receipts(
    command_id: str | None = None,
    executor_agent_id: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, ActionReceipt, user)
    filters = {
        "command_id": command_id,
        "executor_agent_id": executor_agent_id,
        "status": status,
        "tool": tool,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(ActionReceipt, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=ActionReceipt.created_at,
        id_column=ActionReceipt.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, receipt_payload, next_cursor, has_more)


@router.get("/autonomy/recoveries", response_model=CursorPage)
async def autonomy_recoveries(
    room_id: str | None = None,
    policy_id: str | None = None,
    target_agent_id: str | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    enforce(user, action="read")
    query = _owned_query(db, RecoveryLoop, user)
    filters = {
        "room_id": room_id,
        "policy_id": policy_id,
        "target_agent_id": target_agent_id,
        "status": status,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(RecoveryLoop, field) == value)
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=RecoveryLoop.created_at,
        id_column=RecoveryLoop.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, recovery_payload, next_cursor, has_more)


def _operations_registry_user(user: User) -> None:
    require_role(user, "gateway-auditor", "gateway-admin")


def _administration_registry_user(user: User) -> None:
    require_role(user, "gateway-admin")


def _datetime(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _outbox_attempt_payload(row: OutboxDeliveryAttempt) -> dict[str, Any]:
    return {
        "id": row.id,
        "outbox_event_id": row.outbox_event_id,
        "attempt_number": row.attempt_number,
        "replica_id": row.replica_id,
        "status": row.status,
        "error": row.error,
        "broker_stream": row.broker_stream,
        "broker_sequence": row.broker_sequence,
        "started_at": _datetime(row.started_at),
        "completed_at": _datetime(row.completed_at),
    }


def _outbox_payload(
    row: OutboxEvent, attempts: list[OutboxDeliveryAttempt] | None = None
) -> dict[str, Any]:
    return {
        "id": row.id,
        "audit_event_id": row.audit_event_id,
        "owner_subject": row.owner_subject,
        "event_type": row.event_type,
        "subject": row.subject,
        "payload": row.payload,
        "headers": row.headers,
        "status": row.status,
        "attempt_count": row.attempt_count,
        "max_attempts": row.max_attempts,
        "available_at": _datetime(row.available_at),
        "locked_by": row.locked_by,
        "locked_at": _datetime(row.locked_at),
        "published_at": _datetime(row.published_at),
        "broker_stream": row.broker_stream,
        "broker_sequence": row.broker_sequence,
        "last_error": row.last_error,
        "replay_count": row.replay_count,
        "replayed_from_id": row.replayed_from_id,
        "attempts": [_outbox_attempt_payload(item) for item in attempts or []],
        "created_at": _datetime(row.created_at),
        "updated_at": _datetime(row.updated_at),
    }


def _replica_payload(row: GatewayReplica) -> dict[str, Any]:
    return {
        "id": row.id,
        "hostname": row.hostname,
        "process_id": row.process_id,
        "status": row.status,
        "meta": row.meta,
        "started_at": _datetime(row.started_at),
        "last_heartbeat_at": _datetime(row.last_heartbeat_at),
        "expires_at": _datetime(row.expires_at),
        "stopped_at": _datetime(row.stopped_at),
    }


def _realtime_route_payload(row: RealtimeRoute) -> dict[str, Any]:
    return {
        "id": row.id,
        "owner_subject": row.owner_subject,
        "target_kind": row.target_kind,
        "target_id": row.target_id,
        "connection_id": row.connection_id,
        "replica_id": row.replica_id,
        "status": row.status,
        "meta": row.meta,
        "connected_at": _datetime(row.connected_at),
        "last_seen_at": _datetime(row.last_seen_at),
        "expires_at": _datetime(row.expires_at),
        "disconnected_at": _datetime(row.disconnected_at),
    }


def _realtime_notification_payload(row: RealtimeNotification) -> dict[str, Any]:
    return {
        "id": row.id,
        "owner_subject": row.owner_subject,
        "target_kind": row.target_kind,
        "target_id": row.target_id,
        "event_type": row.event_type,
        "payload": row.payload,
        "status": row.status,
        "replica_id": row.replica_id,
        "outbox_event_id": row.outbox_event_id,
        "attempt_count": row.attempt_count,
        "delivered_at": _datetime(row.delivered_at),
        "acknowledged_at": _datetime(row.acknowledged_at),
        "expires_at": _datetime(row.expires_at),
        "created_at": _datetime(row.created_at),
        "updated_at": _datetime(row.updated_at),
    }


def _user_payload(row: User) -> dict[str, Any]:
    return {
        "id": row.subject,
        "database_id": row.id,
        "subject": row.subject,
        "username": row.username,
        "email": row.email,
        "roles": row.roles or [],
        "provider": row.provider,
        "created_at": _datetime(row.created_at),
        "last_seen_at": _datetime(row.last_seen_at),
    }


def _oauth_client_payload(row: OAuthClient) -> dict[str, Any]:
    return {
        "id": row.client_id,
        "client_id": row.client_id,
        "client_name": row.client_name,
        "redirect_uris": row.redirect_uris or [],
        "scopes": [value for value in row.scope.split() if value],
        "created_at": _datetime(row.created_at),
    }


@router.get("/operations/outbox", response_model=CursorPage)
async def operations_outbox(
    request: Request,
    status: str | None = None,
    owner_subject: str | None = None,
    event_type: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(OutboxEvent)
    if status:
        query = query.filter(OutboxEvent.status == status)
    if owner_subject:
        query = query.filter(OutboxEvent.owner_subject == owner_subject)
    if event_type:
        query = query.filter(OutboxEvent.event_type == event_type)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                OutboxEvent.id.ilike(pattern),
                OutboxEvent.event_type.ilike(pattern),
                OutboxEvent.subject.ilike(pattern),
                OutboxEvent.owner_subject.ilike(pattern),
            )
        )
    rows, hot_next_cursor, hot_has_more = page_desc(
        query,
        timestamp_column=OutboxEvent.created_at,
        id_column=OutboxEvent.id,
        limit=limit,
        cursor=cursor,
    )
    attempts_by_event: dict[str, list[OutboxDeliveryAttempt]] = defaultdict(list)
    if rows:
        attempts = (
            db.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id.in_([row.id for row in rows]))
            .order_by(
                OutboxDeliveryAttempt.outbox_event_id,
                OutboxDeliveryAttempt.attempt_number,
            )
            .all()
        )
        for attempt in attempts:
            attempts_by_event[attempt.outbox_event_id].append(attempt)

    def serialize(row: OutboxEvent) -> dict[str, Any]:
        return _outbox_payload(row, attempts_by_event.get(row.id, []))

    cold = _cold_history(request)
    if cold is None:
        return _page(rows, serialize, hot_next_cursor, hot_has_more)
    before_timestamp, before_id = _cursor_boundary(cursor)
    try:
        cold_page = await cold.list_events(
            status=status,
            owner_subject=owner_subject,
            event_type=event_type,
            search=search,
            before_timestamp=before_timestamp,
            before_id=before_id,
            include_attempts=True,
            limit=limit,
        )
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    merged, has_more = merge_history_pages(
        [serialize(row) for row in rows],
        cold_page.items,
        timestamp_key="created_at",
        limit=limit,
        hot_has_more=hot_has_more,
        cold_has_more=cold_page.has_more,
    )
    return _page_payloads(
        merged,
        _merged_next_cursor(merged, has_more=has_more, timestamp_key="created_at"),
        has_more,
    )


@router.get("/operations/outbox-attempts", response_model=CursorPage)
async def operations_outbox_attempts(
    request: Request,
    status: str | None = None,
    outbox_event_id: str | None = None,
    replica_id: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(OutboxDeliveryAttempt)
    if status:
        query = query.filter(OutboxDeliveryAttempt.status == status)
    if outbox_event_id:
        query = query.filter(OutboxDeliveryAttempt.outbox_event_id == outbox_event_id)
    if replica_id:
        query = query.filter(OutboxDeliveryAttempt.replica_id == replica_id)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                OutboxDeliveryAttempt.outbox_event_id.ilike(pattern),
                OutboxDeliveryAttempt.replica_id.ilike(pattern),
                OutboxDeliveryAttempt.error.ilike(pattern),
            )
        )
    rows, hot_next_cursor, hot_has_more = page_desc(
        query,
        timestamp_column=OutboxDeliveryAttempt.started_at,
        id_column=OutboxDeliveryAttempt.id,
        limit=limit,
        cursor=cursor,
    )
    cold = _cold_history(request)
    if cold is None:
        return _page(rows, _outbox_attempt_payload, hot_next_cursor, hot_has_more)
    before_timestamp, before_id = _cursor_boundary(cursor)
    try:
        cold_page = await cold.list_attempts(
            status=status,
            outbox_event_id=outbox_event_id,
            replica_id=replica_id,
            search=search,
            before_timestamp=before_timestamp,
            before_id=before_id,
            limit=limit,
        )
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    merged, has_more = merge_history_pages(
        [_outbox_attempt_payload(row) for row in rows],
        cold_page.items,
        timestamp_key="started_at",
        limit=limit,
        hot_has_more=hot_has_more,
        cold_has_more=cold_page.has_more,
    )
    return _page_payloads(
        merged,
        _merged_next_cursor(merged, has_more=has_more, timestamp_key="started_at"),
        has_more,
    )


@router.get("/operations/replicas", response_model=CursorPage)
async def operations_replicas(
    status: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(GatewayReplica)
    if status:
        query = query.filter(GatewayReplica.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                GatewayReplica.id.ilike(pattern), GatewayReplica.hostname.ilike(pattern)
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=GatewayReplica.last_heartbeat_at,
        id_column=GatewayReplica.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _replica_payload, next_cursor, has_more)


@router.get("/operations/realtime-routes", response_model=CursorPage)
async def operations_realtime_routes(
    status: str | None = None,
    owner_subject: str | None = None,
    target_kind: str | None = None,
    replica_id: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(RealtimeRoute)
    filters = {
        "status": status,
        "owner_subject": owner_subject,
        "target_kind": target_kind,
        "replica_id": replica_id,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(RealtimeRoute, field) == value)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                RealtimeRoute.target_id.ilike(pattern),
                RealtimeRoute.connection_id.ilike(pattern),
                RealtimeRoute.replica_id.ilike(pattern),
                RealtimeRoute.owner_subject.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=RealtimeRoute.last_seen_at,
        id_column=RealtimeRoute.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _realtime_route_payload, next_cursor, has_more)


@router.get("/operations/notifications", response_model=CursorPage)
async def operations_notifications(
    status: str | None = None,
    owner_subject: str | None = None,
    target_kind: str | None = None,
    target_id: str | None = None,
    replica_id: str | None = None,
    event_type: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(RealtimeNotification)
    filters = {
        "status": status,
        "owner_subject": owner_subject,
        "target_kind": target_kind,
        "target_id": target_id,
        "replica_id": replica_id,
        "event_type": event_type,
    }
    for field, value in filters.items():
        if value:
            query = query.filter(getattr(RealtimeNotification, field) == value)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                RealtimeNotification.event_type.ilike(pattern),
                RealtimeNotification.target_id.ilike(pattern),
                RealtimeNotification.owner_subject.ilike(pattern),
                RealtimeNotification.outbox_event_id.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=RealtimeNotification.created_at,
        id_column=RealtimeNotification.id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _realtime_notification_payload, next_cursor, has_more)


@router.get("/operations/broker-diagnostics", response_model=CursorPage)
async def operations_broker_diagnostics(
    stream: str | None = None,
    consumer: str | None = None,
    search: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _operations_registry_user(user)
    query = db.query(
        ProcessedBrokerMessage.stream.label("stream"),
        ProcessedBrokerMessage.consumer.label("consumer"),
        func.count(ProcessedBrokerMessage.message_id).label("message_count"),
        func.max(ProcessedBrokerMessage.processed_at).label("last_processed_at"),
    )
    if stream:
        query = query.filter(ProcessedBrokerMessage.stream == stream)
    if consumer:
        query = query.filter(ProcessedBrokerMessage.consumer == consumer)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ProcessedBrokerMessage.stream.ilike(pattern),
                ProcessedBrokerMessage.consumer.ilike(pattern),
                ProcessedBrokerMessage.subject.ilike(pattern),
            )
        )
    groups = (
        query.group_by(ProcessedBrokerMessage.stream, ProcessedBrokerMessage.consumer)
        .order_by(func.max(ProcessedBrokerMessage.processed_at).desc())
        .limit(limit)
        .all()
    )
    items = []
    for group in groups:
        stream_value = group.stream or "unassigned"
        consumer_value = group.consumer or "unassigned"
        items.append(
            {
                "id": f"{stream_value}:{consumer_value}",
                "stream": group.stream,
                "consumer": group.consumer,
                "message_count": int(group.message_count),
                "last_processed_at": _datetime(group.last_processed_at),
                "mode": "aggregate-only",
            }
        )
    return CursorPage(items=items, next_cursor=None, has_more=False)


@router.get("/administration/users", response_model=CursorPage)
async def administration_users(
    provider: str | None = None,
    role: str | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _administration_registry_user(user)
    query = db.query(User)
    if provider:
        query = query.filter(User.provider == provider)
    if role:
        pattern = f'%"{role.strip()}"%'
        query = query.filter(User.roles.cast(Text).ilike(pattern))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                User.subject.ilike(pattern),
                User.username.ilike(pattern),
                User.email.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=User.last_seen_at,
        id_column=User.subject,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _user_payload, next_cursor, has_more)


@router.get("/administration/oauth-clients", response_model=CursorPage)
async def administration_oauth_clients(
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CursorPage:
    _administration_registry_user(user)
    query = db.query(OAuthClient)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                OAuthClient.client_id.ilike(pattern),
                OAuthClient.client_name.ilike(pattern),
                OAuthClient.scope.ilike(pattern),
            )
        )
    rows, next_cursor, has_more = page_desc(
        query,
        timestamp_column=OAuthClient.created_at,
        id_column=OAuthClient.client_id,
        limit=limit,
        cursor=cursor,
    )
    return _page(rows, _oauth_client_payload, next_cursor, has_more)
