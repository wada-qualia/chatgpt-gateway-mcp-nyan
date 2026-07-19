from __future__ import annotations

import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from sqlalchemy.orm import Session

from ..auth import decode_jwt, dev_user, get_current_user
from ..config import get_settings
from ..database import SessionLocal, get_db
from ..dto import RealtimeNotificationOut
from ..models import AgentInstance, User
from ..policy import enforce
from ..realtime import notification_payload
from ..runtime import GatewayRuntime

router = APIRouter(prefix="/api/agent-realtime", tags=["agent-realtime"])


def _runtime_from_request(request: Request) -> GatewayRuntime:
    runtime = getattr(request.app.state, "gateway_runtime", None)
    if not isinstance(runtime, GatewayRuntime):
        raise HTTPException(status_code=503, detail="Gateway runtime is unavailable")
    return runtime


def _owned_agent(db: Session, *, owner_subject: str, agent_id: str) -> AgentInstance:
    agent = (
        db.query(AgentInstance)
        .filter(
            AgentInstance.id == agent_id,
            AgentInstance.owner_subject == owner_subject,
        )
        .one_or_none()
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/notifications", response_model=list[RealtimeNotificationOut])
async def list_notifications(
    request: Request,
    agent_id: str,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read", owner_subject=user.subject)
    _owned_agent(db, owner_subject=user.subject, agent_id=agent_id)
    return _runtime_from_request(request).realtime.list_notifications(
        db,
        owner_subject=user.subject,
        target_kind="agent",
        target_id=agent_id,
        status=status,
        limit=limit,
    )


@router.post(
    "/notifications/{notification_id}/ack",
    response_model=RealtimeNotificationOut,
)
async def acknowledge_notification(
    notification_id: str,
    request: Request,
    agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="update", owner_subject=user.subject)
    _owned_agent(db, owner_subject=user.subject, agent_id=agent_id)
    try:
        return _runtime_from_request(request).realtime.acknowledge_notification(
            db,
            owner_subject=user.subject,
            target_kind="agent",
            target_id=agent_id,
            notification_id=notification_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _websocket_user(db: Session, token: str | None) -> User | None:
    settings = get_settings()
    if token:
        try:
            claims = decode_jwt(token)
        except Exception:
            return None
        return db.query(User).filter(User.subject == str(claims.get("sub") or "")).one_or_none()
    if settings.gateway_dev_auth:
        return dev_user(db, settings)
    return None


@router.websocket("/ws/{agent_id}")
async def agent_realtime_websocket(
    websocket: WebSocket,
    agent_id: str,
    token: str | None = None,
) -> None:
    runtime = getattr(websocket.app.state, "gateway_runtime", None)
    if not isinstance(runtime, GatewayRuntime):
        await websocket.close(code=1013)
        return
    with SessionLocal() as db:
        user = _websocket_user(db, token)
        if user is None:
            await websocket.close(code=4401)
            return
        agent = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.id == agent_id,
                AgentInstance.owner_subject == user.subject,
            )
            .one_or_none()
        )
        if agent is None:
            await websocket.close(code=4404)
            return
        owner_subject = user.subject
    await websocket.accept()
    connection_id = str(uuid.uuid4())
    await runtime.realtime.hub.register(
        owner_subject=owner_subject,
        target_kind="agent",
        target_id=agent_id,
        connection_id=connection_id,
        websocket=websocket,
    )
    with SessionLocal() as db:
        runtime.realtime.register_route(
            db,
            owner_subject=owner_subject,
            target_kind="agent",
            target_id=agent_id,
            connection_id=connection_id,
            meta={"transport": "websocket"},
        )
        backlog = runtime.realtime.list_notifications(
            db,
            owner_subject=owner_subject,
            target_kind="agent",
            target_id=agent_id,
            status="pending",
            limit=100,
        )
    await websocket.send_json(
        {
            "type": "connected",
            "connection_id": connection_id,
            "replica_id": runtime.replica_id,
        }
    )
    for notification in backlog:
        await websocket.send_json(
            {
                "type": "notification",
                "notification_id": notification.id,
                "event_type": notification.event_type,
                "payload": notification.payload,
                "replayed": True,
            }
        )
    try:
        while True:
            message = await websocket.receive_json()
            message_type = str(message.get("type") or "")
            if message_type == "heartbeat":
                with SessionLocal() as db:
                    runtime.realtime.heartbeat_route(db, connection_id=connection_id)
                await websocket.send_json({"type": "heartbeat_ack"})
            elif message_type == "ack":
                notification_id = str(message.get("notification_id") or "")
                if not notification_id:
                    continue
                with SessionLocal() as db:
                    try:
                        notification = runtime.realtime.acknowledge_notification(
                            db,
                            owner_subject=owner_subject,
                            target_kind="agent",
                            target_id=agent_id,
                            notification_id=notification_id,
                        )
                    except LookupError:
                        await websocket.send_json(
                            {
                                "type": "ack_error",
                                "notification_id": notification_id,
                                "error": "notification_not_found",
                            }
                        )
                    else:
                        await websocket.send_json(
                            {
                                "type": "acknowledged",
                                "notification": notification_payload(notification),
                            }
                        )
    except WebSocketDisconnect:
        pass
    finally:
        await runtime.realtime.hub.unregister(connection_id)
        with SessionLocal() as db:
            runtime.realtime.unregister_route(db, connection_id=connection_id)
