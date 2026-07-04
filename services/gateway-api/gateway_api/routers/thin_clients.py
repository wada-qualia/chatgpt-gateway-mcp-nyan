from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from ..auth import create_jwt, decode_jwt, get_current_user
from ..config import Settings, get_settings
from ..crypto import token_hash
from ..database import SessionLocal, get_db
from ..dto import DeviceCodeOut, ThinClientOut, ThinClientRegister
from ..events import emit_event
from ..models import DeviceCode, ThinClient, User, utcnow
from ..policy import enforce

router = APIRouter(prefix="/api/thin-clients", tags=["thin-clients"])


@router.get("", response_model=list[ThinClientOut])
async def list_thin_clients(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ThinClient]:
    enforce(user, action="read")
    query = db.query(ThinClient).order_by(ThinClient.created_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(ThinClient.owner_subject == user.subject)
    return query.all()


@router.post("/device-code", response_model=DeviceCodeOut, status_code=201)
async def create_device_code(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DeviceCodeOut:
    device_code = secrets.token_urlsafe(40)
    user_code = secrets.token_hex(3).upper()
    code = DeviceCode(
        device_code=device_code,
        user_code=user_code,
        subject=user.subject,
        scope="thin-client:register",
        status="approved" if settings.gateway_dev_auth else "pending",
        expires_at=utcnow() + timedelta(seconds=settings.gateway_device_code_ttl_seconds),
    )
    db.add(code)
    db.commit()
    return DeviceCodeOut(
        device_code=device_code,
        user_code=user_code,
        verification_uri=f"{settings.public_base_url.rstrip()}/thin-clients/activate",
        expires_in=settings.gateway_device_code_ttl_seconds,
        interval=3,
    )


@router.post("/token")
async def token(payload: dict, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> dict:
    device_code = db.get(DeviceCode, str(payload.get("device_code", "")))
    if device_code is None:
        raise HTTPException(status_code=400, detail="Invalid device_code")
    expires_at = device_code.expires_at
    if expires_at.tzinfo is None:
        from datetime import timezone

        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < utcnow():
        raise HTTPException(status_code=400, detail="Device code expired")
    if device_code.status != "approved":
        raise HTTPException(status_code=428, detail="Authorization pending")
    user = db.query(User).filter(User.subject == device_code.subject).one()
    agent_token = create_jwt(
        subject=user.subject,
        username=user.username,
        roles=user.roles,
        scopes=["thin-client:register", "thin-client:control"],
        token_type="agent",
        ttl_seconds=settings.gateway_access_token_ttl_seconds,
    )
    return {"access_token": agent_token, "token_type": "Bearer", "expires_in": settings.gateway_access_token_ttl_seconds}


def _agent_user_from_request(request: Request, db: Session) -> User:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    claims = decode_jwt(auth.split(" ", 1)[1].strip())
    user = db.query(User).filter(User.subject == claims["sub"]).one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown token subject")
    return user


@router.post("/register", response_model=ThinClientOut, status_code=201)
async def register_thin_client(request: Request, payload: ThinClientRegister, db: Session = Depends(get_db)) -> ThinClient:
    user = _agent_user_from_request(request, db)
    token = request.headers["authorization"].split(" ", 1)[1].strip()
    client = ThinClient(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        hostname=payload.hostname,
        directory=payload.directory,
        agent_token_hash=token_hash(token),
        status="online",
        meta={"labels": payload.labels},
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    emit_event(
        db,
        event_type="gateway.thin_client.enrolled.v1",
        actor_subject=user.subject,
        action="enrolled",
        resource_type="thin_client",
        resource_id=client.id,
        payload={"client_id": client.id, "hostname": client.hostname, "directory": client.directory},
    )
    return client


@router.websocket("/ws/{client_id}")
async def websocket_control(websocket: WebSocket, client_id: str, token: str) -> None:
    await websocket.accept()
    try:
        claims = decode_jwt(token)
    except Exception:
        await websocket.close(code=4401)
        return
    with SessionLocal() as db:
        client = db.get(ThinClient, client_id)
        if client is None or client.owner_subject != claims["sub"]:
            await websocket.close(code=4404)
            return
        client.status = "online"
        client.last_seen_at = utcnow()
        db.commit()
    try:
        while True:
            message = await websocket.receive_json()
            if message.get("type") == "heartbeat":
                with SessionLocal() as db:
                    current = db.get(ThinClient, client_id)
                    if current:
                        current.last_seen_at = utcnow()
                        current.status = "online"
                        db.commit()
                await websocket.send_json({"type": "heartbeat_ack"})
            else:
                await websocket.send_json({"type": "ack", "received": message.get("type")})
    except WebSocketDisconnect:
        with SessionLocal() as db:
            current = db.get(ThinClient, client_id)
            if current:
                current.status = "offline"
                db.commit()
