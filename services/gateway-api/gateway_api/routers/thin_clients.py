from __future__ import annotations

import secrets
import uuid
from datetime import timedelta
from html import escape
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from ..auth import create_jwt, decode_jwt, dev_user, get_current_user
from ..config import Settings, get_settings
from ..crypto import token_hash
from ..database import SessionLocal, get_db
from ..dto import DeviceCodeOut, ThinClientOut, ThinClientRegister, ThinClientToolCall, ThinClientToolResult
from ..events import emit_event
from ..models import CommandSession, DeviceCode, ThinClient, User, utcnow
from ..monitoring import monitoring_service
from ..policy import enforce
from ..thin_client_control import thin_client_manager

router = APIRouter(prefix="/api/thin-clients", tags=["thin-clients"])
activation_router = APIRouter(tags=["thin-client-activation"])
_UNBOUND_DEVICE_CODE_SUBJECT_PREFIX = "device-code:"


def _normalize_user_code(value: str) -> str:
    return value.strip().replace(" ", "").replace("-", "").upper()


def _unbound_device_code_subject(device_code: str) -> str:
    return f"{_UNBOUND_DEVICE_CODE_SUBJECT_PREFIX}{device_code}"


def _is_unbound_device_code(code: DeviceCode) -> bool:
    return code.subject.startswith(_UNBOUND_DEVICE_CODE_SUBJECT_PREFIX)


def _websocket_bearer_token(websocket: WebSocket, legacy_query_token: str | None = None) -> str | None:
    authorization = websocket.headers.get("authorization", "").strip()
    scheme, separator, credential = authorization.partition(" ")
    if separator and scheme.casefold() == "bearer" and credential.strip():
        return credential.strip()
    return legacy_query_token


def _activation_login_redirect(user_code: str) -> RedirectResponse:
    next_path = f"/thin-clients/activate?{urlencode({'user_code': user_code})}"
    return RedirectResponse(url=f"/auth/login?{urlencode({'next': next_path})}", status_code=303)


def _html_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      color: #172033;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f7f9;
    }}
    body {{
      align-items: center;
      display: flex;
      margin: 0;
      min-height: 100vh;
      padding: 24px;
    }}
    main {{
      background: #fff;
      border: 1px solid #d8dee7;
      border-radius: 8px;
      box-shadow: 0 12px 36px rgba(18, 26, 39, .08);
      display: grid;
      gap: 18px;
      margin: 0 auto;
      max-width: 520px;
      padding: 28px;
      width: 100%;
    }}
    h1 {{ font-size: 22px; margin: 0; }}
    p {{ color: #536070; line-height: 1.5; margin: 0; }}
    label {{ display: grid; gap: 8px; font-size: 13px; }}
    input {{
      border: 1px solid #cfd6df;
      border-radius: 6px;
      font: inherit;
      height: 44px;
      padding: 0 12px;
      text-transform: uppercase;
    }}
    button {{
      background: #0b5ed7;
      border: 1px solid #0b5ed7;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font: inherit;
      height: 44px;
    }}
    code {{
      background: #eef1f5;
      border-radius: 4px;
      color: #172033;
      padding: 2px 5px;
    }}
    .status {{
      background: #eef6ff;
      border: 1px solid #cfe0ff;
      border-radius: 6px;
      color: #174ea6;
      padding: 12px;
    }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>"""
    )


def _activation_form(*, user_code: str = "", message: str | None = None) -> HTMLResponse:
    safe_user_code = escape(user_code)
    status_block = f'<p class="status">{escape(message)}</p>' if message else ""
    return _html_page(
        "Activate thin client",
        f"""
    <h1>Activate Thin Client</h1>
    <p>Enter the user code printed by <code>gateway-cli login</code>. In local dev mode codes are approved automatically, but this page remains available for the same workflow.</p>
    {status_block}
    <form method="post" action="/thin-clients/activate">
      <label>
        User code
        <input name="user_code" value="{safe_user_code}" autocomplete="one-time-code" autofocus required>
      </label>
      <button type="submit">Activate client</button>
    </form>
    """,
    )


def _expires_at_is_past(device_code: DeviceCode) -> bool:
    expires_at = device_code.expires_at
    if expires_at.tzinfo is None:
        from datetime import timezone

        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < utcnow()


@activation_router.get("/thin-clients/activate")
async def activate_thin_client_page(
    request: Request,
    user_code: str = "",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    normalized = _normalize_user_code(user_code)
    try:
        await get_current_user(request, db=db, settings=settings)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            raise
        return _activation_login_redirect(normalized)
    return _activation_form(user_code=normalized)


@activation_router.post("/thin-clients/activate")
async def activate_thin_client(
    request: Request,
    user_code: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    normalized = _normalize_user_code(user_code)
    try:
        user = await get_current_user(request, db=db, settings=settings)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_401_UNAUTHORIZED:
            raise
        return _activation_login_redirect(normalized)
    code = db.query(DeviceCode).filter(DeviceCode.user_code == normalized).one_or_none()
    if code is None:
        return _activation_form(user_code=normalized, message="Unknown activation code.")
    if _expires_at_is_past(code):
        return _activation_form(user_code=normalized, message="Activation code expired. Issue a new device code from the Thin Clients page.")
    if _is_unbound_device_code(code):
        code.subject = user.subject
    elif code.subject != user.subject and "gateway-admin" not in set(user.roles or []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Activation code belongs to another user")
    if code.status != "approved":
        code.status = "approved"
    db.commit()
    return _html_page(
        "Thin client activated",
        f"""
    <h1>Thin Client Activated</h1>
    <p class="status">Code <code>{escape(normalized)}</code> is approved. Return to the terminal; <code>gateway-cli</code> will continue registration automatically.</p>
    <p>You can close this page.</p>
    """,
    )


@router.get("", response_model=list[ThinClientOut])
async def list_thin_clients(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ThinClient]:
    enforce(user, action="read")
    query = db.query(ThinClient).order_by(ThinClient.created_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(ThinClient.owner_subject == user.subject)
    return query.all()


@router.post("/device-code", response_model=DeviceCodeOut, status_code=201)
async def create_device_code(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DeviceCodeOut:
    device_code = secrets.token_urlsafe(40)
    user_code = secrets.token_hex(3).upper()
    user = dev_user(db, settings) if settings.gateway_dev_auth else None
    code = DeviceCode(
        device_code=device_code,
        user_code=user_code,
        subject=user.subject if user else _unbound_device_code_subject(device_code),
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
    if _is_unbound_device_code(device_code):
        raise HTTPException(status_code=428, detail="Authorization pending")
    user = db.query(User).filter(User.subject == device_code.subject).one_or_none()
    if user is None:
        raise HTTPException(status_code=400, detail="Device code owner no longer exists")
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
    existing_clients = (
        db.query(ThinClient)
        .filter(
            ThinClient.owner_subject == user.subject,
            ThinClient.hostname == payload.hostname,
            ThinClient.directory == payload.directory,
        )
        .order_by(ThinClient.created_at.desc())
        .all()
    )
    client = existing_clients[0] if existing_clients else None
    is_new = client is None
    if client is None:
        client = ThinClient(
            id=str(uuid.uuid4()),
            owner_subject=user.subject,
            hostname=payload.hostname,
            directory=payload.directory,
        )
        db.add(client)
    else:
        for duplicate in existing_clients[1:]:
            db.delete(duplicate)
    client.agent_token_hash = token_hash(token)
    client.status = "online"
    client.meta = {"labels": payload.labels}
    client.last_seen_at = utcnow()
    db.commit()
    db.refresh(client)
    emit_event(
        db,
        event_type="gateway.thin_client.enrolled.v1",
        actor_subject=user.subject,
        action="enrolled" if is_new else "reconnected",
        resource_type="thin_client",
        resource_id=client.id,
        payload={"client_id": client.id, "hostname": client.hostname, "directory": client.directory},
    )
    return client


@router.post("/{client_id}/tools", response_model=ThinClientToolResult)
async def call_thin_client_tool(
    client_id: str,
    payload: ThinClientToolCall,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ThinClientToolResult:
    client = db.get(ThinClient, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Thin client not found")
    enforce(user, action="update", owner_subject=client.owner_subject)
    timeout_seconds = min(payload.timeout_seconds or settings.max_command_timeout_seconds, settings.max_command_timeout_seconds)
    arguments = dict(payload.arguments or {})
    if payload.tool == "run_command":
        session = monitoring_service.create_session(
            db,
            owner_subject=user.subject,
            origin="thin_client",
            resource_id=client.id,
            command=str(arguments.get("command", "")),
            cwd=str(arguments.get("cwd", ".")),
            name=payload.session_name,
            settings=settings,
            meta={"client_id": client.id, "hostname": client.hostname, "directory": client.directory},
        )
        arguments["session_id"] = session.id
        response = await thin_client_manager.request(
            client_id,
            tool="run_monitored_command",
            arguments=arguments,
            timeout_seconds=10,
        )
        if not response.get("ok"):
            monitoring_service.finish_session(session.id, status_value="failed", exit_code=None, meta={"error": response.get("error")})
            return ThinClientToolResult(ok=False, error=str(response.get("error") or "Thin client tool failed"))
        run_result = await monitoring_service.wait_for_existing_session(
            db,
            session_id=session.id,
            settings=settings,
            background=payload.background,
        )
        return ThinClientToolResult(
            ok=run_result.exit_code in {0, None},
            result={
                "session_id": run_result.session_id,
                "status": run_result.status,
                "backgrounded": run_result.backgrounded,
                "exit_code": run_result.exit_code,
                "output": run_result.output,
                "recommendation": run_result.recommendation,
            },
            error=None if run_result.exit_code in {0, None} else "Command failed",
        )
    response = await thin_client_manager.request(
        client_id,
        tool=payload.tool,
        arguments=arguments,
        timeout_seconds=timeout_seconds,
    )
    return ThinClientToolResult(ok=bool(response.get("ok")), result=response.get("result"), error=response.get("error"))


@router.delete("/{client_id}")
async def delete_thin_client(
    client_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    client = db.get(ThinClient, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Thin client not found")
    enforce(user, action="delete", owner_subject=client.owner_subject)
    hostname = client.hostname
    directory = client.directory
    db.delete(client)
    db.commit()
    await thin_client_manager.disconnect(client_id)
    emit_event(
        db,
        event_type="gateway.thin_client.changed.v1",
        actor_subject=user.subject,
        action="deleted",
        resource_type="thin_client",
        resource_id=client_id,
        payload={"client_id": client_id, "hostname": hostname, "directory": directory},
    )
    return {"ok": True}


@router.websocket("/ws/{client_id}")
async def websocket_control(websocket: WebSocket, client_id: str, token: str | None = None) -> None:
    await websocket.accept()
    try:
        claims = decode_jwt(_websocket_bearer_token(websocket, token) or "")
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
    connection = await thin_client_manager.register(client_id, websocket)
    try:
        while True:
            message = await websocket.receive_json()
            if message.get("type") == "heartbeat":
                with SessionLocal() as db:
                    current = db.get(ThinClient, client_id)
                    if current:
                        version = message.get("version")
                        if version:
                            meta = dict(current.meta or {})
                            labels = dict(meta.get("labels") or {})
                            labels["client"] = labels.get("client") or "gateway-cli"
                            labels["version"] = str(version)
                            meta["labels"] = labels
                            current.meta = meta
                        current.last_seen_at = utcnow()
                        current.status = "online"
                        db.commit()
                await websocket.send_json({"type": "heartbeat_ack"})
            elif message.get("type") == "tool_result":
                await thin_client_manager.complete(str(message.get("request_id", "")), message)
            elif message.get("type") == "session_output":
                monitoring_service.append_output(
                    str(message.get("session_id", "")),
                    stream=str(message.get("stream", "stdout")),
                    text=str(message.get("text", "")),
                )
            elif message.get("type") == "session_finished":
                monitoring_service.finish_session(
                    str(message.get("session_id", "")),
                    status_value=str(message.get("status") or "completed"),
                    exit_code=int(message.get("exit_code", 0)),
                )
            elif message.get("type") == "session_failed":
                session_id = str(message.get("session_id", ""))
                monitoring_service.append_output(session_id, stream="stderr", text=str(message.get("error", "")) + "\n")
                monitoring_service.finish_session(session_id, status_value="failed", exit_code=None, meta={"error": str(message.get("error", ""))})
            elif message.get("type") == "session_snapshot":
                with SessionLocal() as db:
                    for item in list(message.get("sessions") or []):
                        current_session = db.get(CommandSession, str(item.get("session_id", "")))
                        if current_session and current_session.status in {"running", "disconnecting", "lost"}:
                            current_session.pid = str(item.get("pid") or current_session.pid or "")
                            current_session.status = "running"
                            current_session.completed_at = None
                            current_session.updated_at = utcnow()
                    db.commit()
            else:
                await websocket.send_json({"type": "ack", "received": message.get("type")})
    except WebSocketDisconnect:
        pass
    finally:
        became_offline = await thin_client_manager.unregister(client_id, connection)
        if became_offline:
            with SessionLocal() as db:
                current = db.get(ThinClient, client_id)
                if current:
                    current.status = "offline"
                running_sessions = (
                    db.query(CommandSession)
                    .filter(CommandSession.origin == "thin_client")
                    .filter(CommandSession.resource_id == client_id)
                    .filter(CommandSession.status == "running")
                    .all()
                )
                for session in running_sessions:
                    session.status = "disconnecting"
                    session.updated_at = utcnow()
                db.commit()
