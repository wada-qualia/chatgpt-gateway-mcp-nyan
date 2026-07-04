from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..adapters.ssh import parse_ssh_target, verify_ssh_key_connection
from ..auth import get_current_user
from ..crypto import encrypt_text
from ..database import get_db
from ..dto import DeviceCreate, DeviceOut
from ..events import emit_event
from ..models import Device, SecretBlob, User, utcnow
from ..policy import enforce

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
async def list_devices(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Device]:
    enforce(user, action="read")
    if "gateway-admin" in set(user.roles or []):
        return db.query(Device).order_by(Device.created_at.desc()).all()
    return db.query(Device).filter(Device.owner_subject == user.subject).order_by(Device.created_at.desc()).all()


@router.post("", response_model=DeviceOut, status_code=201)
async def create_device(payload: DeviceCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Device:
    enforce(user, action="create", owner_subject=user.subject)
    target = parse_ssh_target(payload.target)
    secret_value = payload.private_key if payload.auth_type == "private_key" else payload.password
    secret_id: str | None = None
    if payload.auth_type != "agent":
        if not secret_value:
            raise HTTPException(status_code=422, detail="Credential is required for selected auth_type")
        secret_id = str(uuid.uuid4())
        secret_blob = {"secret": secret_value, "passphrase": payload.passphrase}
        db.add(SecretBlob(id=secret_id, owner_subject=user.subject, kind=f"ssh:{payload.auth_type}", ciphertext=encrypt_text(str(secret_blob))))
    status = "registered"
    if payload.verify_connection and payload.auth_type == "private_key":
        status = verify_ssh_key_connection(target)
    device = Device(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        name=payload.name,
        kind="ssh",
        host=target.host,
        port=target.port,
        username=target.username,
        auth_type=payload.auth_type,
        credential_secret_id=secret_id,
        status=status,
        updated_at=utcnow(),
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    emit_event(
        db,
        event_type="gateway.device.registered.v1",
        actor_subject=user.subject,
        action="registered",
        resource_type="device",
        resource_id=device.id,
        payload={"device_id": device.id, "kind": device.kind, "host": device.host, "port": device.port},
    )
    return device
