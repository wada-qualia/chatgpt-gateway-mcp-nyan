from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..adapters.ssh import (
    check_ssh_tcp_connection,
    load_device_credentials,
    parse_ssh_target,
    serialize_ssh_secret,
    verify_ssh_connection,
    verify_ssh_key_connection,
)
from ..auth import get_current_user
from ..crypto import encrypt_text
from ..database import get_db
from ..dto import DeviceCreate, DeviceOut, DeviceUpdate
from ..events import emit_event
from ..models import Device, SecretBlob, User, utcnow
from ..policy import enforce

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _query_visible_device(device_id: str, user: User, db: Session) -> Device:
    query = db.query(Device).filter(Device.id == device_id)
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(Device.owner_subject == user.subject)
    device = query.first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


def _store_device_secret(
    *,
    db: Session,
    owner_subject: str,
    auth_type: str,
    secret_value: str,
    passphrase: str | None = None,
) -> str:
    secret_id = str(uuid.uuid4())
    db.add(
        SecretBlob(
            id=secret_id,
            owner_subject=owner_subject,
            kind=f"ssh:{auth_type}",
            ciphertext=encrypt_text(serialize_ssh_secret(secret_value, passphrase)),
        )
    )
    db.flush()
    return secret_id


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
        secret_id = _store_device_secret(
            db=db,
            owner_subject=user.subject,
            auth_type=payload.auth_type,
            secret_value=secret_value,
            passphrase=payload.passphrase,
        )
    status_value = "registered"
    if payload.verify_connection and payload.auth_type == "private_key":
        status_value = verify_ssh_key_connection(target)
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
        status=status_value,
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


@router.patch("/{device_id}", response_model=DeviceOut)
async def update_device(
    device_id: str,
    payload: DeviceUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Device:
    device = _query_visible_device(device_id, user, db)
    enforce(user, action="update", owner_subject=device.owner_subject)
    old_auth_type = device.auth_type
    old_secret_id = device.credential_secret_id
    new_auth_type = payload.auth_type or device.auth_type
    new_secret_value = payload.private_key if new_auth_type == "private_key" else payload.password

    if payload.name is not None:
        trimmed_name = payload.name.strip()
        if not trimmed_name:
            raise HTTPException(status_code=422, detail="Device name cannot be empty")
        device.name = trimmed_name

    if payload.target is not None:
        target = parse_ssh_target(payload.target)
        device.username = target.username
        device.host = target.host
        device.port = target.port

    if payload.auth_type is not None:
        device.auth_type = payload.auth_type

    if new_auth_type == "agent":
        device.credential_secret_id = None
    elif new_secret_value:
        device.credential_secret_id = _store_device_secret(
            db=db,
            owner_subject=device.owner_subject,
            auth_type=new_auth_type,
            secret_value=new_secret_value,
            passphrase=payload.passphrase,
        )
    elif payload.auth_type is not None and payload.auth_type != old_auth_type:
        raise HTTPException(status_code=422, detail="Credential is required when changing auth_type")

    device.status = "registered"
    device.updated_at = utcnow()
    db.commit()
    db.refresh(device)
    if old_secret_id and old_secret_id != device.credential_secret_id:
        db.query(SecretBlob).filter(SecretBlob.id == old_secret_id).delete()
        db.commit()
    emit_event(
        db,
        event_type="gateway.device.updated.v1",
        actor_subject=user.subject,
        action="updated",
        resource_type="device",
        resource_id=device.id,
        payload={"device_id": device.id, "host": device.host, "port": device.port},
    )
    return device


def _device_test_status_from_exception(exc: HTTPException) -> str:
    if exc.status_code == status.HTTP_409_CONFLICT:
        return "host_key_untrusted"
    if exc.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN}:
        return "auth_failed"
    if exc.status_code in {status.HTTP_502_BAD_GATEWAY, status.HTTP_504_GATEWAY_TIMEOUT}:
        return "unreachable"
    return "auth_failed"


@router.post("/{device_id}/test", response_model=DeviceOut)
async def test_device_connection(device_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Device:
    device = _query_visible_device(device_id, user, db)
    enforce(user, action="update", owner_subject=device.owner_subject)
    target = parse_ssh_target(f"{device.username}@{device.host}:{device.port}")
    tcp_status = check_ssh_tcp_connection(target)
    if tcp_status != "reachable":
        device.status = "unreachable"
    else:
        try:
            credentials = load_device_credentials(device, db)
            device.status = verify_ssh_connection(device, credentials)
        except HTTPException as exc:
            device.status = _device_test_status_from_exception(exc)
    device.updated_at = utcnow()
    db.commit()
    db.refresh(device)
    emit_event(
        db,
        event_type="gateway.device.connection_tested.v1",
        actor_subject=user.subject,
        action="tested",
        resource_type="device",
        resource_id=device.id,
        payload={"device_id": device.id, "status": device.status, "host": device.host, "port": device.port},
        status="success" if device.status == "verified" else "warning",
    )
    return device


@router.delete("/{device_id}")
async def delete_device(device_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    device = _query_visible_device(device_id, user, db)
    enforce(user, action="delete", owner_subject=device.owner_subject)
    secret_id = device.credential_secret_id
    event_payload = {"device_id": device.id, "host": device.host, "port": device.port}
    db.delete(device)
    if secret_id:
        db.query(SecretBlob).filter(SecretBlob.id == secret_id).delete()
    db.commit()
    emit_event(
        db,
        event_type="gateway.device.deleted.v1",
        actor_subject=user.subject,
        action="deleted",
        resource_type="device",
        resource_id=device_id,
        payload=event_payload,
    )
    return {"ok": True}
