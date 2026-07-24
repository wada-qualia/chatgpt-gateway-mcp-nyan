from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .crypto import decrypt_text, encrypt_text
from .events import emit_event
from .mcp_federation import get_server, mcp_federation_service
from .mcp_upstream import (
    UpstreamMcpError,
    UpstreamMcpManager,
    build_oauth_authorization_url,
    material_to_secret_payload,
)
from .models import (
    McpCredentialBinding,
    McpOAuthAuthorizationState,
    SecretBlob,
    utcnow,
)

_SECRET_NAMESPACE = uuid.UUID("ddfa397a-5b9f-4a19-b044-8d1862b59383")


def create_credential_material(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    idempotency_key: str,
    payload: Any,
) -> McpCredentialBinding:
    material = material_to_secret_payload(payload)
    canonical = _canonical(material)
    secret_id = str(
        uuid.uuid5(_SECRET_NAMESPACE, f"{owner_subject}:create:{idempotency_key}")
    )
    secret = db.get(SecretBlob, secret_id)
    if secret is None:
        secret = SecretBlob(
            id=secret_id,
            owner_subject=owner_subject,
            kind=f"mcp_{payload.binding_type}",
            ciphertext=encrypt_text(canonical),
        )
        db.add(secret)
        db.flush()
    elif secret.owner_subject != owner_subject or decrypt_text(secret.ciphertext) != canonical:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency key was already used with different credential material",
        )
    return mcp_federation_service.create_credential_binding(
        db,
        owner_subject=owner_subject,
        actor_subject=actor_subject,
        idempotency_key=idempotency_key,
        data={
            "binding_type": payload.binding_type,
            "provider": payload.provider,
            "secret_blob_id": secret.id,
            "audience": str(payload.audience) if payload.audience else None,
            "scopes": payload.scopes,
            "meta": {"mode": payload.mode, "backend_reference": True},
        },
    )


def rotate_credential_material(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    binding_id: str,
    idempotency_key: str,
    payload: Any,
) -> McpCredentialBinding:
    binding = _binding(db, owner_subject, binding_id)
    if binding.version != payload.expected_version:
        if binding.meta.get("last_rotation_key") == idempotency_key:
            return binding
        raise HTTPException(status_code=409, detail="Optimistic version conflict")
    if binding.binding_type != payload.binding_type:
        raise HTTPException(status_code=422, detail="Credential binding type cannot change")
    material = material_to_secret_payload(payload)
    canonical = _canonical(material)
    secret_id = str(
        uuid.uuid5(
            _SECRET_NAMESPACE,
            f"{owner_subject}:rotate:{binding_id}:{idempotency_key}",
        )
    )
    secret = db.get(SecretBlob, secret_id)
    if secret is None:
        secret = SecretBlob(
            id=secret_id,
            owner_subject=owner_subject,
            kind=f"mcp_{binding.binding_type}",
            ciphertext=encrypt_text(canonical),
        )
        db.add(secret)
    elif secret.owner_subject != owner_subject or decrypt_text(secret.ciphertext) != canonical:
        raise HTTPException(status_code=409, detail="Idempotency key payload conflict")
    binding.secret_blob_id = secret.id
    binding.provider = payload.provider
    binding.audience = str(payload.audience) if payload.audience else None
    binding.scopes = payload.scopes
    binding.status = "active"
    binding.version += 1
    binding.rotated_at = utcnow()
    binding.updated_at = utcnow()
    binding.meta = {
        **(binding.meta or {}),
        "mode": payload.mode,
        "backend_reference": True,
        "last_rotation_key": idempotency_key,
    }
    emit_event(
        db,
        event_type="gateway.mcp.credential_binding.rotated.v1",
        actor_subject=actor_subject,
        action="rotated",
        resource_type="mcp_credential_binding",
        resource_id=binding.id,
        payload={"binding_id": binding.id, "version": binding.version},
        commit=False,
    )
    db.commit()
    db.refresh(binding)
    return binding


def revoke_credential_material(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    binding_id: str,
    expected_version: int,
) -> McpCredentialBinding:
    binding = _binding(db, owner_subject, binding_id)
    if binding.version != expected_version:
        raise HTTPException(status_code=409, detail="Optimistic version conflict")
    binding.status = "revoked"
    binding.version += 1
    binding.revoked_at = utcnow()
    binding.updated_at = utcnow()
    emit_event(
        db,
        event_type="gateway.mcp.credential_binding.revoked.v1",
        actor_subject=actor_subject,
        action="revoked",
        resource_type="mcp_credential_binding",
        resource_id=binding.id,
        payload={"binding_id": binding.id, "version": binding.version},
        commit=False,
    )
    db.commit()
    db.refresh(binding)
    return binding


async def start_oauth_authorization(
    db: Session,
    *,
    manager: UpstreamMcpManager,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    idempotency_key: str,
    payload: Any,
) -> dict[str, Any]:
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    request_document = {
        "authorization_endpoint": str(payload.authorization_endpoint),
        "token_endpoint": str(payload.token_endpoint),
        "client_id": payload.client_id,
        "redirect_uri": str(payload.redirect_uri),
        "scopes": payload.scopes,
        "audience": str(payload.audience),
        "extra_authorization_parameters": payload.extra_authorization_parameters,
    }
    request_sha256 = hashlib.sha256(_canonical(request_document).encode()).hexdigest()
    existing = (
        db.query(McpOAuthAuthorizationState)
        .filter(
            McpOAuthAuthorizationState.owner_subject == owner_subject,
            McpOAuthAuthorizationState.server_id == server_id,
            McpOAuthAuthorizationState.idempotency_key == idempotency_key,
        )
        .first()
    )
    if existing is not None:
        if existing.status == "expired" or _as_utc(existing.expires_at) < utcnow():
            existing.status = "expired"
            db.commit()
            raise HTTPException(status_code=409, detail="OAuth authorization request expired")
        pending = db.get(SecretBlob, existing.secret_blob_id)
        if pending is None or pending.owner_subject != owner_subject:
            raise HTTPException(status_code=409, detail="OAuth authorization replay material is missing")
        secret_data = json.loads(decrypt_text(pending.ciphertext))
        if secret_data.get("request_sha256") != request_sha256:
            raise HTTPException(status_code=409, detail="Idempotency key payload conflict")
        return _oauth_started_response(existing, secret_data)

    if server.version != payload.expected_version:
        raise HTTPException(status_code=409, detail="Optimistic version conflict")
    await manager.validate_endpoint(
        str(payload.authorization_endpoint), purpose="oauth_authorization"
    )
    await manager.validate_endpoint(str(payload.token_endpoint), purpose="oauth_token")
    manager.validate_resource_audience(server.endpoint_url or "", str(payload.audience))
    binding = None
    if server.credential_binding_id:
        binding = _binding(db, owner_subject, server.credential_binding_id)
        if binding.binding_type != "oauth":
            raise HTTPException(status_code=422, detail="Server binding is not OAuth")
    if binding is None:
        seed_secret = SecretBlob(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            kind="mcp_oauth_pending",
            ciphertext=encrypt_text("{}"),
        )
        db.add(seed_secret)
        db.flush()
        binding = McpCredentialBinding(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            binding_type="oauth",
            provider=None,
            secret_blob_id=seed_secret.id,
            audience=str(payload.audience),
            scopes=payload.scopes,
            status="authorizing",
            version=1,
            meta={"mode": "oauth", "backend_reference": True},
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(binding)
        db.flush()
        server.credential_binding_id = binding.id
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    expires_at = utcnow() + timedelta(minutes=10)
    secret_data = {
        "state": state,
        "code_verifier": verifier,
        "client_id": payload.client_id,
        "client_secret": payload.client_secret.get_secret_value()
        if payload.client_secret
        else None,
        "extra_authorization_parameters": payload.extra_authorization_parameters,
        "request_sha256": request_sha256,
    }
    pending_secret = SecretBlob(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        kind="mcp_oauth_authorization",
        ciphertext=encrypt_text(_canonical(secret_data)),
    )
    db.add(pending_secret)
    flow = McpOAuthAuthorizationState(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        server_id=server.id,
        binding_id=binding.id,
        state_sha256=hashlib.sha256(state.encode()).hexdigest(),
        idempotency_key=idempotency_key,
        secret_blob_id=pending_secret.id,
        redirect_uri=str(payload.redirect_uri),
        authorization_endpoint=str(payload.authorization_endpoint),
        token_endpoint=str(payload.token_endpoint),
        audience=str(payload.audience),
        scopes=payload.scopes,
        status="pending",
        expires_at=expires_at,
        created_at=utcnow(),
    )
    db.add(flow)
    binding.audience = str(payload.audience)
    binding.scopes = payload.scopes
    binding.status = "authorizing"
    binding.updated_at = utcnow()
    server.status = "authorizing"
    server.version += 1
    server.updated_at = utcnow()
    emit_event(
        db,
        event_type="gateway.mcp.oauth.authorization_started.v1",
        actor_subject=actor_subject,
        action="authorizing",
        resource_type="mcp_server",
        resource_id=server.id,
        payload={"server_id": server.id, "binding_id": binding.id},
        commit=False,
    )
    db.commit()
    return _oauth_started_response(flow, secret_data)


async def complete_oauth_authorization(
    db: Session,
    *,
    manager: UpstreamMcpManager,
    owner_subject: str,
    actor_subject: str,
    state: str,
    code: str,
) -> McpCredentialBinding:
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    flow = (
        db.query(McpOAuthAuthorizationState)
        .filter(
            McpOAuthAuthorizationState.owner_subject == owner_subject,
            McpOAuthAuthorizationState.state_sha256 == state_hash,
        )
        .first()
    )
    if flow is None:
        raise HTTPException(status_code=400, detail="OAuth state is invalid")
    if flow.status == "completed":
        return _binding(db, owner_subject, flow.binding_id)
    if flow.status != "pending":
        raise HTTPException(status_code=400, detail="OAuth state is not active")
    if _as_utc(flow.expires_at) < utcnow():
        flow.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="OAuth state expired")
    server = get_server(db, owner_subject=owner_subject, server_id=flow.server_id)
    manager.validate_resource_audience(server.endpoint_url or "", flow.audience)
    await manager.validate_endpoint(flow.token_endpoint, purpose="oauth_token")
    pending = db.get(SecretBlob, flow.secret_blob_id)
    if pending is None or pending.owner_subject != owner_subject:
        raise HTTPException(status_code=400, detail="OAuth authorization secret is missing")
    secret_data = json.loads(decrypt_text(pending.ciphertext))
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": flow.redirect_uri,
        "client_id": secret_data["client_id"],
        "code_verifier": secret_data["code_verifier"],
        "resource": flow.audience,
    }
    auth = None
    client_secret = secret_data.get("client_secret")
    if client_secret:
        auth = httpx.BasicAuth(secret_data["client_id"], client_secret)
    try:
        async with httpx.AsyncClient(timeout=manager.connect_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(flow.token_endpoint, data=data, auth=auth)
        response.raise_for_status()
        tokens = response.json()
    except Exception as exc:
        raise UpstreamMcpError(
            "MCP_AUTH_REQUIRED", "OAuth authorization-code exchange failed", http_status=401
        ) from exc
    access_token = tokens.get("access_token") if isinstance(tokens, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise UpstreamMcpError(
            "MCP_AUTH_REQUIRED", "OAuth token response omitted access_token", http_status=401
        )
    material = {
        "mode": "oauth",
        "access_token": access_token,
        "refresh_token": tokens.get("refresh_token"),
        "token_endpoint": flow.token_endpoint,
        "client_id": secret_data["client_id"],
        "client_secret": client_secret,
    }
    if isinstance(tokens.get("expires_in"), (int, float)):
        material["expires_at"] = (
            utcnow() + timedelta(seconds=float(tokens["expires_in"]))
        ).isoformat()
    token_secret = SecretBlob(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        kind="mcp_oauth",
        ciphertext=encrypt_text(_canonical(material)),
    )
    db.add(token_secret)
    binding = _binding(db, owner_subject, flow.binding_id)
    binding.secret_blob_id = token_secret.id
    binding.status = "active"
    binding.version += 1
    binding.rotated_at = utcnow()
    binding.updated_at = utcnow()
    flow.status = "completed"
    flow.used_at = utcnow()
    server.status = "discovering"
    server.version += 1
    server.updated_at = utcnow()
    emit_event(
        db,
        event_type="gateway.mcp.oauth.authorization_completed.v1",
        actor_subject=actor_subject,
        action="authorized",
        resource_type="mcp_server",
        resource_id=server.id,
        payload={"server_id": server.id, "binding_id": binding.id},
        commit=False,
    )
    db.commit()
    db.refresh(binding)
    return binding


def _binding(db: Session, owner_subject: str, binding_id: str) -> McpCredentialBinding:
    binding = (
        db.query(McpCredentialBinding)
        .filter(
            McpCredentialBinding.id == binding_id,
            McpCredentialBinding.owner_subject == owner_subject,
        )
        .first()
    )
    if binding is None:
        raise HTTPException(status_code=404, detail="MCP credential binding not found")
    return binding


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)




def _oauth_started_response(
    flow: McpOAuthAuthorizationState, secret_data: dict[str, Any]
) -> dict[str, Any]:
    state = str(secret_data["state"])
    verifier = str(secret_data["code_verifier"])
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return {
        "server_id": flow.server_id,
        "binding_id": flow.binding_id,
        "authorization_url": build_oauth_authorization_url(
            authorization_endpoint=flow.authorization_endpoint,
            client_id=str(secret_data["client_id"]),
            redirect_uri=flow.redirect_uri,
            scopes=flow.scopes,
            state=state,
            code_challenge=challenge,
            audience=flow.audience,
            extra=dict(secret_data.get("extra_authorization_parameters") or {}),
        ),
        "state": state,
        "expires_at": _as_utc(flow.expires_at),
    }

def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
