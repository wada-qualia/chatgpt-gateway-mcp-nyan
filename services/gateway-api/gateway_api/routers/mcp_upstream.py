from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_role
from ..database import get_db
from ..dto import McpCredentialBindingOut
from ..mcp_oauth_discovery import discover_oauth_metadata
from ..mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from ..mcp_upstream_credentials import (
    complete_oauth_authorization,
    create_credential_material,
    revoke_credential_material,
    rotate_credential_material,
    start_oauth_authorization,
)
from ..mcp_upstream_dto import (
    McpCredentialCommand,
    McpCredentialMaterialCreate,
    McpCredentialMaterialRotate,
    McpOAuthAuthorizationComplete,
    McpOAuthAuthorizationStart,
    McpOAuthAuthorizationStarted,
    McpOAuthDiscoveryOut,
    McpOAuthDiscoveryRequest,
    McpUpstreamCallInput,
    McpUpstreamCallOut,
)
from ..models import McpToolRevision, User
from ..policy import enforce

router = APIRouter(prefix="/api/mcp", tags=["mcp-upstream"])


def manager(request: Request) -> UpstreamMcpManager:
    return request.app.state.upstream_mcp_manager


def idempotency_key(
    value: str = Header(alias="Idempotency-Key", min_length=1, max_length=160),
) -> str:
    return value


def upstream_http_error(exc: UpstreamMcpError) -> HTTPException:
    return HTTPException(status_code=exc.http_status, detail=exc.as_detail())


@router.post(
    "/credential-bindings/material",
    response_model=McpCredentialBindingOut,
    status_code=201,
)
async def create_material_binding(
    payload: McpCredentialMaterialCreate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="create", owner_subject=user.subject)
    return create_credential_material(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        idempotency_key=request_key,
        payload=payload,
    )


@router.post(
    "/credential-bindings/{binding_id}/rotate",
    response_model=McpCredentialBindingOut,
)
async def rotate_material_binding(
    binding_id: str,
    payload: McpCredentialMaterialRotate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="update", owner_subject=user.subject)
    return rotate_credential_material(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        binding_id=binding_id,
        idempotency_key=request_key,
        payload=payload,
    )


@router.post(
    "/credential-bindings/{binding_id}/revoke",
    response_model=McpCredentialBindingOut,
)
async def revoke_material_binding(
    binding_id: str,
    payload: McpCredentialCommand,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="delete", owner_subject=user.subject)
    return revoke_credential_material(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        binding_id=binding_id,
        expected_version=payload.expected_version,
    )


@router.post(
    "/servers/{server_id}/oauth/discover",
    response_model=McpOAuthDiscoveryOut,
)
async def oauth_discover(
    server_id: str,
    payload: McpOAuthDiscoveryRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    upstream: UpstreamMcpManager = Depends(manager),
):
    enforce(user, action="update", owner_subject=user.subject)
    try:
        return await discover_oauth_metadata(
            db,
            manager=upstream,
            owner_subject=user.subject,
            actor_subject=user.subject,
            server_id=server_id,
            expected_version=payload.expected_version,
            requested_scopes=payload.requested_scopes,
            authorization_server=(
                str(payload.authorization_server)
                if payload.authorization_server is not None
                else None
            ),
        )
    except UpstreamMcpError as exc:
        raise upstream_http_error(exc) from exc


@router.post(
    "/servers/{server_id}/oauth/start",
    response_model=McpOAuthAuthorizationStarted,
)
async def oauth_start(
    server_id: str,
    payload: McpOAuthAuthorizationStart,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    upstream: UpstreamMcpManager = Depends(manager),
):
    enforce(user, action="update", owner_subject=user.subject)
    try:
        return await start_oauth_authorization(
            db,
            manager=upstream,
            owner_subject=user.subject,
            actor_subject=user.subject,
            server_id=server_id,
            idempotency_key=request_key,
            payload=payload,
        )
    except UpstreamMcpError as exc:
        raise upstream_http_error(exc) from exc


@router.post(
    "/oauth/complete",
    response_model=McpCredentialBindingOut,
)
async def oauth_complete(
    payload: McpOAuthAuthorizationComplete,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    upstream: UpstreamMcpManager = Depends(manager),
):
    enforce(user, action="update", owner_subject=user.subject)
    try:
        return await complete_oauth_authorization(
            db,
            manager=upstream,
            owner_subject=user.subject,
            actor_subject=user.subject,
            state=payload.state,
            code=payload.code.get_secret_value(),
        )
    except UpstreamMcpError as exc:
        raise upstream_http_error(exc) from exc


@router.post(
    "/servers/{server_id}/runtime-call",
    response_model=McpUpstreamCallOut,
)
async def runtime_call(
    server_id: str,
    payload: McpUpstreamCallInput,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    upstream: UpstreamMcpManager = Depends(manager),
):
    require_role(user, "gateway-admin")
    enforce(user, action="execute", owner_subject=user.subject)
    revision = db.get(McpToolRevision, payload.revision_id)
    if (
        revision is None
        or revision.owner_subject != user.subject
        or revision.server_id != server_id
    ):
        raise HTTPException(status_code=404, detail="MCP tool revision not found")
    try:
        result = await upstream.call_exact_revision(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            revision_id=payload.revision_id,
            arguments=payload.arguments,
            timeout_seconds=payload.timeout_seconds,
            idempotency_key=request_key,
        )
        return {
            "revision_id": payload.revision_id,
            "schema_hash": revision.schema_hash,
            "result": result.payload,
            "truncated": result.truncated,
            "serialized_bytes": result.serialized_bytes,
        }
    except UpstreamMcpError as exc:
        raise upstream_http_error(exc) from exc
