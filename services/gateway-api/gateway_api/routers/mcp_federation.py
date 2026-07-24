from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_role
from ..database import get_db
from ..dto import (
    McpCredentialBindingCreate,
    McpCredentialBindingOut,
    McpFederationPolicyOut,
    McpFederationPolicyUpdate,
    McpInvocationOut,
    McpRuntimeConnectionOut,
    McpServerCommand,
    McpServerCreate,
    McpServerHealthOut,
    McpServerOut,
    McpServerUpdate,
    McpToolExposureOut,
    McpToolExposureUpdate,
    McpToolOut,
    McpToolRevisionClassification,
    McpToolRevisionOut,
)
from ..mcp_federation import mcp_federation_service
from ..models import User
from ..policy import enforce

router = APIRouter(prefix="/api/mcp", tags=["mcp-federation"])


def idempotency_key(
    value: str = Header(alias="Idempotency-Key", min_length=1, max_length=160),
) -> str:
    return value


def if_match(value: int = Header(alias="If-Match", ge=0)) -> int:
    return value


@router.post(
    "/credential-bindings", response_model=McpCredentialBindingOut, status_code=201
)
async def create_credential_binding(
    payload: McpCredentialBindingCreate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="create", owner_subject=user.subject)
    return mcp_federation_service.create_credential_binding(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        idempotency_key=request_key,
        data=payload.model_dump(),
    )


@router.get("/credential-bindings", response_model=list[McpCredentialBindingOut])
async def list_credential_bindings(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    enforce(user, action="read")
    return mcp_federation_service.list_credential_bindings(
        db, owner_subject=user.subject
    )


@router.post("/servers", response_model=McpServerOut, status_code=201)
async def create_server(
    payload: McpServerCreate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="create", owner_subject=user.subject)
    return mcp_federation_service.create_server(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        idempotency_key=request_key,
        data=payload.model_dump(),
    )


@router.get("/servers", response_model=list[McpServerOut])
async def list_servers(
    server_status: str | None = Query(default=None, alias="status"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    return mcp_federation_service.list_servers(
        db, owner_subject=user.subject, server_status=server_status
    )


@router.get("/servers/{server_id}", response_model=McpServerOut)
async def get_server(
    server_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    return mcp_federation_service.get_server(
        db, owner_subject=user.subject, server_id=server_id
    )


@router.patch("/servers/{server_id}", response_model=McpServerOut)
async def update_server(
    server_id: str,
    payload: McpServerUpdate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="update", owner_subject=user.subject)
    data = payload.model_dump(exclude_unset=True)
    expected_version = int(data.pop("expected_version"))
    return mcp_federation_service.update_server(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server_id,
        idempotency_key=request_key,
        expected_version=expected_version,
        data=data,
    )


@router.delete("/servers/{server_id}", response_model=McpServerOut)
async def disable_server(
    server_id: str,
    expected_version: int = Depends(if_match),
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="delete", owner_subject=user.subject)
    return mcp_federation_service.disable_server(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server_id,
        idempotency_key=request_key,
        expected_version=expected_version,
    )


def transition_server(
    *,
    transition: str,
    server_id: str,
    payload: McpServerCommand,
    request_key: str,
    user: User,
    db: Session,
):
    enforce(user, action="update", owner_subject=user.subject)
    return mcp_federation_service.request_server_transition(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server_id,
        idempotency_key=request_key,
        expected_version=payload.expected_version,
        transition=transition,
    )


@router.post("/servers/{server_id}/authorize", response_model=McpServerOut)
async def authorize_server(
    server_id: str,
    payload: McpServerCommand,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return transition_server(
        transition="authorize",
        server_id=server_id,
        payload=payload,
        request_key=request_key,
        user=user,
        db=db,
    )


@router.post("/servers/{server_id}/refresh", response_model=McpServerOut)
async def refresh_server(
    server_id: str,
    payload: McpServerCommand,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return transition_server(
        transition="refresh",
        server_id=server_id,
        payload=payload,
        request_key=request_key,
        user=user,
        db=db,
    )


@router.post("/servers/{server_id}/test", response_model=McpServerHealthOut)
async def test_server_control_plane(
    server_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    return mcp_federation_service.server_health(
        db, owner_subject=user.subject, server_id=server_id
    )


@router.get("/servers/{server_id}/policy", response_model=McpFederationPolicyOut | None)
async def get_server_policy(
    server_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    mcp_federation_service.get_server(
        db, owner_subject=user.subject, server_id=server_id
    )
    return mcp_federation_service.get_policy(
        db, owner_subject=user.subject, server_id=server_id
    )


@router.put("/servers/{server_id}/policy", response_model=McpFederationPolicyOut)
async def update_server_policy(
    server_id: str,
    payload: McpFederationPolicyUpdate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_role(user, "gateway-admin")
    data = payload.model_dump()
    expected_version = int(data.pop("expected_version"))
    return mcp_federation_service.upsert_policy(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=server_id,
        idempotency_key=request_key,
        expected_version=expected_version,
        data=data,
    )


@router.get("/servers/{server_id}/tools", response_model=list[McpToolOut])
async def list_server_tools(
    server_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    return mcp_federation_service.list_tools(
        db, owner_subject=user.subject, server_id=server_id
    )


@router.get("/tools/{tool_id}/revisions", response_model=list[McpToolRevisionOut])
async def list_tool_revisions(
    tool_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce(user, action="read")
    return mcp_federation_service.list_revisions(
        db, owner_subject=user.subject, tool_id=tool_id
    )


@router.put(
    "/revisions/{revision_id}/classification", response_model=McpToolRevisionOut
)
async def classify_tool_revision(
    revision_id: str,
    payload: McpToolRevisionClassification,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_role(user, "gateway-admin")
    return mcp_federation_service.classify_revision(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        revision_id=revision_id,
        idempotency_key=request_key,
        expected_version=payload.expected_version,
        action_class=payload.action_class,
        read_only_status=payload.read_only_status,
    )


@router.patch("/tools/{tool_id}/exposure", response_model=McpToolExposureOut)
async def update_tool_exposure(
    tool_id: str,
    payload: McpToolExposureUpdate,
    request_key: str = Depends(idempotency_key),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_role(user, "gateway-admin")
    data = payload.model_dump()
    expected_version = int(data.pop("expected_version"))
    return mcp_federation_service.upsert_exposure(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        tool_id=tool_id,
        idempotency_key=request_key,
        expected_version=expected_version,
        data=data,
    )


@router.get("/invocations", response_model=list[McpInvocationOut])
async def list_invocations(
    server_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_role(user, "gateway-auditor", "gateway-admin")
    return mcp_federation_service.list_invocations(
        db, owner_subject=user.subject, server_id=server_id, limit=limit
    )


@router.get("/runtime-connections", response_model=list[McpRuntimeConnectionOut])
async def list_runtime_connections(
    server_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    require_role(user, "gateway-auditor", "gateway-admin")
    return mcp_federation_service.list_runtime_connections(
        db, owner_subject=user.subject, server_id=server_id
    )
