from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..adapters.docker import DockerAdapter, safe_container_name
from ..auth import get_current_user
from ..config import Settings, get_settings
from ..database import get_db
from ..dto import WorkspaceClone, WorkspaceCreate, WorkspaceOut
from ..events import emit_event
from ..models import DockerWorkspace, User, utcnow
from ..policy import enforce

router = APIRouter(prefix="/api/docker", tags=["docker"])


@router.get("/images")
async def list_images(settings: Settings = Depends(get_settings)) -> dict[str, list[str]]:
    return {"images": settings.docker_allowed_images}


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[DockerWorkspace]:
    enforce(user, action="read")
    query = db.query(DockerWorkspace).order_by(DockerWorkspace.created_at.desc())
    if "gateway-admin" not in set(user.roles or []):
        query = query.filter(DockerWorkspace.owner_subject == user.subject)
    return query.all()


@router.post("/workspaces", response_model=WorkspaceOut, status_code=201)
async def create_workspace(
    payload: WorkspaceCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DockerWorkspace:
    enforce(user, action="create", owner_subject=user.subject)
    adapter = DockerAdapter(settings)
    workspace_id = str(uuid.uuid4())
    container_name = safe_container_name(f"gw-{user.username}-{payload.name}-{workspace_id[:8]}")
    result = adapter.create_workspace(image=payload.image, container_name=container_name)
    workspace = DockerWorkspace(
        id=workspace_id,
        owner_subject=user.subject,
        name=payload.name,
        image=payload.image,
        container_name=container_name,
        container_id=result.container_id,
        status=result.status,
        meta={"detail": result.detail},
        updated_at=utcnow(),
    )
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.created.v1",
        actor_subject=user.subject,
        action="created",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "image": workspace.image, "container_name": workspace.container_name},
    )
    return workspace


@router.post("/workspaces/clone", response_model=WorkspaceOut, status_code=201)
async def clone_workspace(
    payload: WorkspaceClone,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DockerWorkspace:
    source = db.get(DockerWorkspace, payload.source_workspace_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source workspace not found")
    enforce(user, action="create", owner_subject=source.owner_subject)
    workspace_id = str(uuid.uuid4())
    container_name = safe_container_name(f"gw-{user.username}-{payload.name}-{workspace_id[:8]}")
    result = DockerAdapter(settings).clone_workspace(source_container_id=source.container_id, image=source.image, container_name=container_name)
    workspace = DockerWorkspace(
        id=workspace_id,
        owner_subject=user.subject,
        name=payload.name,
        image=source.image,
        container_name=container_name,
        container_id=result.container_id,
        status=result.status,
        source_workspace_id=source.id,
        meta={"detail": result.detail},
        updated_at=utcnow(),
    )
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.cloned.v1",
        actor_subject=user.subject,
        action="cloned",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "source_workspace_id": source.id, "image": workspace.image},
    )
    return workspace
