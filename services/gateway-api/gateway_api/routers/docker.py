from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..adapters.docker import DockerAdapter, safe_container_name
from ..auth import get_current_user
from ..config import Settings, get_settings
from ..database import get_db
from ..dto import WorkspaceClone, WorkspaceCreate, WorkspaceExec, WorkspaceExecOut, WorkspaceOut, WorkspaceUpdate
from ..events import emit_event
from ..models import DockerWorkspace, User, utcnow
from ..monitoring import monitoring_service
from ..policy import enforce

router = APIRouter(prefix="/api/docker", tags=["docker"])


def _clean_workspace_description(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


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
    db.flush()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.created.v1",
        actor_subject=user.subject,
        action="created",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "image": workspace.image, "container_name": workspace.container_name},
        commit=False,
    )
    db.commit()
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
    db.flush()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.cloned.v1",
        actor_subject=user.subject,
        action="cloned",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "source_workspace_id": source.id, "image": workspace.image},
        commit=False,
    )
    db.commit()
    return workspace


@router.patch("/workspaces/{workspace_id}", response_model=WorkspaceOut)
async def update_workspace(
    workspace_id: str,
    payload: WorkspaceUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DockerWorkspace:
    workspace = db.get(DockerWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    enforce(user, action="update", owner_subject=workspace.owner_subject)

    meta = dict(workspace.meta or {})
    detail = meta.get("detail")
    if payload.name is not None:
        new_name = payload.name.strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="Workspace name must not be empty")
        if new_name != workspace.name:
            new_container_name = safe_container_name(f"gw-{user.username}-{new_name}-{workspace.id[:8]}")
            if new_container_name != workspace.container_name:
                detail = DockerAdapter(settings).rename_workspace(
                    container_id=workspace.container_id,
                    new_container_name=new_container_name,
                )
                workspace.container_name = new_container_name
            workspace.name = new_name

    if "description" in payload.model_fields_set:
        description = _clean_workspace_description(payload.description)
        if description is None:
            meta.pop("description", None)
        else:
            meta["description"] = description

    if detail:
        meta["detail"] = detail
    workspace.meta = meta
    workspace.updated_at = utcnow()
    db.flush()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.changed.v1",
        actor_subject=user.subject,
        action="updated",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={
            "workspace_id": workspace.id,
            "container_id": workspace.container_id,
            "container_name": workspace.container_name,
            "description_set": workspace.description is not None,
        },
        commit=False,
    )
    db.commit()
    return workspace


@router.post("/workspaces/{workspace_id}/exec", response_model=WorkspaceExecOut)
async def exec_workspace(
    workspace_id: str,
    payload: WorkspaceExec,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> WorkspaceExecOut:
    workspace = db.get(DockerWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    enforce(user, action="update", owner_subject=workspace.owner_subject)
    if not settings.gateway_docker_enabled:
        raise HTTPException(status_code=400, detail="Docker execution disabled")
    if not workspace.container_id:
        raise HTTPException(status_code=400, detail="Workspace has no container_id")
    result = await monitoring_service.run_local_command(
        db,
        owner_subject=user.subject,
        origin="docker",
        resource_id=workspace.id,
        command=payload.command,
        cwd=payload.workdir,
        args=["docker", "exec", "-w", payload.workdir, workspace.container_id, "sh", "-lc", payload.command],
        settings=settings,
        background=payload.background,
        session_name=payload.session_name,
        meta={"container_id": workspace.container_id, "workspace_id": workspace.id},
    )
    return WorkspaceExecOut(
        exit_code=result.exit_code,
        output=result.output,
        session_id=result.session_id,
        status=result.status,
        backgrounded=result.backgrounded,
        recommendation=result.recommendation,
    )


@router.post("/workspaces/{workspace_id}/stop", response_model=WorkspaceOut)
async def stop_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DockerWorkspace:
    workspace = db.get(DockerWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    enforce(user, action="update", owner_subject=workspace.owner_subject)
    result = DockerAdapter(settings).stop_workspace(container_id=workspace.container_id)
    workspace.status = result.status
    workspace.meta = {**(workspace.meta or {}), "detail": result.detail}
    workspace.updated_at = utcnow()
    db.flush()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.changed.v1",
        actor_subject=user.subject,
        action="stopped",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "container_id": workspace.container_id, "status": workspace.status},
        commit=False,
    )
    db.commit()
    return workspace


@router.post("/workspaces/{workspace_id}/start", response_model=WorkspaceOut)
async def start_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DockerWorkspace:
    workspace = db.get(DockerWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    enforce(user, action="update", owner_subject=workspace.owner_subject)
    result = DockerAdapter(settings).start_workspace(container_id=workspace.container_id)
    workspace.status = result.status
    workspace.meta = {**(workspace.meta or {}), "detail": result.detail}
    workspace.updated_at = utcnow()
    db.flush()
    db.refresh(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.changed.v1",
        actor_subject=user.subject,
        action="started",
        resource_type="docker_workspace",
        resource_id=workspace.id,
        payload={"workspace_id": workspace.id, "container_id": workspace.container_id, "status": workspace.status},
        commit=False,
    )
    db.commit()
    return workspace


@router.delete("/workspaces/{workspace_id}")
async def delete_workspace(
    workspace_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, bool]:
    workspace = db.get(DockerWorkspace, workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    enforce(user, action="delete", owner_subject=workspace.owner_subject)
    container_id = workspace.container_id
    container_name = workspace.container_name
    detail = DockerAdapter(settings).remove_workspace(container_id=container_id)
    db.delete(workspace)
    emit_event(
        db,
        event_type="gateway.workspace.changed.v1",
        actor_subject=user.subject,
        action="deleted",
        resource_type="docker_workspace",
        resource_id=workspace_id,
        payload={"workspace_id": workspace_id, "container_id": container_id, "container_name": container_name, "detail": detail},
        commit=False,
    )
    db.commit()
    return {"ok": True}
