from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..agent_coordination import (
    agent_coordination_service,
    handoff_payload,
    integration_payload,
    lease_payload,
)
from ..auth import get_current_user
from ..database import get_db
from ..dto import (
    AgentHandoffAccept,
    AgentHandoffCreate,
    AgentHandoffReady,
    AgentIntegrationCreate,
    AgentIntegrationUpdate,
    FileConflictDetect,
    ResourceLeaseAcquire,
    ResourceLeaseRelease,
    ResourceLeaseRenew,
)
from ..models import User
from ..policy import enforce

router = APIRouter(prefix="/api/agent-coordination", tags=["agent-coordination"])


@router.post("/leases", status_code=201)
async def acquire_lease(
    payload: ResourceLeaseAcquire,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return lease_payload(
        agent_coordination_service.acquire_lease(
            db, owner_subject=user.subject, data=payload.model_dump()
        )
    )


@router.get("/leases")
async def list_leases(
    room_id: str | None = None,
    status: str | None = None,
    holder_agent_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    leases = agent_coordination_service.list_leases(
        db,
        owner_subject=user.subject,
        room_id=room_id,
        status=status,
        holder_agent_id=holder_agent_id,
    )
    return [lease_payload(lease) for lease in leases]


@router.post("/leases/{lease_id}/renew")
async def renew_lease(
    lease_id: str,
    payload: ResourceLeaseRenew,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    lease = agent_coordination_service.renew_lease(
        db,
        owner_subject=user.subject,
        lease_id=lease_id,
        holder_agent_id=payload.holder_agent_id,
        fencing_token=payload.fencing_token,
        ttl_seconds=payload.ttl_seconds,
    )
    return lease_payload(lease)


@router.post("/leases/{lease_id}/release")
async def release_lease(
    lease_id: str,
    payload: ResourceLeaseRelease,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    lease = agent_coordination_service.release_lease(
        db,
        owner_subject=user.subject,
        lease_id=lease_id,
        actor_agent_id=payload.actor_agent_id,
        fencing_token=payload.fencing_token,
        force=payload.force,
    )
    return lease_payload(lease)


@router.post("/conflicts/detect")
async def detect_conflicts(
    payload: FileConflictDetect,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="read")
    return agent_coordination_service.detect_conflicts(
        db,
        owner_subject=user.subject,
        candidate_change_ids=payload.candidate_change_ids,
        comparison_change_ids=payload.comparison_change_ids,
        room_id=payload.room_id,
    )


@router.post("/handoffs", status_code=201)
async def create_handoff(
    payload: AgentHandoffCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return handoff_payload(
        agent_coordination_service.create_handoff(
            db, owner_subject=user.subject, data=payload.model_dump()
        )
    )


@router.get("/handoffs")
async def list_handoffs(
    room_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    barriers = agent_coordination_service.list_handoffs(
        db, owner_subject=user.subject, room_id=room_id, status=status
    )
    return [handoff_payload(barrier) for barrier in barriers]


@router.post("/handoffs/{handoff_id}/ready")
async def mark_handoff_ready(
    handoff_id: str,
    payload: AgentHandoffReady,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return handoff_payload(
        agent_coordination_service.mark_handoff_ready(
            db,
            owner_subject=user.subject,
            handoff_id=handoff_id,
            source_agent_id=payload.source_agent_id,
        )
    )


@router.post("/handoffs/{handoff_id}/accept")
async def accept_handoff(
    handoff_id: str,
    payload: AgentHandoffAccept,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return handoff_payload(
        agent_coordination_service.accept_handoff(
            db,
            owner_subject=user.subject,
            handoff_id=handoff_id,
            target_agent_id=payload.target_agent_id,
            comparison_change_ids=payload.comparison_change_ids,
        )
    )


@router.post("/integrations", status_code=201)
async def create_integration(
    payload: AgentIntegrationCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return integration_payload(
        agent_coordination_service.create_integration(
            db, owner_subject=user.subject, data=payload.model_dump()
        )
    )


@router.get("/integrations")
async def list_integrations(
    room_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    records = agent_coordination_service.list_integrations(
        db, owner_subject=user.subject, room_id=room_id, status=status
    )
    return [integration_payload(record) for record in records]


@router.patch("/integrations/{integration_id}")
async def update_integration(
    integration_id: str,
    payload: AgentIntegrationUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    record = agent_coordination_service.complete_integration(
        db,
        owner_subject=user.subject,
        integration_id=integration_id,
        coordinator_agent_id=payload.coordinator_agent_id,
        expected_version=payload.expected_version,
        status=payload.status,
        observed_target_head=payload.observed_target_head,
        decision=payload.decision,
        integrated_commit=payload.integrated_commit,
    )
    return integration_payload(record)
