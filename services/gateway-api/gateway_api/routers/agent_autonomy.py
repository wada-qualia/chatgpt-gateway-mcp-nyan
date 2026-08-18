from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..agent_autonomy import (
    agent_autonomy_service,
    approval_payload,
    assignment_payload,
    control_payload,
    override_payload,
    permit_payload,
    policy_payload,
    receipt_payload,
    recovery_payload,
)
from ..auth import get_current_user, require_role
from ..database import get_db
from ..dto import (
    ActionReceiptCreate,
    ApprovalRequestCreate,
    ApprovalVoteCreate,
    AutonomyControlUpdate,
    AutonomyOverrideCreate,
    AutonomyPolicyCreate,
    AutonomyPolicyUpdate,
    ExecutionPermitClaim,
    ExecutionPermitIssue,
    RecoveryLoopCreate,
    RecoveryOutcomeCreate,
)
from ..models import ApprovalVote, User
from ..policy import enforce

router = APIRouter(prefix="/api/agent-autonomy", tags=["agent-autonomy"])


def _approval_response(db: Session, *, request: Any, user: User) -> dict[str, Any]:
    votes = (
        db.query(ApprovalVote)
        .filter(ApprovalVote.request_id == request.id)
        .order_by(ApprovalVote.created_at, ApprovalVote.id)
        .all()
    )
    result = approval_payload(request, votes)
    result["review"] = agent_autonomy_service.approval_review_projection(
        db, request=request, user=user, votes=votes
    )
    return result


@router.post("/policies", status_code=201)
async def create_policy(
    payload: AutonomyPolicyCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return policy_payload(
        agent_autonomy_service.create_policy(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            data=payload.model_dump(),
        )
    )


@router.get("/policies")
async def list_policies(
    room_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    return [
        policy_payload(policy)
        for policy in agent_autonomy_service.list_policies(
            db, owner_subject=user.subject, room_id=room_id, status=status
        )
    ]


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    payload: AutonomyPolicyUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    data = payload.model_dump(exclude_unset=True)
    expected_version = int(data.pop("expected_version"))
    return policy_payload(
        agent_autonomy_service.update_policy(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            policy_id=policy_id,
            expected_version=expected_version,
            data=data,
        )
    )


@router.post("/policies/{policy_id}/assignment-cycle")
async def run_assignment_cycle(
    policy_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return agent_autonomy_service.run_assignment_cycle(
        db,
        owner_subject=user.subject,
        policy_id=policy_id,
        actor_subject=user.subject,
        limit=limit,
    )


@router.get("/assignments")
async def list_assignments(
    room_id: str | None = None,
    policy_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    return [
        assignment_payload(assignment)
        for assignment in agent_autonomy_service.list_assignments(
            db,
            owner_subject=user.subject,
            room_id=room_id,
            policy_id=policy_id,
            status=status,
        )
    ]


@router.post("/assignments/{assignment_id}/apply")
async def apply_assignment(
    assignment_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return assignment_payload(
        agent_autonomy_service.apply_assignment(
            db,
            owner_subject=user.subject,
            assignment_id=assignment_id,
            actor_subject=user.subject,
        )
    )


@router.get("/controls")
async def list_controls(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="read")
    controls = agent_autonomy_service.list_controls(
        db, owner_subject=user.subject, include_global=True
    )
    return {
        "controls": [control_payload(control) for control in controls],
        "effective": agent_autonomy_service.control_snapshot(
            db, owner_subject=user.subject
        ),
    }


@router.post("/controls")
async def set_control(
    payload: AutonomyControlUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_role(user, "gateway-admin")
    return control_payload(
        agent_autonomy_service.set_control(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            actor_roles=list(user.roles or []),
            data=payload.model_dump(),
        )
    )


@router.post("/overrides", status_code=201)
async def apply_override(
    payload: AutonomyOverrideCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_role(user, "gateway-admin")
    return override_payload(
        agent_autonomy_service.apply_override(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            actor_roles=list(user.roles or []),
            data=payload.model_dump(),
        )
    )


@router.get("/overrides")
async def list_overrides(
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    require_role(user, "gateway-auditor", "gateway-admin")
    return [
        override_payload(record)
        for record in agent_autonomy_service.list_overrides(
            db, owner_subject=user.subject, limit=limit
        )
    ]


@router.post("/approvals", status_code=201)
async def create_approval_request(
    payload: ApprovalRequestCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    request = agent_autonomy_service.create_approval_request(
        db,
        owner_subject=user.subject,
        actor_subject=user.subject,
        data=payload.model_dump(),
    )
    return _approval_response(db, request=request, user=user)


@router.get("/approvals")
async def list_approval_requests(
    room_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    requests = agent_autonomy_service.list_approval_requests(
        db, user=user, room_id=room_id, status=status
    )
    return [
        _approval_response(db, request=request, user=user)
        for request in requests
    ]


@router.post("/approvals/{request_id}/votes")
async def cast_approval_vote(
    request_id: str,
    payload: ApprovalVoteCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    request = agent_autonomy_service.cast_vote(
        db,
        request_id=request_id,
        user=user,
        decision=payload.decision,
        reason=payload.reason,
    )
    return _approval_response(db, request=request, user=user)


@router.post("/approvals/{request_id}/permit", status_code=201)
async def issue_execution_permit(
    request_id: str,
    payload: ExecutionPermitIssue,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_role(user, "gateway-admin")
    return permit_payload(
        agent_autonomy_service.issue_permit(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            request_id=request_id,
            ttl_seconds=payload.ttl_seconds,
        )
    )


@router.get("/permits")
async def list_permits(
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    return [
        permit_payload(permit)
        for permit in agent_autonomy_service.list_permits(
            db, owner_subject=user.subject, status=status
        )
    ]


@router.post("/permits/{permit_id}/claim")
async def claim_execution_permit(
    permit_id: str,
    payload: ExecutionPermitClaim,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return permit_payload(
        agent_autonomy_service.claim_permit(
            db,
            owner_subject=user.subject,
            permit_id=permit_id,
            executor_agent_id=payload.executor_agent_id,
        )
    )


@router.post("/receipts", status_code=201)
async def record_action_receipt(
    payload: ActionReceiptCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return receipt_payload(
        agent_autonomy_service.record_receipt(
            db, owner_subject=user.subject, data=payload.model_dump()
        )
    )


@router.get("/receipts")
async def list_action_receipts(
    command_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    return [
        receipt_payload(receipt)
        for receipt in agent_autonomy_service.list_receipts(
            db, owner_subject=user.subject, command_id=command_id
        )
    ]


@router.post("/recoveries", status_code=201)
async def create_recovery_loop(
    payload: RecoveryLoopCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    return recovery_payload(
        agent_autonomy_service.create_recovery_loop(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            data=payload.model_dump(),
        )
    )


@router.get("/recoveries")
async def list_recovery_loops(
    room_id: str | None = None,
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    return [
        recovery_payload(loop)
        for loop in agent_autonomy_service.list_recovery_loops(
            db, owner_subject=user.subject, room_id=room_id, status=status
        )
    ]


@router.post("/policies/{policy_id}/recovery-cycle")
async def run_recovery_cycle(
    policy_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return agent_autonomy_service.run_recovery_cycle(
        db,
        owner_subject=user.subject,
        policy_id=policy_id,
        actor_subject=user.subject,
        limit=limit,
    )


@router.post("/recoveries/{loop_id}/outcome")
async def record_recovery_outcome(
    loop_id: str,
    payload: RecoveryOutcomeCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    return recovery_payload(
        agent_autonomy_service.record_recovery_outcome(
            db,
            owner_subject=user.subject,
            loop_id=loop_id,
            status=payload.status,
            command_id=payload.command_id,
            error=payload.error,
        )
    )


@router.get("/metrics")
async def autonomy_metrics(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    require_role(user, "gateway-auditor", "gateway-admin")
    return agent_autonomy_service.metrics(db, owner_subject=user.subject)
