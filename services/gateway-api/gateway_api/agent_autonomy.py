from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .affine_approval_projection import (
    AffineApprovalProjectionConfig,
    approval_user_can_vote,
    emit_affine_approval_projection,
    is_affine_research_server,
)
from .agent_collaboration import (
    COMMAND_TERMINAL_STATUSES,
    agent_collaboration_service,
)
from .agent_command_policy import (
    AgentCommandPolicyError,
    assert_no_secret_like_keys,
    resolve_agent_command_execution,
    validate_agent_command_for_delivery,
)
from .config import Settings, get_settings
from .events import emit_event
from .models import (
    AccessGrant,
    ActionReceipt,
    AgentCommand,
    AgentInstance,
    AgentWorkItem,
    ApprovalRequest,
    ApprovalVote,
    AutonomyAssignment,
    AutonomyControlState,
    AutonomyOverride,
    AutonomyPolicy,
    CollaborationRoom,
    ExecutionPermit,
    McpActionPreparation,
    McpServer,
    McpTool,
    RecoveryLoop,
    User,
    utcnow,
)

logger = logging.getLogger(__name__)

ACTION_CLASSES = {"read", "write", "destructive", "production"}
ASSIGNMENT_MODES = {"manual", "suggest", "automatic"}
POLICY_STATUSES = {"active", "paused", "disabled"}
CONTROL_STATES = {"enabled", "paused", "killed"}
CONTROL_SCOPES = {"global", "tenant", "room", "policy"}
APPROVAL_TERMINAL = {"approved", "rejected", "expired", "revoked"}
PERMIT_TERMINAL = {"consumed", "expired", "revoked"}
RECOVERY_TERMINAL = {"succeeded", "exhausted", "cancelled"}
RECEIPT_STATUSES = {"succeeded", "failed", "partial", "unknown"}
DEFAULT_APPROVAL_RULES: dict[str, dict[str, Any]] = {
    "read": {
        "quorum": 0,
        "require_admin": False,
        "disallow_proposer": False,
    },
    "write": {
        "quorum": 1,
        "require_admin": False,
        "disallow_proposer": True,
    },
    "destructive": {
        "quorum": 2,
        "require_admin": True,
        "disallow_proposer": True,
    },
    "production": {
        "quorum": 2,
        "require_admin": True,
        "disallow_proposer": True,
    },
}
DEFAULT_RECOVERY_POLICY = {
    "max_attempts": 3,
    "base_backoff_seconds": 30,
    "max_backoff_seconds": 900,
}


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _required_text(value: Any, *, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail=f"{field} is required")
    if len(text) > maximum:
        raise HTTPException(status_code=400, detail=f"{field} exceeds length limit")
    return text


def _optional_text(value: Any, *, maximum: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > maximum:
        raise HTTPException(status_code=400, detail="value exceeds length limit")
    return text


def _bounded_int(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int:
    try:
        parsed = int(default if value is None else value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail=f"{field} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise HTTPException(
            status_code=400,
            detail=f"{field} must be between {minimum} and {maximum}",
        )
    return parsed


def _safe_structured(value: Any, *, field: str) -> Any:
    try:
        assert_no_secret_like_keys(value, field=field)
    except AgentCommandPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def policy_payload(policy: AutonomyPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "room_id": policy.room_id,
        "name": policy.name,
        "status": policy.status,
        "assignment_mode": policy.assignment_mode,
        "coordinator_agent_id": policy.coordinator_agent_id,
        "allowed_action_classes": list(policy.allowed_action_classes or []),
        "allowed_tools": list(policy.allowed_tools or []),
        "allowed_command_profiles": list(policy.allowed_command_profiles or []),
        "max_parallel_assignments": policy.max_parallel_assignments,
        "approval_rules": dict(policy.approval_rules or {}),
        "recovery_policy": dict(policy.recovery_policy or {}),
        "generation": policy.generation,
        "version": policy.version,
        "created_by_subject": policy.created_by_subject,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }


def control_payload(control: AutonomyControlState) -> dict[str, Any]:
    return {
        "id": control.id,
        "owner_subject": control.owner_subject,
        "scope_type": control.scope_type,
        "scope_id": control.scope_id,
        "state": control.state,
        "generation": control.generation,
        "reason": control.reason,
        "changed_by_subject": control.changed_by_subject,
        "expires_at": control.expires_at.isoformat() if control.expires_at else None,
        "created_at": control.created_at.isoformat(),
        "updated_at": control.updated_at.isoformat(),
    }


def override_payload(record: AutonomyOverride) -> dict[str, Any]:
    return {
        "id": record.id,
        "scope_type": record.scope_type,
        "scope_id": record.scope_id,
        "action": record.action,
        "previous_state": record.previous_state,
        "new_state": record.new_state,
        "reason": record.reason,
        "actor_subject": record.actor_subject,
        "evidence": dict(record.evidence or {}),
        "created_at": record.created_at.isoformat(),
    }


def assignment_payload(assignment: AutonomyAssignment) -> dict[str, Any]:
    return {
        "id": assignment.id,
        "room_id": assignment.room_id,
        "policy_id": assignment.policy_id,
        "work_item_id": assignment.work_item_id,
        "selected_agent_id": assignment.selected_agent_id,
        "status": assignment.status,
        "score": assignment.score,
        "rationale": dict(assignment.rationale or {}),
        "policy_generation": assignment.policy_generation,
        "work_item_version": assignment.work_item_version,
        "created_by_subject": assignment.created_by_subject,
        "applied_at": assignment.applied_at.isoformat() if assignment.applied_at else None,
        "revoked_at": assignment.revoked_at.isoformat() if assignment.revoked_at else None,
        "created_at": assignment.created_at.isoformat(),
        "updated_at": assignment.updated_at.isoformat(),
    }


def approval_payload(
    request: ApprovalRequest, votes: list[ApprovalVote] | None = None
) -> dict[str, Any]:
    result = {
        "id": request.id,
        "room_id": request.room_id,
        "policy_id": request.policy_id,
        "command_id": request.command_id,
        "work_item_id": request.work_item_id,
        "integration_id": request.integration_id,
        "proposer_agent_id": request.proposer_agent_id,
        "executor_agent_id": request.executor_agent_id,
        "action_kind": request.action_kind,
        "action_class": request.action_class,
        "tool": request.tool,
        "command_profile": request.command_profile,
        "payload_hash": request.payload_hash,
        "payload_summary": dict(request.payload_summary or {}),
        "quorum_required": request.quorum_required,
        "require_admin_approval": request.require_admin_approval,
        "disallow_proposer_vote": request.disallow_proposer_vote,
        "status": request.status,
        "policy_generation": request.policy_generation,
        "version": request.version,
        "created_by_subject": request.created_by_subject,
        "expires_at": request.expires_at.isoformat(),
        "approved_at": request.approved_at.isoformat() if request.approved_at else None,
        "rejected_at": request.rejected_at.isoformat() if request.rejected_at else None,
        "revoked_at": request.revoked_at.isoformat() if request.revoked_at else None,
        "created_at": request.created_at.isoformat(),
        "updated_at": request.updated_at.isoformat(),
    }
    if votes is not None:
        result["votes"] = [vote_payload(vote) for vote in votes]
    return result


def vote_payload(vote: ApprovalVote) -> dict[str, Any]:
    return {
        "id": vote.id,
        "request_id": vote.request_id,
        "voter_subject": vote.voter_subject,
        "voter_roles": list(vote.voter_roles or []),
        "decision": vote.decision,
        "reason": vote.reason,
        "created_at": vote.created_at.isoformat(),
    }


def permit_payload(permit: ExecutionPermit) -> dict[str, Any]:
    return {
        "id": permit.id,
        "approval_request_id": permit.approval_request_id,
        "policy_id": permit.policy_id,
        "command_id": permit.command_id,
        "executor_agent_id": permit.executor_agent_id,
        "action_class": permit.action_class,
        "tool": permit.tool,
        "command_profile": permit.command_profile,
        "payload_hash": permit.payload_hash,
        "status": permit.status,
        "policy_generation": permit.policy_generation,
        "control_snapshot": dict(permit.control_snapshot or {}),
        "fencing_token": permit.fencing_token,
        "max_uses": permit.max_uses,
        "use_count": permit.use_count,
        "issued_by_subject": permit.issued_by_subject,
        "issued_at": permit.issued_at.isoformat(),
        "expires_at": permit.expires_at.isoformat(),
        "claimed_at": permit.claimed_at.isoformat() if permit.claimed_at else None,
        "consumed_at": permit.consumed_at.isoformat() if permit.consumed_at else None,
        "revoked_at": permit.revoked_at.isoformat() if permit.revoked_at else None,
        "revocation_reason": permit.revocation_reason,
        "created_at": permit.created_at.isoformat(),
        "updated_at": permit.updated_at.isoformat(),
    }


def receipt_payload(receipt: ActionReceipt) -> dict[str, Any]:
    return {
        "id": receipt.id,
        "permit_id": receipt.permit_id,
        "approval_request_id": receipt.approval_request_id,
        "command_id": receipt.command_id,
        "executor_agent_id": receipt.executor_agent_id,
        "action_class": receipt.action_class,
        "tool": receipt.tool,
        "command_profile": receipt.command_profile,
        "status": receipt.status,
        "input_hash": receipt.input_hash,
        "output_hash": receipt.output_hash,
        "result_summary": dict(receipt.result_summary or {}),
        "error": receipt.error,
        "external_references": list(receipt.external_references or []),
        "started_at": receipt.started_at.isoformat(),
        "completed_at": receipt.completed_at.isoformat(),
        "created_at": receipt.created_at.isoformat(),
    }


def recovery_payload(loop: RecoveryLoop) -> dict[str, Any]:
    return {
        "id": loop.id,
        "room_id": loop.room_id,
        "policy_id": loop.policy_id,
        "source_type": loop.source_type,
        "source_id": loop.source_id,
        "target_agent_id": loop.target_agent_id,
        "strategy": dict(loop.strategy or {}),
        "status": loop.status,
        "attempt_count": loop.attempt_count,
        "max_attempts": loop.max_attempts,
        "base_backoff_seconds": loop.base_backoff_seconds,
        "next_attempt_at": loop.next_attempt_at.isoformat(),
        "last_command_id": loop.last_command_id,
        "last_error": loop.last_error,
        "policy_generation": loop.policy_generation,
        "generation": loop.generation,
        "created_by_subject": loop.created_by_subject,
        "created_at": loop.created_at.isoformat(),
        "updated_at": loop.updated_at.isoformat(),
        "completed_at": loop.completed_at.isoformat() if loop.completed_at else None,
    }


class AgentAutonomyService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @staticmethod
    def _room(db: Session, *, owner_subject: str, room_id: str) -> CollaborationRoom:
        room = (
            db.query(CollaborationRoom)
            .filter(
                CollaborationRoom.id == room_id,
                CollaborationRoom.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if room is None:
            raise HTTPException(status_code=404, detail="Collaboration room not found")
        return room

    @staticmethod
    def _agent(db: Session, *, owner_subject: str, agent_id: str) -> AgentInstance:
        agent = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.id == agent_id,
                AgentInstance.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent instance not found")
        return agent

    @staticmethod
    def _policy(db: Session, *, owner_subject: str, policy_id: str) -> AutonomyPolicy:
        policy = (
            db.query(AutonomyPolicy)
            .filter(
                AutonomyPolicy.id == policy_id,
                AutonomyPolicy.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if policy is None:
            raise HTTPException(status_code=404, detail="Autonomy policy not found")
        return policy

    @staticmethod
    def _work_item(db: Session, *, owner_subject: str, work_item_id: str) -> AgentWorkItem:
        item = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.id == work_item_id,
                AgentWorkItem.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if item is None:
            raise HTTPException(status_code=404, detail="Work item not found")
        return item

    @staticmethod
    def _command(db: Session, *, owner_subject: str, command_id: str) -> AgentCommand:
        command = (
            db.query(AgentCommand)
            .filter(
                AgentCommand.id == command_id,
                AgentCommand.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if command is None:
            raise HTTPException(status_code=404, detail="Agent command not found")
        return command

    @staticmethod
    def _approval(db: Session, *, request_id: str) -> ApprovalRequest:
        request = db.get(ApprovalRequest, request_id)
        if request is None:
            raise HTTPException(status_code=404, detail="Approval request not found")
        return request

    @staticmethod
    def _permit(db: Session, *, owner_subject: str, permit_id: str) -> ExecutionPermit:
        permit = (
            db.query(ExecutionPermit)
            .filter(
                ExecutionPermit.id == permit_id,
                ExecutionPermit.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if permit is None:
            raise HTTPException(status_code=404, detail="Execution permit not found")
        return permit

    @staticmethod
    def _assignment(
        db: Session, *, owner_subject: str, assignment_id: str
    ) -> AutonomyAssignment:
        assignment = (
            db.query(AutonomyAssignment)
            .filter(
                AutonomyAssignment.id == assignment_id,
                AutonomyAssignment.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if assignment is None:
            raise HTTPException(status_code=404, detail="Autonomy assignment not found")
        return assignment

    @staticmethod
    def _recovery(db: Session, *, owner_subject: str, loop_id: str) -> RecoveryLoop:
        loop = (
            db.query(RecoveryLoop)
            .filter(
                RecoveryLoop.id == loop_id,
                RecoveryLoop.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if loop is None:
            raise HTTPException(status_code=404, detail="Recovery loop not found")
        return loop

    @staticmethod
    def _normalized_strings(values: Any, *, maximum: int = 200) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for value in list(values or []):
            text = str(value).strip()
            if not text or text in seen:
                continue
            if len(text) > 200:
                raise HTTPException(status_code=400, detail="policy value exceeds length limit")
            seen.add(text)
            result.append(text)
        if len(result) > maximum:
            raise HTTPException(status_code=400, detail="too many policy values")
        return result

    def _normalize_approval_rules(self, value: Any) -> dict[str, Any]:
        raw = dict(_safe_structured(dict(value or {}), field="approval rules"))
        result: dict[str, Any] = {}
        for action_class in sorted(ACTION_CLASSES):
            defaults = DEFAULT_APPROVAL_RULES[action_class]
            rule = dict(raw.get(action_class) or {})
            result[action_class] = {
                "quorum": _bounded_int(
                    rule.get("quorum", defaults["quorum"]),
                    field=f"approval_rules.{action_class}.quorum",
                    minimum=0,
                    maximum=20,
                ),
                "require_admin": bool(
                    rule.get("require_admin", defaults["require_admin"])
                ),
                "disallow_proposer": bool(
                    rule.get(
                        "disallow_proposer", defaults["disallow_proposer"]
                    )
                ),
            }
        return result

    def _normalize_recovery_policy(self, value: Any) -> dict[str, Any]:
        raw = dict(_safe_structured(dict(value or {}), field="recovery policy"))
        return {
            "max_attempts": _bounded_int(
                raw.get("max_attempts", DEFAULT_RECOVERY_POLICY["max_attempts"]),
                field="recovery_policy.max_attempts",
                minimum=1,
                maximum=20,
            ),
            "base_backoff_seconds": _bounded_int(
                raw.get(
                    "base_backoff_seconds",
                    DEFAULT_RECOVERY_POLICY["base_backoff_seconds"],
                ),
                field="recovery_policy.base_backoff_seconds",
                minimum=1,
                maximum=86400,
            ),
            "max_backoff_seconds": _bounded_int(
                raw.get(
                    "max_backoff_seconds",
                    DEFAULT_RECOVERY_POLICY["max_backoff_seconds"],
                ),
                field="recovery_policy.max_backoff_seconds",
                minimum=1,
                maximum=604800,
            ),
        }

    def create_policy(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        data: dict[str, Any],
    ) -> AutonomyPolicy:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        self._room(db, owner_subject=owner_subject, room_id=room_id)
        coordinator_agent_id = _optional_text(
            data.get("coordinator_agent_id"), maximum=36
        )
        if coordinator_agent_id:
            coordinator = self._agent(
                db, owner_subject=owner_subject, agent_id=coordinator_agent_id
            )
            if coordinator.current_room_id != room_id:
                raise HTTPException(
                    status_code=409,
                    detail="Coordinator agent is not in the policy room",
                )
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AutonomyPolicy)
                .filter(
                    AutonomyPolicy.owner_subject == owner_subject,
                    AutonomyPolicy.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        assignment_mode = str(data.get("assignment_mode") or "manual")
        if assignment_mode not in ASSIGNMENT_MODES:
            raise HTTPException(status_code=400, detail="Unsupported assignment mode")
        allowed_action_classes = self._normalized_strings(
            data.get("allowed_action_classes") or ["read"]
        )
        if not allowed_action_classes or not set(allowed_action_classes).issubset(
            ACTION_CLASSES
        ):
            raise HTTPException(
                status_code=400, detail="Unsupported allowed action class"
            )
        policy = AutonomyPolicy(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            name=_required_text(data.get("name"), field="name", maximum=200),
            status="active",
            assignment_mode=assignment_mode,
            coordinator_agent_id=coordinator_agent_id,
            allowed_action_classes=allowed_action_classes,
            allowed_tools=self._normalized_strings(data.get("allowed_tools")),
            allowed_command_profiles=self._normalized_strings(
                data.get("allowed_command_profiles")
            ),
            max_parallel_assignments=_bounded_int(
                data.get("max_parallel_assignments", 1),
                field="max_parallel_assignments",
                minimum=1,
                maximum=100,
            ),
            approval_rules=self._normalize_approval_rules(data.get("approval_rules")),
            recovery_policy=self._normalize_recovery_policy(
                data.get("recovery_policy")
            ),
            generation=1,
            version=1,
            idempotency_key=idempotency_key,
            created_by_subject=actor_subject,
        )
        db.add(policy)
        try:
            emit_event(
                db,
                event_type="gateway.autonomy.policy.created.v1",
                actor_subject=actor_subject,
                action="created",
                resource_type="autonomy_policy",
                resource_id=policy.id,
                payload={
                    "policy_id": policy.id,
                    "room_id": policy.room_id,
                    "assignment_mode": policy.assignment_mode,
                    "generation": policy.generation,
                    "version": policy.version,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(AutonomyPolicy)
                    .filter(
                        AutonomyPolicy.owner_subject == owner_subject,
                        AutonomyPolicy.idempotency_key == idempotency_key,
                    )
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(
                status_code=409, detail="Autonomy policy idempotency conflict"
            ) from exc
        db.refresh(policy)
        return policy

    def list_policies(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        status: str | None = None,
    ) -> list[AutonomyPolicy]:
        query = db.query(AutonomyPolicy).filter(
            AutonomyPolicy.owner_subject == owner_subject
        )
        if room_id:
            query = query.filter(AutonomyPolicy.room_id == room_id)
        if status:
            query = query.filter(AutonomyPolicy.status == status)
        return query.order_by(AutonomyPolicy.created_at, AutonomyPolicy.id).all()

    def update_policy(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        policy_id: str,
        expected_version: int,
        data: dict[str, Any],
    ) -> AutonomyPolicy:
        policy = self._policy(db, owner_subject=owner_subject, policy_id=policy_id)
        if int(policy.version) != int(expected_version):
            raise HTTPException(status_code=409, detail="Autonomy policy version conflict")
        values: dict[Any, Any] = {
            AutonomyPolicy.version: AutonomyPolicy.version + 1,
            AutonomyPolicy.generation: AutonomyPolicy.generation + 1,
            AutonomyPolicy.updated_at: utcnow(),
        }
        if data.get("name") is not None:
            values[AutonomyPolicy.name] = _required_text(
                data.get("name"), field="name", maximum=200
            )
        if data.get("status") is not None:
            status = str(data["status"])
            if status not in POLICY_STATUSES:
                raise HTTPException(status_code=400, detail="Unsupported policy status")
            values[AutonomyPolicy.status] = status
        if data.get("assignment_mode") is not None:
            mode = str(data["assignment_mode"])
            if mode not in ASSIGNMENT_MODES:
                raise HTTPException(status_code=400, detail="Unsupported assignment mode")
            values[AutonomyPolicy.assignment_mode] = mode
        if "coordinator_agent_id" in data:
            coordinator_id = _optional_text(data.get("coordinator_agent_id"), maximum=36)
            if coordinator_id:
                coordinator = self._agent(
                    db, owner_subject=owner_subject, agent_id=coordinator_id
                )
                if coordinator.current_room_id != policy.room_id:
                    raise HTTPException(
                        status_code=409,
                        detail="Coordinator agent is not in the policy room",
                    )
            values[AutonomyPolicy.coordinator_agent_id] = coordinator_id
        if data.get("allowed_action_classes") is not None:
            classes = self._normalized_strings(data["allowed_action_classes"])
            if not classes or not set(classes).issubset(ACTION_CLASSES):
                raise HTTPException(
                    status_code=400, detail="Unsupported allowed action class"
                )
            values[AutonomyPolicy.allowed_action_classes] = classes
        if data.get("allowed_tools") is not None:
            values[AutonomyPolicy.allowed_tools] = self._normalized_strings(
                data["allowed_tools"]
            )
        if data.get("allowed_command_profiles") is not None:
            values[AutonomyPolicy.allowed_command_profiles] = self._normalized_strings(
                data["allowed_command_profiles"]
            )
        if data.get("max_parallel_assignments") is not None:
            values[AutonomyPolicy.max_parallel_assignments] = _bounded_int(
                data["max_parallel_assignments"],
                field="max_parallel_assignments",
                minimum=1,
                maximum=100,
            )
        if data.get("approval_rules") is not None:
            values[AutonomyPolicy.approval_rules] = self._normalize_approval_rules(
                data["approval_rules"]
            )
        if data.get("recovery_policy") is not None:
            values[AutonomyPolicy.recovery_policy] = self._normalize_recovery_policy(
                data["recovery_policy"]
            )
        changed = (
            db.query(AutonomyPolicy)
            .filter(
                AutonomyPolicy.id == policy.id,
                AutonomyPolicy.owner_subject == owner_subject,
                AutonomyPolicy.version == int(expected_version),
            )
            .update(values, synchronize_session=False)
        )
        if changed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Autonomy policy version conflict")
        db.flush()
        db.expire_all()
        updated = self._policy(db, owner_subject=owner_subject, policy_id=policy.id)
        self._revoke_permits(
            db,
            owner_subject=owner_subject,
            policy_id=policy.id,
            reason="policy generation changed",
        )
        emit_event(
            db,
            event_type="gateway.autonomy.policy.updated.v1",
            actor_subject=actor_subject,
            action="updated",
            resource_type="autonomy_policy",
            resource_id=updated.id,
            payload={
                "policy_id": updated.id,
                "room_id": updated.room_id,
                "status": updated.status,
                "assignment_mode": updated.assignment_mode,
                "generation": updated.generation,
                "version": updated.version,
            },
            commit=False,
        )
        db.commit()
        db.refresh(updated)
        return updated

    def _control_row(
        self,
        db: Session,
        *,
        owner_subject: str,
        scope_type: str,
        scope_id: str,
    ) -> AutonomyControlState | None:
        return (
            db.query(AutonomyControlState)
            .filter(
                AutonomyControlState.owner_subject == owner_subject,
                AutonomyControlState.scope_type == scope_type,
                AutonomyControlState.scope_id == scope_id,
            )
            .one_or_none()
        )

    def control_snapshot(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        policy_id: str | None = None,
    ) -> dict[str, Any]:
        if self.settings.gateway_autonomy_emergency_stop:
            return {
                "enabled": False,
                "effective_state": "killed",
                "reason": "GATEWAY_AUTONOMY_EMERGENCY_STOP",
                "generations": {"environment": 1},
            }
        scopes = [
            ("*", "global", ""),
            (owner_subject, "tenant", ""),
        ]
        if room_id:
            scopes.append((owner_subject, "room", room_id))
        if policy_id:
            scopes.append((owner_subject, "policy", policy_id))
        effective = "enabled"
        reason: str | None = None
        generations: dict[str, int] = {}
        now = utcnow()
        for control_owner, scope_type, scope_id in scopes:
            row = self._control_row(
                db,
                owner_subject=control_owner,
                scope_type=scope_type,
                scope_id=scope_id,
            )
            if row is None:
                generations[f"{scope_type}:{scope_id}"] = 0
                continue
            expires_at = _aware(row.expires_at)
            state = row.state if expires_at is None or expires_at > now else "enabled"
            generations[f"{scope_type}:{scope_id}"] = row.generation
            if state == "killed":
                effective = "killed"
                reason = row.reason
                break
            if state == "paused" and effective == "enabled":
                effective = "paused"
                reason = row.reason
        return {
            "enabled": effective == "enabled",
            "effective_state": effective,
            "reason": reason,
            "generations": generations,
        }

    def assert_enabled(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str,
        policy: AutonomyPolicy,
    ) -> dict[str, Any]:
        if policy.status != "active":
            raise HTTPException(status_code=409, detail="Autonomy policy is not active")
        snapshot = self.control_snapshot(
            db,
            owner_subject=owner_subject,
            room_id=room_id,
            policy_id=policy.id,
        )
        if not snapshot["enabled"]:
            raise HTTPException(
                status_code=423,
                detail=f"Autonomy is {snapshot['effective_state']}",
            )
        return snapshot

    def list_controls(
        self, db: Session, *, owner_subject: str, include_global: bool = True
    ) -> list[AutonomyControlState]:
        owner_filters = [AutonomyControlState.owner_subject == owner_subject]
        if include_global:
            owner_filters.append(AutonomyControlState.owner_subject == "*")
        query = db.query(AutonomyControlState).filter(or_(*owner_filters))
        return query.order_by(
            AutonomyControlState.scope_type,
            AutonomyControlState.scope_id,
        ).all()

    def _revoke_permits(
        self,
        db: Session,
        *,
        owner_subject: str,
        reason: str,
        room_id: str | None = None,
        policy_id: str | None = None,
    ) -> int:
        query = db.query(ExecutionPermit).filter(
            ExecutionPermit.owner_subject == owner_subject,
            ExecutionPermit.status.in_(["active", "claimed"]),
        )
        if policy_id:
            query = query.filter(ExecutionPermit.policy_id == policy_id)
        permits = query.all()
        now = utcnow()
        changed = 0
        for permit in permits:
            request = db.get(ApprovalRequest, permit.approval_request_id)
            if request is None:
                continue
            if room_id and request.room_id != room_id:
                continue
            permit.status = "revoked"
            permit.revoked_at = now
            permit.revocation_reason = reason[:10000]
            permit.updated_at = now
            changed += 1
        return changed

    def _pause_or_cancel_recoveries(
        self,
        db: Session,
        *,
        owner_subject: str,
        state: str,
        room_id: str | None = None,
        policy_id: str | None = None,
    ) -> int:
        query = db.query(RecoveryLoop).filter(
            RecoveryLoop.owner_subject == owner_subject,
            RecoveryLoop.status.notin_(RECOVERY_TERMINAL),
        )
        if room_id:
            query = query.filter(RecoveryLoop.room_id == room_id)
        if policy_id:
            query = query.filter(RecoveryLoop.policy_id == policy_id)
        now = utcnow()
        changed = 0
        for loop in query.all():
            loop.status = "cancelled" if state == "killed" else "paused"
            loop.generation = int(loop.generation or 0) + 1
            loop.updated_at = now
            if loop.status == "cancelled":
                loop.completed_at = now
            changed += 1
        return changed

    def set_control(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        actor_roles: list[str],
        data: dict[str, Any],
    ) -> AutonomyControlState:
        scope_type = str(data.get("scope_type") or "")
        state = str(data.get("state") or "")
        if scope_type not in CONTROL_SCOPES or state not in CONTROL_STATES:
            raise HTTPException(status_code=400, detail="Unsupported autonomy control")
        if "gateway-admin" not in set(actor_roles or []):
            raise HTTPException(status_code=403, detail="Autonomy control requires gateway-admin")
        scope_id = str(data.get("scope_id") or "").strip()
        control_owner = owner_subject
        room_id: str | None = None
        policy_id: str | None = None
        if scope_type == "global":
            control_owner = "*"
            scope_id = ""
        elif scope_type == "tenant":
            scope_id = ""
        elif scope_type == "room":
            room_id = _required_text(scope_id, field="scope_id", maximum=36)
            self._room(db, owner_subject=owner_subject, room_id=room_id)
        elif scope_type == "policy":
            policy_id = _required_text(scope_id, field="scope_id", maximum=36)
            policy = self._policy(
                db, owner_subject=owner_subject, policy_id=policy_id
            )
            room_id = policy.room_id
        reason = _required_text(data.get("reason"), field="reason", maximum=10000)
        row = self._control_row(
            db,
            owner_subject=control_owner,
            scope_type=scope_type,
            scope_id=scope_id,
        )
        previous_state = row.state if row else None
        now = utcnow()
        if row is None:
            row = AutonomyControlState(
                id=str(uuid.uuid4()),
                owner_subject=control_owner,
                scope_type=scope_type,
                scope_id=scope_id,
                state=state,
                generation=1,
                reason=reason,
                changed_by_subject=actor_subject,
                expires_at=data.get("expires_at"),
                created_at=now,
                updated_at=now,
            )
            db.add(row)
        else:
            row.state = state
            row.generation = int(row.generation or 0) + 1
            row.reason = reason
            row.changed_by_subject = actor_subject
            row.expires_at = data.get("expires_at")
            row.updated_at = now
        evidence = {
            "revoked_permits": 0,
            "affected_recoveries": 0,
        }
        if state in {"paused", "killed"}:
            target_owner = owner_subject
            if scope_type == "global":
                active_owners = {
                    value[0]
                    for value in db.query(ExecutionPermit.owner_subject).distinct().all()
                }
                active_owners.update(
                    value[0]
                    for value in db.query(RecoveryLoop.owner_subject).distinct().all()
                )
            else:
                active_owners = {target_owner}
            for active_owner in active_owners:
                evidence["revoked_permits"] += self._revoke_permits(
                    db,
                    owner_subject=active_owner,
                    reason=f"autonomy {state}: {reason}",
                    room_id=room_id,
                    policy_id=policy_id,
                )
                evidence["affected_recoveries"] += self._pause_or_cancel_recoveries(
                    db,
                    owner_subject=active_owner,
                    state=state,
                    room_id=room_id,
                    policy_id=policy_id,
                )
        override = AutonomyOverride(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            scope_type=scope_type,
            scope_id=scope_id,
            action={"enabled": "resume", "paused": "pause", "killed": "kill"}[state],
            previous_state=previous_state,
            new_state=state,
            reason=reason,
            actor_subject=actor_subject,
            evidence=evidence,
            created_at=now,
        )
        db.add(override)
        emit_event(
            db,
            event_type="gateway.autonomy.control.changed.v1",
            actor_subject=actor_subject,
            action=override.action,
            resource_type="autonomy_control",
            resource_id=row.id,
            payload={
                "control_id": row.id,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "state": state,
                "generation": row.generation,
                "revoked_permits": evidence["revoked_permits"],
                "affected_recoveries": evidence["affected_recoveries"],
            },
            status="warning" if state != "enabled" else "success",
            commit=False,
        )
        db.commit()
        db.refresh(row)
        return row

    def _dependencies_ready(
        self, db: Session, *, owner_subject: str, item: AgentWorkItem
    ) -> bool:
        dependencies = list(item.dependencies or [])
        if not dependencies:
            return True
        completed = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.owner_subject == owner_subject,
                AgentWorkItem.room_id == item.room_id,
                AgentWorkItem.id.in_(dependencies),
                AgentWorkItem.status == "completed",
            )
            .count()
        )
        return completed == len(set(dependencies))

    def _eligible_agents(
        self,
        db: Session,
        *,
        owner_subject: str,
        item: AgentWorkItem,
    ) -> list[tuple[AgentInstance, int, dict[str, Any]]]:
        now = utcnow()
        constraints = dict(item.assignment_constraints or {})
        excluded = {str(value) for value in list(constraints.get("exclude_agent_ids") or [])}
        required_labels = dict(constraints.get("labels") or {})
        required_capabilities = set(item.required_capabilities or [])
        agents = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.owner_subject == owner_subject,
                AgentInstance.current_room_id == item.room_id,
                AgentInstance.status.in_(["active", "idle"]),
                AgentInstance.current_work_item_id.is_(None),
                or_(AgentInstance.expires_at.is_(None), AgentInstance.expires_at > now),
            )
            .order_by(AgentInstance.id)
            .all()
        )
        result: list[tuple[AgentInstance, int, dict[str, Any]]] = []
        for agent in agents:
            if agent.id in excluded:
                continue
            capabilities = set(agent.capabilities or [])
            if not required_capabilities.issubset(capabilities):
                continue
            labels = dict(agent.labels or {})
            if any(labels.get(key) != value for key, value in required_labels.items()):
                continue
            score = 1000 if agent.status == "idle" else 900
            score += len(required_capabilities) * 50
            score += len(capabilities - required_capabilities)
            rationale = {
                "required_capabilities": sorted(required_capabilities),
                "matched_capabilities": sorted(required_capabilities),
                "extra_capability_count": len(capabilities - required_capabilities),
                "required_labels": required_labels,
                "agent_status": agent.status,
            }
            result.append((agent, score, rationale))
        return sorted(result, key=lambda value: (-value[1], value[0].id))

    def _apply_assignment_record(
        self,
        db: Session,
        *,
        assignment: AutonomyAssignment,
        actor_subject: str,
        commit: bool = True,
    ) -> AutonomyAssignment:
        policy = self._policy(
            db,
            owner_subject=assignment.owner_subject,
            policy_id=assignment.policy_id,
        )
        self.assert_enabled(
            db,
            owner_subject=assignment.owner_subject,
            room_id=assignment.room_id,
            policy=policy,
        )
        if assignment.status == "assigned":
            return assignment
        if assignment.status != "proposed":
            raise HTTPException(status_code=409, detail="Assignment is not applicable")
        if assignment.policy_generation != policy.generation:
            raise HTTPException(status_code=409, detail="Assignment policy generation is stale")
        item = self._work_item(
            db,
            owner_subject=assignment.owner_subject,
            work_item_id=assignment.work_item_id,
        )
        agent = self._agent(
            db,
            owner_subject=assignment.owner_subject,
            agent_id=assignment.selected_agent_id,
        )
        if not self._dependencies_ready(db, owner_subject=assignment.owner_subject, item=item):
            raise HTTPException(status_code=409, detail="Work item dependencies are not completed")
        eligible = {
            candidate.id
            for candidate, _, _ in self._eligible_agents(
                db, owner_subject=assignment.owner_subject, item=item
            )
        }
        if agent.id not in eligible:
            raise HTTPException(status_code=409, detail="Selected agent is no longer eligible")
        changed = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.id == item.id,
                AgentWorkItem.owner_subject == assignment.owner_subject,
                AgentWorkItem.status == "open",
                AgentWorkItem.assigned_agent_id.is_(None),
                AgentWorkItem.version == assignment.work_item_version,
            )
            .update(
                {
                    AgentWorkItem.status: "in_progress",
                    AgentWorkItem.assigned_agent_id: agent.id,
                    AgentWorkItem.version: AgentWorkItem.version + 1,
                    AgentWorkItem.updated_at: utcnow(),
                },
                synchronize_session=False,
            )
        )
        if changed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Automatic assignment conflict")
        now = utcnow()
        agent.current_work_item_id = item.id
        agent.status = "busy"
        agent.updated_at = now
        assignment.status = "assigned"
        assignment.applied_at = now
        assignment.updated_at = now
        emit_event(
            db,
            event_type="gateway.autonomy.assignment.applied.v1",
            actor_subject=actor_subject,
            action="assigned",
            resource_type="autonomy_assignment",
            resource_id=assignment.id,
            payload={
                "assignment_id": assignment.id,
                "policy_id": assignment.policy_id,
                "room_id": assignment.room_id,
                "work_item_id": assignment.work_item_id,
                "agent_id": assignment.selected_agent_id,
                "policy_generation": assignment.policy_generation,
            },
            commit=False,
        )
        emit_event(
            db,
            event_type="gateway.work_item.claimed.v1",
            actor_subject=actor_subject,
            action="autonomously_assigned",
            resource_type="agent_work_item",
            resource_id=item.id,
            payload={
                "work_item_id": item.id,
                "room_id": item.room_id,
                "agent_id": agent.id,
                "version": item.version + 1,
            },
            commit=False,
        )
        if commit:
            db.commit()
            db.refresh(assignment)
        else:
            db.flush()
        return assignment

    def run_assignment_cycle(
        self,
        db: Session,
        *,
        owner_subject: str,
        policy_id: str,
        actor_subject: str = "system:autonomy-worker",
        limit: int | None = None,
    ) -> dict[str, Any]:
        policy = self._policy(db, owner_subject=owner_subject, policy_id=policy_id)
        self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=policy.room_id,
            policy=policy,
        )
        if policy.assignment_mode == "manual":
            return {"considered": 0, "proposed": 0, "assigned": 0, "skipped": 0}
        active_count = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.owner_subject == owner_subject,
                AgentWorkItem.room_id == policy.room_id,
                AgentWorkItem.status == "in_progress",
            )
            .count()
        )
        capacity = max(0, int(policy.max_parallel_assignments) - active_count)
        bounded_limit = _bounded_int(
            limit,
            field="limit",
            minimum=1,
            maximum=100,
            default=self.settings.gateway_autonomy_assignment_batch_size,
        )
        if policy.assignment_mode == "automatic":
            bounded_limit = min(bounded_limit, capacity)
        if bounded_limit <= 0:
            return {"considered": 0, "proposed": 0, "assigned": 0, "skipped": 0}
        items = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.owner_subject == owner_subject,
                AgentWorkItem.room_id == policy.room_id,
                AgentWorkItem.status == "open",
                AgentWorkItem.assigned_agent_id.is_(None),
            )
            .order_by(
                AgentWorkItem.priority.desc(),
                AgentWorkItem.created_at,
                AgentWorkItem.id,
            )
            .limit(bounded_limit * 4)
            .all()
        )
        result = {"considered": 0, "proposed": 0, "assigned": 0, "skipped": 0}
        for item in items:
            if result["proposed"] + result["assigned"] >= bounded_limit:
                break
            result["considered"] += 1
            if not self._dependencies_ready(db, owner_subject=owner_subject, item=item):
                result["skipped"] += 1
                continue
            existing = (
                db.query(AutonomyAssignment)
                .filter(
                    AutonomyAssignment.owner_subject == owner_subject,
                    AutonomyAssignment.policy_id == policy.id,
                    AutonomyAssignment.work_item_id == item.id,
                    AutonomyAssignment.status.in_(["proposed", "assigned"]),
                )
                .one_or_none()
            )
            if existing is not None:
                result["skipped"] += 1
                continue
            candidates = self._eligible_agents(
                db, owner_subject=owner_subject, item=item
            )
            if not candidates:
                result["skipped"] += 1
                continue
            agent, score, rationale = candidates[0]
            assignment = AutonomyAssignment(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                room_id=policy.room_id,
                policy_id=policy.id,
                work_item_id=item.id,
                selected_agent_id=agent.id,
                status="proposed",
                score=score,
                rationale={
                    **rationale,
                    "candidate_count": len(candidates),
                    "assignment_mode": policy.assignment_mode,
                },
                policy_generation=policy.generation,
                work_item_version=item.version,
                idempotency_key=f"cycle:{policy.id}:{policy.generation}:{item.id}:{item.version}",
                created_by_subject=actor_subject,
            )
            db.add(assignment)
            emit_event(
                db,
                event_type="gateway.autonomy.assignment.proposed.v1",
                actor_subject=actor_subject,
                action="proposed",
                resource_type="autonomy_assignment",
                resource_id=assignment.id,
                payload={
                    "assignment_id": assignment.id,
                    "policy_id": policy.id,
                    "room_id": policy.room_id,
                    "work_item_id": item.id,
                    "agent_id": agent.id,
                    "score": score,
                    "policy_generation": policy.generation,
                },
                commit=False,
            )
            db.commit()
            db.refresh(assignment)
            if policy.assignment_mode == "automatic":
                assignment = self._apply_assignment_record(
                    db, assignment=assignment, actor_subject=actor_subject
                )
                result["assigned"] += 1
            else:
                result["proposed"] += 1
        return result

    def list_assignments(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        policy_id: str | None = None,
        status: str | None = None,
    ) -> list[AutonomyAssignment]:
        query = db.query(AutonomyAssignment).filter(
            AutonomyAssignment.owner_subject == owner_subject
        )
        if room_id:
            query = query.filter(AutonomyAssignment.room_id == room_id)
        if policy_id:
            query = query.filter(AutonomyAssignment.policy_id == policy_id)
        if status:
            query = query.filter(AutonomyAssignment.status == status)
        return query.order_by(AutonomyAssignment.created_at.desc()).all()

    def apply_assignment(
        self,
        db: Session,
        *,
        owner_subject: str,
        assignment_id: str,
        actor_subject: str,
    ) -> AutonomyAssignment:
        assignment = self._assignment(
            db, owner_subject=owner_subject, assignment_id=assignment_id
        )
        return self._apply_assignment_record(
            db, assignment=assignment, actor_subject=actor_subject
        )

    def _command_envelope(self, command: AgentCommand) -> dict[str, Any]:
        return {
            "command_id": command.id,
            "room_id": command.room_id,
            "issuer_agent_id": command.issuer_agent_id,
            "target_agent_id": command.target_agent_id,
            "kind": command.kind,
            "instruction": command.instruction,
            "structured_payload": dict(command.structured_payload or {}),
            "constraints": dict(command.constraints or {}),
        }

    def create_approval_request(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        data: dict[str, Any],
    ) -> ApprovalRequest:
        policy = self._policy(
            db,
            owner_subject=owner_subject,
            policy_id=_required_text(data.get("policy_id"), field="policy_id", maximum=36),
        )
        self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=policy.room_id,
            policy=policy,
        )
        command = self._command(
            db,
            owner_subject=owner_subject,
            command_id=_required_text(data.get("command_id"), field="command_id", maximum=36),
        )
        executor_agent_id = _required_text(
            data.get("executor_agent_id"), field="executor_agent_id", maximum=36
        )
        executor = self._agent(
            db, owner_subject=owner_subject, agent_id=executor_agent_id
        )
        if command.room_id != policy.room_id or executor.current_room_id != policy.room_id:
            raise HTTPException(status_code=409, detail="Command, executor, and policy room must match")
        if command.target_agent_id != executor.id:
            raise HTTPException(status_code=409, detail="Executor is not the command target")
        if command.status in COMMAND_TERMINAL_STATUSES:
            raise HTTPException(status_code=409, detail="Terminal command cannot be approved")
        action_class = str(data.get("action_class") or "")
        if action_class not in ACTION_CLASSES or action_class not in set(
            policy.allowed_action_classes or []
        ):
            raise HTTPException(status_code=403, detail="Action class is not allowed by policy")
        try:
            execution = resolve_agent_command_execution(
                {
                    "kind": command.kind,
                    "structured_payload": dict(command.structured_payload or {}),
                },
                allowed_tools=list(policy.allowed_tools or []),
                allowed_command_profiles=list(policy.allowed_command_profiles or []),
            )
        except AgentCommandPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(ApprovalRequest)
                .filter(
                    ApprovalRequest.owner_subject == owner_subject,
                    ApprovalRequest.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        envelope = self._command_envelope(command)
        payload_hash = _sha256(envelope)
        rules = dict(policy.approval_rules or DEFAULT_APPROVAL_RULES)
        rule = dict(rules.get(action_class) or DEFAULT_APPROVAL_RULES[action_class])
        ttl_seconds = _bounded_int(
            data.get("ttl_seconds"),
            field="ttl_seconds",
            minimum=30,
            maximum=86400,
            default=self.settings.gateway_autonomy_approval_ttl_seconds,
        )
        now = utcnow()
        request = ApprovalRequest(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=policy.room_id,
            policy_id=policy.id,
            command_id=command.id,
            proposer_agent_id=command.issuer_agent_id,
            executor_agent_id=executor.id,
            action_kind=_required_text(
                data.get("action_kind") or "run_tool",
                field="action_kind",
                maximum=120,
            ),
            action_class=action_class,
            tool=execution.tool,
            command_profile=execution.command_profile,
            payload_hash=payload_hash,
            payload_summary={
                "command_id": command.id,
                "tool": execution.tool,
                "command_profile": execution.command_profile,
                "argument_keys": sorted(execution.arguments),
                "constraint_keys": sorted(dict(command.constraints or {})),
            },
            quorum_required=_bounded_int(
                rule.get("quorum", 1),
                field="quorum_required",
                minimum=0,
                maximum=20,
            ),
            require_admin_approval=bool(rule.get("require_admin", False)),
            disallow_proposer_vote=bool(rule.get("disallow_proposer", True)),
            status="pending",
            policy_generation=policy.generation,
            version=1,
            idempotency_key=idempotency_key,
            created_by_subject=actor_subject,
            expires_at=now + timedelta(seconds=ttl_seconds),
            created_at=now,
            updated_at=now,
        )
        if request.quorum_required == 0 and not request.require_admin_approval:
            request.status = "approved"
            request.approved_at = now
            command.approved_by_subject = f"approval:{request.id}"
            command.updated_at = now
        db.add(request)
        try:
            emit_event(
                db,
                event_type="gateway.autonomy.approval.requested.v1",
                actor_subject=actor_subject,
                action="requested",
                resource_type="approval_request",
                resource_id=request.id,
                payload={
                    "approval_request_id": request.id,
                    "policy_id": policy.id,
                    "room_id": policy.room_id,
                    "command_id": command.id,
                    "executor_agent_id": executor.id,
                    "action_class": action_class,
                    "tool": execution.tool,
                    "quorum_required": request.quorum_required,
                    "require_admin_approval": request.require_admin_approval,
                    "status": request.status,
                    "policy_generation": request.policy_generation,
                    "payload_hash": payload_hash,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(ApprovalRequest)
                    .filter(
                        ApprovalRequest.owner_subject == owner_subject,
                        ApprovalRequest.idempotency_key == idempotency_key,
                    )
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(status_code=409, detail="Approval request conflict") from exc
        db.refresh(request)
        return request

    def _can_vote(self, db: Session, *, request: ApprovalRequest, user: User) -> bool:
        return approval_user_can_vote(db, request=request, user=user)

    def approval_visibility_query(self, db: Session, *, user: User):
        roles = set(user.roles or [])
        if "gateway-admin" in roles:
            return db.query(ApprovalRequest)
        predicates = [ApprovalRequest.owner_subject == user.subject]
        grants = (
            db.query(AccessGrant)
            .filter(
                AccessGrant.grantee_subject == user.subject,
                AccessGrant.resource_type == "autonomy_approval",
                AccessGrant.status == "active",
            )
            .all()
        )
        for grant in grants:
            if "approve" not in set(grant.scopes or []):
                continue
            resource_id = str(grant.resource_id or "").strip()
            if not resource_id:
                continue
            predicates.append(
                and_(
                    ApprovalRequest.owner_subject == grant.owner_subject,
                    or_(
                        ApprovalRequest.id == resource_id,
                        ApprovalRequest.policy_id == resource_id,
                        ApprovalRequest.room_id == resource_id,
                    ),
                )
            )
        return db.query(ApprovalRequest).filter(or_(*predicates))

    def approval_review_projection(
        self,
        db: Session,
        *,
        request: ApprovalRequest,
        user: User,
        votes: list[ApprovalVote] | None = None,
    ) -> dict[str, Any]:
        if votes is None:
            votes = (
                db.query(ApprovalVote)
                .filter(ApprovalVote.request_id == request.id)
                .order_by(ApprovalVote.created_at, ApprovalVote.id)
                .all()
            )
        preparation = (
            db.query(McpActionPreparation)
            .filter(McpActionPreparation.approval_request_id == request.id)
            .one_or_none()
        )
        target: dict[str, Any] = {
            "kind": "gateway",
            "review_surface": "gateway",
        }
        if preparation is not None:
            server = db.get(McpServer, preparation.server_id)
            tool = db.get(McpTool, preparation.tool_id)
            affine_config = AffineApprovalProjectionConfig.from_settings(get_settings())
            is_affine = is_affine_research_server(server, config=affine_config)
            target = {
                "kind": "mcp_federation",
                "provider": "affine" if is_affine else "mcp",
                "review_surface": "affine" if is_affine else "gateway",
                "preparation_id": preparation.id,
                "server_id": preparation.server_id,
                "tool_id": preparation.tool_id,
                "revision_id": preparation.revision_id,
                "server_name": server.display_name if server is not None else None,
                "tool_name": tool.upstream_name if tool is not None else None,
            }
        elif request.integration_id:
            target = {
                "kind": "integration",
                "review_surface": "gateway",
                "integration_id": request.integration_id,
            }

        approvals = [vote for vote in votes if vote.decision == "approve"]
        rejects = [vote for vote in votes if vote.decision == "reject"]
        admin_approvals = [
            vote
            for vote in approvals
            if "gateway-admin" in set(vote.voter_roles or [])
        ]
        current_vote = next(
            (vote for vote in votes if vote.voter_subject == user.subject),
            None,
        )
        authorized = self._can_vote(db, request=request, user=user)
        expires_at = _aware(request.expires_at)
        expired = bool(expires_at is not None and expires_at <= utcnow())
        quorum_met = len(approvals) >= int(request.quorum_required or 0) and (
            not request.require_admin_approval or bool(admin_approvals)
        )
        reason: str | None = None
        can_vote = False
        if target["review_surface"] == "affine":
            reason = "AFFiNE-targeted approvals are reviewed in AFFiNE Notifications"
        elif not authorized:
            reason = "Approval vote is outside granted scope"
        elif request.status != "pending" or expired:
            reason = "Approval request is not pending"
        elif request.disallow_proposer_vote and user.subject == request.created_by_subject:
            reason = "Proposer cannot vote on this request"
        elif current_vote is not None:
            reason = "Current reviewer already voted"
        else:
            can_vote = True

        return {
            "surface": target["review_surface"],
            "authorized": authorized,
            "can_vote": can_vote,
            "reason": reason,
            "current_voter_decision": current_vote.decision if current_vote else None,
            "approve_count": len(approvals),
            "reject_count": len(rejects),
            "quorum_required": int(request.quorum_required or 0),
            "quorum_met": quorum_met,
            "admin_required": bool(request.require_admin_approval),
            "admin_approve_count": len(admin_approvals),
            "expired": expired,
            "target": target,
        }

    def _expire_approval(self, request: ApprovalRequest) -> None:
        if request.status == "pending" and _aware(request.expires_at) <= utcnow():
            request.status = "expired"
            request.updated_at = utcnow()
            request.version = int(request.version or 0) + 1

    def list_approval_requests(
        self,
        db: Session,
        *,
        owner_subject: str | None = None,
        user: User | None = None,
        room_id: str | None = None,
        status: str | None = None,
    ) -> list[ApprovalRequest]:
        if user is not None:
            query = self.approval_visibility_query(db, user=user)
        elif owner_subject is not None:
            query = db.query(ApprovalRequest).filter(
                ApprovalRequest.owner_subject == owner_subject
            )
        else:
            raise ValueError("owner_subject or user is required")
        if room_id:
            query = query.filter(ApprovalRequest.room_id == room_id)
        if status:
            query = query.filter(ApprovalRequest.status == status)
        rows = query.order_by(ApprovalRequest.created_at.desc()).all()
        changed_rows: list[ApprovalRequest] = []
        for row in rows:
            before = row.status
            self._expire_approval(row)
            if before != row.status:
                changed_rows.append(row)
        if changed_rows:
            for row in changed_rows:
                emit_affine_approval_projection(
                    db,
                    request=row,
                    projection_kind="approval_updated",
                    actor_subject="system:autonomy-worker",
                )
            db.commit()
        return rows

    def cast_vote(
        self,
        db: Session,
        *,
        request_id: str,
        user: User,
        decision: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        request = self._approval(db, request_id=request_id)
        if not self._can_vote(db, request=request, user=user):
            raise HTTPException(status_code=403, detail="Approval vote is outside granted scope")
        self._expire_approval(request)
        if request.status != "pending":
            raise HTTPException(status_code=409, detail="Approval request is not pending")
        if decision not in {"approve", "reject"}:
            raise HTTPException(status_code=400, detail="Unsupported approval decision")
        if request.disallow_proposer_vote and user.subject == request.created_by_subject:
            raise HTTPException(status_code=403, detail="Proposer cannot vote on this request")
        existing = (
            db.query(ApprovalVote)
            .filter(
                ApprovalVote.request_id == request.id,
                ApprovalVote.voter_subject == user.subject,
            )
            .one_or_none()
        )
        if existing is not None:
            if existing.decision == decision:
                return request
            raise HTTPException(status_code=409, detail="Voter already recorded a different decision")
        vote = ApprovalVote(
            id=str(uuid.uuid4()),
            owner_subject=request.owner_subject,
            request_id=request.id,
            voter_subject=user.subject,
            voter_roles=sorted(set(user.roles or [])),
            decision=decision,
            reason=_optional_text(reason, maximum=10000),
        )
        db.add(vote)
        db.flush()
        votes = (
            db.query(ApprovalVote)
            .filter(ApprovalVote.request_id == request.id)
            .order_by(ApprovalVote.created_at, ApprovalVote.id)
            .all()
        )
        now = utcnow()
        if any(item.decision == "reject" for item in votes):
            request.status = "rejected"
            request.rejected_at = now
        else:
            approvals = [item for item in votes if item.decision == "approve"]
            admin_present = any(
                "gateway-admin" in set(item.voter_roles or []) for item in approvals
            )
            if len(approvals) >= request.quorum_required and (
                not request.require_admin_approval or admin_present
            ):
                request.status = "approved"
                request.approved_at = now
                if request.command_id:
                    command = self._command(
                        db,
                        owner_subject=request.owner_subject,
                        command_id=request.command_id,
                    )
                    command.approved_by_subject = f"approval:{request.id}"
                    command.updated_at = now
        request.version = int(request.version or 0) + 1
        request.updated_at = now
        emit_event(
            db,
            event_type="gateway.autonomy.approval.voted.v1",
            actor_subject=user.subject,
            action=decision,
            resource_type="approval_request",
            resource_id=request.id,
            payload={
                "approval_request_id": request.id,
                "decision": decision,
                "voter_subject": user.subject,
                "status": request.status,
                "approve_count": sum(
                    item.decision == "approve" for item in votes
                ),
                "quorum_required": request.quorum_required,
            },
            status="warning" if decision == "reject" else "success",
            commit=False,
        )
        emit_affine_approval_projection(
            db,
            request=request,
            projection_kind="approval_updated",
            actor_subject=user.subject,
            votes=votes,
        )
        db.commit()
        db.refresh(request)
        return request

    def _verify_request_integrity(
        self, db: Session, *, request: ApprovalRequest
    ) -> AgentCommand:
        policy = self._policy(
            db, owner_subject=request.owner_subject, policy_id=request.policy_id
        )
        if policy.generation != request.policy_generation or policy.status != "active":
            raise HTTPException(status_code=409, detail="Approval policy generation is stale")
        if request.command_id is None:
            raise HTTPException(status_code=409, detail="Approval request has no command")
        command = self._command(
            db, owner_subject=request.owner_subject, command_id=request.command_id
        )
        if _sha256(self._command_envelope(command)) != request.payload_hash:
            raise HTTPException(status_code=409, detail="Approved command payload changed")
        if command.target_agent_id != request.executor_agent_id:
            raise HTTPException(status_code=409, detail="Approved executor changed")
        return command

    def issue_permit(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        request_id: str,
        ttl_seconds: int | None = None,
    ) -> ExecutionPermit:
        request = self._approval(db, request_id=request_id)
        if request.owner_subject != owner_subject:
            raise HTTPException(status_code=404, detail="Approval request not found")
        self._expire_approval(request)
        if request.status != "approved":
            raise HTTPException(status_code=409, detail="Approval request is not approved")
        command = self._verify_request_integrity(db, request=request)
        policy = self._policy(
            db, owner_subject=owner_subject, policy_id=request.policy_id
        )
        snapshot = self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=request.room_id,
            policy=policy,
        )
        existing = (
            db.query(ExecutionPermit)
            .filter(ExecutionPermit.approval_request_id == request.id)
            .one_or_none()
        )
        if existing is not None:
            self._expire_permit(existing)
            if existing.status in {"active", "claimed"}:
                return existing
            raise HTTPException(
                status_code=409,
                detail="Terminal execution permit requires a new approval request",
            )
        requested_ttl = _bounded_int(
            ttl_seconds,
            field="ttl_seconds",
            minimum=30,
            maximum=3600,
            default=self.settings.gateway_autonomy_permit_ttl_seconds,
        )
        now = utcnow()
        expires_at = min(
            _aware(request.expires_at) or now,
            now + timedelta(seconds=requested_ttl),
        )
        if expires_at <= now:
            raise HTTPException(status_code=409, detail="Approval request has expired")
        permit = ExecutionPermit(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            approval_request_id=request.id,
            policy_id=policy.id,
            command_id=command.id,
            executor_agent_id=request.executor_agent_id,
            action_class=request.action_class,
            tool=request.tool,
            command_profile=request.command_profile,
            payload_hash=request.payload_hash,
            status="active",
            policy_generation=policy.generation,
            control_snapshot=snapshot,
            fencing_token=1,
            max_uses=1,
            use_count=0,
            issued_by_subject=actor_subject,
            issued_at=now,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
        )
        db.add(permit)
        emit_event(
            db,
            event_type="gateway.autonomy.permit.issued.v1",
            actor_subject=actor_subject,
            action="issued",
            resource_type="execution_permit",
            resource_id=permit.id,
            payload={
                "permit_id": permit.id,
                "approval_request_id": request.id,
                "policy_id": policy.id,
                "command_id": command.id,
                "executor_agent_id": permit.executor_agent_id,
                "action_class": permit.action_class,
                "tool": permit.tool,
                "payload_hash": permit.payload_hash,
                "policy_generation": permit.policy_generation,
                "fencing_token": permit.fencing_token,
                "expires_at": permit.expires_at.isoformat(),
            },
            commit=False,
        )
        db.commit()
        db.refresh(permit)
        return permit

    def _expire_permit(self, permit: ExecutionPermit) -> None:
        if permit.status in {"active", "claimed"} and _aware(permit.expires_at) <= utcnow():
            permit.status = "expired"
            permit.updated_at = utcnow()

    def claim_permit(
        self,
        db: Session,
        *,
        owner_subject: str,
        permit_id: str,
        executor_agent_id: str,
    ) -> ExecutionPermit:
        permit = self._permit(db, owner_subject=owner_subject, permit_id=permit_id)
        self._expire_permit(permit)
        if permit.status == "claimed" and permit.executor_agent_id == executor_agent_id:
            return permit
        if permit.status != "active":
            raise HTTPException(status_code=409, detail="Execution permit is not active")
        if permit.executor_agent_id != executor_agent_id:
            raise HTTPException(status_code=403, detail="Execution permit belongs to another agent")
        request = self._approval(db, request_id=permit.approval_request_id)
        command = self._verify_request_integrity(db, request=request)
        policy = self._policy(
            db, owner_subject=owner_subject, policy_id=permit.policy_id
        )
        snapshot = self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=request.room_id,
            policy=policy,
        )
        if policy.generation != permit.policy_generation:
            raise HTTPException(status_code=409, detail="Execution permit policy generation is stale")
        if snapshot.get("generations") != dict(permit.control_snapshot or {}).get(
            "generations"
        ):
            raise HTTPException(status_code=409, detail="Execution permit control generation is stale")
        if command.status != "accepted":
            raise HTTPException(status_code=409, detail="Command must be accepted before permit claim")
        now = utcnow()
        changed = (
            db.query(ExecutionPermit)
            .filter(
                ExecutionPermit.id == permit.id,
                ExecutionPermit.owner_subject == owner_subject,
                ExecutionPermit.status == "active",
                ExecutionPermit.fencing_token == permit.fencing_token,
            )
            .update(
                {
                    ExecutionPermit.status: "claimed",
                    ExecutionPermit.claimed_at: now,
                    ExecutionPermit.use_count: ExecutionPermit.use_count + 1,
                    ExecutionPermit.updated_at: now,
                },
                synchronize_session=False,
            )
        )
        if changed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Execution permit claim conflict")
        db.flush()
        db.expire_all()
        claimed = self._permit(db, owner_subject=owner_subject, permit_id=permit.id)
        emit_event(
            db,
            event_type="gateway.autonomy.permit.claimed.v1",
            actor_subject=owner_subject,
            action="claimed",
            resource_type="execution_permit",
            resource_id=claimed.id,
            payload={
                "permit_id": claimed.id,
                "approval_request_id": claimed.approval_request_id,
                "command_id": claimed.command_id,
                "executor_agent_id": claimed.executor_agent_id,
                "fencing_token": claimed.fencing_token,
                "payload_hash": claimed.payload_hash,
            },
            commit=False,
        )
        db.commit()
        db.refresh(claimed)
        return claimed

    def record_receipt(
        self,
        db: Session,
        *,
        owner_subject: str,
        data: dict[str, Any],
    ) -> ActionReceipt:
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(ActionReceipt)
                .filter(
                    ActionReceipt.owner_subject == owner_subject,
                    ActionReceipt.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        permit = self._permit(
            db,
            owner_subject=owner_subject,
            permit_id=_required_text(data.get("permit_id"), field="permit_id", maximum=36),
        )
        executor_agent_id = _required_text(
            data.get("executor_agent_id"), field="executor_agent_id", maximum=36
        )
        if permit.executor_agent_id != executor_agent_id:
            raise HTTPException(status_code=403, detail="Receipt executor does not match permit")
        if int(permit.fencing_token) != int(data.get("fencing_token") or 0):
            raise HTTPException(status_code=409, detail="Receipt fencing token is stale")
        if permit.status not in {"claimed", "revoked"} or permit.claimed_at is None:
            raise HTTPException(status_code=409, detail="Permit was not claimed for execution")
        status = str(data.get("status") or "")
        if status not in RECEIPT_STATUSES:
            raise HTTPException(status_code=400, detail="Unsupported receipt status")
        result_summary = dict(
            _safe_structured(
                dict(data.get("result_summary") or {}), field="action receipt result"
            )
        )
        external_references = list(
            _safe_structured(
                list(data.get("external_references") or []),
                field="action receipt external references",
            )
        )
        started_at = data.get("started_at")
        completed_at = data.get("completed_at")
        if not isinstance(started_at, datetime) or not isinstance(completed_at, datetime):
            raise HTTPException(status_code=400, detail="Receipt timestamps are required")
        if _aware(completed_at) < _aware(started_at):
            raise HTTPException(status_code=400, detail="Receipt completion precedes start")
        output_hash = _sha256(
            {
                "status": status,
                "result_summary": result_summary,
                "error": data.get("error"),
                "external_references": external_references,
            }
        )
        receipt = ActionReceipt(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            permit_id=permit.id,
            approval_request_id=permit.approval_request_id,
            command_id=permit.command_id,
            executor_agent_id=executor_agent_id,
            action_class=permit.action_class,
            tool=permit.tool,
            command_profile=permit.command_profile,
            status=status,
            input_hash=permit.payload_hash,
            output_hash=output_hash,
            result_summary=result_summary,
            error=_optional_text(data.get("error"), maximum=10000),
            external_references=external_references,
            idempotency_key=idempotency_key,
            started_at=started_at,
            completed_at=completed_at,
        )
        db.add(receipt)
        permit.status = "consumed"
        permit.consumed_at = utcnow()
        permit.updated_at = permit.consumed_at
        try:
            emit_event(
                db,
                event_type="gateway.autonomy.action.receipt.recorded.v1",
                actor_subject=owner_subject,
                action=status,
                resource_type="action_receipt",
                resource_id=receipt.id,
                payload={
                    "receipt_id": receipt.id,
                    "permit_id": permit.id,
                    "approval_request_id": permit.approval_request_id,
                    "command_id": permit.command_id,
                    "executor_agent_id": executor_agent_id,
                    "action_class": permit.action_class,
                    "tool": permit.tool,
                    "status": status,
                    "input_hash": receipt.input_hash,
                    "output_hash": receipt.output_hash,
                    "fencing_token": permit.fencing_token,
                },
                status="success" if status == "succeeded" else "warning",
                commit=False,
            )
            request = db.get(ApprovalRequest, permit.approval_request_id)
            if request is not None:
                emit_affine_approval_projection(
                    db,
                    request=request,
                    projection_kind="action_result",
                    actor_subject=owner_subject,
                    receipt=receipt,
                )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            existing = (
                db.query(ActionReceipt)
                .filter(ActionReceipt.permit_id == permit.id)
                .one_or_none()
            )
            if existing is not None:
                return existing
            raise HTTPException(status_code=409, detail="Action receipt conflict") from exc
        db.refresh(receipt)
        return receipt

    def list_permits(
        self,
        db: Session,
        *,
        owner_subject: str,
        status: str | None = None,
    ) -> list[ExecutionPermit]:
        query = db.query(ExecutionPermit).filter(
            ExecutionPermit.owner_subject == owner_subject
        )
        if status:
            query = query.filter(ExecutionPermit.status == status)
        rows = query.order_by(ExecutionPermit.created_at.desc()).all()
        changed = False
        for permit in rows:
            before = permit.status
            self._expire_permit(permit)
            changed = changed or before != permit.status
        if changed:
            db.commit()
        return rows

    def list_receipts(
        self,
        db: Session,
        *,
        owner_subject: str,
        command_id: str | None = None,
    ) -> list[ActionReceipt]:
        query = db.query(ActionReceipt).filter(
            ActionReceipt.owner_subject == owner_subject
        )
        if command_id:
            query = query.filter(ActionReceipt.command_id == command_id)
        return query.order_by(ActionReceipt.created_at.desc()).all()

    def create_recovery_loop(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        data: dict[str, Any],
    ) -> RecoveryLoop:
        policy = self._policy(
            db,
            owner_subject=owner_subject,
            policy_id=_required_text(data.get("policy_id"), field="policy_id", maximum=36),
        )
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        if policy.room_id != room_id:
            raise HTTPException(status_code=409, detail="Recovery policy room mismatch")
        self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=room_id,
            policy=policy,
        )
        target_agent = self._agent(
            db,
            owner_subject=owner_subject,
            agent_id=_required_text(
                data.get("target_agent_id"), field="target_agent_id", maximum=36
            ),
        )
        if target_agent.current_room_id != room_id:
            raise HTTPException(status_code=409, detail="Recovery target is not in room")
        source_type = str(data.get("source_type") or "")
        source_id = _required_text(data.get("source_id"), field="source_id", maximum=160)
        if source_type == "command":
            source = self._command(db, owner_subject=owner_subject, command_id=source_id)
            if source.room_id != room_id:
                raise HTTPException(status_code=409, detail="Recovery command room mismatch")
        elif source_type == "work_item":
            source = self._work_item(
                db, owner_subject=owner_subject, work_item_id=source_id
            )
            if source.room_id != room_id:
                raise HTTPException(status_code=409, detail="Recovery work item room mismatch")
        elif source_type == "action_receipt":
            source = (
                db.query(ActionReceipt)
                .filter(
                    ActionReceipt.id == source_id,
                    ActionReceipt.owner_subject == owner_subject,
                )
                .one_or_none()
            )
            if source is None:
                raise HTTPException(status_code=404, detail="Recovery receipt not found")
        else:
            raise HTTPException(status_code=400, detail="Unsupported recovery source type")
        strategy = dict(
            _safe_structured(dict(data.get("strategy") or {}), field="recovery strategy")
        )
        command_envelope = {
            "kind": str(strategy.get("kind") or "instruction"),
            "instruction": strategy.get("instruction"),
            "structured_payload": dict(strategy.get("structured_payload") or {}),
        }
        try:
            validate_agent_command_for_delivery(command_envelope)
        except AgentCommandPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(RecoveryLoop)
                .filter(
                    RecoveryLoop.owner_subject == owner_subject,
                    RecoveryLoop.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        recovery_policy = dict(policy.recovery_policy or DEFAULT_RECOVERY_POLICY)
        max_attempts = _bounded_int(
            data.get("max_attempts"),
            field="max_attempts",
            minimum=1,
            maximum=int(recovery_policy.get("max_attempts", 3)),
            default=int(recovery_policy.get("max_attempts", 3)),
        )
        base_backoff = _bounded_int(
            data.get("base_backoff_seconds"),
            field="base_backoff_seconds",
            minimum=1,
            maximum=int(recovery_policy.get("max_backoff_seconds", 900)),
            default=int(recovery_policy.get("base_backoff_seconds", 30)),
        )
        now = utcnow()
        loop = RecoveryLoop(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            policy_id=policy.id,
            source_type=source_type,
            source_id=source_id,
            target_agent_id=target_agent.id,
            strategy=strategy,
            status="planned",
            attempt_count=0,
            max_attempts=max_attempts,
            base_backoff_seconds=base_backoff,
            next_attempt_at=now,
            policy_generation=policy.generation,
            generation=1,
            idempotency_key=idempotency_key,
            created_by_subject=actor_subject,
            created_at=now,
            updated_at=now,
        )
        db.add(loop)
        try:
            emit_event(
                db,
                event_type="gateway.autonomy.recovery.created.v1",
                actor_subject=actor_subject,
                action="created",
                resource_type="recovery_loop",
                resource_id=loop.id,
                payload={
                    "recovery_loop_id": loop.id,
                    "policy_id": policy.id,
                    "room_id": room_id,
                    "source_type": source_type,
                    "source_id": source_id,
                    "target_agent_id": target_agent.id,
                    "max_attempts": loop.max_attempts,
                    "policy_generation": loop.policy_generation,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(RecoveryLoop)
                    .filter(
                        RecoveryLoop.owner_subject == owner_subject,
                        RecoveryLoop.idempotency_key == idempotency_key,
                    )
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(status_code=409, detail="Recovery loop conflict") from exc
        db.refresh(loop)
        return loop

    def run_recovery_cycle(
        self,
        db: Session,
        *,
        owner_subject: str,
        policy_id: str,
        actor_subject: str = "system:autonomy-worker",
        limit: int = 10,
    ) -> dict[str, Any]:
        policy = self._policy(db, owner_subject=owner_subject, policy_id=policy_id)
        self.assert_enabled(
            db,
            owner_subject=owner_subject,
            room_id=policy.room_id,
            policy=policy,
        )
        if not policy.coordinator_agent_id:
            return {"considered": 0, "issued": 0, "paused": 0}
        coordinator = self._agent(
            db,
            owner_subject=owner_subject,
            agent_id=policy.coordinator_agent_id,
        )
        if coordinator.current_room_id != policy.room_id:
            return {"considered": 0, "issued": 0, "paused": 0}
        now = utcnow()
        loops = (
            db.query(RecoveryLoop)
            .filter(
                RecoveryLoop.owner_subject == owner_subject,
                RecoveryLoop.policy_id == policy.id,
                RecoveryLoop.status == "planned",
                RecoveryLoop.next_attempt_at <= now,
            )
            .order_by(RecoveryLoop.next_attempt_at, RecoveryLoop.created_at)
            .limit(max(1, min(int(limit), 100)))
            .all()
        )
        result = {"considered": len(loops), "issued": 0, "paused": 0}
        for loop in loops:
            if loop.policy_generation != policy.generation:
                loop.status = "paused"
                loop.last_error = "policy generation changed"
                loop.generation = int(loop.generation or 0) + 1
                loop.updated_at = now
                db.commit()
                result["paused"] += 1
                continue
            if loop.attempt_count >= loop.max_attempts:
                loop.status = "exhausted"
                loop.completed_at = now
                loop.updated_at = now
                db.commit()
                continue
            strategy = dict(loop.strategy or {})
            attempt = int(loop.attempt_count or 0) + 1
            command = agent_collaboration_service.issue_command(
                db,
                owner_subject=owner_subject,
                data={
                    "room_id": loop.room_id,
                    "issuer_agent_id": coordinator.id,
                    "target_agent_id": loop.target_agent_id,
                    "kind": str(strategy.get("kind") or "instruction"),
                    "instruction": str(strategy.get("instruction") or ""),
                    "structured_payload": dict(
                        strategy.get("structured_payload") or {}
                    ),
                    "constraints": {
                        **dict(strategy.get("constraints") or {}),
                        "recovery_loop_id": loop.id,
                        "recovery_attempt": attempt,
                        "source_type": loop.source_type,
                        "source_id": loop.source_id,
                    },
                    "priority": int(strategy.get("priority", 80)),
                    "requires_approval": bool(
                        strategy.get(
                            "requires_approval",
                            str(strategy.get("kind") or "instruction") == "run_tool",
                        )
                    ),
                    "correlation_id": loop.id,
                    "causation_id": loop.source_id,
                    "idempotency_key": f"recovery:{loop.id}:{attempt}",
                },
            )
            loop.attempt_count = attempt
            loop.last_command_id = command.id
            loop.status = "waiting"
            loop.updated_at = utcnow()
            emit_event(
                db,
                event_type="gateway.autonomy.recovery.attempted.v1",
                actor_subject=actor_subject,
                action="attempted",
                resource_type="recovery_loop",
                resource_id=loop.id,
                payload={
                    "recovery_loop_id": loop.id,
                    "policy_id": policy.id,
                    "room_id": loop.room_id,
                    "attempt": attempt,
                    "max_attempts": loop.max_attempts,
                    "command_id": command.id,
                    "target_agent_id": loop.target_agent_id,
                },
                commit=False,
            )
            db.commit()
            result["issued"] += 1
        return result

    def record_recovery_outcome(
        self,
        db: Session,
        *,
        owner_subject: str,
        loop_id: str,
        status: str,
        command_id: str | None = None,
        error: str | None = None,
    ) -> RecoveryLoop:
        loop = self._recovery(db, owner_subject=owner_subject, loop_id=loop_id)
        if loop.status in RECOVERY_TERMINAL:
            return loop
        if loop.status not in {"waiting", "running", "paused"}:
            raise HTTPException(status_code=409, detail="Recovery loop has no active attempt")
        if command_id and loop.last_command_id != command_id:
            raise HTTPException(status_code=409, detail="Recovery command does not match latest attempt")
        now = utcnow()
        if status == "succeeded":
            loop.status = "succeeded"
            loop.completed_at = now
            loop.last_error = None
        elif status == "cancelled":
            loop.status = "cancelled"
            loop.completed_at = now
            loop.last_error = _optional_text(error, maximum=10000)
        elif status == "failed":
            loop.last_error = _optional_text(error, maximum=10000)
            if loop.attempt_count >= loop.max_attempts:
                loop.status = "exhausted"
                loop.completed_at = now
            else:
                policy = self._policy(
                    db, owner_subject=owner_subject, policy_id=loop.policy_id
                )
                recovery_policy = dict(policy.recovery_policy or DEFAULT_RECOVERY_POLICY)
                delay = min(
                    int(recovery_policy.get("max_backoff_seconds", 900)),
                    int(loop.base_backoff_seconds)
                    * (2 ** max(0, int(loop.attempt_count) - 1)),
                )
                loop.status = "planned"
                loop.next_attempt_at = now + timedelta(seconds=delay)
        else:
            raise HTTPException(status_code=400, detail="Unsupported recovery outcome")
        loop.generation = int(loop.generation or 0) + 1
        loop.updated_at = now
        emit_event(
            db,
            event_type="gateway.autonomy.recovery.completed.v1",
            actor_subject=owner_subject,
            action=status,
            resource_type="recovery_loop",
            resource_id=loop.id,
            payload={
                "recovery_loop_id": loop.id,
                "policy_id": loop.policy_id,
                "room_id": loop.room_id,
                "attempt_count": loop.attempt_count,
                "max_attempts": loop.max_attempts,
                "status": loop.status,
                "command_id": loop.last_command_id,
            },
            status="success" if status == "succeeded" else "warning",
            commit=False,
        )
        db.commit()
        db.refresh(loop)
        return loop

    def list_recovery_loops(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        status: str | None = None,
    ) -> list[RecoveryLoop]:
        query = db.query(RecoveryLoop).filter(
            RecoveryLoop.owner_subject == owner_subject
        )
        if room_id:
            query = query.filter(RecoveryLoop.room_id == room_id)
        if status:
            query = query.filter(RecoveryLoop.status == status)
        return query.order_by(RecoveryLoop.created_at.desc()).all()

    def apply_override(
        self,
        db: Session,
        *,
        owner_subject: str,
        actor_subject: str,
        actor_roles: list[str],
        data: dict[str, Any],
    ) -> AutonomyOverride:
        if "gateway-admin" not in set(actor_roles or []):
            raise HTTPException(status_code=403, detail="Operator override requires gateway-admin")
        action = str(data.get("action") or "")
        reason = _required_text(data.get("reason"), field="reason", maximum=10000)
        evidence = dict(
            _safe_structured(dict(data.get("evidence") or {}), field="override evidence")
        )
        scope_type = "tenant"
        scope_id = ""
        previous_state: str | None = None
        new_state: str | None = None
        if action == "force_assign":
            work_item_id = _required_text(
                data.get("work_item_id"), field="work_item_id", maximum=36
            )
            agent_id = _required_text(data.get("agent_id"), field="agent_id", maximum=36)
            item = self._work_item(
                db, owner_subject=owner_subject, work_item_id=work_item_id
            )
            policy_id = _optional_text(data.get("policy_id"), maximum=36)
            if policy_id:
                policy = self._policy(
                    db, owner_subject=owner_subject, policy_id=policy_id
                )
            else:
                policy = (
                    db.query(AutonomyPolicy)
                    .filter(
                        AutonomyPolicy.owner_subject == owner_subject,
                        AutonomyPolicy.room_id == item.room_id,
                        AutonomyPolicy.status == "active",
                    )
                    .order_by(AutonomyPolicy.created_at)
                    .first()
                )
                if policy is None:
                    raise HTTPException(status_code=404, detail="No active autonomy policy for work item")
            self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
            assignment = AutonomyAssignment(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                room_id=item.room_id,
                policy_id=policy.id,
                work_item_id=item.id,
                selected_agent_id=agent_id,
                status="proposed",
                score=1_000_000,
                rationale={"forced": True, "reason": reason},
                policy_generation=policy.generation,
                work_item_version=item.version,
                idempotency_key=f"override:{uuid.uuid4()}",
                created_by_subject=actor_subject,
            )
            db.add(assignment)
            db.flush()
            self._apply_assignment_record(
                db,
                assignment=assignment,
                actor_subject=actor_subject,
                commit=False,
            )
            scope_type = "room"
            scope_id = item.room_id
            evidence.update(
                {
                    "assignment_id": assignment.id,
                    "work_item_id": item.id,
                    "agent_id": agent_id,
                    "policy_id": policy.id,
                }
            )
        elif action == "revoke_assignment":
            assignment = self._assignment(
                db,
                owner_subject=owner_subject,
                assignment_id=_required_text(
                    data.get("assignment_id"), field="assignment_id", maximum=36
                ),
            )
            previous_state = assignment.status
            if assignment.status == "assigned":
                item = self._work_item(
                    db,
                    owner_subject=owner_subject,
                    work_item_id=assignment.work_item_id,
                )
                agent = self._agent(
                    db,
                    owner_subject=owner_subject,
                    agent_id=assignment.selected_agent_id,
                )
                if item.assigned_agent_id == agent.id and item.status == "in_progress":
                    item.status = "open"
                    item.assigned_agent_id = None
                    item.version = int(item.version or 0) + 1
                    item.updated_at = utcnow()
                    if agent.current_work_item_id == item.id:
                        agent.current_work_item_id = None
                        agent.status = "active"
                        agent.updated_at = utcnow()
            assignment.status = "revoked"
            assignment.revoked_at = utcnow()
            assignment.updated_at = assignment.revoked_at
            new_state = "revoked"
            scope_type = "room"
            scope_id = assignment.room_id
            evidence.update({"assignment_id": assignment.id})
        elif action == "revoke_permits":
            room_id = _optional_text(data.get("room_id"), maximum=36)
            policy_id = _optional_text(data.get("policy_id"), maximum=36)
            count = self._revoke_permits(
                db,
                owner_subject=owner_subject,
                reason=reason,
                room_id=room_id,
                policy_id=policy_id,
            )
            evidence["revoked_permits"] = count
            if policy_id:
                scope_type, scope_id = "policy", policy_id
            elif room_id:
                scope_type, scope_id = "room", room_id
        elif action == "cancel_recoveries":
            room_id = _optional_text(data.get("room_id"), maximum=36)
            policy_id = _optional_text(data.get("policy_id"), maximum=36)
            count = self._pause_or_cancel_recoveries(
                db,
                owner_subject=owner_subject,
                state="killed",
                room_id=room_id,
                policy_id=policy_id,
            )
            evidence["cancelled_recoveries"] = count
            if policy_id:
                scope_type, scope_id = "policy", policy_id
            elif room_id:
                scope_type, scope_id = "room", room_id
        else:
            raise HTTPException(status_code=400, detail="Unsupported operator override")
        record = AutonomyOverride(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            scope_type=scope_type,
            scope_id=scope_id,
            action=action,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
            actor_subject=actor_subject,
            evidence=evidence,
        )
        db.add(record)
        emit_event(
            db,
            event_type="gateway.autonomy.override.applied.v1",
            actor_subject=actor_subject,
            action=action,
            resource_type="autonomy_override",
            resource_id=record.id,
            payload={
                "override_id": record.id,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "action": action,
                "evidence": evidence,
            },
            status="warning",
            commit=False,
        )
        db.commit()
        db.refresh(record)
        return record

    def list_overrides(
        self, db: Session, *, owner_subject: str, limit: int = 100
    ) -> list[AutonomyOverride]:
        return (
            db.query(AutonomyOverride)
            .filter(AutonomyOverride.owner_subject == owner_subject)
            .order_by(AutonomyOverride.created_at.desc())
            .limit(max(1, min(int(limit), 500)))
            .all()
        )

    def metrics(self, db: Session, *, owner_subject: str) -> dict[str, Any]:
        policy_counts = {
            status: db.query(AutonomyPolicy)
            .filter(
                AutonomyPolicy.owner_subject == owner_subject,
                AutonomyPolicy.status == status,
            )
            .count()
            for status in sorted(POLICY_STATUSES)
        }
        approval_counts = {
            status: db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.owner_subject == owner_subject,
                ApprovalRequest.status == status,
            )
            .count()
            for status in sorted(APPROVAL_TERMINAL | {"pending"})
        }
        permit_counts = {
            status: db.query(ExecutionPermit)
            .filter(
                ExecutionPermit.owner_subject == owner_subject,
                ExecutionPermit.status == status,
            )
            .count()
            for status in sorted(PERMIT_TERMINAL | {"active", "claimed"})
        }
        recovery_counts = {
            status: db.query(RecoveryLoop)
            .filter(
                RecoveryLoop.owner_subject == owner_subject,
                RecoveryLoop.status == status,
            )
            .count()
            for status in sorted(
                RECOVERY_TERMINAL | {"planned", "waiting", "running", "paused"}
            )
        }
        return {
            "enabled_by_configuration": self.settings.gateway_autonomy_enabled,
            "environment_emergency_stop": self.settings.gateway_autonomy_emergency_stop,
            "policies": policy_counts,
            "approvals": approval_counts,
            "permits": permit_counts,
            "recoveries": recovery_counts,
            "assignments_total": db.query(AutonomyAssignment)
            .filter(AutonomyAssignment.owner_subject == owner_subject)
            .count(),
            "receipts_total": db.query(ActionReceipt)
            .filter(ActionReceipt.owner_subject == owner_subject)
            .count(),
        }


class AutonomyWorker:
    def __init__(
        self,
        *,
        service: AgentAutonomyService,
        session_factory: sessionmaker,
        settings: Settings,
    ) -> None:
        self.service = service
        self.session_factory = session_factory
        self.settings = settings
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._stopping.clear()
        if self.settings.gateway_autonomy_enabled:
            self._task = asyncio.create_task(
                self._run(), name="gateway-autonomy-worker"
            )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        interval = max(
            0.25, float(self.settings.gateway_autonomy_poll_interval_seconds)
        )
        while not self._stopping.is_set():
            try:
                with self.session_factory() as db:
                    policies = (
                        db.query(AutonomyPolicy)
                        .filter(AutonomyPolicy.status == "active")
                        .order_by(AutonomyPolicy.created_at)
                        .all()
                    )
                    policy_keys = [
                        (policy.owner_subject, policy.id) for policy in policies
                    ]
                for owner_subject, policy_id in policy_keys:
                    if self._stopping.is_set():
                        break
                    with self.session_factory() as db:
                        try:
                            self.service.run_assignment_cycle(
                                db,
                                owner_subject=owner_subject,
                                policy_id=policy_id,
                            )
                        except HTTPException as exc:
                            if exc.status_code not in {409, 423}:
                                logger.exception(
                                    "autonomy_assignment_cycle_failed",
                                    extra={"policy_id": policy_id},
                                )
                    with self.session_factory() as db:
                        try:
                            self.service.run_recovery_cycle(
                                db,
                                owner_subject=owner_subject,
                                policy_id=policy_id,
                            )
                        except HTTPException as exc:
                            if exc.status_code not in {409, 423}:
                                logger.exception(
                                    "autonomy_recovery_cycle_failed",
                                    extra={"policy_id": policy_id},
                                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("autonomy_worker_cycle_failed")
            await asyncio.sleep(interval)


agent_autonomy_service = AgentAutonomyService()
