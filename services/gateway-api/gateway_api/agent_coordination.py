from __future__ import annotations

import fnmatch
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .agent_command_policy import AgentCommandPolicyError, assert_no_secret_like_keys
from .events import emit_event
from .models import (
    AgentHandoffBarrier,
    AgentInstance,
    AgentIntegrationRecord,
    AgentWorkItem,
    CollaborationRoom,
    FileChangeSet,
    ResourceLease,
    utcnow,
)

LEASE_MODES = {"exclusive_write", "shared_read"}
LEASE_ACTIVE_STATUSES = {"active"}
HANDOFF_TERMINAL_STATUSES = {"accepted", "cancelled", "rejected"}
INTEGRATION_TERMINAL_STATUSES = {"integrated", "rejected"}
WRITE_OPERATIONS = {
    "append",
    "regex_replace",
    "remove_markdown_code_blocks",
    "replace",
    "write",
}


@dataclass(frozen=True)
class WriteLeaseContext:
    room_id: str
    agent_id: str
    lease_id: str
    fencing_token: int
    base_commit: str
    branch_name: str
    worktree_path: str
    expected_head: str | None
    expected_sha256: str | None
    expected_absent: bool


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


def _bounded_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(
            status_code=400, detail=f"{field} must be an integer"
        ) from exc
    return max(minimum, min(parsed, maximum))


def _safe_structured(value: Any, *, field: str) -> Any:
    try:
        assert_no_secret_like_keys(value, field=field)
    except AgentCommandPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return value


def normalize_relative_path(value: Any, *, field: str = "path") -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text or text == ".":
        return "."
    if "\x00" in text:
        raise HTTPException(status_code=400, detail=f"{field} contains a NUL byte")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise HTTPException(
            status_code=400, detail=f"{field} must be a safe relative path"
        )
    normalized = str(path)
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized or "."


def _glob_fixed_prefix(pattern: str) -> str:
    wildcard_positions = [
        position for marker in "*[?" if (position := pattern.find(marker)) >= 0
    ]
    if not wildcard_positions:
        return pattern
    prefix = pattern[: min(wildcard_positions)]
    return prefix.rsplit("/", 1)[0] if "/" in prefix else ""


def normalize_reservations(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise HTTPException(
            status_code=400, detail="reservations must be a non-empty array"
        )
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool]] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="reservation must be an object")
        kind = str(item.get("kind") or "path").strip()
        if kind not in {"path", "glob"}:
            raise HTTPException(
                status_code=400, detail="reservation kind must be path or glob"
            )
        pattern = normalize_relative_path(
            item.get("pattern"), field="reservation.pattern"
        )
        if kind == "glob" and not any(marker in pattern for marker in "*?["):
            kind = "path"
        recursive = bool(item.get("recursive", kind == "path"))
        key = (kind, pattern, recursive)
        if key in seen:
            continue
        seen.add(key)
        result.append({"kind": kind, "pattern": pattern, "recursive": recursive})
    if len(result) > 200:
        raise HTTPException(status_code=400, detail="too many reservations")
    return result


def reservation_covers_path(reservation: dict[str, Any], path: str) -> bool:
    pattern = str(reservation.get("pattern") or ".")
    kind = str(reservation.get("kind") or "path")
    if kind == "glob":
        return fnmatch.fnmatchcase(path, pattern)
    if path == pattern:
        return True
    return bool(reservation.get("recursive", True)) and (
        pattern == "." or path.startswith(f"{pattern.rstrip('/')}/")
    )


def reservations_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_kind = str(left.get("kind") or "path")
    right_kind = str(right.get("kind") or "path")
    left_pattern = str(left.get("pattern") or ".")
    right_pattern = str(right.get("pattern") or ".")
    if left_kind == "path" and right_kind == "path":
        return reservation_covers_path(left, right_pattern) or reservation_covers_path(
            right, left_pattern
        )
    if left_kind == "path":
        if fnmatch.fnmatchcase(left_pattern, right_pattern):
            return True
        prefix = _glob_fixed_prefix(right_pattern)
        return bool(
            prefix
            and (
                left_pattern.startswith(prefix)
                or prefix.startswith(left_pattern.rstrip("/") + "/")
            )
        )
    if right_kind == "path":
        return reservations_overlap(right, left)
    left_prefix = _glob_fixed_prefix(left_pattern)
    right_prefix = _glob_fixed_prefix(right_pattern)
    if not left_prefix or not right_prefix:
        return True
    return left_prefix.startswith(right_prefix) or right_prefix.startswith(left_prefix)


def reservation_sets_overlap(
    left: Iterable[dict[str, Any]], right: Iterable[dict[str, Any]]
) -> bool:
    return any(reservations_overlap(a, b) for a in left for b in right)


def lease_payload(lease: ResourceLease) -> dict[str, Any]:
    return {
        "id": lease.id,
        "room_id": lease.room_id,
        "holder_agent_id": lease.holder_agent_id,
        "work_item_id": lease.work_item_id,
        "origin": lease.origin,
        "resource_id": lease.resource_id,
        "mode": lease.mode,
        "reservations": list(lease.reservations or []),
        "fencing_token": lease.fencing_token,
        "status": lease.status,
        "branch_name": lease.branch_name,
        "worktree_path": lease.worktree_path,
        "base_commit": lease.base_commit,
        "expected_head": lease.expected_head,
        "meta": dict(lease.meta or {}),
        "acquired_at": lease.acquired_at.isoformat(),
        "renewed_at": lease.renewed_at.isoformat(),
        "expires_at": lease.expires_at.isoformat(),
        "released_at": lease.released_at.isoformat() if lease.released_at else None,
        "created_at": lease.created_at.isoformat(),
        "updated_at": lease.updated_at.isoformat(),
    }


def handoff_payload(barrier: AgentHandoffBarrier) -> dict[str, Any]:
    return {
        "id": barrier.id,
        "room_id": barrier.room_id,
        "source_agent_id": barrier.source_agent_id,
        "target_agent_id": barrier.target_agent_id,
        "lease_id": barrier.lease_id,
        "expected_fencing_token": barrier.expected_fencing_token,
        "required_change_ids": list(barrier.required_change_ids or []),
        "summary": barrier.summary,
        "payload": dict(barrier.payload or {}),
        "status": barrier.status,
        "conflict_report": dict(barrier.conflict_report or {}),
        "ready_at": barrier.ready_at.isoformat() if barrier.ready_at else None,
        "accepted_at": barrier.accepted_at.isoformat() if barrier.accepted_at else None,
        "cancelled_at": barrier.cancelled_at.isoformat()
        if barrier.cancelled_at
        else None,
        "created_at": barrier.created_at.isoformat(),
        "updated_at": barrier.updated_at.isoformat(),
    }


def integration_payload(record: AgentIntegrationRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "room_id": record.room_id,
        "coordinator_agent_id": record.coordinator_agent_id,
        "target_branch": record.target_branch,
        "expected_target_head": record.expected_target_head,
        "candidate_change_ids": list(record.candidate_change_ids or []),
        "comparison_change_ids": list(record.comparison_change_ids or []),
        "source_lease_ids": list(record.source_lease_ids or []),
        "status": record.status,
        "conflict_report": dict(record.conflict_report or {}),
        "decision": dict(record.decision or {}),
        "integrated_commit": record.integrated_commit,
        "version": record.version,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "completed_at": record.completed_at.isoformat()
        if record.completed_at
        else None,
    }


def file_change_payload(change: FileChangeSet) -> dict[str, Any]:
    return {
        "id": change.id,
        "origin": change.origin,
        "resource_id": change.resource_id,
        "tool_call_id": change.tool_call_id,
        "room_id": change.room_id,
        "agent_id": change.agent_id,
        "lease_id": change.lease_id,
        "fencing_token": change.fencing_token,
        "path": change.path,
        "operation": change.operation,
        "before_sha256": change.before_sha256,
        "after_sha256": change.after_sha256,
        "base_commit": change.base_commit,
        "branch_name": change.branch_name,
        "worktree_path": change.worktree_path,
        "added_lines": change.added_lines,
        "removed_lines": change.removed_lines,
        "bytes_before": change.bytes_before,
        "bytes_after": change.bytes_after,
        "replacements": change.replacements,
        "truncated": change.truncated,
        "suppressed": change.suppressed,
        "diff": dict(change.diff_json or {}),
        "created_at": change.created_at.isoformat(),
    }


class AgentCoordinationService:
    def _room(
        self, db: Session, *, owner_subject: str, room_id: str, lock: bool = False
    ) -> CollaborationRoom:
        query = db.query(CollaborationRoom).filter(
            CollaborationRoom.id == room_id,
            CollaborationRoom.owner_subject == owner_subject,
        )
        if lock:
            query = query.with_for_update()
        room = query.one_or_none()
        if room is None:
            raise HTTPException(status_code=404, detail="Collaboration room not found")
        return room

    def _agent(
        self, db: Session, *, owner_subject: str, agent_id: str
    ) -> AgentInstance:
        agent = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.id == agent_id,
                AgentInstance.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent

    def _lease(
        self, db: Session, *, owner_subject: str, lease_id: str, lock: bool = False
    ) -> ResourceLease:
        query = db.query(ResourceLease).filter(
            ResourceLease.id == lease_id,
            ResourceLease.owner_subject == owner_subject,
        )
        if lock:
            query = query.with_for_update()
        lease = query.one_or_none()
        if lease is None:
            raise HTTPException(status_code=404, detail="Resource lease not found")
        return lease

    def _handoff(
        self, db: Session, *, owner_subject: str, handoff_id: str, lock: bool = False
    ) -> AgentHandoffBarrier:
        query = db.query(AgentHandoffBarrier).filter(
            AgentHandoffBarrier.id == handoff_id,
            AgentHandoffBarrier.owner_subject == owner_subject,
        )
        if lock:
            query = query.with_for_update()
        barrier = query.one_or_none()
        if barrier is None:
            raise HTTPException(status_code=404, detail="Handoff barrier not found")
        return barrier

    def _integration(
        self,
        db: Session,
        *,
        owner_subject: str,
        integration_id: str,
        lock: bool = False,
    ) -> AgentIntegrationRecord:
        query = db.query(AgentIntegrationRecord).filter(
            AgentIntegrationRecord.id == integration_id,
            AgentIntegrationRecord.owner_subject == owner_subject,
        )
        if lock:
            query = query.with_for_update()
        record = query.one_or_none()
        if record is None:
            raise HTTPException(status_code=404, detail="Integration record not found")
        return record

    def _require_agent_in_room(self, agent: AgentInstance, room_id: str) -> None:
        if agent.current_room_id != room_id:
            raise HTTPException(
                status_code=409, detail="Agent is not joined to the collaboration room"
            )

    def _is_coordinator(self, room: CollaborationRoom, agent: AgentInstance) -> bool:
        policy = dict(room.policy or {})
        configured = {
            str(value) for value in list(policy.get("coordinator_agent_ids") or [])
        }
        capabilities = {str(value) for value in list(agent.capabilities or [])}
        return (
            agent.id in configured
            or "coordination:integrate" in capabilities
            or "coordinator" in capabilities
        )

    def expire_stale_leases(self, db: Session, *, owner_subject: str) -> int:
        now = utcnow()
        leases = (
            db.query(ResourceLease)
            .filter(
                ResourceLease.owner_subject == owner_subject,
                ResourceLease.status == "active",
            )
            .all()
        )
        changed = 0
        for lease in leases:
            expires_at = _aware(lease.expires_at)
            if expires_at is not None and expires_at <= now:
                lease.status = "expired"
                lease.released_at = now
                lease.updated_at = now
                changed += 1
        if changed:
            db.commit()
        return changed

    def acquire_lease(
        self, db: Session, *, owner_subject: str, data: dict[str, Any]
    ) -> ResourceLease:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        holder_agent_id = _required_text(
            data.get("holder_agent_id"), field="holder_agent_id", maximum=36
        )
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(ResourceLease)
                .filter(
                    ResourceLease.owner_subject == owner_subject,
                    ResourceLease.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        self.expire_stale_leases(db, owner_subject=owner_subject)
        room = self._room(db, owner_subject=owner_subject, room_id=room_id, lock=True)
        if room.status != "active":
            raise HTTPException(
                status_code=409, detail="Collaboration room is not active"
            )
        agent = self._agent(db, owner_subject=owner_subject, agent_id=holder_agent_id)
        self._require_agent_in_room(agent, room_id)
        mode = str(data.get("mode") or "exclusive_write").strip()
        if mode not in LEASE_MODES:
            raise HTTPException(
                status_code=400, detail="Unsupported resource lease mode"
            )
        origin = _required_text(data.get("origin"), field="origin", maximum=40)
        resource_id = _optional_text(data.get("resource_id"), maximum=160)
        if origin != "server" and resource_id is None:
            raise HTTPException(
                status_code=400, detail="resource_id is required for non-server leases"
            )
        reservations = normalize_reservations(data.get("reservations"))
        branch_name = _optional_text(data.get("branch_name"), maximum=255)
        raw_worktree_path = _optional_text(data.get("worktree_path"), maximum=4096)
        worktree_path = (
            normalize_relative_path(raw_worktree_path, field="worktree_path")
            if raw_worktree_path
            else None
        )
        base_commit = _optional_text(data.get("base_commit"), maximum=128)
        expected_head = _optional_text(data.get("expected_head"), maximum=128)
        if mode == "exclusive_write" and not all(
            (branch_name, worktree_path, base_commit)
        ):
            raise HTTPException(
                status_code=400,
                detail="exclusive_write leases require branch_name, worktree_path, and base_commit",
            )
        if mode == "exclusive_write" and worktree_path == ".":
            raise HTTPException(
                status_code=400,
                detail="exclusive_write worktree_path must identify an isolated subdirectory",
            )
        work_item_id = _optional_text(data.get("work_item_id"), maximum=36)
        if work_item_id:
            work_item = (
                db.query(AgentWorkItem)
                .filter(
                    AgentWorkItem.id == work_item_id,
                    AgentWorkItem.owner_subject == owner_subject,
                    AgentWorkItem.room_id == room_id,
                )
                .one_or_none()
            )
            if work_item is None:
                raise HTTPException(status_code=404, detail="Work item not found")
            if (
                work_item.assigned_agent_id != holder_agent_id
                or work_item.status != "in_progress"
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Work item is not actively assigned to the lease holder",
                )
        active = (
            db.query(ResourceLease)
            .filter(
                ResourceLease.owner_subject == owner_subject,
                ResourceLease.room_id == room_id,
                ResourceLease.status == "active",
            )
            .all()
        )
        for lease in active:
            if mode == "shared_read" and lease.mode == "shared_read":
                continue
            if reservation_sets_overlap(reservations, list(lease.reservations or [])):
                raise HTTPException(
                    status_code=409,
                    detail=f"Reservation conflicts with active lease {lease.id}",
                )
            if branch_name and lease.branch_name == branch_name:
                raise HTTPException(
                    status_code=409,
                    detail=f"Branch is already owned by active lease {lease.id}",
                )
            if worktree_path and lease.worktree_path == worktree_path:
                raise HTTPException(
                    status_code=409,
                    detail=f"Worktree is already owned by active lease {lease.id}",
                )
        max_token = (
            db.query(func.max(ResourceLease.fencing_token))
            .filter(
                ResourceLease.owner_subject == owner_subject,
                ResourceLease.room_id == room_id,
            )
            .scalar()
            or 0
        )
        now = utcnow()
        ttl_seconds = _bounded_int(
            data.get("ttl_seconds", 300), field="ttl_seconds", minimum=30, maximum=3600
        )
        meta = dict(_safe_structured(dict(data.get("meta") or {}), field="lease meta"))
        lease = ResourceLease(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            holder_agent_id=holder_agent_id,
            work_item_id=work_item_id,
            origin=origin,
            resource_id=resource_id,
            mode=mode,
            reservations=reservations,
            fencing_token=int(max_token) + 1,
            status="active",
            branch_name=branch_name,
            worktree_path=worktree_path,
            base_commit=base_commit,
            expected_head=expected_head,
            idempotency_key=idempotency_key,
            meta=meta,
            acquired_at=now,
            renewed_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            created_at=now,
            updated_at=now,
        )
        db.add(lease)
        emit_event(
            db,
            event_type="gateway.resource_lease.acquired.v1",
            actor_subject=owner_subject,
            action="acquired",
            resource_type="resource_lease",
            resource_id=lease.id,
            payload={
                "lease_id": lease.id,
                "room_id": lease.room_id,
                "holder_agent_id": lease.holder_agent_id,
                "origin": lease.origin,
                "resource_id": lease.resource_id,
                "mode": lease.mode,
                "reservations": lease.reservations,
                "fencing_token": lease.fencing_token,
                "branch_name": lease.branch_name,
                "worktree_path": lease.worktree_path,
            },
            commit=False,
        )
        db.commit()
        db.refresh(lease)
        return lease

    def list_leases(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        status: str | None = None,
        holder_agent_id: str | None = None,
    ) -> list[ResourceLease]:
        self.expire_stale_leases(db, owner_subject=owner_subject)
        query = db.query(ResourceLease).filter(
            ResourceLease.owner_subject == owner_subject
        )
        if room_id:
            self._room(db, owner_subject=owner_subject, room_id=room_id)
            query = query.filter(ResourceLease.room_id == room_id)
        if status:
            query = query.filter(ResourceLease.status == status)
        if holder_agent_id:
            self._agent(db, owner_subject=owner_subject, agent_id=holder_agent_id)
            query = query.filter(ResourceLease.holder_agent_id == holder_agent_id)
        return query.order_by(ResourceLease.created_at.desc()).limit(500).all()

    def renew_lease(
        self,
        db: Session,
        *,
        owner_subject: str,
        lease_id: str,
        holder_agent_id: str,
        fencing_token: int,
        ttl_seconds: int,
    ) -> ResourceLease:
        self.expire_stale_leases(db, owner_subject=owner_subject)
        lease = self._lease(
            db, owner_subject=owner_subject, lease_id=lease_id, lock=True
        )
        if lease.status != "active":
            raise HTTPException(status_code=409, detail="Resource lease is not active")
        if (
            lease.holder_agent_id != holder_agent_id
            or lease.fencing_token != fencing_token
        ):
            raise HTTPException(
                status_code=409, detail="Lease holder or fencing token is stale"
            )
        self._agent(db, owner_subject=owner_subject, agent_id=holder_agent_id)
        now = utcnow()
        lease.renewed_at = now
        lease.expires_at = now + timedelta(
            seconds=_bounded_int(
                ttl_seconds, field="ttl_seconds", minimum=30, maximum=3600
            )
        )
        lease.updated_at = now
        emit_event(
            db,
            event_type="gateway.resource_lease.renewed.v1",
            actor_subject=owner_subject,
            action="renewed",
            resource_type="resource_lease",
            resource_id=lease.id,
            payload={
                "lease_id": lease.id,
                "room_id": lease.room_id,
                "holder_agent_id": lease.holder_agent_id,
                "fencing_token": lease.fencing_token,
                "expires_at": lease.expires_at.isoformat(),
            },
            commit=False,
        )
        db.commit()
        db.refresh(lease)
        return lease

    def release_lease(
        self,
        db: Session,
        *,
        owner_subject: str,
        lease_id: str,
        actor_agent_id: str,
        fencing_token: int,
        force: bool = False,
    ) -> ResourceLease:
        lease = self._lease(
            db, owner_subject=owner_subject, lease_id=lease_id, lock=True
        )
        room = self._room(db, owner_subject=owner_subject, room_id=lease.room_id)
        actor = self._agent(db, owner_subject=owner_subject, agent_id=actor_agent_id)
        if lease.status != "active":
            return lease
        if lease.fencing_token != fencing_token:
            raise HTTPException(status_code=409, detail="Fencing token is stale")
        if actor_agent_id != lease.holder_agent_id and not (
            force and self._is_coordinator(room, actor)
        ):
            raise HTTPException(
                status_code=403,
                detail="Only the holder or a coordinator can release this lease",
            )
        now = utcnow()
        lease.status = (
            "revoked"
            if force and actor_agent_id != lease.holder_agent_id
            else "released"
        )
        lease.released_at = now
        lease.updated_at = now
        emit_event(
            db,
            event_type="gateway.resource_lease.released.v1",
            actor_subject=owner_subject,
            action=lease.status,
            resource_type="resource_lease",
            resource_id=lease.id,
            payload={
                "lease_id": lease.id,
                "room_id": lease.room_id,
                "holder_agent_id": lease.holder_agent_id,
                "actor_agent_id": actor_agent_id,
                "fencing_token": lease.fencing_token,
                "status": lease.status,
            },
            commit=False,
        )
        db.commit()
        db.refresh(lease)
        return lease

    def covering_leases(
        self,
        db: Session,
        *,
        owner_subject: str,
        origin: str,
        resource_id: str | None,
        path: str,
    ) -> list[ResourceLease]:
        self.expire_stale_leases(db, owner_subject=owner_subject)
        normalized = normalize_relative_path(path)
        leases = (
            db.query(ResourceLease)
            .filter(
                ResourceLease.owner_subject == owner_subject,
                ResourceLease.origin == origin,
                ResourceLease.resource_id == resource_id,
                ResourceLease.status == "active",
                ResourceLease.mode == "exclusive_write",
            )
            .all()
        )
        covering: list[ResourceLease] = []
        for lease in leases:
            root = normalize_relative_path(
                lease.worktree_path or ".", field="lease.worktree_path"
            )
            if root == ".":
                relative = normalized
            elif normalized == root:
                relative = "."
            elif normalized.startswith(f"{root.rstrip('/')}/"):
                relative = normalized[len(root.rstrip("/")) + 1 :]
            else:
                continue
            if any(
                reservation_covers_path(item, relative)
                for item in list(lease.reservations or [])
            ):
                covering.append(lease)
        return covering

    def validate_write_context(
        self,
        db: Session,
        *,
        owner_subject: str,
        origin: str,
        resource_id: str | None,
        path: str,
        data: dict[str, Any],
    ) -> WriteLeaseContext | None:
        covering = self.covering_leases(
            db,
            owner_subject=owner_subject,
            origin=origin,
            resource_id=resource_id,
            path=path,
        )
        if not covering:
            supplied_guard = any(
                data.get(name) not in {None, ""}
                for name in (
                    "lease_id",
                    "agent_id",
                    "room_id",
                    "fencing_token",
                    "branch_name",
                    "worktree_path",
                    "base_commit",
                )
            )
            if supplied_guard:
                raise HTTPException(
                    status_code=409,
                    detail="No active lease covers the requested write path",
                )
            return None
        lease_id = _required_text(data.get("lease_id"), field="lease_id", maximum=36)
        agent_id = _required_text(data.get("agent_id"), field="agent_id", maximum=36)
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        fencing_token = _bounded_int(
            data.get("fencing_token"),
            field="fencing_token",
            minimum=1,
            maximum=2**63 - 1,
        )
        lease = next(
            (candidate for candidate in covering if candidate.id == lease_id), None
        )
        if lease is None:
            raise HTTPException(
                status_code=409, detail="Write path is reserved by another active lease"
            )
        if (
            lease.room_id != room_id
            or lease.holder_agent_id != agent_id
            or lease.fencing_token != fencing_token
        ):
            raise HTTPException(
                status_code=409, detail="Lease holder, room, or fencing token is stale"
            )
        branch_name = _required_text(
            data.get("branch_name"), field="branch_name", maximum=255
        )
        worktree_path = _required_text(
            data.get("worktree_path"), field="worktree_path", maximum=4096
        )
        base_commit = _required_text(
            data.get("base_commit"), field="base_commit", maximum=128
        )
        if (
            branch_name != lease.branch_name
            or worktree_path != lease.worktree_path
            or base_commit != lease.base_commit
        ):
            raise HTTPException(
                status_code=409,
                detail="Branch, worktree, or base commit does not match the active lease",
            )
        expected_sha256 = _optional_text(data.get("expected_sha256"), maximum=64)
        expected_absent = bool(data.get("expected_absent", False))
        if bool(expected_sha256) == expected_absent:
            raise HTTPException(
                status_code=400,
                detail="Exactly one of expected_sha256 or expected_absent is required",
            )
        return WriteLeaseContext(
            room_id=room_id,
            agent_id=agent_id,
            lease_id=lease_id,
            fencing_token=fencing_token,
            base_commit=base_commit,
            branch_name=branch_name,
            worktree_path=worktree_path,
            expected_head=lease.expected_head,
            expected_sha256=expected_sha256,
            expected_absent=expected_absent,
        )

    def _changes(
        self,
        db: Session,
        *,
        owner_subject: str,
        ids: list[str],
        room_id: str | None = None,
    ) -> list[FileChangeSet]:
        unique_ids = list(dict.fromkeys(str(value) for value in ids if str(value)))
        if not unique_ids:
            return []
        query = db.query(FileChangeSet).filter(
            FileChangeSet.owner_subject == owner_subject,
            FileChangeSet.id.in_(unique_ids),
        )
        if room_id:
            query = query.filter(FileChangeSet.room_id == room_id)
        changes = query.all()
        found = {change.id for change in changes}
        missing = [change_id for change_id in unique_ids if change_id not in found]
        if missing:
            raise HTTPException(
                status_code=404, detail=f"File change not found: {missing[0]}"
            )
        by_id = {change.id: change for change in changes}
        return [by_id[change_id] for change_id in unique_ids]

    @staticmethod
    def _changed_ranges(change: FileChangeSet) -> list[tuple[int, int]] | None:
        diff = dict(change.diff_json or {})
        if (
            change.suppressed
            or change.truncated
            or diff.get("suppressed")
            or diff.get("truncated")
        ):
            return None
        hunks = list(diff.get("hunks") or [])
        if not hunks:
            return None
        ranges: list[tuple[int, int]] = []
        for hunk in hunks:
            if not isinstance(hunk, dict):
                return None
            start = int(hunk.get("new_start", hunk.get("old_start", 1)) or 1)
            count = max(int(hunk.get("new_count", hunk.get("old_count", 1)) or 1), 1)
            ranges.append((start, start + count - 1))
        return ranges

    @staticmethod
    def _ranges_overlap(
        left: list[tuple[int, int]], right: list[tuple[int, int]]
    ) -> bool:
        return any(
            max(a_start, b_start) <= min(a_end, b_end)
            for a_start, a_end in left
            for b_start, b_end in right
        )

    @staticmethod
    def _logical_change_path(change: FileChangeSet) -> str:
        physical = normalize_relative_path(change.path)
        if not change.worktree_path:
            return physical
        root = normalize_relative_path(change.worktree_path, field="change.worktree_path")
        if physical == root:
            return "."
        prefix = f"{root.rstrip('/')}/"
        if physical.startswith(prefix):
            return physical[len(prefix) :]
        return physical

    @staticmethod
    def _changes_share_namespace(left: FileChangeSet, right: FileChangeSet) -> bool:
        if left.room_id and left.room_id == right.room_id:
            return True
        return left.origin == right.origin and left.resource_id == right.resource_id

    def detect_conflicts(
        self,
        db: Session,
        *,
        owner_subject: str,
        candidate_change_ids: list[str],
        comparison_change_ids: list[str] | None = None,
        room_id: str | None = None,
    ) -> dict[str, Any]:
        candidates = self._changes(
            db, owner_subject=owner_subject, ids=candidate_change_ids, room_id=room_id
        )
        if comparison_change_ids is None:
            candidate_ids = {change.id for change in candidates}
            comparison_query = db.query(FileChangeSet).filter(
                FileChangeSet.owner_subject == owner_subject
            )
            if room_id:
                comparison_query = comparison_query.filter(
                    FileChangeSet.room_id == room_id
                )
            comparisons = [
                change
                for change in comparison_query.order_by(FileChangeSet.created_at.desc())
                .limit(2000)
                .all()
                if change.id not in candidate_ids
            ]
        else:
            comparisons = self._changes(
                db,
                owner_subject=owner_subject,
                ids=comparison_change_ids,
                room_id=room_id,
            )
        conflicts: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for candidate in candidates:
            for other in comparisons:
                pair = (candidate.id, other.id)
                if pair in seen_pairs or candidate.id == other.id:
                    continue
                seen_pairs.add(pair)
                candidate_path = self._logical_change_path(candidate)
                other_path = self._logical_change_path(other)
                if not self._changes_share_namespace(candidate, other):
                    continue
                severity: str | None = None
                reason: str | None = None
                if candidate_path == other_path:
                    left_ranges = self._changed_ranges(candidate)
                    right_ranges = self._changed_ranges(other)
                    if left_ranges is None or right_ranges is None:
                        severity = "hard"
                        reason = "same_path_with_incomplete_diff_evidence"
                    elif self._ranges_overlap(left_ranges, right_ranges):
                        severity = "hard"
                        reason = "overlapping_diff_hunks"
                    else:
                        severity = "potential"
                        reason = "same_path_non_overlapping_hunks"
                    if (
                        candidate.before_sha256
                        and other.after_sha256
                        and candidate.before_sha256 != other.after_sha256
                    ):
                        severity = "hard"
                        reason = "stale_file_precondition"
                elif candidate_path.startswith(
                    other_path.rstrip("/") + "/"
                ) or other_path.startswith(candidate_path.rstrip("/") + "/"):
                    severity = "potential"
                    reason = "parent_child_path_overlap"
                if severity:
                    conflicts.append(
                        {
                            "severity": severity,
                            "reason": reason,
                            "candidate_change_id": candidate.id,
                            "comparison_change_id": other.id,
                            "path": candidate_path,
                            "comparison_path": other_path,
                            "candidate_agent_id": candidate.agent_id,
                            "comparison_agent_id": other.agent_id,
                            "candidate_lease_id": candidate.lease_id,
                            "comparison_lease_id": other.lease_id,
                        }
                    )
        hard_count = sum(1 for item in conflicts if item["severity"] == "hard")
        potential_count = sum(
            1 for item in conflicts if item["severity"] == "potential"
        )
        return {
            "safe": hard_count == 0,
            "hard_conflict_count": hard_count,
            "potential_conflict_count": potential_count,
            "conflicts": conflicts,
            "candidate_change_ids": [change.id for change in candidates],
            "comparison_change_ids": [change.id for change in comparisons],
        }

    def list_handoffs(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        status: str | None = None,
    ) -> list[AgentHandoffBarrier]:
        query = db.query(AgentHandoffBarrier).filter(
            AgentHandoffBarrier.owner_subject == owner_subject
        )
        if room_id:
            self._room(db, owner_subject=owner_subject, room_id=room_id)
            query = query.filter(AgentHandoffBarrier.room_id == room_id)
        if status:
            query = query.filter(AgentHandoffBarrier.status == status)
        return query.order_by(AgentHandoffBarrier.created_at.desc()).limit(500).all()

    def list_integrations(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        status: str | None = None,
    ) -> list[AgentIntegrationRecord]:
        query = db.query(AgentIntegrationRecord).filter(
            AgentIntegrationRecord.owner_subject == owner_subject
        )
        if room_id:
            self._room(db, owner_subject=owner_subject, room_id=room_id)
            query = query.filter(AgentIntegrationRecord.room_id == room_id)
        if status:
            query = query.filter(AgentIntegrationRecord.status == status)
        return query.order_by(AgentIntegrationRecord.created_at.desc()).limit(500).all()

    def create_handoff(
        self, db: Session, *, owner_subject: str, data: dict[str, Any]
    ) -> AgentHandoffBarrier:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        source_agent_id = _required_text(
            data.get("source_agent_id"), field="source_agent_id", maximum=36
        )
        target_agent_id = _required_text(
            data.get("target_agent_id"), field="target_agent_id", maximum=36
        )
        lease_id = _required_text(data.get("lease_id"), field="lease_id", maximum=36)
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AgentHandoffBarrier)
                .filter(
                    AgentHandoffBarrier.owner_subject == owner_subject,
                    AgentHandoffBarrier.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        self._room(db, owner_subject=owner_subject, room_id=room_id)
        source = self._agent(db, owner_subject=owner_subject, agent_id=source_agent_id)
        target = self._agent(db, owner_subject=owner_subject, agent_id=target_agent_id)
        self._require_agent_in_room(source, room_id)
        self._require_agent_in_room(target, room_id)
        lease = self._lease(db, owner_subject=owner_subject, lease_id=lease_id)
        expected_token = _bounded_int(
            data.get("expected_fencing_token"),
            field="expected_fencing_token",
            minimum=1,
            maximum=2**63 - 1,
        )
        if (
            lease.room_id != room_id
            or lease.holder_agent_id != source_agent_id
            or lease.fencing_token != expected_token
        ):
            raise HTTPException(
                status_code=409, detail="Handoff lease context is stale"
            )
        if lease.status != "active":
            raise HTTPException(
                status_code=409, detail="Handoff requires an active source lease"
            )
        change_ids = [
            str(value)
            for value in list(data.get("required_change_ids") or [])
            if str(value)
        ]
        changes = self._changes(
            db, owner_subject=owner_subject, ids=change_ids, room_id=room_id
        )
        if any(
            change.lease_id != lease.id or change.fencing_token != lease.fencing_token
            for change in changes
        ):
            raise HTTPException(
                status_code=409,
                detail="Handoff changes do not belong to the source lease and fence",
            )
        barrier = AgentHandoffBarrier(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            lease_id=lease_id,
            expected_fencing_token=expected_token,
            required_change_ids=change_ids,
            summary=str(data.get("summary") or "")[:10000],
            payload=dict(
                _safe_structured(
                    dict(data.get("payload") or {}), field="handoff payload"
                )
            ),
            status="open",
            conflict_report={},
            idempotency_key=idempotency_key,
        )
        db.add(barrier)
        emit_event(
            db,
            event_type="gateway.agent.handoff.created.v1",
            actor_subject=owner_subject,
            action="created",
            resource_type="agent_handoff_barrier",
            resource_id=barrier.id,
            payload={
                "handoff_id": barrier.id,
                "room_id": barrier.room_id,
                "source_agent_id": barrier.source_agent_id,
                "target_agent_id": barrier.target_agent_id,
                "lease_id": barrier.lease_id,
                "expected_fencing_token": barrier.expected_fencing_token,
                "required_change_ids": barrier.required_change_ids,
            },
            commit=False,
        )
        db.commit()
        db.refresh(barrier)
        return barrier

    def mark_handoff_ready(
        self,
        db: Session,
        *,
        owner_subject: str,
        handoff_id: str,
        source_agent_id: str,
    ) -> AgentHandoffBarrier:
        barrier = self._handoff(
            db, owner_subject=owner_subject, handoff_id=handoff_id, lock=True
        )
        if barrier.source_agent_id != source_agent_id:
            raise HTTPException(
                status_code=403,
                detail="Only the source agent can mark this handoff ready",
            )
        if barrier.status in HANDOFF_TERMINAL_STATUSES:
            return barrier
        lease = self._lease(db, owner_subject=owner_subject, lease_id=barrier.lease_id)
        if lease.fencing_token != barrier.expected_fencing_token:
            raise HTTPException(
                status_code=409, detail="Handoff fencing token is stale"
            )
        changes = self._changes(
            db,
            owner_subject=owner_subject,
            ids=list(barrier.required_change_ids or []),
            room_id=barrier.room_id,
        )
        if any(
            change.lease_id != lease.id or change.fencing_token != lease.fencing_token
            for change in changes
        ):
            raise HTTPException(
                status_code=409,
                detail="Handoff evidence no longer matches the source fence",
            )
        barrier.status = "ready"
        barrier.ready_at = utcnow()
        barrier.updated_at = barrier.ready_at
        emit_event(
            db,
            event_type="gateway.agent.handoff.ready.v1",
            actor_subject=owner_subject,
            action="ready",
            resource_type="agent_handoff_barrier",
            resource_id=barrier.id,
            payload={
                "handoff_id": barrier.id,
                "room_id": barrier.room_id,
                "source_agent_id": barrier.source_agent_id,
                "target_agent_id": barrier.target_agent_id,
                "lease_id": barrier.lease_id,
                "required_change_ids": barrier.required_change_ids,
            },
            commit=False,
        )
        db.commit()
        db.refresh(barrier)
        return barrier

    def accept_handoff(
        self,
        db: Session,
        *,
        owner_subject: str,
        handoff_id: str,
        target_agent_id: str,
        comparison_change_ids: list[str] | None = None,
    ) -> AgentHandoffBarrier:
        barrier = self._handoff(
            db, owner_subject=owner_subject, handoff_id=handoff_id, lock=True
        )
        if barrier.target_agent_id != target_agent_id:
            raise HTTPException(
                status_code=403, detail="Only the target agent can accept this handoff"
            )
        if barrier.status == "accepted":
            return barrier
        if barrier.status != "ready":
            raise HTTPException(status_code=409, detail="Handoff is not ready")
        lease = self._lease(db, owner_subject=owner_subject, lease_id=barrier.lease_id)
        if lease.status == "active":
            raise HTTPException(
                status_code=409,
                detail="Source lease must be released before handoff acceptance",
            )
        report = self.detect_conflicts(
            db,
            owner_subject=owner_subject,
            candidate_change_ids=list(barrier.required_change_ids or []),
            comparison_change_ids=comparison_change_ids,
            room_id=barrier.room_id,
        )
        barrier.conflict_report = report
        barrier.updated_at = utcnow()
        if not report["safe"]:
            barrier.status = "blocked"
            db.commit()
            db.refresh(barrier)
            raise HTTPException(
                status_code=409, detail="Handoff is blocked by hard file conflicts"
            )
        barrier.status = "accepted"
        barrier.accepted_at = barrier.updated_at
        emit_event(
            db,
            event_type="gateway.agent.handoff.accepted.v1",
            actor_subject=owner_subject,
            action="accepted",
            resource_type="agent_handoff_barrier",
            resource_id=barrier.id,
            payload={
                "handoff_id": barrier.id,
                "room_id": barrier.room_id,
                "source_agent_id": barrier.source_agent_id,
                "target_agent_id": barrier.target_agent_id,
                "conflict_report": barrier.conflict_report,
            },
            commit=False,
        )
        db.commit()
        db.refresh(barrier)
        return barrier

    def create_integration(
        self, db: Session, *, owner_subject: str, data: dict[str, Any]
    ) -> AgentIntegrationRecord:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        coordinator_agent_id = _required_text(
            data.get("coordinator_agent_id"), field="coordinator_agent_id", maximum=36
        )
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AgentIntegrationRecord)
                .filter(
                    AgentIntegrationRecord.owner_subject == owner_subject,
                    AgentIntegrationRecord.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        room = self._room(db, owner_subject=owner_subject, room_id=room_id)
        coordinator = self._agent(
            db, owner_subject=owner_subject, agent_id=coordinator_agent_id
        )
        self._require_agent_in_room(coordinator, room_id)
        if not self._is_coordinator(room, coordinator):
            raise HTTPException(
                status_code=403, detail="Agent is not a room coordinator"
            )
        candidate_change_ids = [
            str(value)
            for value in list(data.get("candidate_change_ids") or [])
            if str(value)
        ]
        comparison_change_ids = [
            str(value)
            for value in list(data.get("comparison_change_ids") or [])
            if str(value)
        ]
        source_lease_ids = [
            str(value)
            for value in list(data.get("source_lease_ids") or [])
            if str(value)
        ]
        for lease_id in source_lease_ids:
            lease = self._lease(db, owner_subject=owner_subject, lease_id=lease_id)
            if lease.room_id != room_id or lease.status == "active":
                raise HTTPException(
                    status_code=409,
                    detail="Integration source leases must belong to the room and be released",
                )
        report = self.detect_conflicts(
            db,
            owner_subject=owner_subject,
            candidate_change_ids=candidate_change_ids,
            comparison_change_ids=comparison_change_ids or None,
            room_id=room_id,
        )
        record = AgentIntegrationRecord(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            coordinator_agent_id=coordinator_agent_id,
            target_branch=_required_text(
                data.get("target_branch"), field="target_branch", maximum=255
            ),
            expected_target_head=_required_text(
                data.get("expected_target_head"),
                field="expected_target_head",
                maximum=128,
            ),
            candidate_change_ids=candidate_change_ids,
            comparison_change_ids=comparison_change_ids,
            source_lease_ids=source_lease_ids,
            status="blocked" if not report["safe"] else "review",
            conflict_report=report,
            decision={},
            idempotency_key=idempotency_key,
            version=1,
        )
        db.add(record)
        emit_event(
            db,
            event_type="gateway.agent.integration.created.v1",
            actor_subject=owner_subject,
            action="created",
            resource_type="agent_integration_record",
            resource_id=record.id,
            payload={
                "integration_id": record.id,
                "room_id": record.room_id,
                "coordinator_agent_id": record.coordinator_agent_id,
                "target_branch": record.target_branch,
                "expected_target_head": record.expected_target_head,
                "status": record.status,
                "conflict_report": record.conflict_report,
            },
            commit=False,
        )
        db.commit()
        db.refresh(record)
        return record

    def complete_integration(
        self,
        db: Session,
        *,
        owner_subject: str,
        integration_id: str,
        coordinator_agent_id: str,
        expected_version: int,
        status: str,
        observed_target_head: str | None = None,
        decision: dict[str, Any] | None = None,
        integrated_commit: str | None = None,
    ) -> AgentIntegrationRecord:
        if status not in {"approved", "integrated", "rejected"}:
            raise HTTPException(
                status_code=400, detail="Unsupported integration status"
            )
        record = self._integration(
            db, owner_subject=owner_subject, integration_id=integration_id, lock=True
        )
        room = self._room(db, owner_subject=owner_subject, room_id=record.room_id)
        coordinator = self._agent(
            db, owner_subject=owner_subject, agent_id=coordinator_agent_id
        )
        if (
            record.coordinator_agent_id != coordinator_agent_id
            or not self._is_coordinator(room, coordinator)
        ):
            raise HTTPException(
                status_code=403,
                detail="Only the assigned coordinator can update this integration",
            )
        if record.version != expected_version:
            raise HTTPException(status_code=409, detail="Integration version conflict")
        if record.status in INTEGRATION_TERMINAL_STATUSES:
            return record
        if status in {"approved", "integrated"} and not bool(
            record.conflict_report.get("safe", False)
        ):
            raise HTTPException(
                status_code=409, detail="Integration has unresolved hard conflicts"
            )
        observed_head = _optional_text(observed_target_head, maximum=128)
        if status in {"approved", "integrated"}:
            if observed_head is None:
                raise HTTPException(status_code=400, detail="observed_target_head is required")
            if observed_head != record.expected_target_head:
                raise HTTPException(status_code=409, detail="Integration target head is stale")
        commit = _optional_text(integrated_commit, maximum=128)
        if status == "integrated" and commit is None:
            raise HTTPException(status_code=400, detail="integrated_commit is required")
        record.status = status
        record.decision = dict(
            _safe_structured(dict(decision or {}), field="integration decision")
        )
        record.integrated_commit = commit
        record.version += 1
        record.updated_at = utcnow()
        if status in INTEGRATION_TERMINAL_STATUSES:
            record.completed_at = record.updated_at
        emit_event(
            db,
            event_type="gateway.agent.integration.updated.v1",
            actor_subject=owner_subject,
            action=status,
            resource_type="agent_integration_record",
            resource_id=record.id,
            payload={
                "integration_id": record.id,
                "room_id": record.room_id,
                "coordinator_agent_id": record.coordinator_agent_id,
                "status": record.status,
                "version": record.version,
                "observed_target_head": observed_head,
                "integrated_commit": record.integrated_commit,
            },
            commit=False,
        )
        db.commit()
        db.refresh(record)
        return record


agent_coordination_service = AgentCoordinationService()
