from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .models import (
    ActionReceipt,
    AgentCommand,
    AgentWorkItem,
    ApprovalRequest,
    CollaborationRoom,
    CommandSession,
    ExecutionPermit,
    FileChangeSet,
    ResourceLease,
)

TASK_PROGRESS_SCHEMA_VERSION = "1"
TASK_PROGRESS_CAPABILITY_ID = "atlas.task_progress_ui/v1"
TASK_PROGRESS_RESOURCE_V1_URI = "ui://atlas/task-progress/v1.html"
TASK_PROGRESS_RESOURCE_V2_URI = "ui://atlas/task-progress/v2.html"
TASK_PROGRESS_RESOURCE_V3_URI = "ui://atlas/task-progress/v3.html"
TASK_PROGRESS_RESOURCE_V4_URI = "ui://atlas/task-progress/v4.html"
TASK_PROGRESS_RESOURCE_V5_URI = "ui://atlas/task-progress/v5.html"
TASK_PROGRESS_RESOURCE_V6_URI = "ui://atlas/task-progress/v6.html"
TASK_PROGRESS_RESOURCE_V7_URI = "ui://atlas/task-progress/v7.html"
TASK_PROGRESS_RESOURCE_V8_URI = "ui://atlas/task-progress/v8.html"
TASK_PROGRESS_RESOURCE_V9_URI = "ui://atlas/task-progress/v9.html"
TASK_PROGRESS_RESOURCE_URI = "ui://atlas/task-progress/v10.html"
TASK_PROGRESS_RESOURCE_MIME = "text/html;profile=mcp-app"
TASK_PROGRESS_EVENT_TYPES = (
    "gateway.task_progress.run_started.v1",
    "gateway.task_progress.stage_updated.v1",
    "gateway.task_progress.evidence_recorded.v1",
    "gateway.task_progress.blocked.v1",
    "gateway.task_progress.succeeded.v1",
    "gateway.task_progress.failed.v1",
    "gateway.task_progress.cancelled.v1",
    "gateway.task_progress.rollback_started.v1",
    "gateway.task_progress.rolled_back.v1",
)

_SECRET_KEY = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|credential|authorization|cookie|private[_-]?key|api[_-]?key|secret|seed)",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_TERMINAL_STAGE_STATUSES = {"completed", "failed", "cancelled"}
_STAGE_STATUS = {
    "open": "queued",
    "in_progress": "running",
    "review": "waiting",
    "blocked": "blocked",
    "completed": "succeeded",
    "failed": "failed",
    "cancelled": "cancelled",
}


class TaskProgressTelemetry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshots = 0
        self._status = Counter({status: 0 for status in ("queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "rolling_back", "rolled_back", "unknown")})

    def record_snapshot(self, status: str) -> None:
        with self._lock:
            self._snapshots += 1
            if status in self._status:
                self._status[status] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"snapshots": self._snapshots, "status": dict(self._status)}

    def prometheus_lines(self) -> list[str]:
        current = self.snapshot()
        lines = ["# HELP gateway_task_progress_snapshots_total Task-progress snapshots projected by this Gateway process.", "# TYPE gateway_task_progress_snapshots_total counter", f"gateway_task_progress_snapshots_total {int(current['snapshots'])}", "# HELP gateway_task_progress_snapshot_status_total Projected task-progress snapshots by bounded status.", "# TYPE gateway_task_progress_snapshot_status_total counter"]
        for status, value in sorted(current["status"].items()):
            lines.append(f'gateway_task_progress_snapshot_status_total{{status="{status}"}} {int(value)}')
        return lines


task_progress_telemetry = TaskProgressTelemetry()


class TaskProgressSourceV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str | None = None
    project_path: str | None = None
    base_commit: str | None = None
    work_item_ids: list[str] = Field(default_factory=list)
    command_ids: list[str] = Field(default_factory=list)
    session_ids: list[str] = Field(default_factory=list)


class TaskProgressValueV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["determinate", "indeterminate"]
    completed: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)
    unit: str = "stage"


class TaskProgressStageV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    status: Literal[
        "queued",
        "running",
        "waiting",
        "blocked",
        "succeeded",
        "failed",
        "cancelled",
        "rolling_back",
        "rolled_back",
        "unknown",
    ]
    priority: int = 50
    dependencies: list[str] = Field(default_factory=list)
    acceptance_total: int = Field(default=0, ge=0)
    acceptance_passed: int = Field(default=0, ge=0)
    updated_at: datetime


class TaskProgressBlockerV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    source_id: str
    message: str
    status: str


class TaskProgressCheckV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    stage_id: str
    label: str
    status: Literal["pending", "passed", "failed", "unknown"]


class TaskProgressResourceV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    status: str
    origin: str | None = None
    branch: str | None = None
    base_commit: str | None = None


class TaskProgressEvidenceV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    status: str
    label: str
    reference: str | None = None
    recorded_at: datetime


class TaskProgressSnapshotV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    capability: Literal["atlas.task_progress_ui/v1"] = "atlas.task_progress_ui/v1"
    run_id: str
    title: str
    status: Literal[
        "queued",
        "running",
        "waiting",
        "blocked",
        "succeeded",
        "failed",
        "cancelled",
        "rolling_back",
        "rolled_back",
        "unknown",
    ]
    project: str | None = None
    source: TaskProgressSourceV1
    progress: TaskProgressValueV1
    current_stage_id: str | None = None
    stages: list[TaskProgressStageV1] = Field(default_factory=list)
    blockers: list[TaskProgressBlockerV1] = Field(default_factory=list)
    checks: list[TaskProgressCheckV1] = Field(default_factory=list)
    resources: list[TaskProgressResourceV1] = Field(default_factory=list)
    changes: dict[str, Any] = Field(default_factory=dict)
    delivery: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[TaskProgressEvidenceV1] = Field(default_factory=list)
    cancel_supported: bool = False
    sequence: int = Field(ge=0)
    updated_at: datetime


class TaskProgressEventV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    event_type: Literal[
        "gateway.task_progress.run_started.v1",
        "gateway.task_progress.stage_updated.v1",
        "gateway.task_progress.evidence_recorded.v1",
        "gateway.task_progress.blocked.v1",
        "gateway.task_progress.succeeded.v1",
        "gateway.task_progress.failed.v1",
        "gateway.task_progress.cancelled.v1",
        "gateway.task_progress.rollback_started.v1",
        "gateway.task_progress.rolled_back.v1",
    ]
    run_id: str
    sequence: int = Field(ge=0)
    source_type: str
    source_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


def _safe_text(value: Any, *, maximum: int = 600) -> str:
    text = _CONTROL.sub("", str(value or ""))
    text = " ".join(text.split())
    return text[:maximum]


def _safe_path(value: Any) -> str:
    text = _safe_text(value, maximum=400)
    if text.startswith("/") or _WINDOWS_ABSOLUTE.match(text):
        normalized = text.replace("\\", "/")
        return PurePath(normalized).name
    return text


def _redact(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = _safe_text(raw_key, maximum=120)
            if not key:
                continue
            if _SECRET_KEY.search(key):
                result[key] = "[redacted]"
            else:
                result[key] = _redact(child, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_redact(child, depth=depth + 1) for child in value[:50]]
    if isinstance(value, tuple):
        return [_redact(child, depth=depth + 1) for child in value[:50]]
    if isinstance(value, str):
        return _safe_text(value, maximum=1200)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value, maximum=600)


def _timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _latest_timestamp(values: list[datetime | None], fallback: datetime) -> datetime:
    normalized = [stamp for item in values if (stamp := _timestamp(item)) is not None]
    return max(normalized) if normalized else _timestamp(fallback) or datetime.now(UTC)


def _sequence(updated_at: datetime, entity_count: int) -> int:
    micros = int(updated_at.timestamp() * 1_000_000)
    return micros * 1000 + min(max(entity_count, 0), 999)


def _session_ids(commands: list[AgentCommand]) -> list[str]:
    values: set[str] = set()
    for command in commands:
        for payload in (command.result or {}, command.structured_payload or {}):
            for key in ("session_id", "command_session_id"):
                value = payload.get(key) if isinstance(payload, dict) else None
                if isinstance(value, str) and value:
                    values.add(value)
    return sorted(values)


def _run_status(
    work_items: list[AgentWorkItem],
    approvals: list[ApprovalRequest],
    commands: list[AgentCommand],
) -> str:
    if any(bool((command.result or {}).get("outcome_unknown")) for command in commands):
        return "unknown"
    statuses = {item.status for item in work_items}
    if work_items and statuses <= {"completed"}:
        return "succeeded"
    if work_items and statuses <= {"cancelled"}:
        return "cancelled"
    if "blocked" in statuses:
        return "blocked"
    if any(request.status == "pending" for request in approvals):
        return "waiting"
    if "failed" in statuses and not statuses.intersection({"open", "in_progress", "review"}):
        return "failed"
    if "review" in statuses and not statuses.intersection({"open", "in_progress"}):
        return "waiting"
    if statuses.intersection({"in_progress", "review"}):
        return "running"
    if "open" in statuses:
        return "queued"
    if any(
        command.status in {"accepted", "acknowledged", "delivered", "pending"}
        for command in commands
    ):
        return "running"
    return "queued"


def _current_stage(work_items: list[AgentWorkItem]) -> str | None:
    order = ("in_progress", "blocked", "review", "open", "failed")
    for status in order:
        candidates = [item for item in work_items if item.status == status]
        if candidates:
            selected = min(
                candidates,
                key=lambda item: (-item.priority, item.created_at, item.id),
            )
            return selected.id
    return None


def _acceptance_status(
    item: AgentWorkItem,
    index: int,
) -> Literal["pending", "passed", "failed", "unknown"]:
    acceptance = (item.result or {}).get("acceptance")
    if isinstance(acceptance, list) and index < len(acceptance):
        raw = acceptance[index]
        if isinstance(raw, dict):
            status = str(raw.get("status") or "").lower()
            if status in {"pending", "passed", "failed", "unknown"}:
                return status
        if raw is True:
            return "passed"
        if raw is False:
            return "failed"
    if item.status == "completed":
        return "passed"
    if item.status == "failed":
        return "failed"
    return "pending"


def _delivery(work_items: list[AgentWorkItem]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in work_items:
        result = item.result or {}
        if not isinstance(result, dict):
            continue
        for key in ("git", "ci", "deployment", "runtime", "rollback"):
            value = result.get(key)
            if isinstance(value, dict):
                merged[key] = _redact(value)
    return merged


def project_task_progress(
    db: Session,
    *,
    owner_subject: str,
    run_id: str,
) -> TaskProgressSnapshotV1:
    room = (
        db.query(CollaborationRoom)
        .filter(
            CollaborationRoom.id == run_id,
            CollaborationRoom.owner_subject == owner_subject,
        )
        .one_or_none()
    )
    if room is None:
        raise HTTPException(status_code=404, detail="Task progress run not found")

    work_items = (
        db.query(AgentWorkItem)
        .filter(
            AgentWorkItem.owner_subject == owner_subject,
            AgentWorkItem.room_id == room.id,
        )
        .order_by(
            AgentWorkItem.priority.desc(),
            AgentWorkItem.created_at,
            AgentWorkItem.id,
        )
        .all()
    )
    commands = (
        db.query(AgentCommand)
        .filter(
            AgentCommand.owner_subject == owner_subject,
            AgentCommand.room_id == room.id,
        )
        .order_by(AgentCommand.created_at, AgentCommand.id)
        .all()
    )
    leases = (
        db.query(ResourceLease)
        .filter(
            ResourceLease.owner_subject == owner_subject,
            ResourceLease.room_id == room.id,
        )
        .order_by(ResourceLease.created_at, ResourceLease.id)
        .all()
    )
    changes = (
        db.query(FileChangeSet)
        .filter(
            FileChangeSet.owner_subject == owner_subject,
            FileChangeSet.room_id == room.id,
        )
        .order_by(FileChangeSet.created_at, FileChangeSet.id)
        .all()
    )
    approvals = (
        db.query(ApprovalRequest)
        .filter(
            ApprovalRequest.owner_subject == owner_subject,
            ApprovalRequest.room_id == room.id,
        )
        .order_by(ApprovalRequest.created_at, ApprovalRequest.id)
        .all()
    )
    approval_ids = [request.id for request in approvals]
    permits = (
        db.query(ExecutionPermit)
        .filter(
            ExecutionPermit.owner_subject == owner_subject,
            ExecutionPermit.approval_request_id.in_(approval_ids),
        )
        .all()
        if approval_ids
        else []
    )
    receipts = (
        db.query(ActionReceipt)
        .filter(
            ActionReceipt.owner_subject == owner_subject,
            ActionReceipt.approval_request_id.in_(approval_ids),
        )
        .all()
        if approval_ids
        else []
    )
    session_ids = _session_ids(commands)
    sessions = (
        db.query(CommandSession)
        .filter(
            CommandSession.owner_subject == owner_subject,
            CommandSession.id.in_(session_ids),
        )
        .all()
        if session_ids
        else []
    )

    stages = [
        TaskProgressStageV1(
            id=item.id,
            title=_safe_text(item.title, maximum=240),
            status=_STAGE_STATUS.get(item.status, "unknown"),
            priority=item.priority,
            dependencies=[str(value) for value in (item.dependencies or [])[:50]],
            acceptance_total=len(item.acceptance_criteria or []),
            acceptance_passed=sum(
                1
                for index, _ in enumerate(item.acceptance_criteria or [])
                if _acceptance_status(item, index) == "passed"
            ),
            updated_at=_timestamp(item.updated_at) or datetime.now(UTC),
        )
        for item in work_items
    ]

    blockers: list[TaskProgressBlockerV1] = []
    for item in work_items:
        if item.status == "blocked":
            blockers.append(
                TaskProgressBlockerV1(
                    kind="work_item",
                    source_id=item.id,
                    message=_safe_text(item.description or item.title, maximum=500),
                    status="blocked",
                )
            )
    for request in approvals:
        if request.status == "pending":
            blockers.append(
                TaskProgressBlockerV1(
                    kind="approval",
                    source_id=request.id,
                    message=(
                        f"Approval required for "
                        f"{_safe_text(request.action_kind, maximum=120)}"
                    ),
                    status="waiting",
                )
            )
    for command in commands:
        if bool((command.result or {}).get("outcome_unknown")):
            blockers.append(
                TaskProgressBlockerV1(
                    kind="reconciliation",
                    source_id=command.id,
                    message=(
                        "Execution outcome is ambiguous and requires reconciliation"
                    ),
                    status="unknown",
                )
            )

    checks = [
        TaskProgressCheckV1(
            id=f"{item.id}:{index}",
            stage_id=item.id,
            label=_safe_text(label, maximum=400),
            status=_acceptance_status(item, index),
        )
        for item in work_items
        for index, label in enumerate(item.acceptance_criteria or [])
    ]

    resources = [
        TaskProgressResourceV1(
            id=lease.id,
            kind="lease",
            status=lease.status,
            origin=_safe_text(lease.origin, maximum=80) or None,
            branch=_safe_text(lease.branch_name, maximum=255) or None,
            base_commit=_safe_text(lease.base_commit, maximum=128) or None,
        )
        for lease in leases
    ]

    artifacts: list[TaskProgressEvidenceV1] = []
    for session in sessions:
        artifacts.append(
            TaskProgressEvidenceV1(
                id=session.id,
                kind="command_session",
                status=session.status,
                label=_safe_text(session.name or session.origin, maximum=200),
                reference=None,
                recorded_at=_timestamp(session.updated_at) or datetime.now(UTC),
            )
        )
    for request in approvals:
        artifacts.append(
            TaskProgressEvidenceV1(
                id=request.id,
                kind="approval",
                status=request.status,
                label=_safe_text(request.action_kind, maximum=160),
                reference=None,
                recorded_at=_timestamp(request.updated_at) or datetime.now(UTC),
            )
        )
    for receipt in receipts:
        artifacts.append(
            TaskProgressEvidenceV1(
                id=receipt.id,
                kind="action_receipt",
                status=receipt.status,
                label=_safe_text(receipt.tool, maximum=160),
                reference=None,
                recorded_at=_timestamp(receipt.completed_at) or datetime.now(UTC),
            )
        )

    timestamps: list[datetime | None] = [room.updated_at]
    timestamps.extend(item.updated_at for item in work_items)
    timestamps.extend(command.updated_at for command in commands)
    timestamps.extend(lease.updated_at for lease in leases)
    timestamps.extend(change.created_at for change in changes)
    timestamps.extend(request.updated_at for request in approvals)
    timestamps.extend(permit.updated_at for permit in permits)
    timestamps.extend(receipt.created_at for receipt in receipts)
    timestamps.extend(session.updated_at for session in sessions)
    updated_at = _latest_timestamp(timestamps, room.created_at)
    entity_count = sum(
        len(items)
        for items in (
            work_items,
            commands,
            leases,
            changes,
            approvals,
            permits,
            receipts,
            sessions,
        )
    )

    completed = sum(
        1 for item in work_items if item.status in _TERMINAL_STAGE_STATUSES
    )
    progress = (
        TaskProgressValueV1(
            mode="determinate",
            completed=completed,
            total=len(work_items),
            unit="stage",
        )
        if work_items
        else TaskProgressValueV1(mode="indeterminate", unit="stage")
    )
    changed_paths = [
        _safe_path(change.path)
        for change in changes
        if not change.suppressed
    ]
    change_summary = {
        "count": len(changes),
        "visible_count": len(changed_paths),
        "paths": list(dict.fromkeys(path for path in changed_paths if path))[:50],
        "added_lines": sum(
            max(int(change.added_lines or 0), 0) for change in changes
        ),
        "removed_lines": sum(
            max(int(change.removed_lines or 0), 0) for change in changes
        ),
    }
    cancel_supported = any(session.status == "running" for session in sessions)

    snapshot = TaskProgressSnapshotV1(
        run_id=room.id,
        title=_safe_text(room.title, maximum=200),
        status=_run_status(work_items, approvals, commands),
        project=_safe_path(room.project_path) or None,
        source=TaskProgressSourceV1(
            repository=_safe_text(room.repository_identity, maximum=255) or None,
            project_path=_safe_path(room.project_path) or None,
            base_commit=_safe_text(room.base_commit, maximum=128) or None,
            work_item_ids=[item.id for item in work_items],
            command_ids=[command.id for command in commands],
            session_ids=sorted(session.id for session in sessions),
        ),
        progress=progress,
        current_stage_id=_current_stage(work_items),
        stages=stages,
        blockers=blockers,
        checks=checks,
        resources=resources,
        changes=change_summary,
        delivery=_delivery(work_items),
        artifacts=sorted(
            artifacts,
            key=lambda item: (item.recorded_at, item.id),
        )[-50:],
        cancel_supported=cancel_supported,
        sequence=_sequence(updated_at, entity_count),
        updated_at=updated_at,
    )
    task_progress_telemetry.record_snapshot(snapshot.status)
    return snapshot


def task_progress_model_payload(
    snapshot: TaskProgressSnapshotV1,
) -> dict[str, Any]:
    blocker = snapshot.blockers[0] if snapshot.blockers else None
    stage = next(
        (
            item
            for item in snapshot.stages
            if item.id == snapshot.current_stage_id
        ),
        None,
    )
    return {
        "schema_version": snapshot.schema_version,
        "capability": snapshot.capability,
        "run_id": snapshot.run_id,
        "status": snapshot.status,
        "current_stage": (
            {"id": stage.id, "title": stage.title, "status": stage.status}
            if stage is not None
            else None
        ),
        "progress": snapshot.progress.model_dump(mode="json"),
        "blocker": (
            blocker.model_dump(mode="json") if blocker is not None else None
        ),
        "sequence": snapshot.sequence,
        "updated_at": snapshot.updated_at.isoformat(),
    }


def task_progress_text(snapshot: TaskProgressSnapshotV1) -> str:
    if snapshot.progress.mode == "determinate":
        progress = (
            f"{snapshot.progress.completed}/{snapshot.progress.total} "
            "stages resolved"
        )
    else:
        progress = "progress is indeterminate"
    stage = next(
        (
            item
            for item in snapshot.stages
            if item.id == snapshot.current_stage_id
        ),
        None,
    )
    current = f" Current: {stage.title}." if stage is not None else ""
    blocker = (
        f" Blocker: {snapshot.blockers[0].message}."
        if snapshot.blockers
        else ""
    )
    return (
        f"{snapshot.title}: {snapshot.status}; {progress}.{current}{blocker}"
    ).strip()


def build_task_progress_event(
    snapshot: TaskProgressSnapshotV1,
    *,
    event_type: str,
    source_type: str,
    source_id: str,
    payload: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> TaskProgressEventV1:
    if event_type not in TASK_PROGRESS_EVENT_TYPES:
        raise ValueError("Unsupported task progress event type")
    safe_payload = _redact(payload or {})
    encoded = json.dumps(
        safe_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(encoded.encode("utf-8")) > 16_384:
        safe_payload = {
            "truncated": True,
            "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        }
    return TaskProgressEventV1(
        event_type=event_type,
        run_id=snapshot.run_id,
        sequence=snapshot.sequence,
        source_type=_safe_text(source_type, maximum=80),
        source_id=_safe_text(source_id, maximum=160),
        payload=safe_payload,
        created_at=_timestamp(created_at) or snapshot.updated_at,
    )
