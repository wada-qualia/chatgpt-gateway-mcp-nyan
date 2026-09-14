from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException
from gateway_api.models import (
    AgentCommand,
    AgentWorkItem,
    Base,
    CollaborationRoom,
    FileChangeSet,
)
from gateway_api.task_progress import (
    TASK_PROGRESS_CAPABILITY_ID,
    TASK_PROGRESS_EVENT_TYPES,
    TASK_PROGRESS_RESOURCE_MIME,
    TASK_PROGRESS_RESOURCE_URI,
    TASK_PROGRESS_RESOURCE_V1_URI,
    TASK_PROGRESS_RESOURCE_V2_URI,
    TASK_PROGRESS_RESOURCE_V3_URI,
    TASK_PROGRESS_RESOURCE_V4_URI,
    TASK_PROGRESS_RESOURCE_V5_URI,
    TASK_PROGRESS_RESOURCE_V6_URI,
    TASK_PROGRESS_RESOURCE_V7_URI,
    TASK_PROGRESS_RESOURCE_V8_URI,
    TASK_PROGRESS_RESOURCE_V9_URI,
    TaskProgressEventV1,
    TaskProgressSnapshotV1,
    build_task_progress_event,
    project_task_progress,
    task_progress_model_payload,
    task_progress_telemetry,
    task_progress_text,
)
from jsonschema import Draft202012Validator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT_SCHEMA = ROOT / "contracts/task-progress/v1/task-progress-snapshot.schema.json"
EVENT_SCHEMA = ROOT / "contracts/task-progress/v1/task-progress-event.schema.json"


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _room(db: Session, *, owner: str = "owner-a", run_id: str = "run-1") -> CollaborationRoom:
    now = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
    room = CollaborationRoom(
        id=run_id,
        owner_subject=owner,
        title="Task progress rollout",
        project_path="/home/robot/projects/gateway",
        repository_identity="gitlab:project:170",
        base_commit="a" * 40,
        status="active",
        policy={},
        created_at=now,
        updated_at=now,
    )
    db.add(room)
    db.commit()
    return room


def _work_item(db: Session, room: CollaborationRoom, *, item_id: str, status: str, priority: int, updated_at: datetime, result: dict | None = None) -> AgentWorkItem:
    item = AgentWorkItem(
        id=item_id,
        owner_subject=room.owner_subject,
        room_id=room.id,
        title=f"Stage {item_id}",
        description=f"Description {item_id}",
        status=status,
        priority=priority,
        version=1,
        base_commit=room.base_commit,
        dependencies=[],
        acceptance_criteria=["contract", "tests"],
        required_capabilities=[],
        assignment_constraints={},
        result=result or {},
        created_at=updated_at - timedelta(minutes=5),
        updated_at=updated_at,
    )
    db.add(item)
    db.commit()
    return item


def test_task_progress_contract_constants_and_json_schemas() -> None:
    assert TASK_PROGRESS_CAPABILITY_ID == "atlas.task_progress_ui/v1"
    assert TASK_PROGRESS_RESOURCE_V1_URI == "ui://atlas/task-progress/v1.html"
    assert TASK_PROGRESS_RESOURCE_V2_URI == "ui://atlas/task-progress/v2.html"
    assert TASK_PROGRESS_RESOURCE_V3_URI == "ui://atlas/task-progress/v3.html"
    assert TASK_PROGRESS_RESOURCE_V4_URI == "ui://atlas/task-progress/v4.html"
    assert TASK_PROGRESS_RESOURCE_V5_URI == "ui://atlas/task-progress/v5.html"
    assert TASK_PROGRESS_RESOURCE_V6_URI == "ui://atlas/task-progress/v6.html"
    assert TASK_PROGRESS_RESOURCE_V7_URI == "ui://atlas/task-progress/v7.html"
    assert TASK_PROGRESS_RESOURCE_V8_URI == "ui://atlas/task-progress/v8.html"
    assert TASK_PROGRESS_RESOURCE_V9_URI == "ui://atlas/task-progress/v9.html"
    assert TASK_PROGRESS_RESOURCE_URI == "ui://atlas/task-progress/v10.html"
    assert TASK_PROGRESS_RESOURCE_MIME == "text/html;profile=mcp-app"
    assert TASK_PROGRESS_EVENT_TYPES
    Draft202012Validator.check_schema(json.loads(SNAPSHOT_SCHEMA.read_text(encoding="utf-8")))
    Draft202012Validator.check_schema(json.loads(EVENT_SCHEMA.read_text(encoding="utf-8")))


def test_projection_is_owner_scoped_and_determinate(db: Session) -> None:
    room = _room(db)
    now = datetime(2026, 9, 1, 1, 10, tzinfo=UTC)
    _work_item(db, room, item_id="stage-complete", status="completed", priority=80, updated_at=now, result={"acceptance": [True, True]})
    _work_item(db, room, item_id="stage-running", status="in_progress", priority=90, updated_at=now + timedelta(seconds=1), result={"acceptance": [True, {"status": "pending"}]})
    snapshot = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    assert isinstance(snapshot, TaskProgressSnapshotV1)
    assert snapshot.status == "running"
    assert snapshot.progress.mode == "determinate"
    assert snapshot.progress.completed == 1
    assert snapshot.progress.total == 2
    assert snapshot.current_stage_id == "stage-running"
    assert snapshot.project == "gateway"
    assert snapshot.source.project_path == "gateway"
    assert snapshot.source.repository == "gitlab:project:170"
    assert [stage.id for stage in snapshot.stages] == ["stage-running", "stage-complete"]
    assert snapshot.stages[0].acceptance_passed == 1
    assert snapshot.stages[1].acceptance_passed == 2
    with pytest.raises(HTTPException) as exc_info:
        project_task_progress(db, owner_subject="owner-b", run_id=room.id)
    assert exc_info.value.status_code == 404


def test_projection_without_planned_work_is_indeterminate(db: Session) -> None:
    room = _room(db)
    snapshot = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    assert snapshot.status == "queued"
    assert snapshot.progress.mode == "indeterminate"
    assert snapshot.progress.completed is None
    assert snapshot.progress.total is None
    assert "%" not in task_progress_text(snapshot)
    assert "indeterminate" in task_progress_text(snapshot)


def test_projection_exposes_unknown_without_false_success(db: Session) -> None:
    room = _room(db)
    now = datetime(2026, 9, 1, 1, 20, tzinfo=UTC)
    db.add(AgentCommand(
        id="command-unknown",
        owner_subject=room.owner_subject,
        room_id=room.id,
        issuer_agent_id="issuer",
        target_agent_id="executor",
        kind="run_tool",
        instruction="deploy",
        structured_payload={},
        constraints={},
        priority=90,
        status="accepted",
        requires_approval=False,
        result={"outcome_unknown": True},
        created_at=now,
        updated_at=now,
    ))
    db.commit()
    snapshot = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    assert snapshot.status == "unknown"
    assert snapshot.blockers[0].kind == "reconciliation"
    assert snapshot.blockers[0].status == "unknown"
    assert snapshot.cancel_supported is False


def test_projection_redacts_delivery_and_bounds_absolute_paths(db: Session) -> None:
    room = _room(db)
    now = datetime(2026, 9, 1, 1, 30, tzinfo=UTC)
    _work_item(db, room, item_id="delivery", status="in_progress", priority=100, updated_at=now, result={"ci": {"status": "running", "authorization": "Bearer should-not-leak", "nested": {"api_key": "should-not-leak"}}})
    db.add(FileChangeSet(
        id="change-1",
        owner_subject=room.owner_subject,
        origin="server",
        room_id=room.id,
        path="/home/robot/projects/gateway/services/gateway-api/gateway_api/task_progress.py",
        operation="write",
        added_lines=20,
        removed_lines=1,
        bytes_before=0,
        bytes_after=200,
        replacements=0,
        diff_json={},
        truncated=False,
        suppressed=False,
        created_at=now,
    ))
    db.commit()
    snapshot = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    assert snapshot.delivery["ci"]["authorization"] == "[redacted]"
    assert snapshot.delivery["ci"]["nested"]["api_key"] == "[redacted]"
    assert snapshot.changes["paths"] == ["task_progress.py"]
    encoded = snapshot.model_dump_json()
    assert "should-not-leak" not in encoded
    assert "/home/robot/" not in encoded


def test_sequence_advances_with_authoritative_updated_at(db: Session) -> None:
    room = _room(db)
    first_time = datetime(2026, 9, 1, 1, 40, tzinfo=UTC)
    item = _work_item(db, room, item_id="sequence", status="in_progress", priority=50, updated_at=first_time)
    first = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    item.status = "completed"
    item.updated_at = first_time + timedelta(seconds=2)
    item.version += 1
    db.commit()
    second = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    assert second.sequence > first.sequence
    assert second.status == "succeeded"
    assert second.progress.completed == 1


def test_model_payload_and_event_are_bounded_and_schema_valid(db: Session) -> None:
    room = _room(db)
    now = datetime(2026, 9, 1, 1, 50, tzinfo=UTC)
    _work_item(db, room, item_id="model-visible", status="blocked", priority=100, updated_at=now)
    snapshot = project_task_progress(db, owner_subject=room.owner_subject, run_id=room.id)
    model_payload = task_progress_model_payload(snapshot)
    assert set(model_payload) == {"schema_version", "capability", "run_id", "status", "current_stage", "progress", "blocker", "sequence", "updated_at"}
    assert "resources" not in model_payload
    assert "delivery" not in model_payload
    event = build_task_progress_event(
        snapshot,
        event_type="gateway.task_progress.blocked.v1",
        source_type="agent_work_item",
        source_id="model-visible",
        payload={"password": "should-not-leak", "reason": "waiting"},
    )
    assert isinstance(event, TaskProgressEventV1)
    assert event.sequence == snapshot.sequence
    assert event.payload["password"] == "[redacted]"
    assert "should-not-leak" not in event.model_dump_json()
    snapshot_schema = json.loads(SNAPSHOT_SCHEMA.read_text(encoding="utf-8"))
    event_schema = json.loads(EVENT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(snapshot_schema).validate(snapshot.model_dump(mode="json"))
    Draft202012Validator(event_schema).validate(event.model_dump(mode="json"))


def test_task_progress_telemetry_uses_bounded_status_labels() -> None:
    before = task_progress_telemetry.snapshot()["snapshots"]
    task_progress_telemetry.record_snapshot("running")
    task_progress_telemetry.record_snapshot("not-a-public-status")
    current = task_progress_telemetry.snapshot()
    assert current["snapshots"] == before + 2
    assert "not-a-public-status" not in current["status"]
    lines = task_progress_telemetry.prometheus_lines()
    assert any("gateway_task_progress_snapshots_total" in line for line in lines)
    assert not any("owner" in line or "run_id" in line for line in lines)
