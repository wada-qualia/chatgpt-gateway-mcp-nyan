from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .agent_command_policy import (
    AgentCommandPolicyError,
    assert_no_secret_like_keys,
    validate_agent_command_for_delivery,
)
from .events import emit_event
from .models import (
    ActionReceipt,
    AgentCommand,
    AgentInstance,
    AgentMessage,
    AgentMessageDelivery,
    AgentWorkItem,
    CollaborationRoom,
    utcnow,
)


ACTIVE_AGENT_STATUSES = {"active", "busy", "idle"}
MESSAGE_KINDS = {
    "answer",
    "artifact_reference",
    "barrier",
    "blocker",
    "conflict_warning",
    "handoff",
    "information",
    "proposal",
    "question",
    "review_request",
    "review_result",
    "status_update",
}
COMMAND_TERMINAL_STATUSES = {"cancelled", "completed", "expired", "failed", "rejected"}
WORK_ITEM_STATUSES = {"blocked", "cancelled", "completed", "failed", "in_progress", "open", "review"}


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _bounded_priority(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail="priority must be an integer") from exc
    return max(0, min(parsed, 100))


def _bounded_limit(value: Any, *, maximum: int = 200) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail="limit must be an integer") from exc
    return max(1, min(parsed, maximum))


def _bounded_ttl(value: Any, *, default: int = 120, maximum: int = 3600) -> int:
    try:
        parsed = int(value or default)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail="ttl_seconds must be an integer") from exc
    return max(30, min(parsed, maximum))


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


def _safe_structured(value: Any, *, field: str) -> Any:
    try:
        assert_no_secret_like_keys(value, field=field)
    except AgentCommandPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return value


def agent_payload(agent: AgentInstance) -> dict[str, Any]:
    return {
        "id": agent.id,
        "logical_agent_id": agent.logical_agent_id,
        "instance_id": agent.instance_id,
        "display_name": agent.display_name,
        "status": agent.status,
        "capabilities": list(agent.capabilities or []),
        "labels": dict(agent.labels or {}),
        "current_room_id": agent.current_room_id,
        "current_work_item_id": agent.current_work_item_id,
        "last_heartbeat_at": agent.last_heartbeat_at.isoformat(),
        "expires_at": agent.expires_at.isoformat() if agent.expires_at else None,
        "created_at": agent.created_at.isoformat(),
        "updated_at": agent.updated_at.isoformat(),
    }


def room_payload(room: CollaborationRoom) -> dict[str, Any]:
    return {
        "id": room.id,
        "title": room.title,
        "project_path": room.project_path,
        "repository_identity": room.repository_identity,
        "base_commit": room.base_commit,
        "status": room.status,
        "policy": dict(room.policy or {}),
        "created_by_agent_id": room.created_by_agent_id,
        "created_at": room.created_at.isoformat(),
        "updated_at": room.updated_at.isoformat(),
    }


def message_payload(message: AgentMessage, delivery: AgentMessageDelivery | None = None) -> dict[str, Any]:
    result = {
        "id": message.id,
        "room_id": message.room_id,
        "sender_agent_id": message.sender_agent_id,
        "recipient_agent_id": message.recipient_agent_id,
        "recipient_selector": message.recipient_selector,
        "kind": message.kind,
        "body": message.body,
        "payload": dict(message.payload or {}),
        "priority": message.priority,
        "correlation_id": message.correlation_id,
        "causation_id": message.causation_id,
        "sequence_number": message.sequence_number,
        "expires_at": message.expires_at.isoformat() if message.expires_at else None,
        "created_at": message.created_at.isoformat(),
    }
    if delivery is not None:
        result["delivery"] = {
            "status": delivery.status,
            "attempt_count": delivery.attempt_count,
            "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
            "acknowledged_at": delivery.acknowledged_at.isoformat() if delivery.acknowledged_at else None,
        }
    return result


def command_payload(command: AgentCommand) -> dict[str, Any]:
    return {
        "id": command.id,
        "room_id": command.room_id,
        "issuer_agent_id": command.issuer_agent_id,
        "target_agent_id": command.target_agent_id,
        "kind": command.kind,
        "instruction": command.instruction,
        "structured_payload": dict(command.structured_payload or {}),
        "constraints": dict(command.constraints or {}),
        "priority": command.priority,
        "status": command.status,
        "requires_approval": command.requires_approval,
        "approved_by_subject": command.approved_by_subject,
        "correlation_id": command.correlation_id,
        "causation_id": command.causation_id,
        "delivery_attempts": command.delivery_attempts,
        "delivered_at": command.delivered_at.isoformat() if command.delivered_at else None,
        "acknowledged_at": command.acknowledged_at.isoformat() if command.acknowledged_at else None,
        "accepted_at": command.accepted_at.isoformat() if command.accepted_at else None,
        "completed_at": command.completed_at.isoformat() if command.completed_at else None,
        "expires_at": command.expires_at.isoformat() if command.expires_at else None,
        "result": dict(command.result or {}),
        "error": command.error,
        "created_at": command.created_at.isoformat(),
        "updated_at": command.updated_at.isoformat(),
    }


def work_item_payload(item: AgentWorkItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "room_id": item.room_id,
        "parent_id": item.parent_id,
        "title": item.title,
        "description": item.description,
        "status": item.status,
        "priority": item.priority,
        "assigned_agent_id": item.assigned_agent_id,
        "version": item.version,
        "base_commit": item.base_commit,
        "dependencies": list(item.dependencies or []),
        "acceptance_criteria": list(item.acceptance_criteria or []),
        "required_capabilities": list(item.required_capabilities or []),
        "assignment_constraints": dict(item.assignment_constraints or {}),
        "result": dict(item.result or {}),
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
    }


class AgentCollaborationService:
    def _agent(self, db: Session, *, owner_subject: str, agent_id: str) -> AgentInstance:
        agent = (
            db.query(AgentInstance)
            .filter(AgentInstance.id == agent_id, AgentInstance.owner_subject == owner_subject)
            .one_or_none()
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent

    def _room(self, db: Session, *, owner_subject: str, room_id: str) -> CollaborationRoom:
        room = (
            db.query(CollaborationRoom)
            .filter(CollaborationRoom.id == room_id, CollaborationRoom.owner_subject == owner_subject)
            .one_or_none()
        )
        if room is None:
            raise HTTPException(status_code=404, detail="Collaboration room not found")
        return room

    def _require_agent_in_room(self, agent: AgentInstance, room_id: str) -> None:
        if agent.current_room_id != room_id:
            raise HTTPException(status_code=409, detail="Agent is not joined to the collaboration room")

    def _expire_stale_agents(self, db: Session, *, owner_subject: str) -> None:
        now = utcnow()
        stale = (
            db.query(AgentInstance)
            .filter(AgentInstance.owner_subject == owner_subject, AgentInstance.status.in_(ACTIVE_AGENT_STATUSES))
            .all()
        )
        changed = False
        for agent in stale:
            expires_at = _aware(agent.expires_at)
            if expires_at is not None and expires_at <= now:
                agent.status = "offline"
                agent.updated_at = now
                changed = True
        if changed:
            db.commit()

    def register_agent(self, db: Session, *, owner_subject: str, data: dict[str, Any]) -> AgentInstance:
        logical_agent_id = _required_text(data.get("logical_agent_id"), field="logical_agent_id", maximum=160)
        instance_id = _required_text(data.get("instance_id"), field="instance_id", maximum=160)
        display_name = _optional_text(data.get("display_name"), maximum=160) or logical_agent_id
        ttl_seconds = _bounded_ttl(data.get("ttl_seconds"))
        current_room_id = _optional_text(data.get("room_id"), maximum=36)
        if current_room_id:
            self._room(db, owner_subject=owner_subject, room_id=current_room_id)
        agent = (
            db.query(AgentInstance)
            .filter(AgentInstance.owner_subject == owner_subject, AgentInstance.instance_id == instance_id)
            .one_or_none()
        )
        created = agent is None
        if agent is None:
            agent = AgentInstance(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                logical_agent_id=logical_agent_id,
                instance_id=instance_id,
                display_name=display_name,
            )
            db.add(agent)
        agent.logical_agent_id = logical_agent_id
        agent.display_name = display_name
        agent.status = "active"
        agent.capabilities = sorted({str(value).strip() for value in list(data.get("capabilities") or []) if str(value).strip()})
        agent.labels = dict(_safe_structured(dict(data.get("labels") or {}), field="agent labels"))
        agent.current_room_id = current_room_id
        agent.last_heartbeat_at = utcnow()
        agent.expires_at = agent.last_heartbeat_at + timedelta(seconds=ttl_seconds)
        agent.updated_at = agent.last_heartbeat_at
        emit_event(
            db,
            event_type="gateway.agent.registered.v1",
            actor_subject=owner_subject,
            action="registered" if created else "refreshed",
            resource_type="agent_instance",
            resource_id=agent.id,
            payload={
                "agent_id": agent.id,
                "logical_agent_id": agent.logical_agent_id,
                "instance_id": agent.instance_id,
                "status": agent.status,
                "room_id": agent.current_room_id,
            },
            commit=False,
        )
        db.commit()
        db.refresh(agent)
        return agent

    def list_agents(self, db: Session, *, owner_subject: str, room_id: str | None = None) -> list[AgentInstance]:
        self._expire_stale_agents(db, owner_subject=owner_subject)
        query = db.query(AgentInstance).filter(AgentInstance.owner_subject == owner_subject)
        if room_id:
            self._room(db, owner_subject=owner_subject, room_id=room_id)
            query = query.filter(AgentInstance.current_room_id == room_id)
        return query.order_by(AgentInstance.display_name, AgentInstance.id).all()

    def heartbeat_agent(self, db: Session, *, owner_subject: str, agent_id: str, data: dict[str, Any]) -> AgentInstance:
        agent = self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        room_id = data.get("room_id", agent.current_room_id)
        if room_id:
            room_id = str(room_id)
            self._room(db, owner_subject=owner_subject, room_id=room_id)
        ttl_seconds = _bounded_ttl(data.get("ttl_seconds"))
        agent.status = str(data.get("status") or "active")
        if agent.status not in ACTIVE_AGENT_STATUSES:
            raise HTTPException(status_code=400, detail="Unsupported active agent status")
        if "capabilities" in data:
            agent.capabilities = sorted({str(value).strip() for value in list(data.get("capabilities") or []) if str(value).strip()})
        if "labels" in data:
            agent.labels = dict(_safe_structured(dict(data.get("labels") or {}), field="agent labels"))
        agent.current_room_id = room_id
        agent.last_heartbeat_at = utcnow()
        agent.expires_at = agent.last_heartbeat_at + timedelta(seconds=ttl_seconds)
        agent.updated_at = agent.last_heartbeat_at
        emit_event(
            db,
            event_type="gateway.agent.heartbeat.v1",
            actor_subject=owner_subject,
            action="heartbeat",
            resource_type="agent_instance",
            resource_id=agent.id,
            payload={"agent_id": agent.id, "status": agent.status, "room_id": agent.current_room_id},
            commit=False,
        )
        db.commit()
        db.refresh(agent)
        return agent

    def unregister_agent(self, db: Session, *, owner_subject: str, agent_id: str) -> AgentInstance:
        agent = self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        agent.status = "offline"
        agent.expires_at = utcnow()
        agent.updated_at = utcnow()
        emit_event(
            db,
            event_type="gateway.agent.unregistered.v1",
            actor_subject=owner_subject,
            action="unregistered",
            resource_type="agent_instance",
            resource_id=agent.id,
            payload={"agent_id": agent.id},
            commit=False,
        )
        db.commit()
        db.refresh(agent)
        return agent

    def create_room(self, db: Session, *, owner_subject: str, data: dict[str, Any]) -> CollaborationRoom:
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(CollaborationRoom)
                .filter(
                    CollaborationRoom.owner_subject == owner_subject,
                    CollaborationRoom.idempotency_key == idempotency_key,
                )
                .one_or_none()
            )
            if existing is not None:
                return existing
        created_by_agent_id = _optional_text(data.get("created_by_agent_id"), maximum=36)
        if created_by_agent_id:
            self._agent(db, owner_subject=owner_subject, agent_id=created_by_agent_id)
        room = CollaborationRoom(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            title=_required_text(data.get("title"), field="title", maximum=200),
            project_path=_optional_text(data.get("project_path"), maximum=4096),
            repository_identity=_optional_text(data.get("repository_identity"), maximum=255),
            base_commit=_optional_text(data.get("base_commit"), maximum=128),
            status="active",
            policy=dict(_safe_structured(dict(data.get("policy") or {}), field="room policy")),
            created_by_agent_id=created_by_agent_id,
            idempotency_key=idempotency_key,
        )
        db.add(room)
        try:
            emit_event(
                db,
                event_type="gateway.collaboration.room.created.v1",
                actor_subject=owner_subject,
                action="created",
                resource_type="collaboration_room",
                resource_id=room.id,
                payload={
                    "room_id": room.id,
                    "repository_identity": room.repository_identity,
                    "base_commit": room.base_commit,
                    "created_by_agent_id": room.created_by_agent_id,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(CollaborationRoom)
                    .filter(
                        CollaborationRoom.owner_subject == owner_subject,
                        CollaborationRoom.idempotency_key == idempotency_key,
                    )
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(status_code=409, detail="Collaboration room idempotency conflict") from exc
        db.refresh(room)
        return room

    def list_rooms(self, db: Session, *, owner_subject: str, status: str | None = None) -> list[CollaborationRoom]:
        query = db.query(CollaborationRoom).filter(CollaborationRoom.owner_subject == owner_subject)
        if status:
            query = query.filter(CollaborationRoom.status == status)
        return query.order_by(CollaborationRoom.updated_at.desc()).all()

    def join_room(self, db: Session, *, owner_subject: str, room_id: str, agent_id: str) -> AgentInstance:
        room = self._room(db, owner_subject=owner_subject, room_id=room_id)
        if room.status != "active":
            raise HTTPException(status_code=409, detail="Collaboration room is not active")
        agent = self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        agent.current_room_id = room.id
        agent.status = "active"
        agent.updated_at = utcnow()
        emit_event(
            db,
            event_type="gateway.agent.room_joined.v1",
            actor_subject=owner_subject,
            action="joined",
            resource_type="collaboration_room",
            resource_id=room.id,
            payload={"room_id": room.id, "agent_id": agent.id},
            commit=False,
        )
        db.commit()
        db.refresh(agent)
        return agent

    def _message_recipients(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str,
        sender_agent_id: str,
        recipient_agent_id: str | None,
        recipient_selector: str | None,
    ) -> list[AgentInstance]:
        self._expire_stale_agents(db, owner_subject=owner_subject)
        if recipient_agent_id:
            recipient = self._agent(db, owner_subject=owner_subject, agent_id=recipient_agent_id)
            self._require_agent_in_room(recipient, room_id)
            return [recipient]
        if recipient_selector not in {"all", "room"}:
            raise HTTPException(status_code=400, detail="recipient_agent_id or recipient_selector=room is required")
        recipients = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.owner_subject == owner_subject,
                AgentInstance.current_room_id == room_id,
                AgentInstance.id != sender_agent_id,
                AgentInstance.status.in_(ACTIVE_AGENT_STATUSES),
            )
            .order_by(AgentInstance.id)
            .all()
        )
        if not recipients:
            raise HTTPException(status_code=409, detail="No active message recipients in the room")
        return recipients

    def send_message(self, db: Session, *, owner_subject: str, data: dict[str, Any]) -> tuple[AgentMessage, int]:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        sender_agent_id = _required_text(data.get("sender_agent_id"), field="sender_agent_id", maximum=36)
        room = (
            db.query(CollaborationRoom)
            .filter(CollaborationRoom.id == room_id, CollaborationRoom.owner_subject == owner_subject)
            .with_for_update()
            .one_or_none()
        )
        if room is None:
            raise HTTPException(status_code=404, detail="Collaboration room not found")
        if room.status != "active":
            raise HTTPException(status_code=409, detail="Collaboration room is not active")
        sender = self._agent(db, owner_subject=owner_subject, agent_id=sender_agent_id)
        self._require_agent_in_room(sender, room_id)
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AgentMessage)
                .filter(AgentMessage.owner_subject == owner_subject, AgentMessage.idempotency_key == idempotency_key)
                .one_or_none()
            )
            if existing is not None:
                deliveries = (
                    db.query(AgentMessageDelivery)
                    .filter(
                        AgentMessageDelivery.owner_subject == owner_subject,
                        AgentMessageDelivery.message_id == existing.id,
                    )
                    .count()
                )
                return existing, deliveries
        kind = str(data.get("kind") or "information")
        if kind not in MESSAGE_KINDS:
            raise HTTPException(status_code=400, detail="Unsupported message kind")
        recipient_agent_id = _optional_text(data.get("recipient_agent_id"), maximum=36)
        recipient_selector = _optional_text(data.get("recipient_selector"), maximum=80)
        recipients = self._message_recipients(
            db,
            owner_subject=owner_subject,
            room_id=room_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            recipient_selector=recipient_selector,
        )
        next_sequence = int(
            db.query(func.coalesce(func.max(AgentMessage.sequence_number), 0))
            .filter(AgentMessage.owner_subject == owner_subject, AgentMessage.room_id == room_id)
            .scalar()
            or 0
        ) + 1
        message = AgentMessage(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            recipient_selector=recipient_selector,
            kind=kind,
            body=_required_text(data.get("body"), field="body", maximum=100000),
            payload=dict(_safe_structured(dict(data.get("payload") or {}), field="message payload")),
            priority=_bounded_priority(data.get("priority", 50)),
            correlation_id=_optional_text(data.get("correlation_id"), maximum=160),
            causation_id=_optional_text(data.get("causation_id"), maximum=160),
            sequence_number=next_sequence,
            idempotency_key=idempotency_key,
        )
        db.add(message)
        for recipient in recipients:
            db.add(
                AgentMessageDelivery(
                    id=str(uuid.uuid4()),
                    owner_subject=owner_subject,
                    message_id=message.id,
                    recipient_agent_id=recipient.id,
                )
            )
        try:
            emit_event(
                db,
                event_type="gateway.agent.message.sent.v1",
                actor_subject=owner_subject,
                action="sent",
                resource_type="agent_message",
                resource_id=message.id,
                payload={
                    "message_id": message.id,
                    "room_id": message.room_id,
                    "sender_agent_id": message.sender_agent_id,
                    "recipient_agent_ids": [recipient.id for recipient in recipients],
                    "kind": message.kind,
                    "priority": message.priority,
                    "sequence_number": message.sequence_number,
                    "correlation_id": message.correlation_id,
                    "causation_id": message.causation_id,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(AgentMessage)
                    .filter(AgentMessage.owner_subject == owner_subject, AgentMessage.idempotency_key == idempotency_key)
                    .one_or_none()
                )
                if existing is not None:
                    deliveries = db.query(AgentMessageDelivery).filter(AgentMessageDelivery.message_id == existing.id).count()
                    return existing, deliveries
            raise HTTPException(status_code=409, detail="Message sequence or idempotency conflict") from exc
        db.refresh(message)
        return message, len(recipients)

    def read_inbox(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        limit: int = 50,
        after_message_id: str | None = None,
    ) -> list[tuple[AgentMessage, AgentMessageDelivery]]:
        self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        query = (
            db.query(AgentMessage, AgentMessageDelivery)
            .join(AgentMessageDelivery, AgentMessageDelivery.message_id == AgentMessage.id)
            .filter(
                AgentMessage.owner_subject == owner_subject,
                AgentMessageDelivery.owner_subject == owner_subject,
                AgentMessageDelivery.recipient_agent_id == agent_id,
                AgentMessageDelivery.status != "acknowledged",
                or_(AgentMessage.expires_at.is_(None), AgentMessage.expires_at > utcnow()),
            )
        )
        if after_message_id:
            after = (
                db.query(AgentMessage)
                .filter(AgentMessage.id == after_message_id, AgentMessage.owner_subject == owner_subject)
                .one_or_none()
            )
            if after is None:
                raise HTTPException(status_code=404, detail="Inbox cursor message not found")
            query = query.filter(
                or_(
                    AgentMessage.created_at > after.created_at,
                    and_(AgentMessage.created_at == after.created_at, AgentMessage.id > after.id),
                )
            )
        rows = query.order_by(AgentMessage.priority.desc(), AgentMessage.created_at, AgentMessage.id).limit(_bounded_limit(limit)).all()
        now = utcnow()
        for _, delivery in rows:
            delivery.status = "delivered"
            delivery.attempt_count = int(delivery.attempt_count or 0) + 1
            delivery.delivered_at = now
            delivery.visibility_deadline = now + timedelta(minutes=5)
            delivery.updated_at = now
        if rows:
            db.commit()
        return rows

    def ack_message(self, db: Session, *, owner_subject: str, agent_id: str, message_id: str) -> AgentMessageDelivery:
        self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        row = (
            db.query(AgentMessageDelivery, AgentMessage)
            .join(AgentMessage, AgentMessage.id == AgentMessageDelivery.message_id)
            .filter(
                AgentMessageDelivery.owner_subject == owner_subject,
                AgentMessageDelivery.message_id == message_id,
                AgentMessageDelivery.recipient_agent_id == agent_id,
                AgentMessage.owner_subject == owner_subject,
            )
            .one_or_none()
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Message delivery not found")
        delivery, message = row
        if delivery.status != "acknowledged":
            delivery.status = "acknowledged"
            delivery.acknowledged_at = utcnow()
            delivery.updated_at = delivery.acknowledged_at
            emit_event(
                db,
                event_type="gateway.agent.message.acknowledged.v1",
                actor_subject=owner_subject,
                action="acknowledged",
                resource_type="agent_message",
                resource_id=message.id,
                payload={"message_id": message.id, "room_id": message.room_id, "recipient_agent_id": agent_id},
                commit=False,
            )
            db.commit()
            db.refresh(delivery)
        return delivery

    def issue_command(self, db: Session, *, owner_subject: str, data: dict[str, Any]) -> AgentCommand:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        issuer_agent_id = _required_text(data.get("issuer_agent_id"), field="issuer_agent_id", maximum=36)
        target_agent_id = _required_text(data.get("target_agent_id"), field="target_agent_id", maximum=36)
        self._room(db, owner_subject=owner_subject, room_id=room_id)
        issuer = self._agent(db, owner_subject=owner_subject, agent_id=issuer_agent_id)
        target = self._agent(db, owner_subject=owner_subject, agent_id=target_agent_id)
        self._require_agent_in_room(issuer, room_id)
        self._require_agent_in_room(target, room_id)
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AgentCommand)
                .filter(AgentCommand.owner_subject == owner_subject, AgentCommand.idempotency_key == idempotency_key)
                .one_or_none()
            )
            if existing is not None:
                return existing
        envelope = {
            "kind": str(data.get("kind") or "instruction"),
            "instruction": data.get("instruction"),
            "structured_payload": dict(
                _safe_structured(dict(data.get("structured_payload") or {}), field="command structured_payload")
            ),
        }
        constraints = dict(_safe_structured(dict(data.get("constraints") or {}), field="command constraints"))
        try:
            validate_agent_command_for_delivery(envelope)
        except AgentCommandPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        command = AgentCommand(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            issuer_agent_id=issuer_agent_id,
            target_agent_id=target_agent_id,
            kind=str(envelope["kind"]),
            instruction=_required_text(envelope["instruction"], field="instruction", maximum=100000),
            structured_payload=dict(envelope["structured_payload"]),
            constraints=constraints,
            priority=_bounded_priority(data.get("priority", 50)),
            status="pending",
            requires_approval=bool(data.get("requires_approval", False)),
            correlation_id=_optional_text(data.get("correlation_id"), maximum=160),
            causation_id=_optional_text(data.get("causation_id"), maximum=160),
            idempotency_key=idempotency_key,
        )
        db.add(command)
        try:
            emit_event(
                db,
                event_type="gateway.agent.command.issued.v1",
                actor_subject=owner_subject,
                action="issued",
                resource_type="agent_command",
                resource_id=command.id,
                payload={
                    "command_id": command.id,
                    "room_id": command.room_id,
                    "issuer_agent_id": command.issuer_agent_id,
                    "target_agent_id": command.target_agent_id,
                    "kind": command.kind,
                    "priority": command.priority,
                    "requires_approval": command.requires_approval,
                    "correlation_id": command.correlation_id,
                    "causation_id": command.causation_id,
                },
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(AgentCommand)
                    .filter(AgentCommand.owner_subject == owner_subject, AgentCommand.idempotency_key == idempotency_key)
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(status_code=409, detail="Agent command idempotency conflict") from exc
        db.refresh(command)
        return command

    def list_commands(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        status: str | None = None,
        limit: int = 50,
    ) -> list[AgentCommand]:
        self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        query = db.query(AgentCommand).filter(
            AgentCommand.owner_subject == owner_subject,
            AgentCommand.target_agent_id == agent_id,
            AgentCommand.status.notin_(COMMAND_TERMINAL_STATUSES),
        )
        if status:
            query = db.query(AgentCommand).filter(
                AgentCommand.owner_subject == owner_subject,
                AgentCommand.target_agent_id == agent_id,
                AgentCommand.status == status,
            )
        commands = query.order_by(AgentCommand.priority.desc(), AgentCommand.created_at, AgentCommand.id).limit(_bounded_limit(limit)).all()
        now = utcnow()
        changed = False
        for command in commands:
            expires_at = _aware(command.expires_at)
            if expires_at is not None and expires_at <= now and command.status not in COMMAND_TERMINAL_STATUSES:
                command.status = "expired"
                command.completed_at = now
                command.updated_at = now
                changed = True
            elif command.status == "pending":
                command.status = "delivered"
                command.delivery_attempts = int(command.delivery_attempts or 0) + 1
                command.delivered_at = now
                command.updated_at = now
                changed = True
            elif command.status == "delivered":
                command.delivery_attempts = int(command.delivery_attempts or 0) + 1
                command.delivered_at = now
                command.updated_at = now
                changed = True
        if changed:
            db.commit()
        return commands

    def _target_command(self, db: Session, *, owner_subject: str, agent_id: str, command_id: str) -> AgentCommand:
        command = (
            db.query(AgentCommand)
            .filter(
                AgentCommand.id == command_id,
                AgentCommand.owner_subject == owner_subject,
                AgentCommand.target_agent_id == agent_id,
            )
            .one_or_none()
        )
        if command is None:
            raise HTTPException(status_code=404, detail="Agent command not found")
        return command

    def ack_command(self, db: Session, *, owner_subject: str, agent_id: str, command_id: str) -> AgentCommand:
        command = self._target_command(db, owner_subject=owner_subject, agent_id=agent_id, command_id=command_id)
        if command.status in COMMAND_TERMINAL_STATUSES:
            raise HTTPException(status_code=409, detail="Terminal command cannot be acknowledged")
        if command.status in {"pending", "delivered"}:
            command.status = "acknowledged"
            command.acknowledged_at = utcnow()
            command.updated_at = command.acknowledged_at
            emit_event(
                db,
                event_type="gateway.agent.command.acknowledged.v1",
                actor_subject=owner_subject,
                action="acknowledged",
                resource_type="agent_command",
                resource_id=command.id,
                payload={"command_id": command.id, "room_id": command.room_id, "target_agent_id": agent_id},
                commit=False,
            )
            db.commit()
            db.refresh(command)
        return command

    def accept_command(self, db: Session, *, owner_subject: str, agent_id: str, command_id: str) -> AgentCommand:
        command = self._target_command(db, owner_subject=owner_subject, agent_id=agent_id, command_id=command_id)
        if command.status not in {"pending", "delivered", "acknowledged"}:
            raise HTTPException(status_code=409, detail="Command cannot be accepted from its current status")
        if command.requires_approval and not command.approved_by_subject:
            raise HTTPException(status_code=409, detail="Command requires approval before acceptance")
        command.status = "accepted"
        command.accepted_at = utcnow()
        command.updated_at = command.accepted_at
        emit_event(
            db,
            event_type="gateway.agent.command.accepted.v1",
            actor_subject=owner_subject,
            action="accepted",
            resource_type="agent_command",
            resource_id=command.id,
            payload={"command_id": command.id, "room_id": command.room_id, "target_agent_id": agent_id},
            commit=False,
        )
        db.commit()
        db.refresh(command)
        return command

    def reject_command(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        command_id: str,
        error: str | None = None,
    ) -> AgentCommand:
        command = self._target_command(db, owner_subject=owner_subject, agent_id=agent_id, command_id=command_id)
        if command.status in COMMAND_TERMINAL_STATUSES:
            return command
        command.status = "rejected"
        command.error = _optional_text(error, maximum=10000)
        command.completed_at = utcnow()
        command.updated_at = command.completed_at
        emit_event(
            db,
            event_type="gateway.agent.command.completed.v1",
            actor_subject=owner_subject,
            action="rejected",
            resource_type="agent_command",
            resource_id=command.id,
            payload={"command_id": command.id, "room_id": command.room_id, "status": command.status},
            status="warning",
            commit=False,
        )
        db.commit()
        db.refresh(command)
        return command

    def complete_command(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        command_id: str,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> AgentCommand:
        command = self._target_command(db, owner_subject=owner_subject, agent_id=agent_id, command_id=command_id)
        if command.status not in {"accepted", "running"}:
            raise HTTPException(status_code=409, detail="Command must be accepted before completion")
        if status not in {"completed", "failed"}:
            raise HTTPException(status_code=400, detail="Command completion status must be completed or failed")
        if command.kind == "run_tool" and command.requires_approval:
            receipt = (
                db.query(ActionReceipt)
                .filter(
                    ActionReceipt.owner_subject == owner_subject,
                    ActionReceipt.command_id == command.id,
                    ActionReceipt.executor_agent_id == agent_id,
                )
                .one_or_none()
            )
            if receipt is None:
                raise HTTPException(
                    status_code=409,
                    detail="Privileged command requires an action receipt before completion",
                )
            expected_status = "completed" if receipt.status == "succeeded" else "failed"
            if status != expected_status:
                raise HTTPException(
                    status_code=409,
                    detail="Command completion status does not match action receipt",
                )
        command.status = status
        command.result = dict(_safe_structured(dict(result or {}), field="command result"))
        command.error = _optional_text(error, maximum=10000)
        command.completed_at = utcnow()
        command.updated_at = command.completed_at
        emit_event(
            db,
            event_type="gateway.agent.command.completed.v1",
            actor_subject=owner_subject,
            action=status,
            resource_type="agent_command",
            resource_id=command.id,
            payload={"command_id": command.id, "room_id": command.room_id, "status": command.status},
            status="success" if status == "completed" else "warning",
            commit=False,
        )
        db.commit()
        db.refresh(command)
        return command

    def cancel_command(self, db: Session, *, owner_subject: str, issuer_agent_id: str, command_id: str) -> AgentCommand:
        issuer = self._agent(db, owner_subject=owner_subject, agent_id=issuer_agent_id)
        command = (
            db.query(AgentCommand)
            .filter(
                AgentCommand.id == command_id,
                AgentCommand.owner_subject == owner_subject,
                AgentCommand.issuer_agent_id == issuer.id,
            )
            .one_or_none()
        )
        if command is None:
            raise HTTPException(status_code=404, detail="Agent command not found")
        if command.status in COMMAND_TERMINAL_STATUSES:
            return command
        command.status = "cancelled"
        command.completed_at = utcnow()
        command.updated_at = command.completed_at
        emit_event(
            db,
            event_type="gateway.agent.command.cancelled.v1",
            actor_subject=owner_subject,
            action="cancelled",
            resource_type="agent_command",
            resource_id=command.id,
            payload={"command_id": command.id, "room_id": command.room_id, "issuer_agent_id": issuer.id},
            commit=False,
        )
        db.commit()
        db.refresh(command)
        return command

    def create_work_item(self, db: Session, *, owner_subject: str, data: dict[str, Any]) -> AgentWorkItem:
        room_id = _required_text(data.get("room_id"), field="room_id", maximum=36)
        self._room(db, owner_subject=owner_subject, room_id=room_id)
        idempotency_key = _optional_text(data.get("idempotency_key"), maximum=160)
        if idempotency_key:
            existing = (
                db.query(AgentWorkItem)
                .filter(AgentWorkItem.owner_subject == owner_subject, AgentWorkItem.idempotency_key == idempotency_key)
                .one_or_none()
            )
            if existing is not None:
                return existing
        parent_id = _optional_text(data.get("parent_id"), maximum=36)
        if parent_id:
            parent = (
                db.query(AgentWorkItem)
                .filter(
                    AgentWorkItem.id == parent_id,
                    AgentWorkItem.owner_subject == owner_subject,
                    AgentWorkItem.room_id == room_id,
                )
                .one_or_none()
            )
            if parent is None:
                raise HTTPException(status_code=404, detail="Parent work item not found")
        dependencies = [str(value) for value in list(data.get("dependencies") or [])]
        for dependency_id in dependencies:
            dependency = (
                db.query(AgentWorkItem)
                .filter(
                    AgentWorkItem.id == dependency_id,
                    AgentWorkItem.owner_subject == owner_subject,
                    AgentWorkItem.room_id == room_id,
                )
                .one_or_none()
            )
            if dependency is None:
                raise HTTPException(status_code=404, detail="Work item dependency not found")
        item = AgentWorkItem(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room_id,
            parent_id=parent_id,
            title=_required_text(data.get("title"), field="title", maximum=240),
            description=str(data.get("description") or ""),
            status="open",
            priority=_bounded_priority(data.get("priority", 50)),
            base_commit=_optional_text(data.get("base_commit"), maximum=128),
            dependencies=dependencies,
            acceptance_criteria=[str(value) for value in list(data.get("acceptance_criteria") or [])],
            required_capabilities=[
                str(value).strip()
                for value in list(data.get("required_capabilities") or [])
                if str(value).strip()
            ],
            assignment_constraints=dict(
                _safe_structured(
                    dict(data.get("assignment_constraints") or {}),
                    field="work item assignment constraints",
                )
            ),
            idempotency_key=idempotency_key,
        )
        db.add(item)
        try:
            emit_event(
                db,
                event_type="gateway.work_item.created.v1",
                actor_subject=owner_subject,
                action="created",
                resource_type="agent_work_item",
                resource_id=item.id,
                payload={"work_item_id": item.id, "room_id": item.room_id, "priority": item.priority, "version": item.version},
                commit=False,
            )
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            if idempotency_key:
                existing = (
                    db.query(AgentWorkItem)
                    .filter(AgentWorkItem.owner_subject == owner_subject, AgentWorkItem.idempotency_key == idempotency_key)
                    .one_or_none()
                )
                if existing is not None:
                    return existing
            raise HTTPException(status_code=409, detail="Work item idempotency conflict") from exc
        db.refresh(item)
        return item

    def list_work_items(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str,
        status: str | None = None,
        limit: int = 100,
    ) -> list[AgentWorkItem]:
        self._room(db, owner_subject=owner_subject, room_id=room_id)
        query = db.query(AgentWorkItem).filter(
            AgentWorkItem.owner_subject == owner_subject,
            AgentWorkItem.room_id == room_id,
        )
        if status:
            query = query.filter(AgentWorkItem.status == status)
        return query.order_by(AgentWorkItem.priority.desc(), AgentWorkItem.created_at).limit(_bounded_limit(limit)).all()

    def claim_work_item(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        work_item_id: str,
        expected_version: int,
    ) -> AgentWorkItem:
        agent = self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        item = (
            db.query(AgentWorkItem)
            .filter(AgentWorkItem.id == work_item_id, AgentWorkItem.owner_subject == owner_subject)
            .one_or_none()
        )
        if item is None:
            raise HTTPException(status_code=404, detail="Work item not found")
        self._require_agent_in_room(agent, item.room_id)
        dependencies = list(item.dependencies or [])
        if dependencies:
            completed_count = (
                db.query(AgentWorkItem)
                .filter(
                    AgentWorkItem.owner_subject == owner_subject,
                    AgentWorkItem.room_id == item.room_id,
                    AgentWorkItem.id.in_(dependencies),
                    AgentWorkItem.status == "completed",
                )
                .count()
            )
            if completed_count != len(set(dependencies)):
                raise HTTPException(status_code=409, detail="Work item dependencies are not completed")
        changed = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.id == work_item_id,
                AgentWorkItem.owner_subject == owner_subject,
                AgentWorkItem.status == "open",
                AgentWorkItem.assigned_agent_id.is_(None),
                AgentWorkItem.version == int(expected_version),
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
            raise HTTPException(status_code=409, detail="Work item claim conflict")
        agent.current_work_item_id = work_item_id
        agent.status = "busy"
        agent.updated_at = utcnow()
        db.flush()
        db.expire_all()
        claimed = self._work_item(db, owner_subject=owner_subject, work_item_id=work_item_id)
        emit_event(
            db,
            event_type="gateway.work_item.claimed.v1",
            actor_subject=owner_subject,
            action="claimed",
            resource_type="agent_work_item",
            resource_id=claimed.id,
            payload={
                "work_item_id": claimed.id,
                "room_id": claimed.room_id,
                "agent_id": agent.id,
                "version": claimed.version,
            },
            commit=False,
        )
        db.commit()
        db.refresh(claimed)
        return claimed

    def _work_item(self, db: Session, *, owner_subject: str, work_item_id: str) -> AgentWorkItem:
        item = (
            db.query(AgentWorkItem)
            .filter(AgentWorkItem.id == work_item_id, AgentWorkItem.owner_subject == owner_subject)
            .one_or_none()
        )
        if item is None:
            raise HTTPException(status_code=404, detail="Work item not found")
        return item

    def update_work_item(
        self,
        db: Session,
        *,
        owner_subject: str,
        agent_id: str,
        work_item_id: str,
        expected_version: int,
        data: dict[str, Any],
    ) -> AgentWorkItem:
        agent = self._agent(db, owner_subject=owner_subject, agent_id=agent_id)
        item = self._work_item(db, owner_subject=owner_subject, work_item_id=work_item_id)
        self._require_agent_in_room(agent, item.room_id)
        if item.assigned_agent_id != agent.id:
            raise HTTPException(status_code=403, detail="Only the assigned agent can update the work item")
        status = str(data.get("status") or item.status)
        if status not in WORK_ITEM_STATUSES or status == "open":
            raise HTTPException(status_code=400, detail="Unsupported work item update status")
        values: dict[Any, Any] = {
            AgentWorkItem.status: status,
            AgentWorkItem.version: AgentWorkItem.version + 1,
            AgentWorkItem.updated_at: utcnow(),
        }
        if "result" in data:
            values[AgentWorkItem.result] = dict(
                _safe_structured(dict(data.get("result") or {}), field="work item result")
            )
        if "description" in data:
            values[AgentWorkItem.description] = str(data.get("description") or "")
        changed = (
            db.query(AgentWorkItem)
            .filter(
                AgentWorkItem.id == work_item_id,
                AgentWorkItem.owner_subject == owner_subject,
                AgentWorkItem.assigned_agent_id == agent.id,
                AgentWorkItem.version == int(expected_version),
            )
            .update(values, synchronize_session=False)
        )
        if changed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Work item version conflict")
        if status in {"cancelled", "completed", "failed"}:
            agent.current_work_item_id = None
            agent.status = "active"
            agent.updated_at = utcnow()
        db.flush()
        db.expire_all()
        updated = self._work_item(db, owner_subject=owner_subject, work_item_id=work_item_id)
        emit_event(
            db,
            event_type="gateway.work_item.updated.v1",
            actor_subject=owner_subject,
            action=status,
            resource_type="agent_work_item",
            resource_id=updated.id,
            payload={
                "work_item_id": updated.id,
                "room_id": updated.room_id,
                "agent_id": agent.id,
                "status": updated.status,
                "version": updated.version,
            },
            commit=False,
        )
        db.commit()
        db.refresh(updated)
        return updated

    def room_snapshot(self, db: Session, *, owner_subject: str, room_id: str) -> dict[str, Any]:
        room = self._room(db, owner_subject=owner_subject, room_id=room_id)
        agents = self.list_agents(db, owner_subject=owner_subject, room_id=room_id)
        work_items = self.list_work_items(db, owner_subject=owner_subject, room_id=room_id, limit=100)
        messages = (
            db.query(AgentMessage)
            .filter(AgentMessage.owner_subject == owner_subject, AgentMessage.room_id == room_id)
            .order_by(AgentMessage.created_at.desc())
            .limit(20)
            .all()
        )
        commands = (
            db.query(AgentCommand)
            .filter(AgentCommand.owner_subject == owner_subject, AgentCommand.room_id == room_id)
            .order_by(AgentCommand.created_at.desc())
            .limit(20)
            .all()
        )
        return {
            "room": room_payload(room),
            "agents": [agent_payload(agent) for agent in agents],
            "work_items": [work_item_payload(item) for item in work_items],
            "recent_messages": [message_payload(message) for message in reversed(messages)],
            "recent_commands": [command_payload(command) for command in reversed(commands)],
        }


agent_collaboration_service = AgentCollaborationService()
