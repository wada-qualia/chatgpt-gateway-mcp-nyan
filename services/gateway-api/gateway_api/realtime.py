from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import WebSocket
from sqlalchemy.orm import Session, sessionmaker

from .broker import EventBroker
from .config import Settings
from .models import (
    AgentInstance,
    ProcessedBrokerMessage,
    RealtimeNotification,
    RealtimeRoute,
    utcnow,
)


class LocalRealtimeHub:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._targets: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def register(
        self,
        *,
        owner_subject: str,
        target_kind: str,
        target_id: str,
        connection_id: str,
        websocket: WebSocket,
    ) -> None:
        async with self._lock:
            self._connections[connection_id] = websocket
            self._targets[(owner_subject, target_kind, target_id)].add(connection_id)

    async def unregister(self, connection_id: str) -> None:
        async with self._lock:
            self._connections.pop(connection_id, None)
            for key, connection_ids in list(self._targets.items()):
                connection_ids.discard(connection_id)
                if not connection_ids:
                    self._targets.pop(key, None)

    async def send(
        self,
        *,
        owner_subject: str,
        target_kind: str,
        target_id: str,
        payload: dict[str, Any],
    ) -> int:
        async with self._lock:
            connection_ids = list(
                self._targets.get((owner_subject, target_kind, target_id), set())
            )
            connections = [
                (connection_id, self._connections.get(connection_id))
                for connection_id in connection_ids
            ]
        delivered = 0
        for connection_id, websocket in connections:
            if websocket is None:
                continue
            try:
                await websocket.send_json(payload)
                delivered += 1
            except Exception:
                await self.unregister(connection_id)
        return delivered


class RealtimeService:
    def __init__(
        self,
        *,
        session_factory: sessionmaker,
        broker: EventBroker,
        settings: Settings,
        replica_id: str,
    ) -> None:
        self.session_factory = session_factory
        self.broker = broker
        self.settings = settings
        self.replica_id = replica_id
        self.hub = LocalRealtimeHub()
        self._subscription: Any = None

    async def start(self) -> None:
        if self._subscription is not None:
            return
        prefix = self.settings.gateway_nats_subject_prefix.strip(".")
        self._subscription = await self.broker.subscribe(
            f"{prefix}.>", self._on_broker_event
        )

    async def stop(self) -> None:
        self._subscription = None

    def register_route(
        self,
        db: Session,
        *,
        owner_subject: str,
        target_kind: str,
        target_id: str,
        connection_id: str,
        meta: dict[str, Any] | None = None,
    ) -> RealtimeRoute:
        now = utcnow()
        route = (
            db.query(RealtimeRoute)
            .filter(
                RealtimeRoute.owner_subject == owner_subject,
                RealtimeRoute.target_kind == target_kind,
                RealtimeRoute.target_id == target_id,
                RealtimeRoute.connection_id == connection_id,
            )
            .one_or_none()
        )
        if route is None:
            route = RealtimeRoute(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                target_kind=target_kind,
                target_id=target_id,
                connection_id=connection_id,
                replica_id=self.replica_id,
                status="online",
                meta=dict(meta or {}),
                connected_at=now,
                last_seen_at=now,
                expires_at=now
                + timedelta(seconds=self.settings.gateway_realtime_route_ttl_seconds),
            )
            db.add(route)
        else:
            route.replica_id = self.replica_id
            route.status = "online"
            route.meta = dict(meta or route.meta or {})
            route.last_seen_at = now
            route.expires_at = now + timedelta(
                seconds=self.settings.gateway_realtime_route_ttl_seconds
            )
            route.disconnected_at = None
        db.commit()
        db.refresh(route)
        return route

    def heartbeat_route(self, db: Session, *, connection_id: str) -> RealtimeRoute | None:
        route = (
            db.query(RealtimeRoute)
            .filter(
                RealtimeRoute.connection_id == connection_id,
                RealtimeRoute.replica_id == self.replica_id,
            )
            .one_or_none()
        )
        if route is None:
            return None
        now = utcnow()
        route.status = "online"
        route.last_seen_at = now
        route.expires_at = now + timedelta(
            seconds=self.settings.gateway_realtime_route_ttl_seconds
        )
        db.commit()
        db.refresh(route)
        return route

    def unregister_route(self, db: Session, *, connection_id: str) -> None:
        route = (
            db.query(RealtimeRoute)
            .filter(
                RealtimeRoute.connection_id == connection_id,
                RealtimeRoute.replica_id == self.replica_id,
            )
            .one_or_none()
        )
        if route is None:
            return
        now = utcnow()
        route.status = "offline"
        route.expires_at = now
        route.disconnected_at = now
        db.commit()

    @staticmethod
    def _target_agent_ids(db: Session, envelope: dict[str, Any], replica_id: str) -> list[str]:
        owner_subject = str(envelope.get("actor_subject") or "")
        if not owner_subject:
            return []
        event_type = str(envelope.get("event_type") or "")
        payload = dict(envelope.get("payload") or {})
        direct_targets: list[str] = []
        if event_type == "gateway.agent.message.sent.v1":
            direct_targets = [str(value) for value in payload.get("recipient_agent_ids") or []]
        elif event_type == "gateway.agent.command.issued.v1":
            target = payload.get("target_agent_id")
            direct_targets = [str(target)] if target else []
        elif event_type.startswith("gateway.resource_lease."):
            room_id = payload.get("room_id")
            if room_id:
                direct_targets = [
                    str(agent_id)
                    for (agent_id,) in db.query(AgentInstance.id)
                    .filter(
                        AgentInstance.owner_subject == owner_subject,
                        AgentInstance.current_room_id == str(room_id),
                    )
                    .all()
                ]
        elif event_type in {
            "gateway.agent.registered.v1",
            "gateway.agent.heartbeat.v1",
            "gateway.agent.unregistered.v1",
            "gateway.agent.room_joined.v1",
        }:
            room_id = payload.get("room_id")
            source_agent_id = str(payload.get("agent_id") or "")
            if room_id:
                direct_targets = [
                    str(agent_id)
                    for (agent_id,) in db.query(AgentInstance.id)
                    .filter(
                        AgentInstance.owner_subject == owner_subject,
                        AgentInstance.current_room_id == str(room_id),
                        AgentInstance.id != source_agent_id,
                    )
                    .all()
                ]
        if not direct_targets:
            return []
        local_routes = (
            db.query(RealtimeRoute.target_id)
            .filter(
                RealtimeRoute.owner_subject == owner_subject,
                RealtimeRoute.replica_id == replica_id,
                RealtimeRoute.target_kind == "agent",
                RealtimeRoute.status == "online",
                RealtimeRoute.expires_at > utcnow(),
                RealtimeRoute.target_id.in_(list(dict.fromkeys(direct_targets))),
            )
            .distinct()
            .all()
        )
        return [str(target_id) for (target_id,) in local_routes]

    async def _on_broker_event(
        self, subject: str, payload: bytes, headers: dict[str, str]
    ) -> None:
        try:
            wire_payload = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        event_type = str(
            headers.get("X-Gateway-Event-Type")
            or wire_payload.get("event_type")
            or ""
        )
        actor_subject = str(
            headers.get("X-Gateway-Actor-Subject")
            or wire_payload.get("actor_subject")
            or ""
        )
        if not event_type or not actor_subject:
            return
        event_payload = (
            dict(wire_payload.get("payload") or {})
            if "payload" in wire_payload and "event_type" in wire_payload
            else dict(wire_payload)
        )
        envelope = {
            "event_id": str(wire_payload.get("event_id") or ""),
            "event_type": event_type,
            "actor_subject": actor_subject,
            "action": str(headers.get("X-Gateway-Action") or ""),
            "resource_type": str(headers.get("X-Gateway-Resource-Type") or ""),
            "resource_id": str(headers.get("X-Gateway-Resource-Id") or "") or None,
            "status": str(headers.get("X-Gateway-Status") or "success"),
            "payload": event_payload,
            "wire_payload": wire_payload,
        }
        message_id = str(
            headers.get("Nats-Msg-Id")
            or headers.get("X-Gateway-Event-Id")
            or wire_payload.get("event_id")
            or ""
        )
        dedupe_id = f"{self.replica_id}:{message_id}" if message_id else ""
        with self.session_factory() as db:
            if dedupe_id and db.get(ProcessedBrokerMessage, dedupe_id) is not None:
                return
            target_ids = self._target_agent_ids(db, envelope, self.replica_id)
            notifications: list[RealtimeNotification] = []
            now = utcnow()
            for target_id in target_ids:
                notification = RealtimeNotification(
                    id=str(uuid.uuid4()),
                    owner_subject=str(envelope.get("actor_subject") or ""),
                    target_kind="agent",
                    target_id=target_id,
                    event_type=event_type,
                    payload=envelope,
                    status="pending",
                    replica_id=self.replica_id,
                    expires_at=now
                    + timedelta(
                        seconds=self.settings.gateway_realtime_notification_ttl_seconds
                    ),
                    created_at=now,
                    updated_at=now,
                )
                db.add(notification)
                notifications.append(notification)
            if dedupe_id:
                db.add(
                    ProcessedBrokerMessage(
                        message_id=dedupe_id,
                        stream=self.settings.gateway_nats_stream,
                        consumer=f"realtime-{self.replica_id}",
                        subject=subject,
                        payload_sha256=hashlib.sha256(payload).hexdigest(),
                    )
                )
            db.commit()
            for notification in notifications:
                db.refresh(notification)
                delivered = await self.hub.send(
                    owner_subject=notification.owner_subject,
                    target_kind=notification.target_kind,
                    target_id=notification.target_id,
                    payload={
                        "type": "notification",
                        "notification_id": notification.id,
                        "event_type": notification.event_type,
                        "payload": notification.payload,
                    },
                )
                notification.attempt_count += 1
                if delivered:
                    notification.status = "delivered"
                    notification.delivered_at = utcnow()
                notification.updated_at = utcnow()
            if notifications:
                db.commit()

    def list_notifications(
        self,
        db: Session,
        *,
        owner_subject: str,
        target_kind: str,
        target_id: str,
        status: str | None = None,
        limit: int = 100,
    ) -> list[RealtimeNotification]:
        query = db.query(RealtimeNotification).filter(
            RealtimeNotification.owner_subject == owner_subject,
            RealtimeNotification.target_kind == target_kind,
            RealtimeNotification.target_id == target_id,
            RealtimeNotification.expires_at > utcnow(),
        )
        if status:
            query = query.filter(RealtimeNotification.status == status)
        return (
            query.order_by(RealtimeNotification.created_at, RealtimeNotification.id)
            .limit(max(1, min(limit, 500)))
            .all()
        )

    def acknowledge_notification(
        self,
        db: Session,
        *,
        owner_subject: str,
        target_kind: str,
        target_id: str,
        notification_id: str,
    ) -> RealtimeNotification:
        notification = (
            db.query(RealtimeNotification)
            .filter(
                RealtimeNotification.id == notification_id,
                RealtimeNotification.owner_subject == owner_subject,
                RealtimeNotification.target_kind == target_kind,
                RealtimeNotification.target_id == target_id,
            )
            .one_or_none()
        )
        if notification is None:
            raise LookupError("Realtime notification not found")
        notification.status = "acknowledged"
        notification.acknowledged_at = utcnow()
        notification.updated_at = notification.acknowledged_at
        db.commit()
        db.refresh(notification)
        return notification


def notification_payload(notification: RealtimeNotification) -> dict[str, Any]:
    return {
        "id": notification.id,
        "target_kind": notification.target_kind,
        "target_id": notification.target_id,
        "event_type": notification.event_type,
        "payload": notification.payload,
        "status": notification.status,
        "replica_id": notification.replica_id,
        "attempt_count": notification.attempt_count,
        "delivered_at": notification.delivered_at.isoformat()
        if notification.delivered_at
        else None,
        "acknowledged_at": notification.acknowledged_at.isoformat()
        if notification.acknowledged_at
        else None,
        "created_at": notification.created_at.isoformat(),
    }
