# ruff: noqa: B008
from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_role
from ..cold_history import (
    ColdHistoryClient,
    ColdHistoryProtocolError,
    ColdHistoryUnavailable,
    merge_history_pages,
)
from ..database import get_db
from ..dto import (
    GatewayReplicaOut,
    OutboxDeliveryAttemptOut,
    OutboxEventOut,
    OutboxReplayRequest,
    RealtimeRouteOut,
)
from ..metrics_cache import GatewayMetricsCache
from ..models import (
    AuditEvent,
    GatewayReplica,
    OutboxDeliveryAttempt,
    OutboxEvent,
    RealtimeRoute,
    User,
)
from ..runtime import GatewayRuntime

router = APIRouter(prefix="/api/operations", tags=["operations"])
metrics_router = APIRouter(tags=["metrics"])


def _runtime(request: Request) -> GatewayRuntime:
    runtime = getattr(request.app.state, "gateway_runtime", None)
    if not isinstance(runtime, GatewayRuntime):
        raise HTTPException(status_code=503, detail="Gateway runtime is unavailable")
    return runtime


def _cold_history(request: Request) -> ColdHistoryClient | None:
    client = getattr(request.app.state, "cold_history_client", None)
    if client is None:
        return None
    if not isinstance(client, ColdHistoryClient):
        raise HTTPException(status_code=503, detail="Cold history client is unavailable")
    return client


def _cold_history_unavailable(error: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail="Cold outbox history is temporarily unavailable")


def _event_payload(row: OutboxEvent) -> dict[str, Any]:
    return OutboxEventOut.model_validate(row).model_dump(mode="json")


def _attempt_payload(row: OutboxDeliveryAttempt) -> dict[str, Any]:
    return OutboxDeliveryAttemptOut.model_validate(row).model_dump(mode="json")


async def _archived_event_bundle(
    request: Request,
    event_id: str,
) -> tuple[OutboxEventOut, list[OutboxDeliveryAttemptOut]]:
    cold = _cold_history(request)
    if cold is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    try:
        archived = await cold.get_event(event_id)
        attempts = await cold.list_event_attempts(event_id)
    except ColdHistoryUnavailable as exc:
        raise _cold_history_unavailable(exc) from exc
    except ColdHistoryProtocolError as exc:
        raise HTTPException(status_code=502, detail="Cold outbox history payload is invalid") from exc
    if archived is None or attempts is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    try:
        event_model = OutboxEventOut.model_validate(archived)
        attempt_models = [OutboxDeliveryAttemptOut.model_validate(item) for item in attempts]
    except ValidationError as exc:
        raise HTTPException(status_code=502, detail="Cold outbox history payload is invalid") from exc
    if event_model.id != event_id or event_model.status not in {
        "published",
        "dead_letter",
        "cancelled",
    }:
        raise HTTPException(status_code=502, detail="Cold outbox history payload is invalid")
    attempt_ids: set[str] = set()
    attempt_numbers: set[int] = set()
    for attempt in attempt_models:
        if attempt.outbox_event_id != event_id:
            raise HTTPException(status_code=502, detail="Cold outbox history payload is invalid")
        if attempt.id in attempt_ids or attempt.attempt_number in attempt_numbers:
            raise HTTPException(status_code=502, detail="Cold outbox history payload is invalid")
        attempt_ids.add(attempt.id)
        attempt_numbers.add(attempt.attempt_number)
    return event_model, sorted(
        attempt_models,
        key=lambda item: (item.attempt_number, item.id),
    )


async def _reject_cold_only_mutation(
    request: Request,
    db: Session,
    event_id: str,
) -> None:
    if db.get(OutboxEvent, event_id) is not None:
        return
    cold = _cold_history(request)
    if cold is None:
        return
    try:
        archived = await cold.get_event(event_id)
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    if archived is not None:
        raise HTTPException(
            status_code=409,
            detail="Outbox event is archived in cold history and must be rehydrated before mutation",
        )


def _operations_user(user: User) -> None:
    require_role(user, "gateway-auditor", "gateway-admin")


def _metrics_cache(request: Request) -> GatewayMetricsCache:
    cache = getattr(request.app.state, "metrics_cache", None)
    if not isinstance(cache, GatewayMetricsCache):
        raise HTTPException(status_code=503, detail="Metrics cache is unavailable")
    return cache


@router.get("/outbox", response_model=list[OutboxEventOut])
async def list_outbox_events(
    request: Request,
    status: str | None = None,
    event_type: str | None = None,
    owner_subject: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OutboxEvent | dict[str, Any]]:
    _operations_user(user)
    query = db.query(OutboxEvent)
    if status:
        query = query.filter(OutboxEvent.status == status)
    if event_type:
        query = query.filter(OutboxEvent.event_type == event_type)
    if owner_subject:
        query = query.filter(OutboxEvent.owner_subject == owner_subject)
    hot_rows = (
        query.order_by(OutboxEvent.created_at.desc(), OutboxEvent.id.desc())
        .limit(limit)
        .all()
    )
    cold = _cold_history(request)
    if cold is None:
        return hot_rows
    try:
        cold_page = await cold.list_events(
            status=status,
            event_type=event_type,
            owner_subject=owner_subject,
            limit=limit,
        )
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    merged, _ = merge_history_pages(
        [_event_payload(row) for row in hot_rows],
        cold_page.items,
        timestamp_key="created_at",
        limit=limit,
        hot_has_more=False,
        cold_has_more=cold_page.has_more,
    )
    return merged


@router.get("/outbox/{event_id}", response_model=OutboxEventOut)
async def get_outbox_event(
    event_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent | dict[str, Any]:
    _operations_user(user)
    event = db.get(OutboxEvent, event_id)
    if event is not None:
        return event
    cold = _cold_history(request)
    if cold is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    try:
        archived = await cold.get_event(event_id)
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    if archived is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    return archived


@router.get(
    "/outbox/{event_id}/attempts",
    response_model=list[OutboxDeliveryAttemptOut],
)
async def list_outbox_attempts(
    event_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OutboxDeliveryAttempt | dict[str, Any]]:
    _operations_user(user)
    if db.get(OutboxEvent, event_id) is not None:
        return (
            db.query(OutboxDeliveryAttempt)
            .filter(OutboxDeliveryAttempt.outbox_event_id == event_id)
            .order_by(OutboxDeliveryAttempt.attempt_number, OutboxDeliveryAttempt.id)
            .all()
        )
    cold = _cold_history(request)
    if cold is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    try:
        attempts = await cold.list_event_attempts(event_id)
    except (ColdHistoryUnavailable, ColdHistoryProtocolError) as exc:
        raise _cold_history_unavailable(exc) from exc
    if attempts is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    return attempts


@router.post("/outbox/{event_id}/rehydrate", response_model=OutboxEventOut)
async def rehydrate_outbox_event(
    event_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent:
    require_role(user, "gateway-admin")
    existing = db.get(OutboxEvent, event_id)
    if existing is not None:
        return existing
    event_model, attempt_models = await _archived_event_bundle(request, event_id)
    if db.get(AuditEvent, event_model.audit_event_id) is None:
        raise HTTPException(
            status_code=409,
            detail="Cold outbox event cannot be rehydrated because its audit event is unavailable",
        )
    event = OutboxEvent(
        id=event_model.id,
        audit_event_id=event_model.audit_event_id,
        owner_subject=event_model.owner_subject,
        event_type=event_model.event_type,
        subject=event_model.subject,
        payload=event_model.payload,
        headers=event_model.headers,
        status=event_model.status,
        attempt_count=event_model.attempt_count,
        max_attempts=event_model.max_attempts,
        available_at=event_model.available_at,
        locked_by=event_model.locked_by,
        lock_token=None,
        locked_at=event_model.locked_at,
        published_at=event_model.published_at,
        broker_stream=event_model.broker_stream,
        broker_sequence=event_model.broker_sequence,
        last_error=event_model.last_error,
        replay_count=event_model.replay_count,
        replayed_from_id=event_model.replayed_from_id,
        created_at=event_model.created_at,
        updated_at=event_model.updated_at,
    )
    try:
        db.add(event)
        # No ORM relationship links OutboxEvent to OutboxDeliveryAttempt, so
        # PostgreSQL cannot rely on SQLAlchemy's unit-of-work ordering here.
        # Flush the FK parent before staging archived delivery attempts.
        db.flush()
        for attempt_model in attempt_models:
            db.add(
                OutboxDeliveryAttempt(
                    id=attempt_model.id,
                    outbox_event_id=attempt_model.outbox_event_id,
                    attempt_number=attempt_model.attempt_number,
                    replica_id=attempt_model.replica_id,
                    status=attempt_model.status,
                    error=attempt_model.error,
                    broker_stream=attempt_model.broker_stream,
                    broker_sequence=attempt_model.broker_sequence,
                    started_at=attempt_model.started_at,
                    completed_at=attempt_model.completed_at,
                )
            )
        db.add(
            AuditEvent(
                id=str(uuid4()),
                event_type="gateway.outbox.history.rehydrated.v1",
                actor_subject=user.subject,
                action="outbox_history_rehydrate",
                resource_type="outbox_event",
                resource_id=event_id,
                status="success",
                payload={
                    "source": "cold_history",
                    "event_type": event_model.event_type,
                    "delivery_attempt_count": len(attempt_models),
                },
            )
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Outbox event rehydration conflicted with existing hot history",
        ) from exc
    db.refresh(event)
    return event


@router.post("/outbox/{event_id}/replay", response_model=OutboxEventOut)
async def replay_outbox_event(
    event_id: str,
    payload: OutboxReplayRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent:
    require_role(user, "gateway-admin")
    await _reject_cold_only_mutation(request, db, event_id)
    try:
        event = _runtime(request).outbox.replay(
            db,
            event_id=event_id,
            actor_subject=user.subject,
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return event


@router.post("/outbox/{event_id}/cancel", response_model=OutboxEventOut)
async def cancel_outbox_event(
    event_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent:
    require_role(user, "gateway-admin")
    await _reject_cold_only_mutation(request, db, event_id)
    try:
        return _runtime(request).outbox.cancel(
            db, event_id=event_id, actor_subject=user.subject
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/outbox/drain")
async def drain_outbox(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    user: User = Depends(get_current_user),
) -> dict[str, int]:
    require_role(user, "gateway-admin")
    result = await _runtime(request).outbox.run_once(limit=limit)
    return {
        "claimed": result.claimed,
        "published": result.published,
        "retried": result.retried,
        "dead_lettered": result.dead_lettered,
    }


@router.get("/metrics")
async def operations_metrics(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _operations_user(user)
    return _metrics_cache(request).snapshot()


@router.get("/replicas", response_model=list[GatewayReplicaOut])
async def list_replicas(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[GatewayReplica]:
    _operations_user(user)
    return db.query(GatewayReplica).order_by(GatewayReplica.last_heartbeat_at.desc()).all()


@router.get("/realtime-routes", response_model=list[RealtimeRouteOut])
async def list_realtime_routes(
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[RealtimeRoute]:
    _operations_user(user)
    query = db.query(RealtimeRoute)
    if status:
        query = query.filter(RealtimeRoute.status == status)
    return query.order_by(RealtimeRoute.last_seen_at.desc()).limit(1000).all()


@metrics_router.get("/metrics")
async def prometheus_metrics(request: Request) -> Response:
    return Response(
        _metrics_cache(request).prometheus(),
        media_type="text/plain; version=0.0.4",
    )
