# ruff: noqa: B008
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_role
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


def _operations_user(user: User) -> None:
    require_role(user, "gateway-auditor", "gateway-admin")


def _metrics_cache(request: Request) -> GatewayMetricsCache:
    cache = getattr(request.app.state, "metrics_cache", None)
    if not isinstance(cache, GatewayMetricsCache):
        raise HTTPException(status_code=503, detail="Metrics cache is unavailable")
    return cache


@router.get("/outbox", response_model=list[OutboxEventOut])
async def list_outbox_events(
    status: str | None = None,
    event_type: str | None = None,
    owner_subject: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OutboxEvent]:
    _operations_user(user)
    query = db.query(OutboxEvent)
    if status:
        query = query.filter(OutboxEvent.status == status)
    if event_type:
        query = query.filter(OutboxEvent.event_type == event_type)
    if owner_subject:
        query = query.filter(OutboxEvent.owner_subject == owner_subject)
    return query.order_by(OutboxEvent.created_at.desc()).limit(limit).all()


@router.get("/outbox/{event_id}", response_model=OutboxEventOut)
async def get_outbox_event(
    event_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent:
    _operations_user(user)
    event = db.get(OutboxEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    return event


@router.get(
    "/outbox/{event_id}/attempts",
    response_model=list[OutboxDeliveryAttemptOut],
)
async def list_outbox_attempts(
    event_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OutboxDeliveryAttempt]:
    _operations_user(user)
    if db.get(OutboxEvent, event_id) is None:
        raise HTTPException(status_code=404, detail="Outbox event not found")
    return (
        db.query(OutboxDeliveryAttempt)
        .filter(OutboxDeliveryAttempt.outbox_event_id == event_id)
        .order_by(OutboxDeliveryAttempt.attempt_number)
        .all()
    )


@router.post("/outbox/{event_id}/replay", response_model=OutboxEventOut)
async def replay_outbox_event(
    event_id: str,
    payload: OutboxReplayRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OutboxEvent:
    require_role(user, "gateway-admin")
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
