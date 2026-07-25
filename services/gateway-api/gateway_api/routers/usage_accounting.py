# ruff: noqa: B008
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ..auth import LupPrincipal, get_lup_principal, require_role
from ..database import get_db
from ..dto import (
    LupFinalResponseAbandonCreate,
    LupFinalResponseCompleteCreate,
    LupTaskStartCreate,
    LupTaskStartOut,
    LupTaskTerminalOut,
    LupToolCallCreate,
    LupToolCallOut,
    LupToolPhaseSealCreate,
    LupToolPhaseSealOut,
)
from ..usage_accounting import LUP_SDK_VERSION
from ..usage_correlation import LangfuseCorrelationAdapter

router = APIRouter(prefix="/api/host/usage/tasks", tags=["usage-accounting"])
correlation_adapter = LangfuseCorrelationAdapter()


@router.post(
    "/start",
    response_model=LupTaskStartOut,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "description": "The source message already has the same durable task-start binding."
        },
        status.HTTP_409_CONFLICT: {
            "description": "The source message is already bound to another session or trace."
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "LUP accounting or durable acceptance is unavailable."
        },
    },
)
async def start_host_task(
    payload: LupTaskStartCreate,
    request: Request,
    response: Response,
    principal: LupPrincipal = Depends(get_lup_principal),
    db: Session = Depends(get_db),
) -> dict:
    require_role(principal.user, "gateway-user")
    runtime = request.app.state.gateway_runtime
    active_traceparent = getattr(request.state, "traceparent", None)
    resolved_trace_id = correlation_adapter.resolve_trace_id(
        explicit_trace_id=payload.trace_id,
        inbound_traceparent=request.headers.get("traceparent"),
        active_traceparent=active_traceparent,
    )
    result = await runtime.usage_accounting.start_task(
        db,
        owner_subject=principal.user.subject,
        principal_token=principal.token,
        source_message_id=payload.source_message_id,
        session_id=payload.session_id,
        trace_id=resolved_trace_id,
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    task = result.task
    correlation = _correlation_binding(
        task,
        request_id=(
            correlation_adapter.request_id_from_traceparent(
                active_traceparent, expected_trace_id=task.trace_id
            )
            or task.start_event_id
        ),
    )
    return {
        "task_usage_id": task.task_usage_id,
        "correlation_id": task.correlation_id,
        "start_event_id": task.start_event_id,
        "source_message_id": task.source_message_id,
        "session_id": task.session_id,
        "trace_id": task.trace_id,
        "correlation": correlation,
        "receipt_status": task.receipt_status,
        "receipt_id": task.receipt_id,
        "accepted_at": task.accepted_at,
        "broker_provider": task.broker_provider,
        "stream_sequence": task.stream_sequence,
        "receipt_correlation_id": task.receipt_correlation_id,
        "project_attribution_status": task.project_attribution_status,
        "project_attribution_source": task.project_attribution_source,
        "project_atlas_project_key": task.project_atlas_project_key,
        "project_atlas_entity_id": task.project_atlas_entity_id,
        "project_git_commit": task.project_git_commit,
        "project_git_branch": task.project_git_branch,
        "sdk_version": LUP_SDK_VERSION,
        "created": result.created,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
    }


@router.post(
    "/tool-calls",
    response_model=LupToolCallOut,
    status_code=status.HTTP_201_CREATED,
)
async def record_host_tool_call(
    payload: LupToolCallCreate,
    request: Request,
    response: Response,
    principal: LupPrincipal = Depends(get_lup_principal),
    db: Session = Depends(get_db),
) -> dict:
    require_role(principal.user, "gateway-user")
    result = (
        await request.app.state.gateway_runtime.usage_tool_lifecycle.record_tool_call(
            db,
            owner_subject=principal.user.subject,
            principal_token=principal.token,
            payload=payload,
        )
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    call = result.call
    correlation = _correlation_binding(
        result.task,
        request_id=call.request_id or call.callback_id,
        tool_call_id=call.tool_call_id,
        command_session_id=call.command_session_id,
    )
    return {
        "callback_event_id": call.callback_event_id,
        "task_usage_id": call.task_usage_id,
        "correlation_id": result.task.correlation_id,
        "trace_id": result.task.trace_id,
        "correlation": correlation,
        "source_message_id": call.source_message_id,
        "session_id": call.session_id,
        "callback_id": call.callback_id,
        "tool_call_id": call.tool_call_id,
        "command_session_id": call.command_session_id,
        "request_id": call.request_id,
        "observation_event_id": call.observation_event_id,
        "observation_id": call.observation_id,
        "observation_published": call.observation_id is not None,
        "receipt_status": call.receipt_status,
        "receipt_id": call.receipt_id,
        "accepted_at": call.accepted_at,
        "broker_provider": call.broker_provider,
        "stream_sequence": call.stream_sequence,
        "receipt_correlation_id": call.receipt_correlation_id,
        "occurred_at": call.occurred_at,
        "created": result.created,
        "created_at": call.created_at,
        "updated_at": call.updated_at,
    }


@router.post(
    "/tool-phase/seal",
    response_model=LupToolPhaseSealOut,
    status_code=status.HTTP_201_CREATED,
)
async def seal_host_tool_phase(
    payload: LupToolPhaseSealCreate,
    request: Request,
    response: Response,
    principal: LupPrincipal = Depends(get_lup_principal),
    db: Session = Depends(get_db),
) -> dict:
    require_role(principal.user, "gateway-user")
    result = (
        await request.app.state.gateway_runtime.usage_tool_lifecycle.seal_tool_phase(
            db,
            owner_subject=principal.user.subject,
            principal_token=principal.token,
            source_message_id=payload.source_message_id,
            session_id=payload.session_id,
            sealed_at=payload.sealed_at,
        )
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    seal = result.seal
    correlation = _correlation_binding(result.task, request_id=seal.seal_event_id)
    return {
        "seal_event_id": seal.seal_event_id,
        "task_usage_id": seal.task_usage_id,
        "correlation_id": result.task.correlation_id,
        "trace_id": result.task.trace_id,
        "correlation": correlation,
        "source_message_id": seal.source_message_id,
        "session_id": seal.session_id,
        "last_observation_event_id": seal.last_observation_event_id,
        "last_observation_id": seal.last_observation_id,
        "receipt_status": seal.receipt_status,
        "receipt_id": seal.receipt_id,
        "accepted_at": seal.accepted_at,
        "broker_provider": seal.broker_provider,
        "stream_sequence": seal.stream_sequence,
        "receipt_correlation_id": seal.receipt_correlation_id,
        "sealed_at": seal.sealed_at,
        "created": result.created,
        "created_at": seal.created_at,
        "updated_at": seal.updated_at,
    }


@router.post(
    "/final-response/complete",
    response_model=LupTaskTerminalOut,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "description": "The same authenticated terminal callback was already accepted."
        },
        status.HTTP_409_CONFLICT: {
            "description": "The task is already terminal, the tool phase is unsealed, or callback data conflicts."
        },
    },
)
async def complete_host_final_response(
    payload: LupFinalResponseCompleteCreate,
    request: Request,
    response: Response,
    principal: LupPrincipal = Depends(get_lup_principal),
    db: Session = Depends(get_db),
) -> dict:
    require_role(principal.user, "gateway-user")
    result = await request.app.state.gateway_runtime.usage_final_lifecycle.complete(
        db,
        owner_subject=principal.user.subject,
        principal_token=principal.token,
        payload=payload,
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    terminal = result.terminal
    return _terminal_response(result.task, terminal, result.created)


@router.post(
    "/final-response/abandon",
    response_model=LupTaskTerminalOut,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "description": "The same authenticated abandonment callback was already accepted."
        },
        status.HTTP_409_CONFLICT: {
            "description": "The task already has a different terminal lifecycle outcome."
        },
    },
)
async def abandon_host_final_response(
    payload: LupFinalResponseAbandonCreate,
    request: Request,
    response: Response,
    principal: LupPrincipal = Depends(get_lup_principal),
    db: Session = Depends(get_db),
) -> dict:
    require_role(principal.user, "gateway-user")
    result = await request.app.state.gateway_runtime.usage_final_lifecycle.abandon(
        db,
        owner_subject=principal.user.subject,
        principal_token=principal.token,
        payload=payload,
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    terminal = result.terminal
    return _terminal_response(result.task, terminal, result.created)


def _correlation_binding(
    task,
    *,
    request_id: str,
    tool_call_id: str | None = None,
    command_session_id: str | None = None,
) -> dict:
    if task.trace_id is None:
        raise ValueError("LUP task is missing the required W3C trace binding")
    return correlation_adapter.bind(
        trace_id=task.trace_id,
        task_usage_id=task.task_usage_id,
        correlation_id=task.correlation_id,
        session_id=task.session_id,
        request_id=request_id,
        tool_call_id=tool_call_id,
        command_session_id=command_session_id,
    ).as_dict()


def _terminal_response(task, terminal, created: bool) -> dict:
    correlation = _correlation_binding(
        task, request_id=terminal.request_id or terminal.callback_id
    )
    return {
        "terminal_event_id": terminal.terminal_event_id,
        "task_usage_id": terminal.task_usage_id,
        "correlation_id": task.correlation_id,
        "trace_id": task.trace_id,
        "correlation": correlation,
        "source_message_id": terminal.source_message_id,
        "session_id": terminal.session_id,
        "callback_id": terminal.callback_id,
        "terminal_kind": terminal.terminal_kind,
        "completion_mode": terminal.completion_mode,
        "delivery_state": terminal.delivery_state,
        "recovery_id": terminal.recovery_id,
        "reason_code": terminal.reason_code,
        "request_id": terminal.request_id,
        "final_observation_event_id": terminal.final_observation_event_id,
        "final_observation_id": terminal.final_observation_id,
        "observation_receipt_status": terminal.observation_receipt_status,
        "observation_receipt_id": terminal.observation_receipt_id,
        "terminal_receipt_status": terminal.terminal_receipt_status,
        "terminal_receipt_id": terminal.terminal_receipt_id,
        "terminal_at": terminal.terminal_at,
        "created": created,
        "created_at": terminal.created_at,
        "updated_at": terminal.updated_at,
    }
