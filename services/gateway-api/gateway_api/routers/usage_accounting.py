from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ..auth import LupPrincipal, get_lup_principal, require_role
from ..database import get_db
from ..dto import LupTaskStartCreate, LupTaskStartOut
from ..usage_accounting import LUP_SDK_VERSION

router = APIRouter(prefix="/api/host/usage/tasks", tags=["usage-accounting"])


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
    result = await runtime.usage_accounting.start_task(
        db,
        owner_subject=principal.user.subject,
        principal_token=principal.token,
        source_message_id=payload.source_message_id,
        session_id=payload.session_id,
        trace_id=payload.trace_id,
    )
    if not result.created:
        response.status_code = status.HTTP_200_OK
    task = result.task
    return {
        "task_usage_id": task.task_usage_id,
        "correlation_id": task.correlation_id,
        "start_event_id": task.start_event_id,
        "source_message_id": task.source_message_id,
        "session_id": task.session_id,
        "trace_id": task.trace_id,
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
