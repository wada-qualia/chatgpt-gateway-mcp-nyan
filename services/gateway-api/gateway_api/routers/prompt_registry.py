from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse, Response

from ..auth import get_current_user
from ..models import User
from ..policy import enforce
from ..prompt_registry_facade import (
    PromptFacadeResult,
    PromptRegistryFacade,
    PromptRegistryFacadeError,
)

router = APIRouter(prefix="/api/prompts/v1", tags=["prompt-registry"])


def _facade(request: Request) -> PromptRegistryFacade:
    facade = getattr(request.app.state, "prompt_registry_facade", None)
    if not isinstance(facade, PromptRegistryFacade):
        raise PromptRegistryFacadeError(
            503,
            "Prompt registry facade is unavailable",
            headers={"Cache-Control": "no-store"},
        )
    return facade


def _response(result: PromptFacadeResult) -> Response:
    if result.status_code == 304:
        return Response(status_code=304, headers=result.headers)
    return JSONResponse(
        result.payload, status_code=result.status_code, headers=result.headers
    )


def _error(exc: PromptRegistryFacadeError) -> JSONResponse:
    return JSONResponse(
        {"detail": exc.detail},
        status_code=exc.status_code,
        headers=exc.headers,
    )


@router.get("/releases/{channel}/manifest")
async def release_manifest(
    channel: str,
    request: Request,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    user: User = Depends(get_current_user),
) -> Response:
    enforce(user, action="read")
    try:
        return _response(
            await _facade(request).get_manifest(channel, browser_etag=if_none_match)
        )
    except PromptRegistryFacadeError as exc:
        return _error(exc)


@router.get("/bundles/{bundle_id}")
async def bundle(
    bundle_id: str,
    request: Request,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    user: User = Depends(get_current_user),
) -> Response:
    enforce(user, action="read")
    try:
        return _response(
            await _facade(request).get_bundle(bundle_id, browser_etag=if_none_match)
        )
    except PromptRegistryFacadeError as exc:
        return _error(exc)
