from __future__ import annotations

import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..auth import create_jwt, dev_user, exchange_keycloak_code, ensure_user, get_current_user, roles_from_claims
from ..config import Settings, get_settings
from ..database import get_db
from ..dto import UserOut
from ..events import emit_event
from ..models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login")
async def login(request: Request, next: str = "/", settings: Settings = Depends(get_settings)) -> RedirectResponse:
    if settings.gateway_dev_auth:
        return RedirectResponse(url=f"/auth/callback?dev=1&next={next}", status_code=307)
    redirect_uri = f"{settings.public_base_url.rstrip()}/auth/callback"
    params = {
        "client_id": settings.keycloak_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "state": secrets.token_urlsafe(24),
    }
    url = f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/auth?{urlencode(params)}"
    return RedirectResponse(url=url, status_code=307)


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    dev: str | None = None,
    next: str = "/",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if settings.gateway_dev_auth and dev:
        user = dev_user(db, settings)
    else:
        claims = await exchange_keycloak_code(code or "", f"{settings.public_base_url.rstrip()}/auth/callback")
        user = ensure_user(
            db,
            subject=str(claims["sub"]),
            username=str(claims.get("preferred_username") or claims.get("email") or claims["sub"]),
            email=claims.get("email"),
            roles=roles_from_claims(claims) or ["gateway-user"],
            provider="keycloak",
        )
    token = create_jwt(
        subject=user.subject,
        username=user.username,
        roles=user.roles,
        scopes=settings.supported_scopes,
        token_type="session",
        ttl_seconds=settings.gateway_access_token_ttl_seconds,
    )
    emit_event(
        db,
        event_type="gateway.user.authenticated.v1",
        actor_subject=user.subject,
        action="authenticated",
        resource_type="user",
        resource_id=user.subject,
        payload={"subject": user.subject, "username": user.username, "provider": user.provider},
    )
    response = RedirectResponse(url=next or "/", status_code=307)
    response.set_cookie(settings.gateway_session_cookie, token, httponly=True, secure=False, samesite="lax")
    return response


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut(subject=user.subject, username=user.username, email=user.email, roles=user.roles, provider=user.provider)


@router.post("/logout")
async def logout(response: Response, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    response.delete_cookie(settings.gateway_session_cookie)
    return {"ok": True}
