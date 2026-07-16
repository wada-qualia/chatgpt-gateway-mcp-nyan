from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..auth import create_jwt, decode_jwt, dev_user, exchange_keycloak_code, ensure_user, get_current_user, roles_from_claims
from ..config import Settings, get_settings
from ..database import get_db
from ..dto import UserOut
from ..events import emit_event
from ..models import User

router = APIRouter(prefix="/auth", tags=["auth"])


def _oauth_state_cookie(settings: Settings) -> str:
    return f"{settings.gateway_session_cookie}_oauth_state"


def _safe_next_path(value: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@router.get("/login")
async def login(request: Request, next: str = "/", settings: Settings = Depends(get_settings)) -> RedirectResponse:
    if settings.gateway_dev_auth:
        callback_query = urlencode({"dev": "1", "next": _safe_next_path(next)})
        return RedirectResponse(url=f"/auth/callback?{callback_query}", status_code=307)
    redirect_uri = f"{settings.public_base_url.rstrip('/')}/auth/callback"
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    next_path = _safe_next_path(next)
    params = {
        "client_id": settings.keycloak_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": _pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    url = f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/auth?{urlencode(params)}"
    flow_token = create_jwt(
        subject="oauth:login",
        username="oauth-login",
        roles=[],
        scopes=[],
        token_type="oauth_state",
        ttl_seconds=settings.gateway_auth_code_ttl_seconds,
        extra={"oauth_state": state, "code_verifier": code_verifier, "next": next_path},
    )
    response = RedirectResponse(url=url, status_code=307)
    response.set_cookie(
        _oauth_state_cookie(settings),
        flow_token,
        httponly=True,
        secure=settings.public_base_url.lower().startswith("https://"),
        samesite="lax",
        max_age=settings.gateway_auth_code_ttl_seconds,
        path="/auth",
    )
    return response


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    dev: str | None = None,
    next: str = "/",
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if settings.gateway_dev_auth and dev:
        user = dev_user(db, settings)
        next_path = _safe_next_path(next)
    else:
        if error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_description or error,
            )
        flow_cookie = request.cookies.get(_oauth_state_cookie(settings))
        if not code or not state or not flow_cookie:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth callback state")
        try:
            flow = decode_jwt(flow_cookie)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state") from exc
        expected_state = str(flow.get("oauth_state") or "")
        code_verifier = str(flow.get("code_verifier") or "")
        if flow.get("typ") != "oauth_state" or not expected_state or not code_verifier:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state payload")
        if not secrets.compare_digest(state, expected_state):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OAuth state mismatch")
        next_path = _safe_next_path(str(flow.get("next") or "/"))
        claims = await exchange_keycloak_code(
            code,
            f"{settings.public_base_url.rstrip('/')}/auth/callback",
            code_verifier,
        )
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
    response = RedirectResponse(url=next_path, status_code=307)
    response.set_cookie(
        settings.gateway_session_cookie,
        token,
        httponly=True,
        secure=settings.public_base_url.lower().startswith("https://"),
        samesite="lax",
    )
    response.delete_cookie(_oauth_state_cookie(settings), path="/auth")
    return response


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut(subject=user.subject, username=user.username, email=user.email, roles=user.roles, provider=user.provider)


@router.post("/logout")
async def logout(response: Response, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    response.delete_cookie(settings.gateway_session_cookie)
    return {"ok": True}
