from __future__ import annotations

import base64
import hashlib
import secrets
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..auth import create_jwt, get_current_user
from ..config import Settings, get_settings
from ..database import get_db
from ..models import OAuthClient, OAuthCode, User, utcnow

router = APIRouter(tags=["oauth"])


def _base(request: Request, settings: Settings) -> str:
    return settings.public_base_url.rstrip("/") or str(request.base_url).rstrip("/")


def oauth_metadata(base_url: str, settings: Settings) -> dict[str, Any]:
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "revocation_endpoint": f"{base_url}/oauth/revoke",
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        "scopes_supported": settings.supported_scopes,
    }


def oauth_client_metadata(base_url: str, settings: Settings) -> dict[str, Any]:
    client_id = f"{base_url}/oauth/client-metadata.json"
    return {
        "client_id": client_id,
        "client_name": settings.app_name,
        "client_uri": base_url,
        "redirect_uris": [f"{base_url}/mcp-connections"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def protected_resource_metadata(base_url: str, settings: Settings) -> dict[str, Any]:
    return {
        "resource": settings.oauth_audience,
        "authorization_servers": [base_url],
        "scopes_supported": settings.supported_scopes,
        "resource_documentation": f"{base_url}/health",
    }


def _split_scope(value: str | None) -> list[str]:
    if not value:
        return []
    return list(dict.fromkeys(value.replace(",", " ").split()))


def _extension_scopes(settings: Settings) -> list[str]:
    scopes = _split_scope(settings.gateway_browser_extension_oauth_scopes)
    if not scopes or not set(scopes).issubset(settings.supported_scopes):
        raise RuntimeError(
            "Browser extension OAuth scopes must be supported Gateway scopes"
        )
    return scopes


def _validated_scope(requested: str | None, *, allowed: list[str]) -> str:
    requested_scopes = _split_scope(requested) or list(allowed)
    if not requested_scopes or not set(requested_scopes).issubset(allowed):
        raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    return " ".join(requested_scopes)


def _is_extension_identity(
    client_id: str,
    redirect_uris: list[str],
    settings: Settings,
) -> bool:
    exact_redirect = settings.gateway_browser_extension_redirect_uri
    id_matches = client_id == settings.gateway_browser_extension_client_id
    redirect_matches = exact_redirect in redirect_uris
    if id_matches or redirect_matches:
        if not id_matches or redirect_uris != [exact_redirect]:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Browser extension OAuth identity must use the pinned "
                    "client and redirect URI"
                ),
            )
        return True
    return False


def _is_allowed_redirect(uri: str, settings: Settings) -> bool:
    return (
        uri == settings.gateway_browser_extension_redirect_uri
        or uri.startswith("https://chatgpt.com/connector/oauth/")
        or uri == "https://chatgpt.com/connector_platform_oauth_redirect"
        or uri.startswith("http://localhost:")
        or uri.startswith("http://127.0.0.1:")
    )


def _pkce_s256(verifier: str) -> str:
    try:
        encoded = verifier.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid PKCE verifier") from exc
    digest = hashlib.sha256(encoded).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@router.get("/.well-known/oauth-protected-resource")
async def well_known_resource(
    request: Request, settings: Settings = Depends(get_settings)
) -> dict[str, Any]:
    return protected_resource_metadata(_base(request, settings), settings)


@router.get("/.well-known/oauth-protected-resource/mcp")
async def well_known_resource_mcp(
    request: Request, settings: Settings = Depends(get_settings)
) -> dict[str, Any]:
    return protected_resource_metadata(_base(request, settings), settings)


@router.get("/.well-known/oauth-authorization-server")
async def well_known_oauth(
    request: Request, settings: Settings = Depends(get_settings)
) -> dict[str, Any]:
    return oauth_metadata(_base(request, settings), settings)


@router.get("/.well-known/openid-configuration")
async def well_known_openid(
    request: Request, settings: Settings = Depends(get_settings)
) -> dict[str, Any]:
    metadata = oauth_metadata(_base(request, settings), settings)
    metadata["subject_types_supported"] = ["public"]
    metadata["id_token_signing_alg_values_supported"] = ["HS256"]
    return metadata


@router.get("/oauth/client-metadata.json")
async def client_metadata_document(
    request: Request, settings: Settings = Depends(get_settings)
) -> dict[str, Any]:
    return oauth_client_metadata(_base(request, settings), settings)


@router.post("/oauth/register", status_code=201)
async def register_client(
    payload: dict[str, Any],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    raw_redirect_uris = payload.get("redirect_uris", [])
    if not isinstance(raw_redirect_uris, list):
        raise HTTPException(status_code=400, detail="Unsupported redirect_uri")
    redirect_uris = [str(uri) for uri in raw_redirect_uris]
    if not redirect_uris:
        raise HTTPException(status_code=400, detail="Unsupported redirect_uri")
    client_id = str(payload.get("client_id") or f"chatgpt-{secrets.token_urlsafe(18)}")
    is_extension = _is_extension_identity(client_id, redirect_uris, settings)
    if any(not _is_allowed_redirect(uri, settings) for uri in redirect_uris):
        raise HTTPException(status_code=400, detail="Unsupported redirect_uri")
    allowed_scopes = (
        _extension_scopes(settings) if is_extension else settings.supported_scopes
    )
    requested_scope = payload.get("scope")
    if requested_scope is not None and not isinstance(requested_scope, str):
        raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    if (
        is_extension
        and requested_scope is not None
        and _split_scope(requested_scope) != allowed_scopes
    ):
        raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    client = OAuthClient(
        client_id=client_id,
        client_name=str(
            payload.get("client_name")
            or (
                "ATLAS ChatGPT Browser Extension"
                if is_extension
                else "ChatGPT Connector"
            )
        ),
        redirect_uris=redirect_uris,
        scope=_validated_scope(requested_scope, allowed=allowed_scopes),
    )
    db.merge(client)
    db.commit()
    return {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": client.scope,
    }


@router.get("/oauth/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    request: Request,
    code_challenge_method: str = "S256",
    scope: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if response_type != "code" or code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="Unsupported OAuth request")
    if not code_challenge or len(code_challenge) > 255:
        raise HTTPException(status_code=400, detail="Invalid PKCE challenge")
    is_extension = _is_extension_identity(client_id, [redirect_uri], settings)
    if not _is_allowed_redirect(redirect_uri, settings):
        raise HTTPException(status_code=400, detail="Unsupported redirect_uri")
    try:
        user = await get_current_user(request, db=db, settings=settings)
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        return RedirectResponse(
            url=f"/auth/login?{urlencode({'next': next_path})}",
            status_code=307,
        )
    client = db.get(OAuthClient, client_id)
    if client is None:
        if not _is_allowed_redirect(redirect_uri, settings):
            raise HTTPException(status_code=400, detail="Unsupported redirect_uri")
        initial_scopes = (
            _extension_scopes(settings) if is_extension else settings.supported_scopes
        )
        client = OAuthClient(
            client_id=client_id,
            client_name=(
                "ATLAS ChatGPT Browser Extension"
                if is_extension
                else "Auto-registered MCP client"
            ),
            redirect_uris=[redirect_uri],
            scope=" ".join(initial_scopes),
        )
        db.add(client)
        db.commit()
    if redirect_uri not in client.redirect_uris or not _is_allowed_redirect(
        redirect_uri, settings
    ):
        raise HTTPException(status_code=400, detail="redirect_uri is not registered")
    client_scopes = _split_scope(client.scope)
    if not client_scopes or not set(client_scopes).issubset(settings.supported_scopes):
        raise HTTPException(
            status_code=400, detail="OAuth client has invalid registered scope"
        )
    if is_extension:
        if client.redirect_uris != [settings.gateway_browser_extension_redirect_uri]:
            raise HTTPException(
                status_code=400,
                detail="Browser extension OAuth redirect configuration mismatch",
            )
        if set(client_scopes) != set(_extension_scopes(settings)):
            raise HTTPException(
                status_code=400,
                detail="Browser extension OAuth client scope configuration mismatch",
            )
    authorized_scope = _validated_scope(scope, allowed=client_scopes)
    if is_extension and _split_scope(authorized_scope) != _extension_scopes(settings):
        raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    code = secrets.token_urlsafe(36)
    auth_code = OAuthCode(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        scope=authorized_scope,
        subject=user.subject,
        expires_at=utcnow() + timedelta(seconds=settings.gateway_auth_code_ttl_seconds),
    )
    db.add(auth_code)
    db.commit()
    query = {"code": code}
    if state is not None:
        query["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(query)}",
        status_code=307,
    )


@router.post("/oauth/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    is_extension = _is_extension_identity(client_id, [redirect_uri], settings)
    auth_code = db.get(OAuthCode, code)
    if (
        auth_code is None
        or auth_code.consumed
        or auth_code.client_id != client_id
        or auth_code.redirect_uri != redirect_uri
    ):
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    expires_at = auth_code.expires_at
    if expires_at.tzinfo is None:
        from datetime import timezone

        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < utcnow():
        raise HTTPException(status_code=400, detail="Authorization code expired")
    oauth_client = db.get(OAuthClient, client_id)
    if oauth_client is None:
        raise HTTPException(status_code=400, detail="OAuth client is not registered")
    if redirect_uri not in oauth_client.redirect_uris or not _is_allowed_redirect(
        redirect_uri, settings
    ):
        raise HTTPException(status_code=400, detail="redirect_uri is not registered")
    client_scopes = _split_scope(oauth_client.scope)
    code_scopes = _split_scope(auth_code.scope)
    if (
        not client_scopes
        or not set(client_scopes).issubset(settings.supported_scopes)
        or not code_scopes
        or not set(code_scopes).issubset(client_scopes)
    ):
        raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    if is_extension:
        if oauth_client.redirect_uris != [
            settings.gateway_browser_extension_redirect_uri
        ]:
            raise HTTPException(
                status_code=400,
                detail="Browser extension OAuth redirect configuration mismatch",
            )
        extension_scopes = _extension_scopes(settings)
        if set(client_scopes) != set(extension_scopes):
            raise HTTPException(
                status_code=400,
                detail="Browser extension OAuth client scope configuration mismatch",
            )
        if code_scopes != extension_scopes:
            raise HTTPException(status_code=400, detail="Invalid OAuth scope")
    expected_challenge = _pkce_s256(code_verifier)
    if not secrets.compare_digest(expected_challenge, auth_code.code_challenge):
        raise HTTPException(status_code=400, detail="Invalid PKCE verifier")
    user = db.query(User).filter(User.subject == auth_code.subject).one()
    auth_code.consumed = True
    db.commit()
    token_ttl_seconds = (
        settings.gateway_browser_extension_access_token_ttl_seconds
        if is_extension
        else settings.gateway_access_token_ttl_seconds
    )
    access_token = create_jwt(
        subject=user.subject,
        username=user.username,
        roles=user.roles,
        scopes=code_scopes,
        token_type="access",
        ttl_seconds=token_ttl_seconds,
        extra={
            "client_id": client_id,
            "presentation_profile": oauth_client.presentation_profile,
            "presentation_policy_generation": oauth_client.presentation_policy_generation,
            "presentation_mode": oauth_client.presentation_mode,
            "chat_context_mode": oauth_client.chat_context_mode,
            "presentation_capabilities": list(
                oauth_client.presentation_capabilities or []
            ),
            "workspace_plan": oauth_client.workspace_plan,
            "allowed_tool_names": list(oauth_client.allowed_tool_names or []),
        },
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": token_ttl_seconds,
            "scope": " ".join(code_scopes),
        }
    )


@router.post("/oauth/revoke")
async def revoke() -> dict[str, bool]:
    return {"ok": True}


@router.get("/oauth/userinfo")
async def userinfo(user: User = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "sub": user.subject,
        "preferred_username": user.username,
        "email": user.email,
        "roles": user.roles,
    }
