from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import get_db
from .models import User, utcnow


def ensure_user(
    db: Session,
    *,
    subject: str,
    username: str,
    email: str | None,
    roles: list[str],
    provider: str,
) -> User:
    user = db.query(User).filter(User.subject == subject).one_or_none()
    if user is None:
        user = User(subject=subject, username=username, email=email, roles=roles, provider=provider)
        db.add(user)
    else:
        user.username = username
        user.email = email
        user.roles = roles
        user.provider = provider
        user.last_seen_at = utcnow()
    db.commit()
    db.refresh(user)
    return user


def dev_user(db: Session, settings: Settings | None = None) -> User:
    settings = settings or get_settings()
    return ensure_user(
        db,
        subject=settings.gateway_dev_subject,
        username=settings.gateway_dev_username,
        email=settings.gateway_dev_email,
        roles=settings.dev_roles,
        provider="dev",
    )


def create_jwt(
    *,
    subject: str,
    username: str,
    roles: list[str],
    scopes: list[str],
    token_type: str,
    ttl_seconds: int,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "aud": settings.oauth_audience,
        "sub": subject,
        "preferred_username": username,
        "realm_access": {"roles": roles},
        "scope": " ".join(scopes),
        "typ": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.gateway_jwt_secret, algorithm="HS256")


def decode_jwt(token: str, *, verify_exp: bool = True) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(
        token,
        settings.gateway_jwt_secret,
        algorithms=["HS256"],
        audience=settings.oauth_audience,
        issuer=settings.issuer,
        options={"verify_exp": verify_exp},
    )


def roles_from_claims(claims: dict[str, Any]) -> list[str]:
    access = claims.get("realm_access") or {}
    roles = access.get("roles") or claims.get("roles") or []
    return [str(role) for role in roles]


async def exchange_keycloak_code(code: str, redirect_uri: str) -> dict[str, Any]:
    settings = get_settings()
    token_url = f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        token_response = await client.post(token_url, data=data)
        token_response.raise_for_status()
        token_payload = token_response.json()
        userinfo_url = f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/userinfo"
        user_response = await client.get(userinfo_url, headers={"Authorization": f"Bearer {token_payload['access_token']}"})
        user_response.raise_for_status()
        claims = user_response.json()
    id_token = token_payload.get("id_token")
    if id_token:
        try:
            id_claims = jwt.decode(id_token, options={"verify_signature": False})
            claims.update({k: v for k, v in id_claims.items() if k not in claims})
        except Exception:
            pass
    return claims


def _user_from_claims(db: Session, claims: dict[str, Any], provider: str) -> User:
    subject = str(claims.get("sub"))
    username = str(claims.get("preferred_username") or claims.get("email") or subject)
    email = claims.get("email")
    roles = roles_from_claims(claims)
    if provider == "keycloak" and "gateway-user" not in roles:
        roles.append("gateway-user")
    return ensure_user(db, subject=subject, username=username, email=email, roles=roles, provider=provider)


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    cookie = request.cookies.get(settings.gateway_session_cookie)
    if cookie:
        try:
            claims = decode_jwt(cookie)
            return _user_from_claims(db, claims, provider="session")
        except Exception:
            if not settings.gateway_dev_auth:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = decode_jwt(token)
            return _user_from_claims(db, claims, provider="token")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    if settings.gateway_dev_auth:
        return dev_user(db, settings)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


async def get_bearer_or_dev_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    return await get_current_user(request, db=db, settings=settings)


def require_role(user: User, *allowed: str) -> None:
    roles = set(user.roles or [])
    if "gateway-admin" in roles:
        return
    if not roles.intersection(allowed):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Policy denied")
