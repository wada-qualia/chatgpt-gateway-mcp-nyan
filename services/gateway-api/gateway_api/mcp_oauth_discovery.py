from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
import uuid

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .events import emit_event
from .mcp_federation import get_server
from .mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from .models import McpOAuthDiscoverySnapshot, utcnow

_MAX_METADATA_BYTES = 64 * 1024
_PROTECTED_RESOURCE_FIELDS = {
    "resource",
    "authorization_servers",
    "scopes_supported",
    "bearer_methods_supported",
    "resource_signing_alg_values_supported",
    "resource_name",
    "resource_documentation",
}
_AUTHORIZATION_SERVER_FIELDS = {
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "grant_types_supported",
    "code_challenge_methods_supported",
    "token_endpoint_auth_methods_supported",
    "client_id_metadata_document_supported",
    "revocation_endpoint",
    "introspection_endpoint",
    "jwks_uri",
}


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata URL must be an absolute HTTP URL",
            http_status=422,
        )
    hostname = parsed.hostname.lower()
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port
    netloc = hostname if port in {None, default_port} else f"{hostname}:{port}"
    path = parsed.path or ""
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, ""))


def well_known_url(identifier: str, suffix: str) -> str:
    parsed = urlsplit(_canonical_url(identifier))
    path = parsed.path.rstrip("/")
    well_known_path = f"/.well-known/{suffix}{path}"
    return urlunsplit((parsed.scheme, parsed.netloc, well_known_path, parsed.query, ""))


def oidc_discovery_urls(issuer: str) -> tuple[str, ...]:
    canonical = _canonical_url(issuer)
    parsed = urlsplit(canonical)
    appended_path = f"{parsed.path.rstrip('/')}/.well-known/openid-configuration"
    appended = urlunsplit((parsed.scheme, parsed.netloc, appended_path, "", ""))
    inserted = well_known_url(canonical, "openid-configuration")
    return tuple(dict.fromkeys((appended, inserted)))


def _sanitize(document: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    return {key: document[key] for key in sorted(allowed.intersection(document))}


def _scope_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 200:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            f"{field} must be a bounded array",
            http_status=422,
        )
    scopes: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 200 or any(ch.isspace() for ch in item):
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_INVALID",
                f"{field} contains an invalid OAuth scope token",
                http_status=422,
            )
        if item not in scopes:
            scopes.append(item)
    return scopes


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _cache_ttl_seconds(headers: httpx.Headers) -> int:
    default_ttl = 300
    cache_control = headers.get("cache-control", "")
    directives = {
        part.strip().lower()
        for part in cache_control.split(",")
        if part.strip()
    }
    if "no-store" in directives or "no-cache" in directives:
        return 0
    for directive in directives:
        if not directive.startswith("max-age="):
            continue
        raw = directive.split("=", 1)[1].strip().strip('"')
        try:
            return max(0, min(int(raw), 86400))
        except ValueError:
            return default_ttl
    return default_ttl


async def _fetch_json(
    client: httpx.AsyncClient,
    *,
    url: str,
    allow_not_found: bool = False,
) -> tuple[dict[str, Any], int] | None:
    try:
        response = await client.get(
            url,
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )
    except Exception as exc:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_FAILED",
            "OAuth metadata request failed",
            retryable=True,
            http_status=502,
        ) from exc
    if response.status_code == 404 and allow_not_found:
        return None
    if 300 <= response.status_code < 400:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata redirects are not followed",
            http_status=422,
        )
    if response.status_code != 200:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_FAILED",
            f"OAuth metadata endpoint returned HTTP {response.status_code}",
            retryable=response.status_code >= 500,
            http_status=502,
        )
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata response must use a JSON content type",
            http_status=422,
        )
    if len(response.content) > _MAX_METADATA_BYTES:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata response exceeded the bounded size limit",
            http_status=422,
        )
    try:
        value = response.json()
    except Exception as exc:
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata response was not valid JSON",
            http_status=422,
        ) from exc
    if not isinstance(value, dict):
        raise UpstreamMcpError(
            "MCP_AUTH_DISCOVERY_INVALID",
            "OAuth metadata response must be a JSON object",
            http_status=422,
        )
    return value, _cache_ttl_seconds(response.headers)


async def discover_oauth_metadata(
    db: Session,
    *,
    manager: UpstreamMcpManager,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    expected_version: int,
    requested_scopes: list[str],
    authorization_server: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> McpOAuthDiscoverySnapshot:
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    if server.version != expected_version:
        raise HTTPException(status_code=409, detail="Optimistic version conflict")
    if server.origin != "gateway" or not server.endpoint_url:
        raise HTTPException(
            status_code=422,
            detail="OAuth discovery requires a Gateway-origin HTTP MCP server",
        )
    resource = _canonical_url(server.endpoint_url)
    requested = _scope_list(requested_scopes, field="requested_scopes")
    explicit_issuer = (
        _canonical_url(authorization_server)
        if authorization_server is not None
        else None
    )
    now = utcnow()
    latest_snapshot = (
        db.query(McpOAuthDiscoverySnapshot)
        .filter(
            McpOAuthDiscoverySnapshot.owner_subject == owner_subject,
            McpOAuthDiscoverySnapshot.server_id == server.id,
            McpOAuthDiscoverySnapshot.resource == resource,
        )
        .order_by(McpOAuthDiscoverySnapshot.created_at.desc())
        .first()
    )
    if (
        latest_snapshot is not None
        and _as_utc(latest_snapshot.expires_at) > now
        and list(latest_snapshot.requested_scopes) == requested
        and (
            explicit_issuer is None
            or latest_snapshot.authorization_server == explicit_issuer
        )
    ):
        return latest_snapshot
    pinned_issuer = (
        latest_snapshot.authorization_server
        if latest_snapshot is not None
        else None
    )
    resource_metadata_url = well_known_url(resource, "oauth-protected-resource")
    await manager.validate_endpoint(resource_metadata_url, purpose="oauth_resource_metadata")

    owns_client = client is None
    active_client = client or httpx.AsyncClient(
        timeout=manager.connect_timeout_seconds,
        follow_redirects=False,
    )
    try:
        protected_result = await _fetch_json(
            active_client, url=resource_metadata_url
        )
        assert protected_result is not None
        protected, resource_ttl = protected_result
        metadata_resource = protected.get("resource")
        if not isinstance(metadata_resource, str) or _canonical_url(metadata_resource) != resource:
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_AUDIENCE_MISMATCH",
                "Protected resource metadata did not bind to the exact MCP resource URL",
                http_status=422,
            )
        raw_servers = protected.get("authorization_servers")
        if not isinstance(raw_servers, list) or not 1 <= len(raw_servers) <= 10:
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_INVALID",
                "Protected resource metadata must advertise one to ten authorization servers",
                http_status=422,
            )
        issuers: list[str] = []
        for item in raw_servers:
            if not isinstance(item, str):
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_INVALID",
                    "authorization_servers must contain absolute URLs",
                    http_status=422,
                )
            issuer = _canonical_url(item)
            if not issuer.startswith("https://"):
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_INVALID",
                    "OAuth authorization server issuer must use HTTPS",
                    http_status=422,
                )
            if issuer not in issuers:
                issuers.append(issuer)
        if explicit_issuer is not None:
            selected_issuer = explicit_issuer
            if selected_issuer not in issuers:
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_INVALID",
                    "Selected authorization server was not advertised by the resource",
                    http_status=422,
                )
        elif pinned_issuer is not None:
            if pinned_issuer not in issuers:
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_ISSUER_CHANGED",
                    "The pinned authorization server disappeared; explicit re-selection is required",
                    http_status=409,
                )
            selected_issuer = pinned_issuer
        else:
            if len(issuers) != 1:
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_SELECTION_REQUIRED",
                    "Multiple authorization servers were advertised; select one explicitly",
                    http_status=409,
                )
            selected_issuer = issuers[0]
        await manager.validate_endpoint(selected_issuer, purpose="oauth_issuer")

        discovery_candidates = [
            ("rfc8414", well_known_url(selected_issuer, "oauth-authorization-server")),
            *(("openid_connect", url) for url in oidc_discovery_urls(selected_issuer)),
        ]
        authorization_metadata: dict[str, Any] | None = None
        authorization_ttl = 300
        metadata_url = ""
        mechanism = ""
        for candidate_mechanism, candidate_url in discovery_candidates:
            await manager.validate_endpoint(candidate_url, purpose="oauth_server_metadata")
            fetch_result = await _fetch_json(
                active_client,
                url=candidate_url,
                allow_not_found=True,
            )
            if fetch_result is not None:
                authorization_metadata, authorization_ttl = fetch_result
                metadata_url = candidate_url
                mechanism = candidate_mechanism
                break
        if authorization_metadata is None:
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_FAILED",
                "No supported authorization-server metadata endpoint was found",
                http_status=502,
            )
        issuer_claim = authorization_metadata.get("issuer")
        if not isinstance(issuer_claim, str) or _canonical_url(issuer_claim) != selected_issuer:
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_ISSUER_MISMATCH",
                "Authorization-server metadata issuer did not match the selected issuer",
                http_status=422,
            )
        authorization_endpoint = authorization_metadata.get("authorization_endpoint")
        token_endpoint = authorization_metadata.get("token_endpoint")
        if not isinstance(authorization_endpoint, str) or not isinstance(token_endpoint, str):
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_INVALID",
                "Authorization metadata omitted required authorization or token endpoint",
                http_status=422,
            )
        authorization_endpoint = _canonical_url(authorization_endpoint)
        token_endpoint = _canonical_url(token_endpoint)
        if not authorization_endpoint.startswith("https://") or not token_endpoint.startswith("https://"):
            raise UpstreamMcpError(
                "MCP_AUTH_DISCOVERY_INVALID",
                "OAuth authorization and token endpoints must use HTTPS",
                http_status=422,
            )
        await manager.validate_endpoint(authorization_endpoint, purpose="oauth_authorization")
        await manager.validate_endpoint(token_endpoint, purpose="oauth_token")
        manager.validate_resource_audience(resource, metadata_resource)

        resource_scopes = _scope_list(
            protected.get("scopes_supported"), field="resource scopes_supported"
        )
        authorization_scopes = _scope_list(
            authorization_metadata.get("scopes_supported"),
            field="authorization-server scopes_supported",
        )
        if resource_scopes and authorization_scopes:
            available = sorted(set(resource_scopes).intersection(authorization_scopes))
        else:
            available = resource_scopes or authorization_scopes
        if requested:
            unavailable = sorted(set(requested).difference(available)) if available else []
            if unavailable:
                raise UpstreamMcpError(
                    "MCP_AUTH_SCOPE_UNAVAILABLE",
                    f"Requested scopes are not supported: {', '.join(unavailable)}",
                    http_status=422,
                )
            proposed = requested
        else:
            proposed = sorted(available)

        protected_sanitized = _sanitize(protected, _PROTECTED_RESOURCE_FIELDS)
        authorization_sanitized = _sanitize(
            authorization_metadata, _AUTHORIZATION_SERVER_FIELDS
        )
        registration_endpoint = authorization_sanitized.get("registration_endpoint")
        if registration_endpoint is not None:
            if not isinstance(registration_endpoint, str):
                raise UpstreamMcpError(
                    "MCP_AUTH_DISCOVERY_INVALID",
                    "registration_endpoint must be a URL",
                    http_status=422,
                )
            registration_endpoint = _canonical_url(registration_endpoint)
            await manager.validate_endpoint(registration_endpoint, purpose="oauth_registration")

        expires_at = utcnow() + timedelta(
            seconds=min(resource_ttl, authorization_ttl)
        )
        document = {
            "resource": resource,
            "resource_metadata_url": resource_metadata_url,
            "authorization_server": selected_issuer,
            "authorization_server_metadata_url": metadata_url,
            "discovery_mechanism": mechanism,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "registration_endpoint": registration_endpoint,
            "protected_resource_metadata": protected_sanitized,
            "authorization_server_metadata": authorization_sanitized,
            "requested_scopes": requested,
            "proposed_scopes": proposed,
            "expires_at": expires_at,
        }
        metadata_hash = hashlib.sha256(
            json.dumps(
                {**document, "expires_at": expires_at.isoformat()},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        existing = (
            db.query(McpOAuthDiscoverySnapshot)
            .filter(
                McpOAuthDiscoverySnapshot.owner_subject == owner_subject,
                McpOAuthDiscoverySnapshot.server_id == server.id,
                McpOAuthDiscoverySnapshot.metadata_hash == metadata_hash,
            )
            .one_or_none()
        )
        if existing is not None:
            return existing
        snapshot = McpOAuthDiscoverySnapshot(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=server.id,
            metadata_hash=metadata_hash,
            created_by_subject=actor_subject,
            created_at=utcnow(),
            **document,
        )
        db.add(snapshot)
        emit_event(
            db,
            event_type="gateway.mcp.oauth.discovery_completed.v1",
            actor_subject=actor_subject,
            action="discovered",
            resource_type="mcp_oauth_discovery_snapshot",
            resource_id=snapshot.id,
            payload={
                "server_id": server.id,
                "snapshot_id": snapshot.id,
                "metadata_hash": metadata_hash,
                "proposed_scope_count": len(proposed),
                "discovery_mechanism": mechanism,
            },
            commit=False,
        )
        db.commit()
        db.refresh(snapshot)
        return snapshot
    finally:
        if owns_client:
            await active_client.aclose()
