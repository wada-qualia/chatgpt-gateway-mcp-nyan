from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from sqlalchemy.orm import Session

from .models import McpRootGrant, McpRuntimeConnection, McpServer, utcnow

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HINT = re.compile(r"^(?:local|gateway)-root:[0-9a-f]{12,64}$")
_MAX_ROOTS = 64


class McpRootFederationError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status

    def as_detail(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


def _label(value: object, *, fallback: str) -> str:
    text = " ".join(str(value or fallback).split())[:240]
    if not text:
        return fallback
    if any(character in text for character in ("/", "\\", "\x00")):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Root labels must not contain host path separators",
            http_status=422,
        )
    return text


def normalize_root_candidate(value: object, *, hint_prefix: str = "local") -> dict[str, str]:
    if not isinstance(value, dict):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID", "Root candidate must be an object", http_status=422
        )
    allowed = {"root_uri_sha256", "root_name", "root_uri_hint"}
    if set(value).difference(allowed):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Root candidate contains unsupported fields",
            http_status=422,
        )
    digest = str(value.get("root_uri_sha256", "")).strip().lower()
    if not _HEX64.fullmatch(digest):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Root candidate requires a lowercase SHA-256 identity",
            http_status=422,
        )
    expected_hint = f"{hint_prefix}-root:{digest[:12]}"
    hint = str(value.get("root_uri_hint") or expected_hint).strip().lower()
    if not _HINT.fullmatch(hint) or hint != expected_hint:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Root hint must be the redacted hash-derived identifier",
            http_status=422,
        )
    return {
        "root_uri_sha256": digest,
        "root_uri_hint": hint,
        "root_name": _label(value.get("root_name"), fallback="root"),
    }



def normalize_gateway_root_candidate(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID", "Gateway root candidate must be an object", http_status=422
        )
    if set(value).difference({"uri", "name"}):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Gateway root candidate contains unsupported fields",
            http_status=422,
        )
    raw_uri = value.get("uri")
    if not isinstance(raw_uri, str) or not raw_uri.strip() or len(raw_uri) > 4096:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID", "Gateway root URI is invalid", http_status=422
        )
    parsed = urlsplit(raw_uri.strip())
    if (
        parsed.scheme.lower() != "file"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Gateway roots must use local absolute file URIs without authority, query or fragment",
            http_status=422,
        )
    try:
        decoded_path = unquote(parsed.path, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID", "Gateway root URI encoding is invalid", http_status=422
        ) from exc
    if "\\" in decoded_path or "\x00" in decoded_path or "%" in decoded_path:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Gateway root URI contains an unsafe path encoding",
            http_status=422,
        )
    if any(segment in {".", ".."} for segment in decoded_path.split("/")):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Gateway root URI traversal is not permitted",
            http_status=422,
        )
    canonical_path = quote(decoded_path, safe="/:@-._~!$&'()*+,;=")
    canonical_uri = f"file://{canonical_path}"
    digest = hashlib.sha256(canonical_uri.encode("utf-8")).hexdigest()
    return {
        "uri": canonical_uri,
        "root_uri_sha256": digest,
        "root_uri_hint": f"gateway-root:{digest[:12]}",
        "root_name": _label(value.get("name"), fallback="root"),
    }


def _reject_cross_server_reuse(
    db: Session, *, owner_subject: str, server_id: str, root_uri_sha256: str
) -> None:
    collision = (
        db.query(McpRootGrant)
        .filter(
            McpRootGrant.owner_subject == owner_subject,
            McpRootGrant.server_id != server_id,
            McpRootGrant.root_uri_sha256 == root_uri_sha256,
            McpRootGrant.status.in_(["pending", "approved"]),
        )
        .first()
    )
    if collision is not None:
        raise McpRootFederationError(
            "MCP_ROOT_REUSE_FORBIDDEN",
            "Root authority is already bound to another MCP server",
            http_status=409,
        )


def _require_thin_runtime(
    *, owner_subject: str, server: McpServer, runtime: McpRuntimeConnection
) -> None:
    if (
        server.owner_subject != owner_subject
        or server.origin != "thin_client"
        or runtime.owner_subject != owner_subject
        or runtime.server_id != server.id
        or runtime.thin_client_id != server.thin_client_id
        or runtime.runtime_id != server.runtime_id
        or runtime.state != "online"
    ):
        raise McpRootFederationError(
            "MCP_ROOT_RUNTIME_MISMATCH",
            "Root inventory is not bound to the active enrolled runtime",
            http_status=403,
        )


def reconcile_runtime_root_candidates(
    db: Session,
    *,
    owner_subject: str,
    server: McpServer,
    runtime: McpRuntimeConnection,
    candidates: object,
) -> list[McpRootGrant]:
    _require_thin_runtime(owner_subject=owner_subject, server=server, runtime=runtime)
    if not isinstance(candidates, list) or len(candidates) > _MAX_ROOTS:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            f"Root candidate inventory must contain at most {_MAX_ROOTS} entries",
            http_status=422,
        )
    normalized = [normalize_root_candidate(item, hint_prefix="local") for item in candidates]
    for item in normalized:
        _reject_cross_server_reuse(
            db,
            owner_subject=owner_subject,
            server_id=server.id,
            root_uri_sha256=item["root_uri_sha256"],
        )
    hashes = [item["root_uri_sha256"] for item in normalized]
    if len(set(hashes)) != len(hashes):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Root candidate inventory contains duplicate identities",
            http_status=422,
        )
    now = utcnow()
    result: list[McpRootGrant] = []
    for item in normalized:
        grant = (
            db.query(McpRootGrant)
            .filter(
                McpRootGrant.owner_subject == owner_subject,
                McpRootGrant.server_id == server.id,
                McpRootGrant.root_uri_sha256 == item["root_uri_sha256"],
            )
            .one_or_none()
        )
        if grant is None:
            grant = McpRootGrant(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                server_id=server.id,
                runtime_connection_id=runtime.id,
                root_uri_sha256=item["root_uri_sha256"],
                root_uri_hint=item["root_uri_hint"],
                root_name=item["root_name"],
                grant_scope="read",
                status="pending",
                policy_generation=server.policy_generation,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(grant)
        else:
            binding_changed = grant.runtime_connection_id != runtime.id
            policy_changed = grant.policy_generation != server.policy_generation
            if binding_changed or policy_changed:
                grant.runtime_connection_id = runtime.id
                grant.policy_generation = server.policy_generation
                grant.status = "pending"
                grant.granted_by_subject = None
                grant.granted_at = None
                grant.expires_at = None
                grant.version += 1
            if grant.root_uri_hint != item["root_uri_hint"] or grant.root_name != item["root_name"]:
                grant.root_uri_hint = item["root_uri_hint"]
                grant.root_name = item["root_name"]
                grant.version += 1
            grant.updated_at = now
        result.append(grant)
    observed = set(hashes)
    stale = (
        db.query(McpRootGrant)
        .filter(
            McpRootGrant.owner_subject == owner_subject,
            McpRootGrant.server_id == server.id,
            McpRootGrant.runtime_connection_id == runtime.id,
            McpRootGrant.status.in_(["pending", "approved"]),
        )
        .all()
    )
    for grant in stale:
        if grant.root_uri_sha256 not in observed:
            grant.status = "revoked"
            grant.version += 1
            grant.updated_at = now
    db.flush()
    return result



def reconcile_gateway_root_candidates(
    db: Session,
    *,
    owner_subject: str,
    server: McpServer,
    candidates: object,
) -> list[McpRootGrant]:
    if server.owner_subject != owner_subject or server.origin != "gateway":
        raise McpRootFederationError(
            "MCP_ROOT_SERVER_MISMATCH",
            "Gateway root inventory is not bound to an owned remote server",
            http_status=403,
        )
    if not isinstance(candidates, list) or len(candidates) > _MAX_ROOTS:
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            f"Gateway root inventory must contain at most {_MAX_ROOTS} entries",
            http_status=422,
        )
    normalized = [normalize_gateway_root_candidate(item) for item in candidates]
    hashes = [item["root_uri_sha256"] for item in normalized]
    if len(set(hashes)) != len(hashes):
        raise McpRootFederationError(
            "MCP_ROOT_DESCRIPTOR_INVALID",
            "Gateway root inventory contains duplicate identities",
            http_status=422,
        )
    for item in normalized:
        _reject_cross_server_reuse(
            db,
            owner_subject=owner_subject,
            server_id=server.id,
            root_uri_sha256=item["root_uri_sha256"],
        )
    now = utcnow()
    result: list[McpRootGrant] = []
    for item in normalized:
        grant = (
            db.query(McpRootGrant)
            .filter(
                McpRootGrant.owner_subject == owner_subject,
                McpRootGrant.server_id == server.id,
                McpRootGrant.root_uri_sha256 == item["root_uri_sha256"],
            )
            .one_or_none()
        )
        if grant is None:
            grant = McpRootGrant(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                server_id=server.id,
                runtime_connection_id=None,
                root_uri_sha256=item["root_uri_sha256"],
                root_uri_hint=item["root_uri_hint"],
                root_name=item["root_name"],
                grant_scope="read",
                status="pending",
                policy_generation=server.policy_generation,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(grant)
        else:
            authority_changed = (
                grant.runtime_connection_id is not None
                or grant.policy_generation != server.policy_generation
            )
            if authority_changed:
                grant.runtime_connection_id = None
                grant.policy_generation = server.policy_generation
                grant.status = "pending"
                grant.granted_by_subject = None
                grant.granted_at = None
                grant.expires_at = None
                grant.version += 1
            if grant.root_uri_hint != item["root_uri_hint"] or grant.root_name != item["root_name"]:
                grant.root_uri_hint = item["root_uri_hint"]
                grant.root_name = item["root_name"]
                grant.version += 1
            grant.updated_at = now
        result.append(grant)
    observed = set(hashes)
    stale = (
        db.query(McpRootGrant)
        .filter(
            McpRootGrant.owner_subject == owner_subject,
            McpRootGrant.server_id == server.id,
            McpRootGrant.runtime_connection_id.is_(None),
            McpRootGrant.status.in_(["pending", "approved"]),
        )
        .all()
    )
    for grant in stale:
        if grant.root_uri_sha256 not in observed:
            grant.status = "revoked"
            grant.version += 1
            grant.updated_at = now
    db.flush()
    return result


def list_root_grants(
    db: Session,
    *,
    owner_subject: str,
    server_id: str | None = None,
    status: str | None = None,
) -> list[McpRootGrant]:
    query = db.query(McpRootGrant).filter(McpRootGrant.owner_subject == owner_subject)
    if server_id is not None:
        query = query.filter(McpRootGrant.server_id == server_id)
    if status is not None:
        query = query.filter(McpRootGrant.status == status)
    return query.order_by(McpRootGrant.created_at.asc(), McpRootGrant.id.asc()).all()


def _current_runtime_for_grant(db: Session, grant: McpRootGrant) -> McpRuntimeConnection:
    if not grant.runtime_connection_id:
        raise McpRootFederationError(
            "MCP_ROOT_RUNTIME_MISMATCH", "Thin-client root grant is not bound to a runtime connection"
        )
    runtime = db.get(McpRuntimeConnection, grant.runtime_connection_id)
    if runtime is None or runtime.state != "online":
        raise McpRootFederationError(
            "MCP_ROOT_RUNTIME_MISMATCH", "Root grant runtime connection is not active"
        )
    return runtime


def review_root_grant(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    grant_id: str,
    expected_version: int,
    decision: str,
) -> McpRootGrant:
    if decision not in {"approved", "revoked"}:
        raise McpRootFederationError(
            "MCP_ROOT_GRANT_INVALID", "Root grant decision must be approved or revoked", http_status=422
        )
    grant = (
        db.query(McpRootGrant)
        .filter(McpRootGrant.id == grant_id, McpRootGrant.owner_subject == owner_subject)
        .one_or_none()
    )
    if grant is None:
        raise McpRootFederationError(
            "MCP_ROOT_GRANT_NOT_FOUND", "Root grant was not found", http_status=404
        )
    server = db.get(McpServer, grant.server_id)
    if server is None or server.owner_subject != owner_subject:
        raise McpRootFederationError(
            "MCP_ROOT_GRANT_NOT_FOUND", "Root grant server was not found", http_status=404
        )
    if grant.version != expected_version:
        raise McpRootFederationError(
            "MCP_ROOT_GRANT_CONFLICT", "Root grant optimistic version conflict"
        )
    if decision == "approved":
        if grant.policy_generation != server.policy_generation:
            raise McpRootFederationError(
                "MCP_ROOT_POLICY_STALE", "Root grant policy generation is stale"
            )
        if server.origin == "thin_client":
            runtime = _current_runtime_for_grant(db, grant)
            _require_thin_runtime(owner_subject=owner_subject, server=server, runtime=runtime)
    now = utcnow()
    grant.status = decision
    grant.version += 1
    grant.updated_at = now
    if decision == "approved":
        grant.granted_by_subject = actor_subject
        grant.granted_at = now
    else:
        grant.granted_by_subject = None
        grant.granted_at = None
        grant.expires_at = None
    db.commit()
    db.refresh(grant)
    return grant


def approved_root_grants(
    db: Session,
    *,
    owner_subject: str,
    server: McpServer,
    runtime: McpRuntimeConnection | None,
    now: datetime | None = None,
) -> list[McpRootGrant]:
    if server.owner_subject != owner_subject:
        return []
    if server.origin == "thin_client":
        if runtime is None:
            return []
        _require_thin_runtime(owner_subject=owner_subject, server=server, runtime=runtime)
    current = now or datetime.now(UTC)
    query = db.query(McpRootGrant).filter(
        McpRootGrant.owner_subject == owner_subject,
        McpRootGrant.server_id == server.id,
        McpRootGrant.status == "approved",
        McpRootGrant.policy_generation == server.policy_generation,
    )
    if server.origin == "thin_client":
        query = query.filter(McpRootGrant.runtime_connection_id == runtime.id)
    else:
        query = query.filter(McpRootGrant.runtime_connection_id.is_(None))
    grants = query.order_by(McpRootGrant.root_uri_sha256.asc()).all()
    result: list[McpRootGrant] = []
    for grant in grants:
        expires = grant.expires_at
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= current:
                continue
        result.append(grant)
    return result



def approved_gateway_root_values(
    db: Session,
    *,
    owner_subject: str,
    server: McpServer,
    candidates: object,
    now: datetime | None = None,
) -> list[dict[str, str]]:
    if not isinstance(candidates, list) or len(candidates) > _MAX_ROOTS:
        return []
    try:
        normalized = [normalize_gateway_root_candidate(item) for item in candidates]
    except McpRootFederationError:
        return []
    by_hash = {item["root_uri_sha256"]: item for item in normalized}
    if len(by_hash) != len(normalized):
        return []
    grants = approved_root_grants(
        db,
        owner_subject=owner_subject,
        server=server,
        runtime=None,
        now=now,
    )
    result: list[dict[str, str]] = []
    for grant in grants:
        configured = by_hash.get(grant.root_uri_sha256)
        if configured is None:
            continue
        result.append(
            {
                "uri": configured["uri"],
                "root_name": grant.root_name or configured["root_name"],
                "root_uri_sha256": grant.root_uri_sha256,
            }
        )
    return result


def root_grant_set_sha256(grants: list[McpRootGrant]) -> str:
    payload = [
        {
            "root_uri_sha256": grant.root_uri_sha256,
            "root_name": grant.root_name or "root",
            "policy_generation": grant.policy_generation,
            "version": grant.version,
        }
        for grant in sorted(grants, key=lambda item: item.root_uri_sha256)
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def root_sync_set_sha256(
    *, policy_generation: int, roots: list[dict[str, Any]]
) -> str:
    payload = {
        "policy_generation": policy_generation,
        "roots": sorted(
            [
                {
                    "root_uri_sha256": str(root["root_uri_sha256"]),
                    "root_name": str(root.get("root_name") or "root"),
                    "version": int(root["version"]),
                }
                for root in roots
            ],
            key=lambda item: item["root_uri_sha256"],
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def thin_root_sync_payload(
    *, server: McpServer, runtime: McpRuntimeConnection, grants: list[McpRootGrant]
) -> dict[str, Any]:
    _require_thin_runtime(owner_subject=server.owner_subject, server=server, runtime=runtime)
    roots = [
        {
            "root_uri_sha256": grant.root_uri_sha256,
            "root_name": grant.root_name or "root",
            "version": grant.version,
        }
        for grant in grants
    ]
    return {
        "type": "mcp_roots_update",
        "connection_instance_id": runtime.connection_instance_id,
        "runtime_id": runtime.runtime_id,
        "local_server_id": server.local_server_id,
        "server_id": server.id,
        "policy_generation": server.policy_generation,
        "root_set_sha256": root_sync_set_sha256(
            policy_generation=server.policy_generation, roots=roots
        ),
        "roots": roots,
    }
