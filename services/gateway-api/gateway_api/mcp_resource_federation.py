from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlparse

from mcp.shared.uri_template import InvalidUriTemplate, UriTemplate
from sqlalchemy.orm import Session

from .mcp_federation_policy import sha256_json
from .mcp_rich_fidelity import (
    RichFidelityError,
    normalize_annotations,
    normalize_icons,
    sanitize_description,
    sanitize_title,
)
from .models import (
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
    McpCapabilitySubscription,
    McpMutationReceipt,
    McpServer,
    utcnow,
)

_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_MIME = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_TEMPLATE_EXPRESSION = re.compile(r"\{[+#./;?&]?([^}]+)\}")
_ALLOWED_RESOURCE_URI_SCHEMES = {"file", "https", "mcp", "urn"}
_SECRET_QUERY_KEY = re.compile(
    r"(?:^|[_-])(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|credential)(?:$|[_-])",
    re.IGNORECASE,
)
_ALLOWED_RESOURCE_MIME_TYPES = {
    "application/json",
    "application/octet-stream",
    "application/pdf",
    "application/xml",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/csv",
    "text/markdown",
    "text/plain",
    "text/xml",
}
_EXPOSURE_MODES = {"hidden", "catalog_only", "native_projected"}
_APPROVAL_CLASSES = {"none", "operator", "quorum", "production"}
_POLICY_TOKEN = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")


class McpResourceFederationError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int = 422,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status

    def as_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message}


def _fail(
    code: str,
    message: str,
    *,
    http_status: int = 422,
) -> McpResourceFederationError:
    return McpResourceFederationError(code, message, http_status=http_status)


def revoke_resource_subscriptions(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    entity_id: str | None = None,
    now: Any | None = None,
) -> int:
    query = db.query(McpCapabilitySubscription).filter(
        McpCapabilitySubscription.owner_subject == owner_subject,
        McpCapabilitySubscription.server_id == server_id,
        McpCapabilitySubscription.status.in_(("active", "paused")),
    )
    if entity_id is not None:
        query = query.filter(McpCapabilitySubscription.entity_id == entity_id)
    subscriptions = query.all()
    changed_at = now or utcnow()
    for subscription in subscriptions:
        subscription.status = "revoked"
        subscription.version += 1
        subscription.updated_at = changed_at
    return len(subscriptions)


def revoke_resource_subscriptions_for_thin_client(
    db: Session,
    *,
    owner_subject: str,
    thin_client_id: str,
) -> int:
    server_ids = (
        db.query(McpServer.id)
        .filter(
            McpServer.owner_subject == owner_subject,
            McpServer.origin == "thin_client",
            McpServer.thin_client_id == thin_client_id,
        )
        .all()
    )
    changed_at = utcnow()
    return sum(
        revoke_resource_subscriptions(
            db,
            owner_subject=owner_subject,
            server_id=server_id,
            now=changed_at,
        )
        for (server_id,) in server_ids
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_resource_uri(value: Any, *, template: bool = False) -> str:
    if not isinstance(value, str):
        raise _fail("MCP_RESOURCE_URI_INVALID", "MCP resource URI must be a string")
    uri = value.strip()
    if not uri or len(uri.encode("utf-8")) > 4096:
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI is empty or exceeds the size limit",
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in uri):
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI contains control characters",
        )
    if any(char.isspace() for char in uri):
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI must not contain whitespace",
        )
    scheme, separator, _rest = uri.partition(":")
    if not separator or not _URI_SCHEME.fullmatch(scheme):
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI must contain a valid URI scheme",
        )
    scheme_lower = scheme.lower()
    if scheme_lower not in _ALLOWED_RESOURCE_URI_SCHEMES:
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI scheme is not allowed",
        )
    parsed = urlparse(uri)
    if parsed.username or parsed.password:
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI must not contain embedded credentials",
        )
    if parsed.fragment:
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI must not contain a fragment",
        )
    for query_key, _query_value in parse_qsl(parsed.query, keep_blank_values=True):
        if _SECRET_QUERY_KEY.search(query_key):
            raise _fail(
                "MCP_RESOURCE_URI_INVALID",
                "MCP resource URI query contains a secret-shaped key",
            )
    if scheme_lower == "https" and not parsed.hostname:
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "HTTPS MCP resource URI must contain a host",
        )
    if scheme_lower == "urn":
        urn_parts = _rest.split(":", 1)
        if len(urn_parts) != 2 or not urn_parts[0] or not urn_parts[1]:
            raise _fail(
                "MCP_RESOURCE_URI_INVALID",
                "URN MCP resource URI must contain namespace and resource identifiers",
            )
    if not template and ("{" in uri or "}" in uri):
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "Concrete MCP resource URI cannot contain template expressions",
        )
    if template and uri.count("{") != uri.count("}"):
        raise _fail(
            "MCP_RESOURCE_URI_INVALID",
            "MCP resource URI template is unbalanced",
        )
    return uri


def resource_uri_sha256(uri: str, *, template: bool = False) -> str:
    return _sha256_text(validate_resource_uri(uri, template=template))


def citation_safe_uri_hint(uri: str, *, template: bool = False) -> str:
    value = validate_resource_uri(uri, template=template)
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme == "file":
        return "file://…"
    if scheme in {"http", "https"}:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{scheme}://{host}{port}/…"
    if scheme == "urn":
        namespace = value.split(":", 2)[1] if value.count(":") >= 2 else ""
        return f"urn:{namespace}:…"
    if parsed.hostname:
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{scheme}://{parsed.hostname}{port}/…"
    return f"{scheme}:…"


def validate_resource_mime_type(value: Any, *, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            raise _fail(
                "MCP_RESOURCE_MIME_INVALID",
                "MCP resource MIME type is required",
            )
        return None
    if not isinstance(value, str):
        raise _fail(
            "MCP_RESOURCE_MIME_INVALID",
            "MCP resource MIME type must be a string",
        )
    mime = value.strip().lower()
    if not _MIME.fullmatch(mime):
        raise _fail(
            "MCP_RESOURCE_MIME_INVALID",
            "MCP resource MIME type is syntactically invalid",
        )
    if mime not in _ALLOWED_RESOURCE_MIME_TYPES:
        raise _fail(
            "MCP_RESOURCE_MIME_UNSUPPORTED",
            f"MCP resource MIME type is not enabled: {mime}",
        )
    return mime


def _template_argument_schema(uri_template: str) -> dict[str, Any]:
    variables: list[str] = []
    for match in _TEMPLATE_EXPRESSION.finditer(uri_template):
        for raw in match.group(1).split(","):
            name = raw.split(":", 1)[0].rstrip("*")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", name) and name not in variables:
                variables.append(name)
    return {
        "type": "object",
        "properties": {name: {"type": "string"} for name in variables},
        "required": variables,
        "additionalProperties": False,
    }


def normalize_resource_descriptor(
    raw: dict[str, Any],
    *,
    entity_kind: str,
    max_resource_bytes: int = 1_000_000,
) -> tuple[str, dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    if entity_kind not in {"resource", "resource_template"}:
        raise _fail(
            "MCP_RESOURCE_KIND_INVALID",
            "Unsupported MCP resource entity kind",
        )
    if not isinstance(raw, dict):
        raise _fail(
            "MCP_RESOURCE_DESCRIPTOR_INVALID",
            "MCP resource descriptor must be an object",
        )
    key_name = "uri" if entity_kind == "resource" else "uriTemplate"
    is_template = entity_kind == "resource_template"
    uri = validate_resource_uri(raw.get(key_name), template=is_template)
    name = sanitize_title(raw.get("name"))
    if not name:
        raise _fail(
            "MCP_RESOURCE_DESCRIPTOR_INVALID",
            "MCP resource descriptor requires a bounded name",
        )
    title = sanitize_title(raw.get("title"))
    description = sanitize_description(raw.get("description"))
    mime_type = validate_resource_mime_type(raw.get("mimeType"))
    size = raw.get("size")
    if size is not None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise _fail(
                "MCP_RESOURCE_SIZE_INVALID",
                "MCP resource descriptor size is invalid",
            )
        if size > max_resource_bytes:
            raise _fail(
                "MCP_RESOURCE_SIZE_INVALID",
                "MCP resource descriptor exceeds the configured size limit",
            )
    try:
        annotations = normalize_annotations(raw.get("annotations"))
        icons = normalize_icons(raw.get("icons"))
    except RichFidelityError as exc:
        raise _fail(exc.code, exc.message) from exc

    uri_hash = resource_uri_sha256(uri, template=is_template)
    descriptor: dict[str, Any] = {
        "name": name,
        "description": description,
        "annotations": annotations,
        "icons": icons,
        "uri_sha256": uri_hash,
        "uri_hint": citation_safe_uri_hint(uri, template=is_template),
    }
    if title:
        descriptor["title"] = title
    if mime_type:
        descriptor["mimeType"] = mime_type
    if size is not None:
        descriptor["size"] = size
    # Generic MCP Apps/UI metadata remains gated by CMG-FED-980.
    descriptor["component_meta_present"] = bool(raw.get("_meta"))
    argument_schema = _template_argument_schema(uri) if is_template else None
    content_metadata = {
        "state": "catalog_metadata",
        "uri_sha256": uri_hash,
        "uri_hint": descriptor["uri_hint"],
    }
    return uri_hash, descriptor, argument_schema, content_metadata


def _get_server(db: Session, *, owner_subject: str, server_id: str) -> McpServer:
    server = (
        db.query(McpServer)
        .filter(McpServer.id == server_id, McpServer.owner_subject == owner_subject)
        .one_or_none()
    )
    if server is None:
        raise _fail("MCP_SERVER_NOT_FOUND", "MCP server not found", http_status=404)
    return server


def _next_revision_number(db: Session, entity_id: str) -> int:
    latest = (
        db.query(McpCapabilityEntityRevision)
        .filter(McpCapabilityEntityRevision.entity_id == entity_id)
        .order_by(McpCapabilityEntityRevision.revision_number.desc())
        .first()
    )
    return (latest.revision_number if latest is not None else 0) + 1


def reconcile_resource_catalog(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    protocol_version: str,
    catalog_generation: int,
    resources: list[dict[str, Any]],
    resource_templates: list[dict[str, Any]],
    max_entries: int = 5_000,
) -> dict[str, int]:
    server = _get_server(db, owner_subject=owner_subject, server_id=server_id)
    if catalog_generation < server.catalog_generation:
        raise _fail(
            "MCP_RESOURCE_CATALOG_STALE",
            "MCP resource catalog generation is stale",
            http_status=409,
        )
    if len(resources) + len(resource_templates) > max_entries:
        raise _fail(
            "MCP_RESOURCE_CATALOG_TOO_LARGE",
            "MCP resource catalog exceeds the configured entry limit",
        )

    seen: dict[str, set[str]] = {"resource": set(), "resource_template": set()}
    created_entities = 0
    created_revisions = 0
    now = utcnow()
    for entity_kind, values in (
        ("resource", resources),
        ("resource_template", resource_templates),
    ):
        for raw in values:
            uri_hash, descriptor, argument_schema, content_metadata = (
                normalize_resource_descriptor(raw, entity_kind=entity_kind)
            )
            if uri_hash in seen[entity_kind]:
                raise _fail(
                    "MCP_RESOURCE_CATALOG_DUPLICATE",
                    "MCP resource catalog contains duplicate URI identities",
                )
            seen[entity_kind].add(uri_hash)
            entity = (
                db.query(McpCapabilityEntity)
                .filter(
                    McpCapabilityEntity.owner_subject == owner_subject,
                    McpCapabilityEntity.server_id == server_id,
                    McpCapabilityEntity.entity_kind == entity_kind,
                    McpCapabilityEntity.upstream_key == uri_hash,
                )
                .one_or_none()
            )
            if entity is None:
                entity = McpCapabilityEntity(
                    id=str(uuid.uuid4()),
                    owner_subject=owner_subject,
                    server_id=server_id,
                    entity_kind=entity_kind,
                    upstream_key=uri_hash,
                    normalized_key=uri_hash,
                    lifecycle_state="active",
                    version=1,
                    first_observed_at=now,
                    last_observed_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(entity)
                db.flush([entity])
                created_entities += 1
            else:
                entity.lifecycle_state = "active"
                entity.last_observed_at = now
                entity.updated_at = now

            schema_hash = sha256_json(
                {
                    "entity_kind": entity_kind,
                    "descriptor": descriptor,
                    "argument_schema": argument_schema,
                    "content_metadata": content_metadata,
                }
            )
            current = None
            if entity.current_revision_id:
                current = (
                    db.query(McpCapabilityEntityRevision)
                    .filter(
                        McpCapabilityEntityRevision.id == entity.current_revision_id,
                        McpCapabilityEntityRevision.owner_subject == owner_subject,
                    )
                    .one_or_none()
                )
            if current is None or current.schema_hash != schema_hash:
                revision = McpCapabilityEntityRevision(
                    id=str(uuid.uuid4()),
                    owner_subject=owner_subject,
                    server_id=server_id,
                    entity_id=entity.id,
                    entity_kind=entity_kind,
                    revision_number=_next_revision_number(db, entity.id),
                    descriptor=descriptor,
                    argument_schema=argument_schema,
                    content_metadata=content_metadata,
                    schema_hash=schema_hash,
                    protocol_version=protocol_version,
                    catalog_generation=catalog_generation,
                    discovered_at=now,
                    created_at=now,
                )
                db.add(revision)
                db.flush([revision])
                entity.current_revision_id = revision.id
                entity.version += 1
                created_revisions += 1

    for entity_kind in ("resource", "resource_template"):
        existing = (
            db.query(McpCapabilityEntity)
            .filter(
                McpCapabilityEntity.owner_subject == owner_subject,
                McpCapabilityEntity.server_id == server_id,
                McpCapabilityEntity.entity_kind == entity_kind,
                McpCapabilityEntity.lifecycle_state == "active",
            )
            .all()
        )
        for entity in existing:
            if entity.upstream_key not in seen[entity_kind]:
                entity.lifecycle_state = "missing"
                entity.version += 1
                entity.updated_at = now
                revoke_resource_subscriptions(
                    db,
                    owner_subject=owner_subject,
                    server_id=server_id,
                    entity_id=entity.id,
                    now=now,
                )
    server.catalog_generation = max(server.catalog_generation, catalog_generation)
    server.last_catalog_refreshed_at = now
    server.updated_at = now
    db.commit()
    return {
        "resources": len(resources),
        "resource_templates": len(resource_templates),
        "created_entities": created_entities,
        "created_revisions": created_revisions,
    }


def resolve_resource_entity_by_uri(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    uri: str,
) -> McpCapabilityEntity:
    uri_hash = resource_uri_sha256(uri)
    entity = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.server_id == server_id,
            McpCapabilityEntity.entity_kind == "resource",
            McpCapabilityEntity.upstream_key == uri_hash,
        )
        .one_or_none()
    )
    if entity is None:
        raise _fail(
            "MCP_RESOURCE_NOT_FOUND",
            "MCP resource is not present in the reviewed catalog",
            http_status=404,
        )
    return entity


def get_resource_entity(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
) -> McpCapabilityEntity:
    entity = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.id == entity_id,
        )
        .one_or_none()
    )
    if entity is None or entity.entity_kind not in {"resource", "resource_template"}:
        raise _fail(
            "MCP_RESOURCE_NOT_FOUND",
            "MCP resource entity not found",
            http_status=404,
        )
    return entity


def list_resource_entities(
    db: Session,
    *,
    owner_subject: str,
    server_id: str | None = None,
    entity_kind: str | None = None,
    lifecycle_state: str | None = None,
    limit: int = 500,
) -> list[McpCapabilityEntity]:
    if entity_kind is not None and entity_kind not in {"resource", "resource_template"}:
        raise _fail("MCP_RESOURCE_KIND_INVALID", "Unsupported MCP resource entity kind")
    if lifecycle_state is not None and lifecycle_state not in {"active", "missing", "disabled"}:
        raise _fail("MCP_RESOURCE_STATE_INVALID", "Unsupported MCP resource lifecycle state")
    query = db.query(McpCapabilityEntity).filter(
        McpCapabilityEntity.owner_subject == owner_subject,
        McpCapabilityEntity.entity_kind.in_(("resource", "resource_template")),
    )
    if server_id is not None:
        query = query.filter(McpCapabilityEntity.server_id == server_id)
    if entity_kind is not None:
        query = query.filter(McpCapabilityEntity.entity_kind == entity_kind)
    if lifecycle_state is not None:
        query = query.filter(McpCapabilityEntity.lifecycle_state == lifecycle_state)
    return (
        query.order_by(
            McpCapabilityEntity.last_observed_at.desc(),
            McpCapabilityEntity.id.asc(),
        )
        .limit(max(1, min(int(limit), 500)))
        .all()
    )


def list_resource_revisions(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
    limit: int = 100,
) -> list[McpCapabilityEntityRevision]:
    entity = get_resource_entity(db, owner_subject=owner_subject, entity_id=entity_id)
    return (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.entity_id == entity.id,
        )
        .order_by(McpCapabilityEntityRevision.revision_number.desc())
        .limit(max(1, min(int(limit), 500)))
        .all()
    )


def get_current_resource_exposure(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
) -> McpCapabilityExposure | None:
    return (
        db.query(McpCapabilityExposure)
        .filter(
            McpCapabilityExposure.owner_subject == owner_subject,
            McpCapabilityExposure.entity_id == entity_id,
        )
        .order_by(McpCapabilityExposure.updated_at.desc())
        .first()
    )


def _validate_policy_token(value: Any, *, label: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _POLICY_TOKEN.fullmatch(value):
        raise _fail(
            "MCP_RESOURCE_POLICY_INVALID",
            f"MCP resource {label} is invalid",
        )
    return value


def upsert_resource_exposure(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    entity_id: str,
    idempotency_key: str,
    expected_version: int,
    revision_id: str,
    mode: str,
    enabled: bool,
    required_role: str | None,
    required_scope: str | None,
    approval_class: str,
    projection_generation: int = 0,
) -> McpCapabilityExposure:
    if mode not in _EXPOSURE_MODES:
        raise _fail(
            "MCP_RESOURCE_POLICY_INVALID",
            "MCP resource exposure mode is invalid",
        )
    if approval_class not in _APPROVAL_CLASSES:
        raise _fail(
            "MCP_RESOURCE_POLICY_INVALID",
            "MCP resource approval class is invalid",
        )
    if projection_generation < 0 or expected_version < 0:
        raise _fail(
            "MCP_RESOURCE_POLICY_INVALID",
            "MCP resource exposure version is invalid",
        )
    required_role = _validate_policy_token(required_role, label="required role")
    required_scope = _validate_policy_token(required_scope, label="required scope")
    entity = get_resource_entity(db, owner_subject=owner_subject, entity_id=entity_id)
    revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == revision_id,
            McpCapabilityEntityRevision.entity_id == entity.id,
        )
        .one_or_none()
    )
    if revision is None:
        raise _fail(
            "MCP_RESOURCE_REVISION_NOT_FOUND",
            "MCP resource revision does not belong to the selected entity",
            http_status=404,
        )
    server = _get_server(db, owner_subject=owner_subject, server_id=entity.server_id)
    if enabled and mode != "hidden":
        if server.trust_level not in {"restricted", "approved"}:
            raise _fail(
                "MCP_RESOURCE_TRUST_REQUIRED",
                "MCP server trust policy does not allow resource exposure",
                http_status=409,
            )
        if mode == "native_projected" and server.trust_level != "approved":
            raise _fail(
                "MCP_RESOURCE_TRUST_REQUIRED",
                "Native resource projection requires approved server trust",
                http_status=409,
            )
    request_hash = sha256_json(
        {
            "entity_id": entity_id,
            "expected_version": expected_version,
            "revision_id": revision_id,
            "mode": mode,
            "enabled": bool(enabled),
            "required_role": required_role,
            "required_scope": required_scope,
            "approval_class": approval_class,
            "projection_generation": projection_generation,
        }
    )
    receipt = (
        db.query(McpMutationReceipt)
        .filter(
            McpMutationReceipt.owner_subject == owner_subject,
            McpMutationReceipt.operation == "resource.exposure.upsert",
            McpMutationReceipt.idempotency_key == idempotency_key,
        )
        .one_or_none()
    )
    if receipt is not None:
        if receipt.request_hash != request_hash:
            raise _fail(
                "MCP_IDEMPOTENCY_CONFLICT",
                "MCP resource exposure idempotency key was reused with a different request",
                http_status=409,
            )
        return (
            db.query(McpCapabilityExposure)
            .filter(
                McpCapabilityExposure.owner_subject == owner_subject,
                McpCapabilityExposure.id == receipt.resource_id,
            )
            .one()
        )

    exposure = (
        db.query(McpCapabilityExposure)
        .filter(
            McpCapabilityExposure.owner_subject == owner_subject,
            McpCapabilityExposure.revision_id == revision.id,
            McpCapabilityExposure.projection_generation == projection_generation,
        )
        .one_or_none()
    )
    now = utcnow()
    if exposure is None:
        if expected_version != 0:
            raise _fail(
                "MCP_RESOURCE_VERSION_CONFLICT",
                "MCP resource exposure does not exist; expected_version must be 0",
                http_status=409,
            )
        exposure = McpCapabilityExposure(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=entity.server_id,
            entity_id=entity.id,
            revision_id=revision.id,
            entity_kind=entity.entity_kind,
            projection_generation=projection_generation,
            policy_generation=server.policy_generation,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(exposure)
    else:
        if exposure.version != expected_version:
            raise _fail(
                "MCP_RESOURCE_VERSION_CONFLICT",
                "MCP resource exposure optimistic version conflict",
                http_status=409,
            )
        exposure.version += 1
    exposure.mode = mode
    exposure.enabled = bool(enabled)
    exposure.required_role = required_role
    exposure.required_scope = required_scope
    exposure.approval_class = approval_class
    exposure.policy_generation = server.policy_generation
    exposure.reviewed_by_subject = actor_subject
    exposure.reviewed_at = now
    exposure.updated_at = now
    db.flush([exposure])
    if not exposure.enabled or exposure.mode == "hidden":
        revoke_resource_subscriptions(
            db,
            owner_subject=owner_subject,
            server_id=entity.server_id,
            entity_id=entity.id,
            now=now,
        )
    db.add(
        McpMutationReceipt(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            operation="resource.exposure.upsert",
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            resource_type="mcp_capability_exposure",
            resource_id=exposure.id,
            response_version=exposure.version,
            created_at=now,
        )
    )
    db.commit()
    db.refresh(exposure)
    return exposure


def authorize_resource_access(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    uri: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> tuple[
    McpServer,
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
]:
    entity = resolve_resource_entity_by_uri(
        db,
        owner_subject=owner_subject,
        server_id=server_id,
        uri=uri,
    )
    if entity.lifecycle_state != "active" or not entity.current_revision_id:
        raise _fail(
            "MCP_RESOURCE_UNAVAILABLE",
            "MCP resource is not active",
            http_status=409,
        )
    revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == entity.current_revision_id,
        )
        .one()
    )
    exposure = get_current_resource_exposure(
        db,
        owner_subject=owner_subject,
        entity_id=entity.id,
    )
    if (
        exposure is None
        or not exposure.enabled
        or exposure.mode == "hidden"
        or exposure.revision_id != revision.id
    ):
        raise _fail(
            "MCP_RESOURCE_NOT_AUTHORIZED",
            "MCP resource is not authorized for federation",
            http_status=403,
        )
    server = _get_server(db, owner_subject=owner_subject, server_id=server_id)
    if exposure.policy_generation != server.policy_generation:
        raise _fail(
            "MCP_RESOURCE_POLICY_STALE",
            "MCP resource authorization is stale",
            http_status=409,
        )
    caller_roles = roles or set()
    caller_scopes = scopes or set()
    if exposure.required_role and exposure.required_role not in caller_roles:
        raise _fail(
            "MCP_RESOURCE_ROLE_REQUIRED",
            "MCP resource role is required",
            http_status=403,
        )
    if exposure.required_scope and exposure.required_scope not in caller_scopes:
        raise _fail(
            "MCP_RESOURCE_SCOPE_REQUIRED",
            "MCP resource scope is required",
            http_status=403,
        )
    return server, entity, revision, exposure


def exposed_resource_hashes(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    entity_kind: str,
) -> set[str]:
    if entity_kind not in {"resource", "resource_template"}:
        raise _fail(
            "MCP_RESOURCE_KIND_INVALID",
            "Unsupported MCP resource entity kind",
        )
    rows = (
        db.query(McpCapabilityEntity, McpCapabilityExposure)
        .join(
            McpCapabilityExposure,
            McpCapabilityExposure.entity_id == McpCapabilityEntity.id,
        )
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.server_id == server_id,
            McpCapabilityEntity.entity_kind == entity_kind,
            McpCapabilityEntity.lifecycle_state == "active",
            McpCapabilityExposure.owner_subject == owner_subject,
            McpCapabilityExposure.enabled.is_(True),
            McpCapabilityExposure.mode != "hidden",
            McpCapabilityExposure.revision_id == McpCapabilityEntity.current_revision_id,
        )
        .all()
    )
    return {entity.upstream_key for entity, _exposure in rows}


def normalize_resource_read_result(
    *,
    requested_uri: str,
    contents: list[dict[str, Any]],
    max_result_bytes: int = 1_000_000,
    max_item_bytes: int = 524_288,
) -> dict[str, Any]:
    exact_uri = validate_resource_uri(requested_uri)
    if not isinstance(contents, list) or not contents or len(contents) > 32:
        raise _fail(
            "MCP_RESOURCE_CONTENT_INVALID",
            "MCP resources/read returned an invalid content list",
        )
    normalized: list[dict[str, Any]] = []
    evidence_items: list[dict[str, Any]] = []
    total = 0
    for raw in contents:
        if not isinstance(raw, dict):
            raise _fail(
                "MCP_RESOURCE_CONTENT_INVALID",
                "MCP resource content must be an object",
            )
        returned_uri = validate_resource_uri(raw.get("uri"))
        if returned_uri != exact_uri:
            raise _fail(
                "MCP_RESOURCE_URI_MISMATCH",
                "MCP resources/read returned content for a different URI",
                http_status=409,
            )
        has_text = isinstance(raw.get("text"), str)
        has_blob = isinstance(raw.get("blob"), str)
        if has_text == has_blob:
            raise _fail(
                "MCP_RESOURCE_CONTENT_INVALID",
                "MCP resource content must contain exactly one of text or blob",
            )
        mime = validate_resource_mime_type(
            raw.get("mimeType")
            or ("text/plain" if has_text else "application/octet-stream"),
            required=True,
        )
        if has_text:
            payload = raw["text"].encode("utf-8")
            kind = "text"
            item: dict[str, Any] = {
                "uri": exact_uri,
                "mimeType": mime,
                "text": raw["text"],
            }
        else:
            try:
                payload = base64.b64decode(raw["blob"], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise _fail(
                    "MCP_RESOURCE_CONTENT_INVALID",
                    "MCP resource blob is not valid base64",
                ) from exc
            kind = "blob"
            item = {
                "uri": exact_uri,
                "mimeType": mime,
                "blob": raw["blob"],
            }
        if len(payload) > max_item_bytes:
            raise _fail(
                "MCP_RESOURCE_CONTENT_TOO_LARGE",
                "MCP resource content item exceeds the size limit",
            )
        total += len(payload)
        if total > max_result_bytes:
            raise _fail(
                "MCP_RESOURCE_CONTENT_TOO_LARGE",
                "MCP resource content exceeds the total size limit",
            )
        evidence_items.append(
            {
                "kind": kind,
                "mime_type": mime,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        normalized.append(item)
    metadata = {
        "state": "content_observed",
        "uri_sha256": resource_uri_sha256(exact_uri),
        "uri_hint": citation_safe_uri_hint(exact_uri),
        "item_count": len(normalized),
        "total_bytes": total,
        "items": evidence_items,
    }
    metadata["content_sha256"] = sha256_json(
        {"uri_sha256": metadata["uri_sha256"], "items": evidence_items}
    )
    return {"contents": normalized, "content_metadata": metadata}


def record_resource_content_revision(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
    protocol_version: str,
    catalog_generation: int,
    content_metadata: dict[str, Any],
) -> McpCapabilityEntityRevision:
    entity = get_resource_entity(db, owner_subject=owner_subject, entity_id=entity_id)
    if entity.entity_kind != "resource" or not entity.current_revision_id:
        raise _fail(
            "MCP_RESOURCE_NOT_FOUND",
            "Concrete MCP resource metadata revision is unavailable",
            http_status=404,
        )
    catalog_revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == entity.current_revision_id,
        )
        .one()
    )
    schema_hash = sha256_json(
        {
            "entity_kind": "resource",
            "descriptor": catalog_revision.descriptor,
            "content_metadata": content_metadata,
        }
    )
    existing = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.entity_id == entity.id,
            McpCapabilityEntityRevision.schema_hash == schema_hash,
        )
        .one_or_none()
    )
    if existing is not None:
        return existing
    now = utcnow()
    revision = McpCapabilityEntityRevision(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        server_id=entity.server_id,
        entity_id=entity.id,
        entity_kind="resource",
        revision_number=_next_revision_number(db, entity.id),
        descriptor=dict(catalog_revision.descriptor),
        argument_schema=None,
        content_metadata=dict(content_metadata),
        schema_hash=schema_hash,
        protocol_version=protocol_version,
        catalog_generation=catalog_generation,
        discovered_at=now,
        created_at=now,
    )
    db.add(revision)
    db.commit()
    db.refresh(revision)
    return revision


def resource_provenance(
    *,
    server: McpServer,
    entity: McpCapabilityEntity,
    catalog_revision: McpCapabilityEntityRevision,
    content_revision: McpCapabilityEntityRevision,
) -> dict[str, Any]:
    metadata = dict(content_revision.content_metadata or {})
    return {
        "server_id": server.id,
        "server_origin": server.origin,
        "entity_id": entity.id,
        "catalog_revision_id": catalog_revision.id,
        "content_revision_id": content_revision.id,
        "uri_sha256": metadata.get("uri_sha256") or entity.upstream_key,
        "uri_hint": metadata.get("uri_hint")
        or str(catalog_revision.descriptor.get("uri_hint") or ""),
        "content_sha256": metadata.get("content_sha256"),
        "total_bytes": metadata.get("total_bytes"),
        "mime_types": sorted(
            {
                str(item.get("mime_type"))
                for item in metadata.get("items", [])
                if isinstance(item, dict) and item.get("mime_type")
            }
        ),
        "observed_at": content_revision.discovered_at.isoformat(),
    }


def subscribe_resource(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    uri: str,
) -> McpCapabilitySubscription:
    entity = resolve_resource_entity_by_uri(
        db,
        owner_subject=owner_subject,
        server_id=server_id,
        uri=uri,
    )
    if entity.lifecycle_state != "active":
        raise _fail(
            "MCP_RESOURCE_UNAVAILABLE",
            "MCP resource is not active",
            http_status=409,
        )
    server = _get_server(db, owner_subject=owner_subject, server_id=server_id)
    uri_hash = resource_uri_sha256(uri)
    subscription_key = _sha256_text(
        f"{owner_subject}\x00{server_id}\x00{uri_hash}"
    )
    subscription = (
        db.query(McpCapabilitySubscription)
        .filter(
            McpCapabilitySubscription.owner_subject == owner_subject,
            McpCapabilitySubscription.server_id == server_id,
            McpCapabilitySubscription.subscription_key == subscription_key,
        )
        .one_or_none()
    )
    now = utcnow()
    if subscription is None:
        subscription = McpCapabilitySubscription(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=server_id,
            entity_id=entity.id,
            capability_kind="resource",
            subscription_key=subscription_key,
            uri_sha256=uri_hash,
            uri_hint=citation_safe_uri_hint(uri),
            status="active",
            list_generation=server.catalog_generation,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(subscription)
    else:
        subscription.entity_id = entity.id
        subscription.status = "active"
        subscription.list_generation = server.catalog_generation
        subscription.version += 1
        subscription.updated_at = now
    db.commit()
    db.refresh(subscription)
    return subscription


def unsubscribe_resource(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    uri: str,
) -> McpCapabilitySubscription:
    uri_hash = resource_uri_sha256(uri)
    subscription = (
        db.query(McpCapabilitySubscription)
        .filter(
            McpCapabilitySubscription.owner_subject == owner_subject,
            McpCapabilitySubscription.server_id == server_id,
            McpCapabilitySubscription.uri_sha256 == uri_hash,
            McpCapabilitySubscription.status.in_(("active", "paused")),
        )
        .order_by(McpCapabilitySubscription.updated_at.desc())
        .first()
    )
    if subscription is None:
        raise _fail(
            "MCP_RESOURCE_SUBSCRIPTION_NOT_FOUND",
            "Active MCP resource subscription not found",
            http_status=404,
        )
    subscription.status = "revoked"
    subscription.version += 1
    subscription.updated_at = utcnow()
    db.commit()
    db.refresh(subscription)
    return subscription


_PUBLIC_RESOURCE_HOST = "gateway"
_PUBLIC_RESOURCE_PATH = re.compile(
    r"^/(resources|resource-templates)/([0-9a-f-]{36})/revisions/([0-9a-f-]{36})$"
)
_PUBLIC_RESOURCE_TEMPLATE_REFERENCE = re.compile(
    r"^mcp://gateway/resource-templates/([0-9a-f-]{36})/revisions/([0-9a-f-]{36})(?:\{\?[^{}]+\})?$"
)


def _uuid_text(value: str, *, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID", f"Invalid {label}", http_status=404
        ) from exc
    return str(parsed)


def public_resource_uri(entity_id: str, revision_id: str) -> str:
    return (
        f"mcp://{_PUBLIC_RESOURCE_HOST}/resources/"
        f"{_uuid_text(entity_id, label='resource id')}/revisions/"
        f"{_uuid_text(revision_id, label='revision id')}"
    )


def public_resource_template_uri(
    entity_id: str,
    revision_id: str,
    argument_schema: dict[str, Any] | None,
) -> str:
    base = (
        f"mcp://{_PUBLIC_RESOURCE_HOST}/resource-templates/"
        f"{_uuid_text(entity_id, label='resource template id')}/revisions/"
        f"{_uuid_text(revision_id, label='revision id')}"
    )
    properties = (argument_schema or {}).get("properties") or {}
    names = sorted(str(name) for name in properties)
    if not names:
        return base
    return f"{base}{{?{','.join(names)}}}"


def parse_public_resource_uri(
    uri: Any,
) -> tuple[str, str, str, dict[str, str]]:
    value = validate_resource_uri(uri)
    parsed = urlparse(value)
    if parsed.scheme.lower() != "mcp" or parsed.hostname != _PUBLIC_RESOURCE_HOST:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Resource URI is not a Gateway resource binding",
            http_status=404,
        )
    match = _PUBLIC_RESOURCE_PATH.fullmatch(parsed.path)
    if match is None:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Resource URI does not match a Gateway resource binding",
            http_status=404,
        )
    kind = "resource" if match.group(1) == "resources" else "resource_template"
    entity_id = _uuid_text(match.group(2), label="resource id")
    revision_id = _uuid_text(match.group(3), label="revision id")
    values: dict[str, str] = {}
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        if key in values or len(key) > 128 or len(item.encode("utf-8")) > 4096:
            raise _fail(
                "MCP_RESOURCE_BINDING_INVALID",
                "Resource template arguments are invalid",
            )
        if _SECRET_QUERY_KEY.search(key):
            raise _fail(
                "MCP_RESOURCE_BINDING_INVALID",
                "Secret-shaped resource template arguments are forbidden",
            )
        values[key] = item
    if kind == "resource" and values:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Concrete resource binding has arguments",
        )
    return kind, entity_id, revision_id, values


def _authorize_exact_binding(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
    revision_id: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> tuple[
    McpServer,
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
]:
    entity = get_resource_entity(
        db, owner_subject=owner_subject, entity_id=entity_id
    )
    if entity.lifecycle_state != "active" or entity.current_revision_id != revision_id:
        raise _fail(
            "MCP_RESOURCE_UNAVAILABLE",
            "MCP resource revision is not current",
            http_status=409,
        )
    revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == revision_id,
            McpCapabilityEntityRevision.entity_id == entity.id,
        )
        .one_or_none()
    )
    if revision is None:
        raise _fail(
            "MCP_RESOURCE_REVISION_NOT_FOUND",
            "MCP resource revision not found",
            http_status=404,
        )
    exposure = get_current_resource_exposure(
        db, owner_subject=owner_subject, entity_id=entity.id
    )
    server = _get_server(
        db, owner_subject=owner_subject, server_id=entity.server_id
    )
    if (
        exposure is None
        or not exposure.enabled
        or exposure.mode == "hidden"
        or exposure.revision_id != revision.id
        or exposure.policy_generation != server.policy_generation
    ):
        raise _fail(
            "MCP_RESOURCE_NOT_AUTHORIZED",
            "MCP resource is not authorized for federation",
            http_status=403,
        )
    caller_roles = roles or set()
    caller_scopes = scopes or set()
    if exposure.required_role and exposure.required_role not in caller_roles:
        raise _fail(
            "MCP_RESOURCE_ROLE_REQUIRED",
            "MCP resource role is required",
            http_status=403,
        )
    if exposure.required_scope and exposure.required_scope not in caller_scopes:
        raise _fail(
            "MCP_RESOURCE_SCOPE_REQUIRED",
            "MCP resource scope is required",
            http_status=403,
        )
    if exposure.approval_class != "none":
        raise _fail(
            "MCP_RESOURCE_APPROVAL_REQUIRED",
            "MCP resource requires an approval flow unavailable on public reads",
            http_status=403,
        )
    return server, entity, revision, exposure


def resolve_public_resource_binding(
    db: Session,
    *,
    owner_subject: str,
    uri: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> tuple[
    McpServer,
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
    dict[str, str],
]:
    kind, entity_id, revision_id, arguments = parse_public_resource_uri(uri)
    server, entity, revision, exposure = _authorize_exact_binding(
        db,
        owner_subject=owner_subject,
        entity_id=entity_id,
        revision_id=revision_id,
        roles=roles,
        scopes=scopes,
    )
    if entity.entity_kind != kind:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Resource binding kind mismatch",
            http_status=404,
        )
    if kind == "resource_template":
        schema = revision.argument_schema or {}
        properties = set((schema.get("properties") or {}).keys())
        required = set(schema.get("required") or [])
        if set(arguments) - properties or required - set(arguments):
            raise _fail(
                "MCP_RESOURCE_BINDING_INVALID",
                "Resource template arguments do not match the recorded revision",
            )
    return server, entity, revision, exposure, arguments


def public_resource_catalog(
    db: Session,
    *,
    owner_subject: str,
    entity_kind: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> list[dict[str, Any]]:
    if entity_kind not in {"resource", "resource_template"}:
        raise _fail(
            "MCP_RESOURCE_KIND_INVALID", "Unsupported MCP resource entity kind"
        )
    rows = (
        db.query(McpCapabilityEntity, McpCapabilityEntityRevision)
        .join(
            McpCapabilityEntityRevision,
            McpCapabilityEntity.current_revision_id
            == McpCapabilityEntityRevision.id,
        )
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.entity_kind == entity_kind,
            McpCapabilityEntity.lifecycle_state == "active",
        )
        .order_by(McpCapabilityEntity.id.asc())
        .all()
    )
    result: list[dict[str, Any]] = []
    for entity, revision in rows:
        try:
            _authorize_exact_binding(
                db,
                owner_subject=owner_subject,
                entity_id=entity.id,
                revision_id=revision.id,
                roles=roles,
                scopes=scopes,
            )
        except McpResourceFederationError:
            continue
        descriptor = dict(revision.descriptor or {})
        public: dict[str, Any] = {"name": descriptor.get("name") or "resource"}
        for key in (
            "title",
            "description",
            "mimeType",
            "size",
            "annotations",
            "icons",
        ):
            if descriptor.get(key) not in (None, "", [], {}):
                public[key] = descriptor[key]
        if entity_kind == "resource":
            public["uri"] = public_resource_uri(entity.id, revision.id)
        else:
            public["uriTemplate"] = public_resource_template_uri(
                entity.id, revision.id, revision.argument_schema
            )
        result.append(public)
    return result


def public_resources_available(
    db: Session,
    *,
    owner_subject: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> bool:
    return bool(
        public_resource_catalog(
            db,
            owner_subject=owner_subject,
            entity_kind="resource",
            roles=roles,
            scopes=scopes,
        )
        or public_resource_catalog(
            db,
            owner_subject=owner_subject,
            entity_kind="resource_template",
            roles=roles,
            scopes=scopes,
        )
    )


def public_resource_templates_available(
    db: Session,
    *,
    owner_subject: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> bool:
    return bool(
        public_resource_catalog(
            db,
            owner_subject=owner_subject,
            entity_kind="resource_template",
            roles=roles,
            scopes=scopes,
        )
    )


def resolve_public_resource_template_reference(
    db: Session,
    *,
    owner_subject: str,
    uri: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> tuple[
    McpServer,
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
]:
    value = str(uri).strip()
    match = _PUBLIC_RESOURCE_TEMPLATE_REFERENCE.fullmatch(value)
    if match is None:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Resource template reference is not a Gateway exact-revision URI template",
            http_status=404,
        )
    entity_id = _uuid_text(match.group(1), label="resource template entity id")
    revision_id = _uuid_text(match.group(2), label="resource template revision id")
    server, entity, revision, exposure = _authorize_exact_binding(
        db,
        owner_subject=owner_subject,
        entity_id=entity_id,
        revision_id=revision_id,
        roles=roles,
        scopes=scopes,
    )
    if entity.entity_kind != "resource_template":
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Completion reference is not a resource template",
            http_status=404,
        )
    expected = public_resource_template_uri(
        entity.id, revision.id, revision.argument_schema
    )
    if value != expected:
        raise _fail(
            "MCP_RESOURCE_BINDING_INVALID",
            "Resource template reference does not match the selected exact revision",
            http_status=404,
        )
    return server, entity, revision, exposure


def resolve_live_resource_uri(
    *,
    raw_descriptor: dict[str, Any],
    revision: McpCapabilityEntityRevision,
    arguments: dict[str, str] | None = None,
) -> str:
    kind = revision.entity_kind
    uri_hash, descriptor, argument_schema, content_metadata = (
        normalize_resource_descriptor(raw_descriptor, entity_kind=kind)
    )
    live_hash = sha256_json(
        {
            "entity_kind": kind,
            "descriptor": descriptor,
            "argument_schema": argument_schema,
            "content_metadata": content_metadata,
        }
    )
    expected_uri_hash = str((revision.descriptor or {}).get("uri_sha256") or "")
    if uri_hash != expected_uri_hash or live_hash != revision.schema_hash:
        raise _fail(
            "MCP_RESOURCE_SCHEMA_CHANGED",
            "Upstream MCP resource descriptor changed after selection",
            http_status=409,
        )
    if kind == "resource":
        return validate_resource_uri(raw_descriptor.get("uri"))
    raw_template = validate_resource_uri(
        raw_descriptor.get("uriTemplate"), template=True
    )
    try:
        template = UriTemplate.parse(
            raw_template, max_length=4096, max_variables=128
        )
        expanded = template.expand(arguments or {})
    except (InvalidUriTemplate, ValueError, TypeError) as exc:
        raise _fail(
            "MCP_RESOURCE_TEMPLATE_INVALID",
            "Upstream MCP resource template cannot be expanded safely",
            http_status=409,
        ) from exc
    return validate_resource_uri(expanded)
