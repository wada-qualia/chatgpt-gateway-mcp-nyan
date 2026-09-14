from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

from sqlalchemy.orm import Session

from .mcp_federation_policy import canonical_json, sha256_json
from .mcp_rich_fidelity import (
    RichFidelityError,
    normalize_icons,
    project_call_result,
    sanitize_description,
    sanitize_title,
)
from .models import (
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
    McpMutationReceipt,
    McpServer,
    utcnow,
)

_PROMPT_NAME = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")
_PROMPT_ARGUMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_POLICY_TOKEN = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")
_PUBLIC_PROMPT = re.compile(
    r"^gateway\.prompt\."
    r"(?P<entity>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\."
    r"(?P<revision>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_EXPOSURE_MODES = {"hidden", "catalog_only", "native_projected"}
_APPROVAL_CLASSES = {"none", "operator", "quorum", "production"}


class McpPromptFederationError(ValueError):
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
) -> McpPromptFederationError:
    return McpPromptFederationError(code, message, http_status=http_status)


def validate_prompt_name(value: Any) -> str:
    if not isinstance(value, str):
        raise _fail("MCP_PROMPT_NAME_INVALID", "MCP prompt name must be a string")
    if not _PROMPT_NAME.fullmatch(value) or ".." in value:
        raise _fail(
            "MCP_PROMPT_NAME_INVALID",
            "MCP prompt name contains unsupported characters or exceeds the size limit",
        )
    return value


def prompt_name_sha256(name: str) -> str:
    exact = validate_prompt_name(name)
    return hashlib.sha256(exact.encode("utf-8")).hexdigest()


def _normalize_argument(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _fail(
            "MCP_PROMPT_ARGUMENT_INVALID",
            "MCP prompt argument descriptor must be an object",
        )
    name = raw.get("name")
    if not isinstance(name, str) or not _PROMPT_ARGUMENT_NAME.fullmatch(name):
        raise _fail(
            "MCP_PROMPT_ARGUMENT_INVALID",
            "MCP prompt argument name is invalid",
        )
    required = raw.get("required", False)
    if not isinstance(required, bool):
        raise _fail(
            "MCP_PROMPT_ARGUMENT_INVALID",
            "MCP prompt argument required flag must be boolean",
        )
    title = sanitize_title(raw.get("title"))
    description = sanitize_description(raw.get("description"))
    normalized: dict[str, Any] = {"name": name, "required": required}
    if title:
        normalized["title"] = title
    if description:
        normalized["description"] = description
    return normalized


def normalize_prompt_descriptor(
    raw: dict[str, Any],
    *,
    max_arguments: int = 64,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(raw, dict):
        raise _fail(
            "MCP_PROMPT_DESCRIPTOR_INVALID",
            "MCP prompt descriptor must be an object",
        )
    upstream_name = validate_prompt_name(raw.get("name"))
    title = sanitize_title(raw.get("title"))
    description = sanitize_description(raw.get("description"))
    raw_arguments = raw.get("arguments") or []
    if not isinstance(raw_arguments, list) or len(raw_arguments) > max_arguments:
        raise _fail(
            "MCP_PROMPT_ARGUMENT_INVALID",
            "MCP prompt arguments exceed the configured entry limit",
        )
    arguments: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_argument in raw_arguments:
        argument = _normalize_argument(raw_argument)
        if argument["name"] in seen:
            raise _fail(
                "MCP_PROMPT_ARGUMENT_DUPLICATE",
                "MCP prompt contains duplicate argument names",
            )
        seen.add(argument["name"])
        arguments.append(argument)
    try:
        icons = normalize_icons(raw.get("icons"))
    except RichFidelityError as exc:
        raise _fail(exc.code, exc.message) from exc
    name_hash = prompt_name_sha256(upstream_name)
    descriptor: dict[str, Any] = {
        "upstream_name": upstream_name,
        "name_sha256": name_hash,
        "description": description,
        "arguments": arguments,
        "icons": icons,
        "component_meta_present": bool(raw.get("_meta")),
    }
    if title:
        descriptor["title"] = title
    properties = {
        argument["name"]: {"type": "string", "maxLength": 8192}
        for argument in arguments
    }
    required = [
        argument["name"] for argument in arguments if argument["required"]
    ]
    argument_schema = {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }
    content_metadata = {
        "state": "catalog_metadata",
        "prompt_name_sha256": name_hash,
        "argument_count": len(arguments),
    }
    return name_hash, descriptor, argument_schema, content_metadata


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


def reconcile_prompt_catalog(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    protocol_version: str,
    catalog_generation: int,
    prompts: list[dict[str, Any]],
    max_entries: int = 5_000,
) -> dict[str, int]:
    server = _get_server(db, owner_subject=owner_subject, server_id=server_id)
    if catalog_generation < server.catalog_generation:
        raise _fail(
            "MCP_PROMPT_CATALOG_STALE",
            "MCP prompt catalog generation is stale",
            http_status=409,
        )
    if not isinstance(prompts, list) or len(prompts) > max_entries:
        raise _fail(
            "MCP_PROMPT_CATALOG_TOO_LARGE",
            "MCP prompt catalog exceeds the configured entry limit",
        )
    seen: set[str] = set()
    created_entities = 0
    created_revisions = 0
    now = utcnow()
    for raw in prompts:
        name_hash, descriptor, argument_schema, content_metadata = (
            normalize_prompt_descriptor(raw)
        )
        if name_hash in seen:
            raise _fail(
                "MCP_PROMPT_CATALOG_DUPLICATE",
                "MCP prompt catalog contains duplicate prompt identities",
            )
        seen.add(name_hash)
        entity = (
            db.query(McpCapabilityEntity)
            .filter(
                McpCapabilityEntity.owner_subject == owner_subject,
                McpCapabilityEntity.server_id == server_id,
                McpCapabilityEntity.entity_kind == "prompt",
                McpCapabilityEntity.upstream_key == name_hash,
            )
            .one_or_none()
        )
        if entity is None:
            entity = McpCapabilityEntity(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                server_id=server_id,
                entity_kind="prompt",
                upstream_key=name_hash,
                normalized_key=name_hash,
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
                "entity_kind": "prompt",
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
                entity_kind="prompt",
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
    existing = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.server_id == server_id,
            McpCapabilityEntity.entity_kind == "prompt",
            McpCapabilityEntity.lifecycle_state == "active",
        )
        .all()
    )
    missing = 0
    for entity in existing:
        if entity.upstream_key not in seen:
            entity.lifecycle_state = "missing"
            entity.version += 1
            entity.updated_at = now
            missing += 1
    server.catalog_generation = max(server.catalog_generation, catalog_generation)
    server.last_catalog_refreshed_at = now
    server.updated_at = now
    db.commit()
    return {
        "prompts": len(prompts),
        "created_entities": created_entities,
        "created_revisions": created_revisions,
        "missing": missing,
    }


def get_prompt_entity(
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
            McpCapabilityEntity.entity_kind == "prompt",
        )
        .one_or_none()
    )
    if entity is None:
        raise _fail(
            "MCP_PROMPT_NOT_FOUND",
            "MCP prompt entity not found",
            http_status=404,
        )
    return entity


def list_prompt_revisions(
    db: Session,
    *,
    owner_subject: str,
    entity_id: str,
    limit: int = 100,
) -> list[McpCapabilityEntityRevision]:
    entity = get_prompt_entity(db, owner_subject=owner_subject, entity_id=entity_id)
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


def get_current_prompt_exposure(
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
            McpCapabilityExposure.entity_kind == "prompt",
        )
        .order_by(McpCapabilityExposure.updated_at.desc())
        .first()
    )


def _validate_policy_token(value: Any, *, label: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _POLICY_TOKEN.fullmatch(value):
        raise _fail(
            "MCP_PROMPT_POLICY_INVALID",
            f"MCP prompt {label} is invalid",
        )
    return value


def upsert_prompt_exposure(
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
            "MCP_PROMPT_POLICY_INVALID",
            "MCP prompt exposure mode is invalid",
        )
    if approval_class not in _APPROVAL_CLASSES:
        raise _fail(
            "MCP_PROMPT_POLICY_INVALID",
            "MCP prompt approval class is invalid",
        )
    if projection_generation < 0 or expected_version < 0:
        raise _fail(
            "MCP_PROMPT_POLICY_INVALID",
            "MCP prompt exposure version is invalid",
        )
    required_role = _validate_policy_token(required_role, label="required role")
    required_scope = _validate_policy_token(required_scope, label="required scope")
    entity = get_prompt_entity(db, owner_subject=owner_subject, entity_id=entity_id)
    revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == revision_id,
            McpCapabilityEntityRevision.entity_id == entity.id,
            McpCapabilityEntityRevision.entity_kind == "prompt",
        )
        .one_or_none()
    )
    if revision is None:
        raise _fail(
            "MCP_PROMPT_REVISION_NOT_FOUND",
            "MCP prompt revision does not belong to the selected entity",
            http_status=404,
        )
    server = _get_server(db, owner_subject=owner_subject, server_id=entity.server_id)
    if enabled and mode != "hidden":
        if server.trust_level not in {"restricted", "approved"}:
            raise _fail(
                "MCP_PROMPT_TRUST_REQUIRED",
                "MCP server trust policy does not allow prompt exposure",
                http_status=409,
            )
        if mode == "native_projected" and server.trust_level != "approved":
            raise _fail(
                "MCP_PROMPT_TRUST_REQUIRED",
                "Native prompt projection requires approved server trust",
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
            McpMutationReceipt.operation == "prompt.exposure.upsert",
            McpMutationReceipt.idempotency_key == idempotency_key,
        )
        .one_or_none()
    )
    if receipt is not None:
        if receipt.request_hash != request_hash:
            raise _fail(
                "MCP_IDEMPOTENCY_CONFLICT",
                "MCP prompt exposure idempotency key was reused with a different request",
                http_status=409,
            )
        return (
            db.query(McpCapabilityExposure)
            .filter(
                McpCapabilityExposure.owner_subject == owner_subject,
                McpCapabilityExposure.id == receipt.resource_id,
                McpCapabilityExposure.entity_kind == "prompt",
            )
            .one()
        )
    exposure = (
        db.query(McpCapabilityExposure)
        .filter(
            McpCapabilityExposure.owner_subject == owner_subject,
            McpCapabilityExposure.revision_id == revision.id,
            McpCapabilityExposure.projection_generation == projection_generation,
            McpCapabilityExposure.entity_kind == "prompt",
        )
        .one_or_none()
    )
    now = utcnow()
    if exposure is None:
        if expected_version != 0:
            raise _fail(
                "MCP_PROMPT_VERSION_CONFLICT",
                "MCP prompt exposure does not exist; expected_version must be 0",
                http_status=409,
            )
        exposure = McpCapabilityExposure(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=entity.server_id,
            entity_id=entity.id,
            revision_id=revision.id,
            entity_kind="prompt",
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
                "MCP_PROMPT_VERSION_CONFLICT",
                "MCP prompt exposure optimistic version conflict",
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
    db.add(
        McpMutationReceipt(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            operation="prompt.exposure.upsert",
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


def public_prompt_name(entity_id: str, revision_id: str) -> str:
    entity = str(uuid.UUID(entity_id))
    revision = str(uuid.UUID(revision_id))
    return f"gateway.prompt.{entity}.{revision}"


def parse_public_prompt_name(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise _fail(
            "MCP_PROMPT_PUBLIC_NAME_INVALID",
            "Gateway prompt name must be a string",
        )
    match = _PUBLIC_PROMPT.fullmatch(value)
    if match is None:
        raise _fail(
            "MCP_PROMPT_PUBLIC_NAME_INVALID",
            "Gateway prompt name is not an exact revision identifier",
        )
    return match.group("entity"), match.group("revision")


def _exposure_allows(
    exposure: McpCapabilityExposure,
    *,
    server: McpServer,
    roles: set[str],
    scopes: set[str],
) -> bool:
    if (
        not exposure.enabled
        or exposure.mode == "hidden"
        or exposure.policy_generation != server.policy_generation
    ):
        return False
    return not (
        (exposure.required_role and exposure.required_role not in roles)
        or (exposure.required_scope and exposure.required_scope not in scopes)
    )


def resolve_public_prompt_binding(
    db: Session,
    *,
    owner_subject: str,
    name: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> tuple[
    McpServer,
    McpCapabilityEntity,
    McpCapabilityEntityRevision,
    McpCapabilityExposure,
]:
    try:
        entity_id, revision_id = parse_public_prompt_name(name)
    except McpPromptFederationError as exc:
        if exc.code != "MCP_PROMPT_PUBLIC_NAME_INVALID":
            raise
        raise _fail(
            "MCP_PROMPT_UNAVAILABLE",
            "Gateway prompt binding is stale or unavailable",
            http_status=404,
        ) from exc
    entity = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.id == entity_id,
            McpCapabilityEntity.entity_kind == "prompt",
        )
        .one_or_none()
    )
    if (
        entity is None
        or entity.lifecycle_state != "active"
        or entity.current_revision_id != revision_id
    ):
        raise _fail(
            "MCP_PROMPT_UNAVAILABLE",
            "Gateway prompt binding is stale or unavailable",
            http_status=409,
        )
    revision = (
        db.query(McpCapabilityEntityRevision)
        .filter(
            McpCapabilityEntityRevision.owner_subject == owner_subject,
            McpCapabilityEntityRevision.id == revision_id,
            McpCapabilityEntityRevision.entity_id == entity.id,
            McpCapabilityEntityRevision.entity_kind == "prompt",
        )
        .one_or_none()
    )
    exposure = get_current_prompt_exposure(
        db,
        owner_subject=owner_subject,
        entity_id=entity.id,
    )
    if (
        revision is None
        or exposure is None
        or exposure.revision_id != revision.id
    ):
        raise _fail(
            "MCP_PROMPT_NOT_AUTHORIZED",
            "Gateway prompt is not authorized for federation",
            http_status=403,
        )
    server = _get_server(db, owner_subject=owner_subject, server_id=entity.server_id)
    if not _exposure_allows(
        exposure,
        server=server,
        roles=roles or set(),
        scopes=scopes or set(),
    ):
        raise _fail(
            "MCP_PROMPT_NOT_AUTHORIZED",
            "Gateway prompt is not authorized for this caller",
            http_status=403,
        )
    return server, entity, revision, exposure


def public_prompt_catalog(
    db: Session,
    *,
    owner_subject: str,
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    caller_roles = roles or set()
    caller_scopes = scopes or set()
    entities = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.entity_kind == "prompt",
            McpCapabilityEntity.lifecycle_state == "active",
            McpCapabilityEntity.current_revision_id.is_not(None),
        )
        .order_by(McpCapabilityEntity.id.asc())
        .limit(max(1, min(int(limit), 500)))
        .all()
    )
    result: list[dict[str, Any]] = []
    for entity in entities:
        revision = (
            db.query(McpCapabilityEntityRevision)
            .filter(
                McpCapabilityEntityRevision.owner_subject == owner_subject,
                McpCapabilityEntityRevision.id == entity.current_revision_id,
                McpCapabilityEntityRevision.entity_id == entity.id,
                McpCapabilityEntityRevision.entity_kind == "prompt",
            )
            .one_or_none()
        )
        exposure = get_current_prompt_exposure(
            db,
            owner_subject=owner_subject,
            entity_id=entity.id,
        )
        if revision is None or exposure is None or exposure.revision_id != revision.id:
            continue
        server = _get_server(db, owner_subject=owner_subject, server_id=entity.server_id)
        if not _exposure_allows(
            exposure,
            server=server,
            roles=caller_roles,
            scopes=caller_scopes,
        ):
            continue
        descriptor = revision.descriptor if isinstance(revision.descriptor, dict) else {}
        prompt: dict[str, Any] = {
            "name": public_prompt_name(entity.id, revision.id),
            "arguments": list(descriptor.get("arguments") or []),
        }
        title = descriptor.get("title")
        description = descriptor.get("description")
        icons = descriptor.get("icons")
        if isinstance(title, str) and title:
            prompt["title"] = title
        if isinstance(description, str) and description:
            prompt["description"] = description
        if isinstance(icons, list) and icons:
            prompt["icons"] = icons
        result.append(prompt)
    return result


def exposed_prompt_hashes(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
) -> set[str]:
    entities = (
        db.query(McpCapabilityEntity)
        .filter(
            McpCapabilityEntity.owner_subject == owner_subject,
            McpCapabilityEntity.server_id == server_id,
            McpCapabilityEntity.entity_kind == "prompt",
            McpCapabilityEntity.lifecycle_state == "active",
        )
        .all()
    )
    hashes: set[str] = set()
    for entity in entities:
        exposure = get_current_prompt_exposure(
            db,
            owner_subject=owner_subject,
            entity_id=entity.id,
        )
        if (
            exposure is not None
            and exposure.enabled
            and exposure.mode != "hidden"
            and exposure.revision_id == entity.current_revision_id
        ):
            hashes.add(entity.upstream_key)
    return hashes

def _revision_string_schema(
    revision: McpCapabilityEntityRevision,
) -> tuple[dict[str, Any], set[str]]:
    schema = revision.argument_schema if isinstance(revision.argument_schema, dict) else {}
    if schema.get("type") != "object":
        raise _fail(
            "MCP_PROMPT_SCHEMA_INVALID",
            "MCP capability revision argument schema is invalid",
            http_status=409,
        )
    properties = schema.get("properties")
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise _fail(
            "MCP_PROMPT_SCHEMA_INVALID",
            "MCP capability revision argument schema is invalid",
            http_status=409,
        )
    required_names: set[str] = set()
    for value in required:
        if not isinstance(value, str) or value not in properties:
            raise _fail(
                "MCP_PROMPT_SCHEMA_INVALID",
                "MCP capability revision required arguments are invalid",
                http_status=409,
            )
        required_names.add(value)
    return properties, required_names


def _validate_string_arguments(
    revision: McpCapabilityEntityRevision,
    arguments: Any,
    *,
    require_all: bool,
    max_arguments: int,
    max_total_bytes: int,
) -> dict[str, str]:
    if arguments is None:
        raw_arguments: dict[Any, Any] = {}
    elif isinstance(arguments, dict):
        raw_arguments = arguments
    else:
        raise _fail(
            "MCP_PROMPT_ARGUMENTS_INVALID",
            "MCP prompt arguments must be an object",
        )
    if len(raw_arguments) > max_arguments:
        raise _fail(
            "MCP_PROMPT_ARGUMENTS_INVALID",
            "MCP prompt arguments exceed the configured entry limit",
        )
    properties, required_names = _revision_string_schema(revision)
    result: dict[str, str] = {}
    total_bytes = 0
    for raw_name, raw_value in raw_arguments.items():
        if not isinstance(raw_name, str) or raw_name not in properties:
            raise _fail(
                "MCP_PROMPT_ARGUMENTS_INVALID",
                "MCP prompt contains an unknown argument",
            )
        property_schema = properties.get(raw_name)
        if not isinstance(property_schema, dict) or property_schema.get("type") != "string":
            raise _fail(
                "MCP_PROMPT_SCHEMA_INVALID",
                "MCP capability revision argument schema is invalid",
                http_status=409,
            )
        if not isinstance(raw_value, str):
            raise _fail(
                "MCP_PROMPT_ARGUMENTS_INVALID",
                "MCP prompt argument values must be strings",
            )
        configured_max = property_schema.get("maxLength", 8192)
        if (
            isinstance(configured_max, bool)
            or not isinstance(configured_max, int)
            or configured_max < 0
            or configured_max > 8192
        ):
            raise _fail(
                "MCP_PROMPT_SCHEMA_INVALID",
                "MCP capability revision argument size limit is invalid",
                http_status=409,
            )
        value_bytes = len(raw_value.encode("utf-8"))
        if value_bytes > configured_max:
            raise _fail(
                "MCP_PROMPT_ARGUMENTS_INVALID",
                "MCP prompt argument exceeds the configured size limit",
            )
        total_bytes += len(raw_name.encode("utf-8")) + value_bytes
        if total_bytes > max_total_bytes:
            raise _fail(
                "MCP_PROMPT_ARGUMENTS_INVALID",
                "MCP prompt arguments exceed the configured total size limit",
                http_status=413,
            )
        result[raw_name] = raw_value
    if require_all:
        missing = required_names.difference(result)
        if missing:
            raise _fail(
                "MCP_PROMPT_ARGUMENTS_INVALID",
                "MCP prompt is missing required arguments",
            )
    return result


def validate_prompt_arguments(
    revision: McpCapabilityEntityRevision,
    arguments: Any,
    *,
    max_arguments: int = 64,
    max_total_bytes: int = 65536,
) -> dict[str, str]:
    if revision.entity_kind != "prompt":
        raise _fail(
            "MCP_PROMPT_BINDING_INVALID",
            "MCP prompt argument validation requires a prompt revision",
            http_status=409,
        )
    return _validate_string_arguments(
        revision,
        arguments,
        require_all=True,
        max_arguments=max_arguments,
        max_total_bytes=max_total_bytes,
    )


def validate_completion_request(
    revision: McpCapabilityEntityRevision,
    argument: Any,
    context_arguments: Any,
    *,
    max_context_arguments: int = 64,
    max_total_bytes: int = 65536,
) -> tuple[dict[str, str], dict[str, str]]:
    if revision.entity_kind not in {"prompt", "resource_template"}:
        raise _fail(
            "MCP_COMPLETION_BINDING_INVALID",
            "MCP completion requires a prompt or resource-template revision",
            http_status=409,
        )
    if not isinstance(argument, dict) or set(argument) != {"name", "value"}:
        raise _fail(
            "MCP_COMPLETION_ARGUMENT_INVALID",
            "MCP completion argument must contain exactly name and value",
        )
    name = argument.get("name")
    value = argument.get("value")
    if not isinstance(name, str) or not isinstance(value, str):
        raise _fail(
            "MCP_COMPLETION_ARGUMENT_INVALID",
            "MCP completion argument name and value must be strings",
        )
    properties, _required = _revision_string_schema(revision)
    property_schema = properties.get(name)
    if not isinstance(property_schema, dict) or property_schema.get("type") != "string":
        raise _fail(
            "MCP_COMPLETION_ARGUMENT_INVALID",
            "MCP completion argument is not part of the selected exact revision",
        )
    configured_max = property_schema.get("maxLength", 8192)
    if (
        isinstance(configured_max, bool)
        or not isinstance(configured_max, int)
        or configured_max < 0
        or configured_max > 8192
    ):
        raise _fail(
            "MCP_PROMPT_SCHEMA_INVALID",
            "MCP capability revision argument size limit is invalid",
            http_status=409,
        )
    if len(value.encode("utf-8")) > configured_max:
        raise _fail(
            "MCP_COMPLETION_ARGUMENT_INVALID",
            "MCP completion argument exceeds the configured size limit",
        )
    context = _validate_string_arguments(
        revision,
        context_arguments,
        require_all=False,
        max_arguments=max_context_arguments,
        max_total_bytes=max_total_bytes,
    )
    total_bytes = len(name.encode("utf-8")) + len(value.encode("utf-8"))
    total_bytes += sum(
        len(key.encode("utf-8")) + len(item.encode("utf-8"))
        for key, item in context.items()
    )
    if total_bytes > max_total_bytes:
        raise _fail(
            "MCP_COMPLETION_ARGUMENT_INVALID",
            "MCP completion request exceeds the configured total size limit",
            http_status=413,
        )
    return {"name": name, "value": value}, context


def normalize_prompt_get_result(
    payload: Any,
    *,
    max_text_bytes: int,
    max_result_bytes: int,
    max_content_items: int,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _fail(
            "MCP_PROTOCOL_MISMATCH",
            "MCP prompt result must be an object",
            http_status=502,
        )
    result_type = payload.get("resultType", "complete")
    if result_type != "complete":
        raise _fail(
            "MCP_PROMPT_INTERACTION_UNSUPPORTED",
            "Interactive prompt retrieval is not enabled through Gateway federation",
            http_status=409,
        )
    raw_messages = payload.get("messages")
    if not isinstance(raw_messages, list):
        raise _fail(
            "MCP_PROTOCOL_MISMATCH",
            "MCP prompt result messages must be a list",
            http_status=502,
        )
    if len(raw_messages) > max_content_items:
        raise _fail(
            "MCP_PROMPT_RESULT_TOO_LARGE",
            "MCP prompt result exceeds the configured message limit",
            http_status=413,
        )
    messages: list[dict[str, Any]] = []
    for raw_message in raw_messages:
        if not isinstance(raw_message, dict):
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP prompt message must be an object",
                http_status=502,
            )
        role = raw_message.get("role")
        if role not in {"user", "assistant"}:
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP prompt message role is invalid",
                http_status=502,
            )
        content = raw_message.get("content")
        if not isinstance(content, dict):
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP prompt message content is invalid",
                http_status=502,
            )
        try:
            projection = project_call_result(
                {"content": [content], "isError": False},
                max_text_bytes=max_text_bytes,
                max_result_bytes=max_result_bytes,
                max_content_items=1,
            )
        except RichFidelityError as exc:
            raise _fail(exc.code, exc.message, http_status=exc.http_status) from exc
        projected_content = projection.model_payload.get("content")
        if not isinstance(projected_content, list) or len(projected_content) != 1:
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP prompt content projection is invalid",
                http_status=502,
            )
        item = dict(projected_content[0])
        item.pop("_gateway", None)
        messages.append({"role": role, "content": item})
    result: dict[str, Any] = {"messages": messages}
    description = sanitize_description(payload.get("description"))
    if description:
        result["description"] = description
    serialized = canonical_json(result).encode("utf-8")
    if len(serialized) > max_result_bytes:
        raise _fail(
            "MCP_PROMPT_RESULT_TOO_LARGE",
            "MCP prompt result exceeds the Gateway result limit",
            http_status=413,
        )
    return result


def normalize_completion_result(
    payload: Any,
    *,
    max_result_bytes: int,
    max_values: int = 100,
    max_value_bytes: int = 8192,
    max_total: int = 1_000_000,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _fail(
            "MCP_PROTOCOL_MISMATCH",
            "MCP completion result must be an object",
            http_status=502,
        )
    result_type = payload.get("resultType", "complete")
    if result_type != "complete":
        raise _fail(
            "MCP_COMPLETION_INTERACTION_UNSUPPORTED",
            "Interactive completion is not enabled through Gateway federation",
            http_status=409,
        )
    raw_completion = payload.get("completion")
    if not isinstance(raw_completion, dict):
        raise _fail(
            "MCP_PROTOCOL_MISMATCH",
            "MCP completion result is invalid",
            http_status=502,
        )
    raw_values = raw_completion.get("values")
    if not isinstance(raw_values, list) or len(raw_values) > max_values:
        raise _fail(
            "MCP_COMPLETION_RESULT_TOO_LARGE",
            "MCP completion values exceed the configured entry limit",
            http_status=413,
        )
    values: list[str] = []
    for raw_value in raw_values:
        if not isinstance(raw_value, str):
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP completion values must be strings",
                http_status=502,
            )
        if len(raw_value.encode("utf-8")) > max_value_bytes:
            raise _fail(
                "MCP_COMPLETION_RESULT_TOO_LARGE",
                "MCP completion value exceeds the configured size limit",
                http_status=413,
            )
        values.append(raw_value)
    completion: dict[str, Any] = {"values": values}
    total = raw_completion.get("total")
    if total is not None:
        if isinstance(total, bool) or not isinstance(total, int) or not 0 <= total <= max_total:
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP completion total is invalid",
                http_status=502,
            )
        completion["total"] = total
    has_more = raw_completion.get("hasMore")
    if has_more is not None:
        if not isinstance(has_more, bool):
            raise _fail(
                "MCP_PROTOCOL_MISMATCH",
                "MCP completion hasMore is invalid",
                http_status=502,
            )
        completion["hasMore"] = has_more
    result = {"completion": completion}
    if len(canonical_json(result).encode("utf-8")) > max_result_bytes:
        raise _fail(
            "MCP_COMPLETION_RESULT_TOO_LARGE",
            "MCP completion result exceeds the Gateway result limit",
            http_status=413,
        )
    return result
