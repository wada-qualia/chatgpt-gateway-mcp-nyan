from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from fastapi import HTTPException, Request, status
from jsonschema import Draft202012Validator, SchemaError
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import decode_jwt
from .models import (
    McpProjectionGeneration,
    McpProjectionTool,
    McpProjectionVerification,
    McpServer,
    McpTool,
    McpToolExposure,
    McpToolRevision,
    OAuthClient,
    User,
    utcnow,
)

PRESENTATION_PROFILES: dict[str, dict[str, Any]] = {
    "chatgpt-stable": {
        "label": "ChatGPT stable",
        "description": "Stable reviewed native actions; publication requires explicit ChatGPT refresh verification.",
        "supports_list_changed": False,
        "chatgpt_refresh_required": True,
    },
    "developer-dynamic": {
        "label": "Developer dynamic",
        "description": "Reviewed native tools with generic MCP tools.listChanged lifecycle.",
        "supports_list_changed": True,
        "chatgpt_refresh_required": False,
    },
    "agent-restricted": {
        "label": "Agent restricted",
        "description": "Allowlisted subset of built-in, broker and reviewed native tools.",
        "supports_list_changed": False,
        "chatgpt_refresh_required": False,
    },
}

_PUBLIC_NAME_RE = re.compile(r"[^a-z0-9_]+")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class PresentationContext:
    profile_id: str
    client_id: str | None
    policy_generation: int
    scopes: frozenset[str]
    allowed_tool_names: frozenset[str] | None

    @property
    def supports_list_changed(self) -> bool:
        return bool(PRESENTATION_PROFILES[self.profile_id]["supports_list_changed"])


@dataclass(frozen=True, slots=True)
class NativeProjectionEntry:
    generation: McpProjectionGeneration
    tool: McpProjectionTool


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _safe_description(value: str | None, *, limit: int = 1800) -> str:
    text = _CONTROL_RE.sub("", str(value or ""))
    text = " ".join(text.split())
    return text[:limit]


def public_projection_name(server_slug: str, tool_name: str, explicit: str | None) -> str:
    raw = explicit or f"{server_slug}__{tool_name}"
    normalized = _PUBLIC_NAME_RE.sub("_", raw.strip().lower()).strip("_")
    if not normalized:
        raise HTTPException(status_code=422, detail="Projected tool name is empty")
    if normalized[0].isdigit():
        normalized = f"tool_{normalized}"
    if len(normalized) > 64:
        suffix = hashlib.sha256(normalized.encode()).hexdigest()[:10]
        normalized = f"{normalized[:53].rstrip('_')}_{suffix}"
    return normalized


def presentation_profile_payload(profile_id: str) -> dict[str, Any]:
    if profile_id not in PRESENTATION_PROFILES:
        raise HTTPException(status_code=422, detail="Unknown presentation profile")
    return {"id": profile_id, **PRESENTATION_PROFILES[profile_id]}


def resolve_presentation_context(
    request: Request,
    db: Session,
    user: User,
) -> PresentationContext:
    auth_header = request.headers.get("authorization", "")
    claims: dict[str, Any] = {}
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            claims = decode_jwt(token)
        except Exception:
            claims = {}
    client_id = str(claims.get("client_id") or "").strip() or None
    scopes = frozenset(str(claims.get("scope") or "").split())
    if client_id is None:
        return PresentationContext(
            profile_id="developer-dynamic",
            client_id=None,
            policy_generation=1,
            scopes=scopes,
            allowed_tool_names=None,
        )
    client = db.get(OAuthClient, client_id)
    if client is None:
        raise HTTPException(status_code=401, detail="OAuth client is no longer registered")
    profile_id = str(
        claims.get("presentation_profile") or client.presentation_profile
    )
    token_generation = int(
        claims.get("presentation_policy_generation")
        or client.presentation_policy_generation
    )
    if token_generation != client.presentation_policy_generation:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "MCP_PRESENTATION_REAUTH_REQUIRED",
                "message": "Presentation policy changed; authorize the OAuth client again",
            },
        )
    if profile_id not in PRESENTATION_PROFILES:
        raise HTTPException(status_code=403, detail="Invalid presentation profile")
    claim_allowed = claims.get("allowed_tool_names")
    allowed_source = claim_allowed if isinstance(claim_allowed, list) else client.allowed_tool_names
    allowed = (
        frozenset(str(name) for name in (allowed_source or []))
        if profile_id == "agent-restricted"
        else None
    )
    return PresentationContext(
        profile_id=profile_id,
        client_id=client_id,
        policy_generation=token_generation,
        scopes=scopes,
        allowed_tool_names=allowed,
    )


def update_oauth_client_profile(
    db: Session,
    *,
    client_id: str,
    profile_id: str,
    allowed_tool_names: Iterable[str],
) -> OAuthClient:
    if profile_id not in PRESENTATION_PROFILES:
        raise HTTPException(status_code=422, detail="Unknown presentation profile")
    client = db.get(OAuthClient, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="OAuth client not found")
    normalized_allowed = sorted({str(name).strip() for name in allowed_tool_names if str(name).strip()})
    if profile_id != "agent-restricted":
        normalized_allowed = []
    if (
        client.presentation_profile != profile_id
        or list(client.allowed_tool_names or []) != normalized_allowed
    ):
        client.presentation_profile = profile_id
        client.allowed_tool_names = normalized_allowed
        client.presentation_policy_generation += 1
        client.updated_at = utcnow()
        db.commit()
        db.refresh(client)
    return client


def _is_additive_object_schema(old: dict[str, Any], new: dict[str, Any]) -> bool:
    if old.get("type") != "object" or new.get("type") != "object":
        return False
    old_props = old.get("properties") or {}
    new_props = new.get("properties") or {}
    if not isinstance(old_props, dict) or not isinstance(new_props, dict):
        return False
    for name, schema in old_props.items():
        if name not in new_props or new_props[name] != schema:
            return False
    old_required = set(old.get("required") or [])
    new_required = set(new.get("required") or [])
    if not new_required.issubset(old_required):
        return False
    old_additional = old.get("additionalProperties", True)
    new_additional = new.get("additionalProperties", True)
    if old_additional is True and new_additional is False:
        return False
    return True


def classify_projection_change(
    previous: McpProjectionTool | None,
    *,
    revision: McpToolRevision,
    exposure: McpToolExposure,
    title: str | None,
    description: str,
    annotations: dict[str, Any],
) -> str:
    if previous is None:
        return "new"
    risk_changed = any(
        (
            previous.action_class != revision.action_class,
            previous.required_role != exposure.required_role,
            previous.required_scope != exposure.required_scope,
            previous.approval_class != exposure.approval_class,
        )
    )
    if risk_changed:
        return "behavior_risk"
    same_schema = (
        previous.input_schema == revision.input_schema
        and previous.output_schema == revision.output_schema
    )
    if same_schema:
        if (
            previous.sanitized_title != title
            or previous.sanitized_description != description
            or previous.annotations != annotations
        ):
            return "metadata_only"
        return "metadata_only"
    if _is_additive_object_schema(previous.input_schema, revision.input_schema):
        old_output = previous.output_schema or {}
        new_output = revision.output_schema or {}
        if old_output == new_output or _is_additive_object_schema(old_output, new_output):
            return "backward_compatible_additive"
    return "breaking_schema"


def active_generation(
    db: Session, *, owner_subject: str, profile_id: str
) -> McpProjectionGeneration | None:
    return (
        db.query(McpProjectionGeneration)
        .filter(
            McpProjectionGeneration.owner_subject == owner_subject,
            McpProjectionGeneration.profile_id == profile_id,
            McpProjectionGeneration.status == "active",
        )
        .one_or_none()
    )


def generation_tools(
    db: Session, *, generation_id: str
) -> list[McpProjectionTool]:
    return (
        db.query(McpProjectionTool)
        .filter(McpProjectionTool.generation_id == generation_id)
        .order_by(McpProjectionTool.position.asc())
        .all()
    )


def _validate_revision_schema(revision: McpToolRevision) -> None:
    try:
        Draft202012Validator.check_schema(revision.input_schema)
        if revision.output_schema is not None:
            Draft202012Validator.check_schema(revision.output_schema)
    except SchemaError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "MCP_PROJECTION_INVALID_SCHEMA",
                "message": str(exc.message)[:500],
                "revision_id": revision.id,
            },
        ) from exc


def create_candidate_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    profile_id: str,
    reserved_names: Iterable[str],
    exposure_ids: list[str] | None = None,
) -> McpProjectionGeneration:
    if profile_id not in PRESENTATION_PROFILES:
        raise HTTPException(status_code=422, detail="Unknown presentation profile")
    query = (
        db.query(McpToolExposure, McpToolRevision, McpTool, McpServer)
        .join(McpToolRevision, McpToolRevision.id == McpToolExposure.revision_id)
        .join(McpTool, McpTool.id == McpToolExposure.tool_id)
        .join(McpServer, McpServer.id == McpToolExposure.server_id)
        .filter(
            McpToolExposure.owner_subject == owner_subject,
            McpToolExposure.mode == "native_projected",
            McpToolExposure.enabled.is_(True),
        )
    )
    if exposure_ids is not None:
        if not exposure_ids:
            raise HTTPException(status_code=422, detail="exposure_ids cannot be empty")
        query = query.filter(McpToolExposure.id.in_(exposure_ids))
    rows = query.all()
    if exposure_ids is not None and len(rows) != len(set(exposure_ids)):
        raise HTTPException(status_code=404, detail="One or more native exposures were not found")
    previous = active_generation(db, owner_subject=owner_subject, profile_id=profile_id)
    previous_by_name = {
        item.public_name: item
        for item in (generation_tools(db, generation_id=previous.id) if previous else [])
    }
    reserved = set(reserved_names)
    prepared: list[dict[str, Any]] = []
    names: set[str] = set()
    for exposure, revision, tool, server in rows:
        if server.trust_level != "approved":
            raise HTTPException(
                status_code=422,
                detail={"code": "MCP_PROJECTION_SERVER_UNREVIEWED", "server_id": server.id},
            )
        if revision.action_class == "unknown":
            raise HTTPException(
                status_code=422,
                detail={"code": "MCP_PROJECTION_REVISION_UNCLASSIFIED", "revision_id": revision.id},
            )
        if revision.action_class == "read" and revision.read_only_status != "verified":
            raise HTTPException(
                status_code=422,
                detail={"code": "MCP_PROJECTION_READ_ONLY_UNVERIFIED", "revision_id": revision.id},
            )
        _validate_revision_schema(revision)
        public_name = public_projection_name(
            server.normalized_slug,
            tool.normalized_name,
            exposure.projected_name,
        )
        if public_name in reserved or public_name in names:
            raise HTTPException(
                status_code=409,
                detail={"code": "MCP_PROJECTION_NAME_COLLISION", "public_name": public_name},
            )
        names.add(public_name)
        title = _safe_description(revision.sanitized_title, limit=240) or None
        description = _safe_description(revision.sanitized_description)
        availability_note = "Availability is enforced by Gateway at invocation time."
        description = f"{description} {availability_note}".strip()
        annotations = dict(revision.annotations or {})
        classification = classify_projection_change(
            previous_by_name.get(public_name),
            revision=revision,
            exposure=exposure,
            title=title,
            description=description,
            annotations=annotations,
        )
        prepared.append(
            {
                "public_name": public_name,
                "source_exposure_id": exposure.id,
                "server_id": server.id,
                "tool_id": tool.id,
                "revision_id": revision.id,
                "source_schema_hash": revision.schema_hash,
                "input_schema": revision.input_schema,
                "output_schema": revision.output_schema,
                "sanitized_title": title,
                "sanitized_description": description,
                "annotations": annotations,
                "action_class": revision.action_class,
                "required_role": exposure.required_role,
                "required_scope": exposure.required_scope,
                "approval_class": exposure.approval_class,
                "change_classification": classification,
            }
        )
    prepared.sort(key=lambda item: item["public_name"])
    removed = sorted(set(previous_by_name).difference(names))
    counts: dict[str, int] = {}
    for item in prepared:
        key = item["change_classification"]
        counts[key] = counts.get(key, 0) + 1
    if removed:
        counts["removed_unavailable"] = len(removed)
    max_generation = (
        db.query(func.max(McpProjectionGeneration.generation_number))
        .filter(
            McpProjectionGeneration.owner_subject == owner_subject,
            McpProjectionGeneration.profile_id == profile_id,
        )
        .scalar()
        or 0
    )
    schema_document = [
        {
            "name": item["public_name"],
            "inputSchema": item["input_schema"],
            "outputSchema": item["output_schema"],
        }
        for item in prepared
    ]
    content_document = [dict(item) for item in prepared]
    generation = McpProjectionGeneration(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        profile_id=profile_id,
        generation_number=max_generation + 1,
        status="candidate",
        previous_generation_id=previous.id if previous else None,
        content_hash=_sha256(content_document),
        schema_hash=_sha256(schema_document),
        change_summary={"counts": counts, "removed": removed, "tool_count": len(prepared)},
        tools_list_changed_state="not_required",
        chatgpt_refresh_state="not_required",
        created_by_subject=actor_subject,
        updated_at=utcnow(),
    )
    db.add(generation)
    db.flush()
    for position, item in enumerate(prepared):
        db.add(
            McpProjectionTool(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                generation_id=generation.id,
                position=position,
                **item,
            )
        )
    db.commit()
    db.refresh(generation)
    return generation


def list_generations(
    db: Session, *, owner_subject: str, profile_id: str | None = None
) -> list[McpProjectionGeneration]:
    query = db.query(McpProjectionGeneration).filter(
        McpProjectionGeneration.owner_subject == owner_subject
    )
    if profile_id:
        query = query.filter(McpProjectionGeneration.profile_id == profile_id)
    return query.order_by(
        McpProjectionGeneration.profile_id.asc(),
        McpProjectionGeneration.generation_number.desc(),
    ).all()


def get_generation(
    db: Session, *, owner_subject: str, generation_id: str
) -> McpProjectionGeneration:
    generation = db.get(McpProjectionGeneration, generation_id)
    if generation is None or generation.owner_subject != owner_subject:
        raise HTTPException(status_code=404, detail="Projection generation not found")
    return generation


def publish_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    generation_id: str,
) -> McpProjectionGeneration:
    generation = get_generation(db, owner_subject=owner_subject, generation_id=generation_id)
    if generation.status != "candidate":
        raise HTTPException(status_code=409, detail="Only candidate generations can be published")
    current = active_generation(db, owner_subject=owner_subject, profile_id=generation.profile_id)
    if current is not None:
        current.status = "superseded"
        current.updated_at = utcnow()
    generation.status = "active"
    generation.published_by_subject = actor_subject
    generation.published_at = utcnow()
    generation.updated_at = utcnow()
    generation.tools_list_changed_state = (
        "pending" if PRESENTATION_PROFILES[generation.profile_id]["supports_list_changed"] else "not_required"
    )
    generation.chatgpt_refresh_state = (
        "pending" if PRESENTATION_PROFILES[generation.profile_id]["chatgpt_refresh_required"] else "not_required"
    )
    db.commit()
    db.refresh(generation)
    return generation


def rollback_generation(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    generation_id: str,
) -> McpProjectionGeneration:
    generation = get_generation(db, owner_subject=owner_subject, generation_id=generation_id)
    if generation.status not in {"superseded", "active"}:
        raise HTTPException(status_code=409, detail="Generation is not eligible for rollback")
    current = active_generation(db, owner_subject=owner_subject, profile_id=generation.profile_id)
    if current is not None and current.id != generation.id:
        current.status = "superseded"
        current.updated_at = utcnow()
    generation.status = "active"
    generation.published_by_subject = actor_subject
    generation.published_at = utcnow()
    generation.updated_at = utcnow()
    generation.tools_list_changed_state = (
        "pending" if PRESENTATION_PROFILES[generation.profile_id]["supports_list_changed"] else "not_required"
    )
    generation.chatgpt_refresh_state = (
        "pending" if PRESENTATION_PROFILES[generation.profile_id]["chatgpt_refresh_required"] else "not_required"
    )
    db.commit()
    db.refresh(generation)
    return generation


def record_projection_verification(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    generation_id: str,
    verification_kind: str,
    observed_schema_hash: str,
    evidence: dict[str, Any],
) -> McpProjectionVerification:
    generation = get_generation(db, owner_subject=owner_subject, generation_id=generation_id)
    if generation.status != "active":
        raise HTTPException(status_code=409, detail="Only the active generation can be verified")
    if observed_schema_hash != generation.schema_hash:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MCP_PROJECTION_SCHEMA_VERIFICATION_MISMATCH",
                "expected": generation.schema_hash,
                "observed": observed_schema_hash,
            },
        )
    if verification_kind == "chatgpt_actions":
        if generation.profile_id != "chatgpt-stable":
            raise HTTPException(status_code=422, detail="ChatGPT verification applies only to chatgpt-stable")
        generation.chatgpt_refresh_state = "verified"
    elif verification_kind == "generic_tools_list_changed":
        if not PRESENTATION_PROFILES[generation.profile_id]["supports_list_changed"]:
            raise HTTPException(status_code=422, detail="Profile does not advertise tools.listChanged")
        generation.tools_list_changed_state = "notified"
    else:
        raise HTTPException(status_code=422, detail="Unknown verification kind")
    generation.updated_at = utcnow()
    verification = McpProjectionVerification(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        generation_id=generation.id,
        verification_kind=verification_kind,
        observed_schema_hash=observed_schema_hash,
        evidence=dict(evidence or {}),
        verified_by_subject=actor_subject,
    )
    db.add(verification)
    db.commit()
    db.refresh(verification)
    return verification


def projection_entries_for_context(
    db: Session,
    *,
    owner_subject: str,
    user_roles: Iterable[str],
    context: PresentationContext,
) -> list[NativeProjectionEntry]:
    generation = active_generation(
        db, owner_subject=owner_subject, profile_id=context.profile_id
    )
    if generation is None:
        return []
    roles = set(user_roles)
    entries: list[NativeProjectionEntry] = []
    for tool in generation_tools(db, generation_id=generation.id):
        if tool.required_role and tool.required_role not in roles and "gateway-admin" not in roles:
            continue
        if tool.required_scope and tool.required_scope not in context.scopes:
            continue
        if context.allowed_tool_names is not None and tool.public_name not in context.allowed_tool_names:
            continue
        entries.append(NativeProjectionEntry(generation=generation, tool=tool))
    return entries


def native_tool_definition(entry: NativeProjectionEntry) -> dict[str, Any]:
    tool = entry.tool
    definition: dict[str, Any] = {
        "name": tool.public_name,
        "description": tool.sanitized_description,
        "inputSchema": tool.input_schema,
        "annotations": dict(tool.annotations or {}),
    }
    if tool.sanitized_title:
        definition["title"] = tool.sanitized_title
    if tool.output_schema is not None:
        definition["outputSchema"] = tool.output_schema
    return definition


def generation_payload(db: Session, generation: McpProjectionGeneration, *, include_tools: bool = False) -> dict[str, Any]:
    payload = {
        "id": generation.id,
        "owner_subject": generation.owner_subject,
        "profile_id": generation.profile_id,
        "generation_number": generation.generation_number,
        "status": generation.status,
        "previous_generation_id": generation.previous_generation_id,
        "content_hash": generation.content_hash,
        "schema_hash": generation.schema_hash,
        "change_summary": generation.change_summary,
        "tools_list_changed_state": generation.tools_list_changed_state,
        "chatgpt_refresh_state": generation.chatgpt_refresh_state,
        "created_by_subject": generation.created_by_subject,
        "published_by_subject": generation.published_by_subject,
        "created_at": generation.created_at,
        "published_at": generation.published_at,
        "updated_at": generation.updated_at,
    }
    if include_tools:
        payload["tools"] = [
            {
                "id": tool.id,
                "position": tool.position,
                "public_name": tool.public_name,
                "source_exposure_id": tool.source_exposure_id,
                "server_id": tool.server_id,
                "tool_id": tool.tool_id,
                "revision_id": tool.revision_id,
                "source_schema_hash": tool.source_schema_hash,
                "input_schema": tool.input_schema,
                "output_schema": tool.output_schema,
                "sanitized_title": tool.sanitized_title,
                "sanitized_description": tool.sanitized_description,
                "annotations": tool.annotations,
                "action_class": tool.action_class,
                "required_role": tool.required_role,
                "required_scope": tool.required_scope,
                "approval_class": tool.approval_class,
                "change_classification": tool.change_classification,
            }
            for tool in generation_tools(db, generation_id=generation.id)
        ]
    return payload


def oauth_client_presentation_payload(client: OAuthClient) -> dict[str, Any]:
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "presentation_profile": client.presentation_profile,
        "presentation_policy_generation": client.presentation_policy_generation,
        "allowed_tool_names": list(client.allowed_tool_names or []),
        "updated_at": client.updated_at,
    }
