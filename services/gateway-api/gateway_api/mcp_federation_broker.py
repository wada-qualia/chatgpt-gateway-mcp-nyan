from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from jsonschema import Draft202012Validator, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .agent_autonomy import DEFAULT_APPROVAL_RULES, agent_autonomy_service
from .crypto import decrypt_text, encrypt_text
from .dto import (
    McpActionExecuteInput,
    McpActionPrepareInput,
    McpCallReadInput,
    McpCatalogSearchInput,
    McpToolDescribeInput,
)
from .events import emit_event
from .mcp_federation import get_policy, get_revision, get_server, get_tool
from .mcp_federation_policy import (
    McpActionClass,
    McpApprovalClass,
    McpExposureMode,
    McpReadOnlyStatus,
    McpTrustLevel,
    authorize_tool_revision,
    canonical_json,
    reject_secret_shaped_payload,
    required_approval_for,
    sha256_json,
)
from .mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from .models import (
    ActionReceipt,
    AgentCommand,
    AgentInstance,
    ApprovalRequest,
    AutonomyPolicy,
    CollaborationRoom,
    ExecutionPermit,
    McpActionPreparation,
    McpFederationPolicy,
    McpServer,
    McpTool,
    McpToolExposure,
    McpToolRevision,
    SecretBlob,
    User,
    utcnow,
)

_TOOL_REF = re.compile(
    r"^mcp-tool://(?P<server>[0-9a-f-]{36})/(?P<tool>[0-9a-f-]{36})/(?P<revision>[0-9a-f-]{36})$",
    re.IGNORECASE,
)
_BROKER_TOOL_NAMES = frozenset(
    {
        "mcp_catalog_search",
        "mcp_tool_describe",
        "mcp_call_read",
        "mcp_action_prepare",
        "mcp_action_execute",
    }
)
_APPROVAL_ORDER = {
    McpApprovalClass.NONE: 0,
    McpApprovalClass.OPERATOR: 1,
    McpApprovalClass.QUORUM: 2,
    McpApprovalClass.PRODUCTION: 3,
}
_SYSTEM_ROOM_KEY = "mcp-federation-guarded-actions-room"
_SYSTEM_POLICY_KEY = "mcp-federation-guarded-actions-policy"
_SYSTEM_PROPOSER_INSTANCE = "mcp-federation-proposer"
_SYSTEM_EXECUTOR_INSTANCE = "mcp-federation-executor"


@dataclass(frozen=True, slots=True)
class AuthorizedRevision:
    server: McpServer
    tool: McpTool
    revision: McpToolRevision
    exposure: McpToolExposure
    policy: McpFederationPolicy
    approval_class: McpApprovalClass


@dataclass(frozen=True, slots=True)
class FederationExecutionContext:
    room: CollaborationRoom
    proposer: AgentInstance
    executor: AgentInstance
    policy: AutonomyPolicy


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _object(
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
    *,
    additional: bool = False,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": additional,
    }


def _string(description: str, *, min_length: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "description": description}
    if min_length is not None:
        result["minLength"] = min_length
    return result


def _integer(
    description: str, *, minimum: int, maximum: int, default: int
) -> dict[str, Any]:
    return {
        "type": "integer",
        "description": description,
        "minimum": minimum,
        "maximum": maximum,
        "default": default,
    }


def _tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    *,
    read_only: bool,
    idempotent: bool,
    destructive: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "outputSchema": _object(additional=True),
        "annotations": {
            "title": name.replace("_", " ").title(),
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": True,
        },
    }


def mcp_federation_broker_tools() -> list[dict[str, Any]]:
    tool_ref = _string(
        "Stable exact tool reference returned by mcp_catalog_search.", min_length=1
    )
    schema_hash = _string("Exact immutable SHA-256 schema hash.", min_length=64)
    arguments = {
        "type": "object",
        "description": "Arguments validated against the selected immutable upstream schema. Never include secrets.",
        "additionalProperties": True,
    }
    return [
        _tool(
            "mcp_catalog_search",
            "Search the tenant-scoped reviewed MCP catalog. Results are policy-filtered summaries and never execute an upstream tool.",
            _object(
                {
                    "query": _string(
                        "Search terms for server, tool, description, or argument names.",
                        min_length=1,
                    ),
                    "server_id": _string("Optional exact MCP server id."),
                    "limit": _integer(
                        "Maximum result count.", minimum=1, maximum=50, default=20
                    ),
                },
                ["query"],
            ),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "mcp_tool_describe",
            "Return one exact reviewed immutable MCP tool revision, including its schemas, risk classification, exposure, and availability.",
            _object(
                {"tool_ref": tool_ref, "schema_hash": schema_hash},
                ["tool_ref", "schema_hash"],
            ),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "mcp_call_read",
            "Execute only an independently verified read-only MCP tool revision after exact policy, schema, and availability checks.",
            _object(
                {
                    "tool_ref": tool_ref,
                    "schema_hash": schema_hash,
                    "arguments": arguments,
                },
                ["tool_ref", "schema_hash", "arguments"],
            ),
            read_only=True,
            idempotent=False,
        ),
        _tool(
            "mcp_action_prepare",
            "Validate and prepare a write-capable MCP action without executing it. Creates a guarded approval request and encrypted immutable argument binding.",
            _object(
                {
                    "tool_ref": tool_ref,
                    "schema_hash": schema_hash,
                    "arguments": arguments,
                    "justification": _string(
                        "Human-readable reason for the action.", min_length=1
                    ),
                    "idempotency_key": _string(
                        "Caller-stable key for deterministic preparation replay.",
                        min_length=1,
                    ),
                },
                [
                    "tool_ref",
                    "schema_hash",
                    "arguments",
                    "justification",
                    "idempotency_key",
                ],
            ),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "mcp_action_execute",
            "Execute one exact prepared MCP action only after approval and an exact unconsumed execution permit. Records an immutable action receipt.",
            _object(
                {
                    "preparation_id": _string(
                        "Preparation returned by mcp_action_prepare.", min_length=1
                    ),
                    "permit_id": _string(
                        "Exact execution permit issued for the preparation approval request.",
                        min_length=1,
                    ),
                    "expected_schema_hash": schema_hash,
                },
                ["preparation_id", "permit_id", "expected_schema_hash"],
            ),
            read_only=False,
            idempotent=True,
            destructive=True,
        ),
    ]


def mcp_federation_broker_tool_names() -> frozenset[str]:
    return _BROKER_TOOL_NAMES


def _tool_ref(server_id: str, tool_id: str, revision_id: str) -> str:
    return f"mcp-tool://{server_id}/{tool_id}/{revision_id}"


def _parse_tool_ref(value: str) -> tuple[str, str, str]:
    match = _TOOL_REF.fullmatch(value.strip())
    if match is None:
        raise HTTPException(status_code=422, detail="Invalid MCP tool reference")
    return match.group("server"), match.group("tool"), match.group("revision")


def _actor_scopes(user: User) -> list[str]:
    value = dict(user.preferences or {}).get("scopes", [])
    if isinstance(value, str):
        return [item for item in value.replace(",", " ").split() if item]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _current_exposure(
    db: Session, *, owner_subject: str, revision_id: str
) -> McpToolExposure | None:
    return (
        db.query(McpToolExposure)
        .filter(
            McpToolExposure.owner_subject == owner_subject,
            McpToolExposure.revision_id == revision_id,
            McpToolExposure.enabled.is_(True),
            McpToolExposure.mode.in_(["catalog_only", "native_projected"]),
        )
        .order_by(
            McpToolExposure.projection_generation.desc(),
            McpToolExposure.version.desc(),
        )
        .first()
    )


def _federation_policy(
    db: Session, *, owner_subject: str, server_id: str
) -> McpFederationPolicy | None:
    return get_policy(
        db, owner_subject=owner_subject, server_id=server_id
    ) or get_policy(db, owner_subject=owner_subject, server_id=None)


def _strongest_approval(
    action_class: McpActionClass, *configured: McpApprovalClass
) -> McpApprovalClass:
    required = required_approval_for(action_class)
    return max((required, *configured), key=_APPROVAL_ORDER.__getitem__)


def _resolve_authorized(
    db: Session,
    *,
    user: User,
    tool_ref: str,
    schema_hash: str,
    require_available: bool,
) -> AuthorizedRevision:
    server_id, tool_id, revision_id = _parse_tool_ref(tool_ref)
    server = get_server(db, owner_subject=user.subject, server_id=server_id)
    tool = get_tool(db, owner_subject=user.subject, tool_id=tool_id)
    revision = get_revision(db, owner_subject=user.subject, revision_id=revision_id)
    if (
        tool.server_id != server.id
        or revision.server_id != server.id
        or revision.tool_id != tool.id
    ):
        raise HTTPException(
            status_code=409, detail="MCP tool reference components do not match"
        )
    if revision.schema_hash != schema_hash:
        raise HTTPException(
            status_code=409,
            detail="MCP schema hash does not match the selected revision",
        )
    if tool.lifecycle_state != "active" or tool.current_revision_id != revision.id:
        raise HTTPException(
            status_code=409,
            detail="MCP tool revision is not the current active revision",
        )
    if require_available and server.status not in {"online", "degraded"}:
        raise HTTPException(
            status_code=409, detail=f"MCP server is not callable: {server.status}"
        )
    exposure = _current_exposure(
        db, owner_subject=user.subject, revision_id=revision.id
    )
    if exposure is None:
        raise HTTPException(status_code=403, detail="MCP tool revision is not exposed")
    policy = _federation_policy(db, owner_subject=user.subject, server_id=server.id)
    if policy is None or policy.status != "active":
        raise HTTPException(
            status_code=403, detail="No active MCP federation policy permits this tool"
        )
    if policy.required_roles and not set(policy.required_roles).issubset(
        set(user.roles or [])
    ):
        raise HTTPException(
            status_code=403, detail="MCP federation policy roles are missing"
        )
    if policy.required_scopes and not set(policy.required_scopes).issubset(
        set(_actor_scopes(user))
    ):
        raise HTTPException(
            status_code=403, detail="MCP federation policy scopes are missing"
        )
    identities = {tool.id, tool.upstream_name, tool.normalized_name, revision.id}
    if policy.tool_denylist and identities.intersection(set(policy.tool_denylist)):
        raise HTTPException(
            status_code=403, detail="MCP tool is denied by federation policy"
        )
    if policy.tool_allowlist and not identities.intersection(
        set(policy.tool_allowlist)
    ):
        raise HTTPException(
            status_code=403, detail="MCP tool is not in the federation allowlist"
        )
    try:
        action_class = McpActionClass(revision.action_class)
        exposure_approval = McpApprovalClass(exposure.approval_class)
        policy_approval = McpApprovalClass(
            dict(policy.approval_mapping or {}).get(
                action_class.value, McpApprovalClass.NONE.value
            )
        )
        decision = authorize_tool_revision(
            actor_roles=list(user.roles or []),
            actor_scopes=_actor_scopes(user),
            trust_level=McpTrustLevel(policy.trust_level),
            exposure_mode=McpExposureMode(exposure.mode),
            exposure_enabled=exposure.enabled,
            action_class=action_class,
            read_only_status=McpReadOnlyStatus(revision.read_only_status),
            required_role=exposure.required_role,
            required_scope=exposure.required_scope,
            allowed_action_classes=policy.allowed_action_classes,
            approval_class=_strongest_approval(
                action_class, exposure_approval, policy_approval
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Invalid MCP policy state") from exc
    if not decision.allowed:
        raise HTTPException(
            status_code=403, detail=f"MCP policy denied: {decision.reason}"
        )
    return AuthorizedRevision(
        server=server,
        tool=tool,
        revision=revision,
        exposure=exposure,
        policy=policy,
        approval_class=decision.approval_class,
    )


def resolve_authorized_revision(
    db: Session,
    *,
    user: User,
    tool_ref: str,
    schema_hash: str,
    require_available: bool,
) -> AuthorizedRevision:
    return _resolve_authorized(
        db,
        user=user,
        tool_ref=tool_ref,
        schema_hash=schema_hash,
        require_available=require_available,
    )


def _summary(item: AuthorizedRevision) -> dict[str, Any]:
    revision = item.revision
    return {
        "tool_ref": _tool_ref(item.server.id, item.tool.id, revision.id),
        "schema_hash": revision.schema_hash,
        "server_id": item.server.id,
        "server_name": item.server.display_name,
        "server_status": item.server.status,
        "tool_id": item.tool.id,
        "name": item.tool.upstream_name,
        "title": revision.sanitized_title,
        "description": revision.sanitized_description,
        "action_class": revision.action_class,
        "read_only_status": revision.read_only_status,
        "exposure_mode": item.exposure.mode,
        "approval_class": item.approval_class.value,
        "catalog_generation": revision.catalog_generation,
    }


def search_catalog(
    db: Session, *, user: User, payload: McpCatalogSearchInput
) -> dict[str, Any]:
    query_text = " ".join(payload.query.split())
    base = (
        db.query(McpToolRevision, McpTool, McpServer)
        .join(McpTool, McpTool.id == McpToolRevision.tool_id)
        .join(McpServer, McpServer.id == McpToolRevision.server_id)
        .filter(
            McpToolRevision.owner_subject == user.subject,
            McpTool.owner_subject == user.subject,
            McpServer.owner_subject == user.subject,
            McpTool.lifecycle_state == "active",
            McpTool.current_revision_id == McpToolRevision.id,
        )
    )
    if payload.server_id:
        base = base.filter(McpServer.id == payload.server_id)
    dialect = db.bind.dialect.name if db.bind is not None else ""
    if dialect == "postgresql":
        base = base.filter(
            text(
                "mcp_tool_revisions.search_vector @@ websearch_to_tsquery('simple', :mcp_catalog_query)"
            )
        ).params(mcp_catalog_query=query_text)
        base = base.order_by(
            text(
                "ts_rank_cd(mcp_tool_revisions.search_vector, websearch_to_tsquery('simple', :mcp_catalog_query)) DESC"
            ),
            McpTool.upstream_name.asc(),
        )
    else:
        tokens = [token.casefold() for token in query_text.split() if token]
        rows = base.order_by(McpTool.upstream_name.asc()).limit(1000).all()
        rows = [
            row
            for row in rows
            if all(
                token in str(row[0].search_text or "").casefold() for token in tokens
            )
        ]
        base = None
    rows = rows if base is None else base.limit(500).all()
    results: list[dict[str, Any]] = []
    for revision, tool, server in rows:
        try:
            authorized = _resolve_authorized(
                db,
                user=user,
                tool_ref=_tool_ref(server.id, tool.id, revision.id),
                schema_hash=revision.schema_hash,
                require_available=False,
            )
        except HTTPException:
            continue
        results.append(_summary(authorized))
        if len(results) >= payload.limit:
            break
    return {"query": query_text, "results": results, "count": len(results)}


def describe_tool(
    db: Session, *, user: User, payload: McpToolDescribeInput
) -> dict[str, Any]:
    item = _resolve_authorized(
        db,
        user=user,
        tool_ref=payload.tool_ref,
        schema_hash=payload.schema_hash,
        require_available=False,
    )
    result = _summary(item)
    result.update(
        {
            "input_schema": item.revision.input_schema,
            "output_schema": item.revision.output_schema,
            "annotations": item.revision.annotations,
            "icons": item.revision.icons,
            "execution": {
                **dict(item.revision.execution or {}),
                "task_execution_enabled": False,
            },
            "server_instructions": {
                "text": item.server.sanitized_instructions,
                "sha256": item.server.instructions_sha256,
                "trust": "untrusted_advisory",
            },
            "client_only_meta": {
                "present": bool(item.revision.component_meta),
                "sha256": sha256_json(item.revision.component_meta)
                if item.revision.component_meta
                else None,
                "model_visible": False,
            },
            "risk_evidence": item.revision.risk_evidence,
            "protocol_version": item.revision.protocol_version,
            "required_role": item.exposure.required_role,
            "required_scope": item.exposure.required_scope,
            "policy_generation": item.policy.generation,
            "exposure_version": item.exposure.version,
        }
    )
    return {"tool": result}


def _validate_arguments(revision: McpToolRevision, arguments: dict[str, Any]) -> None:
    reject_secret_shaped_payload(arguments)
    try:
        Draft202012Validator(revision.input_schema).validate(arguments)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Arguments do not match the selected MCP schema at {list(exc.path)}",
        ) from exc


async def call_read(
    db: Session,
    *,
    user: User,
    payload: McpCallReadInput,
    upstream: UpstreamMcpManager,
    gateway_tool_call_id: str | None,
) -> dict[str, Any]:
    item = _resolve_authorized(
        db,
        user=user,
        tool_ref=payload.tool_ref,
        schema_hash=payload.schema_hash,
        require_available=True,
    )
    if (
        item.revision.action_class != "read"
        or item.revision.read_only_status != "verified"
    ):
        raise HTTPException(
            status_code=403,
            detail="mcp_call_read requires a verified read-only revision",
        )
    _validate_arguments(item.revision, payload.arguments)
    try:
        result = await upstream.call_exact_revision(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            revision_id=item.revision.id,
            arguments=payload.arguments,
            gateway_tool_call_id=gateway_tool_call_id,
        )
    except UpstreamMcpError as exc:
        raise HTTPException(
            status_code=exc.http_status, detail=exc.as_detail()
        ) from exc
    return {
        "tool_ref": payload.tool_ref,
        "schema_hash": item.revision.schema_hash,
        "invocation_id": result.invocation_id,
        "result": result.payload,
        "truncated": result.truncated,
        "serialized_bytes": result.serialized_bytes,
        "upstream_is_error": result.is_error,
    }


def _system_subject(owner_subject: str) -> str:
    return f"mcp-federation-system:{sha256_json(owner_subject)[:24]}"


def _ensure_execution_context(
    db: Session, *, owner_subject: str
) -> FederationExecutionContext:
    now = utcnow()
    room = (
        db.query(CollaborationRoom)
        .filter(
            CollaborationRoom.owner_subject == owner_subject,
            CollaborationRoom.idempotency_key == _SYSTEM_ROOM_KEY,
        )
        .one_or_none()
    )
    if room is None:
        room = CollaborationRoom(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            title="MCP federation guarded actions",
            status="active",
            policy={"system_managed": True, "purpose": "mcp_federation"},
            idempotency_key=_SYSTEM_ROOM_KEY,
            created_at=now,
            updated_at=now,
        )
        db.add(room)
        db.flush()
    if room.status != "active":
        raise HTTPException(
            status_code=423, detail="MCP federation action room is not active"
        )

    def agent(instance_id: str, display_name: str) -> AgentInstance:
        row = (
            db.query(AgentInstance)
            .filter(
                AgentInstance.owner_subject == owner_subject,
                AgentInstance.instance_id == instance_id,
            )
            .one_or_none()
        )
        if row is None:
            row = AgentInstance(
                id=str(uuid.uuid4()),
                owner_subject=owner_subject,
                logical_agent_id=instance_id,
                instance_id=instance_id,
                display_name=display_name,
                status="active",
                capabilities=["mcp_federation_guarded_action"],
                labels={"system_managed": True},
                current_room_id=room.id,
                last_heartbeat_at=now,
                expires_at=now + timedelta(days=3650),
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
        row.status = "active"
        row.current_room_id = room.id
        row.last_heartbeat_at = now
        row.expires_at = now + timedelta(days=3650)
        row.updated_at = now
        return row

    proposer = agent(_SYSTEM_PROPOSER_INSTANCE, "MCP Federation Proposer")
    executor = agent(_SYSTEM_EXECUTOR_INSTANCE, "MCP Federation Executor")
    policy = (
        db.query(AutonomyPolicy)
        .filter(
            AutonomyPolicy.owner_subject == owner_subject,
            AutonomyPolicy.idempotency_key == _SYSTEM_POLICY_KEY,
        )
        .one_or_none()
    )
    if policy is None:
        policy = AutonomyPolicy(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            room_id=room.id,
            name="MCP federation guarded action policy",
            status="active",
            assignment_mode="manual",
            coordinator_agent_id=executor.id,
            allowed_action_classes=["write", "destructive", "production"],
            allowed_tools=["mcp_action_execute"],
            allowed_command_profiles=[],
            max_parallel_assignments=1,
            approval_rules=DEFAULT_APPROVAL_RULES,
            recovery_policy={
                "max_attempts": 1,
                "base_backoff_seconds": 30,
                "max_backoff_seconds": 30,
            },
            generation=1,
            version=1,
            idempotency_key=_SYSTEM_POLICY_KEY,
            created_by_subject=_system_subject(owner_subject),
            created_at=now,
            updated_at=now,
        )
        db.add(policy)
        db.flush()
    if (
        policy.status != "active"
        or policy.room_id != room.id
        or "mcp_action_execute" not in set(policy.allowed_tools or [])
    ):
        raise HTTPException(
            status_code=423, detail="MCP federation autonomy policy is not active"
        )
    agent_autonomy_service.assert_enabled(
        db,
        owner_subject=owner_subject,
        room_id=room.id,
        policy=policy,
    )
    return FederationExecutionContext(
        room=room, proposer=proposer, executor=executor, policy=policy
    )


def _approval_rule(approval_class: McpApprovalClass) -> dict[str, Any]:
    if approval_class is McpApprovalClass.OPERATOR:
        return {"quorum": 1, "require_admin": False, "disallow_proposer": True}
    if approval_class is McpApprovalClass.QUORUM:
        return {"quorum": 2, "require_admin": True, "disallow_proposer": True}
    if approval_class is McpApprovalClass.PRODUCTION:
        return {"quorum": 2, "require_admin": True, "disallow_proposer": True}
    raise HTTPException(
        status_code=409, detail="Write-capable MCP action has no approval requirement"
    )


def _command_hash(command: AgentCommand) -> str:
    return sha256_json(
        {
            "command_id": command.id,
            "room_id": command.room_id,
            "issuer_agent_id": command.issuer_agent_id,
            "target_agent_id": command.target_agent_id,
            "kind": command.kind,
            "instruction": command.instruction,
            "structured_payload": command.structured_payload,
            "constraints": command.constraints,
        }
    )


def _preparation_payload(preparation: McpActionPreparation) -> dict[str, Any]:
    return {
        "preparation_id": preparation.id,
        "tool_ref": _tool_ref(
            preparation.server_id, preparation.tool_id, preparation.revision_id
        ),
        "schema_hash": preparation.schema_hash,
        "action_class": preparation.action_class,
        "arguments_sha256": preparation.arguments_sha256,
        "preview": preparation.preview,
        "approval_class": preparation.approval_class,
        "approval_request_id": preparation.approval_request_id,
        "executor_agent_id": preparation.executor_agent_id,
        "status": preparation.status,
        "expires_at": preparation.expires_at.isoformat(),
    }


def prepare_action(
    db: Session,
    *,
    user: User,
    payload: McpActionPrepareInput,
    preparation_ttl_seconds: int,
) -> dict[str, Any]:
    item = _resolve_authorized(
        db,
        user=user,
        tool_ref=payload.tool_ref,
        schema_hash=payload.schema_hash,
        require_available=True,
    )
    if item.revision.action_class not in {"write", "destructive", "production"}:
        raise HTTPException(
            status_code=403,
            detail="mcp_action_prepare requires a classified write-capable revision",
        )
    _validate_arguments(item.revision, payload.arguments)
    arguments_hash = sha256_json(payload.arguments)
    existing = (
        db.query(McpActionPreparation)
        .filter(
            McpActionPreparation.owner_subject == user.subject,
            McpActionPreparation.idempotency_key == payload.idempotency_key,
        )
        .one_or_none()
    )
    if existing is not None:
        if (
            existing.revision_id != item.revision.id
            or existing.schema_hash != item.revision.schema_hash
            or existing.arguments_sha256 != arguments_hash
            or existing.actor_subject != user.subject
        ):
            raise HTTPException(
                status_code=409, detail="MCP action preparation idempotency conflict"
            )
        return {"preparation": _preparation_payload(existing), "replayed": True}

    context = _ensure_execution_context(db, owner_subject=user.subject)
    now = utcnow()
    expires_at = now + timedelta(
        seconds=max(60, min(int(preparation_ttl_seconds), 86400))
    )
    secret = SecretBlob(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        kind="mcp_action_arguments",
        ciphertext=encrypt_text(canonical_json(payload.arguments)),
        created_at=now,
    )
    db.add(secret)
    db.flush()
    preparation_id = str(uuid.uuid4())
    command = AgentCommand(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        room_id=context.room.id,
        issuer_agent_id=context.proposer.id,
        target_agent_id=context.executor.id,
        kind="run_tool",
        instruction="Execute the exact approved MCP federation preparation.",
        structured_payload={
            "tool": "mcp_action_execute",
            "arguments": {
                "preparation_id": preparation_id,
                "expected_schema_hash": item.revision.schema_hash,
                "arguments_sha256": arguments_hash,
            },
        },
        constraints={
            "server_id": item.server.id,
            "tool_id": item.tool.id,
            "revision_id": item.revision.id,
            "exposure_version": item.exposure.version,
            "federation_policy_generation": item.policy.generation,
        },
        priority=80,
        status="pending",
        requires_approval=True,
        correlation_id=preparation_id,
        idempotency_key=f"mcp-action-command:{payload.idempotency_key}",
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(command)
    db.flush()
    command_hash = _command_hash(command)
    rule = _approval_rule(item.approval_class)
    approval = ApprovalRequest(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        room_id=context.room.id,
        policy_id=context.policy.id,
        command_id=command.id,
        proposer_agent_id=context.proposer.id,
        executor_agent_id=context.executor.id,
        action_kind="mcp_federation_action",
        action_class=item.revision.action_class,
        tool="mcp_action_execute",
        payload_hash=command_hash,
        payload_summary={
            "preparation_id": preparation_id,
            "server_id": item.server.id,
            "tool_id": item.tool.id,
            "revision_id": item.revision.id,
            "schema_hash": item.revision.schema_hash,
            "arguments_sha256": arguments_hash,
            "justification": payload.justification,
        },
        quorum_required=int(rule["quorum"]),
        require_admin_approval=bool(rule["require_admin"]),
        disallow_proposer_vote=bool(rule["disallow_proposer"]),
        status="pending",
        policy_generation=context.policy.generation,
        version=1,
        idempotency_key=f"mcp-action-approval:{payload.idempotency_key}",
        created_by_subject=_system_subject(user.subject),
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(approval)
    db.flush()
    preparation = McpActionPreparation(
        id=preparation_id,
        owner_subject=user.subject,
        actor_subject=user.subject,
        server_id=item.server.id,
        tool_id=item.tool.id,
        revision_id=item.revision.id,
        schema_hash=item.revision.schema_hash,
        action_class=item.revision.action_class,
        arguments_secret_id=secret.id,
        arguments_redacted={key: "[REDACTED]" for key in sorted(payload.arguments)},
        arguments_sha256=arguments_hash,
        justification=payload.justification,
        preview={
            "server": item.server.display_name,
            "tool": item.tool.upstream_name,
            "argument_names": sorted(payload.arguments),
            "argument_count": len(payload.arguments),
            "schema_hash": item.revision.schema_hash,
        },
        approval_class=item.approval_class.value,
        exposure_id=item.exposure.id,
        exposure_version=item.exposure.version,
        federation_policy_id=item.policy.id,
        federation_policy_generation=item.policy.generation,
        autonomy_policy_id=context.policy.id,
        autonomy_policy_generation=context.policy.generation,
        command_id=command.id,
        executor_agent_id=context.executor.id,
        approval_request_id=approval.id,
        status="pending_approval",
        idempotency_key=payload.idempotency_key,
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(preparation)
    emit_event(
        db,
        event_type="gateway.mcp.action.prepared.v1",
        actor_subject=user.subject,
        action="prepared",
        resource_type="mcp_action_preparation",
        resource_id=preparation.id,
        payload={
            "preparation_id": preparation.id,
            "server_id": preparation.server_id,
            "tool_id": preparation.tool_id,
            "revision_id": preparation.revision_id,
            "schema_hash": preparation.schema_hash,
            "arguments_sha256": preparation.arguments_sha256,
            "approval_request_id": preparation.approval_request_id,
            "approval_class": preparation.approval_class,
            "action_class": preparation.action_class,
        },
        commit=False,
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        existing = (
            db.query(McpActionPreparation)
            .filter(
                McpActionPreparation.owner_subject == user.subject,
                McpActionPreparation.idempotency_key == payload.idempotency_key,
            )
            .one_or_none()
        )
        if existing is not None and existing.arguments_sha256 == arguments_hash:
            return {"preparation": _preparation_payload(existing), "replayed": True}
        raise HTTPException(
            status_code=409, detail="MCP action preparation conflict"
        ) from exc
    db.refresh(preparation)
    return {"preparation": _preparation_payload(preparation), "replayed": False}


def _load_preparation(
    db: Session, *, owner_subject: str, preparation_id: str
) -> McpActionPreparation:
    preparation = (
        db.query(McpActionPreparation)
        .filter(
            McpActionPreparation.id == preparation_id,
            McpActionPreparation.owner_subject == owner_subject,
        )
        .one_or_none()
    )
    if preparation is None:
        raise HTTPException(status_code=404, detail="MCP action preparation not found")
    return preparation


def _existing_receipt(db: Session, permit_id: str) -> ActionReceipt | None:
    return (
        db.query(ActionReceipt)
        .filter(ActionReceipt.permit_id == permit_id)
        .one_or_none()
    )


async def execute_action(
    db: Session,
    *,
    user: User,
    payload: McpActionExecuteInput,
    upstream: UpstreamMcpManager,
    gateway_tool_call_id: str | None,
) -> dict[str, Any]:
    preparation = _load_preparation(
        db, owner_subject=user.subject, preparation_id=payload.preparation_id
    )
    if preparation.actor_subject != user.subject:
        raise HTTPException(
            status_code=403, detail="MCP action preparation belongs to another actor"
        )
    if preparation.schema_hash != payload.expected_schema_hash:
        raise HTTPException(
            status_code=409, detail="MCP action schema hash changed after preparation"
        )
    receipt = _existing_receipt(db, payload.permit_id)
    if receipt is not None:
        return {
            "preparation": _preparation_payload(preparation),
            "receipt_id": receipt.id,
            "receipt_status": receipt.status,
            "replayed": True,
        }
    if _aware(preparation.expires_at) <= utcnow():
        preparation.status = "expired"
        preparation.updated_at = utcnow()
        db.commit()
        raise HTTPException(status_code=409, detail="MCP action preparation expired")
    item = _resolve_authorized(
        db,
        user=user,
        tool_ref=_tool_ref(
            preparation.server_id, preparation.tool_id, preparation.revision_id
        ),
        schema_hash=preparation.schema_hash,
        require_available=True,
    )
    if (
        item.exposure.id != preparation.exposure_id
        or item.exposure.version != preparation.exposure_version
        or item.policy.id != preparation.federation_policy_id
        or item.policy.generation != preparation.federation_policy_generation
    ):
        raise HTTPException(
            status_code=409,
            detail="MCP exposure or federation policy changed after preparation",
        )
    autonomy_policy = db.get(AutonomyPolicy, preparation.autonomy_policy_id)
    if (
        autonomy_policy is None
        or autonomy_policy.generation != preparation.autonomy_policy_generation
    ):
        raise HTTPException(
            status_code=409, detail="MCP autonomy policy changed after preparation"
        )
    approval = db.get(ApprovalRequest, preparation.approval_request_id)
    command = db.get(AgentCommand, preparation.command_id)
    permit = db.get(ExecutionPermit, payload.permit_id)
    if approval is None or command is None or permit is None:
        raise HTTPException(
            status_code=409, detail="MCP guarded action evidence is incomplete"
        )
    if approval.status != "approved":
        raise HTTPException(
            status_code=409, detail=f"MCP action approval is {approval.status}"
        )
    if permit.approval_request_id != approval.id or permit.command_id != command.id:
        raise HTTPException(
            status_code=409,
            detail="Execution permit does not belong to the preparation",
        )
    if (
        permit.payload_hash != approval.payload_hash
        or approval.payload_hash != _command_hash(command)
    ):
        raise HTTPException(
            status_code=409, detail="MCP guarded action payload hash mismatch"
        )
    if command.status in {"pending", "delivered", "acknowledged"}:
        command.status = "accepted"
        command.approved_by_subject = user.subject
        command.accepted_at = utcnow()
        command.updated_at = command.accepted_at
        db.commit()
    claimed = agent_autonomy_service.claim_permit(
        db,
        owner_subject=user.subject,
        permit_id=permit.id,
        executor_agent_id=preparation.executor_agent_id,
    )
    secret = db.get(SecretBlob, preparation.arguments_secret_id)
    if secret is None or secret.owner_subject != user.subject:
        raise HTTPException(
            status_code=409, detail="Prepared MCP arguments are unavailable"
        )
    try:
        arguments = json.loads(decrypt_text(secret.ciphertext))
    except Exception as exc:
        raise HTTPException(
            status_code=409, detail="Prepared MCP arguments cannot be decrypted"
        ) from exc
    if (
        not isinstance(arguments, dict)
        or sha256_json(arguments) != preparation.arguments_sha256
    ):
        raise HTTPException(
            status_code=409, detail="Prepared MCP arguments failed integrity validation"
        )
    preparation.status = "executing"
    preparation.updated_at = utcnow()
    db.commit()
    started_at = utcnow()
    result = None
    error: UpstreamMcpError | None = None
    try:
        result = await upstream.call_exact_revision(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            revision_id=preparation.revision_id,
            arguments=arguments,
            idempotency_key=f"mcp-action:{preparation.id}",
            gateway_tool_call_id=gateway_tool_call_id,
            correlation_id=preparation.id,
            preparation_id=preparation.id,
            approval_request_id=approval.id,
            execution_permit_id=claimed.id,
        )
    except UpstreamMcpError as exc:
        error = exc
    completed_at = utcnow()
    receipt_status = (
        "unknown"
        if error is not None and error.unknown_outcome
        else "failed"
        if error is not None or (result is not None and result.is_error)
        else "succeeded"
    )
    receipt = agent_autonomy_service.record_receipt(
        db,
        owner_subject=user.subject,
        data={
            "permit_id": claimed.id,
            "executor_agent_id": preparation.executor_agent_id,
            "fencing_token": claimed.fencing_token,
            "status": receipt_status,
            "result_summary": {
                "preparation_id": preparation.id,
                "revision_id": preparation.revision_id,
                "schema_hash": preparation.schema_hash,
                "invocation_id": result.invocation_id if result else None,
                "serialized_bytes": result.serialized_bytes if result else None,
                "truncated": result.truncated if result else False,
                "normalized_error_code": error.code if error else None,
            },
            "error": error.message if error else None,
            "external_references": [
                {"type": "mcp_invocation", "id": result.invocation_id}
            ]
            if result and result.invocation_id
            else [],
            "idempotency_key": f"mcp-action-receipt:{preparation.id}",
            "started_at": started_at,
            "completed_at": completed_at,
        },
    )
    preparation.status = "succeeded" if receipt_status == "succeeded" else "failed"
    preparation.executed_at = completed_at
    preparation.updated_at = completed_at
    emit_event(
        db,
        event_type="gateway.mcp.action.executed.v1",
        actor_subject=user.subject,
        action=receipt_status,
        resource_type="mcp_action_preparation",
        resource_id=preparation.id,
        payload={
            "preparation_id": preparation.id,
            "server_id": preparation.server_id,
            "tool_id": preparation.tool_id,
            "revision_id": preparation.revision_id,
            "schema_hash": preparation.schema_hash,
            "arguments_sha256": preparation.arguments_sha256,
            "approval_request_id": preparation.approval_request_id,
            "execution_permit_id": claimed.id,
            "action_receipt_id": receipt.id,
            "status": receipt_status,
            "invocation_id": result.invocation_id if result else None,
        },
        status="success" if receipt_status == "succeeded" else "warning",
        commit=False,
    )
    db.commit()
    if error is not None:
        raise HTTPException(
            status_code=error.http_status, detail=error.as_detail()
        ) from error
    return {
        "preparation": _preparation_payload(preparation),
        "receipt_id": receipt.id,
        "receipt_status": receipt.status,
        "invocation_id": result.invocation_id if result else None,
        "result": result.payload if result else None,
        "truncated": result.truncated if result else False,
        "serialized_bytes": result.serialized_bytes if result else 0,
        "upstream_is_error": result.is_error if result else True,
        "replayed": False,
    }


async def call_mcp_federation_broker_tool(
    name: str,
    args: dict[str, Any],
    *,
    user: User,
    db: Session,
    upstream: UpstreamMcpManager,
    preparation_ttl_seconds: int,
    gateway_tool_call_id: str | None = None,
) -> dict[str, Any]:
    if name == "mcp_catalog_search":
        return search_catalog(
            db, user=user, payload=McpCatalogSearchInput.model_validate(args)
        )
    if name == "mcp_tool_describe":
        return describe_tool(
            db, user=user, payload=McpToolDescribeInput.model_validate(args)
        )
    if name == "mcp_call_read":
        return await call_read(
            db,
            user=user,
            payload=McpCallReadInput.model_validate(args),
            upstream=upstream,
            gateway_tool_call_id=gateway_tool_call_id,
        )
    if name == "mcp_action_prepare":
        return prepare_action(
            db,
            user=user,
            payload=McpActionPrepareInput.model_validate(args),
            preparation_ttl_seconds=preparation_ttl_seconds,
        )
    if name == "mcp_action_execute":
        return await execute_action(
            db,
            user=user,
            payload=McpActionExecuteInput.model_validate(args),
            upstream=upstream,
            gateway_tool_call_id=gateway_tool_call_id,
        )
    raise HTTPException(
        status_code=404, detail=f"Unknown MCP federation broker tool: {name}"
    )
