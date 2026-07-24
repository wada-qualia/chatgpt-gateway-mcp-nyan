from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .events import emit_event
from .mcp_federation_policy import (
    McpActionClass,
    McpApprovalClass,
    McpExposureMode,
    McpOrigin,
    McpPolicyViolation,
    McpReadOnlyStatus,
    McpTrustLevel,
    derive_risk_evidence,
    normalize_slug,
    reject_secret_shaped_payload,
    sha256_json,
    validate_credential_binding,
    validate_operator_classification,
)
from .models import (
    McpCredentialBinding,
    McpFederationPolicy,
    McpInvocation,
    McpMutationReceipt,
    McpRuntimeConnection,
    McpServer,
    McpTool,
    McpToolExposure,
    McpToolRevision,
    SecretBlob,
    ThinClient,
    utcnow,
)


_SERVER_STATUSES = {
    "draft",
    "authorizing",
    "discovering",
    "online",
    "degraded",
    "offline",
    "auth_required",
    "schema_invalid",
    "quarantined",
    "disabled",
}
_TOOL_NAME_NORMALIZER = re.compile(r"[^a-z0-9_]+")


def _policy_error(exc: McpPolicyViolation) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
    )


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def _check_version(actual: int, expected: int) -> None:
    if actual != expected:
        raise _conflict(
            f"Optimistic version conflict: expected {expected}, current {actual}"
        )


def _mutation_receipt(
    db: Session,
    *,
    owner_subject: str,
    operation: str,
    idempotency_key: str,
    request: dict[str, Any],
) -> tuple[McpMutationReceipt | None, str]:
    request_hash = sha256_json({"operation": operation, "request": request})
    receipt = (
        db.query(McpMutationReceipt)
        .filter(
            McpMutationReceipt.owner_subject == owner_subject,
            McpMutationReceipt.operation == operation,
            McpMutationReceipt.idempotency_key == idempotency_key,
        )
        .first()
    )
    if receipt is not None and receipt.request_hash != request_hash:
        raise _conflict(
            "MCP mutation idempotency key was reused with a different request"
        )
    return receipt, request_hash


def _record_mutation_receipt(
    db: Session,
    *,
    owner_subject: str,
    operation: str,
    idempotency_key: str,
    request_hash: str,
    resource_type: str,
    resource_id: str,
    response_version: int | None,
) -> McpMutationReceipt:
    receipt = McpMutationReceipt(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type=resource_type,
        resource_id=resource_id,
        response_version=response_version,
        created_at=utcnow(),
    )
    db.add(receipt)
    return receipt


def _policy_by_id(
    db: Session, *, owner_subject: str, policy_id: str
) -> McpFederationPolicy:
    policy = (
        db.query(McpFederationPolicy)
        .filter(
            McpFederationPolicy.id == policy_id,
            McpFederationPolicy.owner_subject == owner_subject,
        )
        .first()
    )
    if policy is None:
        raise _not_found("MCP federation policy not found")
    return policy


def _exposure_by_id(
    db: Session, *, owner_subject: str, exposure_id: str
) -> McpToolExposure:
    exposure = (
        db.query(McpToolExposure)
        .filter(
            McpToolExposure.id == exposure_id,
            McpToolExposure.owner_subject == owner_subject,
        )
        .first()
    )
    if exposure is None:
        raise _not_found("MCP tool exposure not found")
    return exposure


def _validate_http_endpoint(endpoint_url: str | None) -> None:
    if endpoint_url is None:
        return
    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="MCP endpoint must be an absolute http or https URL",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="MCP endpoint must not contain embedded credentials",
        )


def _owned_binding(
    db: Session, *, owner_subject: str, binding_id: str
) -> McpCredentialBinding:
    binding = (
        db.query(McpCredentialBinding)
        .filter(
            McpCredentialBinding.id == binding_id,
            McpCredentialBinding.owner_subject == owner_subject,
        )
        .first()
    )
    if binding is None:
        raise _not_found("MCP credential binding not found")
    return binding


def get_server(db: Session, *, owner_subject: str, server_id: str) -> McpServer:
    server = (
        db.query(McpServer)
        .filter(McpServer.id == server_id, McpServer.owner_subject == owner_subject)
        .first()
    )
    if server is None:
        raise _not_found("MCP server not found")
    return server


def get_tool(db: Session, *, owner_subject: str, tool_id: str) -> McpTool:
    tool = (
        db.query(McpTool)
        .filter(McpTool.id == tool_id, McpTool.owner_subject == owner_subject)
        .first()
    )
    if tool is None:
        raise _not_found("MCP tool not found")
    return tool


def get_revision(
    db: Session, *, owner_subject: str, revision_id: str
) -> McpToolRevision:
    revision = (
        db.query(McpToolRevision)
        .filter(
            McpToolRevision.id == revision_id,
            McpToolRevision.owner_subject == owner_subject,
        )
        .first()
    )
    if revision is None:
        raise _not_found("MCP tool revision not found")
    return revision


def create_credential_binding(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    idempotency_key: str,
    data: dict[str, Any],
) -> McpCredentialBinding:
    operation = "credential_binding.create"
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=data,
    )
    if receipt is not None:
        return _owned_binding(
            db, owner_subject=owner_subject, binding_id=receipt.resource_id
        )
    reject_secret_shaped_payload(data.get("meta", {}))
    binding_type = str(data["binding_type"])
    secret_blob_id = data.get("secret_blob_id")
    try:
        validate_credential_binding(
            origin=McpOrigin.THIN_CLIENT
            if binding_type == "thin_client_local"
            else McpOrigin.GATEWAY,
            binding_type=binding_type,
            secret_blob_id=secret_blob_id,
        )
    except McpPolicyViolation as exc:
        raise _policy_error(exc) from exc
    if secret_blob_id:
        secret = (
            db.query(SecretBlob)
            .filter(
                SecretBlob.id == secret_blob_id,
                SecretBlob.owner_subject == owner_subject,
            )
            .first()
        )
        if secret is None:
            raise _not_found("Backend secret reference not found")
    binding = McpCredentialBinding(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        binding_type=binding_type,
        provider=data.get("provider"),
        secret_blob_id=secret_blob_id,
        audience=data.get("audience"),
        scopes=list(data.get("scopes") or []),
        meta=dict(data.get("meta") or {}),
        version=1,
        idempotency_key=idempotency_key,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(binding)
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_credential_binding",
        resource_id=binding.id,
        response_version=binding.version,
    )
    emit_event(
        db,
        event_type="gateway.mcp.credential_binding.created.v1",
        actor_subject=actor_subject,
        action="created",
        resource_type="mcp_credential_binding",
        resource_id=binding.id,
        payload={
            "binding_id": binding.id,
            "binding_type": binding.binding_type,
            "provider": binding.provider,
            "status": binding.status,
        },
        commit=False,
    )
    db.commit()
    db.refresh(binding)
    return binding


def list_credential_bindings(
    db: Session, *, owner_subject: str
) -> list[McpCredentialBinding]:
    return (
        db.query(McpCredentialBinding)
        .filter(McpCredentialBinding.owner_subject == owner_subject)
        .order_by(McpCredentialBinding.created_at.desc())
        .all()
    )


def create_server(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    idempotency_key: str,
    data: dict[str, Any],
) -> McpServer:
    operation = "server.create"
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=data,
    )
    if receipt is not None:
        return get_server(
            db, owner_subject=owner_subject, server_id=receipt.resource_id
        )
    origin = McpOrigin(data["origin"])
    _validate_http_endpoint(data.get("endpoint_url"))
    binding: McpCredentialBinding | None = None
    binding_id = data.get("credential_binding_id")
    if binding_id:
        binding = _owned_binding(db, owner_subject=owner_subject, binding_id=binding_id)
    try:
        validate_credential_binding(
            origin=origin,
            binding_type=binding.binding_type if binding else None,
            secret_blob_id=binding.secret_blob_id if binding else None,
        )
    except McpPolicyViolation as exc:
        raise _policy_error(exc) from exc
    if origin is McpOrigin.THIN_CLIENT:
        thin_client = (
            db.query(ThinClient)
            .filter(
                ThinClient.id == data.get("thin_client_id"),
                ThinClient.owner_subject == owner_subject,
            )
            .first()
        )
        if thin_client is None:
            raise _not_found("Thin client not found")
    display_name = str(data["display_name"]).strip()
    server = McpServer(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        origin=origin.value,
        thin_client_id=data.get("thin_client_id"),
        runtime_id=data.get("runtime_id"),
        display_name=display_name,
        normalized_slug=normalize_slug(display_name),
        transport=str(data["transport"]),
        endpoint_url=data.get("endpoint_url"),
        credential_binding_id=binding_id,
        version=1,
        idempotency_key=idempotency_key,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(server)
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_server",
        resource_id=server.id,
        response_version=server.version,
    )
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict("MCP server slug or idempotency key already exists") from exc
    emit_event(
        db,
        event_type="gateway.mcp.server.created.v1",
        actor_subject=actor_subject,
        action="created",
        resource_type="mcp_server",
        resource_id=server.id,
        payload={
            "server_id": server.id,
            "origin": server.origin,
            "transport": server.transport,
            "status": server.status,
            "trust_level": server.trust_level,
        },
        commit=False,
    )
    db.commit()
    db.refresh(server)
    return server


def list_servers(
    db: Session,
    *,
    owner_subject: str,
    server_status: str | None = None,
) -> list[McpServer]:
    query = db.query(McpServer).filter(McpServer.owner_subject == owner_subject)
    if server_status:
        if server_status not in _SERVER_STATUSES:
            raise HTTPException(status_code=422, detail="Unsupported MCP server status")
        query = query.filter(McpServer.status == server_status)
    return query.order_by(McpServer.created_at.desc()).all()


def update_server(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    idempotency_key: str,
    expected_version: int,
    data: dict[str, Any],
    operation: str = "server.update",
) -> McpServer:
    request = {
        "server_id": server_id,
        "expected_version": expected_version,
        "data": data,
    }
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=request,
    )
    if receipt is not None:
        return get_server(
            db, owner_subject=owner_subject, server_id=receipt.resource_id
        )
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    _check_version(server.version, expected_version)
    if data.get("display_name") is not None:
        server.display_name = str(data["display_name"]).strip()
    if "credential_binding_id" in data:
        binding_id = data.get("credential_binding_id")
        binding = (
            _owned_binding(db, owner_subject=owner_subject, binding_id=binding_id)
            if binding_id
            else None
        )
        try:
            validate_credential_binding(
                origin=McpOrigin(server.origin),
                binding_type=binding.binding_type if binding else None,
                secret_blob_id=binding.secret_blob_id if binding else None,
            )
        except McpPolicyViolation as exc:
            raise _policy_error(exc) from exc
        server.credential_binding_id = binding_id
    if data.get("enabled") is False:
        server.status = "disabled"
        server.disabled_at = utcnow()
    elif data.get("enabled") is True and server.status == "disabled":
        server.status = "draft"
        server.disabled_at = None
    server.version += 1
    server.updated_at = utcnow()
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_server",
        resource_id=server.id,
        response_version=server.version,
    )
    emit_event(
        db,
        event_type="gateway.mcp.server.updated.v1",
        actor_subject=actor_subject,
        action="updated",
        resource_type="mcp_server",
        resource_id=server.id,
        payload={
            "server_id": server.id,
            "status": server.status,
            "version": server.version,
            "credential_binding_configured": server.credential_binding_id is not None,
        },
        commit=False,
    )
    db.commit()
    db.refresh(server)
    return server


def request_server_transition(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    idempotency_key: str,
    expected_version: int,
    transition: str,
) -> McpServer:
    target_status = {"authorize": "authorizing", "refresh": "discovering"}.get(
        transition
    )
    if target_status is None:
        raise HTTPException(status_code=422, detail="Unsupported MCP server transition")
    operation = f"server.{transition}"
    request = {
        "server_id": server_id,
        "expected_version": expected_version,
        "transition": transition,
    }
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=request,
    )
    if receipt is not None:
        return get_server(
            db, owner_subject=owner_subject, server_id=receipt.resource_id
        )
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    _check_version(server.version, expected_version)
    if server.status == "disabled":
        raise _conflict("Disabled MCP server cannot start a control-plane transition")
    if transition == "authorize" and server.origin == McpOrigin.GATEWAY.value:
        if server.credential_binding_id is None:
            raise _conflict("Gateway-origin MCP server requires a credential binding")
    previous = server.status
    server.status = target_status
    server.version += 1
    server.updated_at = utcnow()
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_server",
        resource_id=server.id,
        response_version=server.version,
    )
    emit_event(
        db,
        event_type="gateway.mcp.server.status_changed.v1",
        actor_subject=actor_subject,
        action=transition,
        resource_type="mcp_server",
        resource_id=server.id,
        payload={
            "server_id": server.id,
            "previous_status": previous,
            "status": server.status,
            "version": server.version,
        },
        commit=False,
    )
    db.commit()
    db.refresh(server)
    return server


def disable_server(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    idempotency_key: str,
    expected_version: int,
) -> McpServer:
    return update_server(
        db,
        owner_subject=owner_subject,
        actor_subject=actor_subject,
        server_id=server_id,
        idempotency_key=idempotency_key,
        expected_version=expected_version,
        data={"enabled": False},
        operation="server.disable",
    )


def server_health(db: Session, *, owner_subject: str, server_id: str) -> dict[str, Any]:
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    return {
        "server_id": server.id,
        "status": server.status,
        "trust_level": server.trust_level,
        "catalog_generation": server.catalog_generation,
        "negotiated_protocol_version": server.negotiated_protocol_version,
        "last_connected_at": server.last_connected_at,
        "last_catalog_refreshed_at": server.last_catalog_refreshed_at,
    }


def upsert_policy(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    server_id: str | None,
    idempotency_key: str,
    expected_version: int,
    data: dict[str, Any],
) -> McpFederationPolicy:
    operation = "policy.upsert"
    request = {
        "server_id": server_id,
        "expected_version": expected_version,
        "data": data,
    }
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=request,
    )
    if receipt is not None:
        return _policy_by_id(
            db, owner_subject=owner_subject, policy_id=receipt.resource_id
        )
    if server_id is not None:
        server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    else:
        server = None
    policy = (
        db.query(McpFederationPolicy)
        .filter(
            McpFederationPolicy.owner_subject == owner_subject,
            McpFederationPolicy.server_id == server_id,
        )
        .first()
    )
    if policy is None:
        if expected_version != 0:
            raise _conflict(
                "Federation policy does not exist; expected_version must be 0"
            )
        policy = McpFederationPolicy(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=server_id,
            created_by_subject=actor_subject,
            updated_by_subject=actor_subject,
            generation=1,
            version=1,
            idempotency_key=idempotency_key,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(policy)
        event_type = "gateway.mcp.policy.created.v1"
    else:
        _check_version(policy.version, expected_version)
        policy.version += 1
        policy.generation += 1
        policy.updated_by_subject = actor_subject
        policy.updated_at = utcnow()
        event_type = "gateway.mcp.policy.updated.v1"
    policy.trust_level = str(data["trust_level"])
    policy.allowed_action_classes = list(data.get("allowed_action_classes") or [])
    policy.required_roles = list(data.get("required_roles") or [])
    policy.required_scopes = list(data.get("required_scopes") or [])
    policy.approval_mapping = dict(data.get("approval_mapping") or {})
    policy.tool_allowlist = list(data.get("tool_allowlist") or [])
    policy.tool_denylist = list(data.get("tool_denylist") or [])
    policy.status = str(data.get("status") or "active")
    if server is not None:
        server.trust_level = policy.trust_level
        server.policy_generation = policy.generation
        if policy.trust_level == McpTrustLevel.QUARANTINED.value:
            server.status = "quarantined"
        if policy.trust_level == McpTrustLevel.REVOKED.value:
            server.status = "disabled"
            server.disabled_at = utcnow()
        server.version += 1
        server.updated_at = utcnow()
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_federation_policy",
        resource_id=policy.id,
        response_version=policy.version,
    )
    emit_event(
        db,
        event_type=event_type,
        actor_subject=actor_subject,
        action="policy_updated",
        resource_type="mcp_federation_policy",
        resource_id=policy.id,
        payload={
            "policy_id": policy.id,
            "server_id": server_id,
            "trust_level": policy.trust_level,
            "generation": policy.generation,
            "status": policy.status,
        },
        commit=False,
    )
    db.commit()
    db.refresh(policy)
    return policy


def get_policy(
    db: Session, *, owner_subject: str, server_id: str | None
) -> McpFederationPolicy | None:
    return (
        db.query(McpFederationPolicy)
        .filter(
            McpFederationPolicy.owner_subject == owner_subject,
            McpFederationPolicy.server_id == server_id,
        )
        .first()
    )


def record_tool_revision(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    server_id: str,
    upstream_name: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] | None,
    title: str | None,
    description: str,
    annotations: dict[str, Any],
    protocol_version: str | None,
    catalog_generation: int,
) -> tuple[McpTool, McpToolRevision, bool]:
    server = get_server(db, owner_subject=owner_subject, server_id=server_id)
    reject_secret_shaped_payload(input_schema)
    schema_document = {"input": input_schema, "output": output_schema}
    schema_hash = sha256_json(schema_document)
    tool = (
        db.query(McpTool)
        .filter(McpTool.server_id == server_id, McpTool.upstream_name == upstream_name)
        .first()
    )
    now = utcnow()
    if tool is None:
        normalized_name = _TOOL_NAME_NORMALIZER.sub("_", upstream_name.lower()).strip(
            "_"
        )
        tool = McpTool(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=server_id,
            upstream_name=upstream_name,
            normalized_name=normalized_name or "tool",
            first_observed_at=now,
            last_observed_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(tool)
        db.flush()
    else:
        tool.lifecycle_state = "active"
        tool.last_observed_at = now
        tool.updated_at = now
    existing = (
        db.query(McpToolRevision)
        .filter(
            McpToolRevision.tool_id == tool.id,
            McpToolRevision.schema_hash == schema_hash,
        )
        .first()
    )
    if existing is not None:
        tool.current_revision_id = existing.id
        db.commit()
        db.refresh(tool)
        return tool, existing, False
    revision_number = (
        db.query(McpToolRevision).filter(McpToolRevision.tool_id == tool.id).count() + 1
    )
    evidence = derive_risk_evidence(
        tool_name=upstream_name,
        input_schema=input_schema,
        upstream_annotations=annotations,
    )
    revision = McpToolRevision(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        server_id=server_id,
        tool_id=tool.id,
        revision_number=revision_number,
        input_schema=input_schema,
        output_schema=output_schema,
        sanitized_title=(title or "")[:240] or None,
        sanitized_description=description[:4000],
        annotations=annotations,
        schema_hash=schema_hash,
        protocol_version=protocol_version,
        catalog_generation=catalog_generation,
        risk_evidence=evidence,
        discovered_at=now,
        created_at=now,
    )
    previous_revision_id = tool.current_revision_id
    db.add(revision)
    db.flush()
    if previous_revision_id:
        previous = db.get(McpToolRevision, previous_revision_id)
        if previous is not None and previous.superseded_by_revision_id is None:
            previous.superseded_by_revision_id = revision.id
    tool.current_revision_id = revision.id
    tool.version += 1
    server.catalog_generation = max(server.catalog_generation, catalog_generation)
    server.last_catalog_refreshed_at = now
    server.updated_at = now
    emit_event(
        db,
        event_type="gateway.mcp.tool.revision_created.v1",
        actor_subject=actor_subject,
        action="revision_created",
        resource_type="mcp_tool_revision",
        resource_id=revision.id,
        payload={
            "server_id": server_id,
            "tool_id": tool.id,
            "revision_id": revision.id,
            "schema_hash": schema_hash,
            "catalog_generation": catalog_generation,
            "action_class": revision.action_class,
        },
        commit=False,
    )
    db.commit()
    db.refresh(tool)
    db.refresh(revision)
    return tool, revision, True


def classify_revision(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    revision_id: str,
    idempotency_key: str,
    expected_version: int,
    action_class: str,
    read_only_status: str,
) -> McpToolRevision:
    operation = "revision.classify"
    request = {
        "revision_id": revision_id,
        "expected_version": expected_version,
        "action_class": action_class,
        "read_only_status": read_only_status,
    }
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=request,
    )
    if receipt is not None:
        return get_revision(
            db, owner_subject=owner_subject, revision_id=receipt.resource_id
        )
    revision = get_revision(db, owner_subject=owner_subject, revision_id=revision_id)
    _check_version(revision.version, expected_version)
    try:
        validate_operator_classification(
            action_class=McpActionClass(action_class),
            read_only_status=McpReadOnlyStatus(read_only_status),
        )
    except McpPolicyViolation as exc:
        raise _policy_error(exc) from exc
    revision.action_class = action_class
    revision.read_only_status = read_only_status
    revision.version += 1
    revision.classified_by_subject = actor_subject
    revision.classified_at = utcnow()
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_tool_revision",
        resource_id=revision.id,
        response_version=revision.version,
    )
    emit_event(
        db,
        event_type="gateway.mcp.tool.classification_changed.v1",
        actor_subject=actor_subject,
        action="classified",
        resource_type="mcp_tool_revision",
        resource_id=revision.id,
        payload={
            "server_id": revision.server_id,
            "tool_id": revision.tool_id,
            "revision_id": revision.id,
            "schema_hash": revision.schema_hash,
            "action_class": revision.action_class,
            "read_only_status": revision.read_only_status,
        },
        commit=False,
    )
    db.commit()
    db.refresh(revision)
    return revision


def list_tools(db: Session, *, owner_subject: str, server_id: str) -> list[McpTool]:
    get_server(db, owner_subject=owner_subject, server_id=server_id)
    return (
        db.query(McpTool)
        .filter(McpTool.owner_subject == owner_subject, McpTool.server_id == server_id)
        .order_by(McpTool.upstream_name.asc())
        .all()
    )


def list_revisions(
    db: Session, *, owner_subject: str, tool_id: str
) -> list[McpToolRevision]:
    get_tool(db, owner_subject=owner_subject, tool_id=tool_id)
    return (
        db.query(McpToolRevision)
        .filter(
            McpToolRevision.owner_subject == owner_subject,
            McpToolRevision.tool_id == tool_id,
        )
        .order_by(McpToolRevision.revision_number.desc())
        .all()
    )


def upsert_exposure(
    db: Session,
    *,
    owner_subject: str,
    actor_subject: str,
    tool_id: str,
    idempotency_key: str,
    expected_version: int,
    data: dict[str, Any],
) -> McpToolExposure:
    operation = "exposure.upsert"
    request = {
        "tool_id": tool_id,
        "expected_version": expected_version,
        "data": data,
    }
    receipt, request_hash = _mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request=request,
    )
    if receipt is not None:
        return _exposure_by_id(
            db, owner_subject=owner_subject, exposure_id=receipt.resource_id
        )
    tool = get_tool(db, owner_subject=owner_subject, tool_id=tool_id)
    revision = get_revision(
        db, owner_subject=owner_subject, revision_id=str(data["revision_id"])
    )
    if revision.tool_id != tool.id:
        raise _conflict("MCP revision does not belong to the selected tool")
    server = get_server(db, owner_subject=owner_subject, server_id=tool.server_id)
    mode = McpExposureMode(data["mode"])
    enabled = bool(data["enabled"])
    if enabled and mode is not McpExposureMode.HIDDEN:
        if revision.action_class == McpActionClass.UNKNOWN.value:
            raise _conflict("Unknown-risk MCP tools cannot be enabled")
        if server.trust_level not in {
            McpTrustLevel.RESTRICTED.value,
            McpTrustLevel.APPROVED.value,
        }:
            raise _conflict("MCP server trust policy does not allow exposure")
        if (
            mode is McpExposureMode.NATIVE_PROJECTED
            and server.trust_level != McpTrustLevel.APPROVED.value
        ):
            raise _conflict("Native projection requires approved server trust")
    projection_generation = int(data.get("projection_generation") or 0)
    exposure = (
        db.query(McpToolExposure)
        .filter(
            McpToolExposure.revision_id == revision.id,
            McpToolExposure.projection_generation == projection_generation,
        )
        .first()
    )
    if exposure is None:
        if expected_version != 0:
            raise _conflict("MCP exposure does not exist; expected_version must be 0")
        exposure = McpToolExposure(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            server_id=server.id,
            tool_id=tool.id,
            revision_id=revision.id,
            projection_generation=projection_generation,
            policy_generation=server.policy_generation,
            version=1,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(exposure)
    else:
        _check_version(exposure.version, expected_version)
        exposure.version += 1
    exposure.mode = mode.value
    exposure.enabled = enabled
    exposure.projected_name = data.get("projected_name")
    exposure.required_role = data.get("required_role")
    exposure.required_scope = data.get("required_scope")
    exposure.approval_class = McpApprovalClass(data["approval_class"]).value
    exposure.reviewed_by_subject = actor_subject
    exposure.reviewed_at = utcnow()
    exposure.updated_at = utcnow()
    _record_mutation_receipt(
        db,
        owner_subject=owner_subject,
        operation=operation,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        resource_type="mcp_tool_exposure",
        resource_id=exposure.id,
        response_version=exposure.version,
    )
    emit_event(
        db,
        event_type="gateway.mcp.tool.exposure_changed.v1",
        actor_subject=actor_subject,
        action="exposure_changed",
        resource_type="mcp_tool_exposure",
        resource_id=exposure.id,
        payload={
            "server_id": server.id,
            "tool_id": tool.id,
            "revision_id": revision.id,
            "schema_hash": revision.schema_hash,
            "mode": exposure.mode,
            "enabled": exposure.enabled,
            "approval_class": exposure.approval_class,
            "policy_generation": exposure.policy_generation,
            "projection_generation": exposure.projection_generation,
        },
        commit=False,
    )
    db.commit()
    db.refresh(exposure)
    return exposure


def list_invocations(
    db: Session,
    *,
    owner_subject: str,
    server_id: str | None,
    limit: int,
) -> list[McpInvocation]:
    query = db.query(McpInvocation).filter(McpInvocation.owner_subject == owner_subject)
    if server_id:
        query = query.filter(McpInvocation.server_id == server_id)
    return query.order_by(McpInvocation.started_at.desc()).limit(limit).all()


def list_runtime_connections(
    db: Session,
    *,
    owner_subject: str,
    server_id: str | None,
) -> list[McpRuntimeConnection]:
    query = db.query(McpRuntimeConnection).filter(
        McpRuntimeConnection.owner_subject == owner_subject
    )
    if server_id:
        query = query.filter(McpRuntimeConnection.server_id == server_id)
    return query.order_by(McpRuntimeConnection.last_seen_at.desc()).all()


class McpFederationService:
    create_credential_binding = staticmethod(create_credential_binding)
    list_credential_bindings = staticmethod(list_credential_bindings)
    create_server = staticmethod(create_server)
    list_servers = staticmethod(list_servers)
    get_server = staticmethod(get_server)
    update_server = staticmethod(update_server)
    request_server_transition = staticmethod(request_server_transition)
    disable_server = staticmethod(disable_server)
    server_health = staticmethod(server_health)
    upsert_policy = staticmethod(upsert_policy)
    get_policy = staticmethod(get_policy)
    record_tool_revision = staticmethod(record_tool_revision)
    classify_revision = staticmethod(classify_revision)
    list_tools = staticmethod(list_tools)
    list_revisions = staticmethod(list_revisions)
    upsert_exposure = staticmethod(upsert_exposure)
    list_invocations = staticmethod(list_invocations)
    list_runtime_connections = staticmethod(list_runtime_connections)


mcp_federation_service = McpFederationService()
