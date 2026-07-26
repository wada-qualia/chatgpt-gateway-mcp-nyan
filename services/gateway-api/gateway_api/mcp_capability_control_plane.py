from __future__ import annotations

import hashlib
import json
from typing import Any
import uuid

from sqlalchemy.orm import Session

from .models import McpCapabilitySnapshot, utcnow


class McpCapabilitySnapshotConflict(RuntimeError):
    pass


def capability_snapshot_hash(
    *,
    protocol_version: str,
    server_capabilities: dict[str, Any],
    client_capabilities: dict[str, Any],
    negotiated_features: dict[str, Any],
) -> str:
    payload = {
        "protocol_version": protocol_version,
        "server_capabilities": server_capabilities,
        "client_capabilities": client_capabilities,
        "negotiated_features": negotiated_features,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def record_capability_snapshot(
    db: Session,
    *,
    owner_subject: str,
    server_id: str,
    runtime_connection_id: str,
    source: str,
    protocol_version: str,
    catalog_generation: int,
    server_capabilities: dict[str, Any],
    client_capabilities: dict[str, Any],
    negotiated_features: dict[str, Any],
) -> McpCapabilitySnapshot:
    capability_hash = capability_snapshot_hash(
        protocol_version=protocol_version,
        server_capabilities=server_capabilities,
        client_capabilities=client_capabilities,
        negotiated_features=negotiated_features,
    )
    existing = (
        db.query(McpCapabilitySnapshot)
        .filter(
            McpCapabilitySnapshot.owner_subject == owner_subject,
            McpCapabilitySnapshot.server_id == server_id,
            McpCapabilitySnapshot.runtime_connection_id == runtime_connection_id,
        )
        .one_or_none()
    )
    if existing is not None:
        if existing.capability_hash != capability_hash:
            raise McpCapabilitySnapshotConflict(
                "Runtime capability snapshot changed without a new connection identity"
            )
        return existing
    snapshot = McpCapabilitySnapshot(
        id=str(uuid.uuid4()),
        owner_subject=owner_subject,
        server_id=server_id,
        runtime_connection_id=runtime_connection_id,
        source=source,
        protocol_version=protocol_version,
        catalog_generation=catalog_generation,
        server_capabilities=server_capabilities,
        client_capabilities=client_capabilities,
        negotiated_features=negotiated_features,
        capability_hash=capability_hash,
        created_at=utcnow(),
    )
    db.add(snapshot)
    return snapshot
