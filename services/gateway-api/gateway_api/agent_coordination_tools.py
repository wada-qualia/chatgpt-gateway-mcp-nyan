from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .agent_coordination import (
    agent_coordination_service,
    handoff_payload,
    integration_payload,
    lease_payload,
)
from .models import User

SECRET_ARGUMENT_NOTE = " Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments."


def _object(
    properties: dict[str, Any] | None = None, required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _integer(
    description: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer", "description": description}
    if default is not None:
        schema["default"] = default
    if minimum is not None:
        schema["minimum"] = minimum
    if maximum is not None:
        schema["maximum"] = maximum
    return schema


def _boolean(description: str, *, default: bool | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "boolean", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _array(description: str, items: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "description": description, "items": items}


def _enum(
    description: str, values: list[str], *, default: str | None = None
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "string",
        "description": description,
        "enum": values,
    }
    if default is not None:
        schema["default"] = default
    return schema


def _output(properties: dict[str, Any]) -> dict[str, Any]:
    return _object(
        {
            "ok": _boolean("Whether the call succeeded."),
            "error": {"type": ["string", "null"]},
            **properties,
        },
        ["ok"],
    )


def _tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    *,
    read_only: bool,
    idempotent: bool,
    destructive: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{description}{SECRET_ARGUMENT_NOTE}",
        "inputSchema": input_schema,
        "outputSchema": output_schema,
        "annotations": {
            "title": name.replace("_", " ").title(),
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": False,
        },
    }


def _reservation_schema() -> dict[str, Any]:
    return _object(
        {
            "kind": _enum("Reservation kind.", ["path", "glob"], default="path"),
            "pattern": _string("Safe resource-relative path or glob."),
            "recursive": _boolean(
                "Whether a path reservation covers descendants.", default=True
            ),
        },
        ["pattern"],
    )


def agent_coordination_tools() -> list[dict[str, Any]]:
    lease = {
        "type": "object",
        "description": "Resource lease with a monotonic fencing token.",
    }
    handoff = {"type": "object", "description": "Durable handoff barrier."}
    integration = {"type": "object", "description": "Coordinator integration record."}
    conflict_report = {
        "type": "object",
        "description": "Deterministic FileChangeSet conflict report.",
    }
    return [
        _tool(
            "agent_acquire_lease",
            "Acquire a tenant-scoped path or glob reservation. Exclusive write leases require an isolated branch, worktree, and base commit.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "holder_agent_id": _string("Lease holder agent id."),
                    "work_item_id": _string("Optional actively assigned work item id."),
                    "origin": _enum(
                        "Resource origin.", ["server", "thin_client", "docker"]
                    ),
                    "resource_id": _string(
                        "Origin resource id for non-server origins."
                    ),
                    "mode": _enum(
                        "Lease mode.",
                        ["exclusive_write", "shared_read"],
                        default="exclusive_write",
                    ),
                    "reservations": _array(
                        "Path and glob reservations.", _reservation_schema()
                    ),
                    "branch_name": _string("Lease-owned branch name."),
                    "worktree_path": _string("Lease-owned worktree path."),
                    "base_commit": _string("Immutable base commit."),
                    "expected_head": _string("Optional expected branch head."),
                    "ttl_seconds": _integer(
                        "Lease TTL.", default=300, minimum=30, maximum=3600
                    ),
                    "idempotency_key": _string("Tenant-scoped idempotency key."),
                    "meta": {"type": "object", "additionalProperties": True},
                },
                ["room_id", "holder_agent_id", "origin", "reservations"],
            ),
            _output({"lease": lease}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_list_leases",
            "List resource leases with automatic stale-lease expiry.",
            _object(
                {
                    "room_id": _string("Optional room filter."),
                    "status": _string("Optional status filter."),
                    "holder_agent_id": _string("Optional holder filter."),
                }
            ),
            _output({"leases": _array("Resource leases.", lease)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_renew_lease",
            "Renew an active lease only when holder and fencing token still match.",
            _object(
                {
                    "lease_id": _string("Resource lease id."),
                    "holder_agent_id": _string("Lease holder agent id."),
                    "fencing_token": _integer("Current fencing token.", minimum=1),
                    "ttl_seconds": _integer(
                        "New TTL.", default=300, minimum=30, maximum=3600
                    ),
                },
                ["lease_id", "holder_agent_id", "fencing_token"],
            ),
            _output({"lease": lease}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_release_lease",
            "Release a lease. A coordinator may force-revoke a lease when explicitly requested.",
            _object(
                {
                    "lease_id": _string("Resource lease id."),
                    "actor_agent_id": _string("Releasing agent id."),
                    "fencing_token": _integer("Current fencing token.", minimum=1),
                    "force": _boolean("Coordinator force revocation.", default=False),
                },
                ["lease_id", "actor_agent_id", "fencing_token"],
            ),
            _output({"lease": lease}),
            read_only=False,
            idempotent=True,
            destructive=True,
        ),
        _tool(
            "agent_detect_conflicts",
            "Compare FileChangeSet evidence and classify hard or potential path, hash, and diff-hunk conflicts.",
            _object(
                {
                    "candidate_change_ids": _array(
                        "Candidate change ids.", {"type": "string"}
                    ),
                    "comparison_change_ids": _array(
                        "Optional explicit comparison change ids.", {"type": "string"}
                    ),
                    "room_id": _string("Optional room scope."),
                },
                ["candidate_change_ids"],
            ),
            _output({"conflict_report": conflict_report}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_create_handoff",
            "Create a handoff barrier bound to one lease, fencing token, and exact FileChangeSet evidence.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "source_agent_id": _string("Source agent id."),
                    "target_agent_id": _string("Target agent id."),
                    "lease_id": _string("Source resource lease id."),
                    "expected_fencing_token": _integer(
                        "Source fencing token.", minimum=1
                    ),
                    "required_change_ids": _array(
                        "Exact handoff FileChangeSet ids.", {"type": "string"}
                    ),
                    "summary": _string("Handoff summary."),
                    "payload": {"type": "object", "additionalProperties": True},
                    "idempotency_key": _string("Tenant-scoped idempotency key."),
                },
                [
                    "room_id",
                    "source_agent_id",
                    "target_agent_id",
                    "lease_id",
                    "expected_fencing_token",
                ],
            ),
            _output({"handoff": handoff}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_list_handoffs",
            "List tenant-scoped handoff barriers.",
            _object(
                {
                    "room_id": _string("Optional room filter."),
                    "status": _string("Optional status filter."),
                }
            ),
            _output({"handoffs": _array("Handoff barriers.", handoff)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_mark_handoff_ready",
            "Mark a handoff ready after revalidating source lease and change evidence.",
            _object(
                {
                    "handoff_id": _string("Handoff id."),
                    "source_agent_id": _string("Source agent id."),
                },
                ["handoff_id", "source_agent_id"],
            ),
            _output({"handoff": handoff}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_accept_handoff",
            "Accept a ready handoff only after the source lease is released and hard conflicts are absent.",
            _object(
                {
                    "handoff_id": _string("Handoff id."),
                    "target_agent_id": _string("Target agent id."),
                    "comparison_change_ids": _array(
                        "Optional explicit comparison changes.", {"type": "string"}
                    ),
                },
                ["handoff_id", "target_agent_id"],
            ),
            _output({"handoff": handoff}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_create_integration",
            "Create a coordinator-only integration review. This records evidence and never performs a Git merge automatically.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "coordinator_agent_id": _string("Assigned coordinator agent id."),
                    "target_branch": _string("Integration target branch."),
                    "expected_target_head": _string("Expected immutable target head."),
                    "candidate_change_ids": _array(
                        "Candidate FileChangeSet ids.", {"type": "string"}
                    ),
                    "comparison_change_ids": _array(
                        "Explicit comparison FileChangeSet ids.", {"type": "string"}
                    ),
                    "source_lease_ids": _array(
                        "Released source lease ids.", {"type": "string"}
                    ),
                    "idempotency_key": _string("Tenant-scoped idempotency key."),
                },
                [
                    "room_id",
                    "coordinator_agent_id",
                    "target_branch",
                    "expected_target_head",
                    "candidate_change_ids",
                ],
            ),
            _output({"integration": integration}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_list_integrations",
            "List coordinator integration records.",
            _object(
                {
                    "room_id": _string("Optional room filter."),
                    "status": _string("Optional status filter."),
                }
            ),
            _output({"integrations": _array("Integration records.", integration)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_complete_integration",
            "Approve, reject, or record completion of an integration with optimistic version and target commit evidence.",
            _object(
                {
                    "integration_id": _string("Integration record id."),
                    "coordinator_agent_id": _string("Assigned coordinator agent id."),
                    "expected_version": _integer(
                        "Current optimistic version.", minimum=1
                    ),
                    "status": _enum(
                        "Integration status.", ["approved", "integrated", "rejected"]
                    ),
                    "observed_target_head": _string(
                        "Observed target head before approval or integration."
                    ),
                    "decision": {"type": "object", "additionalProperties": True},
                    "integrated_commit": _string(
                        "Required commit when status is integrated."
                    ),
                },
                [
                    "integration_id",
                    "coordinator_agent_id",
                    "expected_version",
                    "status",
                ],
            ),
            _output({"integration": integration}),
            read_only=False,
            idempotent=True,
        ),
    ]


def agent_coordination_tool_names() -> frozenset[str]:
    return frozenset(tool["name"] for tool in agent_coordination_tools())


async def call_agent_coordination_tool(
    name: str, args: dict[str, Any], user: User, db: Session
) -> dict[str, Any]:
    owner = user.subject
    if name == "agent_acquire_lease":
        return {
            "lease": lease_payload(
                agent_coordination_service.acquire_lease(
                    db, owner_subject=owner, data=args
                )
            )
        }
    if name == "agent_list_leases":
        leases = agent_coordination_service.list_leases(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
            holder_agent_id=args.get("holder_agent_id"),
        )
        return {"leases": [lease_payload(lease) for lease in leases]}
    if name == "agent_renew_lease":
        lease = agent_coordination_service.renew_lease(
            db,
            owner_subject=owner,
            lease_id=str(args["lease_id"]),
            holder_agent_id=str(args["holder_agent_id"]),
            fencing_token=int(args["fencing_token"]),
            ttl_seconds=int(args.get("ttl_seconds", 300)),
        )
        return {"lease": lease_payload(lease)}
    if name == "agent_release_lease":
        lease = agent_coordination_service.release_lease(
            db,
            owner_subject=owner,
            lease_id=str(args["lease_id"]),
            actor_agent_id=str(args["actor_agent_id"]),
            fencing_token=int(args["fencing_token"]),
            force=bool(args.get("force", False)),
        )
        return {"lease": lease_payload(lease)}
    if name == "agent_detect_conflicts":
        report = agent_coordination_service.detect_conflicts(
            db,
            owner_subject=owner,
            candidate_change_ids=list(args.get("candidate_change_ids") or []),
            comparison_change_ids=list(args["comparison_change_ids"])
            if args.get("comparison_change_ids") is not None
            else None,
            room_id=str(args["room_id"]) if args.get("room_id") else None,
        )
        return {"conflict_report": report}
    if name == "agent_create_handoff":
        return {
            "handoff": handoff_payload(
                agent_coordination_service.create_handoff(
                    db, owner_subject=owner, data=args
                )
            )
        }
    if name == "agent_list_handoffs":
        barriers = agent_coordination_service.list_handoffs(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
        )
        return {"handoffs": [handoff_payload(barrier) for barrier in barriers]}
    if name == "agent_mark_handoff_ready":
        barrier = agent_coordination_service.mark_handoff_ready(
            db,
            owner_subject=owner,
            handoff_id=str(args["handoff_id"]),
            source_agent_id=str(args["source_agent_id"]),
        )
        return {"handoff": handoff_payload(barrier)}
    if name == "agent_accept_handoff":
        barrier = agent_coordination_service.accept_handoff(
            db,
            owner_subject=owner,
            handoff_id=str(args["handoff_id"]),
            target_agent_id=str(args["target_agent_id"]),
            comparison_change_ids=list(args["comparison_change_ids"])
            if args.get("comparison_change_ids") is not None
            else None,
        )
        return {"handoff": handoff_payload(barrier)}
    if name == "agent_create_integration":
        return {
            "integration": integration_payload(
                agent_coordination_service.create_integration(
                    db, owner_subject=owner, data=args
                )
            )
        }
    if name == "agent_list_integrations":
        records = agent_coordination_service.list_integrations(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
        )
        return {"integrations": [integration_payload(record) for record in records]}
    if name == "agent_complete_integration":
        record = agent_coordination_service.complete_integration(
            db,
            owner_subject=owner,
            integration_id=str(args["integration_id"]),
            coordinator_agent_id=str(args["coordinator_agent_id"]),
            expected_version=int(args["expected_version"]),
            status=str(args["status"]),
            observed_target_head=str(args["observed_target_head"])
            if args.get("observed_target_head")
            else None,
            decision=dict(args.get("decision") or {}),
            integrated_commit=str(args["integrated_commit"])
            if args.get("integrated_commit")
            else None,
        )
        return {"integration": integration_payload(record)}
    raise HTTPException(
        status_code=404, detail=f"Unknown agent coordination tool: {name}"
    )
