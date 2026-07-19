from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .agent_autonomy import (
    agent_autonomy_service,
    approval_payload,
    assignment_payload,
    control_payload,
    override_payload,
    permit_payload,
    policy_payload,
    receipt_payload,
    recovery_payload,
)
from .auth import require_role
from .dto import (
    ActionReceiptCreate,
    ApprovalRequestCreate,
    ApprovalVoteCreate,
    AutonomyControlUpdate,
    AutonomyOverrideCreate,
    AutonomyPolicyCreate,
    ExecutionPermitClaim,
    ExecutionPermitIssue,
    RecoveryLoopCreate,
    RecoveryOutcomeCreate,
)
from .models import ApprovalVote, User

SECRET_ARGUMENT_NOTE = (
    " Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments."
)


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


def _string(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _integer(
    description: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    default: int | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "integer", "description": description}
    if minimum is not None:
        value["minimum"] = minimum
    if maximum is not None:
        value["maximum"] = maximum
    if default is not None:
        value["default"] = default
    return value


def _boolean(description: str, *, default: bool | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "boolean", "description": description}
    if default is not None:
        value["default"] = default
    return value


def _enum(description: str, values: list[str]) -> dict[str, Any]:
    return {"type": "string", "description": description, "enum": values}


def _array(description: str, items: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "description": description, "items": items}


def _nullable(schema: dict[str, Any]) -> dict[str, Any]:
    result = dict(schema)
    result["type"] = [str(result.get("type") or "string"), "null"]
    return result


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


def agent_autonomy_tools() -> list[dict[str, Any]]:
    generic = {"type": "object", "additionalProperties": True}
    policy_rules = _object(
        {
            action_class: _object(
                {
                    "quorum": _integer("Distinct approval count.", minimum=0, maximum=20),
                    "require_admin": _boolean("Require at least one gateway-admin vote."),
                    "disallow_proposer": _boolean("Disallow the proposer from voting."),
                }
            )
            for action_class in ("read", "write", "destructive", "production")
        }
    )
    return [
        _tool(
            "agent_autonomy_create_policy",
            "Create a tenant-scoped fail-closed autonomy policy for one collaboration room.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "name": _string("Policy name."),
                    "assignment_mode": _enum(
                        "Assignment mode.", ["manual", "suggest", "automatic"]
                    ),
                    "coordinator_agent_id": _nullable(_string("Coordinator agent id.")),
                    "allowed_action_classes": _array(
                        "Allowed action classes.",
                        _enum("Action class.", ["read", "write", "destructive", "production"]),
                    ),
                    "allowed_tools": _array("Allowed structured tools.", _string("Tool name.")),
                    "allowed_command_profiles": _array(
                        "Allowed command profiles.", _string("Profile name.")
                    ),
                    "max_parallel_assignments": _integer(
                        "Maximum simultaneous room assignments.", minimum=1, maximum=100
                    ),
                    "approval_rules": policy_rules,
                    "recovery_policy": _object(
                        {
                            "max_attempts": _integer(
                                "Maximum recovery attempts.", minimum=1, maximum=20
                            ),
                            "base_backoff_seconds": _integer(
                                "Initial retry backoff.", minimum=1, maximum=86400
                            ),
                            "max_backoff_seconds": _integer(
                                "Maximum retry backoff.", minimum=1, maximum=604800
                            ),
                        }
                    ),
                    "idempotency_key": _nullable(_string("Tenant-scoped idempotency key.")),
                },
                ["room_id", "name"],
            ),
            _output({"policy": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_list_policies",
            "List autonomy policies owned by the authenticated tenant.",
            _object(
                {
                    "room_id": _nullable(_string("Optional room filter.")),
                    "status": _nullable(_string("Optional policy status filter.")),
                }
            ),
            _output({"policies": _array("Policies.", generic)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_run_assignment_cycle",
            "Run one bounded deterministic assignment cycle; automatic mode may assign eligible idle agents.",
            _object(
                {
                    "policy_id": _string("Autonomy policy id."),
                    "limit": _integer("Maximum work items to assign or propose.", minimum=1, maximum=100, default=10),
                },
                ["policy_id"],
            ),
            _output({"cycle": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_list_assignments",
            "List automatic or suggested assignment decisions and their evidence.",
            _object(
                {
                    "room_id": _nullable(_string("Optional room filter.")),
                    "policy_id": _nullable(_string("Optional policy filter.")),
                    "status": _nullable(_string("Optional assignment status.")),
                }
            ),
            _output({"assignments": _array("Assignments.", generic)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_apply_assignment",
            "Apply one still-valid suggested assignment using work-item CAS and policy-generation fencing.",
            _object({"assignment_id": _string("Assignment id.")}, ["assignment_id"]),
            _output({"assignment": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_request_approval",
            "Create a quorum approval request bound to the exact structured command payload hash and executor.",
            _object(
                {
                    "policy_id": _string("Autonomy policy id."),
                    "command_id": _string("Existing durable agent command id."),
                    "executor_agent_id": _string("Exact command target/executor agent id."),
                    "action_class": _enum(
                        "Risk class.", ["read", "write", "destructive", "production"]
                    ),
                    "action_kind": _string("Action kind, normally run_tool."),
                    "ttl_seconds": _integer("Approval lifetime.", minimum=30, maximum=86400),
                    "idempotency_key": _nullable(_string("Tenant-scoped idempotency key.")),
                },
                ["policy_id", "command_id", "executor_agent_id", "action_class"],
            ),
            _output({"approval": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_list_approvals",
            "List approval requests with recorded votes.",
            _object(
                {
                    "room_id": _nullable(_string("Optional room filter.")),
                    "status": _nullable(_string("Optional approval status.")),
                }
            ),
            _output({"approvals": _array("Approval requests.", generic)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_vote",
            "Cast one immutable approve/reject vote; access grants and proposer independence are enforced.",
            _object(
                {
                    "request_id": _string("Approval request id."),
                    "decision": _enum("Vote decision.", ["approve", "reject"]),
                    "reason": _nullable(_string("Optional vote reason.")),
                },
                ["request_id", "decision"],
            ),
            _output({"approval": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_issue_permit",
            "Issue a short-lived single-use execution permit after quorum approval. Requires gateway-admin.",
            _object(
                {
                    "request_id": _string("Approved request id."),
                    "ttl_seconds": _integer("Permit lifetime.", minimum=30, maximum=3600),
                },
                ["request_id"],
            ),
            _output({"permit": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_claim_permit",
            "Atomically claim an active permit for its exact executor after command acceptance.",
            _object(
                {
                    "permit_id": _string("Execution permit id."),
                    "executor_agent_id": _string("Exact executor agent id."),
                },
                ["permit_id", "executor_agent_id"],
            ),
            _output({"permit": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_record_receipt",
            "Record the immutable result receipt for a claimed permit; required before privileged command completion.",
            _object(
                {
                    "permit_id": _string("Claimed permit id."),
                    "executor_agent_id": _string("Exact executor agent id."),
                    "fencing_token": _integer("Permit fencing token.", minimum=1),
                    "status": _enum("Outcome.", ["succeeded", "failed", "partial", "unknown"]),
                    "result_summary": _object(additional=True),
                    "error": _nullable(_string("Bounded error detail.")),
                    "external_references": _array(
                        "Safe external references without credentials.",
                        _object(additional=True),
                    ),
                    "started_at": _string("ISO-8601 execution start."),
                    "completed_at": _string("ISO-8601 execution completion."),
                    "idempotency_key": _nullable(_string("Tenant-scoped idempotency key.")),
                },
                [
                    "permit_id",
                    "executor_agent_id",
                    "fencing_token",
                    "status",
                    "started_at",
                    "completed_at",
                ],
            ),
            _output({"receipt": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_create_recovery",
            "Create a bounded recovery loop that can issue durable commands but never executes side effects directly.",
            _object(
                {
                    "policy_id": _string("Autonomy policy id."),
                    "room_id": _string("Collaboration room id."),
                    "source_type": _enum(
                        "Recovery source type.", ["command", "work_item", "action_receipt"]
                    ),
                    "source_id": _string("Recovery source id."),
                    "target_agent_id": _string("Target agent id."),
                    "strategy": _object(additional=True),
                    "max_attempts": _integer("Bounded attempts.", minimum=1, maximum=20),
                    "base_backoff_seconds": _integer("Retry backoff.", minimum=1, maximum=86400),
                    "idempotency_key": _nullable(_string("Tenant-scoped idempotency key.")),
                },
                ["policy_id", "room_id", "source_type", "source_id", "target_agent_id", "strategy"],
            ),
            _output({"recovery": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_list_recoveries",
            "List bounded recovery loops and attempt evidence.",
            _object(
                {
                    "room_id": _nullable(_string("Optional room filter.")),
                    "status": _nullable(_string("Optional recovery status.")),
                }
            ),
            _output({"recoveries": _array("Recovery loops.", generic)}),
            read_only=True,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_run_recovery_cycle",
            "Run one bounded recovery cycle that may issue one durable command per due loop.",
            _object(
                {
                    "policy_id": _string("Autonomy policy id."),
                    "limit": _integer("Maximum due loops.", minimum=1, maximum=100, default=10),
                },
                ["policy_id"],
            ),
            _output({"cycle": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_record_recovery_outcome",
            "Record the latest recovery attempt outcome and bounded retry decision.",
            _object(
                {
                    "loop_id": _string("Recovery loop id."),
                    "status": _enum("Outcome.", ["succeeded", "failed", "cancelled"]),
                    "command_id": _nullable(_string("Latest recovery command id.")),
                    "error": _nullable(_string("Bounded failure detail.")),
                },
                ["loop_id", "status"],
            ),
            _output({"recovery": generic}),
            read_only=False,
            idempotent=True,
        ),
        _tool(
            "agent_autonomy_control",
            "Pause, kill, or resume autonomy at global, tenant, room, or policy scope. Requires gateway-admin.",
            _object(
                {
                    "scope_type": _enum("Control scope.", ["global", "tenant", "room", "policy"]),
                    "scope_id": _nullable(_string("Room or policy id; omitted for global/tenant.")),
                    "state": _enum("Control state.", ["enabled", "paused", "killed"]),
                    "reason": _string("Operator reason."),
                    "expires_at": _nullable(_string("Optional ISO-8601 expiry.")),
                },
                ["scope_type", "state", "reason"],
            ),
            _output({"control": generic}),
            read_only=False,
            idempotent=True,
            destructive=True,
        ),
        _tool(
            "agent_autonomy_override",
            "Apply an audited operator override. Requires gateway-admin.",
            _object(
                {
                    "action": _enum(
                        "Override action.",
                        ["force_assign", "revoke_assignment", "revoke_permits", "cancel_recoveries"],
                    ),
                    "reason": _string("Operator reason."),
                    "room_id": _nullable(_string("Optional room id.")),
                    "policy_id": _nullable(_string("Optional policy id.")),
                    "work_item_id": _nullable(_string("Work item id for force assignment.")),
                    "agent_id": _nullable(_string("Agent id for force assignment.")),
                    "assignment_id": _nullable(_string("Assignment id for revocation.")),
                    "evidence": _object(additional=True),
                },
                ["action", "reason"],
            ),
            _output({"override": generic}),
            read_only=False,
            idempotent=False,
            destructive=True,
        ),
        _tool(
            "agent_autonomy_metrics",
            "Return tenant-scoped autonomy policy, approval, permit, recovery, assignment, and receipt counts.",
            _object(),
            _output({"metrics": generic}),
            read_only=True,
            idempotent=True,
        ),
    ]


def agent_autonomy_tool_names() -> frozenset[str]:
    return frozenset(tool["name"] for tool in agent_autonomy_tools())


def _approval_with_votes(db: Session, request: Any) -> dict[str, Any]:
    votes = (
        db.query(ApprovalVote)
        .filter(ApprovalVote.request_id == request.id)
        .order_by(ApprovalVote.created_at, ApprovalVote.id)
        .all()
    )
    return approval_payload(request, votes)


async def call_agent_autonomy_tool(
    name: str,
    args: dict[str, Any],
    user: User,
    db: Session,
) -> dict[str, Any]:
    owner = user.subject
    if name == "agent_autonomy_create_policy":
        payload = AutonomyPolicyCreate.model_validate(args)
        policy = agent_autonomy_service.create_policy(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            data=payload.model_dump(),
        )
        return {"policy": policy_payload(policy)}
    if name == "agent_autonomy_list_policies":
        policies = agent_autonomy_service.list_policies(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
        )
        return {"policies": [policy_payload(policy) for policy in policies]}
    if name == "agent_autonomy_run_assignment_cycle":
        return {
            "cycle": agent_autonomy_service.run_assignment_cycle(
                db,
                owner_subject=owner,
                policy_id=str(args["policy_id"]),
                actor_subject=user.subject,
                limit=int(args.get("limit", 10)),
            )
        }
    if name == "agent_autonomy_list_assignments":
        rows = agent_autonomy_service.list_assignments(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            policy_id=args.get("policy_id"),
            status=args.get("status"),
        )
        return {"assignments": [assignment_payload(row) for row in rows]}
    if name == "agent_autonomy_apply_assignment":
        row = agent_autonomy_service.apply_assignment(
            db,
            owner_subject=owner,
            assignment_id=str(args["assignment_id"]),
            actor_subject=user.subject,
        )
        return {"assignment": assignment_payload(row)}
    if name == "agent_autonomy_request_approval":
        payload = ApprovalRequestCreate.model_validate(args)
        request = agent_autonomy_service.create_approval_request(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            data=payload.model_dump(),
        )
        return {"approval": _approval_with_votes(db, request)}
    if name == "agent_autonomy_list_approvals":
        rows = agent_autonomy_service.list_approval_requests(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
        )
        return {"approvals": [_approval_with_votes(db, row) for row in rows]}
    if name == "agent_autonomy_vote":
        payload = ApprovalVoteCreate.model_validate(
            {"decision": args["decision"], "reason": args.get("reason")}
        )
        request = agent_autonomy_service.cast_vote(
            db,
            request_id=str(args["request_id"]),
            user=user,
            decision=payload.decision,
            reason=payload.reason,
        )
        return {"approval": _approval_with_votes(db, request)}
    if name == "agent_autonomy_issue_permit":
        require_role(user, "gateway-admin")
        payload = ExecutionPermitIssue.model_validate(
            {"ttl_seconds": args.get("ttl_seconds")}
        )
        permit = agent_autonomy_service.issue_permit(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            request_id=str(args["request_id"]),
            ttl_seconds=payload.ttl_seconds,
        )
        return {"permit": permit_payload(permit)}
    if name == "agent_autonomy_claim_permit":
        payload = ExecutionPermitClaim.model_validate(
            {"executor_agent_id": args["executor_agent_id"]}
        )
        permit = agent_autonomy_service.claim_permit(
            db,
            owner_subject=owner,
            permit_id=str(args["permit_id"]),
            executor_agent_id=payload.executor_agent_id,
        )
        return {"permit": permit_payload(permit)}
    if name == "agent_autonomy_record_receipt":
        payload = ActionReceiptCreate.model_validate(args)
        receipt = agent_autonomy_service.record_receipt(
            db, owner_subject=owner, data=payload.model_dump()
        )
        return {"receipt": receipt_payload(receipt)}
    if name == "agent_autonomy_create_recovery":
        payload = RecoveryLoopCreate.model_validate(args)
        loop = agent_autonomy_service.create_recovery_loop(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            data=payload.model_dump(),
        )
        return {"recovery": recovery_payload(loop)}
    if name == "agent_autonomy_list_recoveries":
        loops = agent_autonomy_service.list_recovery_loops(
            db,
            owner_subject=owner,
            room_id=args.get("room_id"),
            status=args.get("status"),
        )
        return {"recoveries": [recovery_payload(loop) for loop in loops]}
    if name == "agent_autonomy_run_recovery_cycle":
        return {
            "cycle": agent_autonomy_service.run_recovery_cycle(
                db,
                owner_subject=owner,
                policy_id=str(args["policy_id"]),
                actor_subject=user.subject,
                limit=int(args.get("limit", 10)),
            )
        }
    if name == "agent_autonomy_record_recovery_outcome":
        payload = RecoveryOutcomeCreate.model_validate(
            {
                "status": args["status"],
                "command_id": args.get("command_id"),
                "error": args.get("error"),
            }
        )
        loop = agent_autonomy_service.record_recovery_outcome(
            db,
            owner_subject=owner,
            loop_id=str(args["loop_id"]),
            status=payload.status,
            command_id=payload.command_id,
            error=payload.error,
        )
        return {"recovery": recovery_payload(loop)}
    if name == "agent_autonomy_control":
        require_role(user, "gateway-admin")
        payload = AutonomyControlUpdate.model_validate(args)
        control = agent_autonomy_service.set_control(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            actor_roles=list(user.roles or []),
            data=payload.model_dump(),
        )
        return {"control": control_payload(control)}
    if name == "agent_autonomy_override":
        require_role(user, "gateway-admin")
        payload = AutonomyOverrideCreate.model_validate(args)
        record = agent_autonomy_service.apply_override(
            db,
            owner_subject=owner,
            actor_subject=user.subject,
            actor_roles=list(user.roles or []),
            data=payload.model_dump(),
        )
        return {"override": override_payload(record)}
    if name == "agent_autonomy_metrics":
        require_role(user, "gateway-auditor", "gateway-admin")
        return {"metrics": agent_autonomy_service.metrics(db, owner_subject=owner)}
    raise HTTPException(status_code=404, detail=f"Unknown agent autonomy tool: {name}")
