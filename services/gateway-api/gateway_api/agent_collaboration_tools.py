from __future__ import annotations

import asyncio
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .agent_collaboration import (
    agent_collaboration_service,
    agent_payload,
    command_payload,
    message_payload,
    room_payload,
    work_item_payload,
)
from .models import User


SECRET_ARGUMENT_NOTE = " Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments."


def _object(properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str, *, default: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "description": description}
    if default is not None:
        result["default"] = default
    return result


def _nullable_string(description: str) -> dict[str, Any]:
    return {"type": ["string", "null"], "description": description}


def _integer(description: str, *, default: int | None = None, minimum: int | None = None, maximum: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "integer", "description": description}
    if default is not None:
        result["default"] = default
    if minimum is not None:
        result["minimum"] = minimum
    if maximum is not None:
        result["maximum"] = maximum
    return result


def _boolean(description: str, *, default: bool | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "boolean", "description": description}
    if default is not None:
        result["default"] = default
    return result


def _array(description: str, items: dict[str, Any], *, default: list[Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "array", "description": description, "items": items}
    if default is not None:
        result["default"] = default
    return result


def _enum(description: str, values: list[str], *, default: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "description": description, "enum": values}
    if default is not None:
        result["default"] = default
    return result


def _output(properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return _object(
        {
            "ok": _boolean("Whether the tool call completed successfully."),
            "error": _nullable_string("Error message when ok is false."),
            **(properties or {}),
        },
        ["ok"],
    )


def _annotations(*, title: str, read_only: bool, destructive: bool = False, idempotent: bool = False) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": False,
    }


def _tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    annotations: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{description}{SECRET_ARGUMENT_NOTE}",
        "inputSchema": input_schema,
        "outputSchema": output_schema,
        "annotations": annotations,
    }


def agent_collaboration_tools() -> list[dict[str, Any]]:
    agent_schema = {"type": "object", "description": "Agent instance."}
    room_schema = {"type": "object", "description": "Collaboration room."}
    message_schema = {"type": "object", "description": "Durable agent message."}
    command_schema = {"type": "object", "description": "Durable agent command."}
    work_item_schema = {"type": "object", "description": "Agent work item."}
    return [
        _tool(
            "agent_register",
            "Register or refresh one ephemeral agent instance under the authenticated tenant.",
            _object(
                {
                    "logical_agent_id": _string("Stable logical agent identity."),
                    "instance_id": _string("Optional runtime instance identity. Generated when omitted."),
                    "display_name": _string("Optional display name."),
                    "capabilities": _array("Agent capability names.", {"type": "string"}, default=[]),
                    "labels": {"type": "object", "description": "Agent labels.", "additionalProperties": True},
                    "room_id": _string("Optional room to join during registration."),
                    "ttl_seconds": _integer("Heartbeat expiry interval.", default=120, minimum=30, maximum=3600),
                },
                ["logical_agent_id", "instance_id"],
            ),
            _output({"agent": agent_schema}),
            _annotations(title="Register agent", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_heartbeat",
            "Refresh agent presence, current room, labels, and capabilities.",
            _object(
                {
                    "agent_id": _string("Agent instance id."),
                    "status": _enum("Active presence status.", ["active", "busy", "idle"], default="active"),
                    "capabilities": _array("Replacement capabilities.", {"type": "string"}),
                    "labels": {"type": "object", "description": "Replacement labels.", "additionalProperties": True},
                    "room_id": _string("Current collaboration room id."),
                    "ttl_seconds": _integer("Heartbeat expiry interval.", default=120, minimum=30, maximum=3600),
                },
                ["agent_id"],
            ),
            _output({"agent": agent_schema}),
            _annotations(title="Heartbeat agent", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_list",
            "List tenant-owned agent instances, optionally scoped to one room.",
            _object({"room_id": _string("Optional collaboration room id.")}),
            _output({"agents": _array("Agent instances.", agent_schema)}),
            _annotations(title="List agents", read_only=True, idempotent=True),
        ),
        _tool(
            "agent_unregister",
            "Mark one agent instance offline without deleting its durable history.",
            _object({"agent_id": _string("Agent instance id.")}, ["agent_id"]),
            _output({"agent": agent_schema}),
            _annotations(title="Unregister agent", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_create_room",
            "Create a tenant-scoped collaboration room for one repository or project context.",
            _object(
                {
                    "title": _string("Room title."),
                    "project_path": _string("Optional project path."),
                    "repository_identity": _string("Optional canonical repository identity."),
                    "base_commit": _string("Optional immutable base commit."),
                    "policy": {"type": "object", "description": "Room policy.", "additionalProperties": True},
                    "created_by_agent_id": _string("Optional creating agent id."),
                    "idempotency_key": _string("Optional tenant-scoped idempotency key."),
                },
                ["title"],
            ),
            _output({"room": room_schema}),
            _annotations(title="Create collaboration room", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_list_rooms",
            "List collaboration rooms for the authenticated tenant.",
            _object({"status": _string("Optional room status filter.")}),
            _output({"rooms": _array("Collaboration rooms.", room_schema)}),
            _annotations(title="List collaboration rooms", read_only=True, idempotent=True),
        ),
        _tool(
            "agent_join_room",
            "Move one agent instance into an active collaboration room.",
            _object(
                {
                    "agent_id": _string("Agent instance id."),
                    "room_id": _string("Collaboration room id."),
                },
                ["agent_id", "room_id"],
            ),
            _output({"agent": agent_schema}),
            _annotations(title="Join collaboration room", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_get_room_snapshot",
            "Read one room snapshot with agents, work items, recent messages, and recent commands.",
            _object({"room_id": _string("Collaboration room id.")}, ["room_id"]),
            _output({"snapshot": {"type": "object"}}),
            _annotations(title="Get collaboration room snapshot", read_only=True, idempotent=True),
        ),
        _tool(
            "agent_send_message",
            "Send a durable direct or room-broadcast message with explicit delivery acknowledgements.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "sender_agent_id": _string("Sender agent id."),
                    "recipient_agent_id": _string("Direct recipient agent id."),
                    "recipient_selector": _enum("Broadcast selector.", ["all", "room"]),
                    "kind": _string("Message kind, for example information, question, blocker, or handoff."),
                    "body": _string("Human-readable message body."),
                    "payload": {"type": "object", "description": "Structured message payload.", "additionalProperties": True},
                    "priority": _integer("Priority from 0 to 100.", default=50, minimum=0, maximum=100),
                    "correlation_id": _string("Optional correlation id."),
                    "causation_id": _string("Optional causation id."),
                    "idempotency_key": _string("Optional tenant-scoped idempotency key."),
                },
                ["room_id", "sender_agent_id", "body"],
            ),
            _output({"message": message_schema, "recipient_count": _integer("Number of delivery records created.")}),
            _annotations(title="Send agent message", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_read_inbox",
            "Pull unacknowledged durable messages for one agent. Messages are redelivered until explicitly acknowledged.",
            _object(
                {
                    "agent_id": _string("Recipient agent id."),
                    "limit": _integer("Maximum messages.", default=50, minimum=1, maximum=200),
                    "after_message_id": _string("Optional message cursor."),
                    "wait_seconds": _integer("Optional long-poll wait duration.", default=0, minimum=0, maximum=30),
                },
                ["agent_id"],
            ),
            _output(
                {
                    "messages": _array("Inbox messages.", message_schema),
                    "next_cursor": _nullable_string("Last returned message id."),
                }
            ),
            _annotations(title="Read agent inbox", read_only=True, idempotent=False),
        ),
        _tool(
            "agent_ack_message",
            "Acknowledge one message delivery for the recipient agent.",
            _object(
                {
                    "agent_id": _string("Recipient agent id."),
                    "message_id": _string("Message id."),
                },
                ["agent_id", "message_id"],
            ),
            _output({"message_id": _string("Message id."), "status": _string("Delivery status.")}),
            _annotations(title="Acknowledge agent message", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_issue_command",
            "Issue a durable command to one agent. Phase 1 stores and delivers commands but never executes instruction text automatically.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "issuer_agent_id": _string("Issuer agent id."),
                    "target_agent_id": _string("Target agent id."),
                    "kind": _enum(
                        "Command kind.",
                        ["handoff", "instruction", "pause", "resume", "review_request", "run_tool"],
                        default="instruction",
                    ),
                    "instruction": _string("Human-readable command instruction. Never executable by itself."),
                    "structured_payload": {"type": "object", "description": "Typed command payload.", "additionalProperties": True},
                    "constraints": {"type": "object", "description": "Command constraints.", "additionalProperties": True},
                    "priority": _integer("Priority from 0 to 100.", default=50, minimum=0, maximum=100),
                    "requires_approval": _boolean("Whether acceptance requires a future approval record.", default=False),
                    "correlation_id": _string("Optional correlation id."),
                    "causation_id": _string("Optional causation id."),
                    "idempotency_key": _string("Optional tenant-scoped idempotency key."),
                },
                ["room_id", "issuer_agent_id", "target_agent_id", "instruction"],
            ),
            _output({"command": command_schema}),
            _annotations(title="Issue agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_list_commands",
            "Pull durable nonterminal commands for one target agent.",
            _object(
                {
                    "agent_id": _string("Target agent id."),
                    "status": _string("Optional exact command status."),
                    "limit": _integer("Maximum commands.", default=50, minimum=1, maximum=200),
                    "wait_seconds": _integer("Optional long-poll wait duration.", default=0, minimum=0, maximum=30),
                },
                ["agent_id"],
            ),
            _output({"commands": _array("Agent commands.", command_schema)}),
            _annotations(title="List agent commands", read_only=True, idempotent=False),
        ),
        _tool(
            "agent_ack_command",
            "Acknowledge delivery of one command.",
            _object({"agent_id": _string("Target agent id."), "command_id": _string("Command id.")}, ["agent_id", "command_id"]),
            _output({"command": command_schema}),
            _annotations(title="Acknowledge agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_accept_command",
            "Accept one acknowledged or delivered command without executing it automatically.",
            _object({"agent_id": _string("Target agent id."), "command_id": _string("Command id.")}, ["agent_id", "command_id"]),
            _output({"command": command_schema}),
            _annotations(title="Accept agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_reject_command",
            "Reject one command with an optional reason.",
            _object(
                {
                    "agent_id": _string("Target agent id."),
                    "command_id": _string("Command id."),
                    "error": _string("Optional rejection reason."),
                },
                ["agent_id", "command_id"],
            ),
            _output({"command": command_schema}),
            _annotations(title="Reject agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_complete_command",
            "Complete or fail an accepted command and attach a structured result.",
            _object(
                {
                    "agent_id": _string("Target agent id."),
                    "command_id": _string("Command id."),
                    "status": _enum("Terminal result.", ["completed", "failed"]),
                    "result": {"type": "object", "description": "Structured command result.", "additionalProperties": True},
                    "error": _string("Optional failure detail."),
                },
                ["agent_id", "command_id", "status"],
            ),
            _output({"command": command_schema}),
            _annotations(title="Complete agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_cancel_command",
            "Cancel a nonterminal command as its issuing agent.",
            _object(
                {
                    "issuer_agent_id": _string("Issuer agent id."),
                    "command_id": _string("Command id."),
                },
                ["issuer_agent_id", "command_id"],
            ),
            _output({"command": command_schema}),
            _annotations(title="Cancel agent command", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_create_work_item",
            "Create a durable work item with dependencies, acceptance criteria, and optimistic versioning.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "parent_id": _string("Optional parent work item id."),
                    "title": _string("Work item title."),
                    "description": _string("Work item description."),
                    "priority": _integer("Priority from 0 to 100.", default=50, minimum=0, maximum=100),
                    "base_commit": _string("Optional base commit."),
                    "dependencies": _array("Dependency work item ids.", {"type": "string"}, default=[]),
                    "acceptance_criteria": _array("Acceptance criteria.", {"type": "string"}, default=[]),
                    "required_capabilities": _array(
                        "Capabilities an automatically selected agent must advertise.",
                        {"type": "string"},
                        default=[],
                    ),
                    "assignment_constraints": {
                        "type": "object",
                        "description": "Safe capability-assignment constraints such as labels and excluded agent ids.",
                        "additionalProperties": True,
                    },
                    "idempotency_key": _string("Optional tenant-scoped idempotency key."),
                },
                ["room_id", "title"],
            ),
            _output({"work_item": work_item_schema}),
            _annotations(title="Create agent work item", read_only=False, idempotent=True),
        ),
        _tool(
            "agent_list_work_items",
            "List work items in one collaboration room.",
            _object(
                {
                    "room_id": _string("Collaboration room id."),
                    "status": _string("Optional exact status."),
                    "limit": _integer("Maximum work items.", default=100, minimum=1, maximum=200),
                },
                ["room_id"],
            ),
            _output({"work_items": _array("Work items.", work_item_schema)}),
            _annotations(title="List agent work items", read_only=True, idempotent=True),
        ),
        _tool(
            "agent_claim_work_item",
            "Atomically claim one open work item using its expected version.",
            _object(
                {
                    "agent_id": _string("Claiming agent id."),
                    "work_item_id": _string("Work item id."),
                    "expected_version": _integer("Expected optimistic version.", default=1, minimum=1),
                },
                ["agent_id", "work_item_id"],
            ),
            _output({"work_item": work_item_schema}),
            _annotations(title="Claim agent work item", read_only=False, idempotent=False),
        ),
        _tool(
            "agent_update_work_item",
            "Update an assigned work item using optimistic version checking.",
            _object(
                {
                    "agent_id": _string("Assigned agent id."),
                    "work_item_id": _string("Work item id."),
                    "expected_version": _integer("Expected optimistic version.", minimum=1),
                    "status": _enum("New work item status.", ["blocked", "cancelled", "completed", "failed", "in_progress", "review"]),
                    "description": _string("Optional replacement description."),
                    "result": {"type": "object", "description": "Structured work result.", "additionalProperties": True},
                },
                ["agent_id", "work_item_id", "expected_version", "status"],
            ),
            _output({"work_item": work_item_schema}),
            _annotations(title="Update agent work item", read_only=False, idempotent=True),
        ),
    ]


def agent_collaboration_tool_names() -> frozenset[str]:
    return frozenset(tool["name"] for tool in agent_collaboration_tools())


async def call_agent_collaboration_tool(name: str, args: dict[str, Any], user: User, db: Session) -> dict[str, Any]:
    service = agent_collaboration_service
    owner_subject = user.subject
    if name == "agent_register":
        return {"agent": agent_payload(service.register_agent(db, owner_subject=owner_subject, data=args))}
    if name == "agent_heartbeat":
        agent = service.heartbeat_agent(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            data={key: value for key, value in args.items() if key != "agent_id"},
        )
        return {"agent": agent_payload(agent)}
    if name == "agent_list":
        agents = service.list_agents(db, owner_subject=owner_subject, room_id=args.get("room_id"))
        return {"agents": [agent_payload(agent) for agent in agents]}
    if name == "agent_unregister":
        agent = service.unregister_agent(db, owner_subject=owner_subject, agent_id=str(args["agent_id"]))
        return {"agent": agent_payload(agent)}
    if name == "agent_create_room":
        return {"room": room_payload(service.create_room(db, owner_subject=owner_subject, data=args))}
    if name == "agent_list_rooms":
        rooms = service.list_rooms(db, owner_subject=owner_subject, status=args.get("status"))
        return {"rooms": [room_payload(room) for room in rooms]}
    if name == "agent_join_room":
        agent = service.join_room(
            db,
            owner_subject=owner_subject,
            room_id=str(args["room_id"]),
            agent_id=str(args["agent_id"]),
        )
        return {"agent": agent_payload(agent)}
    if name == "agent_get_room_snapshot":
        return {"snapshot": service.room_snapshot(db, owner_subject=owner_subject, room_id=str(args["room_id"]))}
    if name == "agent_send_message":
        message, recipient_count = service.send_message(db, owner_subject=owner_subject, data=args)
        return {"message": message_payload(message), "recipient_count": recipient_count}
    if name == "agent_read_inbox":
        wait_seconds = max(0, min(int(args.get("wait_seconds", 0) or 0), 30))
        deadline = asyncio.get_running_loop().time() + wait_seconds
        rows = service.read_inbox(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            limit=int(args.get("limit", 50) or 50),
            after_message_id=args.get("after_message_id"),
        )
        while not rows and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.25)
            db.expire_all()
            rows = service.read_inbox(
                db,
                owner_subject=owner_subject,
                agent_id=str(args["agent_id"]),
                limit=int(args.get("limit", 50) or 50),
                after_message_id=args.get("after_message_id"),
            )
        messages = [message_payload(message, delivery) for message, delivery in rows]
        return {"messages": messages, "next_cursor": messages[-1]["id"] if messages else args.get("after_message_id")}
    if name == "agent_ack_message":
        delivery = service.ack_message(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            message_id=str(args["message_id"]),
        )
        return {"message_id": str(args["message_id"]), "status": delivery.status}
    if name == "agent_issue_command":
        return {"command": command_payload(service.issue_command(db, owner_subject=owner_subject, data=args))}
    if name == "agent_list_commands":
        wait_seconds = max(0, min(int(args.get("wait_seconds", 0) or 0), 30))
        deadline = asyncio.get_running_loop().time() + wait_seconds
        commands = service.list_commands(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            status=args.get("status"),
            limit=int(args.get("limit", 50) or 50),
        )
        while not commands and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.25)
            db.expire_all()
            commands = service.list_commands(
                db,
                owner_subject=owner_subject,
                agent_id=str(args["agent_id"]),
                status=args.get("status"),
                limit=int(args.get("limit", 50) or 50),
            )
        return {"commands": [command_payload(command) for command in commands]}
    if name == "agent_ack_command":
        command = service.ack_command(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            command_id=str(args["command_id"]),
        )
        return {"command": command_payload(command)}
    if name == "agent_accept_command":
        command = service.accept_command(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            command_id=str(args["command_id"]),
        )
        return {"command": command_payload(command)}
    if name == "agent_reject_command":
        command = service.reject_command(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            command_id=str(args["command_id"]),
            error=args.get("error"),
        )
        return {"command": command_payload(command)}
    if name == "agent_complete_command":
        command = service.complete_command(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            command_id=str(args["command_id"]),
            status=str(args["status"]),
            result=dict(args.get("result") or {}),
            error=args.get("error"),
        )
        return {"command": command_payload(command)}
    if name == "agent_cancel_command":
        command = service.cancel_command(
            db,
            owner_subject=owner_subject,
            issuer_agent_id=str(args["issuer_agent_id"]),
            command_id=str(args["command_id"]),
        )
        return {"command": command_payload(command)}
    if name == "agent_create_work_item":
        return {"work_item": work_item_payload(service.create_work_item(db, owner_subject=owner_subject, data=args))}
    if name == "agent_list_work_items":
        items = service.list_work_items(
            db,
            owner_subject=owner_subject,
            room_id=str(args["room_id"]),
            status=args.get("status"),
            limit=int(args.get("limit", 100) or 100),
        )
        return {"work_items": [work_item_payload(item) for item in items]}
    if name == "agent_claim_work_item":
        item = service.claim_work_item(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            work_item_id=str(args["work_item_id"]),
            expected_version=int(args.get("expected_version", 1)),
        )
        return {"work_item": work_item_payload(item)}
    if name == "agent_update_work_item":
        item = service.update_work_item(
            db,
            owner_subject=owner_subject,
            agent_id=str(args["agent_id"]),
            work_item_id=str(args["work_item_id"]),
            expected_version=int(args["expected_version"]),
            data={key: value for key, value in args.items() if key not in {"agent_id", "work_item_id", "expected_version"}},
        )
        return {"work_item": work_item_payload(item)}
    raise HTTPException(status_code=404, detail=f"Unknown agent collaboration tool: {name}")
