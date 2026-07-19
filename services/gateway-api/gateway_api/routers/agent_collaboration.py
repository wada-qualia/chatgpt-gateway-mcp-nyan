from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..agent_collaboration import (
    agent_collaboration_service,
    agent_payload,
    command_payload,
    message_payload,
    room_payload,
    work_item_payload,
)
from ..auth import get_current_user
from ..database import get_db
from ..dto import (
    AgentCommandComplete,
    AgentCommandCreate,
    AgentCommandReject,
    AgentHeartbeat,
    AgentMessageCreate,
    AgentRegister,
    AgentWorkItemClaim,
    AgentWorkItemCreate,
    AgentWorkItemUpdate,
    CollaborationRoomCreate,
    CollaborationRoomJoin,
)
from ..models import User
from ..policy import enforce

router = APIRouter(prefix="/api/agent-collaboration", tags=["agent-collaboration"])


@router.post("/agents", status_code=201)
async def register_agent(
    payload: AgentRegister,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    agent = agent_collaboration_service.register_agent(db, owner_subject=user.subject, data=payload.model_dump())
    return agent_payload(agent)


@router.get("/agents")
async def list_agents(
    room_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    agents = agent_collaboration_service.list_agents(db, owner_subject=user.subject, room_id=room_id)
    return [agent_payload(agent) for agent in agents]


@router.post("/agents/{agent_id}/heartbeat")
async def heartbeat_agent(
    agent_id: str,
    payload: AgentHeartbeat,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    agent = agent_collaboration_service.heartbeat_agent(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        data=payload.model_dump(exclude_unset=True),
    )
    return agent_payload(agent)


@router.post("/agents/{agent_id}/unregister")
async def unregister_agent(
    agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    agent = agent_collaboration_service.unregister_agent(db, owner_subject=user.subject, agent_id=agent_id)
    return agent_payload(agent)


@router.post("/rooms", status_code=201)
async def create_room(
    payload: CollaborationRoomCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    room = agent_collaboration_service.create_room(db, owner_subject=user.subject, data=payload.model_dump())
    return room_payload(room)


@router.get("/rooms")
async def list_rooms(
    status: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    rooms = agent_collaboration_service.list_rooms(db, owner_subject=user.subject, status=status)
    return [room_payload(room) for room in rooms]


@router.post("/rooms/{room_id}/join")
async def join_room(
    room_id: str,
    payload: CollaborationRoomJoin,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    agent = agent_collaboration_service.join_room(
        db,
        owner_subject=user.subject,
        room_id=room_id,
        agent_id=payload.agent_id,
    )
    return agent_payload(agent)


@router.get("/rooms/{room_id}/snapshot")
async def room_snapshot(
    room_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="read")
    return agent_collaboration_service.room_snapshot(db, owner_subject=user.subject, room_id=room_id)


@router.post("/messages", status_code=201)
async def send_message(
    payload: AgentMessageCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    message, recipient_count = agent_collaboration_service.send_message(
        db,
        owner_subject=user.subject,
        data=payload.model_dump(),
    )
    return {"message": message_payload(message), "recipient_count": recipient_count}


@router.get("/messages/inbox")
async def read_inbox(
    agent_id: str,
    limit: int = 50,
    after_message_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="read")
    rows = agent_collaboration_service.read_inbox(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        limit=limit,
        after_message_id=after_message_id,
    )
    messages = [message_payload(message, delivery) for message, delivery in rows]
    return {"messages": messages, "next_cursor": messages[-1]["id"] if messages else after_message_id}


@router.post("/messages/{message_id}/ack")
async def acknowledge_message(
    message_id: str,
    agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    delivery = agent_collaboration_service.ack_message(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        message_id=message_id,
    )
    return {
        "message_id": message_id,
        "agent_id": agent_id,
        "status": delivery.status,
        "acknowledged_at": delivery.acknowledged_at.isoformat() if delivery.acknowledged_at else None,
    }


@router.post("/commands", status_code=201)
async def issue_command(
    payload: AgentCommandCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    command = agent_collaboration_service.issue_command(db, owner_subject=user.subject, data=payload.model_dump())
    return command_payload(command)


@router.get("/commands/inbox")
async def list_commands(
    agent_id: str,
    status: str | None = None,
    limit: int = 50,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="read")
    commands = agent_collaboration_service.list_commands(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        status=status,
        limit=limit,
    )
    return {"commands": [command_payload(command) for command in commands]}


@router.post("/commands/{command_id}/ack")
async def acknowledge_command(
    command_id: str,
    agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    command = agent_collaboration_service.ack_command(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        command_id=command_id,
    )
    return command_payload(command)


@router.post("/commands/{command_id}/accept")
async def accept_command(
    command_id: str,
    agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    command = agent_collaboration_service.accept_command(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        command_id=command_id,
    )
    return command_payload(command)


@router.post("/commands/{command_id}/reject")
async def reject_command(
    command_id: str,
    agent_id: str,
    payload: AgentCommandReject,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    command = agent_collaboration_service.reject_command(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        command_id=command_id,
        error=payload.error,
    )
    return command_payload(command)


@router.post("/commands/{command_id}/complete")
async def complete_command(
    command_id: str,
    agent_id: str,
    payload: AgentCommandComplete,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    command = agent_collaboration_service.complete_command(
        db,
        owner_subject=user.subject,
        agent_id=agent_id,
        command_id=command_id,
        status=payload.status,
        result=payload.result,
        error=payload.error,
    )
    return command_payload(command)


@router.post("/commands/{command_id}/cancel")
async def cancel_command(
    command_id: str,
    issuer_agent_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    command = agent_collaboration_service.cancel_command(
        db,
        owner_subject=user.subject,
        issuer_agent_id=issuer_agent_id,
        command_id=command_id,
    )
    return command_payload(command)


@router.post("/work-items", status_code=201)
async def create_work_item(
    payload: AgentWorkItemCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="create", owner_subject=user.subject)
    item = agent_collaboration_service.create_work_item(db, owner_subject=user.subject, data=payload.model_dump())
    return work_item_payload(item)


@router.get("/work-items")
async def list_work_items(
    room_id: str,
    status: str | None = None,
    limit: int = 100,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    enforce(user, action="read")
    items = agent_collaboration_service.list_work_items(
        db,
        owner_subject=user.subject,
        room_id=room_id,
        status=status,
        limit=limit,
    )
    return [work_item_payload(item) for item in items]


@router.post("/work-items/{work_item_id}/claim")
async def claim_work_item(
    work_item_id: str,
    payload: AgentWorkItemClaim,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    item = agent_collaboration_service.claim_work_item(
        db,
        owner_subject=user.subject,
        agent_id=payload.agent_id,
        work_item_id=work_item_id,
        expected_version=payload.expected_version,
    )
    return work_item_payload(item)


@router.patch("/work-items/{work_item_id}")
async def update_work_item(
    work_item_id: str,
    payload: AgentWorkItemUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    enforce(user, action="update", owner_subject=user.subject)
    item = agent_collaboration_service.update_work_item(
        db,
        owner_subject=user.subject,
        agent_id=payload.agent_id,
        work_item_id=work_item_id,
        expected_version=payload.expected_version,
        data=payload.model_dump(exclude_unset=True),
    )
    return work_item_payload(item)
