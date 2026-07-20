from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..account_settings import (
    set_ssh_command_profile_override,
    ssh_command_settings_payload,
)
from ..auth import get_current_user
from ..config import Settings, get_settings
from ..database import get_db
from ..dto import AccountSettingsOut, AccountSettingsUpdate
from ..events import emit_event
from ..models import User

router = APIRouter(prefix="/api/account", tags=["account"])


@router.get("/settings", response_model=AccountSettingsOut)
async def get_account_settings(
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> AccountSettingsOut:
    return AccountSettingsOut(**ssh_command_settings_payload(user, settings))


@router.patch("/settings", response_model=AccountSettingsOut)
async def update_account_settings(
    payload: AccountSettingsUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AccountSettingsOut:
    profile = None if payload.ssh_command_profile == "inherit" else payload.ssh_command_profile
    set_ssh_command_profile_override(user, profile)
    db.add(user)
    emit_event(
        db,
        event_type="gateway.user.settings_updated.v1",
        actor_subject=user.subject,
        action="settings_updated",
        resource_type="user",
        resource_id=user.subject,
        payload={
            "setting": "ssh_command_profile",
            "override": profile,
            "effective": ssh_command_settings_payload(user, settings)["ssh_command_profile"],
        },
        commit=False,
    )
    db.commit()
    db.refresh(user)
    return AccountSettingsOut(**ssh_command_settings_payload(user, settings))
