from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..account_settings import (
    account_settings_payload,
    set_ssh_command_profile_override,
    set_ui_language,
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
    return AccountSettingsOut(**account_settings_payload(user, settings))


@router.patch("/settings", response_model=AccountSettingsOut)
async def update_account_settings(
    payload: AccountSettingsUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AccountSettingsOut:
    changed: dict[str, object] = {}

    if "ssh_command_profile" in payload.model_fields_set:
        profile = (
            None
            if payload.ssh_command_profile == "inherit"
            else payload.ssh_command_profile
        )
        set_ssh_command_profile_override(user, profile)
        changed["ssh_command_profile"] = profile or "inherit"

    if "ui_language" in payload.model_fields_set and payload.ui_language is not None:
        set_ui_language(user, payload.ui_language)
        changed["ui_language"] = payload.ui_language

    db.add(user)
    current = account_settings_payload(user, settings)
    emit_event(
        db,
        event_type="gateway.user.settings_updated.v1",
        actor_subject=user.subject,
        action="settings_updated",
        resource_type="user",
        resource_id=user.subject,
        payload={"changed": changed, "effective": current},
        commit=False,
    )
    db.commit()
    db.refresh(user)
    return AccountSettingsOut(**account_settings_payload(user, settings))
