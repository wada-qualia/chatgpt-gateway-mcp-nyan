from __future__ import annotations

from typing import Literal, cast

from .config import Settings
from .models import User

SshCommandProfile = Literal["restricted", "filtered", "unrestricted"]
UiLanguage = Literal["en", "ru"]
SSH_COMMAND_PROFILES: tuple[SshCommandProfile, ...] = (
    "restricted",
    "filtered",
    "unrestricted",
)
UI_LANGUAGES: tuple[UiLanguage, ...] = ("en", "ru")
SSH_COMMAND_PROFILE_PREFERENCE = "ssh_command_profile"
UI_LANGUAGE_PREFERENCE = "ui_language"


def ssh_command_profile_override(user: User) -> SshCommandProfile | None:
    value = (user.preferences or {}).get(SSH_COMMAND_PROFILE_PREFERENCE)
    if value in SSH_COMMAND_PROFILES:
        return cast(SshCommandProfile, value)
    return None


def effective_ssh_command_profile(user: User, settings: Settings) -> SshCommandProfile:
    return ssh_command_profile_override(user) or settings.ssh_command_profile_default


def raw_ssh_commands_enabled(user: User, settings: Settings) -> bool:
    return effective_ssh_command_profile(user, settings) != "restricted"


def ui_language(user: User) -> UiLanguage:
    value = (user.preferences or {}).get(UI_LANGUAGE_PREFERENCE)
    if value in UI_LANGUAGES:
        return cast(UiLanguage, value)
    return "en"


def account_settings_payload(user: User, settings: Settings) -> dict[str, object]:
    override = ssh_command_profile_override(user)
    effective = effective_ssh_command_profile(user, settings)
    return {
        "ui_language": ui_language(user),
        "ssh_command_profile": effective,
        "ssh_command_profile_override": override,
        "ssh_command_profile_default": settings.ssh_command_profile_default,
        "raw_commands_enabled": effective != "restricted",
        "deny_patterns_enabled": effective == "filtered",
    }


def set_ui_language(user: User, language: UiLanguage) -> None:
    preferences = dict(user.preferences or {})
    preferences[UI_LANGUAGE_PREFERENCE] = language
    user.preferences = preferences


def set_ssh_command_profile_override(
    user: User,
    profile: SshCommandProfile | None,
) -> None:
    preferences = dict(user.preferences or {})
    if profile is None:
        preferences.pop(SSH_COMMAND_PROFILE_PREFERENCE, None)
    else:
        preferences[SSH_COMMAND_PROFILE_PREFERENCE] = profile
    user.preferences = preferences
