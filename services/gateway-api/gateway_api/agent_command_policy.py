from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


SHELL_CAPABLE_TOOLS = frozenset(
    {
        "docker_workspace_exec",
        "run_cli_command",
        "ssh_device_run_command",
        "thin_client_run_command",
    }
)
RAW_SHELL_ARGUMENT_KEYS = frozenset(
    {
        "args",
        "argv",
        "command",
        "script",
        "shell",
    }
)


class AgentCommandPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class AgentToolExecution:
    tool: str
    arguments: dict[str, Any]
    command_profile: str | None


def enforce_agent_tenant_scope(*, actor_subject: str, owner_subject: str) -> None:
    if not actor_subject or actor_subject != owner_subject:
        raise AgentCommandPolicyError("Agent resource is outside the authenticated tenant scope")


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AgentCommandPolicyError(f"{field} must be an object")
    return value


def _normalized_allowlist(values: Iterable[str]) -> frozenset[str]:
    return frozenset(str(value).strip() for value in values if str(value).strip())


def resolve_agent_command_execution(
    command: Mapping[str, Any],
    *,
    allowed_tools: Iterable[str],
    allowed_command_profiles: Iterable[str] = (),
) -> AgentToolExecution:
    kind = str(command.get("kind") or "").strip()
    if kind != "run_tool":
        raise AgentCommandPolicyError("Text instructions are not executable; kind must be run_tool")

    payload = _mapping(command.get("structured_payload"), field="structured_payload")
    tool = str(payload.get("tool") or "").strip()
    if not tool:
        raise AgentCommandPolicyError("structured_payload.tool is required")

    tool_allowlist = _normalized_allowlist(allowed_tools)
    if tool not in tool_allowlist:
        raise AgentCommandPolicyError("Tool is not allowed by the agent execution policy")

    arguments = dict(_mapping(payload.get("arguments") or {}, field="structured_payload.arguments"))
    command_profile: str | None = None

    if tool in SHELL_CAPABLE_TOOLS:
        forbidden_keys = RAW_SHELL_ARGUMENT_KEYS.intersection(arguments)
        if forbidden_keys:
            names = ", ".join(sorted(forbidden_keys))
            raise AgentCommandPolicyError(f"Raw shell arguments are forbidden: {names}")
        command_profile = str(arguments.get("command_profile") or "").strip()
        if not command_profile:
            raise AgentCommandPolicyError("Shell-capable tools require command_profile")
        profile_allowlist = _normalized_allowlist(allowed_command_profiles)
        if command_profile not in profile_allowlist:
            raise AgentCommandPolicyError("Command profile is not allowed by the agent execution policy")

    return AgentToolExecution(tool=tool, arguments=arguments, command_profile=command_profile)


DELIVERABLE_COMMAND_KINDS = frozenset(
    {
        "handoff",
        "instruction",
        "pause",
        "resume",
        "review_request",
        "run_tool",
    }
)


def validate_agent_command_for_delivery(command: Mapping[str, Any]) -> None:
    kind = str(command.get("kind") or "").strip()
    if kind not in DELIVERABLE_COMMAND_KINDS:
        raise AgentCommandPolicyError("Unsupported agent command kind")
    instruction = str(command.get("instruction") or "").strip()
    if not instruction:
        raise AgentCommandPolicyError("Agent command instruction is required")
    if kind != "run_tool":
        return
    payload = _mapping(command.get("structured_payload"), field="structured_payload")
    tool = str(payload.get("tool") or "").strip()
    if not tool:
        raise AgentCommandPolicyError("structured_payload.tool is required")
    arguments = dict(_mapping(payload.get("arguments") or {}, field="structured_payload.arguments"))
    if tool in SHELL_CAPABLE_TOOLS:
        forbidden_keys = RAW_SHELL_ARGUMENT_KEYS.intersection(arguments)
        if forbidden_keys:
            names = ", ".join(sorted(forbidden_keys))
            raise AgentCommandPolicyError(f"Raw shell arguments are forbidden: {names}")
        command_profile = str(arguments.get("command_profile") or "").strip()
        if not command_profile:
            raise AgentCommandPolicyError("Shell-capable tools require command_profile")


SECRET_LIKE_ARGUMENT_NAMES = frozenset(
    {
        "access_token",
        "access_tokens",
        "api_key",
        "auth_token",
        "authorization",
        "bearer",
        "client_secret",
        "credential",
        "credentials",
        "github_token",
        "gitlab_token",
        "password",
        "passphrase",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)
SECRET_LIKE_ARGUMENT_SUFFIXES = (
    "apikey",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "privatekey",
    "secret",
    "token",
)


def _normalized_secret_name(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def _is_secret_like_name(value: str) -> bool:
    normalized = _normalized_secret_name(value)
    exact_names = {_normalized_secret_name(item) for item in SECRET_LIKE_ARGUMENT_NAMES}
    return normalized in exact_names or normalized.endswith(SECRET_LIKE_ARGUMENT_SUFFIXES)


def assert_no_secret_like_keys(value: Any, *, field: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _is_secret_like_name(str(key)):
                raise AgentCommandPolicyError(f"Secret-like key is not accepted in {field}: {key}")
            assert_no_secret_like_keys(item, field=field)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            assert_no_secret_like_keys(item, field=field)
