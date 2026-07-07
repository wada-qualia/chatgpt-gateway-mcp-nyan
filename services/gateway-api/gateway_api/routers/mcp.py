from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..adapters.docker import DockerAdapter, safe_container_name
from ..auth import get_bearer_or_dev_user
from ..config import Settings, get_settings
from ..database import get_db
from ..events import emit_event
from ..models import CommandSession, Device, DockerWorkspace, ThinClient, User, utcnow
from ..monitoring import monitoring_service
from ..thin_client_control import thin_client_manager

router = APIRouter(tags=["mcp"])


def _workspace(user: User, settings: Settings) -> Path:
    root = Path(settings.workspace_root).resolve()
    path = (root / "users" / user.username).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_path(user: User, settings: Settings, relative: str = ".") -> Path:
    root = _workspace(user, settings)
    target = (root / relative).resolve()
    if root != target and root not in target.parents:
        raise HTTPException(status_code=400, detail="Path escapes user workspace")
    return target


def _object_schema(properties: dict[str, Any] | None = None, required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str, *, default: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _integer(description: str, *, default: int | None = None, minimum: int | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer", "description": description}
    if default is not None:
        schema["default"] = default
    if minimum is not None:
        schema["minimum"] = minimum
    return schema


def _boolean(description: str, *, default: bool | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "boolean", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _array(description: str, items: dict[str, Any], *, default: list[Any] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "array", "description": description, "items": items}
    if default is not None:
        schema["default"] = default
    return schema


def _string_or_null(description: str) -> dict[str, Any]:
    return {"type": ["string", "null"], "description": description}


def _integer_or_null(description: str) -> dict[str, Any]:
    return {"type": ["integer", "null"], "description": description}


def _enum(description: str, values: list[str], *, default: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "enum": values, "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _output_schema(properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return _object_schema(
        {
            "ok": _boolean("Whether the tool call completed successfully."),
            "error": _string_or_null("Error message when ok is false."),
            **(properties or {}),
        },
        ["ok"],
    )


def _entry_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "path": _string("Path relative to the tool sandbox root."),
            "kind": _string("Entry kind: file or dir."),
            "size": _integer_or_null("File size in bytes, or null for directories."),
        },
        ["path", "kind", "size"],
    )


def _command_output_schema() -> dict[str, Any]:
    return _output_schema(
        {
            "command": _string("Command that was executed."),
            "cwd": _string("Working directory used for the command."),
            "exit_code": _integer_or_null("Process exit code."),
            "output": _string("Combined stdout and stderr output."),
            "session_id": _string_or_null("Background command session id."),
            "status": _string_or_null("Command session status."),
            "backgrounded": _boolean("Whether the command is still running in a background session."),
            "recommendation": _string_or_null("Recommended monitoring follow-up when backgrounded."),
        }
    )


def _browser_base_properties() -> dict[str, Any]:
    return {
        "client_id": _string("Thin-client id."),
        "session_id": _string("Browser session id. If omitted and exactly one browser session is open, that session is used."),
        "browser": _enum("Browser engine to launch for a new session.", ["chromium", "firefox", "webkit"], default="chromium"),
        "width": _integer("Viewport width in CSS pixels.", default=1440, minimum=1),
        "height": _integer("Viewport height in CSS pixels.", default=900, minimum=1),
        "headless": _boolean("Launch browser in headless mode.", default=True),
        "storage_state": _string("Optional workspace-relative Playwright storage state JSON file."),
    }


def _browser_target_properties() -> dict[str, Any]:
    return {
        "selector": _string("CSS selector target."),
        "ref": _string("Reference id returned by thin_client_browser_snapshot."),
        "text": _string("Visible text target."),
        "role": _string("ARIA role target."),
        "name": _string("Accessible name target when role is used."),
        "exact": _boolean("Whether text or role name matching must be exact.", default=True),
    }


def _browser_output_schema() -> dict[str, Any]:
    return _output_schema(
        {
            "client_id": _string("Thin-client id."),
            "session_id": _string_or_null("Browser session id."),
            "browser": _string_or_null("Browser engine."),
            "url": _string_or_null("Current page URL."),
            "title": _string_or_null("Current page title."),
            "artifact_dir": _string_or_null("Workspace-relative browser artifact directory."),
            "screenshot": {"type": ["object", "null"], "description": "Screenshot metadata when a screenshot was created."},
            "trace": {"type": ["object", "null"], "description": "Trace metadata when a trace was stopped."},
            "nodes": _array("Accessibility-oriented page snapshot nodes.", {"type": "object"}),
            "console": _array("Captured browser console entries.", {"type": "object"}),
            "network": _array("Captured failed requests and HTTP error responses.", {"type": "object"}),
            "verdict": _string_or_null("Local visual assertion verdict."),
        }
    )


def _browser_tools() -> list[dict[str, Any]]:
    base = _browser_base_properties()
    target = _browser_target_properties()
    return [
        _tool(
            "thin_client_browser_open_session",
            "Open a Playwright browser session inside an online thin client's launch directory.",
            _object_schema(base, ["client_id"]),
            _annotations(title="Open thin-client browser", read_only=False, destructive=False, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_goto",
            "Navigate a thin-client Playwright browser session to an allowlisted local or configured URL.",
            _object_schema(
                {
                    **base,
                    "url": _string("URL to open in the browser."),
                    "wait_until": _enum("Playwright navigation wait condition.", ["commit", "domcontentloaded", "load", "networkidle"], default="networkidle"),
                    "timeout_ms": _integer("Navigation timeout in milliseconds.", default=30000, minimum=1),
                },
                ["client_id", "url"],
            ),
            _annotations(title="Navigate thin-client browser", read_only=False, destructive=False, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_snapshot",
            "Return an accessibility-oriented snapshot of visible interactive and semantic page elements with stable refs for follow-up actions.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum number of visible nodes to return.", default=150, minimum=1)}, ["client_id"]),
            _annotations(title="Snapshot thin-client browser", read_only=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_click",
            "Click a browser target by CSS selector, snapshot ref, visible text, or role+name.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], **target, "timeout_ms": _integer("Click timeout in milliseconds.", default=10000, minimum=1)}, ["client_id"]),
            _annotations(title="Click thin-client browser", read_only=False, destructive=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_type",
            "Fill or type text into a browser target by CSS selector, snapshot ref, visible text, or role+name.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    **target,
                    "value": _string("Text value to enter."),
                    "clear": _boolean("Whether to replace the existing value instead of typing after it.", default=True),
                    "delay_ms": _integer("Delay between keystrokes when clear=false.", default=0, minimum=0),
                    "timeout_ms": _integer("Typing timeout in milliseconds.", default=10000, minimum=1),
                },
                ["client_id", "value"],
            ),
            _annotations(title="Type into thin-client browser", read_only=False, destructive=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_screenshot",
            "Capture a PNG screenshot and return it as MCP image content when it fits the configured size limit.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    "name": _string("Artifact filename stem or PNG filename."),
                    "full_page": _boolean("Capture the full scrollable page.", default=False),
                },
                ["client_id"],
            ),
            _annotations(title="Screenshot thin-client browser", read_only=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_visual_assert",
            "Capture a screenshot for ChatGPT visual review and attach local console and network diagnostics.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    "assertion": _string("Natural-language visual assertion to evaluate against the screenshot."),
                    "name": _string("Artifact filename stem or PNG filename."),
                    "full_page": _boolean("Capture the full scrollable page.", default=True),
                },
                ["client_id", "assertion"],
            ),
            _annotations(title="Visual assert thin-client browser", read_only=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_console",
            "Return captured browser console and page error entries.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum entries to return.", default=100, minimum=1)}, ["client_id"]),
            _annotations(title="Read thin-client browser console", read_only=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_network",
            "Return captured failed requests and HTTP error responses.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum entries to return.", default=100, minimum=1)}, ["client_id"]),
            _annotations(title="Read thin-client browser network", read_only=True, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_start_trace",
            "Start Playwright tracing for the browser context.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"]}, ["client_id"]),
            _annotations(title="Start thin-client browser trace", read_only=False, destructive=False, idempotent=True, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_stop_trace",
            "Stop Playwright tracing and save a trace.zip artifact.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "name": _string("Trace artifact filename stem or zip filename.")}, ["client_id"]),
            _annotations(title="Stop thin-client browser trace", read_only=True, destructive=False, idempotent=False, open_world=True),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_close_session",
            "Close one browser session or all thin-client browser sessions when session_id is omitted.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"]}, ["client_id"]),
            _annotations(title="Close thin-client browser", read_only=False, destructive=False, idempotent=True, open_world=False),
            output_schema=_browser_output_schema(),
        ),
    ]


SECRET_ARGUMENT_NAMES = {
    "access_token",
    "access_tokens",
    "accesstoken",
    "accesstokens",
    "api_key",
    "apikey",
    "auth_token",
    "authorization",
    "bearer",
    "gitlab_token",
    "github_token",
    "password",
    "private_key",
    "secret",
    "token",
}

SECRET_ARGUMENT_NOTE = " Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments."


def _annotations(
    *,
    title: str,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }


def _tool(
    name: str,
    description: str,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{description}{SECRET_ARGUMENT_NOTE}",
        "inputSchema": input_schema or _object_schema(),
        "outputSchema": output_schema or _output_schema(),
        "annotations": annotations
        or _annotations(title=name.replace("_", " ").title(), read_only=True, idempotent=True, open_world=False),
    }


def _tools() -> list[dict[str, Any]]:
    return [
        _tool(
            "workspace_info",
            "Return the authenticated user's isolated workspace path.",
            annotations=_annotations(title="Workspace info", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "workspace": _string("Absolute server-side workspace path."),
                    "user": _string("Authenticated gateway username."),
                }
            ),
        ),
        _tool(
            "list_resources",
            "List registered SSH devices, Docker workspaces, and thin clients.",
            annotations=_annotations(title="List gateway resources", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "devices": _integer("Number of registered SSH devices."),
                    "docker_workspaces": _integer("Number of registered Docker workspaces."),
                    "thin_clients": _integer("Number of registered thin clients."),
                }
            ),
        ),
        _tool(
            "list_files",
            "List files under a workspace path.",
            _object_schema({"path": _string("Workspace-relative directory path.", default=".")}),
            _annotations(title="List workspace files", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "path": _string("Workspace-relative directory that was listed."),
                    "entries": _array("Directory entries.", _entry_schema()),
                }
            ),
        ),
        _tool(
            "read_file",
            "Read a text file from the workspace.",
            _object_schema({"path": _string("Workspace-relative file path.")}, ["path"]),
            _annotations(title="Read workspace file", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "path": _string("Workspace-relative file path that was read."),
                    "content": _string("UTF-8 decoded file content."),
                    "truncated": _boolean("Whether content was truncated by max_file_read_bytes."),
                }
            ),
        ),
        _tool(
            "write_file",
            "Write a text file into the workspace.",
            _object_schema(
                {
                    "path": _string("Workspace-relative file path."),
                    "content": _string("UTF-8 text content to write."),
                },
                ["path", "content"],
            ),
            _annotations(title="Write workspace file", read_only=False, destructive=True, open_world=False),
            output_schema=_output_schema(
                {
                    "path": _string("Workspace-relative file path that was written."),
                    "bytes": _integer("Number of UTF-8 bytes written."),
                }
            ),
        ),
        _tool(
            "run_cli_command",
            "Run a CLI command inside the workspace.",
            _object_schema(
                {
                    "command": _string("Shell command to run inside the isolated workspace."),
                    "cwd": _string("Workspace-relative working directory.", default="."),
                    "timeout_seconds": _integer("Optional timeout in seconds.", minimum=1),
                    "background": _boolean("Start immediately as a background monitoring session.", default=False),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["command"],
            ),
            _annotations(title="Run workspace command", read_only=False, destructive=True, open_world=True),
            output_schema=_command_output_schema(),
        ),
        _tool(
            "docker_workspace_exec",
            "Run a command inside a registered Docker workspace container.",
            _object_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "command": _string("Shell command to run inside the container."),
                    "workdir": _string("Container working directory.", default="/workspace"),
                    "timeout_seconds": _integer("Optional timeout in seconds.", minimum=1),
                    "background": _boolean("Start immediately as a background monitoring session.", default=False),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["workspace_id", "command"],
            ),
            _annotations(title="Run Docker workspace command", read_only=False, destructive=True, open_world=True),
            output_schema=_command_output_schema(),
        ),
        _tool(
            "docker_workspace_update",
            "Update a Docker workspace name and optional description.",
            _object_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "name": _string("New display name for the workspace."),
                    "description": _string("Optional human-readable workspace description."),
                },
                ["workspace_id"],
            ),
            _annotations(title="Update Docker workspace metadata", read_only=False, destructive=False, idempotent=True, open_world=False),
            output_schema=_output_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "name": _string("Docker workspace display name."),
                    "description": _string_or_null("Optional Docker workspace description."),
                    "container_name": _string("Docker container name."),
                }
            ),
        ),
        _tool(
            "docker_workspace_stop",
            "Stop a Docker workspace container to save host resources.",
            _object_schema({"workspace_id": _string("Docker workspace id.")}, ["workspace_id"]),
            _annotations(title="Stop Docker workspace", read_only=False, destructive=False, idempotent=True, open_world=False),
            output_schema=_output_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "status": _string("Workspace status after the operation."),
                }
            ),
        ),
        _tool(
            "docker_workspace_start",
            "Start a stopped Docker workspace container.",
            _object_schema({"workspace_id": _string("Docker workspace id.")}, ["workspace_id"]),
            _annotations(title="Start Docker workspace", read_only=False, destructive=False, idempotent=True, open_world=False),
            output_schema=_output_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "status": _string("Workspace status after the operation."),
                }
            ),
        ),
        _tool(
            "docker_workspace_delete",
            "Remove a Docker workspace container and unregister it.",
            _object_schema({"workspace_id": _string("Docker workspace id.")}, ["workspace_id"]),
            _annotations(title="Delete Docker workspace", read_only=False, destructive=True, idempotent=False, open_world=False),
            output_schema=_output_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "deleted": _boolean("Whether the workspace was deleted."),
                    "detail": _string("Docker deletion detail."),
                }
            ),
        ),
        _tool(
            "thin_client_list_files",
            "List files inside an online thin client's launch directory.",
            _object_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative path inside the thin-client sandbox.", default="."),
                },
                ["client_id"],
            ),
            _annotations(title="List thin-client files", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "root": _string("Absolute thin-client sandbox root path."),
                    "entries": _array("Directory entries.", _entry_schema()),
                }
            ),
        ),
        _tool(
            "thin_client_read_file",
            "Read a file inside an online thin client's launch directory.",
            _object_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative file path inside the thin-client sandbox."),
                },
                ["client_id", "path"],
            ),
            _annotations(title="Read thin-client file", read_only=True, idempotent=True),
            output_schema=_output_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative file path that was read."),
                    "content": _string("UTF-8 decoded file content."),
                    "truncated": _boolean("Whether content was truncated by max_read_bytes."),
                }
            ),
        ),
        _tool(
            "thin_client_write_file",
            "Write or edit a file inside an online thin client's launch directory. Supports Aurum-style content/content_base64 writes, append, exact replace, regex replace, and Markdown code-fence removal.",
            _object_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative file path inside the thin-client sandbox."),
                    "operation": _enum(
                        "Write/edit operation to apply.",
                        ["write", "append", "replace", "regex_replace", "remove_markdown_code_blocks"],
                        default="write",
                    ),
                    "content": _string("UTF-8 text content for operation=write or operation=append."),
                    "content_base64": _string("Base64 binary content for operation=write. Alternative to content."),
                    "overwrite": _boolean("Whether operation=write may replace an existing file.", default=True),
                    "mode": _integer("Optional POSIX file mode, for example 420 for 0644."),
                    "old_text": _string("Exact text to replace when operation=replace."),
                    "new_text": _string("Replacement text for operation=replace.", default=""),
                    "pattern": _string("Python regex pattern when operation=regex_replace."),
                    "replacement": _string("Regex replacement when operation=regex_replace.", default=""),
                    "count": _integer("Maximum replacements; 0 means replace all.", default=0, minimum=0),
                    "flags": _array(
                        "Regex flags for operation=regex_replace.",
                        {"type": "string", "enum": ["ignorecase", "multiline", "dotall"]},
                        default=[],
                    ),
                    "language": _string("Optional Markdown code fence language filter for operation=remove_markdown_code_blocks."),
                    "expected_replacements": _integer("Optional exact replacement count guard.", minimum=0),
                },
                ["client_id", "path"],
            ),
            _annotations(title="Write thin-client file", read_only=False, destructive=True, open_world=False),
            output_schema=_output_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative file path that was written."),
                    "operation": _string("Operation that was applied."),
                    "bytes": _integer("Number of bytes written or changed."),
                    "bytes_before": _integer("File size before the operation."),
                    "bytes_after": _integer("File size after the operation."),
                    "encoding": _string_or_null("Content encoding used by the write operation."),
                    "replacements": _integer("Number of replacements applied for edit operations."),
                    "content": _string_or_null("Edited UTF-8 content for text edit operations."),
                }
            ),
        ),
        _tool(
            "thin_client_run_command",
            "Run any shell command inside an online thin client's launch directory. The working directory is constrained to the launch directory, but the command is executed by the host shell.",
            _object_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "command": _string("Shell command to run inside the thin-client sandbox."),
                    "cwd": _string("Directory-relative working directory inside the sandbox.", default="."),
                    "timeout_seconds": _integer("Optional timeout in seconds.", minimum=1),
                    "background": _boolean("Start immediately as a background monitoring session.", default=False),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["client_id", "command"],
            ),
            _annotations(title="Run thin-client command", read_only=False, destructive=True, open_world=True),
            output_schema=_command_output_schema(),
        ),
        *_browser_tools(),
        _tool(
            "monitoring_list_sessions",
            "List command monitoring sessions.",
            _object_schema({"status": _string("Optional session status filter.")}),
            _annotations(title="List command sessions", read_only=True, idempotent=True),
            output_schema=_output_schema({"sessions": _array("Command sessions.", {"type": "object"})}),
        ),
        _tool(
            "monitoring_get_session",
            "Get one command monitoring session.",
            _object_schema({"session_id": _string("Command session id.")}, ["session_id"]),
            _annotations(title="Get command session", read_only=True, idempotent=True),
            output_schema=_output_schema({"session": {"type": "object"}}),
        ),
        _tool(
            "monitoring_read_output",
            "Read a sliding output window for a command monitoring session.",
            _object_schema(
                {
                    "session_id": _string("Command session id."),
                    "start_line": _integer("First 1-based line to read.", minimum=1),
                    "limit": _integer("Maximum lines to return.", default=200, minimum=1),
                    "tail": _integer("Read the last N lines instead of start_line.", minimum=1),
                },
                ["session_id"],
            ),
            _annotations(title="Read command output", read_only=True, idempotent=True),
            output_schema=_output_schema({"output": {"type": "object"}}),
        ),
        _tool(
            "monitoring_terminate_session",
            "Terminate a running command monitoring session.",
            _object_schema(
                {
                    "session_id": _string("Command session id."),
                    "force": _boolean("Force-kill instead of graceful termination.", default=False),
                },
                ["session_id"],
            ),
            _annotations(title="Terminate command session", read_only=False, destructive=True, open_world=False),
            output_schema=_output_schema({"session": {"type": "object"}}),
        ),
    ]


def _tool_by_name(name: str) -> dict[str, Any] | None:
    for tool in _tools():
        if tool["name"] == name:
            return tool
    return None


def _normalized_arg_name(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum() or char == "_")


def _validate_tool_arguments(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(args, dict):
        raise HTTPException(status_code=400, detail="Tool arguments must be an object")
    tool = _tool_by_name(name)
    if tool is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
    schema = tool.get("inputSchema") or {}
    properties = set((schema.get("properties") or {}).keys())
    required = set(schema.get("required") or [])
    unknown = sorted(set(args.keys()) - properties)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unsupported tool argument: {unknown[0]}")
    missing = sorted(required - set(args.keys()))
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required tool argument: {missing[0]}")
    for key in args:
        if _normalized_arg_name(key) in SECRET_ARGUMENT_NAMES:
            raise HTTPException(status_code=400, detail="Secret-like tool arguments are not accepted")
    return args


def _bounded_timeout(raw_value: Any, settings: Settings) -> int:
    try:
        timeout_seconds = int(raw_value or settings.max_command_timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="timeout_seconds must be an integer") from exc
    return max(1, min(timeout_seconds, settings.max_command_timeout_seconds))


def _relative_or_dot(root: Path, target: Path) -> str:
    return "." if target == root else str(target.relative_to(root))


def _result(data: dict[str, Any], *, is_error: bool = False, extra_content: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    structured = {"ok": not is_error, "error": None if not is_error else str(data.get("error") or "Tool call failed"), **data}
    if not is_error:
        structured["error"] = None
    return {
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}, *(extra_content or [])],
        "structuredContent": structured,
        "isError": is_error,
    }


def _refresh_result_content(result: dict[str, Any]) -> dict[str, Any]:
    structured = result.get("structuredContent") or {}
    preserved = [item for item in result.get("content", []) if isinstance(item, dict) and item.get("type") != "text"]
    result["content"] = [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}, *preserved]
    return result


def _command_result(
    *,
    command: str,
    cwd: str,
    run_result: Any,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        **(extra or {}),
        "command": command,
        "cwd": cwd,
        "exit_code": run_result.exit_code,
        "output": run_result.output,
        "session_id": run_result.session_id,
        "status": run_result.status,
        "backgrounded": run_result.backgrounded,
        "recommendation": run_result.recommendation,
    }
    return _result(payload, is_error=(run_result.exit_code is not None and run_result.exit_code != 0))


def _session_payload(session: CommandSession) -> dict[str, Any]:
    return {
        "session_id": session.id,
        "origin": session.origin,
        "resource_id": session.resource_id,
        "name": session.name,
        "command": session.command,
        "cwd": session.cwd,
        "status": session.status,
        "pid": session.pid,
        "exit_code": session.exit_code,
        "line_count": session.line_count,
        "truncated": session.truncated,
        "created_at": session.created_at.isoformat(),
        "started_at": session.started_at.isoformat(),
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        "updated_at": session.updated_at.isoformat(),
    }


@router.get("/mcp")
async def mcp_info(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {"name": settings.app_name, "transport": "http-json-rpc", "tools": [tool["name"] for tool in _tools()]}


@router.post("/mcp")
async def mcp(
    request: Request,
    user: User = Depends(get_bearer_or_dev_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    body = await request.json()
    method = body.get("method")
    request_id = body.get("id")
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": settings.app_name, "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": _tools()}
        elif method == "tools/call":
            params = body.get("params") or {}
            name = str(params.get("name") or "")
            arguments = _validate_tool_arguments(name, params.get("arguments") or {})
            tool_call = monitoring_service.create_tool_call(db, owner_subject=user.subject, tool_name=name, arguments=arguments)
            try:
                result = await _call_tool(name, arguments, user, db, settings, tool_call_id=tool_call.id)
                structured = result.get("structuredContent") or {}
                session_id = structured.get("session_id")
                monitoring_service.finish_tool_call(
                    db,
                    call=tool_call,
                    status="error" if result.get("isError") else "success",
                    session_id=str(session_id) if session_id else None,
                    error=str(structured.get("error")) if result.get("isError") else None,
                )
                structured["background_session_tails"] = monitoring_service.background_tails(
                    db,
                    owner_subject=user.subject,
                    tool_call_id=tool_call.id,
                )
                result["structuredContent"] = structured
                result = _refresh_result_content(result)
            except HTTPException as exc:
                monitoring_service.finish_tool_call(db, call=tool_call, status="error", error=str(exc.detail))
                raise
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported JSON-RPC method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except HTTPException as exc:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": exc.status_code, "message": str(exc.detail)}}


async def _call_tool(name: str, args: dict[str, Any], user: User, db: Session, settings: Settings, tool_call_id: str | None = None) -> dict[str, Any]:
    if name == "workspace_info":
        path = _workspace(user, settings)
        return _result({"workspace": str(path), "user": user.username})
    if name == "list_resources":
        devices = db.query(Device).filter(Device.owner_subject == user.subject).count()
        workspaces = db.query(DockerWorkspace).filter(DockerWorkspace.owner_subject == user.subject).count()
        thin_clients = db.query(ThinClient).filter(ThinClient.owner_subject == user.subject).count()
        return _result({"devices": devices, "docker_workspaces": workspaces, "thin_clients": thin_clients})
    if name == "monitoring_list_sessions":
        query = db.query(CommandSession).filter(CommandSession.owner_subject == user.subject).order_by(CommandSession.updated_at.desc())
        if args.get("status"):
            query = query.filter(CommandSession.status == str(args.get("status")))
        sessions = [_session_payload(session) for session in query.limit(20).all()]
        return _result({"sessions": sessions})
    if name == "monitoring_get_session":
        session = db.get(CommandSession, str(args.get("session_id", "")))
        if session is None or session.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Command session not found")
        return _result({"session": _session_payload(session)})
    if name == "monitoring_read_output":
        session = db.get(CommandSession, str(args.get("session_id", "")))
        if session is None or session.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Command session not found")
        output = monitoring_service.output_window(
            db,
            session=session,
            start_line=int(args["start_line"]) if args.get("start_line") is not None else None,
            limit=int(args["limit"]) if args.get("limit") is not None else None,
            tail=int(args["tail"]) if args.get("tail") is not None else None,
            owner_subject=user.subject,
            reason="explicit_read",
            tool_call_id=tool_call_id,
        )
        return _result({"output": output})
    if name == "monitoring_terminate_session":
        session = db.get(CommandSession, str(args.get("session_id", "")))
        if session is None or session.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Command session not found")
        if session.origin == "thin_client" and session.resource_id:
            try:
                await thin_client_manager.request(
                    session.resource_id,
                    tool="terminate_session",
                    arguments={"session_id": session.id, "force": bool(args.get("force", False))},
                    timeout_seconds=10,
                )
            except HTTPException as exc:
                monitoring_service.finish_session(
                    session.id,
                    status_value="lost",
                    exit_code=None,
                    meta={"terminate_error": str(exc.detail)},
                )
                db.expire_all()
                session = db.get(CommandSession, session.id)
                if session is None:
                    raise HTTPException(status_code=404, detail="Command session not found") from exc
                return _result({"session": _session_payload(session)})
        session = await monitoring_service.terminate(db, session=session, force=bool(args.get("force", False)))
        return _result({"session": _session_payload(session)})
    if name == "list_files":
        root = _workspace(user, settings)
        target = _safe_path(user, settings, str(args.get("path", ".")))
        if not target.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        entries = []
        for child in sorted(target.iterdir()):
            entries.append({"path": str(child.relative_to(root)), "kind": "dir" if child.is_dir() else "file", "size": child.stat().st_size if child.is_file() else None})
        return _result({"path": _relative_or_dot(root, target), "entries": entries})
    if name == "read_file":
        root = _workspace(user, settings)
        target = _safe_path(user, settings, str(args.get("path", ".")))
        if not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        data = target.read_bytes()[: settings.max_file_read_bytes]
        return _result(
            {
                "path": _relative_or_dot(root, target),
                "content": data.decode("utf-8", errors="replace"),
                "truncated": target.stat().st_size > len(data),
            }
        )
    if name == "write_file":
        root = _workspace(user, settings)
        target = _safe_path(user, settings, str(args.get("path", ".")))
        text = str(args.get("content", ""))
        raw = text.encode("utf-8")
        if len(raw) > settings.max_file_write_bytes:
            raise HTTPException(status_code=413, detail="File content is too large")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return _result({"path": _relative_or_dot(root, target), "bytes": len(raw)})
    if name == "run_cli_command":
        command = str(args.get("command", ""))
        cwd = _safe_path(user, settings, str(args.get("cwd", ".")))
        run_result = await monitoring_service.run_local_command(
            db,
            owner_subject=user.subject,
            origin="server",
            resource_id=None,
            command=command,
            cwd=str(cwd),
            args=command,
            settings=settings,
            background=bool(args.get("background", False)),
            session_name=str(args.get("session_name") or "") or None,
        )
        return _command_result(
            command=command,
            cwd=_relative_or_dot(_workspace(user, settings), cwd),
            run_result=run_result,
        )
    if name == "docker_workspace_exec":
        workspace = db.get(DockerWorkspace, str(args.get("workspace_id", "")))
        if workspace is None or workspace.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Workspace not found")
        if not settings.gateway_docker_enabled:
            raise HTTPException(status_code=400, detail="Docker execution disabled")
        if not workspace.container_id:
            raise HTTPException(status_code=400, detail="Workspace has no container_id")
        command = str(args.get("command", ""))
        workdir = str(args.get("workdir", "/workspace"))
        run_result = await monitoring_service.run_local_command(
            db,
            owner_subject=user.subject,
            origin="docker",
            resource_id=workspace.id,
            command=command,
            cwd=workdir,
            args=["docker", "exec", "-w", workdir, workspace.container_id, "sh", "-lc", command],
            settings=settings,
            background=bool(args.get("background", False)),
            session_name=str(args.get("session_name") or "") or None,
            meta={"container_id": workspace.container_id, "workspace_id": workspace.id},
        )
        return _command_result(
            command=command,
            cwd=workdir,
            run_result=run_result,
            extra={"workspace_id": workspace.id, "workdir": workdir},
        )
    if name == "docker_workspace_update":
        workspace = db.get(DockerWorkspace, str(args.get("workspace_id", "")))
        if workspace is None or workspace.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Workspace not found")
        meta = dict(workspace.meta or {})
        detail = meta.get("detail")
        if "name" in args and args.get("name") is not None:
            new_name = str(args.get("name", "")).strip()
            if not new_name:
                raise HTTPException(status_code=400, detail="Workspace name must not be empty")
            if new_name != workspace.name:
                new_container_name = safe_container_name(f"gw-{user.username}-{new_name}-{workspace.id[:8]}")
                if new_container_name != workspace.container_name:
                    detail = DockerAdapter(settings).rename_workspace(
                        container_id=workspace.container_id,
                        new_container_name=new_container_name,
                    )
                    workspace.container_name = new_container_name
                workspace.name = new_name
        if "description" in args:
            description = str(args.get("description") or "").strip()
            if description:
                meta["description"] = description
            else:
                meta.pop("description", None)
        if detail:
            meta["detail"] = detail
        workspace.meta = meta
        workspace.updated_at = utcnow()
        db.commit()
        db.refresh(workspace)
        emit_event(
            db,
            event_type="gateway.workspace.changed.v1",
            actor_subject=user.subject,
            action="updated",
            resource_type="docker_workspace",
            resource_id=workspace.id,
            payload={
                "workspace_id": workspace.id,
                "container_id": workspace.container_id,
                "container_name": workspace.container_name,
                "description_set": workspace.description is not None,
            },
        )
        return _result(
            {
                "workspace_id": workspace.id,
                "name": workspace.name,
                "description": workspace.description,
                "container_name": workspace.container_name,
            }
        )
    if name in {"docker_workspace_stop", "docker_workspace_start", "docker_workspace_delete"}:
        workspace = db.get(DockerWorkspace, str(args.get("workspace_id", "")))
        if workspace is None or workspace.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Workspace not found")
        adapter = DockerAdapter(settings)
        if name == "docker_workspace_delete":
            container_id = workspace.container_id
            container_name = workspace.container_name
            detail = adapter.remove_workspace(container_id=container_id)
            db.delete(workspace)
            db.commit()
            emit_event(
                db,
                event_type="gateway.workspace.changed.v1",
                actor_subject=user.subject,
                action="deleted",
                resource_type="docker_workspace",
                resource_id=str(args.get("workspace_id", "")),
                payload={"workspace_id": str(args.get("workspace_id", "")), "container_id": container_id, "container_name": container_name, "detail": detail},
            )
            return _result({"workspace_id": str(args.get("workspace_id", "")), "deleted": True, "detail": detail})
        if name == "docker_workspace_stop":
            result = adapter.stop_workspace(container_id=workspace.container_id)
            action = "stopped"
        else:
            result = adapter.start_workspace(container_id=workspace.container_id)
            action = "started"
        workspace.status = result.status
        workspace.meta = {**(workspace.meta or {}), "detail": result.detail}
        workspace.updated_at = utcnow()
        db.commit()
        db.refresh(workspace)
        emit_event(
            db,
            event_type="gateway.workspace.changed.v1",
            actor_subject=user.subject,
            action=action,
            resource_type="docker_workspace",
            resource_id=workspace.id,
            payload={"workspace_id": workspace.id, "container_id": workspace.container_id, "status": workspace.status},
        )
        return _result({"workspace_id": workspace.id, "status": workspace.status})
    if name.startswith("thin_client_"):
        client = db.get(ThinClient, str(args.get("client_id", "")))
        if client is None or client.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Thin client not found")
        tool = name.removeprefix("thin_client_")
        if tool == "list_files":
            arguments = {"path": args.get("path", ".")}
        elif tool == "read_file":
            arguments = {"path": args.get("path", "")}
        elif tool == "write_file":
            arguments = {key: value for key, value in args.items() if key != "client_id"}
        elif tool.startswith("browser_"):
            arguments = {key: value for key, value in args.items() if key != "client_id"}
        elif tool == "run_command":
            timeout_seconds = _bounded_timeout(args.get("timeout_seconds"), settings)
            session = monitoring_service.create_session(
                db,
                owner_subject=user.subject,
                origin="thin_client",
                resource_id=client.id,
                command=str(args.get("command", "")),
                cwd=str(args.get("cwd", ".")),
                name=str(args.get("session_name") or "") or None,
                settings=settings,
                meta={"client_id": client.id, "hostname": client.hostname, "directory": client.directory},
            )
            arguments = {
                "session_id": session.id,
                "command": args.get("command", ""),
                "cwd": args.get("cwd", "."),
                "timeout_seconds": timeout_seconds,
            }
        else:
            raise HTTPException(status_code=404, detail=f"Unknown thin-client tool: {tool}")
        timeout_seconds = _bounded_timeout(args.get("timeout_seconds"), settings)
        if tool == "run_command":
            arguments["timeout_seconds"] = timeout_seconds
        response = await thin_client_manager.request(
            client.id,
            tool="run_monitored_command" if tool == "run_command" else tool,
            arguments=arguments,
            timeout_seconds=10 if tool == "run_command" else timeout_seconds,
        )
        if not response.get("ok"):
            if tool == "run_command":
                monitoring_service.finish_session(
                    str(arguments["session_id"]),
                    status_value="failed",
                    exit_code=None,
                    meta={"error": str(response.get("error") or "Thin client tool failed")},
                )
            return _result({"client_id": client.id, "error": str(response.get("error") or "Thin client tool failed")}, is_error=True)
        result = response.get("result")
        if not isinstance(result, dict):
            result = {"output": str(result)}
        if tool == "list_files":
            structured = {
                "client_id": client.id,
                "root": str(result.get("root", client.directory)),
                "entries": list(result.get("entries") or []),
            }
        elif tool == "read_file":
            structured = {
                "client_id": client.id,
                "path": str(result.get("path", args.get("path", ""))),
                "content": str(result.get("content", "")),
                "truncated": bool(result.get("truncated", False)),
            }
        elif tool == "write_file":
            structured = {
                "client_id": client.id,
                "path": str(result.get("path", args.get("path", ""))),
                "operation": str(result.get("operation", args.get("operation", "write"))),
                "bytes": int(result.get("bytes", 0)),
                "bytes_before": int(result.get("bytes_before", 0)),
                "bytes_after": int(result.get("bytes_after", result.get("bytes", 0))),
                "encoding": result.get("encoding"),
                "replacements": int(result.get("replacements", 0)),
                "content": result.get("content"),
            }
        elif tool.startswith("browser_"):
            result_payload = dict(result)
            image_base64 = result_payload.pop("image_base64", None)
            mime_type = str(result_payload.pop("mime_type", "image/png") or "image/png")
            structured = {"client_id": client.id, **result_payload}
            extra_content = []
            if image_base64:
                extra_content.append({"type": "image", "data": str(image_base64), "mimeType": mime_type})
            return _result(structured, extra_content=extra_content)
        else:
            run_result = await monitoring_service.wait_for_existing_session(
                db,
                session_id=str(arguments["session_id"]),
                settings=settings,
                background=bool(args.get("background", False)),
            )
            return _command_result(
                command=str(args.get("command", "")),
                cwd=str(args.get("cwd", ".")),
                run_result=run_result,
                extra={"client_id": client.id},
            )
        return _result(structured)
    raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
