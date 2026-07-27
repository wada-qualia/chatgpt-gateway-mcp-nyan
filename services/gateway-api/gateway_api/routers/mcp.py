from __future__ import annotations

import asyncio
import hashlib
import json
import re
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..account_settings import effective_ssh_command_profile, raw_ssh_commands_enabled
from ..adapters.docker import DockerAdapter, safe_container_name
from ..adapters.ssh import (
    load_device_credentials,
    run_ssh_command,
    verify_ssh_connection,
)
from ..agent_autonomy_tools import (
    agent_autonomy_tool_names,
    agent_autonomy_tools,
    call_agent_autonomy_tool,
)
from ..agent_collaboration_tools import (
    agent_collaboration_tool_names,
    agent_collaboration_tools,
    call_agent_collaboration_tool,
)
from ..mcp_deferred_native import (
    deferred_entries_for_context,
    deferred_native_dispatch_target,
    deferred_native_tool_definition,
    resolve_deferred_dispatch,
)
from ..mcp_federation_broker import (
    call_mcp_federation_broker_tool,
    mcp_federation_broker_tool_names,
    mcp_federation_broker_tools,
)
from ..mcp_federation_compat import (
    McpProtocolAdmissionError,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
    gateway_public_server_capabilities,
    negotiate_gateway_protocol_version,
    validate_http_protocol_version,
)
from ..mcp_presentation import (
    PresentationContext,
    native_tool_definition,
    projection_entries_for_context,
    resolve_presentation_context,
)
from ..mcp_tool_registry import ToolDispatchTarget, ToolRegistry
from ..mcp_upstream import UpstreamMcpError, UpstreamMcpManager
from ..agent_coordination import WriteLeaseContext, agent_coordination_service
from ..agent_coordination_tools import (
    agent_coordination_tool_names,
    agent_coordination_tools,
    call_agent_coordination_tool,
)
from ..auth import get_bearer_or_dev_user
from ..config import Settings, get_settings
from ..database import get_db
from ..events import emit_event
from ..models import (
    CommandSession,
    Device,
    DockerWorkspace,
    FileChangeSet,
    McpProjectionGeneration,
    McpProjectionTool,
    McpServer,
    McpToolExposure,
    ThinClient,
    User,
    utcnow,
)
from ..monitoring import CommandRunResult, monitoring_service
from ..policy import enforce
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


def _local_git_state(worktree: Path, base_commit: str) -> dict[str, Any]:
    if not worktree.is_dir():
        raise HTTPException(status_code=409, detail="Lease worktree path is not a directory")

    def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", "-C", str(worktree), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if check and completed.returncode != 0:
            raise HTTPException(status_code=409, detail="Lease worktree is not a valid Git worktree")
        return completed

    toplevel = Path(git("rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if toplevel != worktree.resolve():
        raise HTTPException(status_code=409, detail="Lease worktree path is not the Git worktree root")
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    head = git("rev-parse", "HEAD").stdout.strip()
    ancestor = git("merge-base", "--is-ancestor", base_commit, head, check=False).returncode == 0
    return {"branch_name": branch, "head": head, "base_commit": base_commit, "base_is_ancestor": ancestor}


def _validate_write_git_state(state: dict[str, Any], context: WriteLeaseContext) -> None:
    if str(state.get("branch_name") or "") != context.branch_name:
        raise HTTPException(status_code=409, detail="Lease worktree branch does not match branch_name")
    head = str(state.get("head") or "")
    if not head:
        raise HTTPException(status_code=409, detail="Lease worktree HEAD is unavailable")
    if context.expected_head and head != context.expected_head:
        raise HTTPException(status_code=409, detail="Lease worktree HEAD is stale")
    if str(state.get("base_commit") or "") != context.base_commit or not bool(state.get("base_is_ancestor")):
        raise HTTPException(status_code=409, detail="Lease base commit is not an ancestor of worktree HEAD")


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
    schema: dict[str, Any] = {"type": "array", "description": description, "items": items,
    }
    if default is not None:
        schema["default"] = default
    return schema


def _string_or_null(description: str) -> dict[str, Any]:
    return {"type": ["string", "null"], "description": description}


def _integer_or_null(description: str) -> dict[str, Any]:
    return {"type": ["integer", "null"], "description": description}


def _enum(description: str, values: list[str], *, default: str | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "enum": values, "description": description,
    }
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


def _ssh_device_resource_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "device_id": _string("SSH device id accepted by ssh_device_* tools."),
            "name": _string("User-visible SSH device name."),
            "host": _string("SSH host name or address."),
            "port": _integer("SSH port."),
            "username": _string("Remote SSH username."),
            "auth_type": _string("Configured backend-side authentication type."),
            "status": _string("Current recorded SSH device status."),
        },
        ["device_id", "name", "host", "port", "username", "auth_type", "status"],
    )


def _docker_workspace_resource_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "workspace_id": _string("Docker workspace id accepted by docker_workspace_* tools."),
            "name": _string("User-visible Docker workspace name."),
            "description": _string_or_null("Optional Docker workspace description."),
            "image": _string("Configured container image."),
            "status": _string("Current recorded Docker workspace status."),
        },
        ["workspace_id", "name", "description", "image", "status"],
    )


def _thin_client_resource_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "client_id": _string("Thin-client id accepted by thin_client_* tools."),
            "hostname": _string("Thin-client host name."),
            "directory": _string("Registered thin-client launch directory."),
            "status": _string("Current recorded thin-client status."),
            "connected": _boolean("Whether the gateway currently has a live thin-client connection."),
            "last_seen_at": _string("Last recorded thin-client activity timestamp."),
        },
        ["client_id", "hostname", "directory", "status", "connected", "last_seen_at"],
    )


def _diff_line_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "kind": _enum("Diff line kind.", ["context", "delete", "insert"]),
            "text": _string("Line text without newline terminator."),
        },
        ["kind", "text"],
    )


def _diff_hunk_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "old_start": _integer("1-based start line in the original file."),
            "old_count": _integer("Number of original lines covered by the hunk."),
            "new_start": _integer("1-based start line in the edited file."),
            "new_count": _integer("Number of edited lines covered by the hunk."),
            "lines": _array("Diff lines in this hunk.", _diff_line_schema()),
        },
        ["old_start", "old_count", "new_start", "new_count", "lines"],
    )


def _diff_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "format": _string("Diff format identifier, currently unified."),
            "suppressed": _boolean("Whether inline diff content was intentionally omitted."),
            "reason": _string_or_null("Suppression reason when suppressed is true."),
            "truncated": _boolean("Whether hunks were truncated by max_diff_lines."),
            "added_lines": _integer("Number of inserted lines included in the diff."),
            "removed_lines": _integer("Number of deleted lines included in the diff."),
            "hunks": _array("Structured diff hunks.", _diff_hunk_schema()),
        },
        ["format", "suppressed", "truncated", "added_lines", "removed_lines", "hunks"],
    )


def _write_guard_schema_properties() -> dict[str, Any]:
    return {
        "room_id": _string("Collaboration room id for a guarded write."),
        "agent_id": _string("Agent instance id holding the write lease."),
        "lease_id": _string("Active resource lease id."),
        "fencing_token": _integer(
            "Monotonic fencing token issued with the lease.", minimum=1
        ),
        "expected_sha256": _string("Expected full SHA-256 of an existing file."),
        "expected_absent": _boolean(
            "Require the path to be absent before writing.", default=False
        ),
        "base_commit": _string("Lease base commit."),
        "branch_name": _string("Lease-owned branch name."),
        "worktree_path": _string("Lease-owned worktree path."),
    }


def _file_change_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "id": _string("File change id."),
            "origin": _string("Origin resource type, for example thin_client."),
            "resource_id": _string_or_null("Origin resource id."),
            "tool_call_id": _string_or_null("MCP tool call id that produced the change."),
            "room_id": _string_or_null(
                "Collaboration room id associated with the guarded write."
            ),
            "agent_id": _string_or_null("Agent instance id that held the write lease."),
            "lease_id": _string_or_null("Resource lease id that authorized the write."),
            "fencing_token": _integer_or_null(
                "Monotonic fencing token used by the write."
            ),
            "path": _string("Changed file path relative to origin workspace."),
            "operation": _string("Write/edit operation that was applied."),
            "before_sha256": _string_or_null("Full file SHA-256 before the write."),
            "after_sha256": _string_or_null("Full file SHA-256 after the write."),
            "base_commit": _string_or_null("Lease base commit."),
            "branch_name": _string_or_null("Lease-owned branch name."),
            "worktree_path": _string_or_null("Lease-owned worktree path."),
            "added_lines": _integer("Inserted lines included in the diff."),
            "removed_lines": _integer("Deleted lines included in the diff."),
            "bytes_before": _integer("File size before the operation."),
            "bytes_after": _integer("File size after the operation."),
            "replacements": _integer("Replacement count for edit operations."),
            "truncated": _boolean("Whether the diff was truncated."),
            "suppressed": _boolean("Whether inline diff content was suppressed."),
            "diff": _diff_schema(),
            "created_at": _string("Creation timestamp."),
        },
        ["id", "origin", "path", "operation", "added_lines", "removed_lines", "bytes_before", "bytes_after", "replacements", "truncated", "suppressed", "diff", "created_at",
        ],
    )


def _file_change_payload(change: FileChangeSet) -> dict[str, Any]:
    return {
        "id": change.id,
        "origin": change.origin,
        "resource_id": change.resource_id,
        "tool_call_id": change.tool_call_id,
        "room_id": change.room_id,
        "agent_id": change.agent_id,
        "lease_id": change.lease_id,
        "fencing_token": change.fencing_token,
        "path": change.path,
        "operation": change.operation,
        "before_sha256": change.before_sha256,
        "after_sha256": change.after_sha256,
        "base_commit": change.base_commit,
        "branch_name": change.branch_name,
        "worktree_path": change.worktree_path,
        "added_lines": change.added_lines,
        "removed_lines": change.removed_lines,
        "bytes_before": change.bytes_before,
        "bytes_after": change.bytes_after,
        "replacements": change.replacements,
        "truncated": change.truncated,
        "suppressed": change.suppressed,
        "diff": change.diff_json,
        "created_at": change.created_at.isoformat(),
    }


def _persist_file_change(
    db: Session,
    *,
    user: User,
    origin: str,
    resource_id: str | None,
    tool_call_id: str | None,
    structured: dict[str, Any],
    lease_context: WriteLeaseContext | None = None,
) -> FileChangeSet:
    diff = structured.get("diff") if isinstance(structured.get("diff"), dict) else {}
    change = FileChangeSet(
        id=str(uuid.uuid4()),
        owner_subject=user.subject,
        origin=origin,
        resource_id=resource_id,
        tool_call_id=tool_call_id,
        room_id=lease_context.room_id if lease_context else None,
        agent_id=lease_context.agent_id if lease_context else None,
        lease_id=lease_context.lease_id if lease_context else None,
        fencing_token=lease_context.fencing_token if lease_context else None,
        path=str(structured.get("path", "")),
        operation=str(structured.get("operation", "write")),
        before_sha256=str(structured.get("before_sha256"))
        if structured.get("before_sha256")
        else None,
        after_sha256=str(structured.get("after_sha256"))
        if structured.get("after_sha256")
        else None,
        base_commit=lease_context.base_commit if lease_context else None,
        branch_name=lease_context.branch_name if lease_context else None,
        worktree_path=lease_context.worktree_path if lease_context else None,
        added_lines=int(diff.get("added_lines", 0) or 0),
        removed_lines=int(diff.get("removed_lines", 0) or 0),
        bytes_before=int(structured.get("bytes_before", 0) or 0),
        bytes_after=int(structured.get("bytes_after", structured.get("bytes", 0)) or 0),
        replacements=int(structured.get("replacements", 0) or 0),
        diff_json=diff,
        truncated=bool(diff.get("truncated", False)),
        suppressed=bool(diff.get("suppressed", False)),
    )
    db.add(change)
    db.flush()
    db.refresh(change)
    emit_event(
        db,
        event_type="gateway.file_change.created.v1",
        actor_subject=user.subject,
        action="created",
        resource_type="file_change",
        resource_id=change.id,
        payload={
            "origin": change.origin,
            "resource_id": change.resource_id,
            "room_id": change.room_id,
            "agent_id": change.agent_id,
            "lease_id": change.lease_id,
            "fencing_token": change.fencing_token,
            "path": change.path,
            "operation": change.operation,
            "before_sha256": change.before_sha256,
            "after_sha256": change.after_sha256,
            "added_lines": change.added_lines,
            "removed_lines": change.removed_lines,
            "suppressed": change.suppressed,
            "truncated": change.truncated,
        },
        commit=False,
    )
    db.commit()
    return change


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


def _ssh_device_schema() -> dict[str, Any]:
    properties = {
            "device_id": _string("SSH device id."),
            "name": _string("SSH device display name."),
            "host": _string("SSH host name or address."),
            "port": _integer("SSH TCP port."),
            "username": _string("SSH username."),
            "auth_type": _string("Configured SSH authentication type."),
            "status": _string("Current device connection status."),
        }
    return _object_schema(properties, list(properties))


def _ssh_device_output_schema() -> dict[str, Any]:
    return _output_schema(_ssh_device_schema()["properties"])


def _ssh_connection_output_schema() -> dict[str, Any]:
    return _output_schema(
        {
            "device_id": _string("SSH device id."),
            "status": _string("Connection verification status."),
            "detail": _string_or_null("Connection verification detail."),
        }
    )


def _ssh_tools(settings: Settings, ssh_command_profile: str) -> list[dict[str, Any]]:
    if not settings.gateway_ssh_enabled:
        return []
    allowed_actions = settings.ssh_allowed_actions or ["uptime", "disk_usage", "memory_usage", "whoami", "pwd", "home_list",
    ]
    tools = [
        _tool(
            "ssh_device_info",
            "Return safe metadata for a registered SSH device without exposing credentials.",
            _object_schema({"device_id": _string("SSH device id.")}, ["device_id"]),
            _annotations(title="SSH device info", read_only=True, idempotent=True, open_world=False,
            ),
            output_schema=_ssh_device_output_schema(),
        ),
        _tool(
            "ssh_device_check_connection",
            "Verify backend-side SSH authentication for a registered SSH device.",
            _object_schema(
                {
                    "device_id": _string("SSH device id."),
                    "timeout_seconds": _integer("Optional SSH connection timeout in seconds.", default=15, minimum=1,
                    ),
                },
                ["device_id"],
            ),
            _annotations(title="Check SSH connection", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_ssh_connection_output_schema(),
        ),
        _tool(
            "ssh_device_run_action",
            "Run one allowlisted action on a registered SSH device. Actions map to fixed gateway-owned commands.",
            _object_schema(
                {
                    "device_id": _string("SSH device id."),
                    "action": _enum("Allowlisted SSH action to run.", allowed_actions),
                    "timeout_seconds": _integer("Optional SSH command timeout in seconds.", default=30, minimum=1,
                    ),
                    "background": _boolean("Start immediately as a background monitoring session.", default=False,
                    ),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["device_id", "action"],
            ),
            _annotations(title="Run SSH allowlisted action", read_only=False, destructive=True, open_world=True,
            ),
            output_schema=_command_output_schema(),
        ),
        _tool(
            "ssh_device_read_home",
            "List a bounded view of the registered SSH device user's home directory.",
            _object_schema(
                {
                    "device_id": _string("SSH device id."),
                    "timeout_seconds": _integer("Optional SSH command timeout in seconds.", default=30, minimum=1,
                    ),
                },
                ["device_id"],
            ),
            _annotations(title="Read SSH home listing", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_command_output_schema(),
        ),
    ]
    if ssh_command_profile != "restricted":
        tools.append(
            _tool(
                "ssh_device_run_command",
                "Run an arbitrary shell command on a registered SSH device when the effective account SSH command profile is filtered or unrestricted. The unrestricted profile is the deployment default. A command beginning with sudo uses the registered password credential for backend-only privilege authentication without exposing it in tool arguments, command text, monitoring output, or audit payloads.",
                _object_schema(
                    {
                        "device_id": _string("SSH device id."),
                        "command": _string("Raw shell command to run on the SSH device."),
                        "cwd": _string("Remote working directory.", default="~"),
                        "timeout_seconds": _integer("Optional SSH command timeout in seconds.", default=30, minimum=1,
                        ),
                        "background": _boolean("Start immediately as a background monitoring session.", default=False,
                        ),
                        "session_name": _string("Optional display name for the monitoring session."),
                    },
                    ["device_id", "command"],
                ),
                _annotations(title="Run raw SSH command", read_only=False, destructive=True, open_world=True,
                ),
                output_schema=_command_output_schema(),
            )
        )
    return tools


def _browser_base_properties() -> dict[str, Any]:
    return {
        "client_id": _string("Thin-client id."),
        "session_id": _string("Optional page handle. Usually omit it when one page is open."),
        "browser": _enum("Browser engine to launch for a new session.", ["chromium", "firefox", "webkit"], default="chromium",
        ),
        "width": _integer("Viewport width in CSS pixels.", default=1440, minimum=1),
        "height": _integer("Viewport height in CSS pixels.", default=900, minimum=1),
        "headless": _boolean("Launch browser in headless mode.", default=True),
        "storage_state": _string("Optional workspace-relative Playwright storage state JSON file."),
    }


def _browser_target_properties() -> dict[str, Any]:
    return {
        "selector": _string("CSS selector target."),
        "ref": _string("Reference id returned by thin_client_browser_page_state."),
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
            "file_dir": _string_or_null("Workspace-relative browser file directory."),
            "screenshot": {"type": ["object", "null"], "description": "Screenshot metadata when a screenshot was created.",
            },
            "trace": {"type": ["object", "null"], "description": "Trace metadata when a trace export was produced.",
            },
            "nodes": _array("Accessibility-oriented page-state nodes.", {"type": "object"}),
            "request_failures": _array("Failed browser requests and HTTP error responses.", {"type": "object"}),
            "status": _string_or_null("Local page capture status."),
            "note": _string_or_null("Capture note supplied by the caller."),
            "capture": {"type": ["object", "null"], "description": "Local page capture summary.",
            },
            "page_status": {"type": ["object", "null"], "description": "Compact page status summary.",
            },
            "note_count": _integer_or_null("Number of captured page notes."),
            "warning_count": _integer_or_null("Number of captured page warnings."),
            "error_count": _integer_or_null("Number of page failures."),
            "issue_count": _integer_or_null("Number of application failures."),
            "failed_request_count": _integer_or_null("Number of failed requests and HTTP error responses."),
            "detail_file": {"type": ["object", "null"], "description": "Workspace-relative detail file metadata.",
            },
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
            _annotations(title="Open thin-client browser", read_only=False, destructive=False, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_goto",
            "Navigate a thin-client Playwright browser session to an allowlisted local or configured URL.",
            _object_schema(
                {
                    **base,
                    "url": _string("URL to open in the browser."),
                    "wait_until": _enum("Playwright navigation wait condition.", ["commit", "domcontentloaded", "load", "networkidle"], default="networkidle",
                    ),
                    "timeout_ms": _integer("Navigation timeout in milliseconds.", default=30000, minimum=1),
                },
                ["client_id", "url"],
            ),
            _annotations(title="Navigate thin-client browser", read_only=False, destructive=False, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_page_state",
            "Return an accessibility-oriented page state of visible interactive and semantic elements with stable refs for follow-up actions.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum number of visible nodes to return.", default=150, minimum=1,
                    ),
                },
                ["client_id"],
            ),
            _annotations(title="Read thin-client browser page state", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_click",
            "Click a browser target by CSS selector, page-state ref, visible text, or role+name.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], **target, "timeout_ms": _integer("Click timeout in milliseconds.", default=10000, minimum=1),
                },
                ["client_id"],
            ),
            _annotations(title="Click thin-client browser", read_only=False, destructive=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_type",
            "Fill or type text into a browser target by CSS selector, page-state ref, visible text, or role+name.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    **target,
                    "value": _string("Text value to enter."),
                    "clear": _boolean("Whether to replace the existing value instead of typing after it.", default=True,
                    ),
                    "delay_ms": _integer("Delay between keystrokes when clear=false.", default=0, minimum=0,
                    ),
                    "timeout_ms": _integer("Typing timeout in milliseconds.", default=10000, minimum=1),
                },
                ["client_id", "value"],
            ),
            _annotations(title="Type into thin-client browser", read_only=False, destructive=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_screenshot",
            "Capture a PNG screenshot and return it as MCP image content when it fits the configured size limit.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    "name": _string("File filename stem or PNG filename."),
                    "full_page": _boolean("Capture the full scrollable page.", default=False),
                },
                ["client_id"],
            ),
            _annotations(title="Screenshot thin-client browser", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_capture_page",
            "Capture a page image and save details to a file.",
            _object_schema(
                {
                    "client_id": base["client_id"],
                    "session_id": base["session_id"],
                    "note": _string("Optional note for the saved capture."),
                    "name": _string("File filename stem or PNG filename."),
                    "full_page": _boolean("Capture the full scrollable page.", default=True),
                },
                ["client_id", "note"],
            ),
            _annotations(title="Capture browser page", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_page_status",
            "Return compact page status and save details to a file.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum entries to include in the saved file.", default=100, minimum=1,
                    ),
                },
                ["client_id"],
            ),
            _annotations(title="Read browser page status", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_request_failures",
            "Return failed browser requests and HTTP error responses.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "limit": _integer("Maximum entries to return.", default=100, minimum=1),
                },
                ["client_id"],
            ),
            _annotations(title="Read thin-client browser request failures", read_only=True, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_start_trace",
            "Start Playwright tracing for the browser context.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"]}, ["client_id"],
            ),
            _annotations(title="Start thin-client browser trace", read_only=False, destructive=False, idempotent=True, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_trace_export",
            "Export Playwright tracing to a trace.zip file and end the active trace capture.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"], "name": _string("Trace file filename stem or zip filename."),
                },
                ["client_id"],
            ),
            _annotations(title="Export thin-client browser trace", read_only=True, destructive=False, idempotent=False, open_world=True,
            ),
            output_schema=_browser_output_schema(),
        ),
        _tool(
            "thin_client_browser_release_page",
            "Release one browser page, or all browser pages when session_id is omitted.",
            _object_schema({"client_id": base["client_id"], "session_id": base["session_id"]}, ["client_id"],
            ),
            _annotations(title="Release browser page", read_only=False, destructive=False, idempotent=True, open_world=False,
            ),
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
        or _annotations(title=name.replace("_", " ").title(), read_only=True, idempotent=True, open_world=False,
        ),
    }


def _legacy_tools(
    settings: Settings | None = None,
    ssh_command_profile: str | None = None,
) -> list[dict[str, Any]]:
    resolved_settings = settings or get_settings()
    resolved_profile = ssh_command_profile or resolved_settings.ssh_command_profile_default
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
                    "ssh_devices": _array(
                        "Safe metadata for registered SSH devices.",
                        _ssh_device_resource_schema(),
                    ),
                    "docker_workspace_items": _array(
                        "Safe metadata for registered Docker workspaces.",
                        _docker_workspace_resource_schema(),
                    ),
                    "thin_client_items": _array("Safe metadata for registered thin clients.", _thin_client_resource_schema()),
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
                    **_write_guard_schema_properties(),
                },
                ["path", "content"],
            ),
            _annotations(title="Write workspace file", read_only=False, destructive=True, open_world=False,
            ),
            output_schema=_output_schema(
                {
                    "path": _string("Workspace-relative file path that was written."),
                    "bytes": _integer("Number of UTF-8 bytes written."),
                    "before_sha256": _string_or_null(
                        "Full file SHA-256 before the write."
                    ),
                    "after_sha256": _string("Full file SHA-256 after the write."),
                    "file_change_id": _string("Persisted FileChangeSet id."),
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
                    "background": _boolean("Start immediately as a background monitoring session.", default=False,
                    ),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["command"],
            ),
            _annotations(title="Run workspace command", read_only=False, destructive=True, open_world=True,
            ),
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
                    "background": _boolean("Start immediately as a background monitoring session.", default=False,
                    ),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["workspace_id", "command"],
            ),
            _annotations(title="Run Docker workspace command", read_only=False, destructive=True, open_world=True,
            ),
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
            _annotations(title="Update Docker workspace metadata", read_only=False, destructive=False, idempotent=True, open_world=False,
            ),
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
            _annotations(title="Stop Docker workspace", read_only=False, destructive=False, idempotent=True, open_world=False,
            ),
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
            _annotations(title="Start Docker workspace", read_only=False, destructive=False, idempotent=True, open_world=False,
            ),
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
            _annotations(title="Delete Docker workspace", read_only=False, destructive=True, idempotent=False, open_world=False,
            ),
            output_schema=_output_schema(
                {
                    "workspace_id": _string("Docker workspace id."),
                    "deleted": _boolean("Whether the workspace was deleted."),
                    "detail": _string("Docker deletion detail."),
                }
            ),
        ),
        *_ssh_tools(resolved_settings, resolved_profile),
        _tool(
            "thin_client_list_files",
            "List files inside an online thin client's launch directory.",
            _object_schema(
                {
                    "client_id": _string("Thin-client id."),
                    "path": _string("Directory-relative path inside the thin-client sandbox.", default=".",
                    ),
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
                        ["write", "append", "replace", "regex_replace", "remove_markdown_code_blocks",
                        ],
                        default="write",
                    ),
                    "content": _string("UTF-8 text content for operation=write or operation=append."),
                    "content_base64": _string("Base64 binary content for operation=write. Alternative to content."),
                    "overwrite": _boolean("Whether operation=write may replace an existing file.", default=True,
                    ),
                    "mode": _integer("Optional POSIX file mode, for example 420 for 0644."),
                    "old_text": _string("Exact text to replace when operation=replace."),
                    "new_text": _string("Replacement text for operation=replace.", default=""),
                    "pattern": _string("Python regex pattern when operation=regex_replace."),
                    "replacement": _string("Regex replacement when operation=regex_replace.", default=""),
                    "count": _integer("Maximum replacements; 0 means replace all.", default=0, minimum=0,
                    ),
                    "flags": _array(
                        "Regex flags for operation=regex_replace.",
                        {"type": "string", "enum": ["ignorecase", "multiline", "dotall"],
                        },
                        default=[],
                    ),
                    "language": _string("Optional Markdown code fence language filter for operation=remove_markdown_code_blocks."),
                    "expected_replacements": _integer("Optional exact replacement count guard.", minimum=0),
                    "return_content": _boolean("Return edited UTF-8 content in addition to diff.", default=False,
                    ),
                    "diff": _boolean("Return structured diff payload when possible.", default=True
                    ),
                    **_write_guard_schema_properties(),
                },
                ["client_id", "path"],
            ),
            _annotations(title="Write thin-client file", read_only=False, destructive=True, open_world=False,
            ),
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
                    "content": _string_or_null("Edited UTF-8 content when return_content is true."),
                    "before_sha256": _string_or_null(
                        "Full file SHA-256 before the write."
                    ),
                    "after_sha256": _string_or_null(
                        "Full file SHA-256 after the write."
                    ),
                    "file_change_id": _string("Persisted FileChangeSet id."),
                    "diff": _diff_schema(),
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
                    "cwd": _string("Directory-relative working directory inside the sandbox.", default=".",
                    ),
                    "timeout_seconds": _integer("Optional timeout in seconds.", minimum=1),
                    "background": _boolean("Start immediately as a background monitoring session.", default=False,
                    ),
                    "session_name": _string("Optional display name for the monitoring session."),
                },
                ["client_id", "command"],
            ),
            _annotations(title="Run thin-client command", read_only=False, destructive=True, open_world=True,
            ),
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
            _annotations(title="Terminate command session", read_only=False, destructive=True, open_world=False,
            ),
            output_schema=_output_schema({"session": {"type": "object"}}),
        ),
        *agent_collaboration_tools(),
        *agent_coordination_tools(),
        *agent_autonomy_tools(),
        *mcp_federation_broker_tools(),
        _tool(
            "file_changes_list",
            "List recent server-side file change records produced by write/edit tool calls.",
            _object_schema(
                {
                    "limit": _integer("Maximum number of file changes to return.", default=100, minimum=1,
                    ),
                    "origin": _string("Optional origin filter, for example thin_client."),
                    "resource_id": _string("Optional resource id filter."),
                }
            ),
            _annotations(title="List file changes", read_only=True, idempotent=True),
            output_schema=_output_schema({"changes": _array("Recent file changes.", _file_change_schema())}),
        ),
    ]


def _tool_registry(
    settings: Settings,
    ssh_command_profile: str,
    *,
    db: Session | None = None,
    user: User | None = None,
    presentation: PresentationContext | None = None,
) -> ToolRegistry:
    legacy = _legacy_tools(settings, ssh_command_profile)
    order_by_name = {str(tool["name"]): index for index, tool in enumerate(legacy)}
    broker_names = set(mcp_federation_broker_tool_names())
    registry = ToolRegistry()
    registry.register(
        "gateway",
        [tool for tool in legacy if str(tool["name"]) not in broker_names],
        order_by_name=order_by_name,
    )
    registry.register(
        "broker",
        [tool for tool in legacy if str(tool["name"]) in broker_names],
        order_by_name=order_by_name,
    )
    if (
        db is not None
        and user is not None
        and presentation is not None
        and presentation.includes_native_projection
    ):
        entries = projection_entries_for_context(
            db,
            owner_subject=user.subject,
            user_roles=user.roles,
            context=presentation,
        )
        native_tools = [native_tool_definition(entry) for entry in entries]
        native_targets = {
            entry.tool.public_name: ToolDispatchTarget(
                provider="native_projection",
                public_name=entry.tool.public_name,
                revision_id=entry.tool.revision_id,
                generation_id=entry.generation.id,
                metadata={
                    "projection_tool_id": entry.tool.id,
                    "server_id": entry.tool.server_id,
                    "source_exposure_id": entry.tool.source_exposure_id,
                    "profile_id": entry.generation.profile_id,
                },
            )
            for entry in entries
        }
        registry.register(
            "native_projection",
            native_tools,
            start_order=len(legacy) + 1000,
            targets=native_targets,
        )
    if (
        db is not None
        and user is not None
        and presentation is not None
        and presentation.selected_mode == "deferred_native"
    ):
        deferred_entries = deferred_entries_for_context(
            db,
            user=user,
            context=presentation,
        )
        deferred_tools = [
            deferred_native_tool_definition(entry) for entry in deferred_entries
        ]
        deferred_targets = {
            entry.public_name: deferred_native_dispatch_target(entry)
            for entry in deferred_entries
        }
        registry.register(
            "deferred_native",
            deferred_tools,
            start_order=len(legacy) + 2000,
            targets=deferred_targets,
        )
    allowed_names = None
    if presentation is not None and presentation.allowed_tool_names is not None:
        allowed_names = set(presentation.allowed_tool_names) | broker_names
    return registry.filtered(allowed_names)


def _tools(
    settings: Settings | None = None,
    ssh_command_profile: str | None = None,
    *,
    db: Session | None = None,
    user: User | None = None,
    presentation: PresentationContext | None = None,
) -> list[dict[str, Any]]:
    resolved_settings = settings or get_settings()
    resolved_profile = (
        ssh_command_profile or resolved_settings.ssh_command_profile_default
    )
    return _tool_registry(
        resolved_settings,
        resolved_profile,
        db=db,
        user=user,
        presentation=presentation,
    ).tools()


def _tool_by_name(
    name: str,
    settings: Settings,
    ssh_command_profile: str,
    *,
    registry: ToolRegistry | None = None,
) -> dict[str, Any] | None:
    selected = registry or _tool_registry(settings, ssh_command_profile)
    return selected.tool(name)


def _normalized_arg_name(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum() or char == "_")


def _validate_tool_arguments(
    name: str,
    args: dict[str, Any],
    settings: Settings,
    ssh_command_profile: str,
    *,
    registry: ToolRegistry | None = None,
) -> dict[str, Any]:
    if not isinstance(args, dict):
        raise HTTPException(status_code=400, detail="Tool arguments must be an object")
    tool = _tool_by_name(name, settings, ssh_command_profile, registry=registry)
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


def _result(data: dict[str, Any], *, is_error: bool = False, extra_content: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    structured = {"ok": not is_error, "error": None if not is_error else str(data.get("error") or "Tool call failed"), **data,
    }
    if not is_error:
        structured["error"] = None
    return {
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}, *(extra_content or []),
        ],
        "structuredContent": structured,
        "isError": is_error,
    }


def _refresh_result_content(result: dict[str, Any]) -> dict[str, Any]:
    structured = result.get("structuredContent") or {}
    preserved = [item for item in result.get("content", []) if isinstance(item, dict) and item.get("type") != "text"]
    result["content"] = [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}, *preserved,
    ]
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
    return _result(payload, is_error=(run_result.exit_code is not None and run_result.exit_code != 0),
    )


def _query_visible_ssh_device(device_id: str, user: User, db: Session) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.kind != "ssh" or device.owner_subject != user.subject:
        raise HTTPException(status_code=404, detail="SSH device not found")
    return device


def _ssh_device_payload(device: Device) -> dict[str, Any]:
    return {
        "device_id": device.id,
        "name": device.name,
        "host": device.host,
        "port": device.port,
        "username": device.username,
        "auth_type": device.auth_type,
        "status": device.status,
    }


def _docker_workspace_payload(workspace: DockerWorkspace) -> dict[str, Any]:
    return {
        "workspace_id": workspace.id,
        "name": workspace.name,
        "description": workspace.description,
        "image": workspace.image,
        "status": workspace.status,
    }


def _thin_client_payload(client: ThinClient) -> dict[str, Any]:
    return {
        "client_id": client.id,
        "hostname": client.hostname,
        "directory": client.directory,
        "status": client.status,
        "connected": thin_client_manager.is_connected(client.id),
        "last_seen_at": client.last_seen_at.isoformat(),
    }


def _ssh_status_from_exception(exc: HTTPException) -> str:
    if exc.status_code == 409:
        return "host_key_untrusted"
    if exc.status_code in {401, 403}:
        return "auth_failed"
    if exc.status_code in {502, 504}:
        return "unreachable"
    return "auth_failed"


def _ssh_action_command(action: str) -> str:
    commands = {
        "whoami": "whoami",
        "pwd": "pwd",
        "uptime": "uptime",
        "disk_usage": "df -h",
        "memory_usage": "free -h || vm_stat",
        "home_list": "printf 'HOME=%s\\n' \"$HOME\"; ls -la \"$HOME\" | sed -n '1,120p'",
    }
    try:
        return commands[action]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="Unsupported SSH action") from exc


def _validate_ssh_raw_command(
    command: str,
    settings: Settings,
    ssh_command_profile: str,
) -> str:
    normalized = command.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="SSH command must not be empty")
    if any(char in normalized for char in ("\x00", "\r", "\n")):
        raise HTTPException(status_code=400, detail="SSH command must be a single line")
    if len(normalized) > int(settings.gateway_ssh_raw_command_max_chars):
        raise HTTPException(status_code=400, detail="SSH command exceeds configured length limit")
    if ssh_command_profile == "filtered":
        for pattern in settings.ssh_raw_command_denied_patterns:
            try:
                matched = re.search(pattern, normalized, flags=re.IGNORECASE)
            except re.error as exc:
                raise HTTPException(status_code=500, detail="Invalid SSH raw command deny pattern") from exc
            if matched:
                raise HTTPException(status_code=400, detail="SSH command is blocked by filtered-mode policy")
    return normalized


def _ssh_session_meta(device: Device, *, action: str | None = None) -> dict[str, Any]:
    return {
        "device_id": device.id,
        "device_name": device.name,
        "host": device.host,
        "port": device.port,
        "username": device.username,
        "auth_type": device.auth_type,
        "action": action,
    }


def _finish_ssh_worker(session_id: str, device: Device, credentials: Any, *, command: str, timeout_seconds: int,
) -> HTTPException | None:
    try:
        result = run_ssh_command(device, credentials, command=command, timeout_seconds=timeout_seconds)
        monitoring_service.append_output(session_id, stream="stdout", text=result.stdout)
        monitoring_service.append_output(session_id, stream="stderr", text=result.stderr)
        monitoring_service.finish_session(
            session_id,
            status_value="completed" if result.exit_code == 0 else "failed",
            exit_code=result.exit_code,
        )
        return None
    except HTTPException as exc:
        monitoring_service.append_output(session_id, stream="stderr", text=f"SSH command failed: {exc.detail}\n")
        monitoring_service.finish_session(session_id, status_value="failed", exit_code=1, meta={"error": str(exc.detail)},
        )
        return exc
    except Exception as exc:  # pragma: no cover - defensive safety net for unexpected adapter failures.
        monitoring_service.append_output(session_id, stream="stderr", text="SSH command failed\n")
        monitoring_service.finish_session(session_id, status_value="failed", exit_code=1, meta={"error": str(exc)})
        return HTTPException(status_code=502, detail="SSH command execution failed")


async def _run_ssh_command_monitored(
    db: Session,
    *,
    user: User,
    device: Device,
    command: str,
    action: str | None,
    timeout_seconds: int,
    background: bool,
    session_name: str | None,
    settings: Settings,
) -> CommandRunResult:
    credentials = load_device_credentials(device, db)
    session = monitoring_service.create_session(
        db,
        owner_subject=user.subject,
        origin="ssh",
        resource_id=device.id,
        command=command,
        cwd="~",
        name=session_name,
        settings=settings,
        meta=_ssh_session_meta(device, action=action),
    )
    if background:
        threading.Thread(
            target=_finish_ssh_worker,
            args=(session.id, device, credentials),
            kwargs={"command": command, "timeout_seconds": timeout_seconds},
            name=f"ssh-command-session-{session.id}",
            daemon=True,
        ).start()
        return CommandRunResult(
            session_id=session.id,
            status="running",
            backgrounded=True,
            recommendation=(
                f"SSH command is running in background session {session.id}. "
                "Use monitoring_get_session, monitoring_read_output, or monitoring_terminate_session."
            ),
        )
    await asyncio.to_thread(
        _finish_ssh_worker,
        session.id,
        device,
        credentials,
        command=command,
        timeout_seconds=timeout_seconds,
    )
    db.expire_all()
    completed = db.get(CommandSession, session.id)
    output = "\n".join(record["text"] for record in monitoring_service.read_output_records(session.id, tail=1000))
    return CommandRunResult(
        session_id=session.id,
        status=completed.status if completed else "completed",
        backgrounded=False,
        exit_code=completed.exit_code if completed else None,
        output=output[: settings.max_output_chars],
    )


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


def _mcp_jsonrpc_error(
    request_id: Any,
    *,
    code: int,
    message: str,
    status_code: int = 200,
    data: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return JSONResponse(
        status_code=status_code,
        content={"jsonrpc": "2.0", "id": request_id, "error": error},
    )


@router.get("/mcp")
async def mcp_info(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {
        "name": settings.app_name,
        "transport": "http-json-rpc",
        "tools": [tool["name"] for tool in _tools()],
    }


@router.post("/mcp")
async def mcp(
    request: Request,
    user: User = Depends(get_bearer_or_dev_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Any:
    raw_body = await request.body()
    try:
        raw_text = raw_body.decode("utf-8")
        body = json.loads(raw_text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _mcp_jsonrpc_error(
            None, code=-32700, message="Parse error", status_code=400
        )
    if not isinstance(body, dict):
        return _mcp_jsonrpc_error(
            None, code=-32600, message="Invalid Request", status_code=400
        )
    method = body.get("method")
    request_id = body.get("id")
    if method != "initialize":
        try:
            validate_http_protocol_version(request.headers.get("MCP-Protocol-Version"))
        except McpProtocolAdmissionError as exc:
            return _mcp_jsonrpc_error(
                request_id,
                code=-32602,
                message=str(exc),
                status_code=400,
                data={"supported": list(SUPPORTED_MCP_PROTOCOL_VERSIONS)},
            )
    ssh_profile = effective_ssh_command_profile(user, settings)
    presentation = resolve_presentation_context(request, db, user)
    registry = _tool_registry(
        settings,
        ssh_profile,
        db=db,
        user=user,
        presentation=presentation,
    )
    tool_call = None
    if method == "tools/call":
        try:
            await request.app.state.gateway_runtime.mcp_traffic.flush_pending(
                db,
                owner_subject=user.subject,
            )
        except Exception:
            db.rollback()
    try:
        if method == "initialize":
            params = body.get("params") if isinstance(body.get("params"), dict) else {}
            try:
                protocol_version = negotiate_gateway_protocol_version(
                    params.get("protocolVersion")
                )
            except McpProtocolAdmissionError as exc:
                return _mcp_jsonrpc_error(
                    request_id,
                    code=-32602,
                    message=str(exc),
                    status_code=400,
                    data={"supported": list(SUPPORTED_MCP_PROTOCOL_VERSIONS)},
                )
            result = {
                "protocolVersion": protocol_version,
                "capabilities": gateway_public_server_capabilities(
                    tools_list_changed=presentation.supports_list_changed
                ),
                "serverInfo": {
                    "name": settings.app_name,
                    "version": settings.gateway_release_version,
                },
                "_meta": {
                    "gateway": {
                        "presentation": {
                            "profile_id": presentation.profile_id,
                            "configured_mode": presentation.configured_mode,
                            "selected_mode": presentation.selected_mode,
                            "policy_generation": presentation.policy_generation,
                            "capabilities": sorted(presentation.capabilities),
                            "selection_reason": presentation.selection_reason,
                        }
                    }
                },
            }
        elif method == "tools/list":
            result = {"tools": registry.tools()}
        elif method == "tools/call":
            params = body.get("params") if isinstance(body.get("params"), dict) else {}
            name = str(params.get("name") or "")
            raw_arguments = (
                params.get("arguments")
                if isinstance(params.get("arguments"), dict)
                else {}
            )
            tool_call = monitoring_service.create_tool_call(
                db,
                owner_subject=user.subject,
                tool_name=name or "invalid-tools-call",
                arguments=raw_arguments,
            )
            arguments = _validate_tool_arguments(
                name,
                raw_arguments,
                settings,
                ssh_profile,
                registry=registry,
            )
            result = await _call_tool(
                name,
                arguments,
                user,
                db,
                settings,
                upstream=request.app.state.upstream_mcp_manager,
                tool_call_id=tool_call.id,
                dispatch_target=registry.target(name),
                presentation=presentation,
            )
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
        else:
            return _mcp_jsonrpc_error(
                request_id,
                code=-32601,
                message=f"Method not found: {method}",
            )
        payload = {"jsonrpc": "2.0", "id": request_id, "result": result}
    except HTTPException as exc:
        if tool_call is not None:
            monitoring_service.finish_tool_call(
                db, call=tool_call, status="error", error=str(exc.detail)
            )
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": exc.status_code, "message": str(exc.detail)},
        }

    response = JSONResponse(content=payload)
    if tool_call is not None:
        try:
            await request.app.state.gateway_runtime.mcp_traffic.record_exchange(
                db,
                call=tool_call,
                request_characters=len(raw_text),
                response_characters=len(response.body.decode("utf-8")),
            )
        except Exception:
            db.rollback()
    return response


async def _call_native_projection(
    target: ToolDispatchTarget,
    args: dict[str, Any],
    user: User,
    db: Session,
    upstream: UpstreamMcpManager,
    presentation: PresentationContext,
    *,
    tool_call_id: str | None,
) -> dict[str, Any]:
    generation = db.get(McpProjectionGeneration, target.generation_id)
    projection_tool_id = str(target.metadata.get("projection_tool_id") or "")
    projection = db.get(McpProjectionTool, projection_tool_id)
    if (
        generation is None
        or projection is None
        or generation.owner_subject != user.subject
        or generation.status != "active"
        or generation.profile_id != presentation.profile_id
        or projection.generation_id != generation.id
        or projection.public_name != target.public_name
        or projection.revision_id != target.revision_id
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MCP_PROJECTED_TOOL_STALE",
                "message": "The projected tool no longer belongs to the active presentation generation",
            },
        )
    exposure = db.get(McpToolExposure, projection.source_exposure_id)
    server = db.get(McpServer, projection.server_id)
    if (
        exposure is None
        or exposure.owner_subject != user.subject
        or exposure.mode != "native_projected"
        or not exposure.enabled
        or exposure.revision_id != projection.revision_id
        or server is None
        or server.owner_subject != user.subject
        or server.status != "online"
    ):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "MCP_PROJECTED_TOOL_UNAVAILABLE",
                "message": "The projected action remains published but its exact upstream revision is unavailable",
                "generation_id": generation.id,
                "revision_id": projection.revision_id,
                "server_id": projection.server_id,
            },
        )
    try:
        call = await upstream.call_exact_revision(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            revision_id=projection.revision_id,
            arguments=args,
            gateway_tool_call_id=tool_call_id,
        )
    except UpstreamMcpError as exc:
        raise HTTPException(
            status_code=exc.http_status, detail=exc.as_detail()
        ) from exc
    return dict(call.payload)


async def _call_deferred_native(
    target: ToolDispatchTarget,
    args: dict[str, Any],
    user: User,
    db: Session,
    upstream: UpstreamMcpManager,
    presentation: PresentationContext,
    *,
    tool_call_id: str | None,
) -> dict[str, Any]:
    item = resolve_deferred_dispatch(
        db,
        user=user,
        context=presentation,
        target=target,
    )
    try:
        call = await upstream.call_exact_revision(
            db,
            owner_subject=user.subject,
            actor_subject=user.subject,
            revision_id=item.revision.id,
            arguments=args,
            gateway_tool_call_id=tool_call_id,
        )
    except UpstreamMcpError as exc:
        raise HTTPException(
            status_code=exc.http_status, detail=exc.as_detail()
        ) from exc
    return dict(call.payload)


async def _call_tool(
    name: str,
    args: dict[str, Any],
    user: User,
    db: Session,
    settings: Settings,
    *,
    upstream: UpstreamMcpManager,
    tool_call_id: str | None = None,
    dispatch_target: ToolDispatchTarget | None = None,
    presentation: PresentationContext | None = None,
) -> dict[str, Any]:
    if dispatch_target is not None and dispatch_target.provider == "native_projection":
        if presentation is None:
            raise HTTPException(status_code=409, detail="Presentation context is required")
        return await _call_native_projection(
            dispatch_target,
            args,
            user,
            db,
            upstream,
            presentation,
            tool_call_id=tool_call_id,
        )
    if dispatch_target is not None and dispatch_target.provider == "deferred_native":
        if presentation is None:
            raise HTTPException(status_code=409, detail="Presentation context is required")
        return await _call_deferred_native(
            dispatch_target,
            args,
            user,
            db,
            upstream,
            presentation,
            tool_call_id=tool_call_id,
        )
    if name in agent_collaboration_tool_names():
        return _result(await call_agent_collaboration_tool(name, args, user, db))
    if name in agent_coordination_tool_names():
        return _result(await call_agent_coordination_tool(name, args, user, db))
    if name in agent_autonomy_tool_names():
        return _result(await call_agent_autonomy_tool(name, args, user, db))
    if name in mcp_federation_broker_tool_names():
        return _result(
            await call_mcp_federation_broker_tool(
                name,
                args,
                user=user,
                db=db,
                upstream=upstream,
                preparation_ttl_seconds=settings.gateway_mcp_action_preparation_ttl_seconds,
                gateway_tool_call_id=tool_call_id,
            )
        )
    if name == "workspace_info":
        path = _workspace(user, settings)
        return _result({"workspace": str(path), "user": user.username})
    if name == "list_resources":
        devices = (
            db.query(Device)
            .filter(Device.owner_subject == user.subject, Device.kind == "ssh")
            .order_by(Device.created_at.desc())
            .all()
        )
        workspaces = (
            db.query(DockerWorkspace)
            .filter(DockerWorkspace.owner_subject == user.subject)
            .order_by(DockerWorkspace.created_at.desc())
            .all()
        )
        thin_clients = (
            db.query(ThinClient)
            .filter(ThinClient.owner_subject == user.subject)
            .order_by(ThinClient.created_at.desc())
            .all()
        )
        return _result(
            {
                "devices": len(devices),
                "docker_workspaces": len(workspaces),
                "thin_clients": len(thin_clients),
                "ssh_devices": [_ssh_device_payload(device) for device in devices],
                "docker_workspace_items": [_docker_workspace_payload(workspace) for workspace in workspaces],
                "thin_client_items": [_thin_client_payload(client) for client in thin_clients],
            }
        )
    if name in {"ssh_device_info", "ssh_device_check_connection", "ssh_device_run_action", "ssh_device_read_home", "ssh_device_run_command"}:
        if not settings.gateway_ssh_enabled:
            raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
        device = _query_visible_ssh_device(str(args.get("device_id", "")), user, db)
        if name == "ssh_device_info":
            enforce(user, action="read")
            return _result(_ssh_device_payload(device))
        if name == "ssh_device_check_connection":
            timeout_seconds = _bounded_timeout(args.get("timeout_seconds"), settings)
            try:
                credentials = load_device_credentials(device, db)
                status_value = verify_ssh_connection(device, credentials, timeout_seconds=timeout_seconds)
                device.status = status_value
                detail = "authenticated"
            except HTTPException as exc:
                status_value = _ssh_status_from_exception(exc)
                device.status = status_value
                detail = str(exc.detail)
            device.updated_at = utcnow()
            db.flush()
            db.refresh(device)
            emit_event(
                db,
                event_type="gateway.device.connection_verified.v1",
                actor_subject=user.subject,
                action="verified" if device.status == "verified" else "verification_failed",
                resource_type="device",
                resource_id=device.id,
                payload={"device_id": device.id, "status": device.status, "host": device.host, "port": device.port,
                },
                status="success" if device.status == "verified" else "warning",
                commit=False,
            )
            db.commit()
            return _result({"device_id": device.id, "status": device.status, "detail": detail})
        if name == "ssh_device_run_command":
            ssh_command_profile = effective_ssh_command_profile(user, settings)
            if not raw_ssh_commands_enabled(user, settings):
                raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
            command = _validate_ssh_raw_command(
                str(args.get("command", "")),
                settings,
                ssh_command_profile,
            )
            action = "raw_command"
        else:
            action = (
                "home_list" if name == "ssh_device_read_home" else str(args.get("action", "")))
            if action not in set(settings.ssh_allowed_actions):
                raise HTTPException(status_code=400, detail="Unsupported SSH action")
            command = _ssh_action_command(action)
        timeout_seconds = _bounded_timeout(args.get("timeout_seconds"), settings)
        run_result = await _run_ssh_command_monitored(
            db,
            user=user,
            device=device,
            command=command,
            action=action,
            timeout_seconds=timeout_seconds,
            background=bool(args.get("background", False)),
            session_name=str(args.get("session_name") or "") or None,
            settings=settings,
        )
        return _command_result(
            command=command,
            cwd="~",
            run_result=run_result,
            extra={"device_id": device.id, "action": action},
        )
    if name == "monitoring_list_sessions":
        query = (
            db.query(CommandSession).filter(CommandSession.owner_subject == user.subject).order_by(CommandSession.updated_at.desc()))
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
                    arguments={"session_id": session.id, "force": bool(args.get("force", False)),
                    },
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
    if name == "file_changes_list":
        enforce(user, action="read")
        safe_limit = min(max(int(args.get("limit", 100) or 100), 1), 500)
        query = (
            db.query(FileChangeSet).filter(FileChangeSet.owner_subject == user.subject).order_by(FileChangeSet.created_at.desc()))
        if args.get("origin"):
            query = query.filter(FileChangeSet.origin == str(args["origin"]))
        if args.get("resource_id"):
            query = query.filter(FileChangeSet.resource_id == str(args["resource_id"]))
        return _result({"changes": [_file_change_payload(change) for change in query.limit(safe_limit).all()]})
    if name == "list_files":
        root = _workspace(user, settings)
        target = _safe_path(user, settings, str(args.get("path", ".")))
        if not target.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        entries = []
        for child in sorted(target.iterdir()):
            entries.append({"path": str(child.relative_to(root)), "kind": "dir" if child.is_dir() else "file", "size": child.stat().st_size if child.is_file() else None,
                })
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
        relative_path = _relative_or_dot(root, target)
        lease_context = agent_coordination_service.validate_write_context(
            db,
            owner_subject=user.subject,
            origin="server",
            resource_id=None,
            path=relative_path,
            data=args,
        )
        if lease_context and not settings.gateway_agent_allow_unverified_git_context:
            worktree = _safe_path(user, settings, lease_context.worktree_path)
            _validate_write_git_state(
                _local_git_state(worktree, lease_context.base_commit),
                lease_context,
            )
        if target.exists() and not target.is_file():
            raise HTTPException(
                status_code=409, detail="Write path exists and is not a file"
            )
        existed_before = target.is_file()
        before_raw = target.read_bytes() if existed_before else b""
        before_sha256 = (
            hashlib.sha256(before_raw).hexdigest() if existed_before else None
        )
        if lease_context:
            if lease_context.expected_absent and target.exists():
                raise HTTPException(
                    status_code=409,
                    detail="File precondition failed: path already exists",
                )
            if (
                lease_context.expected_sha256
                and before_sha256 != lease_context.expected_sha256
            ):
                raise HTTPException(
                    status_code=409, detail="File precondition failed: sha256 mismatch"
                )
        text = str(args.get("content", ""))
        raw = text.encode("utf-8")
        if len(raw) > settings.max_file_write_bytes:
            raise HTTPException(status_code=413, detail="File content is too large")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        after_sha256 = hashlib.sha256(raw).hexdigest()
        structured = {
            "path": relative_path,
            "operation": "write",
            "bytes": len(raw),
            "bytes_before": len(before_raw),
            "bytes_after": len(raw),
            "replacements": 0,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "diff": {
                "format": "unified",
                "suppressed": True,
                "reason": "server write diff is not materialized",
                "truncated": False,
                "added_lines": 0,
                "removed_lines": 0,
                "hunks": [],
            },
        }
        file_change = _persist_file_change(
            db,
            user=user,
            origin="server",
            resource_id=None,
            tool_call_id=tool_call_id,
            structured=structured,
            lease_context=lease_context,
        )
        return _result(
            {
                "path": relative_path,
                "bytes": len(raw),
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "file_change_id": file_change.id,
            })
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
            args=["docker", "exec", "-w", workdir, workspace.container_id, "sh", "-lc", command,
            ],
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
        db.flush()
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
            commit=False,
        )
        db.commit()
        return _result(
            {
                "workspace_id": workspace.id,
                "name": workspace.name,
                "description": workspace.description,
                "container_name": workspace.container_name,
            }
        )
    if name in {"docker_workspace_stop", "docker_workspace_start", "docker_workspace_delete",
    }:
        workspace = db.get(DockerWorkspace, str(args.get("workspace_id", "")))
        if workspace is None or workspace.owner_subject != user.subject:
            raise HTTPException(status_code=404, detail="Workspace not found")
        adapter = DockerAdapter(settings)
        if name == "docker_workspace_delete":
            container_id = workspace.container_id
            container_name = workspace.container_name
            detail = adapter.remove_workspace(container_id=container_id)
            db.delete(workspace)
            emit_event(
                db,
                event_type="gateway.workspace.changed.v1",
                actor_subject=user.subject,
                action="deleted",
                resource_type="docker_workspace",
                resource_id=str(args.get("workspace_id", "")),
                payload={"workspace_id": str(args.get("workspace_id", "")), "container_id": container_id, "container_name": container_name, "detail": detail,
                },
                commit=False,
            )
            db.commit()
            return _result({"workspace_id": str(args.get("workspace_id", "")), "deleted": True, "detail": detail,
                })
        if name == "docker_workspace_stop":
            result = adapter.stop_workspace(container_id=workspace.container_id)
            action = "stopped"
        else:
            result = adapter.start_workspace(container_id=workspace.container_id)
            action = "started"
        workspace.status = result.status
        workspace.meta = {**(workspace.meta or {}), "detail": result.detail}
        workspace.updated_at = utcnow()
        db.flush()
        db.refresh(workspace)
        emit_event(
            db,
            event_type="gateway.workspace.changed.v1",
            actor_subject=user.subject,
            action=action,
            resource_type="docker_workspace",
            resource_id=workspace.id,
            payload={"workspace_id": workspace.id, "container_id": workspace.container_id, "status": workspace.status,
            },
            commit=False,
        )
        db.commit()
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
            lease_context = agent_coordination_service.validate_write_context(
                db,
                owner_subject=user.subject,
                origin="thin_client",
                resource_id=client.id,
                path=str(args.get("path", "")),
                data=args,
            )
            if lease_context:
                if not settings.gateway_agent_allow_unverified_git_context:
                    git_response = await thin_client_manager.request(
                        client.id,
                        tool="git_state",
                        arguments={
                            "worktree_path": lease_context.worktree_path,
                            "base_commit": lease_context.base_commit,
                        },
                        timeout_seconds=_bounded_timeout(
                            args.get("timeout_seconds"), settings
                        ),
                    )
                    if not git_response.get("ok") or not isinstance(
                        git_response.get("result"), dict
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail="Thin client does not support guarded Git worktree checks",
                        )
                    git_state = dict(git_response["result"])
                    if str(git_state.get("toplevel") or "") != lease_context.worktree_path:
                        raise HTTPException(
                            status_code=409,
                            detail="Thin-client lease path is not the Git worktree root",
                        )
                    _validate_write_git_state(git_state, lease_context)
                state_response = await thin_client_manager.request(
                    client.id,
                    tool="file_state",
                    arguments={"path": args.get("path", "")},
                    timeout_seconds=_bounded_timeout(
                        args.get("timeout_seconds"), settings
                    ),
                )
                if not state_response.get("ok") or not isinstance(
                    state_response.get("result"), dict
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="Thin client does not support guarded file state checks",
                    )
                state = dict(state_response["result"])
                if lease_context.expected_absent and bool(state.get("exists")):
                    raise HTTPException(
                        status_code=409,
                        detail="File precondition failed: path already exists",
                    )
                if (
                    lease_context.expected_sha256
                    and str(state.get("sha256") or "") != lease_context.expected_sha256
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="File precondition failed: sha256 mismatch",
                    )
            arguments = {key: value for key, value in args.items() if key
                not in {
                    "client_id",
                    "room_id",
                    "agent_id",
                    "lease_id",
                    "fencing_token",
                    "base_commit",
                    "branch_name",
                    "worktree_path",
                }
            }
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
                meta={"client_id": client.id, "hostname": client.hostname, "directory": client.directory,
                },
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
            return _result({"client_id": client.id, "error": str(response.get("error") or "Thin client tool failed"),
                },
                is_error=True,
            )
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
                "before_sha256": result.get("before_sha256"),
                "after_sha256": result.get("after_sha256"),
                "diff": result.get("diff")
                or {
                    "format": "unified",
                    "suppressed": True,
                    "reason": "not provided by thin client",
                    "truncated": False,
                    "added_lines": 0,
                    "removed_lines": 0,
                    "hunks": [],
                },
            }
            if lease_context and (
                (
                    not structured.get("before_sha256")
                    and not lease_context.expected_absent
                )
                or not structured.get("after_sha256")
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Thin client did not return guarded write hashes",
                )
            file_change = _persist_file_change(
                db,
                user=user,
                origin="thin_client",
                resource_id=client.id,
                tool_call_id=tool_call_id,
                structured=structured,
                lease_context=lease_context,
            )
            structured["file_change_id"] = file_change.id
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
