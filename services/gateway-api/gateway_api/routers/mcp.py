from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import get_bearer_or_dev_user
from ..config import Settings, get_settings
from ..database import get_db
from ..models import Device, DockerWorkspace, ThinClient, User

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


def _tools() -> list[dict[str, Any]]:
    return [
        {"name": "workspace_info", "description": "Return the authenticated user's isolated workspace path."},
        {"name": "list_resources", "description": "List registered SSH devices, Docker workspaces, and thin clients."},
        {"name": "list_files", "description": "List files under a workspace path."},
        {"name": "read_file", "description": "Read a text file from the workspace."},
        {"name": "write_file", "description": "Write a text file into the workspace."},
        {"name": "run_cli_command", "description": "Run a CLI command inside the workspace."},
    ]


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
            result = {"protocolVersion": "2025-03-26", "serverInfo": {"name": settings.app_name, "version": "0.1.0"}}
        elif method == "tools/list":
            result = {"tools": _tools()}
        elif method == "tools/call":
            params = body.get("params") or {}
            result = await _call_tool(params.get("name"), params.get("arguments") or {}, user, db, settings)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported JSON-RPC method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except HTTPException as exc:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": exc.status_code, "message": str(exc.detail)}}


async def _call_tool(name: str, args: dict[str, Any], user: User, db: Session, settings: Settings) -> dict[str, Any]:
    if name == "workspace_info":
        path = _workspace(user, settings)
        return {"content": [{"type": "text", "text": str({"workspace": str(path), "user": user.username})}]}
    if name == "list_resources":
        devices = db.query(Device).filter(Device.owner_subject == user.subject).count()
        workspaces = db.query(DockerWorkspace).filter(DockerWorkspace.owner_subject == user.subject).count()
        thin_clients = db.query(ThinClient).filter(ThinClient.owner_subject == user.subject).count()
        return {"content": [{"type": "text", "text": str({"devices": devices, "docker_workspaces": workspaces, "thin_clients": thin_clients})}]}
    if name == "list_files":
        target = _safe_path(user, settings, str(args.get("path", ".")))
        if not target.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        entries = []
        for child in sorted(target.iterdir()):
            entries.append({"path": str(child.relative_to(_workspace(user, settings))), "kind": "dir" if child.is_dir() else "file", "size": child.stat().st_size if child.is_file() else None})
        return {"content": [{"type": "text", "text": str(entries)}]}
    if name == "read_file":
        target = _safe_path(user, settings, str(args.get("path", ".")))
        data = target.read_bytes()[: settings.max_file_read_bytes]
        return {"content": [{"type": "text", "text": data.decode("utf-8", errors="replace")}]} 
    if name == "write_file":
        target = _safe_path(user, settings, str(args.get("path", ".")))
        text = str(args.get("content", ""))
        if len(text.encode("utf-8")) > settings.max_file_write_bytes:
            raise HTTPException(status_code=413, detail="File content is too large")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return {"content": [{"type": "text", "text": "ok"}]}
    if name == "run_cli_command":
        command = str(args.get("command", ""))
        cwd = _safe_path(user, settings, str(args.get("cwd", ".")))
        completed = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True, timeout=settings.max_command_timeout_seconds)
        output = (completed.stdout + completed.stderr)[: settings.max_output_chars]
        return {"content": [{"type": "text", "text": output}], "isError": completed.returncode != 0}
    raise HTTPException(status_code=404, detail=f"Unknown tool: {name}")
