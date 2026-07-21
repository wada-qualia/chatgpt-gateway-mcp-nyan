from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import SessionLocal
from .events import emit_event
from .models import AgentToolCall, CommandSession, CommandSessionDelivery, utcnow


ACTIVE_STATUSES = {"running", "disconnecting"}
TERMINAL_STATUSES = {"completed", "failed", "terminated", "lost"}
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
    "client_secret",
    "credential",
    "credentials",
    "gitlab_token",
    "github_token",
    "password",
    "passphrase",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}
SECRET_ARGUMENT_SUFFIXES = (
    "apikey",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "privatekey",
    "secret",
    "token",
)


@dataclass
class CommandRunResult:
    session_id: str
    status: str
    backgrounded: bool
    exit_code: int | None = None
    output: str = ""
    recommendation: str | None = None


@dataclass
class RunningProcess:
    process: subprocess.Popen[str]
    done: threading.Event


def utciso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalized_secret_name(value: str) -> str:
    return "".join(char for char in value.lower() if char.isalnum())


def _is_secret_argument_name(value: str) -> bool:
    normalized = _normalized_secret_name(value)
    exact_names = {_normalized_secret_name(item) for item in SECRET_ARGUMENT_NAMES}
    return normalized in exact_names or normalized.endswith(SECRET_ARGUMENT_SUFFIXES)


def _redacted_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]" if _is_secret_argument_name(str(key)) else _redacted_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redacted_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redacted_value(item) for item in value)
    return value


def redacted_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return _redacted_value(arguments)


class MonitoringService:
    def __init__(self) -> None:
        self._processes: dict[str, RunningProcess] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _session_matches_scope(
        session: CommandSession,
        *,
        owner_subject: str | None,
        origin: str | None,
        resource_id: str | None,
    ) -> bool:
        if owner_subject is not None and session.owner_subject != owner_subject:
            return False
        if origin is not None and session.origin != origin:
            return False
        if resource_id is not None and session.resource_id != resource_id:
            return False
        return True

    def _spool_root(self, settings: Settings | None = None) -> Path:
        resolved = settings or get_settings()
        root = Path(resolved.command_session_spool_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _output_path(self, session_id: str, settings: Settings | None = None) -> Path:
        return self._spool_root(settings) / f"{session_id}.jsonl"

    def create_tool_call(self, db: Session, *, owner_subject: str, tool_name: str, arguments: dict[str, Any]) -> AgentToolCall:
        call = AgentToolCall(
            id=str(uuid.uuid4()),
            owner_subject=owner_subject,
            tool_name=tool_name,
            arguments=redacted_arguments(arguments),
            status="running",
        )
        db.add(call)
        db.commit()
        db.refresh(call)
        return call

    def finish_tool_call(
        self,
        db: Session,
        *,
        call: AgentToolCall | None,
        status: str,
        session_id: str | None = None,
        error: str | None = None,
    ) -> None:
        if call is None:
            return
        current = db.get(AgentToolCall, call.id)
        if current is None:
            return
        current.status = status
        current.session_id = session_id
        current.error = error
        current.completed_at = utcnow()
        db.commit()

    def create_session(
        self,
        db: Session,
        *,
        owner_subject: str,
        origin: str,
        resource_id: str | None,
        command: str,
        cwd: str,
        name: str | None,
        settings: Settings,
        meta: dict[str, Any] | None = None,
    ) -> CommandSession:
        session_id = str(uuid.uuid4())
        output_path = self._output_path(session_id, settings)
        output_path.touch(exist_ok=True)
        session = CommandSession(
            id=session_id,
            owner_subject=owner_subject,
            origin=origin,
            resource_id=resource_id,
            name=name,
            command=command,
            cwd=cwd,
            status="running",
            output_path=str(output_path),
            meta=meta or {},
            started_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(session)
        db.flush()
        db.refresh(session)
        emit_event(
            db,
            event_type="gateway.command_session.started.v1",
            actor_subject=owner_subject,
            action="started",
            resource_type="command_session",
            resource_id=session.id,
            payload={"session_id": session.id, "origin": origin, "resource_id": resource_id},
            commit=False,
        )
        db.commit()
        return session

    def append_output(
        self,
        session_id: str,
        *,
        stream: str,
        text: str,
        owner_subject: str | None = None,
        origin: str | None = None,
        resource_id: str | None = None,
    ) -> bool:
        if not text:
            return False
        with SessionLocal() as db:
            session = db.get(CommandSession, session_id)
            if session is None or not self._session_matches_scope(
                session,
                owner_subject=owner_subject,
                origin=origin,
                resource_id=resource_id,
            ):
                return False
            path = Path(session.output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            records = []
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            fragments = normalized.splitlines()
            if normalized.endswith("\n"):
                pass
            elif fragments:
                pass
            else:
                fragments = [normalized]
            line = int(session.line_count or 0)
            for fragment in fragments:
                line += 1
                records.append({"line": line, "stream": stream, "text": fragment, "timestamp": utciso()})
            with path.open("a", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            session.line_count = line
            session.updated_at = utcnow()
            if records:
                emit_event(
                    db,
                    event_type="gateway.command_session.output.v1",
                    actor_subject=session.owner_subject,
                    action="output",
                    resource_type="command_session",
                    resource_id=session.id,
                    payload={
                        "session_id": session.id,
                        "origin": session.origin,
                        "stream": stream,
                        "start_line": int(records[0]["line"]),
                        "end_line": int(records[-1]["line"]),
                    },
                    commit=False,
                )
            db.commit()
            return True

    def finish_session(
        self,
        session_id: str,
        *,
        status_value: str,
        exit_code: int | None = None,
        meta: dict[str, Any] | None = None,
        owner_subject: str | None = None,
        origin: str | None = None,
        resource_id: str | None = None,
    ) -> bool:
        with SessionLocal() as db:
            session = db.get(CommandSession, session_id)
            if session is None or not self._session_matches_scope(
                session,
                owner_subject=owner_subject,
                origin=origin,
                resource_id=resource_id,
            ):
                return False
            if session.status == "terminated" and status_value != "terminated":
                session.exit_code = exit_code
                session.updated_at = utcnow()
                if meta:
                    session.meta = {**(session.meta or {}), **meta}
                db.commit()
                return True
            session.status = status_value
            session.exit_code = exit_code
            session.completed_at = utcnow()
            session.updated_at = utcnow()
            if meta:
                session.meta = {**(session.meta or {}), **meta}
            emit_event(
                db,
                event_type=(
                    "gateway.command_session.terminated.v1"
                    if status_value == "terminated"
                    else "gateway.command_session.finished.v1"
                ),
                actor_subject=session.owner_subject,
                action=status_value,
                resource_type="command_session",
                resource_id=session.id,
                payload={"session_id": session.id, "status": status_value, "exit_code": exit_code},
                commit=False,
            )
            db.commit()
            return True

    async def run_local_command(
        self,
        db: Session,
        *,
        owner_subject: str,
        origin: str,
        resource_id: str | None,
        command: str,
        cwd: str,
        args: list[str] | str,
        settings: Settings,
        background: bool = False,
        session_name: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> CommandRunResult:
        session = self.create_session(
            db,
            owner_subject=owner_subject,
            origin=origin,
            resource_id=resource_id,
            command=command,
            cwd=cwd,
            name=session_name,
            settings=settings,
            meta=meta,
        )
        done = threading.Event()
        try:
            process = subprocess.Popen(
                args,
                cwd=cwd if origin == "server" else None,
                shell=isinstance(args, str),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,
            )
        except OSError as exc:
            error = f"Unable to start command: {exc}"
            self.append_output(session.id, stream="stderr", text=f"{error}\n")
            self.finish_session(
                session.id,
                status_value="failed",
                exit_code=127,
                meta={"error": str(exc), "error_type": type(exc).__name__},
            )
            return CommandRunResult(
                session_id=session.id,
                status="failed",
                backgrounded=False,
                exit_code=127,
                output=error[: settings.max_output_chars],
            )
        session.pid = str(process.pid)
        db.commit()
        with self._lock:
            self._processes[session.id] = RunningProcess(process=process, done=done)

        def worker() -> None:
            try:
                assert process.stdout is not None
                for line in process.stdout:
                    self.append_output(session.id, stream="stdout", text=line)
                exit_code = process.wait()
                status_value = "completed" if exit_code == 0 else "failed"
                self.finish_session(session.id, status_value=status_value, exit_code=exit_code)
            except Exception as exc:
                self.append_output(session.id, stream="stderr", text=f"monitoring error: {exc}\n")
                self.finish_session(session.id, status_value="failed", exit_code=None, meta={"error": str(exc)})
            finally:
                done.set()
                with self._lock:
                    self._processes.pop(session.id, None)

        threading.Thread(target=worker, name=f"command-session-{session.id}", daemon=True).start()
        return await self._wait_or_background(db, session.id, settings=settings, background=background)

    async def _wait_or_background(
        self,
        db: Session,
        session_id: str,
        *,
        settings: Settings,
        background: bool,
    ) -> CommandRunResult:
        wait_seconds = 0 if background else max(1, int(settings.command_background_after_seconds))
        done = False
        if wait_seconds > 0:
            running = self._processes.get(session_id)
            if running:
                done = await asyncio.to_thread(running.done.wait, wait_seconds)
        if background or not done:
            session = db.get(CommandSession, session_id)
            return CommandRunResult(
                session_id=session_id,
                status=session.status if session else "running",
                backgrounded=True,
                recommendation=(
                    f"Command is running in background session {session_id}. "
                    "Use monitoring_get_session, monitoring_read_output, or monitoring_terminate_session."
                ),
            )
        db.expire_all()
        session = db.get(CommandSession, session_id)
        output = "\n".join(record["text"] for record in self.read_output_records(session_id, tail=1000))
        return CommandRunResult(
            session_id=session_id,
            status=session.status if session else "completed",
            backgrounded=False,
            exit_code=session.exit_code if session else None,
            output=output[: settings.max_output_chars],
        )

    async def wait_for_existing_session(
        self,
        db: Session,
        *,
        session_id: str,
        settings: Settings,
        background: bool,
    ) -> CommandRunResult:
        wait_seconds = 0 if background else max(1, int(settings.command_background_after_seconds))
        deadline = asyncio.get_running_loop().time() + wait_seconds
        if wait_seconds > 0:
            while asyncio.get_running_loop().time() < deadline:
                db.expire_all()
                session = db.get(CommandSession, session_id)
                if session is None:
                    raise HTTPException(status_code=404, detail="Command session not found")
                if session.status in TERMINAL_STATUSES:
                    output = "\n".join(record["text"] for record in self.read_output_records(session_id, tail=1000))
                    return CommandRunResult(
                        session_id=session_id,
                        status=session.status,
                        backgrounded=False,
                        exit_code=session.exit_code,
                        output=output[: settings.max_output_chars],
                    )
                await asyncio.sleep(0.25)
        session = db.get(CommandSession, session_id)
        return CommandRunResult(
            session_id=session_id,
            status=session.status if session else "running",
            backgrounded=True,
            recommendation=(
                f"Command is running in background session {session_id}. "
                "Use monitoring_get_session, monitoring_read_output, or monitoring_terminate_session."
            ),
        )

    def read_output_records(
        self,
        session_id: str,
        *,
        start_line: int | None = None,
        limit: int | None = None,
        tail: int | None = None,
    ) -> list[dict[str, Any]]:
        with SessionLocal() as db:
            session = db.get(CommandSession, session_id)
            if session is None:
                raise HTTPException(status_code=404, detail="Command session not found")
            path = Path(session.output_path)
        if not path.exists():
            return []
        records = []
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                try:
                    records.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        if tail is not None:
            return records[-max(0, int(tail)) :]
        start = max(1, int(start_line or 1))
        bounded_limit = max(1, min(int(limit or 200), 1000))
        return [record for record in records if int(record.get("line", 0)) >= start][:bounded_limit]

    def output_window(
        self,
        db: Session,
        *,
        session: CommandSession,
        start_line: int | None,
        limit: int | None,
        tail: int | None,
        owner_subject: str,
        reason: str | None = None,
        tool_call_id: str | None = None,
    ) -> dict[str, Any]:
        records = self.read_output_records(session.id, start_line=start_line, limit=limit, tail=tail)
        if records and reason:
            self.record_delivery(
                db,
                session_id=session.id,
                owner_subject=owner_subject,
                reason=reason,
                start_line=int(records[0]["line"]),
                end_line=int(records[-1]["line"]),
                tool_call_id=tool_call_id,
            )
        markers = self.delivery_markers(db, session.id)
        lines = [self._line_with_markers(record, markers) for record in records]
        return {
            "session_id": session.id,
            "start_line": int(records[0]["line"]) if records else 0,
            "end_line": int(records[-1]["line"]) if records else 0,
            "total_lines": session.line_count,
            "lines": lines,
        }

    def _line_with_markers(self, record: dict[str, Any], markers: dict[int, set[str]]) -> dict[str, Any]:
        line = int(record.get("line", 0))
        reasons = markers.get(line, set())
        return {
            "line": line,
            "stream": str(record.get("stream", "stdout")),
            "text": str(record.get("text", "")),
            "timestamp": record.get("timestamp"),
            "auto_sent": "auto_tail" in reasons,
            "agent_requested": "explicit_read" in reasons,
        }

    def record_delivery(
        self,
        db: Session,
        *,
        session_id: str,
        owner_subject: str,
        reason: str,
        start_line: int,
        end_line: int,
        tool_call_id: str | None,
    ) -> None:
        if start_line <= 0 or end_line <= 0:
            return
        db.add(
            CommandSessionDelivery(
                id=str(uuid.uuid4()),
                session_id=session_id,
                owner_subject=owner_subject,
                reason=reason,
                start_line=start_line,
                end_line=end_line,
                tool_call_id=tool_call_id,
            )
        )
        db.commit()

    def delivery_markers(self, db: Session, session_id: str) -> dict[int, set[str]]:
        markers: dict[int, set[str]] = {}
        deliveries = db.query(CommandSessionDelivery).filter(CommandSessionDelivery.session_id == session_id).all()
        for delivery in deliveries:
            for line in range(delivery.start_line, delivery.end_line + 1):
                markers.setdefault(line, set()).add(delivery.reason)
        return markers

    def background_tails(self, db: Session, *, owner_subject: str, tool_call_id: str | None) -> list[dict[str, Any]]:
        sessions = (
            db.query(CommandSession)
            .filter(CommandSession.owner_subject == owner_subject)
            .filter(CommandSession.status.in_(list(ACTIVE_STATUSES | TERMINAL_STATUSES)))
            .order_by(CommandSession.updated_at.desc())
            .limit(20)
            .all()
        )
        tails: list[dict[str, Any]] = []
        for session in sessions:
            already_reported = bool((session.meta or {}).get("terminal_tail_reported"))
            if session.status in TERMINAL_STATUSES and already_reported:
                continue
            records = self.read_output_records(session.id, tail=5)
            if records:
                self.record_delivery(
                    db,
                    session_id=session.id,
                    owner_subject=owner_subject,
                    reason="auto_tail",
                    start_line=int(records[0]["line"]),
                    end_line=int(records[-1]["line"]),
                    tool_call_id=tool_call_id,
                )
            tails.append(
                {
                    "session_id": session.id,
                    "name": session.name,
                    "origin": session.origin,
                    "status": session.status,
                    "command": session.command,
                    "line_count": session.line_count,
                    "lines": [
                        {
                            **self._line_with_markers(record, {}),
                            "auto_sent": True,
                            "agent_requested": False,
                        }
                        for record in records
                    ],
                }
            )
            if session.status in TERMINAL_STATUSES:
                session.meta = {**(session.meta or {}), "terminal_tail_reported": True}
        db.commit()
        return tails

    async def terminate(self, db: Session, *, session: CommandSession, force: bool) -> CommandSession:
        if session.status in TERMINAL_STATUSES:
            return session
        running = self._processes.get(session.id)
        if running:
            try:
                if force:
                    os.killpg(os.getpgid(running.process.pid), signal.SIGKILL)
                else:
                    os.killpg(os.getpgid(running.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError:
                if force:
                    running.process.kill()
                else:
                    running.process.terminate()
        session.status = "terminated"
        session.completed_at = utcnow()
        session.updated_at = utcnow()
        db.flush()
        db.refresh(session)
        emit_event(
            db,
            event_type="gateway.command_session.terminated.v1",
            actor_subject=session.owner_subject,
            action="terminated",
            resource_type="command_session",
            resource_id=session.id,
            payload={"session_id": session.id, "force": force},
            commit=False,
        )
        db.commit()
        return session


monitoring_service = MonitoringService()
