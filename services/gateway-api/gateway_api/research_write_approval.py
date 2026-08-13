from __future__ import annotations

import asyncio
import logging
from datetime import UTC

from sqlalchemy.orm import Session, sessionmaker

from .agent_autonomy import AgentAutonomyService, agent_autonomy_service
from .config import Settings
from .models import (
    ApprovalRequest,
    McpActionPreparation,
    McpServer,
    McpTool,
    McpToolRevision,
    User,
    utcnow,
)

logger = logging.getLogger(__name__)

SAFE_RESEARCH_WRITE_TOOLS = frozenset(
    {
        "research_v1_note_create",
        "research_v1_note_update_content",
        "research_v1_note_append",
        "research_v1_note_set_tags",
        "research_v1_note_link",
        "research_v1_note_add_source",
        "research_v1_note_update_title",
    }
)


class ResearchWriteApprovalWorker:
    def __init__(
        self,
        *,
        service: AgentAutonomyService = agent_autonomy_service,
        session_factory: sessionmaker,
        settings: Settings,
    ) -> None:
        self.service = service
        self.session_factory = session_factory
        self.settings = settings
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @staticmethod
    def _csv(value: str) -> set[str]:
        return {item.strip() for item in value.split(",") if item.strip()}

    def _validate_configuration(self) -> None:
        if self.settings.gateway_research_persistent_writes_enabled:
            if not self.settings.gateway_research_unattended_approval_enabled:
                raise RuntimeError(
                    "persistent research writes require unattended approval to remain fenced"
                )
            if self.settings.gateway_mcp_federation_writes_paused:
                raise RuntimeError(
                    "persistent research writes require federation writes to be explicitly unpaused"
                )
            if not self.settings.gateway_autonomy_enabled:
                raise RuntimeError(
                    "persistent research writes require the autonomy control plane"
                )
        if not self.settings.gateway_research_unattended_approval_enabled:
            return
        if not self.settings.gateway_autonomy_enabled:
            raise RuntimeError(
                "unattended research approval requires GATEWAY_AUTONOMY_ENABLED"
            )
        if not self.settings.gateway_research_unattended_approver_subject.strip():
            raise RuntimeError(
                "unattended research approval requires an explicit approver subject"
            )
        if not self._csv(self.settings.gateway_research_unattended_allowed_server_ids):
            raise RuntimeError(
                "unattended research approval requires an exact MCP server allowlist"
            )
        allowed_tools = self._csv(
            self.settings.gateway_research_unattended_allowed_tools
        )
        if not allowed_tools:
            raise RuntimeError(
                "unattended research approval requires an exact tool allowlist"
            )
        unsupported_tools = allowed_tools - SAFE_RESEARCH_WRITE_TOOLS
        if unsupported_tools:
            raise RuntimeError(
                "unattended research approval tool allowlist contains unsupported tools: "
                + ",".join(sorted(unsupported_tools))
            )

    async def start(self) -> None:
        self._validate_configuration()
        self._stopping.clear()
        if self.settings.gateway_research_unattended_approval_enabled:
            self._task = asyncio.create_task(
                self._run(), name="gateway-research-write-approval-worker"
            )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def _approver(self, db: Session) -> User:
        subject = self.settings.gateway_research_unattended_approver_subject.strip()
        user = db.query(User).filter(User.subject == subject).one_or_none()
        if user is None:
            raise RuntimeError("configured research approver user does not exist")
        roles = set(user.roles or [])
        if "gateway-user" not in roles or "gateway-admin" in roles:
            raise RuntimeError(
                "research approver must be a non-admin gateway-user service principal"
            )
        return user

    def _eligible(
        self,
        db: Session,
        *,
        request: ApprovalRequest,
        allowed_servers: set[str],
        allowed_tools: set[str],
    ) -> bool:
        if request.action_kind != "mcp_federation_action":
            return False
        if request.action_class != "write" or request.require_admin_approval:
            return False
        if request.status != "pending":
            return False
        now = utcnow()
        expires_at = request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            return False

        preparation = (
            db.query(McpActionPreparation)
            .filter(McpActionPreparation.approval_request_id == request.id)
            .one_or_none()
        )
        if preparation is None:
            return False
        prep_expires = preparation.expires_at
        if prep_expires.tzinfo is None:
            prep_expires = prep_expires.replace(tzinfo=UTC)
        if preparation.status != "pending_approval" or prep_expires <= now:
            return False
        if preparation.action_class != "write" or preparation.approval_class != "operator":
            return False
        if preparation.owner_subject != request.owner_subject:
            return False
        if preparation.server_id not in allowed_servers:
            return False

        server = db.get(McpServer, preparation.server_id)
        tool = db.get(McpTool, preparation.tool_id)
        revision = db.get(McpToolRevision, preparation.revision_id)
        if server is None or tool is None or revision is None:
            return False
        if server.status not in {"online", "degraded"}:
            return False
        if server.trust_level not in {"restricted", "approved"}:
            return False
        if tool.server_id != server.id or tool.lifecycle_state != "active":
            return False
        if tool.upstream_name not in allowed_tools:
            return False
        if tool.current_revision_id != revision.id:
            return False
        if revision.tool_id != tool.id or revision.server_id != server.id:
            return False
        if revision.action_class != "write" or revision.read_only_status != "rejected":
            return False
        if revision.schema_hash != preparation.schema_hash:
            return False
        return (
            preparation.tool_id == tool.id
            and preparation.revision_id == revision.id
        )

    def run_cycle(self, db: Session) -> int:
        if not self.settings.gateway_research_unattended_approval_enabled:
            return 0
        if self.settings.gateway_mcp_federation_writes_paused:
            return 0
        if self.settings.gateway_autonomy_emergency_stop:
            return 0

        approver = self._approver(db)
        allowed_servers = self._csv(
            self.settings.gateway_research_unattended_allowed_server_ids
        )
        allowed_tools = self._csv(
            self.settings.gateway_research_unattended_allowed_tools
        )
        batch_size = max(
            1, min(100, int(self.settings.gateway_research_unattended_batch_size))
        )
        requests = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.status == "pending",
                ApprovalRequest.action_kind == "mcp_federation_action",
                ApprovalRequest.action_class == "write",
            )
            .order_by(ApprovalRequest.created_at, ApprovalRequest.id)
            .limit(batch_size)
            .all()
        )
        approved = 0
        for request in requests:
            if not self._eligible(
                db,
                request=request,
                allowed_servers=allowed_servers,
                allowed_tools=allowed_tools,
            ):
                continue
            self.service.cast_vote(
                db,
                request_id=request.id,
                user=approver,
                decision="approve",
                reason="research-write-allowlist-v1",
            )
            db.commit()
            approved += 1
        return approved

    async def _run(self) -> None:
        interval = max(
            0.25,
            float(self.settings.gateway_research_unattended_poll_interval_seconds),
        )
        while not self._stopping.is_set():
            try:
                with self.session_factory() as db:
                    await asyncio.to_thread(self.run_cycle, db)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("research_write_approval_cycle_failed")
            await asyncio.sleep(interval)
