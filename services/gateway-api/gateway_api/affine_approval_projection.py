from __future__ import annotations

import hashlib
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .affine_approval_delegation import (
    AffineApprovalDelegationConfig,
    reviewer_bindings,
)
from .config import Settings, get_settings
from .events import emit_event
from .models import (
    AccessGrant,
    ActionReceipt,
    ApprovalRequest,
    ApprovalVote,
    McpActionPreparation,
    McpServer,
    McpTool,
    User,
)

AFFINE_APPROVAL_PROJECTION_EVENT_TYPE = "gateway.affine.approval.projected.v1"
AFFINE_APPROVAL_PROJECTION_SCHEMA_VERSION = "1.0"


class AffineApprovalProjectionConfig(BaseModel):
    """Typed runtime configuration for the AFFiNE approval event projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    server_endpoint: str = Field(min_length=1)
    preview_max_chars: int = Field(default=1200, ge=128, le=8000)
    preview_max_items: int = Field(default=20, ge=1, le=100)
    reviewer_max_subjects: int = Field(default=100, ge=1, le=500)

    @classmethod
    def from_settings(cls, settings: Settings) -> AffineApprovalProjectionConfig:
        config = cls(
            enabled=settings.gateway_affine_approval_projection_enabled,
            server_endpoint=settings.gateway_affine_approval_server_endpoint,
            preview_max_chars=settings.gateway_affine_approval_preview_max_chars,
            preview_max_items=settings.gateway_affine_approval_preview_max_items,
            reviewer_max_subjects=settings.gateway_affine_approval_reviewer_max_subjects,
        )
        if config.enabled and not settings.gateway_outbox_enabled:
            raise RuntimeError(
                "AFFiNE approval projection requires the transactional outbox"
            )
        return config


class AffineApprovalPreview(BaseModel):
    """Bounded, display-safe preview copied into AFFiNE notification state."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "create",
        "content_replace",
        "content_append",
        "tags_replace",
        "link_add",
        "source_add",
        "title_update",
        "lifecycle",
    ]
    summary: str = Field(max_length=240)
    before_text: str | None = Field(default=None, max_length=8000)
    after_text: str | None = Field(default=None, max_length=8000)
    before_hash: str | None = Field(default=None, max_length=128)
    after_hash: str | None = Field(default=None, max_length=128)
    items: list[str] = Field(default_factory=list, max_length=100)
    target_workspace_id: str | None = Field(default=None, max_length=160)
    target_document_id: str | None = Field(default=None, max_length=160)
    source_url: str | None = Field(default=None, max_length=2048)
    source_title: str | None = Field(default=None, max_length=8000)
    lifecycle_from: str | None = Field(default=None, max_length=40)
    lifecycle_to: str | None = Field(default=None, max_length=40)
    truncated: bool = False


class AffineApprovalResultProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str
    status: Literal["succeeded", "failed", "partial", "unknown"]
    invocation_id: str | None = None


class AffineApprovalReviewerBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gateway_subject: str = Field(min_length=1, max_length=255)
    affine_user_id: str = Field(min_length=1, max_length=160)


class AffineApprovalProjectionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = AFFINE_APPROVAL_PROJECTION_SCHEMA_VERSION
    projection_kind: Literal["approval_requested", "approval_updated", "action_result"]
    approval_request_id: str
    approval_version: int = Field(ge=1)
    preparation_id: str
    owner_subject: str
    actor_subject: str
    server_id: str
    tool_id: str
    revision_id: str
    schema_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_name: str
    action_class: Literal["write", "destructive", "production"]
    approval_class: Literal["operator", "quorum", "production"]
    workspace_id: str
    document_id: str | None = None
    status: Literal["pending", "approved", "rejected", "expired", "revoked"]
    quorum_required: int = Field(ge=0)
    approve_count: int = Field(ge=0)
    reject_count: int = Field(ge=0)
    admin_required: bool
    admin_approve_count: int = Field(ge=0)
    disallow_proposer_vote: bool
    eligible_reviewer_subjects: list[str] = Field(default_factory=list, max_length=500)
    eligible_reviewer_bindings: list[AffineApprovalReviewerBinding] = Field(
        default_factory=list, max_length=500
    )
    unmapped_reviewer_count: int = Field(default=0, ge=0)
    eligible_reviewers_truncated: bool = False
    expires_at: str
    preview: AffineApprovalPreview
    result: AffineApprovalResultProjection | None = None



def approval_user_can_vote(
    db: Session, *, request: ApprovalRequest, user: User
) -> bool:
    roles = set(user.roles or [])
    if user.subject == request.owner_subject or "gateway-admin" in roles:
        return True
    grant = (
        db.query(AccessGrant)
        .filter(
            AccessGrant.owner_subject == request.owner_subject,
            AccessGrant.grantee_subject == user.subject,
            AccessGrant.resource_type == "autonomy_approval",
            AccessGrant.resource_id.in_([request.id, request.policy_id, request.room_id]),
            AccessGrant.status == "active",
        )
        .first()
    )
    return bool(grant and "approve" in set(grant.scopes or []))


def eligible_approval_reviewer_subjects(
    db: Session,
    *,
    request: ApprovalRequest,
    votes: list[ApprovalVote],
    maximum: int,
) -> tuple[list[str], bool]:
    if request.status != "pending":
        return [], False
    voted = {vote.voter_subject for vote in votes}
    candidates: list[User] = []
    owner = db.query(User).filter(User.subject == request.owner_subject).one_or_none()
    if owner is not None:
        candidates.append(owner)
    grant_subjects = {
        grant.grantee_subject
        for grant in db.query(AccessGrant)
        .filter(
            AccessGrant.owner_subject == request.owner_subject,
            AccessGrant.resource_type == "autonomy_approval",
            AccessGrant.resource_id.in_([request.id, request.policy_id, request.room_id]),
            AccessGrant.status == "active",
        )
        .all()
        if "approve" in set(grant.scopes or [])
    }
    if grant_subjects:
        candidates.extend(
            db.query(User).filter(User.subject.in_(sorted(grant_subjects))).all()
        )
    candidates.extend(
        user for user in db.query(User).all() if "gateway-admin" in set(user.roles or [])
    )
    subjects: list[str] = []
    seen: set[str] = set()
    for user in sorted(candidates, key=lambda item: item.subject):
        if user.subject in seen or user.subject in voted:
            continue
        if request.disallow_proposer_vote and user.subject == request.created_by_subject:
            continue
        if not approval_user_can_vote(db, request=request, user=user):
            continue
        seen.add(user.subject)
        subjects.append(user.subject)
    truncated = len(subjects) > maximum
    return subjects[:maximum], truncated

def is_affine_research_server(
    server: McpServer | None, *, config: AffineApprovalProjectionConfig
) -> bool:
    return bool(
        server is not None
        and server.origin == "gateway"
        and server.transport == "streamable_http"
        and str(server.endpoint_url or "").rstrip("/")
        == config.server_endpoint.rstrip("/")
    )


def _bounded_text(value: Any, *, maximum: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    text = str(value)
    if len(text) <= maximum:
        return text, False
    return text[:maximum], True


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _content_hash(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_affine_approval_preview(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    config: AffineApprovalProjectionConfig,
) -> AffineApprovalPreview | None:
    max_chars = config.preview_max_chars
    max_items = config.preview_max_items

    if tool_name == "research_v1_document_create":
        after, truncated = _bounded_text(arguments.get("content"), maximum=max_chars)
        title, title_truncated = _bounded_text(arguments.get("title"), maximum=max_chars)
        return AffineApprovalPreview(
            kind="create",
            summary="Create document",
            after_text=after,
            after_hash=_content_hash(arguments.get("content")),
            source_title=title,
            truncated=truncated or title_truncated,
        )

    if tool_name == "research_v1_document_update_content":
        after, truncated = _bounded_text(arguments.get("content"), maximum=max_chars)
        return AffineApprovalPreview(
            kind="content_replace",
            summary="Replace document content",
            before_hash=str(arguments.get("expected_content_hash") or "") or None,
            after_text=after,
            after_hash=_content_hash(arguments.get("content")),
            truncated=truncated,
        )

    if tool_name == "research_v1_document_append":
        after, truncated = _bounded_text(arguments.get("content"), maximum=max_chars)
        return AffineApprovalPreview(
            kind="content_append",
            summary="Append document content",
            before_hash=str(arguments.get("expected_content_hash") or "") or None,
            after_text=after,
            after_hash=_content_hash(arguments.get("content")),
            truncated=truncated,
        )

    if tool_name == "research_v1_document_set_tags":
        raw_tags = arguments.get("tags")
        tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
        bounded = tags[:max_items]
        return AffineApprovalPreview(
            kind="tags_replace",
            summary="Replace document tags",
            before_hash=str(arguments.get("expected_tags_hash") or "") or None,
            items=bounded,
            truncated=len(tags) > len(bounded),
        )

    if tool_name == "research_v1_document_link":
        label, truncated = _bounded_text(arguments.get("label"), maximum=max_chars)
        return AffineApprovalPreview(
            kind="link_add",
            summary="Add document link",
            before_hash=str(arguments.get("expected_content_hash") or "") or None,
            after_text=label,
            target_workspace_id=str(arguments.get("target_workspace_id") or "") or None,
            target_document_id=str(arguments.get("target_document_id") or "") or None,
            truncated=truncated,
        )

    if tool_name == "research_v1_document_add_source":
        title, title_truncated = _bounded_text(
            arguments.get("title"), maximum=max_chars
        )
        locator, locator_truncated = _bounded_text(
            arguments.get("locator"), maximum=max_chars
        )
        return AffineApprovalPreview(
            kind="source_add",
            summary="Add source reference",
            before_hash=str(arguments.get("expected_content_hash") or "") or None,
            after_text=locator,
            source_url=_safe_url(arguments.get("url")),
            source_title=title,
            truncated=title_truncated or locator_truncated,
        )

    if tool_name == "research_v1_document_update_title":
        before, before_truncated = _bounded_text(
            arguments.get("expected_title"), maximum=max_chars
        )
        after, after_truncated = _bounded_text(
            arguments.get("title"), maximum=max_chars
        )
        return AffineApprovalPreview(
            kind="title_update",
            summary="Update document title",
            before_text=before,
            after_text=after,
            truncated=before_truncated or after_truncated,
        )

    lifecycle_to = {
        "research_v1_document_trash": "trashed",
        "research_v1_document_restore": "active",
        "research_v1_document_purge": "purged",
    }.get(tool_name)
    if lifecycle_to is not None:
        expected = arguments.get("expected_trash")
        lifecycle_from = "trashed" if expected is True else "active"
        return AffineApprovalPreview(
            kind="lifecycle",
            summary={
                "research_v1_document_trash": "Move document to Trash",
                "research_v1_document_restore": "Restore document from Trash",
                "research_v1_document_purge": "Permanently delete document",
            }[tool_name],
            lifecycle_from=lifecycle_from,
            lifecycle_to=lifecycle_to,
        )

    return None


def decorate_preparation_preview(
    *,
    server: McpServer,
    tool: McpTool,
    arguments: dict[str, Any],
    base_preview: dict[str, Any],
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    config = AffineApprovalProjectionConfig.from_settings(settings)
    preview = dict(base_preview)
    if not is_affine_research_server(server, config=config):
        return preview
    affine_preview = build_affine_approval_preview(
        tool.upstream_name, arguments, config=config
    )
    if affine_preview is None:
        return preview
    preview["affine_approval"] = affine_preview.model_dump(mode="json")
    return preview


def _load_projection_context(
    db: Session,
    request: ApprovalRequest,
    *,
    config: AffineApprovalProjectionConfig,
) -> tuple[McpActionPreparation, McpServer, McpTool] | None:
    preparation = (
        db.query(McpActionPreparation)
        .filter(McpActionPreparation.approval_request_id == request.id)
        .one_or_none()
    )
    if preparation is None:
        return None
    server = db.get(McpServer, preparation.server_id)
    tool = db.get(McpTool, preparation.tool_id)
    if not is_affine_research_server(server, config=config) or tool is None:
        return None
    if "affine_approval" not in dict(preparation.preview or {}):
        return None
    return preparation, server, tool


def is_affine_approval_request(
    db: Session,
    *,
    request: ApprovalRequest,
    settings: Settings | None = None,
) -> bool:
    config = AffineApprovalProjectionConfig.from_settings(settings or get_settings())
    return _load_projection_context(db, request, config=config) is not None


def build_affine_approval_projection(
    db: Session,
    *,
    request: ApprovalRequest,
    projection_kind: Literal[
        "approval_requested", "approval_updated", "action_result"
    ],
    preparation: McpActionPreparation | None = None,
    server: McpServer | None = None,
    tool: McpTool | None = None,
    votes: list[ApprovalVote] | None = None,
    receipt: ActionReceipt | None = None,
    config: AffineApprovalProjectionConfig | None = None,
    delegation_config: AffineApprovalDelegationConfig | None = None,
) -> AffineApprovalProjectionPayload | None:
    config = config or AffineApprovalProjectionConfig.from_settings(get_settings())
    delegation_config = delegation_config or AffineApprovalDelegationConfig.from_settings(
        get_settings()
    )
    if preparation is None or server is None or tool is None:
        context = _load_projection_context(db, request, config=config)
        if context is None:
            return None
        preparation, server, tool = context
    if not is_affine_research_server(server, config=config):
        return None
    stored_preview = dict(preparation.preview or {}).get("affine_approval")
    if not isinstance(stored_preview, dict):
        return None
    preview = AffineApprovalPreview.model_validate(stored_preview)

    if votes is None:
        votes = (
            db.query(ApprovalVote)
            .filter(ApprovalVote.request_id == request.id)
            .order_by(ApprovalVote.created_at, ApprovalVote.id)
            .all()
        )
    approvals = [vote for vote in votes if vote.decision == "approve"]
    rejects = [vote for vote in votes if vote.decision == "reject"]
    admin_approvals = [
        vote
        for vote in approvals
        if "gateway-admin" in set(vote.voter_roles or [])
    ]
    eligible_reviewer_subjects, eligible_reviewers_truncated = (
        eligible_approval_reviewer_subjects(
            db,
            request=request,
            votes=votes,
            maximum=config.reviewer_max_subjects,
        )
    )
    raw_bindings, unmapped_reviewer_count = reviewer_bindings(
        eligible_reviewer_subjects, config=delegation_config
    )
    eligible_reviewer_bindings = [
        AffineApprovalReviewerBinding.model_validate(item) for item in raw_bindings
    ]
    summary = dict(request.payload_summary or {})
    workspace_id = str(summary.get("workspace_id") or "")
    document_id = str(summary.get("document_id") or "") or None

    if not workspace_id:
        workspace_id = str(
            dict(preparation.preview or {}).get("workspace_id") or ""
        )
    if document_id is None:
        document_id = (
            str(dict(preparation.preview or {}).get("document_id") or "") or None
        )
    if not workspace_id:
        return None

    result_projection = None
    if receipt is not None:
        invocation_id = (
            str(dict(receipt.result_summary or {}).get("invocation_id") or "") or None
        )
        result_projection = AffineApprovalResultProjection(
            receipt_id=receipt.id,
            status=receipt.status,
            invocation_id=invocation_id,
        )

    return AffineApprovalProjectionPayload(
        projection_kind=projection_kind,
        approval_request_id=request.id,
        approval_version=max(1, int(request.version or 1)),
        preparation_id=preparation.id,
        owner_subject=request.owner_subject,
        actor_subject=preparation.actor_subject,
        server_id=preparation.server_id,
        tool_id=preparation.tool_id,
        revision_id=preparation.revision_id,
        schema_hash=preparation.schema_hash,
        tool_name=tool.upstream_name,
        action_class=preparation.action_class,
        approval_class=preparation.approval_class,
        workspace_id=workspace_id,
        document_id=document_id,
        status=request.status,
        quorum_required=int(request.quorum_required or 0),
        approve_count=len(approvals),
        reject_count=len(rejects),
        admin_required=bool(request.require_admin_approval),
        admin_approve_count=len(admin_approvals),
        disallow_proposer_vote=bool(request.disallow_proposer_vote),
        eligible_reviewer_subjects=eligible_reviewer_subjects,
        eligible_reviewer_bindings=eligible_reviewer_bindings,
        unmapped_reviewer_count=unmapped_reviewer_count,
        eligible_reviewers_truncated=eligible_reviewers_truncated,
        expires_at=request.expires_at.isoformat(),
        preview=preview,
        result=result_projection,
    )


def emit_affine_approval_projection(
    db: Session,
    *,
    request: ApprovalRequest,
    projection_kind: Literal[
        "approval_requested", "approval_updated", "action_result"
    ],
    actor_subject: str,
    preparation: McpActionPreparation | None = None,
    server: McpServer | None = None,
    tool: McpTool | None = None,
    votes: list[ApprovalVote] | None = None,
    receipt: ActionReceipt | None = None,
    settings: Settings | None = None,
) -> bool:
    settings = settings or get_settings()
    config = AffineApprovalProjectionConfig.from_settings(settings)
    if not config.enabled:
        return False
    delegation_config = AffineApprovalDelegationConfig.from_settings(settings)
    projection = build_affine_approval_projection(
        db,
        request=request,
        projection_kind=projection_kind,
        preparation=preparation,
        server=server,
        tool=tool,
        votes=votes,
        receipt=receipt,
        config=config,
        delegation_config=delegation_config,
    )
    if projection is None:
        return False
    emit_event(
        db,
        event_type=AFFINE_APPROVAL_PROJECTION_EVENT_TYPE,
        actor_subject=actor_subject,
        action=projection_kind,
        resource_type="affine_approval_projection",
        resource_id=request.id,
        owner_subject=request.owner_subject,
        payload=projection.model_dump(mode="json"),
        status=(
            "warning"
            if request.status in {"rejected", "expired", "revoked"}
            or (receipt is not None and receipt.status != "succeeded")
            else "success"
        ),
        commit=False,
    )
    return True
