from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from gateway_api.agent_autonomy import agent_autonomy_service
from gateway_api.config import Settings
from gateway_api.models import (
    AccessGrant,
    ApprovalRequest,
    Base,
    McpActionPreparation,
    McpServer,
    McpTool,
    McpToolRevision,
    User,
    utcnow,
)
from gateway_api.obsidian_research_provider import (
    ObsidianConflictError,
    ObsidianProviderSettings,
    ObsidianVaultStore,
)
from gateway_api.research_knowledge_contract import (
    ResearchLink,
    ResearchSourceReference,
    render_note_link,
    render_source_reference,
)
from gateway_api.research_write_approval import ResearchWriteApprovalWorker
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def test_provider_neutral_link_and_source_rendering_is_versioned_and_visible() -> None:
    link = render_note_link(
        ResearchLink(
            target_note_id="note-2",
            target_url="obsidian://open?vault=Research&file=note-2",
            label="Related -- note",
        )
    )
    assert link.startswith("<!-- research-link:v1 ")
    link_comment = link.splitlines()[0]
    assert "--" not in link_comment.removeprefix("<!--").removesuffix("-->")
    assert "\\u002d\\u002d" in link_comment
    link_payload = json.loads(
        link_comment.removeprefix("<!-- research-link:v1 ").removesuffix(" -->")
    )
    assert link_payload["label"] == "Related -- note"
    assert "[Related -- note](obsidian://open?vault=Research&file=note-2)" in link

    source = render_source_reference(
        ResearchSourceReference(
            url="https://example.test/paper",
            title="Paper -- draft",
            locator="p. -- 12",
        )
    )
    assert source.startswith("<!-- research-source:v1 ")
    source_comment = source.splitlines()[0]
    assert "\\u002d\\u002d" in source_comment
    source_payload = json.loads(
        source_comment.removeprefix("<!-- research-source:v1 ").removesuffix(" -->")
    )
    assert source_payload["title"] == "Paper -- draft"
    assert source_payload["locator"] == "p. -- 12"
    assert "[Paper -- draft](https://example.test/paper) — p. -- 12" in source

    with pytest.raises(ValueError, match="scheme"):
        render_source_reference(
            ResearchSourceReference(url="file:///etc/passwd", title="unsafe")
        )


def _obsidian_store(tmp_path: Path) -> ObsidianVaultStore:
    vault = tmp_path / "vault"
    (vault / "Research").mkdir(parents=True)
    return ObsidianVaultStore(
        ObsidianProviderSettings(
            vault_root=str(vault),
            vault_name="Research Vault",
            allowed_prefixes="Research",
            default_folder="Research",
            access_mode="read_write",
            internal_bearer_token="provider-token",
            auth_issuer_url="http://provider.internal",
            auth_resource_url="http://provider.internal:8011",
        )
    )


def test_obsidian_store_is_confined_atomic_cas_and_replay_safe(tmp_path: Path) -> None:
    store = _obsidian_store(tmp_path)
    lock_path = tmp_path / "vault" / ".gateway-research.lock"
    assert lock_path.exists() is False
    note, replayed = store.create("Fixture", "first", "create-key")
    assert lock_path.is_file()
    assert lock_path.stat().st_mode & 0o777 == 0o600
    assert replayed is False
    replay, replayed = store.create("Fixture", "first", "create-key")
    assert replayed is True
    assert replay.note_id == note.note_id

    updated, replayed = store.update_content(note.note_id, "second", note.content_hash)
    assert replayed is False
    same, replayed = store.update_content(note.note_id, "second", note.content_hash)
    assert replayed is True
    assert same.content_hash == updated.content_hash
    with pytest.raises(ObsidianConflictError) as conflict:
        store.update_content(note.note_id, "stale overwrite", note.content_hash)
    assert conflict.value.code == "DOCUMENT_CONTENT_CONFLICT"
    assert store.read(note.note_id).content == "second"

    appended, replayed = store.append(
        note.note_id, "third", updated.content_hash, "append-key"
    )
    assert replayed is False
    replay, replayed = store.append(
        note.note_id, "third", updated.content_hash, "append-key"
    )
    assert replayed is True
    assert replay.content_hash == appended.content_hash
    assert replay.content.count("third") == 1

    before_tags = store.read(note.note_id)
    tagged, replayed = store.set_tags(
        note.note_id, ["ML", "Research", "ml"], before_tags.tags_hash
    )
    assert replayed is False
    assert tagged.tags == ["ML", "Research"]
    same_tags, replayed = store.set_tags(
        note.note_id, ["ML", "Research"], before_tags.tags_hash
    )
    assert replayed is True
    assert same_tags.tags_hash == tagged.tags_hash
    with pytest.raises(ObsidianConflictError) as tags_conflict:
        store.set_tags(note.note_id, ["Agents"], before_tags.tags_hash)
    assert tags_conflict.value.code == "DOCUMENT_TAGS_CONFLICT"

    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    escape = tmp_path / "vault" / "Research" / "escape.md"
    try:
        escape.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")
    with pytest.raises(ValueError, match="escapes"):
        store.read("Research/escape.md")


def test_obsidian_store_requires_existing_default_folder(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    settings = ObsidianProviderSettings(
        vault_root=str(vault),
        vault_name="Research Vault",
        allowed_prefixes="Research",
        default_folder="Research",
        access_mode="read_only",
        internal_bearer_token="provider-token",
        auth_issuer_url="http://provider.internal",
        auth_resource_url="http://provider.internal:8011",
    )
    with pytest.raises(RuntimeError, match="DEFAULT_FOLDER must resolve"):
        ObsidianVaultStore(settings)


def _worker_db() -> tuple[Session, sessionmaker]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return factory(), factory


class _VoteRecorder:
    def __init__(self, *, autonomy_enabled: bool = True) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.autonomy_enabled = autonomy_enabled

    def control_snapshot(
        self,
        db: Session,
        *,
        owner_subject: str,
        room_id: str | None = None,
        policy_id: str | None = None,
    ) -> dict[str, object]:
        del db, owner_subject, room_id, policy_id
        return {
            "enabled": self.autonomy_enabled,
            "effective_state": "enabled" if self.autonomy_enabled else "killed",
        }

    def cast_vote(
        self,
        db: Session,
        *,
        request_id: str,
        user: User,
        decision: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        assert user.roles == ["gateway-user"]
        self.calls.append((request_id, decision, reason or ""))
        request = db.get(ApprovalRequest, request_id)
        assert request is not None
        request.status = "approved"
        return request


def _seed_research_approval(
    db: Session,
    *,
    tool_name: str,
    grant_status: str | None = "active",
) -> str:
    owner = "research-writer-owner"
    request_id = "approval-1"
    server_id = "server-affine"
    tool_id = "tool-1"
    revision_id = "revision-1"
    schema_hash = "a" * 64
    db.add(
        User(
            id=1,
            subject="research-approver",
            username="research-approver",
            roles=["gateway-user"],
        )
    )
    db.add(
        McpServer(
            id=server_id,
            owner_subject=owner,
            origin="gateway",
            display_name="AFFiNE research",
            normalized_slug="affine-research",
            transport="streamable_http",
            endpoint_url="http://affine-research-provider:8010/mcp",
            status="online",
            trust_level="restricted",
        )
    )
    db.add(
        McpTool(
            id=tool_id,
            owner_subject=owner,
            server_id=server_id,
            upstream_name=tool_name,
            normalized_name=tool_name,
            lifecycle_state="active",
            current_revision_id=revision_id,
        )
    )
    db.add(
        McpToolRevision(
            id=revision_id,
            owner_subject=owner,
            server_id=server_id,
            tool_id=tool_id,
            revision_number=1,
            input_schema={"type": "object"},
            schema_hash=schema_hash,
            catalog_generation=1,
            action_class="write",
            read_only_status="rejected",
        )
    )
    expires = utcnow() + timedelta(minutes=10)
    db.add(
        ApprovalRequest(
            id=request_id,
            owner_subject=owner,
            room_id="room-1",
            policy_id="policy-1",
            executor_agent_id="executor-1",
            action_kind="mcp_federation_action",
            action_class="write",
            tool="mcp_action_execute",
            payload_hash="b" * 64,
            quorum_required=1,
            require_admin_approval=False,
            disallow_proposer_vote=True,
            status="pending",
            policy_generation=1,
            created_by_subject="system:research-writer-owner",
            expires_at=expires,
        )
    )
    db.add(
        McpActionPreparation(
            id="preparation-1",
            owner_subject=owner,
            actor_subject=owner,
            server_id=server_id,
            tool_id=tool_id,
            revision_id=revision_id,
            schema_hash=schema_hash,
            action_class="write",
            arguments_secret_id="secret-1",
            arguments_redacted={},
            arguments_sha256="c" * 64,
            justification="research update",
            preview={},
            approval_class="operator",
            exposure_id="exposure-1",
            exposure_version=1,
            federation_policy_id="federation-policy-1",
            federation_policy_generation=1,
            autonomy_policy_id="policy-1",
            autonomy_policy_generation=1,
            command_id="command-1",
            executor_agent_id="executor-1",
            approval_request_id=request_id,
            status="pending_approval",
            idempotency_key="prepare-key",
            expires_at=expires,
        )
    )
    if grant_status is not None:
        db.add(
            AccessGrant(
                id="research-approval-grant-1",
                owner_subject=owner,
                grantee_subject="research-approver",
                resource_type="autonomy_approval",
                resource_id="policy-1",
                scopes=["approve"],
                status=grant_status,
            )
        )
    db.commit()
    return request_id


def test_affine_approval_review_projection_uses_canonical_preparation_identity() -> None:
    db, _ = _worker_db()
    request_id = _seed_research_approval(
        db, tool_name="research_v1_document_append"
    )
    request = db.get(ApprovalRequest, request_id)
    reviewer = db.query(User).filter(User.subject == "research-approver").one()
    assert request is not None

    projection = agent_autonomy_service.approval_review_projection(
        db, request=request, user=reviewer
    )
    assert projection["surface"] == "affine"
    assert projection["authorized"] is True
    assert projection["can_vote"] is False
    assert (
        projection["reason"]
        == "AFFiNE-targeted approvals are reviewed in AFFiNE Notifications"
    )
    assert projection["target"] == {
        "kind": "mcp_federation",
        "provider": "affine",
        "review_surface": "affine",
        "preparation_id": "preparation-1",
        "server_id": "server-affine",
        "tool_id": "tool-1",
        "revision_id": "revision-1",
        "server_name": "AFFiNE research",
        "tool_name": "research_v1_document_append",
    }

    server = db.get(McpServer, "server-affine")
    assert server is not None
    server.endpoint_url = "https://unrelated.example.test/mcp"
    db.commit()
    non_affine = agent_autonomy_service.approval_review_projection(
        db, request=request, user=reviewer
    )
    assert non_affine["surface"] == "gateway"
    assert non_affine["can_vote"] is True
    assert non_affine["target"]["provider"] == "mcp"
    assert non_affine["target"]["server_name"] == "AFFiNE research"
    db.close()


def _unattended_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "gateway_autonomy_enabled": True,
        "gateway_autonomy_emergency_stop": False,
        "gateway_mcp_federation_writes_paused": False,
        "gateway_research_persistent_writes_enabled": True,
        "gateway_research_unattended_approval_enabled": True,
        "gateway_research_unattended_approver_subject": "research-approver",
        "gateway_research_unattended_allowed_server_ids": "server-affine",
        "gateway_research_unattended_allowed_tools": "research_v1_document_append",
    }
    values.update(overrides)
    return Settings(**values)


def test_unattended_worker_only_votes_for_exact_allowlisted_research_write() -> None:
    db, factory = _worker_db()
    recorder = _VoteRecorder()
    request_id = _seed_research_approval(db, tool_name="research_v1_document_append")
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=True,
        gateway_research_unattended_approver_subject="research-approver",
        gateway_research_unattended_allowed_server_ids="server-affine",
        gateway_research_unattended_allowed_tools="research_v1_document_append",
    )
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    assert worker.run_cycle(db) == 1
    assert recorder.calls == [(request_id, "approve", "research-write-allowlist-v1")]


def test_unattended_worker_requires_scoped_access_grant_with_real_service() -> None:
    db, factory = _worker_db()
    request_id = _seed_research_approval(
        db, tool_name="research_v1_document_append", grant_status=None
    )
    request = db.get(ApprovalRequest, request_id)
    assert request is not None
    request.command_id = None
    db.commit()

    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=True,
        gateway_research_unattended_approver_subject="research-approver",
        gateway_research_unattended_allowed_server_ids="server-affine",
        gateway_research_unattended_allowed_tools="research_v1_document_append",
    )
    worker = ResearchWriteApprovalWorker(
        service=agent_autonomy_service,
        session_factory=factory,
        settings=settings,
    )

    assert worker.run_cycle(db) == 0
    request = db.get(ApprovalRequest, request_id)
    assert request is not None and request.status == "pending"

    db.add(
        AccessGrant(
            id="research-approval-grant-1",
            owner_subject="research-writer-owner",
            grantee_subject="research-approver",
            resource_type="autonomy_approval",
            resource_id=request_id,
            scopes=["approve"],
            status="active",
        )
    )
    db.commit()

    assert worker.run_cycle(db) == 1
    request = db.get(ApprovalRequest, request_id)
    assert request is not None and request.status == "approved"


def test_unattended_worker_skips_revoked_access_grant() -> None:
    db, factory = _worker_db()
    _seed_research_approval(
        db,
        tool_name="research_v1_document_append",
        grant_status="revoked",
    )
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_wrong_federation_owner() -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    server = db.get(McpServer, "server-affine")
    assert server is not None
    server.owner_subject = "other-owner"
    db.commit()
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_server_outside_allowlist() -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(
            gateway_research_unattended_allowed_server_ids="other-server"
        ),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_tool_outside_allowlist() -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(
            gateway_research_unattended_allowed_tools="research_v1_document_set_tags"
        ),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_schema_drift() -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    revision = db.get(McpToolRevision, "revision-1")
    assert revision is not None
    revision.schema_hash = "d" * 64
    db.commit()
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_policy_generation_drift() -> None:
    db, factory = _worker_db()
    request_id = _seed_research_approval(db, tool_name="research_v1_document_append")
    request = db.get(ApprovalRequest, request_id)
    assert request is not None
    request.policy_generation = 2
    db.commit()
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_unattended_worker_skips_dynamic_autonomy_kill() -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    recorder = _VoteRecorder(autonomy_enabled=False)
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"gateway_mcp_federation_writes_paused": True},
        {"gateway_autonomy_emergency_stop": True},
    ],
)
def test_unattended_worker_static_kill_switches_never_vote(
    overrides: dict[str, object],
) -> None:
    db, factory = _worker_db()
    _seed_research_approval(db, tool_name="research_v1_document_append")
    recorder = _VoteRecorder()
    worker = ResearchWriteApprovalWorker(
        service=recorder,  # type: ignore[arg-type]
        session_factory=factory,
        settings=_unattended_settings(**overrides),
    )
    assert worker.run_cycle(db) == 0
    assert recorder.calls == []


def test_persistent_write_configuration_is_fail_closed() -> None:
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_mcp_federation_writes_paused=True,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=False,
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    with pytest.raises(RuntimeError, match="explicitly unpaused"):
        worker._validate_configuration()


def test_persistent_operator_write_configuration_does_not_require_unattended() -> None:
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=False,
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    worker._validate_configuration()


def test_unattended_configuration_requires_persistent_write_mode() -> None:
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=False,
        gateway_research_unattended_approval_enabled=True,
        gateway_research_unattended_approver_subject="research-approver",
        gateway_research_unattended_allowed_server_ids="server-affine",
        gateway_research_unattended_allowed_tools="research_v1_document_append",
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    with pytest.raises(RuntimeError, match="requires persistent research writes"):
        worker._validate_configuration()


def test_unattended_configuration_requires_explicit_tool_allowlist() -> None:
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=True,
        gateway_research_unattended_approver_subject="research-approver",
        gateway_research_unattended_allowed_server_ids="server-affine",
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    with pytest.raises(RuntimeError, match="exact tool allowlist"):
        worker._validate_configuration()


def test_unattended_configuration_rejects_non_research_write_tool() -> None:
    settings = Settings(
        gateway_autonomy_enabled=True,
        gateway_autonomy_emergency_stop=False,
        gateway_mcp_federation_writes_paused=False,
        gateway_research_persistent_writes_enabled=True,
        gateway_research_unattended_approval_enabled=True,
        gateway_research_unattended_approver_subject="research-approver",
        gateway_research_unattended_allowed_server_ids="server-affine",
        gateway_research_unattended_allowed_tools="dangerous_arbitrary_write",
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    with pytest.raises(RuntimeError, match="unsupported tools"):
        worker._validate_configuration()


def test_unattended_configuration_rejects_destructive_document_purge() -> None:
    settings = _unattended_settings(
        gateway_research_unattended_allowed_tools="research_v1_document_purge"
    )
    _, factory = _worker_db()
    worker = ResearchWriteApprovalWorker(
        service=SimpleNamespace(),  # type: ignore[arg-type]
        session_factory=factory,
        settings=settings,
    )
    with pytest.raises(RuntimeError, match="unsupported tools"):
        worker._validate_configuration()
