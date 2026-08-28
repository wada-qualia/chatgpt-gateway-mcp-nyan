from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from gateway_api.chat_context import (
    ChatContextBindingConflict,
    ChatContextDisabled,
    ChatContextNotFound,
    ChatContextService,
)
from gateway_api.config import Settings
from gateway_api.mcp_chat_context import (
    McpChatContextAdmissionError,
    McpChatContextReservedArgumentCollision,
    admit_chat_context,
    chat_context_initialize_metadata,
    decorate_public_tool,
    refresh_chat_context,
    start_chat_context,
)
from gateway_api.mcp_presentation import update_oauth_client_profile
from gateway_api.models import (
    ChatContext,
    ChatContextAlias,
    ChatContextEvent,
    OAuthClient,
)
from gateway_api.schema_migrations import run_schema_migrations
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

TEST_HMAC_KEY = "test-hmac-key-000000000000000000"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 28, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def make_settings(**overrides) -> Settings:
    values = {
        "gateway_chat_context_enabled": True,
        "gateway_chat_context_hmac_key": TEST_HMAC_KEY,
        "gateway_chat_context_ttl_seconds": 300,
        "gateway_chat_context_renew_threshold_seconds": 60,
        "gateway_chat_context_quarantine_seconds": 3600,
        "gateway_chat_context_allocation_attempts": 8,
    }
    values.update(overrides)
    return Settings(**values)


def code_factory(*values: str):
    iterator = iter(values)
    return lambda: next(iterator)


@pytest.fixture()
def db(tmp_path: Path) -> Session:
    engine = create_engine(f"sqlite:///{tmp_path / 'chat-context.sqlite'}")
    run_schema_migrations(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def test_configuration_is_default_off_and_fails_closed() -> None:
    assert Settings().gateway_chat_context_enabled is False
    with pytest.raises(ValueError, match="renew_threshold_seconds"):
        Settings(
            gateway_chat_context_ttl_seconds=300,
            gateway_chat_context_renew_threshold_seconds=300,
        )
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Settings(
            gateway_chat_context_enabled=True,
            gateway_chat_context_hmac_key="short",
        )


def test_disabled_service_refuses_context_creation(db: Session) -> None:
    service = ChatContextService(Settings())

    with pytest.raises(ChatContextDisabled):
        service.start_context(db, owner_subject="owner-a")


def test_provisional_create_is_owner_scoped_and_idempotent(db: Session) -> None:
    clock = Clock()
    first_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("aK7Q"),
    )

    first = first_service.create_provisional(
        db,
        owner_subject="owner-a",
        client_nonce="tab-1",
        project_ref="project-a",
    )
    replay = first_service.create_provisional(
        db,
        owner_subject="owner-a",
        client_nonce="tab-1",
        project_ref="project-a",
    )
    second_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("P8xm"),
    )
    other_owner = second_service.create_provisional(
        db,
        owner_subject="owner-b",
        client_nonce="tab-1",
        project_ref="project-a",
    )

    assert replay.context_id == first.context_id
    assert replay.code == first.code == "aK7Q"
    assert other_owner.context_id != first.context_id
    assert other_owner.code == "P8xm"
    contexts = db.scalars(select(ChatContext)).all()
    aliases = db.scalars(select(ChatContextAlias)).all()
    assert len(contexts) == 2
    assert len(aliases) == 2
    first_events = db.scalars(
        select(ChatContextEvent).where(ChatContextEvent.context_id == first.context_id)
    ).all()
    assert [event.action for event in first_events] == ["created", "issued"]


def test_same_owner_history_is_never_reused_but_other_owner_can_reuse_after_release(
    db: Session,
) -> None:
    clock = Clock()
    owner_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA", "AAAA", "BBBB"),
    )
    first = owner_service.start_context(db, owner_subject="owner-a")
    clock.advance(seconds=4000)

    second = owner_service.start_context(db, owner_subject="owner-a")
    other_owner_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    other_owner = other_owner_service.start_context(db, owner_subject="owner-b")

    assert first.code == "AAAA"
    assert second.code == "BBBB"
    assert second.context_id != first.context_id
    assert other_owner.code == "AAAA"
    historical = db.scalar(
        select(ChatContextAlias).where(
            ChatContextAlias.owner_subject == "owner-a",
            ChatContextAlias.code == "AAAA",
        )
    )
    assert historical is not None
    assert historical.status == "released"


def test_quarantine_blocks_cross_owner_reuse(db: Session) -> None:
    clock = Clock()
    owner_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    first = owner_service.start_context(db, owner_subject="owner-a")
    clock.advance(seconds=301)
    other_owner_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA", "BBBB"),
    )

    other_owner = other_owner_service.start_context(db, owner_subject="owner-b")

    assert other_owner.code == "BBBB"
    historical = db.scalar(
        select(ChatContextAlias).where(ChatContextAlias.id == first.context_id)
    )
    alias = db.scalar(
        select(ChatContextAlias).where(
            ChatContextAlias.owner_subject == "owner-a",
            ChatContextAlias.code == "AAAA",
        )
    )
    assert historical is None
    assert alias is not None
    assert alias.status == "quarantined"


def test_sliding_renewal_keeps_alias_and_generation(db: Session) -> None:
    clock = Clock()
    service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("aK7Q"),
    )
    initial = service.start_context(db, owner_subject="owner-a")
    clock.advance(seconds=250)

    renewed = service.resolve_alias(
        db,
        owner_subject="owner-a",
        code=initial.code,
    )

    assert renewed.code == initial.code
    assert renewed.generation == initial.generation == 1
    assert renewed.expires_at == clock() + timedelta(seconds=300)
    actions = db.scalars(
        select(ChatContextEvent.action).where(
            ChatContextEvent.context_id == initial.context_id
        )
    ).all()
    assert actions == ["created", "issued", "renewed"]


def test_refresh_reactivates_same_alias_during_quarantine(db: Session) -> None:
    clock = Clock()
    service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    initial = service.start_context(db, owner_subject="owner-a")
    clock.advance(seconds=301)

    refreshed = service.refresh_alias(
        db,
        owner_subject="owner-a",
        previous_code=initial.code,
    )

    assert refreshed.code == "AAAA"
    assert refreshed.generation == 1
    assert refreshed.rotated is False
    alias = db.scalar(select(ChatContextAlias).where(ChatContextAlias.code == "AAAA"))
    assert alias is not None
    assert alias.status == "active"
    assert alias.quarantine_until is None


def test_refresh_rotates_on_cross_owner_reuse_without_changing_context(
    db: Session,
) -> None:
    clock = Clock()
    initial_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    initial = initial_service.start_context(db, owner_subject="owner-a")
    clock.advance(seconds=4000)
    other_owner_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    other_owner_service.start_context(db, owner_subject="owner-b")
    recovery_service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("BBBB"),
    )

    refreshed = recovery_service.refresh_alias(
        db,
        owner_subject="owner-a",
        previous_code="AAAA",
    )

    assert refreshed.context_id == initial.context_id
    assert refreshed.code == "BBBB"
    assert refreshed.generation == 2
    assert refreshed.rotated is True
    previous = db.scalar(
        select(ChatContextAlias).where(
            ChatContextAlias.owner_subject == "owner-a",
            ChatContextAlias.code == "AAAA",
        )
    )
    replacement = db.scalar(
        select(ChatContextAlias).where(
            ChatContextAlias.owner_subject == "owner-a",
            ChatContextAlias.code == "BBBB",
        )
    )
    assert previous is not None
    assert replacement is not None
    assert previous.replaced_by_alias_id == replacement.id


def test_conversation_binding_is_owner_scoped_versioned_and_never_persists_raw_reference(
    db: Session,
) -> None:
    clock = Clock()
    service = ChatContextService(
        make_settings(gateway_chat_context_hmac_key_version=1),
        now=clock,
        code_factory=code_factory("AAAA", "BBBB"),
    )
    first = service.start_context(db, owner_subject="owner-a")
    second = service.start_context(db, owner_subject="owner-a")
    raw_reference = " conversation-123 "

    first_bind = service.bind_conversation(
        db,
        owner_subject="owner-a",
        context_id=first.context_id,
        conversation_reference=raw_reference,
    )
    replay = service.bind_conversation(
        db,
        owner_subject="owner-a",
        context_id=first.context_id,
        conversation_reference="conversation-123",
    )
    version_two_service = ChatContextService(
        make_settings(gateway_chat_context_hmac_key_version=2),
        now=clock,
    )

    assert first_bind.newly_bound is True
    assert replay.newly_bound is False
    assert first_bind.key_version == replay.key_version == 1
    assert (
        version_two_service.resolve_conversation(
            db,
            owner_subject="owner-a",
            conversation_reference="conversation-123",
        )
        == first.context_id
    )
    with pytest.raises(ChatContextBindingConflict):
        service.bind_conversation(
            db,
            owner_subject="owner-a",
            context_id=second.context_id,
            conversation_reference="conversation-123",
        )
    with pytest.raises(ChatContextNotFound):
        service.resolve_conversation(
            db,
            owner_subject="owner-b",
            conversation_reference="conversation-123",
        )
    stored = db.get(ChatContext, first.context_id)
    assert stored is not None
    assert stored.conversation_ref_hmac is not None
    assert stored.conversation_ref_hmac != raw_reference.strip()
    assert len(stored.conversation_ref_hmac) == 64
    assert stored.conversation_key_version == 1
    serialized_events = json.dumps(
        [event.event_metadata for event in db.scalars(select(ChatContextEvent)).all()],
        sort_keys=True,
    )
    assert "conversation-123" not in serialized_events


def test_database_rejects_non_base62_alias(db: Session) -> None:
    clock = Clock()
    service = ChatContextService(
        make_settings(),
        now=clock,
        code_factory=code_factory("AAAA"),
    )
    lease = service.start_context(db, owner_subject="owner-a")
    now = clock()

    with pytest.raises(IntegrityError):
        db.execute(
            text(
                "INSERT INTO chat_context_aliases "
                "(id, context_id, owner_subject, code, generation, status, "
                "issued_at, last_seen_at, expires_at, quarantine_until, "
                "replaced_by_alias_id, created_at, updated_at) VALUES "
                "(:id, :context_id, :owner_subject, :code, :generation, :status, "
                ":issued_at, :last_seen_at, :expires_at, NULL, NULL, :created_at, "
                ":updated_at)"
            ),
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "context_id": lease.context_id,
                "owner_subject": "owner-a",
                "code": "***!",
                "generation": 2,
                "status": "released",
                "issued_at": now,
                "last_seen_at": now,
                "expires_at": now,
                "created_at": now,
                "updated_at": now,
            },
        )
        db.flush()


def test_mcp_chat_context_schema_modes_preserve_provider_contract() -> None:
    provider_tool = {
        "name": "echo_value",
        "inputSchema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
    }

    off = decorate_public_tool(provider_tool, "off")
    optional = decorate_public_tool(provider_tool, "optional")
    required = decorate_public_tool(provider_tool, "required")

    assert off == provider_tool
    assert off is not provider_tool
    assert list(optional["inputSchema"]["properties"]) == ["chat_context", "value"]
    assert optional["inputSchema"]["required"] == ["value"]
    assert required["inputSchema"]["required"] == ["chat_context", "value"]
    assert required["inputSchema"]["properties"]["chat_context"] == {
        "type": "string",
        "pattern": "^[A-Za-z0-9]{4}$",
        "description": (
            "ATLAS chat context code for the current conversation. "
            "This is not an authentication credential."
        ),
    }
    assert provider_tool["inputSchema"]["properties"] == {
        "value": {"type": "string"}
    }
    assert provider_tool["inputSchema"]["required"] == ["value"]


def test_mcp_chat_context_reserved_provider_argument_is_rejected() -> None:
    provider_tool = {
        "name": "conflicting_tool",
        "inputSchema": {
            "type": "object",
            "properties": {"chat_context": {"type": "string"}},
        },
    }

    with pytest.raises(McpChatContextReservedArgumentCollision):
        decorate_public_tool(provider_tool, "optional")

    assert decorate_public_tool(provider_tool, "off") == provider_tool


def test_mcp_chat_context_initialize_metadata_is_versioned() -> None:
    assert chat_context_initialize_metadata("required") == {
        "contract_version": 1,
        "mode": "required",
        "pattern": "^[A-Za-z0-9]{4}$",
        "bootstrap_tool": "chat_context_start",
        "refresh_tool": "chat_context_refresh",
    }


def test_mcp_chat_context_start_admission_and_owner_isolation(db: Session) -> None:
    settings = make_settings()
    started = start_chat_context(
        db,
        settings,
        owner_subject="owner-a",
    )
    code = started["chat_context"]

    admitted = admit_chat_context(
        db,
        settings,
        owner_subject="owner-a",
        tool_name="workspace_info",
        arguments={"chat_context": code, "value": "payload"},
        mode="required",
    )

    assert admitted.code == code
    assert admitted.context_id is not None
    assert admitted.arguments == {"value": "payload"}

    optional = admit_chat_context(
        db,
        settings,
        owner_subject="owner-a",
        tool_name="workspace_info",
        arguments={"value": "payload"},
        mode="optional",
    )
    assert optional.context_id is None
    assert optional.arguments == {"value": "payload"}

    with pytest.raises(McpChatContextAdmissionError) as other_owner:
        admit_chat_context(
            db,
            settings,
            owner_subject="owner-b",
            tool_name="workspace_info",
            arguments={"chat_context": code},
            mode="required",
        )
    assert other_owner.value.error_code == "CHAT_CONTEXT_UNKNOWN"
    assert other_owner.value.recovery_tool == "chat_context_start"


def test_mcp_chat_context_required_and_refresh_results_are_recoverable(
    db: Session,
) -> None:
    settings = make_settings()

    with pytest.raises(McpChatContextAdmissionError) as missing:
        admit_chat_context(
            db,
            settings,
            owner_subject="owner-a",
            tool_name="workspace_info",
            arguments={},
            mode="required",
        )
    assert missing.value.payload() == {
        "error": "ATLAS chat context is required.",
        "error_code": "CHAT_CONTEXT_REQUIRED",
        "recovery_tool": "chat_context_start",
        "retry_original_call": True,
    }

    with pytest.raises(McpChatContextAdmissionError) as invalid:
        admit_chat_context(
            db,
            settings,
            owner_subject="owner-a",
            tool_name="workspace_info",
            arguments={"chat_context": "bad!"},
            mode="required",
        )
    assert invalid.value.error_code == "CHAT_CONTEXT_INVALID"

    started = start_chat_context(db, settings, owner_subject="owner-a")
    refreshed = refresh_chat_context(
        db,
        settings,
        owner_subject="owner-a",
        previous_chat_context=started["chat_context"],
    )
    assert refreshed["chat_context"] == started["chat_context"]
    assert refreshed["rotated"] is False


def test_chat_context_mode_change_uses_presentation_generation_fence(
    db: Session,
) -> None:
    client = OAuthClient(
        client_id="chat-context-policy-client",
        client_name="Chat context policy client",
        redirect_uris=["https://example.test/callback"],
        scope="mcp:read",
    )
    db.add(client)
    db.commit()
    assert client.presentation_policy_generation == 1
    assert client.chat_context_mode == "off"

    updated = update_oauth_client_profile(
        db,
        client_id=client.client_id,
        profile_id="chatgpt-stable",
        allowed_tool_names=[],
        chat_context_mode="optional",
    )
    assert updated.chat_context_mode == "optional"
    assert updated.presentation_policy_generation == 2

    unchanged = update_oauth_client_profile(
        db,
        client_id=client.client_id,
        profile_id="chatgpt-stable",
        allowed_tool_names=[],
        chat_context_mode="optional",
    )
    assert unchanged.presentation_policy_generation == 2


def test_mcp_chat_context_nested_provider_field_survives_decoration_and_admission(
    db: Session,
) -> None:
    provider_tool = {
        "name": "nested_context_tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "object",
                    "properties": {"chat_context": {"type": "string"}},
                    "required": ["chat_context"],
                }
            },
            "required": ["payload"],
        },
    }

    decorated = decorate_public_tool(provider_tool, "required")

    assert decorated["inputSchema"]["properties"]["payload"] == {
        "type": "object",
        "properties": {"chat_context": {"type": "string"}},
        "required": ["chat_context"],
    }
    assert provider_tool["inputSchema"]["properties"].keys() == {"payload"}

    settings = make_settings()
    started = start_chat_context(db, settings, owner_subject="owner-a")
    admission = admit_chat_context(
        db,
        settings,
        owner_subject="owner-a",
        tool_name="nested_context_tool",
        arguments={
            "chat_context": started["chat_context"],
            "payload": {"chat_context": "provider-owned-value"},
        },
        mode="required",
    )

    assert admission.arguments == {
        "payload": {"chat_context": "provider-owned-value"}
    }
