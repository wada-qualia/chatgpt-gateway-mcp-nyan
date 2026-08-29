from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .chat_context_telemetry import ChatContextTelemetry
from .config import Settings
from .models import ChatContext, ChatContextAlias, ChatContextEvent

BASE62_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
CHAT_CONTEXT_CODE_PATTERN = re.compile(r"^[A-Za-z0-9]{4}$")
ACTOR_KINDS = frozenset({"browser_extension", "mcp", "gateway", "operator"})


class ChatContextError(RuntimeError):
    pass


class ChatContextDisabled(ChatContextError):
    pass


class ChatContextValidationError(ChatContextError):
    pass


class ChatContextNotFound(ChatContextError):
    pass


class ChatContextExpired(ChatContextError):
    pass


class ChatContextClosed(ChatContextError):
    pass


class ChatContextBindingConflict(ChatContextError):
    pass


class ChatContextAllocationExhausted(ChatContextError):
    pass


@dataclass(frozen=True, slots=True)
class ChatContextLease:
    context_id: str
    code: str
    generation: int
    expires_at: datetime
    rotated: bool = False


@dataclass(frozen=True, slots=True)
class ChatContextBinding:
    context_id: str
    key_version: int
    newly_bound: bool


class ChatContextService:
    def __init__(
        self,
        settings: Settings,
        *,
        now: Callable[[], datetime] | None = None,
        code_factory: Callable[[], str] | None = None,
        telemetry: ChatContextTelemetry | None = None,
    ) -> None:
        self._settings = settings
        self._now = now or (lambda: datetime.now(UTC))
        self._code_factory = code_factory or self._generate_code
        self._telemetry = telemetry
        self._hmac_master_key = (
            settings.gateway_chat_context_hmac_key.get_secret_value().encode("utf-8")
        )

    def start_context(
        self,
        db: Session,
        *,
        owner_subject: str,
        project_ref: str | None = None,
        actor_kind: str = "mcp",
    ) -> ChatContextLease:
        return self._create_context(
            db,
            owner_subject=owner_subject,
            client_nonce=None,
            project_ref=project_ref,
            actor_kind=actor_kind,
        )

    def create_provisional(
        self,
        db: Session,
        *,
        owner_subject: str,
        client_nonce: str,
        project_ref: str | None = None,
        actor_kind: str = "browser_extension",
    ) -> ChatContextLease:
        nonce = self._bounded_value(client_nonce, "client_nonce", 128)
        return self._create_context(
            db,
            owner_subject=owner_subject,
            client_nonce=nonce,
            project_ref=project_ref,
            actor_kind=actor_kind,
        )

    def resolve_alias(
        self,
        db: Session,
        *,
        owner_subject: str,
        code: str,
        actor_kind: str = "mcp",
    ) -> ChatContextLease:
        self._require_enabled()
        owner = self._owner(owner_subject)
        try:
            alias_code = self._code(code)
        except ChatContextValidationError:
            self._record_resolution("invalid")
            raise
        actor = self._actor(actor_kind)
        initial = db.scalar(
            select(ChatContextAlias).where(
                ChatContextAlias.owner_subject == owner,
                ChatContextAlias.code == alias_code,
            )
        )
        if initial is None:
            self._record_resolution("not_found")
            raise ChatContextNotFound("chat context alias was not found")
        context = self._lock_context(db, owner, initial.context_id)
        alias = db.scalar(
            select(ChatContextAlias)
            .where(ChatContextAlias.id == initial.id)
            .with_for_update()
        )
        if alias is None:
            self._record_resolution("not_found")
            raise ChatContextNotFound("chat context alias was not found")
        now = self._current_time()
        self._reconcile_alias(db, context, alias, now=now, actor_kind="gateway")
        if context.state == "closed":
            self._record_resolution("closed")
            raise ChatContextClosed("chat context is closed")
        if alias.status != "active":
            self._record_resolution("expired")
            raise ChatContextExpired("chat context alias is expired")
        self._renew_alias(db, context, alias, now=now, actor_kind=actor, force=False)
        db.flush()
        self._record_resolution("success")
        return self._lease(alias)

    def refresh_alias(
        self,
        db: Session,
        *,
        owner_subject: str,
        previous_code: str,
        actor_kind: str = "mcp",
    ) -> ChatContextLease:
        self._require_enabled()
        owner = self._owner(owner_subject)
        code = self._code(previous_code)
        actor = self._actor(actor_kind)
        initial = db.scalar(
            select(ChatContextAlias).where(
                ChatContextAlias.owner_subject == owner,
                ChatContextAlias.code == code,
            )
        )
        if initial is None:
            raise ChatContextNotFound("historical chat context alias was not found")
        context = self._lock_context(db, owner, initial.context_id)
        if context.state == "closed":
            raise ChatContextClosed("chat context is closed")
        previous = db.scalar(
            select(ChatContextAlias)
            .where(ChatContextAlias.id == initial.id)
            .with_for_update()
        )
        if previous is None:
            raise ChatContextNotFound("historical chat context alias was not found")
        now = self._current_time()
        self._reconcile_alias(db, context, previous, now=now, actor_kind="gateway")
        current = db.scalar(
            select(ChatContextAlias)
            .where(
                ChatContextAlias.context_id == context.id,
                ChatContextAlias.status == "active",
            )
            .with_for_update()
        )
        if current is not None:
            self._reconcile_alias(db, context, current, now=now, actor_kind="gateway")
            if current.status == "active":
                self._renew_alias(
                    db,
                    context,
                    current,
                    now=now,
                    actor_kind=actor,
                    force=True,
                )
                db.flush()
                return self._lease(current, rotated=current.id != previous.id)
        self._reconcile_code_reservations(db, previous.code, now=now)
        conflicting = db.scalar(
            select(ChatContextAlias.id).where(
                ChatContextAlias.code == previous.code,
                ChatContextAlias.id != previous.id,
                ChatContextAlias.status.in_(("active", "quarantined")),
            )
        )
        can_reactivate = (
            conflicting is None
            and previous.status in {"quarantined", "released"}
            and previous.generation == context.generation
            and previous.replaced_by_alias_id is None
        )
        if can_reactivate:
            target_expiry = now + timedelta(
                seconds=self._settings.gateway_chat_context_ttl_seconds
            )
            try:
                with db.begin_nested():
                    previous.status = "active"
                    previous.last_seen_at = now
                    previous.expires_at = target_expiry
                    previous.quarantine_until = None
                    previous.updated_at = now
                    db.flush()
            except IntegrityError:
                db.refresh(previous)
            else:
                context.state = "active"
                context.last_seen_at = now
                context.updated_at = now
                self._event(
                    db,
                    context,
                    action="renewed",
                    alias_generation=previous.generation,
                    actor_kind=actor,
                    metadata={"reactivated": True},
                    now=now,
                )
                db.flush()
                return self._lease(previous)
        replacement = self._allocate_alias(db, context, actor_kind=actor, now=now)
        if previous.replaced_by_alias_id is None:
            previous.replaced_by_alias_id = replacement.id
            previous.updated_at = now
        self._event(
            db,
            context,
            action="rotated",
            alias_generation=replacement.generation,
            actor_kind=actor,
            metadata={
                "previous_alias_id": previous.id,
                "replacement_alias_id": replacement.id,
            },
            now=now,
        )
        if self._telemetry is not None:
            self._telemetry.record_rotation()
        db.flush()
        return self._lease(replacement, rotated=True)

    def bind_conversation(
        self,
        db: Session,
        *,
        owner_subject: str,
        context_id: str,
        conversation_reference: str,
        actor_kind: str = "browser_extension",
    ) -> ChatContextBinding:
        self._require_enabled()
        owner = self._owner(owner_subject)
        actor = self._actor(actor_kind)
        normalized = self._normalize_conversation_reference(conversation_reference)
        context = self._lock_context(db, owner, context_id)
        if context.state == "closed":
            raise ChatContextClosed("chat context is closed")
        bound_contexts = db.scalars(
            select(ChatContext).where(
                ChatContext.owner_subject == owner,
                ChatContext.host_kind == context.host_kind,
                ChatContext.conversation_ref_hmac.is_not(None),
                ChatContext.conversation_key_version.is_not(None),
            )
        ).all()
        for candidate in bound_contexts:
            assert candidate.conversation_ref_hmac is not None
            assert candidate.conversation_key_version is not None
            expected = self._conversation_digest(
                normalized,
                candidate.conversation_key_version,
            )
            if not hmac.compare_digest(expected, candidate.conversation_ref_hmac):
                continue
            if candidate.id != context.id:
                raise ChatContextBindingConflict(
                    "conversation reference is already bound to another chat context"
                )
            context.last_seen_at = self._current_time()
            context.updated_at = context.last_seen_at
            db.flush()
            return ChatContextBinding(
                context_id=context.id,
                key_version=candidate.conversation_key_version,
                newly_bound=False,
            )
        if context.conversation_ref_hmac is not None:
            raise ChatContextBindingConflict(
                "chat context is already bound to another conversation reference"
            )
        version = self._settings.gateway_chat_context_hmac_key_version
        digest = self._conversation_digest(normalized, version)
        now = self._current_time()
        try:
            with db.begin_nested():
                context.conversation_ref_hmac = digest
                context.conversation_key_version = version
                context.last_seen_at = now
                context.updated_at = now
                db.flush()
        except IntegrityError as error:
            raise ChatContextBindingConflict(
                "conversation reference binding conflicted with another chat context"
            ) from error
        self._event(
            db,
            context,
            action="bound",
            alias_generation=context.generation or None,
            actor_kind=actor,
            metadata={"key_version": version},
            now=now,
        )
        db.flush()
        return ChatContextBinding(
            context_id=context.id,
            key_version=version,
            newly_bound=True,
        )

    def resolve_conversation(
        self,
        db: Session,
        *,
        owner_subject: str,
        conversation_reference: str,
    ) -> str:
        self._require_enabled()
        owner = self._owner(owner_subject)
        normalized = self._normalize_conversation_reference(conversation_reference)
        candidates = db.scalars(
            select(ChatContext).where(
                ChatContext.owner_subject == owner,
                ChatContext.host_kind == "chatgpt",
                ChatContext.conversation_ref_hmac.is_not(None),
                ChatContext.conversation_key_version.is_not(None),
            )
        ).all()
        matches: list[ChatContext] = []
        for candidate in candidates:
            assert candidate.conversation_ref_hmac is not None
            assert candidate.conversation_key_version is not None
            expected = self._conversation_digest(
                normalized,
                candidate.conversation_key_version,
            )
            if hmac.compare_digest(expected, candidate.conversation_ref_hmac):
                matches.append(candidate)
        if not matches:
            raise ChatContextNotFound("conversation binding was not found")
        if len(matches) != 1:
            raise ChatContextBindingConflict("conversation binding is ambiguous")
        context = matches[0]
        if context.state == "closed":
            raise ChatContextClosed("chat context is closed")
        now = self._current_time()
        context.last_seen_at = now
        context.updated_at = now
        db.flush()
        return context.id

    def resolve_conversation_lease(
        self,
        db: Session,
        *,
        owner_subject: str,
        conversation_reference: str,
        actor_kind: str = "browser_extension",
    ) -> ChatContextLease:
        context_id = self.resolve_conversation(
            db,
            owner_subject=owner_subject,
            conversation_reference=conversation_reference,
        )
        context = self._lock_context(db, self._owner(owner_subject), context_id)
        return self._ensure_context_alias(
            db,
            context,
            actor_kind=self._actor(actor_kind),
        )

    def _create_context(
        self,
        db: Session,
        *,
        owner_subject: str,
        client_nonce: str | None,
        project_ref: str | None,
        actor_kind: str,
    ) -> ChatContextLease:
        self._require_enabled()
        owner = self._owner(owner_subject)
        actor = self._actor(actor_kind)
        project = (
            self._bounded_value(project_ref, "project_ref", 255)
            if project_ref is not None
            else None
        )
        if client_nonce is not None:
            existing = db.scalar(
                select(ChatContext).where(
                    ChatContext.owner_subject == owner,
                    ChatContext.client_nonce == client_nonce,
                )
            )
            if existing is not None:
                return self._ensure_context_alias(db, existing, actor_kind=actor)
        now = self._current_time()
        context = ChatContext(
            id=str(uuid.uuid4()),
            owner_subject=owner,
            host_kind="chatgpt",
            state="active",
            project_ref=project,
            client_nonce=client_nonce,
            generation=0,
            created_at=now,
            last_seen_at=now,
            updated_at=now,
        )
        try:
            with db.begin_nested():
                db.add(context)
                db.flush()
                self._event(
                    db,
                    context,
                    action="created",
                    alias_generation=None,
                    actor_kind=actor,
                    metadata={"host_kind": "chatgpt"},
                    now=now,
                )
                alias = self._allocate_alias(db, context, actor_kind=actor, now=now)
                db.flush()
        except IntegrityError:
            if client_nonce is None:
                raise
            existing = db.scalar(
                select(ChatContext).where(
                    ChatContext.owner_subject == owner,
                    ChatContext.client_nonce == client_nonce,
                )
            )
            if existing is None:
                raise
            return self._ensure_context_alias(db, existing, actor_kind=actor)
        return self._lease(alias)

    def _ensure_context_alias(
        self,
        db: Session,
        context: ChatContext,
        *,
        actor_kind: str,
    ) -> ChatContextLease:
        locked = self._lock_context(db, context.owner_subject, context.id)
        if locked.state == "closed":
            raise ChatContextClosed("chat context is closed")
        active = db.scalar(
            select(ChatContextAlias)
            .where(
                ChatContextAlias.context_id == locked.id,
                ChatContextAlias.status == "active",
            )
            .with_for_update()
        )
        now = self._current_time()
        if active is not None:
            self._reconcile_alias(db, locked, active, now=now, actor_kind="gateway")
            if active.status == "active":
                self._renew_alias(
                    db,
                    locked,
                    active,
                    now=now,
                    actor_kind=actor_kind,
                    force=False,
                )
                db.flush()
                return self._lease(active)
        latest = db.scalar(
            select(ChatContextAlias)
            .where(ChatContextAlias.context_id == locked.id)
            .order_by(ChatContextAlias.generation.desc())
            .limit(1)
        )
        if latest is not None:
            return self.refresh_alias(
                db,
                owner_subject=locked.owner_subject,
                previous_code=latest.code,
                actor_kind=actor_kind,
            )
        alias = self._allocate_alias(db, locked, actor_kind=actor_kind, now=now)
        db.flush()
        return self._lease(alias)

    def _allocate_alias(
        self,
        db: Session,
        context: ChatContext,
        *,
        actor_kind: str,
        now: datetime,
    ) -> ChatContextAlias:
        context = self._lock_context(db, context.owner_subject, context.id)
        retries = 0
        for _ in range(self._settings.gateway_chat_context_allocation_attempts):
            candidate = self._code(self._code_factory())
            self._reconcile_code_reservations(db, candidate, now=now)
            owner_history = db.scalar(
                select(ChatContextAlias.id).where(
                    ChatContextAlias.owner_subject == context.owner_subject,
                    ChatContextAlias.code == candidate,
                )
            )
            if owner_history is not None:
                retries += 1
                continue
            live_reservation = db.scalar(
                select(ChatContextAlias.id).where(
                    ChatContextAlias.code == candidate,
                    ChatContextAlias.status.in_(("active", "quarantined")),
                )
            )
            if live_reservation is not None:
                retries += 1
                continue
            generation = context.generation + 1
            alias = ChatContextAlias(
                id=str(uuid.uuid4()),
                context_id=context.id,
                owner_subject=context.owner_subject,
                code=candidate,
                generation=generation,
                status="active",
                issued_at=now,
                last_seen_at=now,
                expires_at=now
                + timedelta(seconds=self._settings.gateway_chat_context_ttl_seconds),
                created_at=now,
                updated_at=now,
            )
            try:
                with db.begin_nested():
                    db.add(alias)
                    db.flush()
            except IntegrityError:
                retries += 1
                continue
            context.generation = generation
            context.state = "active"
            context.last_seen_at = now
            context.updated_at = now
            self._event(
                db,
                context,
                action="issued",
                alias_generation=generation,
                actor_kind=actor_kind,
                metadata={"alias_id": alias.id, "allocation_retries": retries},
                now=now,
            )
            if self._telemetry is not None:
                self._telemetry.record_allocation("success", retries=retries)
            return alias
        if self._telemetry is not None:
            self._telemetry.record_allocation("exhausted", retries=retries)
        raise ChatContextAllocationExhausted(
            "chat context alias allocation attempt budget was exhausted"
        )

    def _reconcile_code_reservations(
        self,
        db: Session,
        code: str,
        *,
        now: datetime,
    ) -> None:
        reservations = db.scalars(
            select(ChatContextAlias)
            .where(
                ChatContextAlias.code == code,
                ChatContextAlias.status.in_(("active", "quarantined")),
            )
            .with_for_update()
        ).all()
        for alias in reservations:
            context = self._lock_context(db, alias.owner_subject, alias.context_id)
            self._reconcile_alias(
                db,
                context,
                alias,
                now=now,
                actor_kind="gateway",
            )
        db.flush()

    def _reconcile_alias(
        self,
        db: Session,
        context: ChatContext,
        alias: ChatContextAlias,
        *,
        now: datetime,
        actor_kind: str,
    ) -> None:
        if alias.status == "active" and self._as_utc(alias.expires_at) <= now:
            expiry = self._as_utc(alias.expires_at)
            quarantine_until = expiry + timedelta(
                seconds=self._settings.gateway_chat_context_quarantine_seconds
            )
            alias.status = "quarantined"
            alias.quarantine_until = quarantine_until
            alias.updated_at = now
            context.state = "dormant"
            context.updated_at = now
            self._event(
                db,
                context,
                action="expired",
                alias_generation=alias.generation,
                actor_kind=actor_kind,
                metadata={},
                now=now,
            )
            self._event(
                db,
                context,
                action="quarantined",
                alias_generation=alias.generation,
                actor_kind=actor_kind,
                metadata={"until": quarantine_until.isoformat()},
                now=now,
            )
        if (
            alias.status == "quarantined"
            and alias.quarantine_until is not None
            and self._as_utc(alias.quarantine_until) <= now
        ):
            alias.status = "released"
            alias.updated_at = now
            self._event(
                db,
                context,
                action="released",
                alias_generation=alias.generation,
                actor_kind=actor_kind,
                metadata={},
                now=now,
            )

    def _renew_alias(
        self,
        db: Session,
        context: ChatContext,
        alias: ChatContextAlias,
        *,
        now: datetime,
        actor_kind: str,
        force: bool,
    ) -> None:
        current_expiry = self._as_utc(alias.expires_at)
        alias.last_seen_at = now
        alias.updated_at = now
        context.last_seen_at = now
        context.updated_at = now
        context.state = "active"
        remaining = current_expiry - now
        if (
            not force
            and remaining.total_seconds()
            > self._settings.gateway_chat_context_renew_threshold_seconds
        ):
            return
        target = now + timedelta(
            seconds=self._settings.gateway_chat_context_ttl_seconds
        )
        if target <= current_expiry:
            return
        alias.expires_at = target
        self._event(
            db,
            context,
            action="renewed",
            alias_generation=alias.generation,
            actor_kind=actor_kind,
            metadata={"reactivated": False},
            now=now,
        )

    def _event(
        self,
        db: Session,
        context: ChatContext,
        *,
        action: str,
        alias_generation: int | None,
        actor_kind: str,
        metadata: dict,
        now: datetime,
    ) -> None:
        db.add(
            ChatContextEvent(
                id=str(uuid.uuid4()),
                context_id=context.id,
                owner_subject=context.owner_subject,
                action=action,
                alias_generation=alias_generation,
                actor_kind=self._actor(actor_kind),
                event_metadata=dict(metadata),
                created_at=now,
            )
        )

    def _record_resolution(self, result: str) -> None:
        if self._telemetry is not None:
            self._telemetry.record_resolution(result)

    def _lock_context(
        self,
        db: Session,
        owner_subject: str,
        context_id: str,
    ) -> ChatContext:
        context = db.scalar(
            select(ChatContext)
            .where(
                ChatContext.id == context_id,
                ChatContext.owner_subject == owner_subject,
            )
            .with_for_update()
        )
        if context is None:
            raise ChatContextNotFound("chat context was not found")
        return context

    def _conversation_digest(self, normalized_reference: str, version: int) -> str:
        version_key = hmac.new(
            self._hmac_master_key,
            f"chat-context-conversation-hmac:v{version}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        return hmac.new(
            version_key,
            normalized_reference.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _normalize_conversation_reference(self, value: str) -> str:
        if not isinstance(value, str):
            raise ChatContextValidationError("conversation_reference must be a string")
        normalized = unicodedata.normalize("NFC", value.strip())
        if not normalized or len(normalized) > 512:
            raise ChatContextValidationError(
                "conversation_reference must contain between 1 and 512 characters"
            )
        if any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ChatContextValidationError(
                "conversation_reference contains a control character"
            )
        return normalized

    def _owner(self, value: str) -> str:
        return self._bounded_value(value, "owner_subject", 255)

    def _actor(self, value: str) -> str:
        if value not in ACTOR_KINDS:
            raise ChatContextValidationError("actor_kind is not supported")
        return value

    def _code(self, value: str) -> str:
        if (
            not isinstance(value, str)
            or CHAT_CONTEXT_CODE_PATTERN.fullmatch(value) is None
        ):
            raise ChatContextValidationError(
                "chat context code must contain exactly four Base62 characters"
            )
        return value

    def _bounded_value(self, value: str, name: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ChatContextValidationError(f"{name} must be a string")
        bounded = value.strip()
        if not bounded or len(bounded) > maximum:
            raise ChatContextValidationError(
                f"{name} must contain between 1 and {maximum} characters"
            )
        return bounded

    def _require_enabled(self) -> None:
        if not self._settings.gateway_chat_context_enabled:
            raise ChatContextDisabled("chat context persistence is disabled")
        if len(self._hmac_master_key) < 32:
            raise ChatContextValidationError("chat context HMAC key is not configured")

    def _current_time(self) -> datetime:
        return self._as_utc(self._now())

    def _lease(
        self, alias: ChatContextAlias, *, rotated: bool = False
    ) -> ChatContextLease:
        return ChatContextLease(
            context_id=alias.context_id,
            code=alias.code,
            generation=alias.generation,
            expires_at=self._as_utc(alias.expires_at),
            rotated=rotated,
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _generate_code() -> str:
        return "".join(secrets.choice(BASE62_ALPHABET) for _ in range(4))
