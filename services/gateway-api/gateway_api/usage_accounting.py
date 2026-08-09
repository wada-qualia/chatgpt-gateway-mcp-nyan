from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid5

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .client_credentials import ClientCredentialsTokenProvider
from .config import Settings
from .models import LupTaskStart

LUP_TASK_NAMESPACE = UUID("ff9957a6-f2b5-5e12-a9c5-1c68f538a23a")
LUP_SDK_VERSION = "0.1.0b2"
_DURABLE_RECEIPT_STATUSES = frozenset({"accepted", "duplicate"})


@dataclass(frozen=True, slots=True)
class PublishedTaskStart:
    receipt_status: str
    receipt_id: str | None
    accepted_at: datetime | None
    broker_provider: str | None
    stream_sequence: int | None
    receipt_correlation_id: str | None
    project_attribution_status: str
    project_attribution_source: str
    project_atlas_project_key: str | None
    project_atlas_entity_id: str | None
    project_git_commit: str | None
    project_git_branch: str | None


@dataclass(frozen=True, slots=True)
class TaskStartResult:
    task: LupTaskStart
    created: bool


class TaskStartPublisher(Protocol):
    def publish_start(
        self,
        *,
        principal_token: str,
        task_usage_id: UUID,
        correlation_id: UUID,
        event_id: UUID,
        source_message_id: str,
        session_id: str,
        trace_id: str | None,
    ) -> PublishedTaskStart: ...


class KeycloakClientCredentialsProvider:
    """Server-owned application proof provider with an in-memory bounded cache."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        token_url = settings.gateway_lup_application_token_url or (
            f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"
        )
        self._provider = ClientCredentialsTokenProvider(
            token_url=token_url,
            client_id=settings.gateway_lup_application_client_id,
            client_secret=settings.gateway_lup_application_client_secret.get_secret_value(),
            scope=settings.gateway_lup_application_scope,
            timeout_seconds=settings.gateway_lup_timeout_seconds,
            ca_bundle=settings.keycloak_ca_cert_path,
            error_label="LUP application proof",
        )

    def __repr__(self) -> str:
        return "KeycloakClientCredentialsProvider(<redacted>)"

    def get_token(self) -> str:
        client_id = self._settings.gateway_lup_application_client_id
        client_secret = (
            self._settings.gateway_lup_application_client_secret.get_secret_value()
        )
        if not client_id or not client_secret:
            raise RuntimeError("LUP application credentials are not configured")
        return self._provider.get_token()


class SdkTaskStartPublisher:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._application_provider = KeycloakClientCredentialsProvider(settings)

    def publish_start(
        self,
        *,
        principal_token: str,
        task_usage_id: UUID,
        correlation_id: UUID,
        event_id: UUID,
        source_message_id: str,
        session_id: str,
        trace_id: str | None,
    ) -> PublishedTaskStart:
        try:
            from klab_llm_usage import (
                AttributionSource,
                AttributionStatus,
                ProjectHint,
                StartTask,
                StaticTokenProvider,
                UsageClient,
                UsageConfigurationError,
                UsageProtocolError,
                UsageRejectedError,
                UsageUnavailableError,
            )
        except ImportError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP SDK is not installed",
            ) from error

        client = None
        try:
            project_key = self._settings.gateway_lup_project_atlas_project_key
            project_hint = ProjectHint(
                attribution_status=(
                    AttributionStatus.ATTRIBUTED
                    if project_key
                    else AttributionStatus.UNATTRIBUTED
                ),
                attribution_source=(
                    AttributionSource.EXPLICIT
                    if project_key
                    else AttributionSource.UNKNOWN
                ),
                atlas_project_key=project_key,
                atlas_entity_id=self._settings.gateway_lup_project_atlas_entity_id,
                git_commit=self._settings.gateway_release_revision or None,
                git_branch=self._settings.gateway_lup_project_git_branch,
                worktree_id=None,
            )
            client = UsageClient(
                endpoint_alias=self._settings.gateway_lup_endpoint,
                user_token_provider=StaticTokenProvider(principal_token),
                application_proof_provider=self._application_provider,
                project_context_provider=lambda: project_hint,
                timeout_seconds=self._settings.gateway_lup_timeout_seconds,
                max_attempts=self._settings.gateway_lup_max_attempts,
            )
            context = client.start_task(
                StartTask(
                    task_usage_id=task_usage_id,
                    correlation_id=correlation_id,
                    event_id=event_id,
                    project_hint=project_hint,
                    source_message_id=source_message_id,
                    trace_id=trace_id,
                    session_id=session_id,
                )
            )
            context.__enter__()
            receipt = context.start_receipt
            project = context.resolved_project
            if receipt is None or project is None:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="LUP returned an incomplete durable start receipt",
                )
            receipt_status = str(receipt.status)
            if receipt_status not in _DURABLE_RECEIPT_STATUSES:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="LUP did not durably accept the task start",
                )
            return PublishedTaskStart(
                receipt_status=receipt_status,
                receipt_id=str(receipt.receipt_id) if receipt.receipt_id else None,
                accepted_at=receipt.accepted_at,
                broker_provider=receipt.broker_provider,
                stream_sequence=receipt.stream_sequence,
                receipt_correlation_id=(
                    str(receipt.correlation_id) if receipt.correlation_id else None
                ),
                project_attribution_status=str(project.attribution_status),
                project_attribution_source=str(project.attribution_source),
                project_atlas_project_key=project.atlas_project_key,
                project_atlas_entity_id=project.atlas_entity_id,
                project_git_commit=project.git_commit,
                project_git_branch=project.git_branch,
            )
        except UsageUnavailableError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP durable acceptance is unavailable",
            ) from error
        except UsageRejectedError as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP rejected the task start",
            ) from error
        except UsageConfigurationError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP client configuration is invalid",
            ) from error
        except UsageProtocolError as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP returned an invalid protocol response",
            ) from error
        finally:
            if client is not None:
                client.close()


class LupUsageAccountingService:
    def __init__(
        self,
        settings: Settings,
        publisher: TaskStartPublisher | None = None,
    ) -> None:
        self.settings = settings
        self.publisher = publisher or SdkTaskStartPublisher(settings)

    @staticmethod
    def identifiers(
        owner_subject: str, source_message_id: str
    ) -> tuple[UUID, UUID, UUID]:
        identity = f"{owner_subject}\x1f{source_message_id}"
        return (
            uuid5(LUP_TASK_NAMESPACE, f"task\x1f{identity}"),
            uuid5(LUP_TASK_NAMESPACE, f"correlation\x1f{identity}"),
            uuid5(LUP_TASK_NAMESPACE, f"start-event\x1f{identity}"),
        )

    @staticmethod
    def _existing(
        db: Session,
        *,
        owner_subject: str,
        source_message_id: str,
    ) -> LupTaskStart | None:
        return (
            db.query(LupTaskStart)
            .filter(
                LupTaskStart.owner_subject == owner_subject,
                LupTaskStart.source_message_id == source_message_id,
            )
            .one_or_none()
        )

    @staticmethod
    def _assert_same_request(
        task: LupTaskStart,
        *,
        session_id: str,
        trace_id: str | None,
    ) -> None:
        if task.session_id != session_id or task.trace_id != trace_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The source message is already bound to a different session or trace",
            )

    async def start_task(
        self,
        db: Session,
        *,
        owner_subject: str,
        principal_token: str,
        source_message_id: str,
        session_id: str,
        trace_id: str | None,
    ) -> TaskStartResult:
        if not self.settings.gateway_lup_enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP accounting is disabled",
            )
        existing = self._existing(
            db,
            owner_subject=owner_subject,
            source_message_id=source_message_id,
        )
        if existing is not None:
            self._assert_same_request(
                existing, session_id=session_id, trace_id=trace_id
            )
            return TaskStartResult(task=existing, created=False)

        task_usage_id, correlation_id, event_id = self.identifiers(
            owner_subject, source_message_id
        )
        published = await asyncio.to_thread(
            self.publisher.publish_start,
            principal_token=principal_token,
            task_usage_id=task_usage_id,
            correlation_id=correlation_id,
            event_id=event_id,
            source_message_id=source_message_id,
            session_id=session_id,
            trace_id=trace_id,
        )
        if published.receipt_status not in _DURABLE_RECEIPT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP did not return a durable task-start receipt",
            )
        task = LupTaskStart(
            task_usage_id=str(task_usage_id),
            owner_subject=owner_subject,
            source_message_id=source_message_id,
            session_id=session_id,
            trace_id=trace_id,
            correlation_id=str(correlation_id),
            start_event_id=str(event_id),
            receipt_status=published.receipt_status,
            receipt_id=published.receipt_id,
            accepted_at=published.accepted_at,
            broker_provider=published.broker_provider,
            stream_sequence=published.stream_sequence,
            receipt_correlation_id=published.receipt_correlation_id,
            project_attribution_status=published.project_attribution_status,
            project_attribution_source=published.project_attribution_source,
            project_atlas_project_key=published.project_atlas_project_key,
            project_atlas_entity_id=published.project_atlas_entity_id,
            project_git_commit=published.project_git_commit,
            project_git_branch=published.project_git_branch,
        )
        db.add(task)
        try:
            db.commit()
            db.refresh(task)
            return TaskStartResult(task=task, created=True)
        except IntegrityError:
            db.rollback()
            existing = self._existing(
                db,
                owner_subject=owner_subject,
                source_message_id=source_message_id,
            )
            if existing is None:
                raise
            self._assert_same_request(
                existing, session_id=session_id, trace_id=trace_id
            )
            return TaskStartResult(task=existing, created=False)
