from __future__ import annotations

import asyncio
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid5

import httpx
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

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
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "KeycloakClientCredentialsProvider(<redacted>)"

    def get_token(self) -> str:
        with self._lock:
            now = time.monotonic()
            if self._token is not None and now < self._expires_at - 30:
                return self._token
            client_id = self._settings.gateway_lup_application_client_id
            client_secret = (
                self._settings.gateway_lup_application_client_secret.get_secret_value()
            )
            if not client_id or not client_secret:
                raise RuntimeError("LUP application credentials are not configured")
            token_url = self._settings.gateway_lup_application_token_url or (
                f"{self._settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"
            )
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if self._settings.gateway_lup_application_scope:
                data["scope"] = self._settings.gateway_lup_application_scope
            context = ssl.create_default_context()
            if self._settings.keycloak_ca_cert_path:
                context.load_verify_locations(
                    cafile=self._settings.keycloak_ca_cert_path
                )
            try:
                with httpx.Client(
                    timeout=self._settings.gateway_lup_timeout_seconds, verify=context
                ) as client:
                    response = client.post(token_url, data=data)
                    response.raise_for_status()
                    payload = response.json()
            except (httpx.HTTPError, ValueError) as error:
                raise RuntimeError(
                    "LUP application proof acquisition failed"
                ) from error
            token = payload.get("access_token")
            expires_in = payload.get("expires_in", 60)
            if not isinstance(token, str) or not token or len(token) > 131072:
                raise RuntimeError("LUP application proof response is invalid")
            if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
                expires_in = 60
            self._token = token
            self._expires_at = now + max(60.0, min(float(expires_in), 86400.0))
            return token


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
