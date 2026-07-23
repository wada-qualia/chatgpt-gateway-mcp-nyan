from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid5

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings
from .dto import LupToolCallCreate
from .models import LupTaskStart, LupToolCall, LupToolPhaseSeal
from .usage_accounting import LUP_TASK_NAMESPACE, KeycloakClientCredentialsProvider

_DURABLE_RECEIPT_STATUSES = frozenset({"accepted", "duplicate"})


@dataclass(frozen=True, slots=True)
class PublishedLifecycleEvent:
    receipt_status: str
    receipt_id: str | None
    accepted_at: datetime | None
    broker_provider: str | None
    stream_sequence: int | None
    receipt_correlation_id: str | None


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    task: LupTaskStart
    call: LupToolCall
    created: bool


@dataclass(frozen=True, slots=True)
class ToolPhaseSealResult:
    task: LupTaskStart
    seal: LupToolPhaseSeal
    created: bool


class ToolLifecyclePublisher(Protocol):
    def publish_observation(self, **kwargs: object) -> PublishedLifecycleEvent: ...

    def publish_seal(self, **kwargs: object) -> PublishedLifecycleEvent: ...


class SdkToolLifecyclePublisher:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._application_provider = KeycloakClientCredentialsProvider(settings)

    def _open_context(self, *, principal_token: str, task: LupTaskStart):
        try:
            from klab_llm_usage import (
                AttributionSource,
                AttributionStatus,
                ProjectHint,
                StartTask,
                StaticTokenProvider,
                UsageClient,
            )
        except ImportError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP SDK is not installed",
            ) from error
        project_hint = ProjectHint(
            attribution_status=AttributionStatus(task.project_attribution_status),
            attribution_source=AttributionSource(task.project_attribution_source),
            atlas_project_key=task.project_atlas_project_key,
            atlas_entity_id=task.project_atlas_entity_id,
            git_commit=task.project_git_commit,
            git_branch=task.project_git_branch,
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
                task_usage_id=UUID(task.task_usage_id),
                correlation_id=UUID(task.correlation_id),
                event_id=UUID(task.start_event_id),
                project_hint=project_hint,
                source_message_id=task.source_message_id,
                trace_id=task.trace_id,
                session_id=task.session_id,
            )
        )
        context.__enter__()
        return client, context

    @staticmethod
    def _published(receipt) -> PublishedLifecycleEvent:
        receipt_status = str(receipt.status)
        if receipt_status not in _DURABLE_RECEIPT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP did not durably accept the lifecycle event",
            )
        return PublishedLifecycleEvent(
            receipt_status=receipt_status,
            receipt_id=str(receipt.receipt_id) if receipt.receipt_id else None,
            accepted_at=receipt.accepted_at,
            broker_provider=receipt.broker_provider,
            stream_sequence=receipt.stream_sequence,
            receipt_correlation_id=(
                str(receipt.correlation_id) if receipt.correlation_id else None
            ),
        )

    @staticmethod
    def _raise_sdk_error(error: Exception) -> None:
        try:
            from klab_llm_usage import (
                UsageConfigurationError,
                UsageLifecycleError,
                UsageProtocolError,
                UsageRejectedError,
                UsageUnavailableError,
            )
        except ImportError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP SDK is not installed",
            ) from error
        if isinstance(error, UsageUnavailableError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP durable acceptance is unavailable",
            ) from error
        if isinstance(error, UsageRejectedError):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP rejected the lifecycle event",
            ) from error
        if isinstance(error, UsageConfigurationError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP client configuration is invalid",
            ) from error
        if isinstance(error, UsageLifecycleError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LUP lifecycle state rejected the event",
            ) from error
        if isinstance(error, UsageProtocolError):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="LUP returned an invalid protocol response",
            ) from error
        if isinstance(error, RuntimeError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP application proof is unavailable",
            ) from error
        raise error

    def publish_observation(
        self,
        *,
        principal_token: str,
        task: LupTaskStart,
        event_id: UUID,
        observation_id: UUID,
        causation_id: UUID,
        request_id: str,
        occurred_at: datetime,
        usage: dict,
    ) -> PublishedLifecycleEvent:
        client = None
        try:
            from klab_llm_usage import (
                CoveredInput,
                EstimationEvidence,
                ExcludedInput,
                MeasurementKind,
                ModelIdentity,
                TokenCategory,
                TokenCounts,
                UsageMeasurement,
            )

            client, context = self._open_context(
                principal_token=principal_token,
                task=task,
            )
            estimation_data = usage.get("estimation")
            estimation = None
            if estimation_data is not None:
                estimation = EstimationEvidence(
                    estimator_profile_id=estimation_data["estimator_profile_id"],
                    estimator_version=estimation_data["estimator_version"],
                    confidence=estimation_data["confidence"],
                    lower_bound_tokens=estimation_data["lower_bound_tokens"],
                    upper_bound_tokens=estimation_data["upper_bound_tokens"],
                    covered_inputs=tuple(
                        CoveredInput(value)
                        for value in estimation_data.get("covered_inputs", [])
                    ),
                    excluded_inputs=tuple(
                        ExcludedInput(value)
                        for value in estimation_data.get("excluded_inputs", [])
                    ),
                    evidence_ref=estimation_data.get("evidence_ref"),
                )
            model_data = usage["model"]
            measurement = UsageMeasurement(
                model=ModelIdentity(
                    provider=model_data["provider"],
                    requested_model=model_data["requested_model"],
                    resolved_model=model_data["resolved_model"],
                    model_revision=model_data.get("model_revision"),
                ),
                tokens=TokenCounts(**usage["tokens"]),
                measurement_kind=MeasurementKind(usage["measurement_kind"]),
                covered_categories=tuple(
                    TokenCategory(value) for value in usage["covered_categories"]
                ),
                estimation=estimation,
                request_id=request_id,
                occurred_at=occurred_at,
                event_id=event_id,
                observation_id=observation_id,
                causation_id=causation_id,
            )
            return self._published(context.record_usage(measurement))
        except HTTPException:
            raise
        except Exception as error:
            self._raise_sdk_error(error)
            raise
        finally:
            if client is not None:
                client.close()

    def publish_seal(
        self,
        *,
        principal_token: str,
        task: LupTaskStart,
        event_id: UUID,
        causation_id: UUID,
        last_observation_id: UUID | None,
        sealed_at: datetime,
    ) -> PublishedLifecycleEvent:
        client = None
        try:
            client, context = self._open_context(
                principal_token=principal_token,
                task=task,
            )
            context._last_event_id = causation_id
            context._last_observation_id = last_observation_id
            context._seal_event_id = event_id
            context._seal_payload = {
                "event_id": str(event_id),
                "correlation_id": task.correlation_id,
                "causation_id": str(causation_id),
                "tool_phase_sealed_at": sealed_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "last_observation_id": (
                    str(last_observation_id)
                    if last_observation_id is not None
                    else None
                ),
            }
            return self._published(context.seal_tool_phase())
        except HTTPException:
            raise
        except Exception as error:
            self._raise_sdk_error(error)
            raise
        finally:
            if client is not None:
                client.close()


class LupToolLifecycleService:
    def __init__(
        self,
        settings: Settings,
        publisher: ToolLifecyclePublisher | None = None,
    ) -> None:
        self.settings = settings
        self.publisher = publisher or SdkToolLifecyclePublisher(settings)

    @staticmethod
    def _task(
        db: Session,
        *,
        owner_subject: str,
        source_message_id: str,
    ) -> LupTaskStart:
        task = (
            db.query(LupTaskStart)
            .filter(
                LupTaskStart.owner_subject == owner_subject,
                LupTaskStart.source_message_id == source_message_id,
            )
            .one_or_none()
        )
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="The LUP task start does not exist",
            )
        return task

    @staticmethod
    def _assert_session(task: LupTaskStart, session_id: str) -> None:
        if task.session_id != session_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The source message is bound to a different session",
            )

    @staticmethod
    def _fingerprint(payload: LupToolCallCreate) -> str:
        canonical = json.dumps(
            payload.model_dump(mode="json", exclude_none=True),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def callback_identifiers(
        owner_subject: str,
        source_message_id: str,
        callback_id: str,
    ) -> tuple[UUID, UUID, UUID]:
        identity = f"{owner_subject}\x1f{source_message_id}\x1f{callback_id}"
        return (
            uuid5(LUP_TASK_NAMESPACE, f"tool-callback\x1f{identity}"),
            uuid5(LUP_TASK_NAMESPACE, f"tool-observation-event\x1f{identity}"),
            uuid5(LUP_TASK_NAMESPACE, f"tool-observation\x1f{identity}"),
        )

    @staticmethod
    def seal_identifier(owner_subject: str, source_message_id: str) -> UUID:
        identity = f"{owner_subject}\x1f{source_message_id}"
        return uuid5(LUP_TASK_NAMESPACE, f"tool-phase-seal\x1f{identity}")

    async def record_tool_call(
        self,
        db: Session,
        *,
        owner_subject: str,
        principal_token: str,
        payload: LupToolCallCreate,
    ) -> ToolCallResult:
        if not self.settings.gateway_lup_enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP accounting is disabled",
            )
        task = self._task(
            db,
            owner_subject=owner_subject,
            source_message_id=payload.source_message_id,
        )
        self._assert_session(task, payload.session_id)
        fingerprint = self._fingerprint(payload)
        existing = (
            db.query(LupToolCall)
            .filter(
                LupToolCall.task_usage_id == task.task_usage_id,
                LupToolCall.callback_id == payload.callback_id,
            )
            .one_or_none()
        )
        if existing is not None:
            if existing.binding_fingerprint != fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The callback id is already bound to different lifecycle data",
                )
            return ToolCallResult(task=task, call=existing, created=False)
        if db.get(LupToolPhaseSeal, task.task_usage_id) is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The tool phase is already sealed",
            )
        callback_event_id, observation_event_id, observation_id = (
            self.callback_identifiers(
                owner_subject,
                payload.source_message_id,
                payload.callback_id,
            )
        )
        occurred_at = payload.occurred_at or datetime.now(UTC)
        usage = (
            payload.usage.model_dump(mode="json", exclude_none=True)
            if payload.usage is not None
            else None
        )
        previous = (
            db.query(LupToolCall)
            .filter(
                LupToolCall.task_usage_id == task.task_usage_id,
                LupToolCall.observation_event_id.is_not(None),
            )
            .order_by(LupToolCall.occurred_at.desc(), LupToolCall.created_at.desc())
            .first()
        )
        causation_id = (
            UUID(previous.observation_event_id)
            if previous is not None and previous.observation_event_id is not None
            else UUID(task.start_event_id)
        )
        published = None
        if usage is not None:
            published = await asyncio.to_thread(
                self.publisher.publish_observation,
                principal_token=principal_token,
                task=task,
                event_id=observation_event_id,
                observation_id=observation_id,
                causation_id=causation_id,
                request_id=payload.request_id or payload.callback_id,
                occurred_at=occurred_at,
                usage=usage,
            )
        call = LupToolCall(
            callback_event_id=str(callback_event_id),
            task_usage_id=task.task_usage_id,
            owner_subject=owner_subject,
            source_message_id=payload.source_message_id,
            session_id=payload.session_id,
            callback_id=payload.callback_id,
            tool_call_id=payload.tool_call_id,
            command_session_id=payload.command_session_id,
            request_id=payload.request_id,
            binding_fingerprint=fingerprint,
            usage_measurement=usage,
            observation_event_id=(
                str(observation_event_id) if usage is not None else None
            ),
            observation_id=str(observation_id) if usage is not None else None,
            receipt_status=published.receipt_status if published is not None else None,
            receipt_id=published.receipt_id if published is not None else None,
            accepted_at=published.accepted_at if published is not None else None,
            broker_provider=published.broker_provider
            if published is not None
            else None,
            stream_sequence=published.stream_sequence
            if published is not None
            else None,
            receipt_correlation_id=(
                published.receipt_correlation_id if published is not None else None
            ),
            occurred_at=occurred_at,
        )
        db.add(call)
        try:
            db.commit()
            db.refresh(call)
            return ToolCallResult(task=task, call=call, created=True)
        except IntegrityError:
            db.rollback()
            existing = (
                db.query(LupToolCall)
                .filter(
                    LupToolCall.task_usage_id == task.task_usage_id,
                    LupToolCall.callback_id == payload.callback_id,
                )
                .one_or_none()
            )
            if existing is None:
                raise
            if existing.binding_fingerprint != fingerprint:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The callback id is already bound to different lifecycle data",
                )
            return ToolCallResult(task=task, call=existing, created=False)

    async def seal_tool_phase(
        self,
        db: Session,
        *,
        owner_subject: str,
        principal_token: str,
        source_message_id: str,
        session_id: str,
        sealed_at: datetime | None,
    ) -> ToolPhaseSealResult:
        if not self.settings.gateway_lup_enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="LUP accounting is disabled",
            )
        task = self._task(
            db,
            owner_subject=owner_subject,
            source_message_id=source_message_id,
        )
        self._assert_session(task, session_id)
        existing = db.get(LupToolPhaseSeal, task.task_usage_id)
        if existing is not None:
            if sealed_at is not None:
                requested = sealed_at.astimezone(UTC)
                stored = existing.sealed_at
                if stored.tzinfo is None:
                    stored = stored.replace(tzinfo=UTC)
                if stored.astimezone(UTC) != requested:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="The tool phase was already sealed with different data",
                    )
            return ToolPhaseSealResult(task=task, seal=existing, created=False)
        effective_at = sealed_at or datetime.now(UTC)
        last_call = (
            db.query(LupToolCall)
            .filter(
                LupToolCall.task_usage_id == task.task_usage_id,
                LupToolCall.observation_id.is_not(None),
            )
            .order_by(LupToolCall.occurred_at.desc(), LupToolCall.created_at.desc())
            .first()
        )
        causation_id = (
            UUID(last_call.observation_event_id)
            if last_call is not None and last_call.observation_event_id is not None
            else UUID(task.start_event_id)
        )
        last_observation_id = (
            UUID(last_call.observation_id)
            if last_call is not None and last_call.observation_id is not None
            else None
        )
        seal_event_id = self.seal_identifier(owner_subject, source_message_id)
        published = await asyncio.to_thread(
            self.publisher.publish_seal,
            principal_token=principal_token,
            task=task,
            event_id=seal_event_id,
            causation_id=causation_id,
            last_observation_id=last_observation_id,
            sealed_at=effective_at,
        )
        seal = LupToolPhaseSeal(
            task_usage_id=task.task_usage_id,
            seal_event_id=str(seal_event_id),
            owner_subject=owner_subject,
            source_message_id=source_message_id,
            session_id=session_id,
            last_observation_event_id=(
                str(causation_id) if last_call is not None else None
            ),
            last_observation_id=(
                str(last_observation_id) if last_observation_id is not None else None
            ),
            receipt_status=published.receipt_status,
            receipt_id=published.receipt_id,
            accepted_at=published.accepted_at,
            broker_provider=published.broker_provider,
            stream_sequence=published.stream_sequence,
            receipt_correlation_id=published.receipt_correlation_id,
            sealed_at=effective_at,
        )
        db.add(seal)
        try:
            db.commit()
            db.refresh(seal)
            return ToolPhaseSealResult(task=task, seal=seal, created=True)
        except IntegrityError:
            db.rollback()
            existing = db.get(LupToolPhaseSeal, task.task_usage_id)
            if existing is None:
                raise
            return ToolPhaseSealResult(task=task, seal=existing, created=False)
