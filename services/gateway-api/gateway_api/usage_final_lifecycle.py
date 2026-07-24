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
from .dto import LupFinalResponseAbandonCreate, LupFinalResponseCompleteCreate
from .models import LupTaskStart, LupTaskTerminal, LupToolCall, LupToolPhaseSeal
from .usage_accounting import LUP_TASK_NAMESPACE
from .usage_estimation import FinalResponseCountMetrics, estimate_visible_final_response
from .usage_tool_lifecycle import PublishedLifecycleEvent, SdkToolLifecyclePublisher


@dataclass(frozen=True, slots=True)
class PublishedTaskTerminal:
    observation: PublishedLifecycleEvent | None
    terminal: PublishedLifecycleEvent


@dataclass(frozen=True, slots=True)
class TaskTerminalResult:
    task: LupTaskStart
    terminal: LupTaskTerminal
    created: bool


class FinalLifecyclePublisher(Protocol):
    def publish_completion(self, **kwargs: object) -> PublishedTaskTerminal: ...

    def publish_abandonment(self, **kwargs: object) -> PublishedTaskTerminal: ...


class SdkFinalLifecyclePublisher(SdkToolLifecyclePublisher):
    @staticmethod
    def _usage_measurement(
        *,
        usage: dict,
        request_id: str,
        occurred_at: datetime,
        event_id: UUID,
        observation_id: UUID,
        causation_id: UUID,
    ):
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
        model = usage["model"]
        return UsageMeasurement(
            model=ModelIdentity(
                provider=model["provider"],
                requested_model=model["requested_model"],
                resolved_model=model["resolved_model"],
                model_revision=model.get("model_revision"),
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

    def publish_completion(
        self,
        *,
        principal_token: str,
        task: LupTaskStart,
        terminal_event_id: UUID,
        causation_id: UUID,
        completed_at: datetime,
        completion_mode: str,
        final_observation_event_id: UUID | None,
        final_observation_id: UUID | None,
        prior_observation_id: UUID | None,
        request_id: str,
        usage: dict | None,
    ) -> PublishedTaskTerminal:
        client = None
        try:
            from klab_llm_usage import CompletionMode, TaskCompletion

            client, context = self._open_context(
                principal_token=principal_token,
                task=task,
            )
            context._last_event_id = causation_id
            context._last_observation_id = prior_observation_id
            observation_receipt = None
            completion_causation = causation_id
            if usage is not None:
                assert final_observation_event_id is not None
                assert final_observation_id is not None
                observation_receipt = self._published(
                    context.record_usage(
                        self._usage_measurement(
                            usage=usage,
                            request_id=request_id,
                            occurred_at=completed_at,
                            event_id=final_observation_event_id,
                            observation_id=final_observation_id,
                            causation_id=causation_id,
                        )
                    )
                )
                completion_causation = final_observation_event_id
                context._last_event_id = final_observation_event_id
                context._last_observation_id = final_observation_id
            else:
                context._last_observation_id = None

            context._complete_event_id = terminal_event_id
            context._complete_payload = {
                "event_id": str(terminal_event_id),
                "correlation_id": task.correlation_id,
                "causation_id": str(completion_causation),
                "response_completed_at": completed_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "completion_mode": completion_mode,
                "final_observation_id": (
                    str(final_observation_id)
                    if final_observation_id is not None
                    else None
                ),
            }
            terminal_receipt = self._published(
                context.complete(
                    TaskCompletion(
                        completion_mode=CompletionMode(completion_mode),
                        at=completed_at,
                        final_observation_id=final_observation_id,
                        causation_id=completion_causation,
                    )
                )
            )
            return PublishedTaskTerminal(
                observation=observation_receipt,
                terminal=terminal_receipt,
            )
        except HTTPException:
            raise
        except Exception as error:
            self._raise_sdk_error(error)
            raise
        finally:
            if client is not None:
                client.close()

    def publish_abandonment(
        self,
        *,
        principal_token: str,
        task: LupTaskStart,
        terminal_event_id: UUID,
        causation_id: UUID,
        last_observation_id: UUID | None,
        abandoned_at: datetime,
        reason_code: str,
    ) -> PublishedTaskTerminal:
        client = None
        try:
            from klab_llm_usage import AbandonReason

            client, context = self._open_context(
                principal_token=principal_token,
                task=task,
            )
            context._last_event_id = causation_id
            context._last_observation_id = last_observation_id
            context._abandon_event_id = terminal_event_id
            context._abandon_payload = {
                "event_id": str(terminal_event_id),
                "correlation_id": task.correlation_id,
                "causation_id": str(causation_id),
                "abandoned_at": abandoned_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "reason_code": reason_code,
                "last_observation_id": (
                    str(last_observation_id)
                    if last_observation_id is not None
                    else None
                ),
            }
            terminal_receipt = self._published(
                context.abandon(AbandonReason(reason_code), abandoned_at)
            )
            return PublishedTaskTerminal(
                observation=None,
                terminal=terminal_receipt,
            )
        except HTTPException:
            raise
        except Exception as error:
            self._raise_sdk_error(error)
            raise
        finally:
            if client is not None:
                client.close()


class LupFinalLifecycleService:
    def __init__(
        self,
        settings: Settings,
        publisher: FinalLifecyclePublisher | None = None,
    ) -> None:
        self.settings = settings
        self.publisher = publisher or SdkFinalLifecyclePublisher(settings)

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
    def _fingerprint(payload: object) -> str:
        value = (
            payload.model_dump(mode="json", exclude_none=True)
            if hasattr(payload, "model_dump")
            else payload
        )
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def terminal_identifier(owner_subject: str, source_message_id: str) -> UUID:
        identity = f"{owner_subject}\x1f{source_message_id}"
        return uuid5(LUP_TASK_NAMESPACE, f"task-terminal\x1f{identity}")

    @staticmethod
    def final_observation_identifiers(
        owner_subject: str, source_message_id: str
    ) -> tuple[UUID, UUID]:
        identity = f"{owner_subject}\x1f{source_message_id}"
        return (
            uuid5(LUP_TASK_NAMESPACE, f"final-observation-event\x1f{identity}"),
            uuid5(LUP_TASK_NAMESPACE, f"final-observation\x1f{identity}"),
        )

    @staticmethod
    def _lineage(
        db: Session,
        task: LupTaskStart,
        *,
        require_sealed_tools: bool,
    ) -> tuple[UUID, UUID | None]:
        seal = db.get(LupToolPhaseSeal, task.task_usage_id)
        any_tool_call = (
            db.query(LupToolCall.callback_event_id)
            .filter(LupToolCall.task_usage_id == task.task_usage_id)
            .first()
            is not None
        )
        if require_sealed_tools and any_tool_call and seal is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The tool phase must be sealed before task completion",
            )
        if seal is not None:
            return UUID(seal.seal_event_id), (
                UUID(seal.last_observation_id)
                if seal.last_observation_id is not None
                else None
            )
        latest = (
            db.query(LupToolCall)
            .filter(
                LupToolCall.task_usage_id == task.task_usage_id,
                LupToolCall.observation_event_id.is_not(None),
            )
            .order_by(LupToolCall.occurred_at.desc(), LupToolCall.created_at.desc())
            .first()
        )
        if latest is not None and latest.observation_event_id is not None:
            return UUID(latest.observation_event_id), (
                UUID(latest.observation_id)
                if latest.observation_id is not None
                else None
            )
        return UUID(task.start_event_id), None

    @staticmethod
    def _existing(
        db: Session,
        task_usage_id: str,
        fingerprint: str,
    ) -> LupTaskTerminal | None:
        existing = db.get(LupTaskTerminal, task_usage_id)
        if existing is not None and existing.binding_fingerprint != fingerprint:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The task already has a different terminal lifecycle outcome",
            )
        return existing

    @staticmethod
    def _receipt_fields(
        published: PublishedLifecycleEvent | None,
        *,
        prefix: str,
    ) -> dict[str, object]:
        if published is None:
            return {
                f"{prefix}_receipt_status": None,
                f"{prefix}_receipt_id": None,
                f"{prefix}_accepted_at": None,
                f"{prefix}_broker_provider": None,
                f"{prefix}_stream_sequence": None,
                f"{prefix}_receipt_correlation_id": None,
            }
        return {
            f"{prefix}_receipt_status": published.receipt_status,
            f"{prefix}_receipt_id": published.receipt_id,
            f"{prefix}_accepted_at": published.accepted_at,
            f"{prefix}_broker_provider": published.broker_provider,
            f"{prefix}_stream_sequence": published.stream_sequence,
            f"{prefix}_receipt_correlation_id": published.receipt_correlation_id,
        }

    async def complete(
        self,
        db: Session,
        *,
        owner_subject: str,
        principal_token: str,
        payload: LupFinalResponseCompleteCreate,
    ) -> TaskTerminalResult:
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
        usage = None
        if payload.usage is not None:
            usage = payload.usage.model_dump(mode="json", exclude_none=True)
        elif payload.final_response_estimate is not None:
            estimate = payload.final_response_estimate
            usage = estimate_visible_final_response(
                model=estimate.model.model_dump(mode="json", exclude_none=True),
                metrics=FinalResponseCountMetrics(
                    visible_character_count=estimate.visible_character_count,
                    visible_utf8_byte_count=estimate.visible_utf8_byte_count,
                    visible_word_count=estimate.visible_word_count,
                ),
            )
        fingerprint_payload = payload.model_dump(mode="json", exclude_none=True)
        if usage is not None:
            fingerprint_payload["resolved_usage"] = usage
        fingerprint = self._fingerprint(fingerprint_payload)
        existing = self._existing(db, task.task_usage_id, fingerprint)
        if existing is not None:
            return TaskTerminalResult(task=task, terminal=existing, created=False)

        causation_id, prior_observation_id = self._lineage(
            db,
            task,
            require_sealed_tools=True,
        )
        completed_at = payload.completed_at or datetime.now(UTC)
        terminal_event_id = self.terminal_identifier(
            owner_subject, payload.source_message_id
        )
        final_observation_event_id = None
        final_observation_id = None
        if usage is not None:
            final_observation_event_id, final_observation_id = (
                self.final_observation_identifiers(
                    owner_subject, payload.source_message_id
                )
            )
        published = await asyncio.to_thread(
            self.publisher.publish_completion,
            principal_token=principal_token,
            task=task,
            terminal_event_id=terminal_event_id,
            causation_id=causation_id,
            completed_at=completed_at,
            completion_mode=payload.completion_mode,
            final_observation_event_id=final_observation_event_id,
            final_observation_id=final_observation_id,
            prior_observation_id=prior_observation_id,
            request_id=payload.request_id or payload.callback_id,
            usage=usage,
        )
        terminal = LupTaskTerminal(
            task_usage_id=task.task_usage_id,
            terminal_event_id=str(terminal_event_id),
            owner_subject=owner_subject,
            source_message_id=payload.source_message_id,
            session_id=payload.session_id,
            callback_id=payload.callback_id,
            binding_fingerprint=fingerprint,
            terminal_kind="completed",
            completion_mode=payload.completion_mode,
            delivery_state=payload.delivery_state,
            recovery_id=payload.recovery_id,
            reason_code=None,
            request_id=payload.request_id,
            final_usage_measurement=usage,
            final_observation_event_id=(
                str(final_observation_event_id)
                if final_observation_event_id is not None
                else None
            ),
            final_observation_id=(
                str(final_observation_id) if final_observation_id is not None else None
            ),
            terminal_at=completed_at,
            **self._receipt_fields(published.observation, prefix="observation"),
            **self._receipt_fields(published.terminal, prefix="terminal"),
        )
        db.add(terminal)
        try:
            db.commit()
            db.refresh(terminal)
            return TaskTerminalResult(task=task, terminal=terminal, created=True)
        except IntegrityError:
            db.rollback()
            existing = self._existing(db, task.task_usage_id, fingerprint)
            if existing is None:
                raise
            return TaskTerminalResult(task=task, terminal=existing, created=False)

    async def abandon(
        self,
        db: Session,
        *,
        owner_subject: str,
        principal_token: str,
        payload: LupFinalResponseAbandonCreate,
    ) -> TaskTerminalResult:
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
        existing = self._existing(db, task.task_usage_id, fingerprint)
        if existing is not None:
            return TaskTerminalResult(task=task, terminal=existing, created=False)

        causation_id, last_observation_id = self._lineage(
            db,
            task,
            require_sealed_tools=False,
        )
        abandoned_at = payload.abandoned_at or datetime.now(UTC)
        terminal_event_id = self.terminal_identifier(
            owner_subject, payload.source_message_id
        )
        published = await asyncio.to_thread(
            self.publisher.publish_abandonment,
            principal_token=principal_token,
            task=task,
            terminal_event_id=terminal_event_id,
            causation_id=causation_id,
            last_observation_id=last_observation_id,
            abandoned_at=abandoned_at,
            reason_code=payload.reason_code,
        )
        terminal = LupTaskTerminal(
            task_usage_id=task.task_usage_id,
            terminal_event_id=str(terminal_event_id),
            owner_subject=owner_subject,
            source_message_id=payload.source_message_id,
            session_id=payload.session_id,
            callback_id=payload.callback_id,
            binding_fingerprint=fingerprint,
            terminal_kind="abandoned",
            completion_mode=None,
            delivery_state=None,
            recovery_id=None,
            reason_code=payload.reason_code,
            request_id=None,
            final_usage_measurement=None,
            final_observation_event_id=None,
            final_observation_id=None,
            terminal_at=abandoned_at,
            **self._receipt_fields(None, prefix="observation"),
            **self._receipt_fields(published.terminal, prefix="terminal"),
        )
        db.add(terminal)
        try:
            db.commit()
            db.refresh(terminal)
            return TaskTerminalResult(task=task, terminal=terminal, created=True)
        except IntegrityError:
            db.rollback()
            existing = self._existing(db, task.task_usage_id, fingerprint)
            if existing is None:
                raise
            return TaskTerminalResult(task=task, terminal=existing, created=False)
