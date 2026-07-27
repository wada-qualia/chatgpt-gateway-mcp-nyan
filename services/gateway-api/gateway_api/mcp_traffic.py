from __future__ import annotations

import asyncio
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid5

import httpx
from sqlalchemy.orm import Session

from .config import Settings
from .models import AgentToolCall
from .usage_accounting import (
    LUP_TASK_NAMESPACE,
    KeycloakClientCredentialsProvider,
)

ESTIMATOR_PROFILE_ID = "mcp-jsonrpc-character-div4"
ESTIMATOR_VERSION = "1.0.0"
CHARACTERS_PER_TOKEN = 4
_PROVIDER = "mcp"
_REQUESTED_MODEL = "tools/call"
_RESOLVED_MODEL = ESTIMATOR_PROFILE_ID
_PENDING = "pending"
_DELIVERED = "delivered"
_DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class PublishedTraffic:
    receipt_status: str
    accepted_at: datetime | None


class TrafficPublisher(Protocol):
    def publish(self, *, call: AgentToolCall) -> PublishedTraffic: ...


class GatewayPrincipalCredentialsProvider:
    """Keycloak service principal for unattended MCP traffic delivery."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "GatewayPrincipalCredentialsProvider(<redacted>)"

    def get_token(self) -> str:
        with self._lock:
            now = time.monotonic()
            if self._token is not None and now < self._expires_at - 30:
                return self._token
            client_id = self._settings.keycloak_client_id
            client_secret = self._settings.keycloak_client_secret
            if not client_id or not client_secret:
                raise RuntimeError("LUP principal credentials are not configured")
            token_url = (
                f"{self._settings.keycloak_issuer.rstrip('/')}"
                "/protocol/openid-connect/token"
            )
            context = ssl.create_default_context()
            if self._settings.keycloak_ca_cert_path:
                context.load_verify_locations(
                    cafile=self._settings.keycloak_ca_cert_path
                )
            try:
                with httpx.Client(
                    timeout=self._settings.gateway_lup_timeout_seconds,
                    verify=context,
                ) as client:
                    response = client.post(
                        token_url,
                        data={
                            "grant_type": "client_credentials",
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "scope": "usage:write",
                        },
                    )
                    response.raise_for_status()
                    payload = response.json()
            except (httpx.HTTPError, ValueError) as error:
                raise RuntimeError("LUP principal proof acquisition failed") from error
            token = payload.get("access_token")
            expires_in = payload.get("expires_in", 60)
            if not isinstance(token, str) or not token or len(token) > 131072:
                raise RuntimeError("LUP principal proof response is invalid")
            if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
                expires_in = 60
            self._token = token
            self._expires_at = now + max(60.0, min(float(expires_in), 86400.0))
            return token


def estimate_tokens(character_count: int) -> int:
    if isinstance(character_count, bool) or not isinstance(character_count, int):
        raise TypeError("character_count must be an integer")
    if character_count < 0:
        raise ValueError("character_count cannot be negative")
    return (character_count + CHARACTERS_PER_TOKEN - 1) // CHARACTERS_PER_TOKEN


def traffic_identifiers(
    owner_subject: str, tool_call_id: str
) -> tuple[UUID, UUID, UUID, UUID]:
    identity = f"{owner_subject}\x1f{tool_call_id}"
    return (
        uuid5(LUP_TASK_NAMESPACE, f"mcp-traffic-task\x1f{identity}"),
        uuid5(LUP_TASK_NAMESPACE, f"mcp-traffic-correlation\x1f{identity}"),
        uuid5(LUP_TASK_NAMESPACE, f"mcp-traffic-event\x1f{identity}"),
        uuid5(LUP_TASK_NAMESPACE, f"mcp-traffic-observation\x1f{identity}"),
    )


class SdkMcpTrafficPublisher:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._principal_provider = GatewayPrincipalCredentialsProvider(settings)
        self._application_provider = KeycloakClientCredentialsProvider(settings)

    def publish(self, *, call: AgentToolCall) -> PublishedTraffic:
        from klab_llm_usage import (
            CoveredInput,
            EstimationEvidence,
            ExcludedInput,
            MeasurementKind,
            ModelIdentity,
            TokenCategory,
            TokenCounts,
            UsageClient,
            UsageMeasurement,
        )

        required = (
            call.traffic_task_usage_id,
            call.traffic_correlation_id,
            call.traffic_event_id,
            call.traffic_observation_id,
            call.estimated_input_tokens,
            call.estimated_output_tokens,
        )
        if any(value is None for value in required):
            raise RuntimeError("MCP traffic outbox row is incomplete")
        input_tokens = int(call.estimated_input_tokens or 0)
        output_tokens = int(call.estimated_output_tokens or 0)
        total = input_tokens + output_tokens
        measurement = UsageMeasurement(
            model=ModelIdentity(
                provider=_PROVIDER,
                requested_model=_REQUESTED_MODEL,
                resolved_model=_RESOLVED_MODEL,
            ),
            tokens=TokenCounts(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            ),
            measurement_kind=MeasurementKind.HEURISTIC_ESTIMATE,
            covered_categories=(TokenCategory.INPUT, TokenCategory.OUTPUT),
            estimation=EstimationEvidence(
                estimator_profile_id=ESTIMATOR_PROFILE_ID,
                estimator_version=ESTIMATOR_VERSION,
                confidence=0.5,
                lower_bound_tokens=total,
                upper_bound_tokens=total,
                covered_inputs=(
                    CoveredInput.VISIBLE_TOOL_ARGUMENTS,
                    CoveredInput.VISIBLE_TOOL_RESULTS,
                ),
                excluded_inputs=(
                    ExcludedInput.SYSTEM_CONTEXT,
                    ExcludedInput.HIDDEN_REASONING,
                    ExcludedInput.PROVIDER_TRANSFORMATIONS,
                    ExcludedInput.CACHED_CONTEXT,
                    ExcludedInput.UNKNOWN_INTERNAL_CALLS,
                ),
                evidence_ref=None,
            ),
            request_id=call.id,
            occurred_at=call.completed_at or call.created_at,
            event_id=UUID(str(call.traffic_event_id)),
            observation_id=UUID(str(call.traffic_observation_id)),
        )
        client = UsageClient(
            endpoint_alias=self._settings.gateway_lup_endpoint,
            user_token_provider=self._principal_provider,
            application_proof_provider=self._application_provider,
            timeout_seconds=self._settings.gateway_lup_timeout_seconds,
            max_attempts=self._settings.gateway_lup_max_attempts,
        )
        try:
            receipt = client.record_detached_usage(
                task_usage_id=UUID(str(call.traffic_task_usage_id)),
                correlation_id=UUID(str(call.traffic_correlation_id)),
                measurement=measurement,
            )
            return PublishedTraffic(
                receipt_status=str(receipt.status),
                accepted_at=receipt.accepted_at,
            )
        finally:
            client.close()


class McpTrafficAccountingService:
    def __init__(
        self,
        settings: Settings,
        publisher: TrafficPublisher | None = None,
    ) -> None:
        self.settings = settings
        self.publisher = publisher or SdkMcpTrafficPublisher(settings)

    async def record_exchange(
        self,
        db: Session,
        *,
        call: AgentToolCall,
        request_characters: int,
        response_characters: int,
    ) -> AgentToolCall:
        current = db.get(AgentToolCall, call.id)
        if current is None:
            raise RuntimeError("tool call disappeared before traffic accounting")
        task_id, correlation_id, event_id, observation_id = traffic_identifiers(
            current.owner_subject,
            current.id,
        )
        current.request_characters = request_characters
        current.response_characters = response_characters
        current.estimated_input_tokens = estimate_tokens(request_characters)
        current.estimated_output_tokens = estimate_tokens(response_characters)
        current.traffic_task_usage_id = str(task_id)
        current.traffic_correlation_id = str(correlation_id)
        current.traffic_event_id = str(event_id)
        current.traffic_observation_id = str(observation_id)
        current.traffic_receipt_status = None
        current.traffic_last_error_code = None
        current.traffic_delivered_at = None
        current.traffic_delivery_status = (
            _PENDING if self.settings.gateway_lup_mcp_traffic_enabled else _DISABLED
        )
        db.commit()
        db.refresh(current)
        if current.traffic_delivery_status == _PENDING:
            await self._deliver(db, current)
        return current

    async def flush_pending(
        self,
        db: Session,
        *,
        owner_subject: str | None = None,
    ) -> int:
        if not self.settings.gateway_lup_mcp_traffic_enabled:
            return 0
        query = db.query(AgentToolCall).filter(
            AgentToolCall.traffic_delivery_status == _PENDING,
        )
        if owner_subject is not None:
            query = query.filter(AgentToolCall.owner_subject == owner_subject)
        rows = (
            query.order_by(AgentToolCall.created_at, AgentToolCall.id)
            .limit(self.settings.gateway_lup_mcp_traffic_flush_limit)
            .all()
        )
        delivered = 0
        for row in rows:
            if await self._deliver(db, row):
                delivered += 1
        return delivered

    async def _deliver(self, db: Session, call: AgentToolCall) -> bool:
        call.traffic_attempt_count = int(call.traffic_attempt_count or 0) + 1
        try:
            published = await asyncio.to_thread(
                self.publisher.publish,
                call=call,
            )
        except Exception as error:
            call.traffic_delivery_status = _PENDING
            call.traffic_last_error_code = type(error).__name__[:128]
            db.commit()
            return False
        call.traffic_delivery_status = _DELIVERED
        call.traffic_receipt_status = published.receipt_status[:32]
        call.traffic_last_error_code = None
        call.traffic_delivered_at = published.accepted_at or datetime.now(UTC)
        db.commit()
        return True
