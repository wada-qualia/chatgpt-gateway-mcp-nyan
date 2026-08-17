from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from .config import get_settings
from .database import MetricsSessionLocal, SessionLocal
from .mcp_federation_runtime import (
    FederationBoundaryError,
    new_traceparent,
    parse_recursion_context,
)
from .mcp_upstream import UpstreamMcpManager
from .metrics_cache import GatewayMetricsCache
from .readiness_cache import ReadinessCache
from .research_write_approval import ResearchWriteApprovalWorker
from .routers import (
    access,
    account,
    agent_autonomy,
    agent_collaboration,
    agent_coordination,
    audit,
    auth,
    devices,
    docker,
    file_changes,
    mcp,
    mcp_federation,
    mcp_upstream,
    monitoring,
    oauth,
    outbox,
    realtime,
    registry,
    thin_clients,
    usage_accounting,
)
from .runtime import GatewayRuntime
from .schema_migrations import (
    revision_is_forward,
    validate_database_schema,
)
from .spa import SPAStaticFiles

logger = logging.getLogger(__name__)


def _normalized_request_path(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template:
        return template[:256]
    return "/<unmatched>"


def create_app() -> FastAPI:
    settings = get_settings()
    runtime = GatewayRuntime(settings=settings, session_factory=SessionLocal)
    upstream_mcp_manager = UpstreamMcpManager(
        public_base_url=settings.public_base_url,
        allow_private_networks=settings.gateway_mcp_upstream_allow_private_networks,
        allow_insecure_http=settings.gateway_mcp_upstream_allow_insecure_http,
        trusted_internal_endpoints=settings.mcp_trusted_internal_endpoints,
        connect_timeout_seconds=settings.gateway_mcp_upstream_connect_timeout_seconds,
        call_timeout_seconds=settings.gateway_mcp_upstream_call_timeout_seconds,
        cancellation_grace_seconds=settings.gateway_mcp_upstream_cancellation_grace_seconds,
        max_concurrency_per_server=settings.gateway_mcp_upstream_max_concurrency_per_server,
        max_concurrency_per_tenant=settings.gateway_mcp_upstream_max_concurrency_per_tenant,
        calls_per_minute_per_server=settings.gateway_mcp_upstream_calls_per_minute_per_server,
        calls_per_minute_per_tenant=settings.gateway_mcp_upstream_calls_per_minute_per_tenant,
        max_connections=settings.gateway_mcp_upstream_max_connections,
        max_keepalive_connections=settings.gateway_mcp_upstream_max_keepalive_connections,
        circuit_failure_threshold=settings.gateway_mcp_upstream_circuit_failure_threshold,
        circuit_open_seconds=settings.gateway_mcp_upstream_circuit_open_seconds,
        circuit_max_open_seconds=settings.gateway_mcp_upstream_circuit_max_open_seconds,
        federation_enabled=settings.gateway_mcp_federation_enabled,
        federation_writes_paused=settings.gateway_mcp_federation_writes_paused,
        pilot_owner_subjects=settings.mcp_federation_pilot_owner_subjects,
        gateway_instance_id=(
            settings.gateway_mcp_instance_id
            or settings.gateway_replica_id
            or "gateway-local"
        ),
        max_federation_hops=settings.gateway_mcp_max_federation_hops,
        catalog_stale_after_seconds=settings.gateway_mcp_catalog_stale_after_seconds,
        max_result_bytes=settings.gateway_mcp_upstream_max_result_bytes,
        max_text_bytes=settings.gateway_mcp_upstream_max_text_bytes,
        max_content_items=settings.gateway_mcp_upstream_max_content_items,
        max_catalog_tools=settings.gateway_mcp_catalog_max_tools,
        thin_client_transport=thin_clients.thin_client_manager,
    )
    readiness_cache = ReadinessCache(
        settings=settings,
        session_factory=SessionLocal,
        upstream_mcp_manager=upstream_mcp_manager,
    )
    metrics_cache = GatewayMetricsCache(
        settings=settings,
        session_factory=MetricsSessionLocal,
        outbox=runtime.outbox,
        upstream_mcp_manager=upstream_mcp_manager,
    )
    research_write_approval_worker = ResearchWriteApprovalWorker(
        settings=settings,
        session_factory=SessionLocal,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runtime_started = False
        readiness_cache_started = False
        metrics_cache_started = False
        research_write_approval_started = False
        app.state.initialization_status = "verifying_schema"
        app.state.database_at_head = False
        app.state.database_forward_compatible = False
        app.state.database_schema_valid = False
        app.state.database_compatible = False
        try:
            migration_status = await asyncio.to_thread(
                validate_database_schema,
                allow_forward_revision=True,
            )
            forward_compatible = revision_is_forward(
                migration_status.current_revision,
                migration_status.head_revision,
            )
            app.state.database_revision = migration_status.current_revision
            app.state.database_head = migration_status.head_revision
            app.state.database_at_head = migration_status.at_head
            app.state.database_forward_compatible = forward_compatible
            app.state.database_schema_valid = True
            app.state.database_compatible = True
            app.state.initialization_status = "starting_runtime"
            app.state.gateway_runtime = runtime
            await asyncio.to_thread(readiness_cache.seed, migration_status)
            await runtime.start()
            runtime_started = True
            await readiness_cache.start()
            readiness_cache_started = True
            await metrics_cache.start()
            metrics_cache_started = True
            await research_write_approval_worker.start()
            research_write_approval_started = True
            app.state.initialization_status = "ready"
            yield
        except BaseException:
            app.state.initialization_status = "failed"
            app.state.database_at_head = False
            app.state.database_forward_compatible = False
            app.state.database_schema_valid = False
            app.state.database_compatible = False
            raise
        finally:
            if research_write_approval_started:
                await research_write_approval_worker.stop()
            if metrics_cache_started:
                await metrics_cache.stop()
            if readiness_cache_started:
                await readiness_cache.stop()
            await upstream_mcp_manager.stop()
            if runtime_started:
                await runtime.stop()
            if app.state.initialization_status != "failed":
                app.state.initialization_status = "stopped"

    app = FastAPI(
        title=settings.app_name,
        version=settings.gateway_release_version,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.gateway_runtime = runtime
    app.state.upstream_mcp_manager = upstream_mcp_manager
    app.state.readiness_cache = readiness_cache
    app.state.metrics_cache = metrics_cache
    app.state.initialization_status = "created"
    app.state.database_revision = None
    app.state.database_head = None
    app.state.database_at_head = False
    app.state.database_forward_compatible = False
    app.state.database_schema_valid = False
    app.state.database_compatible = False

    @app.exception_handler(SQLAlchemyTimeoutError)
    async def database_pool_timeout_handler(
        _request: Request, _error: SQLAlchemyTimeoutError
    ) -> JSONResponse:
        logger.warning("gateway_database_pool_timeout")
        return JSONResponse(
            status_code=503,
            content={"detail": "Database connection pool temporarily unavailable"},
            headers={"Retry-After": "1"},
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", settings.public_base_url.rstrip("/")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_timing(request: Request, call_next):
        started = time.monotonic()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            total_duration = max(0.0, time.monotonic() - started)
            upstream_duration = getattr(
                request.state, "upstream_duration_seconds", None
            )
            mcp_method = getattr(request.state, "mcp_method", None)
            logger.info(
                "gateway_request_completed",
                extra={
                    "http_method": request.method,
                    "normalized_path": _normalized_request_path(request),
                    "mcp_method": mcp_method,
                    "status_code": status_code,
                    "duration_seconds": total_duration,
                    "upstream_duration_seconds": upstream_duration,
                },
            )

    @app.middleware("http")
    async def initialization_gate(request: Request, call_next):
        initialization_status = request.app.state.initialization_status
        database_compatible = request.app.state.database_compatible
        if request.url.path not in {"/health", "/ready"} and (
            initialization_status != "ready" or not database_compatible
        ):
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "initialization_status": initialization_status,
                    "database_at_head": request.app.state.database_at_head,
                    "database_forward_compatible": (
                        request.app.state.database_forward_compatible
                    ),
                    "database_schema_valid": request.app.state.database_schema_valid,
                    "database_compatible": database_compatible,
                    "database_revision": request.app.state.database_revision,
                    "database_head": request.app.state.database_head,
                },
            )
        return await call_next(request)

    @app.middleware("http")
    async def federation_boundary(request: Request, call_next):
        traceparent = new_traceparent(request.headers.get("traceparent"))
        request.state.traceparent = traceparent
        federation_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower().startswith("x-gateway-mcp-")
        }
        if federation_headers:
            try:
                request.state.mcp_recursion_context = parse_recursion_context(
                    federation_headers,
                    instance_id=upstream_mcp_manager.gateway_instance_id,
                    max_hops=upstream_mcp_manager.max_federation_hops,
                )
            except FederationBoundaryError as exc:
                upstream_mcp_manager.telemetry.increment(
                    "recursion_rejected", outcome=exc.code
                )
                return JSONResponse(
                    status_code=exc.http_status,
                    content={"code": exc.code, "message": exc.message},
                    headers={"traceparent": traceparent},
                )
        response = await call_next(request)
        response.headers["traceparent"] = traceparent
        return response

    @app.get("/health")
    async def health(request: Request) -> dict[str, object]:
        return {
            "status": "ok",
            "service": "gateway-api",
            "version": settings.gateway_release_version,
            "revision": settings.gateway_release_revision,
            "slot": settings.gateway_deployment_slot,
            "initialization_status": request.app.state.initialization_status,
            "database_at_head": request.app.state.database_at_head,
            "database_forward_compatible": (
                request.app.state.database_forward_compatible
            ),
            "database_schema_valid": request.app.state.database_schema_valid,
            "database_compatible": request.app.state.database_compatible,
            "database_revision": request.app.state.database_revision,
            "database_head": request.app.state.database_head,
        }

    @app.get("/ready")
    async def ready(request: Request) -> dict:
        state = request.app.state.gateway_runtime.readiness()
        state["initialization_status"] = request.app.state.initialization_status
        cache: ReadinessCache = request.app.state.readiness_cache
        snapshot, stale, refresh_error = cache.cached()
        database_reachable = await cache.probe_database()
        cache_valid = snapshot is not None and not stale
        if snapshot is not None:
            migration_status = snapshot.migration_status
            database_revision = migration_status.current_revision
            database_head = migration_status.head_revision
            database_at_head = migration_status.at_head
            forward_compatible = snapshot.forward_compatible
            state["federation"] = snapshot.federation
        else:
            database_revision = request.app.state.database_revision
            database_head = request.app.state.database_head
            database_at_head = request.app.state.database_at_head
            forward_compatible = False
        database_compatible = cache_valid and database_reachable
        request.app.state.database_revision = database_revision
        request.app.state.database_head = database_head
        request.app.state.database_at_head = database_at_head
        request.app.state.database_forward_compatible = forward_compatible
        request.app.state.database_schema_valid = cache_valid
        request.app.state.database_compatible = database_compatible
        state["database_revision"] = database_revision
        state["database_head"] = database_head
        state["database_at_head"] = database_at_head
        state["database_forward_compatible"] = forward_compatible
        state["database_schema_valid"] = cache_valid
        state["database_compatible"] = database_compatible
        if not database_compatible:
            state["status"] = "not_ready"
            if not cache_valid:
                state["database_error_code"] = (
                    "readiness_cache_stale"
                    if snapshot is not None
                    else refresh_error or "schema_validation_failed"
                )
            else:
                state["database_error_code"] = "database_probe_failed"
            raise HTTPException(status_code=503, detail=state)
        if state["status"] != "ready" or state["initialization_status"] != "ready":
            raise HTTPException(status_code=503, detail=state)
        return state

    app.include_router(auth.router)
    app.include_router(account.router)
    app.include_router(oauth.router)
    app.include_router(devices.router)
    app.include_router(docker.router)
    app.include_router(thin_clients.activation_router)
    app.include_router(thin_clients.router)
    app.include_router(access.router)
    app.include_router(audit.router)
    app.include_router(monitoring.router)
    app.include_router(file_changes.router)
    app.include_router(agent_collaboration.router)
    app.include_router(agent_coordination.router)
    app.include_router(agent_autonomy.router)
    app.include_router(outbox.router)
    app.include_router(outbox.metrics_router)
    app.include_router(realtime.router)
    app.include_router(registry.router)
    app.include_router(usage_accounting.router)
    app.include_router(mcp_federation.router)
    app.include_router(mcp_upstream.router)
    app.include_router(mcp.router)

    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist.exists():
        app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
