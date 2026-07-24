from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .database import SessionLocal, init_db
from .mcp_federation_runtime import (
    FederationBoundaryError,
    new_traceparent,
    parse_recursion_context,
)
from .mcp_upstream import UpstreamMcpManager
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
from .spa import SPAStaticFiles


def create_app() -> FastAPI:
    settings = get_settings()
    runtime = GatewayRuntime(settings=settings, session_factory=SessionLocal)
    upstream_mcp_manager = UpstreamMcpManager(
        public_base_url=settings.public_base_url,
        allow_private_networks=settings.gateway_mcp_upstream_allow_private_networks,
        allow_insecure_http=settings.gateway_mcp_upstream_allow_insecure_http,
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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        app.state.gateway_runtime = runtime
        await runtime.start()
        try:
            yield
        finally:
            await upstream_mcp_manager.stop()
            await runtime.stop()

    app = FastAPI(
        title=settings.app_name,
        version=settings.gateway_release_version,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.gateway_runtime = runtime
    app.state.upstream_mcp_manager = upstream_mcp_manager
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", settings.public_base_url.rstrip("/")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    async def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "gateway-api",
            "version": settings.gateway_release_version,
            "revision": settings.gateway_release_revision,
            "slot": settings.gateway_deployment_slot,
        }

    @app.get("/ready")
    async def ready(request: Request) -> dict:
        init_db()
        state = request.app.state.gateway_runtime.readiness()
        with SessionLocal() as db:
            state["federation"] = upstream_mcp_manager.readiness_snapshot(db)
        if state["status"] != "ready":
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
