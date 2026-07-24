from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import SessionLocal, init_db
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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        app.state.gateway_runtime = runtime
        await runtime.start()
        try:
            yield
        finally:
            await runtime.stop()

    app = FastAPI(
        title=settings.app_name,
        version=settings.gateway_release_version,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.gateway_runtime = runtime
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", settings.public_base_url.rstrip("/")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    app.include_router(mcp.router)

    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist.exists():
        app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
