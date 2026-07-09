from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .database import init_db
from .routers import access, audit, auth, devices, docker, file_changes, mcp, monitoring, oauth, thin_clients


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        init_db()
        yield

    app = FastAPI(title=settings.app_name, version="0.1.0", openapi_url="/openapi.json", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", settings.public_base_url.rstrip("/")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "gateway-api"}

    @app.get("/ready")
    async def ready() -> dict[str, str]:
        init_db()
        return {"status": "ready"}

    app.include_router(auth.router)
    app.include_router(oauth.router)
    app.include_router(devices.router)
    app.include_router(docker.router)
    app.include_router(thin_clients.activation_router)
    app.include_router(thin_clients.router)
    app.include_router(access.router)
    app.include_router(audit.router)
    app.include_router(monitoring.router)
    app.include_router(file_changes.router)
    app.include_router(mcp.router)

    dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
