from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway_api.spa import SPAStaticFiles


@pytest.fixture()
def spa_client(tmp_path: Path) -> TestClient:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text("<html><body>gateway-spa</body></html>")
    (assets / "app.js").write_text("console.log('gateway')")

    app = FastAPI()

    @app.get("/api/value")
    async def api_value() -> dict[str, bool]:
        return {"ok": True}

    app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")
    return TestClient(app)


@pytest.mark.parametrize(
    "path",
    [
        "/devices",
        "/devices/",
        "/thin-clients",
        "/monitoring",
        "/some/deep/path?tab=details",
    ],
)
def test_spa_routes_return_index_html(spa_client: TestClient, path: str) -> None:
    response = spa_client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "gateway-spa" in response.text


def test_spa_head_navigation_returns_index_metadata(spa_client: TestClient) -> None:
    response = spa_client.head("/devices")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.content == b""


def test_static_asset_requests_keep_real_404_behavior(spa_client: TestClient) -> None:
    existing = spa_client.get("/assets/app.js")
    missing = spa_client.get("/assets/missing.js")

    assert existing.status_code == 200
    assert "gateway" in existing.text
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not Found"}


def test_backend_routes_and_prefixes_do_not_use_spa_fallback(spa_client: TestClient) -> None:
    existing = spa_client.get("/api/value")
    missing = spa_client.get("/api/missing")

    assert existing.status_code == 200
    assert existing.json() == {"ok": True}
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not Found"}


def test_non_navigation_file_path_does_not_use_spa_fallback(spa_client: TestClient) -> None:
    response = spa_client.get("/missing.json")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
