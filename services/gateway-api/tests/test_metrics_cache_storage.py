from __future__ import annotations

from types import SimpleNamespace

from gateway_api.config import Settings
from gateway_api.metrics_cache import GatewayMetricsCache


def _cache(settings: Settings) -> GatewayMetricsCache:
    cache = GatewayMetricsCache.__new__(GatewayMetricsCache)
    cache.settings = settings
    return cache


def test_storage_snapshot_sets_warning_and_critical_watermarks(monkeypatch) -> None:
    settings = Settings(
        gateway_storage_monitor_path="/monitored",
        gateway_storage_warning_usage_ratio=0.80,
        gateway_storage_critical_usage_ratio=0.95,
    )
    cache = _cache(settings)
    monkeypatch.setattr(
        "gateway_api.metrics_cache.shutil.disk_usage",
        lambda path: SimpleNamespace(total=1000, used=900, free=40),
    )

    snapshot = cache._storage_snapshot()

    assert snapshot == {
        "available": True,
        "path": "/monitored",
        "total_bytes": 1000,
        "used_bytes": 900,
        "free_bytes": 40,
        "usage_ratio": 0.96,
        "warning": True,
        "critical": True,
    }


def test_storage_snapshot_reports_unavailable_without_failing_metrics(
    monkeypatch,
) -> None:
    settings = Settings(gateway_storage_monitor_path="/missing")
    cache = _cache(settings)

    def unavailable(path: str):
        raise FileNotFoundError(path)

    monkeypatch.setattr("gateway_api.metrics_cache.shutil.disk_usage", unavailable)

    snapshot = cache._storage_snapshot()

    assert snapshot["available"] is False
    assert snapshot["path"] == "/missing"
    assert snapshot["total_bytes"] == 0
    assert snapshot["used_bytes"] == 0
    assert snapshot["free_bytes"] == 0
    assert snapshot["usage_ratio"] == 0.0
    assert snapshot["warning"] is False
    assert snapshot["critical"] is False
