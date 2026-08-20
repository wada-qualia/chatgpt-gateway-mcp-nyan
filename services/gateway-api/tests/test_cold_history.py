from __future__ import annotations

import asyncio

import httpx
import pytest
from gateway_api.cold_history import (
    ColdHistoryClient,
    ColdHistoryProtocolError,
    item_order_key,
)


def test_malformed_health_json_is_typed_protocol_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{not-json",
            headers={"content-type": "application/json"},
        )

    async_client = httpx.AsyncClient(
        base_url="https://history.test",
        transport=httpx.MockTransport(handler),
    )
    history_client = ColdHistoryClient(
        base_url="https://history.test",
        ca_cert_path="unused",
        client_cert_path="unused",
        client_key_path="unused",
        connect_timeout_seconds=1.0,
        read_timeout_seconds=1.0,
        client=async_client,
    )
    try:
        with pytest.raises(ColdHistoryProtocolError, match="not valid JSON"):
            asyncio.run(history_client.health())
    finally:
        asyncio.run(history_client.close())


def test_invalid_history_timestamp_is_typed_protocol_error() -> None:
    with pytest.raises(ColdHistoryProtocolError, match="invalid created_at"):
        item_order_key(
            {"id": "event-1", "created_at": "not-a-timestamp"},
            timestamp_key="created_at",
        )
