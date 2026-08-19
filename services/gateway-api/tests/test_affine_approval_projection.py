import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from gateway_api.affine_approval_projection import (
    AffineApprovalProjectionConfig,
    build_affine_approval_preview,
    decorate_preparation_preview,
    is_affine_research_server,
)
from gateway_api.config import Settings
from jsonschema import Draft202012Validator


def test_projection_config_requires_transactional_outbox() -> None:
    with pytest.raises(RuntimeError, match="transactional outbox"):
        AffineApprovalProjectionConfig.from_settings(
            Settings(
                gateway_affine_approval_projection_enabled=True,
                gateway_outbox_enabled=False,
            )
        )

    config = AffineApprovalProjectionConfig.from_settings(
        Settings(
            gateway_affine_approval_projection_enabled=True,
            gateway_outbox_enabled=True,
            gateway_affine_approval_preview_max_chars=256,
            gateway_affine_approval_preview_max_items=7,
        )
    )
    assert config.enabled is True
    assert config.preview_max_chars == 256
    assert config.preview_max_items == 7


def test_preview_is_bounded_and_source_query_is_removed() -> None:
    config = AffineApprovalProjectionConfig(
        enabled=True,
        server_endpoint="http://affine-research-provider:8010/mcp",
        preview_max_chars=128,
        preview_max_items=2,
    )
    content = "x" * 300
    preview = build_affine_approval_preview(
        "research_v1_document_update_content",
        {
            "workspace_id": "workspace",
            "document_id": "doc",
            "content": content,
            "expected_content_hash": "a" * 64,
        },
        config=config,
    )
    assert preview is not None
    assert preview.kind == "content_replace"
    assert preview.truncated is True
    assert len(preview.after_text or "") == 128
    assert preview.after_hash is not None
    assert content not in preview.model_dump_json()

    source = build_affine_approval_preview(
        "research_v1_document_add_source",
        {
            "workspace_id": "workspace",
            "document_id": "doc",
            "url": "https://example.test/paper?token=redacted#private",
            "title": "Paper",
            "locator": "p. 12",
            "expected_content_hash": "b" * 64,
        },
        config=config,
    )
    assert source is not None
    assert source.source_url == "https://example.test/paper"
    assert "token=" not in source.model_dump_json()


def test_affine_routing_uses_immutable_endpoint_not_display_name() -> None:
    affine = SimpleNamespace(
        origin="gateway",
        transport="streamable_http",
        endpoint_url="http://affine-research-provider:8010/mcp",
        display_name="anything",
    )
    spoof = SimpleNamespace(
        origin="gateway",
        transport="streamable_http",
        endpoint_url="https://unrelated.example.test/mcp",
        display_name="AFFiNE Research Knowledge v1",
    )
    config = AffineApprovalProjectionConfig.from_settings(Settings())
    assert is_affine_research_server(affine, config=config) is True
    assert is_affine_research_server(spoof, config=config) is False

    preview = decorate_preparation_preview(
        server=spoof,
        tool=SimpleNamespace(upstream_name="research_v1_document_update_title"),
        arguments={
            "workspace_id": "workspace",
            "document_id": "doc",
            "title": "new",
            "expected_title": "old",
        },
        base_preview={"tool": "research_v1_document_update_title"},
        settings=Settings(
            gateway_affine_approval_projection_enabled=True,
            gateway_outbox_enabled=True,
        ),
    )
    assert "affine_approval" not in preview



def test_affine_approval_projection_contract_is_registered_and_valid() -> None:
    root = Path(__file__).resolve().parents[3]
    schema_path = root / "schemas" / "gateway.affine.approval.projected.v1.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)

    root_asyncapi = (root / "asyncapi" / "gateway-events.asyncapi.yaml").read_text()
    contract_asyncapi = (
        root
        / "contracts"
        / "research-knowledge"
        / "approval-notifications"
        / "v1"
        / "asyncapi.yaml"
    ).read_text()
    event_type = "gateway.affine.approval.projected.v1"
    schema_ref = "gateway.affine.approval.projected.v1.schema.json"
    assert event_type in root_asyncapi
    assert schema_ref in root_asyncapi
    assert event_type in contract_asyncapi
    assert schema_ref in contract_asyncapi
