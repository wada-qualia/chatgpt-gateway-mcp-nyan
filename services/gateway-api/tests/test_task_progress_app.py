from __future__ import annotations

from datetime import UTC, datetime

import pytest
from gateway_api.config import Settings
from gateway_api.mcp_federation_compat import (
    MCP_APPS_EXTENSION_ID,
    MCP_CURRENT_PROTOCOL_VERSION,
    QUALIFIED_PUBLIC_SERVER_EXTENSIONS,
    QUALIFIED_SERVER_EXTENSIONS,
    ModernRequestAdmission,
    gateway_public_server_capabilities,
)
from gateway_api.mcp_presentation import PresentationContext
from gateway_api.task_progress import (
    TASK_PROGRESS_CAPABILITY_ID,
    TASK_PROGRESS_RESOURCE_MIME,
    TASK_PROGRESS_RESOURCE_URI,
    TASK_PROGRESS_RESOURCE_V1_URI,
    TASK_PROGRESS_RESOURCE_V2_URI,
    TASK_PROGRESS_RESOURCE_V3_URI,
    TASK_PROGRESS_RESOURCE_V4_URI,
    TASK_PROGRESS_RESOURCE_V5_URI,
    TASK_PROGRESS_RESOURCE_V6_URI,
    TASK_PROGRESS_RESOURCE_V7_URI,
    TASK_PROGRESS_RESOURCE_V8_URI,
    TASK_PROGRESS_RESOURCE_V9_URI,
    TaskProgressSnapshotV1,
    TaskProgressSourceV1,
    TaskProgressStageV1,
    TaskProgressValueV1,
)
from gateway_api.task_progress_app import (
    TASK_PROGRESS_APP_HTML,
    TASK_PROGRESS_APP_SHA256,
    TASK_PROGRESS_APP_V1_HTML,
    TASK_PROGRESS_APP_V1_SHA256,
    TASK_PROGRESS_APP_V2_HTML,
    TASK_PROGRESS_APP_V2_SHA256,
    TASK_PROGRESS_APP_V3_HTML,
    TASK_PROGRESS_APP_V3_SHA256,
    TASK_PROGRESS_APP_V4_HTML,
    TASK_PROGRESS_APP_V4_SHA256,
    TASK_PROGRESS_APP_V5_HTML,
    TASK_PROGRESS_APP_V5_SHA256,
    TASK_PROGRESS_APP_V6_HTML,
    TASK_PROGRESS_APP_V6_SHA256,
    TASK_PROGRESS_APP_V7_HTML,
    TASK_PROGRESS_APP_V7_SHA256,
    TASK_PROGRESS_APP_V8_HTML,
    TASK_PROGRESS_APP_V8_SHA256,
    TASK_PROGRESS_APP_V9_HTML,
    TASK_PROGRESS_APP_V9_SHA256,
    TASK_PROGRESS_CANCEL_TOOL,
    TASK_PROGRESS_GET_TOOL,
    TASK_PROGRESS_RENDER_TOOL,
    TASK_PROGRESS_TOOL_NAMES,
    task_progress_apps_negotiated,
    task_progress_resource_list_result,
    task_progress_resource_read_result,
    task_progress_server_extensions,
    task_progress_tool_definitions,
    task_progress_tool_result,
)


def _presentation(allowed: frozenset[str] | None = None) -> PresentationContext:
    return PresentationContext(
        profile_id="developer-dynamic",
        client_id="test-client",
        policy_generation=1,
        scopes=frozenset({"mcp:read"}),
        allowed_tool_names=allowed,
        configured_mode="catalog_broker",
        selected_mode="catalog_broker",
        capabilities=frozenset(),
        workspace_plan="none",
        chat_context_mode="off",
        selection_reason="test",
    )


def _admission(*, mime_types: list[str] | None = None) -> ModernRequestAdmission:
    extension = {"mimeTypes": mime_types or [TASK_PROGRESS_RESOURCE_MIME]}
    return ModernRequestAdmission(
        protocol_version=MCP_CURRENT_PROTOCOL_VERSION,
        client_capabilities={"extensions": {MCP_APPS_EXTENSION_ID: extension}},
        client_info={"name": "task-progress-test", "version": "1"},
        requested_extensions=(MCP_APPS_EXTENSION_ID,),
    )


def _snapshot() -> TaskProgressSnapshotV1:
    now = datetime(2026, 9, 1, tzinfo=UTC)
    stage = TaskProgressStageV1(
        id="stage-1",
        title="Qualification",
        status="running",
        priority=90,
        dependencies=[],
        acceptance_total=2,
        acceptance_passed=1,
        updated_at=now,
    )
    return TaskProgressSnapshotV1(
        run_id="run-1",
        title="Task Progress qualification",
        status="running",
        project="gateway",
        source=TaskProgressSourceV1(
            repository="products/gateway",
            project_path="gateway",
            base_commit="abc123",
            work_item_ids=["stage-1"],
            command_ids=[],
            session_ids=[],
        ),
        progress=TaskProgressValueV1(
            mode="determinate", completed=0, total=1, unit="stage"
        ),
        current_stage_id="stage-1",
        stages=[stage],
        blockers=[],
        checks=[],
        resources=[],
        changes={"visible_count": 1, "added_lines": 2, "removed_lines": 0},
        delivery={},
        artifacts=[],
        cancel_supported=False,
        sequence=7,
        updated_at=now,
    )


def test_apps_negotiation_is_modern_feature_and_policy_gated() -> None:
    enabled = Settings(gateway_task_progress_ui_enabled=True)
    disabled = Settings(gateway_task_progress_ui_enabled=False)
    admission = _admission()
    assert task_progress_apps_negotiated(enabled, admission, _presentation()) is True
    assert task_progress_apps_negotiated(disabled, admission, _presentation()) is False
    assert task_progress_apps_negotiated(enabled, None, _presentation()) is False
    assert (
        task_progress_apps_negotiated(
            enabled,
            _admission(mime_types=["text/html"]),
            _presentation(),
        )
        is False
    )
    assert (
        task_progress_apps_negotiated(
            enabled,
            admission,
            _presentation(frozenset({TASK_PROGRESS_RENDER_TOOL})),
        )
        is False
    )
    assert (
        task_progress_apps_negotiated(
            enabled,
            admission,
            _presentation(frozenset(TASK_PROGRESS_TOOL_NAMES)),
        )
        is True
    )


def test_public_apps_qualification_does_not_qualify_upstream_apps() -> None:
    assert MCP_APPS_EXTENSION_ID in QUALIFIED_PUBLIC_SERVER_EXTENSIONS
    assert MCP_APPS_EXTENSION_ID not in QUALIFIED_SERVER_EXTENSIONS
    assert gateway_public_server_capabilities(tools_list_changed=False) == {"tools": {}}
    capabilities = gateway_public_server_capabilities(
        tools_list_changed=True,
        extensions=task_progress_server_extensions(True),
    )
    assert capabilities["tools"] == {"listChanged": True}
    assert capabilities["resources"] == {}
    assert capabilities["extensions"] == {MCP_APPS_EXTENSION_ID: {}}
    with pytest.raises(ValueError, match="Unqualified public MCP extension"):
        gateway_public_server_capabilities(
            tools_list_changed=False,
            extensions={"example.invalid/ui": {}},
        )


def test_task_progress_resource_is_immutable_self_contained_and_sandboxed() -> None:
    listed = task_progress_resource_list_result()["resources"]
    assert [item["uri"] for item in listed] == [
        TASK_PROGRESS_RESOURCE_URI,
        TASK_PROGRESS_RESOURCE_V9_URI,
        TASK_PROGRESS_RESOURCE_V8_URI,
        TASK_PROGRESS_RESOURCE_V7_URI,
        TASK_PROGRESS_RESOURCE_V6_URI,
        TASK_PROGRESS_RESOURCE_V5_URI,
        TASK_PROGRESS_RESOURCE_V4_URI,
        TASK_PROGRESS_RESOURCE_V3_URI,
        TASK_PROGRESS_RESOURCE_V2_URI,
        TASK_PROGRESS_RESOURCE_V1_URI,
    ]
    assert all(item["mimeType"] == TASK_PROGRESS_RESOURCE_MIME for item in listed)
    assert "legacy v9" in listed[1]["name"]
    assert "legacy v8" in listed[2]["name"]
    assert "legacy v7" in listed[3]["name"]
    assert "legacy v6" in listed[4]["name"]
    assert "legacy v5" in listed[5]["name"]
    assert "legacy v4" in listed[6]["name"]
    assert "legacy v3" in listed[7]["name"]
    assert "legacy v2" in listed[8]["name"]
    assert "legacy v1" in listed[9]["name"]
    meta = listed[0]["_meta"]["ui"]
    assert meta["csp"] == {
        "connectDomains": [],
        "resourceDomains": [],
        "frameDomains": [],
        "baseUriDomains": [],
    }
    assert meta["permissions"] == {}
    assert meta["prefersBorder"] is True

    active = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_URI)["contents"][0]
    assert active["uri"] == TASK_PROGRESS_RESOURCE_URI
    assert active["text"] == TASK_PROGRESS_APP_HTML
    assert len(TASK_PROGRESS_APP_HTML.encode("utf-8")) == 18837
    assert TASK_PROGRESS_APP_SHA256 == "18e1083af7218f7f4d64918bad29b018348db2317b9c5d06a4a94ea7f3ff8a7c"

    legacy_v9 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V9_URI)["contents"][0]
    assert legacy_v9["uri"] == TASK_PROGRESS_RESOURCE_V9_URI
    assert legacy_v9["text"] == TASK_PROGRESS_APP_V9_HTML
    assert len(TASK_PROGRESS_APP_V9_HTML.encode("utf-8")) == 18488
    assert TASK_PROGRESS_APP_V9_SHA256 == "5be04c885ca05b86f193e2148c03218626ddbb73d5147658406e2c62d881eae6"

    legacy_v8 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V8_URI)["contents"][0]
    assert legacy_v8["uri"] == TASK_PROGRESS_RESOURCE_V8_URI
    assert legacy_v8["text"] == TASK_PROGRESS_APP_V8_HTML
    assert TASK_PROGRESS_APP_V8_SHA256 == "fdb4732537feeedca875a56b8c9b2b0b2becfd6cfcf7ac229c8ebf800da3276a"

    legacy_v7 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V7_URI)["contents"][0]
    assert legacy_v7["uri"] == TASK_PROGRESS_RESOURCE_V7_URI
    assert legacy_v7["text"] == TASK_PROGRESS_APP_V7_HTML
    assert TASK_PROGRESS_APP_V7_SHA256 == "e5ec527a24436146616d4ba4595aa274157dbb9dae6917d9e7e65fc1ff35e364"

    legacy_v6 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V6_URI)["contents"][0]
    assert legacy_v6["uri"] == TASK_PROGRESS_RESOURCE_V6_URI
    assert legacy_v6["text"] == TASK_PROGRESS_APP_V6_HTML
    assert TASK_PROGRESS_APP_V6_SHA256 == "21fe88c2351fb7a896e1b5c690b3914fae8d4b3e286238677b4e4d8698fc1729"

    legacy_v5 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V5_URI)["contents"][0]
    assert legacy_v5["uri"] == TASK_PROGRESS_RESOURCE_V5_URI
    assert legacy_v5["text"] == TASK_PROGRESS_APP_V5_HTML
    assert TASK_PROGRESS_APP_V5_SHA256 == "e7f7422c07605fcee0d72364cea8bf342455746e6807351b5f7e7dfb4f44b31b"

    legacy_v4 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V4_URI)["contents"][0]
    assert legacy_v4["uri"] == TASK_PROGRESS_RESOURCE_V4_URI
    assert legacy_v4["text"] == TASK_PROGRESS_APP_V4_HTML
    assert TASK_PROGRESS_APP_V4_SHA256 == "2e2f901bdba42d47e28cf0655ccdf15acab323f13d89a8e3eb45c4f48e834de7"

    legacy_v3 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V3_URI)["contents"][0]
    assert legacy_v3["uri"] == TASK_PROGRESS_RESOURCE_V3_URI
    assert legacy_v3["text"] == TASK_PROGRESS_APP_V3_HTML
    assert TASK_PROGRESS_APP_V3_SHA256 == "89c7a07f72b28d38c232925c323879e42acdff239f7ac376b344c64e53600cae"

    legacy_v2 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V2_URI)["contents"][0]
    assert legacy_v2["uri"] == TASK_PROGRESS_RESOURCE_V2_URI
    assert legacy_v2["text"] == TASK_PROGRESS_APP_V2_HTML
    assert TASK_PROGRESS_APP_V2_SHA256 == "4730fb0fe981206079cc50d1155d14e80103d616e5852d1630d2b3d2f6ed5b2f"

    legacy_v1 = task_progress_resource_read_result(TASK_PROGRESS_RESOURCE_V1_URI)["contents"][0]
    assert legacy_v1["uri"] == TASK_PROGRESS_RESOURCE_V1_URI
    assert legacy_v1["text"] == TASK_PROGRESS_APP_V1_HTML
    assert TASK_PROGRESS_APP_V1_SHA256 == "1de3c8f2940a00202faef802519094a94040c911545fce8107f8bb2478d20c6d"

    assert TASK_PROGRESS_APP_V1_HTML != TASK_PROGRESS_APP_V2_HTML
    assert TASK_PROGRESS_APP_V2_HTML != TASK_PROGRESS_APP_V3_HTML
    assert TASK_PROGRESS_APP_V3_HTML != TASK_PROGRESS_APP_V4_HTML
    assert TASK_PROGRESS_APP_V4_HTML != TASK_PROGRESS_APP_V5_HTML
    assert TASK_PROGRESS_APP_V5_HTML != TASK_PROGRESS_APP_V6_HTML
    assert TASK_PROGRESS_APP_V6_HTML != TASK_PROGRESS_APP_V7_HTML
    assert TASK_PROGRESS_APP_V7_HTML != TASK_PROGRESS_APP_V8_HTML
    assert TASK_PROGRESS_APP_V8_HTML != TASK_PROGRESS_APP_V9_HTML
    assert TASK_PROGRESS_APP_V9_HTML != TASK_PROGRESS_APP_HTML
    assert "allowLegacyFallback" in TASK_PROGRESS_APP_V3_HTML
    assert "isDefiniteStandardBridgeUnavailable" in TASK_PROGRESS_APP_V3_HTML
    assert "message.params&&message.params.arguments||{}" in TASK_PROGRESS_APP_V4_HTML
    assert "const params=message.params&&typeof message.params===\"object\"?message.params:{}" in TASK_PROGRESS_APP_V5_HTML
    assert "const input=params.arguments&&typeof params.arguments===\"object\"?params.arguments:params" in TASK_PROGRESS_APP_V5_HTML
    assert "const params=message.params&&typeof message.params===\"object\"?message.params:{}" in TASK_PROGRESS_APP_V6_HTML
    assert "const input=params.arguments&&typeof params.arguments===\"object\"?params.arguments:params" in TASK_PROGRESS_APP_V6_HTML
    assert "allowCompatibilityFallback" in TASK_PROGRESS_APP_V6_HTML
    assert "const params=message.params&&typeof message.params===\"object\"?message.params:{}" in TASK_PROGRESS_APP_HTML
    assert "const input=params.arguments&&typeof params.arguments===\"object\"?params.arguments:params" in TASK_PROGRESS_APP_HTML
    assert "mcp_tool_result" not in TASK_PROGRESS_APP_V7_HTML
    assert "call_tool_result" not in TASK_PROGRESS_APP_V7_HTML
    assert "mcp_tool_result" in TASK_PROGRESS_APP_V8_HTML
    assert "call_tool_result" in TASK_PROGRESS_APP_V8_HTML
    assert "mcp_tool_result" in TASK_PROGRESS_APP_HTML
    assert "call_tool_result" in TASK_PROGRESS_APP_HTML
    assert "function initializeHostBridge()" not in TASK_PROGRESS_APP_V8_HTML
    assert "function deferInitializeHostBridge()" not in TASK_PROGRESS_APP_V8_HTML
    assert "function initializeHostBridge()" in TASK_PROGRESS_APP_HTML
    assert "function deferInitializeHostBridge()" in TASK_PROGRESS_APP_HTML
    assert 'window.addEventListener("load",deferInitializeHostBridge,{once:true})' in TASK_PROGRESS_APP_HTML
    assert 'if(document.readyState==="complete")deferInitializeHostBridge()' in TASK_PROGRESS_APP_HTML

    lower = TASK_PROGRESS_APP_HTML.lower()
    assert "<script src=" not in lower
    assert "fetch(" not in lower
    assert ".innerhtml" not in lower
    assert "postmessage" in lower
    assert "ui/initialize" in TASK_PROGRESS_APP_HTML
    assert "tools/call" in TASK_PROGRESS_APP_HTML
    assert "window.openai" in TASK_PROGRESS_APP_HTML
    assert "openai:set_globals" in TASK_PROGRESS_APP_HTML
    assert "const previousRunId=runId" in TASK_PROGRESS_APP_HTML
    assert "if(runId&&runId!==previousRunId)refresh()" in TASK_PROGRESS_APP_HTML
    assert "catch(_){reconnecting=true;render();scheduleRefresh()}" in TASK_PROGRESS_APP_HTML
    assert "refreshTimer=setTimeout(()=>{refreshTimer=null;reconnecting=false;refresh()},4000)" in TASK_PROGRESS_APP_HTML
    assert "standardBridgeState=\"pending\"" in TASK_PROGRESS_APP_HTML
    assert "allowLegacyFallback" not in TASK_PROGRESS_APP_HTML
    assert "allowCompatibilityFallback" in TASK_PROGRESS_APP_HTML
    assert "isDefiniteStandardBridgeUnavailable" in TASK_PROGRESS_APP_HTML
    assert "Promise.race([standardBridgeReady" not in TASK_PROGRESS_APP_V9_HTML
    assert "Promise.race([standardBridgeReady" in TASK_PROGRESS_APP_HTML
    assert 'setTimeout(()=>resolve("compatibility-timeout"),500)' in TASK_PROGRESS_APP_HTML
    assert 'state==="compatibility-timeout"&&standardBridgeState==="pending"' in TASK_PROGRESS_APP_HTML
    assert "try{return await standardCallTool(name,toolArgs)}" in TASK_PROGRESS_APP_HTML
    assert "return compatibilityCallTool(name,toolArgs)" in TASK_PROGRESS_APP_HTML
    assert "callTool(\"task_progress_get\",args(true),{allowCompatibilityFallback:true})" in TASK_PROGRESS_APP_HTML
    assert "callTool(\"task_progress_cancel\",args(false))" in TASK_PROGRESS_APP_HTML
    assert 'callTool("task_progress_cancel",args(false),{' not in TASK_PROGRESS_APP_HTML
    assert "if(Number.isInteger(message.error.code))error.code=message.error.code" in TASK_PROGRESS_APP_HTML
    assert "settleStandardBridge(\"ready\")" in TASK_PROGRESS_APP_V6_HTML
    assert "const capabilities=result&&result.hostCapabilities" in TASK_PROGRESS_APP_HTML
    assert "settleStandardBridge(capabilities&&capabilities.serverTools?\"ready\":\"unavailable\")" in TASK_PROGRESS_APP_HTML
    assert "settleStandardBridge(\"unavailable\")" in TASK_PROGRESS_APP_HTML
    assert "host.callTool" in TASK_PROGRESS_APP_HTML
    assert "refreshInFlight" in TASK_PROGRESS_APP_HTML
    assert "host.requestDisplayMode" in TASK_PROGRESS_APP_HTML
    assert "host.notifyIntrinsicHeight" in TASK_PROGRESS_APP_HTML
    assert "overflow:auto" not in lower
    with pytest.raises(ValueError, match="Unknown Task Progress UI resource"):
        task_progress_resource_read_result("ui://atlas/task-progress/v11.html")


def test_task_progress_tools_have_strict_schemas_and_component_only_metadata() -> None:
    fallback = {
        tool["name"]: tool
        for tool in task_progress_tool_definitions()
    }
    apps = {
        tool["name"]: tool
        for tool in task_progress_tool_definitions()
    }
    assert set(apps) == TASK_PROGRESS_TOOL_NAMES
    expected_security_schemes = [{"type": "oauth2", "scopes": []}]
    for tool in fallback.values():
        assert "_meta" in tool
        assert tool["securitySchemes"] == expected_security_schemes
        assert tool["_meta"]["securitySchemes"] == expected_security_schemes
        assert tool["securitySchemes"] is not tool["_meta"]["securitySchemes"]
        assert tool["inputSchema"]["additionalProperties"] is False
        assert tool["inputSchema"]["required"] == ["run_id"]
        assert tool["outputSchema"]["additionalProperties"] is False
        assert set(tool["outputSchema"]["required"]) == set(
            tool["outputSchema"]["properties"]
        )
    render_meta = apps[TASK_PROGRESS_RENDER_TOOL]["_meta"]
    assert render_meta["ui"]["resourceUri"] == TASK_PROGRESS_RESOURCE_URI
    assert render_meta["ui/resourceUri"] == TASK_PROGRESS_RESOURCE_URI
    assert fallback[TASK_PROGRESS_RENDER_TOOL]["_meta"]["ui"]["resourceUri"] == TASK_PROGRESS_RESOURCE_URI
    assert render_meta["ui"]["visibility"] == ["model", "app"]
    assert render_meta["openai/outputTemplate"] == TASK_PROGRESS_RESOURCE_URI
    assert render_meta["openai/widgetAccessible"] is True
    assert "resourceUri" not in apps[TASK_PROGRESS_GET_TOOL]["_meta"]["ui"]
    assert "resourceUri" not in apps[TASK_PROGRESS_CANCEL_TOOL]["_meta"]["ui"]
    assert apps[TASK_PROGRESS_GET_TOOL]["_meta"]["openai/widgetAccessible"] is True
    assert apps[TASK_PROGRESS_CANCEL_TOOL]["_meta"]["openai/widgetAccessible"] is True
    assert apps[TASK_PROGRESS_CANCEL_TOOL]["annotations"]["destructiveHint"] is True
    assert apps[TASK_PROGRESS_RENDER_TOOL]["annotations"]["readOnlyHint"] is True


def test_task_progress_tool_result_keeps_complete_text_fallback() -> None:
    snapshot = _snapshot()
    fallback = task_progress_tool_result(snapshot, apps_negotiated=False)
    assert fallback["isError"] is False
    assert fallback["content"][0]["type"] == "text"
    assert "Task Progress qualification" in fallback["content"][0]["text"]
    assert fallback["structuredContent"]["capability"] == TASK_PROGRESS_CAPABILITY_ID
    assert "_meta" not in fallback

    apps = task_progress_tool_result(
        snapshot,
        apps_negotiated=True,
        last_sequence=snapshot.sequence,
    )
    assert "snapshot" not in apps["structuredContent"]
    component = apps["_meta"]["atlas.task_progress_ui"]
    assert component["resourceUri"] == TASK_PROGRESS_RESOURCE_URI
    assert component["resourceSha256"] == TASK_PROGRESS_APP_SHA256
    assert component["unchanged"] is True
    assert component["snapshot"]["run_id"] == snapshot.run_id
