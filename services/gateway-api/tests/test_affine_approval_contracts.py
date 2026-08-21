import json
from pathlib import Path

import yaml
from jsonschema.validators import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "contracts/research-knowledge/approval-notifications/v1"
PROJECTION_SCHEMA = ROOT / "schemas/gateway.affine.approval.projected.v1.schema.json"
VOTE_PATH = "/api/agent-autonomy/affine/v1/approvals/{request_id}/votes"


def test_affine_approval_contract_schemas_are_valid_and_additive() -> None:
    projection = json.loads(PROJECTION_SCHEMA.read_text())
    assertion = json.loads(
        (CONTRACT / "affine-approval-vote-assertion.schema.json").read_text()
    )
    Draft202012Validator.check_schema(projection)
    Draft202012Validator.check_schema(assertion)

    assert "eligible_reviewer_bindings" in projection["properties"]
    assert "unmapped_reviewer_count" in projection["properties"]
    assert "eligible_reviewer_bindings" not in projection["required"]
    assert "unmapped_reviewer_count" not in projection["required"]
    assert assertion["properties"]["aud"]["const"] == (
        "chatgpt-mcp-gateway:affine-approval-v1"
    )
    assert assertion["additionalProperties"] is False


def test_affine_approval_vote_openapi_matches_versioned_bridge() -> None:
    openapi = yaml.safe_load((CONTRACT / "openapi.yaml").read_text())
    assert openapi["openapi"] == "3.1.0"
    operation = openapi["paths"][VOTE_PATH]["post"]
    header = next(
        item
        for item in operation["parameters"]
        if item["in"] == "header" and item["name"] == "X-AFFiNE-Approval-Assertion"
    )
    assert header["required"] is True
    assert header["schema"]["maxLength"] == 8192
    vote = openapi["components"]["schemas"]["ApprovalVote"]
    assert vote["properties"]["decision"]["enum"] == ["approve", "reject"]
    assert "voter_subject" not in vote["properties"]
