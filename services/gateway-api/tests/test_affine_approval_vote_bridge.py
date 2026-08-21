from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from gateway_api.dto import ApprovalVoteCreate
from gateway_api.models import ApprovalRequest, User
from gateway_api.routers import agent_autonomy as router_module


class _Query:
    def __init__(self, user):
        self.user = user

    def filter(self, *_args, **_kwargs):
        return self

    def one_or_none(self):
        return self.user


class _Db:
    def __init__(self, approval, user):
        self.approval = approval
        self.user = user

    def get(self, model, key):
        if model is ApprovalRequest and key == self.approval.id:
            return self.approval
        return None

    def query(self, model):
        assert model is User
        return _Query(self.user)


@pytest.mark.anyio
async def test_affine_vote_route_uses_mapped_gateway_user_and_canonical_cast_vote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = "approval-1"
    path = f"/api/agent-autonomy/affine/v1/approvals/{request_id}/votes"
    request = SimpleNamespace(method="POST", url=SimpleNamespace(path=path))
    approval = SimpleNamespace(id=request_id)
    user = SimpleNamespace(subject="gateway-reviewer", roles=["gateway-auditor"])
    db = _Db(approval, user)
    calls: dict[str, object] = {}

    def verify(assertion, **kwargs):
        calls["assertion"] = assertion
        calls["verification"] = kwargs
        return SimpleNamespace(affine_user_id="affine-user-1"), "gateway-reviewer"

    def cast_vote(db_arg, **kwargs):
        calls["cast_db"] = db_arg
        calls["cast"] = kwargs
        return approval

    monkeypatch.setattr(router_module, "verify_affine_approval_assertion", verify)
    monkeypatch.setattr(
        router_module, "is_affine_approval_request", lambda *_args, **_kwargs: True
    )
    monkeypatch.setattr(router_module.agent_autonomy_service, "cast_vote", cast_vote)
    monkeypatch.setattr(
        router_module,
        "_approval_response",
        lambda _db, *, request, user: {"id": request.id, "reviewer": user.subject},
    )

    response = await router_module.cast_affine_approval_vote(
        request=request,
        request_id=request_id,
        payload=ApprovalVoteCreate(decision="approve", reason="reviewed"),
        assertion="signed-assertion",
        db=db,
    )

    assert response == {"id": request_id, "reviewer": "gateway-reviewer"}
    assert calls["assertion"] == "signed-assertion"
    assert calls["verification"] == {
        "method": "POST",
        "path": path,
        "approval_request_id": request_id,
        "decision": "approve",
        "reason": "reviewed",
    }
    assert calls["cast_db"] is db
    assert calls["cast"] == {
        "request_id": request_id,
        "user": user,
        "decision": "approve",
        "reason": "reviewed",
    }


@pytest.mark.anyio
async def test_affine_vote_route_rejects_non_affine_request_before_cast_vote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_id = "approval-other"
    request = SimpleNamespace(
        method="POST",
        url=SimpleNamespace(
            path=f"/api/agent-autonomy/affine/v1/approvals/{request_id}/votes"
        ),
    )
    approval = SimpleNamespace(id=request_id)
    user = SimpleNamespace(subject="gateway-reviewer", roles=[])
    db = _Db(approval, user)
    monkeypatch.setattr(
        router_module,
        "verify_affine_approval_assertion",
        lambda *_args, **_kwargs: (
            SimpleNamespace(affine_user_id="affine-user-1"),
            "gateway-reviewer",
        ),
    )
    monkeypatch.setattr(
        router_module, "is_affine_approval_request", lambda *_args, **_kwargs: False
    )
    monkeypatch.setattr(
        router_module.agent_autonomy_service,
        "cast_vote",
        lambda *_args, **_kwargs: pytest.fail("canonical vote must not run"),
    )

    with pytest.raises(HTTPException) as exc_info:
        await router_module.cast_affine_approval_vote(
            request=request,
            request_id=request_id,
            payload=ApprovalVoteCreate(decision="approve"),
            assertion="signed-assertion",
            db=db,
        )
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "AFFiNE approval request not found"
