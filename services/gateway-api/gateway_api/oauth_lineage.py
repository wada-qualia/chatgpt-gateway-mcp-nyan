from __future__ import annotations

from sqlalchemy.orm import Session

from .models import OAuthClient, OAuthCode

CHATGPT_CONNECTOR_REDIRECT_PREFIX = "https://chatgpt.com/connector/oauth/"


def chatgpt_connector_policy_predecessors(
    db: Session,
    *,
    oauth_client: OAuthClient,
    subject: str,
    redirect_uri: str,
    lock: bool = False,
) -> list[OAuthClient]:
    if not redirect_uri.startswith(CHATGPT_CONNECTOR_REDIRECT_PREFIX):
        return []
    if oauth_client.redirect_uris != [redirect_uri]:
        return []

    predecessor_ids = [
        client_id
        for (client_id,) in (
            db.query(OAuthCode.client_id)
            .filter(
                OAuthCode.subject == subject,
                OAuthCode.consumed.is_(True),
                OAuthCode.client_id != oauth_client.client_id,
            )
            .distinct()
            .all()
        )
    ]
    if not predecessor_ids:
        return []

    query = (
        db.query(OAuthClient)
        .filter(
            OAuthClient.client_id.in_(predecessor_ids),
            OAuthClient.chat_context_mode.in_(("optional", "required")),
        )
        .order_by(OAuthClient.client_id.asc())
    )
    if lock:
        query = query.with_for_update()
    candidates = query.all()
    return [
        candidate
        for candidate in candidates
        if candidate.redirect_uris == [redirect_uri]
    ]
