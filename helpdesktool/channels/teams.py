"""Microsoft Teams channel adapter, via the Bot Framework Connector
Service (not a bespoke Teams API -- Teams is one channel among several
that Azure Bot Service routes through the same Bot Framework protocol).

Verification: the documented, stable Bot Framework contract
-------------------------------------------------------------
Every request Bot Framework delivers to a bot's messaging endpoint
carries an ``Authorization: Bearer <jwt>`` header. The token is:

- RS256-signed.
- ``iss`` (issuer): ``https://api.botframework.com`` (the public/
  commercial Azure cloud -- the US Government cloud uses a different
  issuer, not supported here).
- ``aud`` (audience): this bot's single, platform-wide Microsoft App ID
  (``Settings.teams_bot_app_id``). Unlike Google Chat's per-customer
  Cloud project number, one Bot Framework App registration serves every
  Microsoft 365 tenant that installs this app -- the audience is a fixed
  constant, not something a ``ChannelWorkspaceLink`` varies.
- JWKS published at ``https://login.botframework.com/v1/.well-known/
  keys``.
- A ``serviceurl`` claim that, when present, must match the Activity's
  own ``serviceUrl`` field -- the documented Bot Framework SDK protection
  against a token being replayed to redirect where a reply would be sent.

Deliberately **not** required: a ``sub`` claim. This token authenticates
the Bot Framework Connector Service itself, not an end user, so its exact
claim set is less certain than a standard OIDC ID token's (see
``helpdesktool.oidc.OIDCVerifier``, which does require ``sub`` because a
human-login ID token always carries one) -- this verifier checks only
what is genuinely well-documented (signature, issuer, audience, expiry,
and the conditional ``serviceUrl`` match) rather than asserting an
unverified detail about a token type this codebase has never seen for
real. That is why this module writes its own small verifier with
``pyjwt``/``PyJWKClient`` directly instead of reusing ``OIDCVerifier``.

The actual Teams end-user identity is never taken from message text or
from the JWT itself -- it comes from the Activity body's
``from.aadObjectId`` (falling back to ``from.id``), trusted only because
the request that carried it has already been cryptographically verified
as genuinely from the Bot Framework Connector Service. This is the same
identity-in-an-already-verified-payload pattern ``channels/slack.py``'s
``event.user`` and ``channels/google_chat.py``'s ``message.sender.name``
both use.

No loop-prevention filter is needed here, unlike Slack: Bot Framework
never redelivers a bot's own sent replies to this same messaging
endpoint. A reply is posted out-of-band to the Bot Connector REST API
against the Activity's own ``serviceUrl`` -- see ``NullTeamsReplySender``
below -- never received back as a new inbound activity.

**BLOCKED-EXTERNAL**: this has not been exercised against a live Bot
Framework/Teams app registration (no Azure AD app exists in this
environment) -- only against a locally generated RSA keypair standing in
for the real JWKS, exactly the same disclosed-limitation pattern
``google_chat.py`` used before its own live verification pass. Outbound
replies (POSTing to ``{serviceUrl}/v3/conversations/{conversationId}/
activities/{activityId}`` via the Bot Connector API) require a real Azure
AD client secret to obtain an OAuth2 token first -- also BLOCKED-EXTERNAL;
``NullTeamsReplySender`` is the only implementation that exists, and it
only logs, mirroring ``channels/slack.py``'s ``NullSlackReplySender``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

import jwt
from jwt import PyJWKClient

from . import ChannelSigningError

LOG = logging.getLogger("helpdesktool-channels-teams")

BOT_FRAMEWORK_ISSUER = "https://api.botframework.com"
BOT_FRAMEWORK_JWKS_URL = "https://login.botframework.com/v1/.well-known/keys"


class BotFrameworkKeyResolver(Protocol):
    """Matches ``PyJWKClient``'s interface -- production fetches and
    caches keys from the real Bot Framework JWKS endpoint; tests inject a
    resolver backed by a locally generated key pair (see
    ``tests/support.StaticKeyResolver``), exactly like ``oidc.py``'s
    ``SigningKeyResolver``.
    """

    def get_signing_key_from_jwt(self, token: str) -> Any: ...


def verify_teams_bot_framework_token(
    authorization_header: str,
    *,
    app_id: str,
    activity_service_url: str | None,
    key_resolver: BotFrameworkKeyResolver | None = None,
) -> None:
    """Raises ``ChannelSigningError`` -- never returns a bool -- matching
    ``verify_slack_signature``'s single raise/no-raise decision point.
    ``activity_service_url`` is the Activity payload's own (not yet
    trusted) ``serviceUrl`` field; it is only ever *compared against* the
    signed token's ``serviceurl`` claim, never trusted on its own.
    """
    if not authorization_header.startswith("Bearer "):
        raise ChannelSigningError("missing bearer token")
    token = authorization_header.removeprefix("Bearer ").strip()
    if not token:
        raise ChannelSigningError("missing bearer token")
    resolver = key_resolver or PyJWKClient(BOT_FRAMEWORK_JWKS_URL)
    try:
        signing_key = resolver.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=app_id,
            issuer=BOT_FRAMEWORK_ISSUER,
            options={"require": ["exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        raise ChannelSigningError(str(exc)) from exc
    claimed_service_url = claims.get("serviceurl")
    if (
        isinstance(claimed_service_url, str)
        and activity_service_url is not None
        and claimed_service_url.rstrip("/") != activity_service_url.rstrip("/")
    ):
        raise ChannelSigningError(
            "serviceUrl claim does not match the activity's serviceUrl"
        )


@dataclass(frozen=True, slots=True)
class TeamsActivityEnvelope:
    activity_id: str
    tenant_id: str  # Microsoft 365 / Azure AD tenant id, channelData.tenant.id
    user_id: str  # from.aadObjectId, falling back to from.id
    conversation_id: str
    text: str
    service_url: str


def parse_teams_activity(payload: Mapping[str, Any]) -> TeamsActivityEnvelope | None:
    """Extracts the fields the Conversation Service needs from a Bot
    Framework ``message`` Activity, or ``None`` if this event should not
    be processed at all (e.g. ``conversationUpdate`` -- a bot
    added/removed from a chat -- which carries no message text).
    """
    if payload.get("type") != "message":
        return None
    text = payload.get("text")
    activity_id = payload.get("id")
    service_url = payload.get("serviceUrl")
    conversation = payload.get("conversation")
    conversation_id = conversation.get("id") if isinstance(conversation, dict) else None
    sender = payload.get("from")
    user_id = None
    if isinstance(sender, dict):
        user_id = sender.get("aadObjectId") or sender.get("id")
    channel_data = payload.get("channelData")
    tenant_id = None
    if isinstance(channel_data, dict):
        tenant = channel_data.get("tenant")
        if isinstance(tenant, dict):
            tenant_id = tenant.get("id")
    if not (
        text
        and activity_id
        and service_url
        and conversation_id
        and user_id
        and tenant_id
    ):
        return None
    return TeamsActivityEnvelope(
        activity_id=str(activity_id),
        tenant_id=str(tenant_id),
        user_id=str(user_id),
        conversation_id=str(conversation_id),
        text=str(text),
        service_url=str(service_url),
    )


class TeamsReplySender(Protocol):
    def send(
        self, *, service_url: str, conversation_id: str, activity_id: str, text: str
    ) -> None: ...


class NullTeamsReplySender:
    """The only implementation available in this environment -- posting a
    real reply needs an OAuth2 token obtained from Azure AD using this
    bot's App ID + client secret, then a POST to the Bot Connector API
    (BLOCKED-EXTERNAL, no live Azure AD app registration exists here).
    Logs instead of silently discarding, so an operator can see what
    *would* have been sent -- mirrors ``NullSlackReplySender`` exactly.
    """

    def send(
        self, *, service_url: str, conversation_id: str, activity_id: str, text: str
    ) -> None:
        LOG.info(
            "teams reply not sent (no bot credentials configured): "
            "service_url=%s conversation_id=%s activity_id=%s text=%r",
            service_url,
            conversation_id,
            activity_id,
            text,
        )


__all__ = [
    "BOT_FRAMEWORK_ISSUER",
    "BOT_FRAMEWORK_JWKS_URL",
    "NullTeamsReplySender",
    "TeamsActivityEnvelope",
    "TeamsReplySender",
    "parse_teams_activity",
    "verify_teams_bot_framework_token",
]
