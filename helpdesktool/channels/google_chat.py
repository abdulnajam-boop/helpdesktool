"""Google Chat channel adapter: verifies Google's signed Bearer ID token
against Google's own published JWKS, parses inbound ``MESSAGE`` space
events, and -- unlike Slack (``channels/slack.py``) -- can reply
**synchronously in the same HTTP response** Google Chat is already
blocked waiting on. That makes this the first channel adapter in this
codebase whose reply path is real end-to-end, not BLOCKED-EXTERNAL: no
bot token, no separate outbound API call, no live app installation
required to close the loop.

Verification reuses ``helpdesktool.oidc.OIDCVerifier`` rather than
duplicating JWT/JWKS-fetching logic: Google Chat's inbound auth token is a
completely standard Google-issued, RS256-signed JWT with the usual
``iss``/``aud``/``exp``/``sub`` claims (this module supplies the
provider's own fixed issuer and JWKS endpoint; only ``aud`` -- the
tenant's Google Cloud project number, stored as ``ChannelWorkspaceLink.
workspace_id`` -- varies per tenant). This is exactly the "swapping
providers is a configuration change" contract ``oidc.py``'s own docstring
describes, applied to a second, non-human-login use of the same standard.

Per Google's documented request-verification contract, Google Chat signs
with a service-account key distinct from a normal "Sign in with Google"
ID token: issuer ``chat@system.gserviceaccount.com``, JWKS at
``https://www.googleapis.com/service_accounts/v1/jwk/
chat@system.gserviceaccount.com`` -- not the generic
``accounts.google.com``/``oauth2/v3/certs`` used for user sign-in. Like
this codebase's other external-provider integrations that lack a live
account to test against (see ``windows_agent/win32_dns_resolver.py``'s
own disclosure before this pass), the exact claim shape here has not been
exercised against a real Google Cloud Chat app deployment -- only against
a locally generated RSA keypair standing in for Google's JWKS, exercising
the real verification code path (``OIDCVerifier``) that a genuine
deployment would also run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from helpdesktool.oidc import InvalidIdentityToken, OIDCVerifier

from . import ChannelSigningError

GOOGLE_CHAT_ISSUER = "chat@system.gserviceaccount.com"
GOOGLE_CHAT_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/chat@system.gserviceaccount.com"
)


def build_google_chat_verifier(audience: str, **kwargs: Any) -> OIDCVerifier:
    """``audience`` is the tenant's Google Cloud project number
    (``ChannelWorkspaceLink.workspace_id``) -- see ``api.py``'s
    ``google_chat_events``. Extra keyword arguments (e.g. a test
    ``key_resolver``) pass straight through to ``OIDCVerifier``.
    """
    return OIDCVerifier(GOOGLE_CHAT_ISSUER, audience, GOOGLE_CHAT_JWKS_URL, **kwargs)


def verify_google_chat_request(
    verifier: OIDCVerifier, authorization_header: str
) -> None:
    """Raises ``ChannelSigningError`` -- never returns a bool -- matching
    ``verify_slack_signature``'s single raise/no-raise decision point."""
    if not authorization_header.startswith("Bearer "):
        raise ChannelSigningError("missing bearer token")
    token = authorization_header.removeprefix("Bearer ").strip()
    if not token:
        raise ChannelSigningError("missing bearer token")
    try:
        verifier.verify(token)
    except InvalidIdentityToken as exc:
        raise ChannelSigningError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class GoogleChatEventEnvelope:
    event_id: str
    space_name: str
    user_name: str
    text: str


def parse_google_chat_event(
    payload: Mapping[str, Any],
) -> GoogleChatEventEnvelope | None:
    """Extracts the fields the Conversation Service needs from a Google
    Chat ``MESSAGE`` event, or ``None`` if this event should not be
    processed at all (e.g. ``ADDED_TO_SPACE``/``REMOVED_FROM_SPACE``,
    which carry no message text). Google Chat has no bot-echo problem
    Slack's loop-prevention filter exists for: a synchronous reply is
    rendered directly by Chat as this app's own response, never re-
    delivered to this same webhook as a new inbound event.
    """
    if payload.get("type") != "MESSAGE":
        return None
    message = payload.get("message")
    if not isinstance(message, dict):
        return None
    space = payload.get("space")
    if not isinstance(space, dict):
        return None
    sender = message.get("sender")
    text = message.get("text")
    space_name = space.get("name")
    user_name = sender.get("name") if isinstance(sender, dict) else None
    event_id = message.get("name")
    if not (text and space_name and user_name and event_id):
        return None
    return GoogleChatEventEnvelope(
        event_id=str(event_id),
        space_name=str(space_name),
        user_name=str(user_name),
        text=str(text),
    )


def build_google_chat_reply(text: str) -> dict[str, Any]:
    """The synchronous JSON response body Google Chat renders as this
    app's reply. No outbound API call, no bot token, no BLOCKED-EXTERNAL
    dependency, unlike Slack's ``SlackReplySender``/Teams' equivalent."""
    return {"text": text}


__all__ = [
    "GOOGLE_CHAT_ISSUER",
    "GOOGLE_CHAT_JWKS_URL",
    "GoogleChatEventEnvelope",
    "build_google_chat_reply",
    "build_google_chat_verifier",
    "parse_google_chat_event",
    "verify_google_chat_request",
]
