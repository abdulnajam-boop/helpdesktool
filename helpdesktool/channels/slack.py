"""Slack channel adapter: request signature verification, replay
protection, and inbound event parsing -- no Slack SDK dependency (stdlib
``hmac``/``hashlib`` only, matching this codebase's dependency-light
pattern for trust-boundary code, e.g. ``agent_common``).

**Outbound replies are BLOCKED-EXTERNAL.** Actually posting a reply back
into a Slack conversation requires calling Slack's ``chat.postMessage``
with a real bot token, which needs a live Slack app installation this
environment does not have. ``SlackReplySender`` below is the real,
already-correct interface for that call; ``NullSlackReplySender`` is the
only implementation that exists today, and it only logs. Everything
*before* that point -- signature verification, replay protection, event
parsing, bot-message loop prevention, identity resolution, and the full
identity -> conversation -> intent -> policy -> connector/ticket pipeline
-- is real and fully exercised by ``POST /v1/channels/slack/events/{link_id}``
in ``api.py``, not mocked.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Protocol

from . import ChannelSigningError

LOG = logging.getLogger("helpdesktool-channels-slack")

# Slack's own documented recommendation (https://api.slack.com/authentication/verifying-requests-from-slack):
# reject any request whose timestamp is more than five minutes old, to
# defeat replay of a captured, still-validly-signed request.
MAX_TIMESTAMP_SKEW_SECONDS = 300


def verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    now: datetime | None = None,
) -> None:
    """Implements Slack's documented v0 request-signing scheme. Raises
    ``ChannelSigningError`` -- never returns a bool -- so a caller cannot
    accidentally ignore a ``False`` result; every failure mode (malformed
    timestamp, excessive clock skew, signature mismatch) is a single
    raise/no-raise decision point.
    """
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise ChannelSigningError("malformed X-Slack-Request-Timestamp") from exc

    current = int((now or datetime.now(UTC)).timestamp())
    if abs(current - ts) > MAX_TIMESTAMP_SKEW_SECONDS:
        raise ChannelSigningError("request timestamp is outside the allowed skew")

    basestring = b"v0:" + timestamp.encode() + b":" + body
    computed = (
        "v0="
        + hmac.new(signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    )
    if not hmac.compare_digest(computed, signature):
        raise ChannelSigningError("signature mismatch")


_SLACK_SECRET_PREFIX = "HELPDESK_SLACK_SIGNING_SECRET_"


def resolve_slack_signing_secret(environment: Mapping[str, str], reference: str) -> str:
    """Same environment-reference-only pattern as
    ``integrations.EnvironmentSecretsProvider``/``ApplicationConnectorConfig.
    credential_ref`` -- a signing secret is never stored as a literal value
    in the database, only a reference to where the real value actually
    lives.
    """
    if not reference.startswith("env:"):
        raise ChannelSigningError("unsupported signing secret reference")
    name = reference.removeprefix("env:")
    if not name.startswith(_SLACK_SECRET_PREFIX):
        raise ChannelSigningError("slack signing secret reference has invalid prefix")
    value = environment.get(name)
    if not value:
        raise ChannelSigningError("slack signing secret is unavailable")
    return value


@dataclass(frozen=True, slots=True)
class SlackEventEnvelope:
    event_id: str
    team_id: str
    user_id: str
    channel_id: str
    text: str
    thread_ts: str | None


def parse_slack_event(payload: Mapping[str, Any]) -> SlackEventEnvelope | None:
    """Extracts the fields the Conversation Service needs from a Slack
    Events API ``event_callback`` payload, or ``None`` if this event
    should not be processed at all.

    Critically filters out any event carrying ``bot_id``/
    ``subtype == "bot_message"`` -- without this, a bot's own reply (once
    reply-sending is implemented) would itself trigger a new inbound
    event, which would trigger another reply, forever. This is this
    adapter's concrete instance of Phase 8's loop-prevention requirement.
    """
    if payload.get("type") != "event_callback":
        return None
    event = payload.get("event")
    if not isinstance(event, dict):
        return None
    if event.get("type") != "message":
        return None
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return None
    user_id = event.get("user")
    text = event.get("text")
    channel_id = event.get("channel")
    event_id = payload.get("event_id")
    team_id = payload.get("team_id")
    if not (user_id and text and channel_id and event_id and team_id):
        return None
    return SlackEventEnvelope(
        event_id=str(event_id),
        team_id=str(team_id),
        user_id=str(user_id),
        channel_id=str(channel_id),
        text=str(text),
        thread_ts=event.get("thread_ts"),
    )


class SlackReplySender(Protocol):
    def send(self, *, channel_id: str, thread_ts: str | None, text: str) -> None: ...


class NullSlackReplySender:
    """The only implementation available in this environment -- posting a
    real reply needs a live Slack bot token (BLOCKED-EXTERNAL, no
    installed Slack app exists here). Logs instead of silently discarding,
    so an operator can see what *would* have been sent."""

    def send(self, *, channel_id: str, thread_ts: str | None, text: str) -> None:
        LOG.info(
            "slack reply not sent (no bot token configured): channel=%s thread_ts=%s text=%r",
            channel_id,
            thread_ts,
            text,
        )


__all__ = [
    "MAX_TIMESTAMP_SKEW_SECONDS",
    "NullSlackReplySender",
    "SlackEventEnvelope",
    "SlackReplySender",
    "parse_slack_event",
    "resolve_slack_signing_secret",
    "verify_slack_signature",
]
