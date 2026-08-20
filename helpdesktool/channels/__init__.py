"""Channel adapters for the omnichannel help desk (Phase 18): each adapter
verifies its provider's own request signature, extracts an
already-authenticated identity claim, and calls into the single shared
``conversation.handle_message`` -- see CLAUDE.md's Channel Adapter ->
Identity Resolver -> Conversation Service -> Intent Classifier -> Policy ->
Connector -> Ticket -> Audit -> Response chain. Slack is the first adapter
(``helpdesktool/channels/slack.py``); Teams/Google Chat plug in behind the
same shape.
"""

from __future__ import annotations


class ChannelSigningError(ValueError):
    """A channel webhook request failed signature/replay verification and
    must not be trusted or processed."""


__all__ = ["ChannelSigningError"]
