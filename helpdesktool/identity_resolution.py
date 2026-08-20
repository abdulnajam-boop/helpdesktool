"""Channel identity resolution: maps an authenticated chat-provider identity
to a Helpdesktool user, for the omnichannel help desk architecture (see
CLAUDE.md's Channel Adapter -> Identity Resolver -> Conversation Service
chain).

Trust model, stated plainly because it's the single most important
invariant in this module: **the only trustworthy input here is the
provider's own authenticated identity claim** (its signature-verified
webhook payload's user id, or -- for the web channel -- the caller's
already-verified Helpdesktool session). A name, email, or employee id that
merely appears in a chat *message's text* is never an acceptable
resolution input; if it were, anyone could type "reset my password, I'm
admin@example.com" and impersonate another employee. Every channel
adapter is responsible for extracting its own already-authenticated
identity signal (verified against the provider's own signature/token, not
parsed from message content) before calling ``resolve_channel_identity``.

For this MVP pass, ``email`` is the resolution key -- exact, case-sensitive
match against ``User.email`` within the given tenant, mirroring
``auth.py``'s OIDC-based resolution (a verified email claim, never a
client-supplied header). No fuzzy or partial matching is ever performed:
an unresolvable identity is reported as such, not guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db_models import User


@dataclass(frozen=True, slots=True)
class ChannelIdentity:
    """An already-authenticated identity claim from a channel adapter --
    never constructed from unverified chat message content.
    """

    channel: str
    provider_user_id: str
    email: str


def resolve_channel_identity(
    session: Session, tenant_id: str, identity: ChannelIdentity
) -> User | None:
    """Returns the matching active ``User`` for this tenant, or ``None`` if
    no exact, active match exists. Never raises on a miss -- an
    unresolvable identity is an ordinary, expected outcome (a contractor
    messaging from a personal account, a typo in provider-side email
    mapping), not an error condition, and the caller decides how to
    respond (e.g. "I couldn't verify who you are; please contact IT").
    """
    return session.scalar(
        select(User).where(
            User.tenant_id == tenant_id,
            User.email == identity.email,
            User.active.is_(True),
        )
    )


__all__ = ["ChannelIdentity", "resolve_channel_identity"]
