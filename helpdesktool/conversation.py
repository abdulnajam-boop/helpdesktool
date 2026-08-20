"""Conversation Service: the single shared orchestration layer every
channel adapter (web chat today; Slack/Teams/Google Chat adapters plug in
here later, per CLAUDE.md's Channel Adapter -> Identity Resolver ->
Conversation Service -> Intent Classifier -> Policy -> Connector -> Ticket
-> Audit -> Response chain) feeds a resolved identity and a message into.

Intent classification here is deliberately a small, deterministic keyword
matcher -- not an LLM call -- for the same reason
``helpdesktool/ai/provider.py``'s ``DeterministicFallbackProvider`` exists:
the whole pipeline (identity -> intent -> policy -> connector -> ticket ->
audit) must be provable end to end with no external AI provider
configured. A real NLU/LLM-based classifier can be layered in later behind
the exact same ``ClassifiedIntent`` contract this module returns --
whatever classifies intent, the *safety* boundary is unchanged: the
classifier only ever proposes a structured intent, never an executable
instruction, and everything downstream of it (policy, connector execution)
is exactly as deterministic and auditable regardless of how the intent was
guessed.

**Self-service scope, stated explicitly:** this pass only supports an
employee acting on *their own* account (`target_email` is always the
resolved requester's own email -- there is no "reset someone else's
password" chat command). A future admin-assist flow that lets a helpdesk
operator act on another employee's behalf is real, separate, higher-risk
scope this pass does not build.

**Approval, stated explicitly:** every high-risk connector operation
(`connectors.HIGH_RISK_OPERATIONS`) requires approval from a user other
than the requester -- the exact same separation-of-duties rule
`orchestrator.py` enforces for endpoint actions, applied here rather than
loosened for the "it's my own account" case, so a v1 pilot has a human in
the loop for every credential-affecting operation. Loosening this for
low-blast-radius self-service resets is real, deliberately deferred future
work -- not built to avoid the more conservative default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .connectors import HIGH_RISK_OPERATIONS
from .db_models import (
    ApplicationConnectorConfig,
    ConnectorRequest,
    Conversation,
    ConversationMessage,
    Ticket,
    User,
)
from .persistence import SqlAuditLog

_PASSWORD_RESET_RE = re.compile(r"\b(reset|forgot|forgotten)\b.*\bpassword\b", re.I)
_UNLOCK_RE = re.compile(r"\b(unlock|locked out of|locked)\b.*\baccount\b", re.I)
_MFA_RESET_RE = re.compile(
    r"\breset\b.*\b(mfa|2fa|multi.?factor|authenticator)\b", re.I
)

_INTENT_OPERATIONS: dict[str, str] = {
    "password_reset": "reset_password",
    "unlock_account": "unlock_account",
    "mfa_reset": "reset_mfa",
}


@dataclass(frozen=True, slots=True)
class ClassifiedIntent:
    intent: str  # "password_reset" | "unlock_account" | "mfa_reset" | "general_inquiry"
    application_hint: str | None  # e.g. "salesforce", parsed from message text


def classify_intent(
    message: str, known_application_ids: frozenset[str]
) -> ClassifiedIntent:
    """Deterministic keyword classification -- see module docstring for why
    this is intentionally not an LLM call. ``known_application_ids`` scopes
    the application-name match to applications the caller's tenant actually
    has a connector configured for, so an unrelated word in the message can
    never accidentally match an application name that means nothing here.
    """
    lowered = message.lower()
    application_hint = next(
        (app_id for app_id in known_application_ids if app_id in lowered), None
    )
    if _PASSWORD_RESET_RE.search(message):
        return ClassifiedIntent("password_reset", application_hint)
    if _UNLOCK_RE.search(message):
        return ClassifiedIntent("unlock_account", application_hint)
    if _MFA_RESET_RE.search(message):
        return ClassifiedIntent("mfa_reset", application_hint)
    return ClassifiedIntent("general_inquiry", application_hint)


@dataclass(frozen=True, slots=True)
class ConversationTurnResult:
    conversation_id: str
    reply: str
    ticket_id: str | None
    connector_request_id: str | None


def _audit(
    session: Session,
    tenant_id: str,
    correlation_id: str,
    event_type: str,
    actor_id: str,
    details: dict[str, Any],
) -> None:
    SqlAuditLog(session).append(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        event_type=event_type,
        actor_id=actor_id,
        details=details,
    )


def handle_message(
    session: Session,
    tenant_id: str,
    user: User,
    channel: str,
    channel_thread_id: str,
    message: str,
    *,
    conversation_id: str | None = None,
) -> ConversationTurnResult:
    """Processes one inbound message from an already-identity-resolved
    user (see ``identity_resolution.py`` -- the caller must have already
    verified ``user`` is who the channel says it is; this function trusts
    it completely). Creates or continues a ``Conversation``, classifies
    intent, and either proposes a policy-gated connector operation or
    creates a general support ticket.
    """
    conversation = (
        session.get(Conversation, conversation_id) if conversation_id else None
    )
    if conversation is None or conversation.tenant_id != tenant_id:
        conversation = Conversation(
            tenant_id=tenant_id,
            channel=channel,
            channel_thread_id=channel_thread_id,
            user_id=user.id,
            status="open",
        )
        session.add(conversation)
        session.flush()
        _audit(
            session,
            tenant_id,
            conversation.id,
            "conversation.started",
            user.id,
            {"channel": channel},
        )

    session.add(
        ConversationMessage(
            tenant_id=tenant_id,
            conversation_id=conversation.id,
            role="user",
            content=message,
        )
    )

    connectors = session.scalars(
        select(ApplicationConnectorConfig).where(
            ApplicationConnectorConfig.tenant_id == tenant_id,
            ApplicationConnectorConfig.active.is_(True),
        )
    ).all()
    known_application_ids = frozenset(c.application_id for c in connectors)
    classified = classify_intent(message, known_application_ids)

    ticket_id = conversation.ticket_id
    connector_request_id: str | None = None

    if classified.intent == "general_inquiry":
        if ticket_id is None:
            ticket = Ticket(
                tenant_id=tenant_id,
                title=message[:280] or "Help desk chat request",
                description=message,
                priority="normal",
                created_by=user.id,
            )
            session.add(ticket)
            session.flush()
            ticket_id = ticket.id
            conversation.ticket_id = ticket_id
            _audit(
                session,
                tenant_id,
                ticket_id,
                "ticket.created",
                user.id,
                {"source": "conversation", "conversation_id": conversation.id},
            )
        reply = (
            f"I've logged this as ticket #{ticket_id[:8]}. An IT operator will "
            "follow up. If this is about a specific application password, "
            "account lockout, or MFA reset, tell me which application and "
            "I can help directly."
        )
    else:
        operation = _INTENT_OPERATIONS[classified.intent]
        connector_config = next(
            (c for c in connectors if c.application_id == classified.application_hint),
            connectors[0] if len(connectors) == 1 else None,
        )
        if connector_config is None:
            reply = (
                "I understood you want an account action, but I couldn't tell "
                'which application -- please name it (e.g. "reset my '
                'Salesforce password").'
                if connectors
                else "No applications are configured for self-service account "
                "actions yet. I've logged this as a ticket instead."
            )
            if not connectors:
                ticket = Ticket(
                    tenant_id=tenant_id,
                    title=message[:280] or "Help desk chat request",
                    description=message,
                    priority="normal",
                    created_by=user.id,
                )
                session.add(ticket)
                session.flush()
                ticket_id = ticket.id
                conversation.ticket_id = ticket_id
        else:
            request = ConnectorRequest(
                tenant_id=tenant_id,
                conversation_id=conversation.id,
                connector_id=connector_config.id,
                operation=operation,
                target_email=user.email,
                requested_by=user.id,
                risk="high" if operation in HIGH_RISK_OPERATIONS else "read_only",
                status="pending_approval",
            )
            session.add(request)
            session.flush()
            connector_request_id = request.id
            ticket = Ticket(
                tenant_id=tenant_id,
                title=f"{operation.replace('_', ' ').title()}: {connector_config.display_name}",
                description=message,
                priority="high",
                created_by=user.id,
            )
            session.add(ticket)
            session.flush()
            ticket_id = ticket.id
            conversation.ticket_id = ticket_id
            _audit(
                session,
                tenant_id,
                request.id,
                "connector_request.created",
                user.id,
                {
                    "operation": operation,
                    "application_id": connector_config.application_id,
                    "target_email": user.email,
                    "ticket_id": ticket_id,
                },
            )
            reply = (
                f"I've submitted a request to {operation.replace('_', ' ')} for "
                f"{connector_config.display_name} on your account. This needs "
                "approval from an admin before it runs -- and before an admin "
                "can approve it, you'll need to log into the Helpdesktool "
                "console yourself and retrieve a step-up verification code "
                "for this request, then share it with your approver. "
                f"Ticket #{ticket_id[:8]} created — I'll let you know here "
                "once it's actioned."
            )

    session.add(
        ConversationMessage(
            tenant_id=tenant_id,
            conversation_id=conversation.id,
            role="assistant",
            content=reply,
            intent=classified.intent,
        )
    )
    return ConversationTurnResult(
        conversation_id=conversation.id,
        reply=reply,
        ticket_id=ticket_id,
        connector_request_id=connector_request_id,
    )


__all__ = [
    "ClassifiedIntent",
    "ConversationTurnResult",
    "classify_intent",
    "handle_message",
]
