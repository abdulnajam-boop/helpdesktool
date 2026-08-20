"""Application Integration Framework: the typed contract every third-party
application connector implements, plus the registry that resolves a
tenant's configured connector for a given application.

Trust model (mirrors ``skills.py``/``policy.py``'s executor contract
exactly, applied to identity/SaaS applications instead of endpoint
devices): a connector is a deterministic, typed executor for one
application's account-management operations. It never receives a raw
natural-language instruction and never runs arbitrary code on the caller's
behalf -- ``conversation.py`` (the orchestration layer) proposes a
structured, named operation (``reset_password``, ``unlock_account``, ...)
against a specific resolved account; ``policy`` decides whether that
operation is allowed and whether it needs independent approval;
*only then* does a connector method run, against a resolved external
account id, never a caller-supplied search string. The connector itself
has no opinion about policy or approval -- it is the last, narrowest link
in the chain, exactly like ``linux_agent/executor.py`` is for endpoint
skills.

``ConnectorResult`` is intentionally minimal and never carries a raw
secret: a connector may return an opaque ``data`` payload for genuinely
non-sensitive facts (an account's lock state, a permission list), but must
never put a password, token, or MFA seed in it -- see each protocol
method's docstring for what is and isn't appropriate to return.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    success: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class ApplicationConnector(Protocol):
    """One application's account-management operations.

    Every method is synchronous and deterministic from the connector's own
    perspective (a real implementation talks to one external API per call,
    with its own timeout/retry handling) -- there is no method here that
    accepts free text or a caller-chosen action name; the operation is
    always which *method* gets called, decided by the policy-gated
    conversation layer, never by the connector itself.
    """

    connector_type: str

    def resolve_user(self, email: str) -> ConnectorResult:
        """Looks up the application account for a given, already-verified
        email address. Must never search by name or employee id -- only an
        exact, previously-authenticated email is an acceptable lookup key,
        so a chat message merely mentioning someone's name can never
        resolve to their account. ``data`` should include an opaque
        ``external_user_id`` on success.
        """
        ...

    def check_account(self, external_user_id: str) -> ConnectorResult:
        """Read-only account status (exists / active / locked). Never
        requires approval to call."""
        ...

    def reset_password(self, external_user_id: str) -> ConnectorResult:
        """Triggers the application's own password-reset flow (e.g. an
        emailed reset link, or a temporary password delivered through the
        application's own secure channel) -- never returns a new password
        directly, since that would make this response itself a secret in
        transit through chat/audit logs."""
        ...

    def unlock_account(self, external_user_id: str) -> ConnectorResult: ...

    def reset_mfa(self, external_user_id: str) -> ConnectorResult:
        """Clears enrolled MFA factors so the user can re-enroll. High risk
        by construction -- see ``conversation.py``'s risk classification."""
        ...

    def check_permissions(self, external_user_id: str) -> ConnectorResult:
        """Read-only role/permission summary. Never requires approval."""
        ...

    def verify_result(self, external_user_id: str, action: str) -> ConnectorResult:
        """Re-checks account state after a mutating action to confirm it
        actually took effect, independent of the mutating call's own
        reported success -- mirrors ``linux_agent/executor.py``'s
        verify-after-execute pattern for endpoint skills.
        """
        ...


# Risk classification per operation, consumed by conversation.py's policy
# check -- deliberately separate from any single connector implementation,
# so every connector (mock or real) is governed by the same policy
# regardless of which application it talks to.
READ_ONLY_OPERATIONS: frozenset[str] = frozenset(
    {"resolve_user", "check_account", "check_permissions", "verify_result"}
)
HIGH_RISK_OPERATIONS: frozenset[str] = frozenset(
    {"reset_password", "unlock_account", "reset_mfa"}
)


class ConnectorRegistry:
    """Maps a connector_type string (e.g. ``"mock"``) to a constructed
    ``ApplicationConnector`` instance. Deliberately not a global singleton
    registry keyed by tenant -- callers construct one per request from the
    tenant's stored ``ApplicationConnectorConfig`` rows, so nothing about
    connector configuration is ever shared across tenants in memory.
    """

    def __init__(self) -> None:
        self._factories: dict[str, type[ApplicationConnector]] = {}

    def register(
        self, connector_type: str, factory: type[ApplicationConnector]
    ) -> None:
        self._factories[connector_type] = factory

    def create(self, connector_type: str, **kwargs: Any) -> ApplicationConnector:
        factory = self._factories.get(connector_type)
        if factory is None:
            raise ValueError(f"unregistered connector type: {connector_type!r}")
        return factory(**kwargs)

    def known_types(self) -> frozenset[str]:
        return frozenset(self._factories)


__all__ = [
    "ApplicationConnector",
    "ConnectorRegistry",
    "ConnectorResult",
    "HIGH_RISK_OPERATIONS",
    "READ_ONLY_OPERATIONS",
]
