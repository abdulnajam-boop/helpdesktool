"""Dev-safe, in-memory application connector -- the always-available
default when no real application credentials are configured, and what
this repository's own tests exercise the full password-reset pipeline
against. Mirrors ``helpdesktool.ai.provider.DeterministicFallbackProvider``'s
role for AI diagnosis: a real, working implementation of the contract with
no network access and no external account required, so the whole pipeline
(chat -> identity -> policy -> connector -> verify -> ticket -> audit) is
provable end to end without any credential this environment doesn't have.

State is per-instance, not persisted -- a new ``MockApplicationConnector()``
starts with a small fixed roster of demo accounts (see ``_DEMO_ACCOUNTS``)
plus anything a test seeds directly via ``seed_account``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import ConnectorResult


@dataclass
class _MockAccount:
    external_user_id: str
    email: str
    active: bool = True
    locked: bool = False
    mfa_enrolled: bool = True
    permissions: list[str] = field(default_factory=lambda: ["standard_user"])
    last_reset_token: str | None = None


_DEMO_ACCOUNTS: tuple[_MockAccount, ...] = (
    _MockAccount("mock-ext-001", "owner@example.com"),
    _MockAccount("mock-ext-002", "admin@example.com"),
)


class MockApplicationConnector:
    connector_type = "mock"

    def __init__(self) -> None:
        self._accounts: dict[str, _MockAccount] = {
            account.email: account for account in _DEMO_ACCOUNTS
        }

    def seed_account(self, email: str, **overrides: object) -> None:
        """Test/demo hook: add or replace an account by email."""
        external_user_id = str(
            overrides.pop("external_user_id", f"mock-ext-{len(self._accounts) + 1:03d}")
        )
        account = _MockAccount(external_user_id=external_user_id, email=email)
        for key, value in overrides.items():
            setattr(account, key, value)
        self._accounts[email] = account

    def resolve_user(self, email: str) -> ConnectorResult:
        account = self._accounts.get(email)
        if account is None:
            return ConnectorResult(False, "no account found for this email")
        return ConnectorResult(
            True, "account resolved", {"external_user_id": account.external_user_id}
        )

    def _by_id(self, external_user_id: str) -> _MockAccount | None:
        for account in self._accounts.values():
            if account.external_user_id == external_user_id:
                return account
        return None

    def check_account(self, external_user_id: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        return ConnectorResult(
            True,
            "account status retrieved",
            {"active": account.active, "locked": account.locked},
        )

    def reset_password(self, external_user_id: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        if not account.active:
            return ConnectorResult(False, "account is not active")
        # A real connector would trigger the application's own reset-link
        # email; this token exists only so verify_result has something
        # deterministic to check, and is never returned to the caller.
        account.last_reset_token = secrets.token_hex(8)
        return ConnectorResult(True, "password reset initiated")

    def unlock_account(self, external_user_id: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        account.locked = False
        return ConnectorResult(True, "account unlocked")

    def reset_mfa(self, external_user_id: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        account.mfa_enrolled = False
        return ConnectorResult(True, "MFA factors cleared; re-enrollment required")

    def check_permissions(self, external_user_id: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        return ConnectorResult(
            True, "permissions retrieved", {"permissions": list(account.permissions)}
        )

    def verify_result(self, external_user_id: str, action: str) -> ConnectorResult:
        account = self._by_id(external_user_id)
        if account is None:
            return ConnectorResult(False, "account not found")
        if action == "reset_password":
            ok = account.last_reset_token is not None
            return ConnectorResult(
                ok, "reset token present" if ok else "no reset recorded"
            )
        if action == "unlock_account":
            return ConnectorResult(not account.locked, "lock state verified")
        if action == "reset_mfa":
            return ConnectorResult(not account.mfa_enrolled, "mfa state verified")
        return ConnectorResult(False, f"unknown action to verify: {action}")
