"""Phase 6: known-good organizational state.

Nothing before this module could distinguish "a generic public best
practice" from "what this specific organization actually configured/
wants." That distinction matters concretely: the roadmap's own worked
example is that a device failing DNS resolution must never be "fixed" by
pointing it at a public resolver (8.8.8.8/1.1.1.1) just because resolution
is failing -- the organization's own configured DNS servers (an
``ORGANIZATIONAL_POLICY`` or ``DEVICE_BASELINE`` entry) are the only
authoritative source of "what this key should be," and a
``GENERIC_BEST_PRACTICE`` entry (if one even exists) is never sufficient
justification for a configuration change on its own.

This module is deliberately just the resolution primitive -- a pure
function over already-loaded ``BaselineEntry`` rows -- not itself wired
into any diagnosis/remediation code path yet. Persistence lives in
``helpdesktool/db_models.py``'s ``OrganizationalBaselineRow`` (tenant-
scoped, RLS-protected like every other tenant-owned table) and the
``/v1/baselines`` API surface in ``helpdesktool/api.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import BaselineScope


class BaselineValidationError(ValueError):
    """A baseline entry failed validation and must not be trusted."""


# Precedence order for what counts as "known good" for a given key, most
# specific/authoritative first. CURRENT_STATE is deliberately excluded --
# it describes what is presently configured, not what *should* be
# configured, so it is never itself a valid resolution candidate.
_PRECEDENCE: dict[BaselineScope, int] = {
    BaselineScope.DEVICE_BASELINE: 0,
    BaselineScope.USER_BASELINE: 1,
    BaselineScope.ORGANIZATIONAL_POLICY: 2,
    BaselineScope.GENERIC_BEST_PRACTICE: 3,
}


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    scope: BaselineScope
    key: str
    value: Any
    device_id: str | None = None
    user_id: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        # Coerce a plain str (e.g. straight from a DB row or a Pydantic
        # Literal field) into the real BaselineScope member. Every check
        # below -- here and in resolve_known_good -- uses `is`/`is not`
        # identity comparison against BaselineScope members; a raw str
        # equal-by-value but not by identity would silently make every one
        # of those checks a no-op instead of raising, which is exactly the
        # kind of quiet safety-check bypass this module exists to prevent.
        if not isinstance(self.scope, BaselineScope):
            object.__setattr__(self, "scope", BaselineScope(self.scope))
        if not self.key.strip():
            raise BaselineValidationError("key must not be empty")
        if self.scope is BaselineScope.DEVICE_BASELINE and not self.device_id:
            raise BaselineValidationError(
                "a device_baseline entry must carry a device_id"
            )
        if self.scope is BaselineScope.USER_BASELINE and not self.user_id:
            raise BaselineValidationError("a user_baseline entry must carry a user_id")
        if self.scope in (
            BaselineScope.GENERIC_BEST_PRACTICE,
            BaselineScope.ORGANIZATIONAL_POLICY,
            BaselineScope.CURRENT_STATE,
        ) and (self.device_id or self.user_id):
            raise BaselineValidationError(
                f"a {self.scope.value} entry must not carry a device_id/user_id "
                "-- it is not scoped to one device or user"
            )


def resolve_known_good(
    entries: list[BaselineEntry],
    key: str,
    *,
    device_id: str | None = None,
    user_id: str | None = None,
) -> BaselineEntry | None:
    """Returns the single most authoritative ``BaselineEntry`` for ``key``,
    or ``None`` if nothing at all is declared for it -- callers must treat
    ``None`` as "no organizational opinion exists," never silently fall
    back to inventing a value themselves (e.g. a public DNS resolver).

    Only entries matching ``key`` are considered. A ``device_baseline``
    entry only matches when its ``device_id`` equals the given
    ``device_id``; a ``user_baseline`` entry only matches when its
    ``user_id`` equals the given ``user_id``. ``current_state`` entries are
    never returned -- they describe what *is* configured, not what
    *should* be, so they can never themselves be the resolution.
    """
    candidates = [
        entry
        for entry in entries
        if entry.key == key
        and entry.scope is not BaselineScope.CURRENT_STATE
        and (
            entry.scope is not BaselineScope.DEVICE_BASELINE
            or entry.device_id == device_id
        )
        and (entry.scope is not BaselineScope.USER_BASELINE or entry.user_id == user_id)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda entry: _PRECEDENCE[entry.scope])


__all__ = [
    "BaselineEntry",
    "BaselineValidationError",
    "resolve_known_good",
]
