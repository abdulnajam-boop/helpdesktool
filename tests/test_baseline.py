"""Unit tests for helpdesktool.baseline (Phase 6: known-good organizational
state). Central invariant under test: a device_baseline/organizational_policy
entry always outranks a generic_best_practice one, and current_state is
never itself a valid resolution -- concretely, the roadmap's own DNS
example: a device failing DNS resolution must never be "fixed" by
substituting a public resolver just because that's a generic best practice.
"""

from __future__ import annotations

import pytest

from helpdesktool.baseline import (
    BaselineEntry,
    BaselineValidationError,
    resolve_known_good,
)
from helpdesktool.models import BaselineScope


def test_device_baseline_entry_requires_device_id():
    with pytest.raises(BaselineValidationError, match="device_id"):
        BaselineEntry(BaselineScope.DEVICE_BASELINE, "dns_servers", ["10.0.0.1"])


def test_user_baseline_entry_requires_user_id():
    with pytest.raises(BaselineValidationError, match="user_id"):
        BaselineEntry(BaselineScope.USER_BASELINE, "timezone", "UTC")


def test_organizational_policy_entry_must_not_carry_a_device_id():
    with pytest.raises(BaselineValidationError, match="must not carry"):
        BaselineEntry(
            BaselineScope.ORGANIZATIONAL_POLICY,
            "dns_servers",
            ["10.0.0.1"],
            device_id="device-1",
        )


def test_key_must_not_be_empty():
    with pytest.raises(BaselineValidationError, match="key"):
        BaselineEntry(BaselineScope.GENERIC_BEST_PRACTICE, "", "x")


def test_resolve_returns_none_when_nothing_is_declared():
    assert resolve_known_good([], "dns_servers") is None


def test_dns_example_organizational_policy_outranks_generic_best_practice():
    """The roadmap's own worked example: never treat a public-resolver
    'generic best practice' as authoritative over the organization's own
    configured DNS."""
    entries = [
        BaselineEntry(
            BaselineScope.GENERIC_BEST_PRACTICE,
            "dns_servers",
            ["8.8.8.8", "1.1.1.1"],
        ),
        BaselineEntry(
            BaselineScope.ORGANIZATIONAL_POLICY, "dns_servers", ["10.0.0.1", "10.0.0.2"]
        ),
    ]
    resolved = resolve_known_good(entries, "dns_servers")
    assert resolved is not None
    assert resolved.scope is BaselineScope.ORGANIZATIONAL_POLICY
    assert resolved.value == ["10.0.0.1", "10.0.0.2"]


def test_device_baseline_outranks_organizational_policy_for_that_device():
    entries = [
        BaselineEntry(BaselineScope.ORGANIZATIONAL_POLICY, "dns_servers", ["10.0.0.1"]),
        BaselineEntry(
            BaselineScope.DEVICE_BASELINE,
            "dns_servers",
            ["10.0.5.9"],
            device_id="device-42",
        ),
    ]
    resolved = resolve_known_good(entries, "dns_servers", device_id="device-42")
    assert resolved is not None
    assert resolved.scope is BaselineScope.DEVICE_BASELINE
    assert resolved.value == ["10.0.5.9"]


def test_device_baseline_for_a_different_device_does_not_match():
    entries = [
        BaselineEntry(
            BaselineScope.DEVICE_BASELINE,
            "dns_servers",
            ["10.0.5.9"],
            device_id="device-42",
        ),
        BaselineEntry(BaselineScope.ORGANIZATIONAL_POLICY, "dns_servers", ["10.0.0.1"]),
    ]
    resolved = resolve_known_good(entries, "dns_servers", device_id="some-other-device")
    assert resolved is not None
    assert resolved.scope is BaselineScope.ORGANIZATIONAL_POLICY


def test_current_state_is_never_returned_as_the_resolution():
    entries = [
        BaselineEntry(BaselineScope.CURRENT_STATE, "dns_servers", ["8.8.8.8"]),
    ]
    assert resolve_known_good(entries, "dns_servers") is None


def test_user_baseline_outranks_organizational_policy_for_that_user():
    entries = [
        BaselineEntry(BaselineScope.ORGANIZATIONAL_POLICY, "timezone", "UTC"),
        BaselineEntry(
            BaselineScope.USER_BASELINE, "timezone", "America/New_York", user_id="u1"
        ),
    ]
    resolved = resolve_known_good(entries, "timezone", user_id="u1")
    assert resolved is not None
    assert resolved.scope is BaselineScope.USER_BASELINE


def test_unrelated_keys_are_never_candidates():
    entries = [
        BaselineEntry(BaselineScope.ORGANIZATIONAL_POLICY, "dns_servers", ["10.0.0.1"]),
    ]
    assert resolve_known_good(entries, "ntp_servers") is None


def test_only_generic_best_practice_declared_is_still_returned():
    """Absence of an org-specific override doesn't mean no answer -- it
    means the best available answer is explicitly the generic one, which
    a caller can treat with appropriately lower confidence via its scope."""
    entries = [
        BaselineEntry(BaselineScope.GENERIC_BEST_PRACTICE, "dns_servers", ["8.8.8.8"]),
    ]
    resolved = resolve_known_good(entries, "dns_servers")
    assert resolved is not None
    assert resolved.scope is BaselineScope.GENERIC_BEST_PRACTICE
