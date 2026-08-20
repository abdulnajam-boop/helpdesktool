"""Tests for helpdesktool.security_classification (Phase 4). The central
invariant: a single evidence category, however many signals it contains,
must never alone justify SUSPICIOUS or worse -- correlation across
distinct categories is required. CONFIRMED_COMPROMISE is reachable only
via an explicit authoritative-source flag, never from signal accumulation.
"""

from __future__ import annotations

import pytest

from helpdesktool.models import SecurityClassification
from helpdesktool.security_classification import (
    SecuritySignal,
    classify_security_state,
)


def test_no_signals_is_normal():
    result = classify_security_state()
    assert result.classification is SecurityClassification.NORMAL


def test_no_signals_but_explicit_policy_violation_is_policy_violation():
    result = classify_security_state(policy_violation=True)
    assert result.classification is SecurityClassification.POLICY_VIOLATION


def test_high_cpu_alone_never_becomes_suspicious():
    """The mandate's own example: high CPU alone is not malware evidence."""
    signals = (SecuritySignal("resource_usage", "high_cpu"),)
    result = classify_security_state(signals)
    assert result.classification not in {
        SecurityClassification.SUSPICIOUS,
        SecurityClassification.LIKELY_COMPROMISED,
        SecurityClassification.CONFIRMED_COMPROMISE,
    }


def test_many_signals_in_one_category_alone_never_becomes_suspicious():
    """Ten process-category signals are still just one category."""
    signals = tuple(SecuritySignal("process", f"observation_{i}") for i in range(10))
    result = classify_security_state(signals)
    assert result.classification not in {
        SecurityClassification.SUSPICIOUS,
        SecurityClassification.LIKELY_COMPROMISED,
        SecurityClassification.CONFIRMED_COMPROMISE,
    }


def test_powershell_alone_never_becomes_suspicious():
    signals = (SecuritySignal("process", "powershell_execution"),)
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.MISCONFIGURATION


def test_unsigned_software_alone_never_becomes_suspicious():
    signals = (SecuritySignal("process", "unsigned_binary"),)
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.MISCONFIGURATION


def test_one_failed_login_alone_never_becomes_suspicious():
    signals = (SecuritySignal("authentication", "failed_login"),)
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.MISCONFIGURATION


def test_two_correlated_categories_reaches_suspicious():
    signals = (
        SecuritySignal("process", "unusual_process_name"),
        SecuritySignal("network", "unexpected_outbound_connection"),
    )
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.SUSPICIOUS
    assert result.distinct_categories == 2


def test_three_correlated_high_weight_categories_reaches_likely_compromised():
    signals = (
        SecuritySignal("process", "unusual_process_name", weight=0.8),
        SecuritySignal("network", "c2_like_traffic", weight=0.8),
        SecuritySignal("file_integrity", "unexpected_binary_modification", weight=0.8),
    )
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.LIKELY_COMPROMISED


def test_ambiguous_evidence_never_auto_reaches_confirmed_compromise():
    """No amount of accumulated ambiguous signal evidence, by itself, may
    reach CONFIRMED_COMPROMISE -- that requires the explicit authoritative
    flag, tested separately below.
    """
    signals = tuple(
        SecuritySignal(category, f"signal_{i}", weight=1.0)
        for i, category in enumerate(
            ["process", "network", "file_integrity", "authentication", "edr_alert"] * 4
        )
    )
    result = classify_security_state(signals)
    assert result.classification is not SecurityClassification.CONFIRMED_COMPROMISE
    assert result.classification is SecurityClassification.LIKELY_COMPROMISED


def test_confirmed_compromise_requires_the_explicit_authoritative_flag():
    result = classify_security_state(signals=(), confirmed_by_authoritative_source=True)
    assert result.classification is SecurityClassification.CONFIRMED_COMPROMISE


def test_mitre_technique_alone_is_metadata_not_evidence_of_compromise():
    """A single 'T1059 PowerShell' style signal must not alone escalate --
    MITRE mappings are metadata, not proof (Phase 11)."""
    signals = (SecuritySignal("process", "mitre_t1059_powershell_execution"),)
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.MISCONFIGURATION


def test_cryptominer_style_signals_need_correlation_too():
    """High CPU + a mining-related port alone is explicitly called out as
    insufficient (Phase 15 concern #7) -- both are 'resource_usage'/
    'network' but if only weakly correlated they land at SUSPICIOUS, not
    an automatic compromise verdict."""
    signals = (
        SecuritySignal("resource_usage", "sustained_high_cpu"),
        SecuritySignal("network", "mining_pool_port"),
    )
    result = classify_security_state(signals)
    assert result.classification is SecurityClassification.SUSPICIOUS
    assert result.classification is not SecurityClassification.CONFIRMED_COMPROMISE


def test_signal_requires_non_empty_category_and_name():
    with pytest.raises(ValueError, match="must not be empty"):
        SecuritySignal("", "x")


def test_signal_weight_out_of_range_is_rejected():
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        SecuritySignal("process", "x", weight=1.5)
