"""Tests for helpdesktool.confidence -- deterministic, evidence-based
confidence scoring (Phase 5). The LLM must never be trusted to invent
these numbers; see tests/test_ai_provider.py for the provider-side half
of that guarantee.
"""

from __future__ import annotations

import pytest

from helpdesktool.confidence import (
    ConfidenceInput,
    ConfidenceThresholds,
    compute_confidence,
)


def test_all_required_signals_present_with_no_adjustments_yields_full_confidence():
    result = compute_confidence(
        ConfidenceInput(required_signals_present=3, required_signals_total=3)
    )
    assert result.score == pytest.approx(1.0)
    assert result.band == "VERY_HIGH"


def test_missing_required_signals_lowers_the_base_score():
    result = compute_confidence(
        ConfidenceInput(required_signals_present=1, required_signals_total=4)
    )
    assert result.score == pytest.approx(0.25)
    assert result.band == "LOW"


def test_supporting_signals_increase_confidence_with_diminishing_returns():
    # A deliberately low base (1/4 required signals present) so the bonus
    # from supporting signals has room to show its shape rather than
    # immediately saturating at the [0, 1] ceiling.
    def _with(supporting: int):
        return compute_confidence(
            ConfidenceInput(
                required_signals_present=1,
                required_signals_total=4,
                supporting_signals=supporting,
            )
        )

    zero, one, two, ten = _with(0), _with(1), _with(2), _with(10)
    assert one.score > zero.score
    assert two.score >= one.score
    assert ten.score >= two.score
    # Diminishing returns: the jump from 0->1 signals is bigger than 2->10.
    assert (ten.score - two.score) < (one.score - zero.score)


def test_a_single_contradicting_signal_caps_confidence_regardless_of_support():
    result = compute_confidence(
        ConfidenceInput(
            required_signals_present=5,
            required_signals_total=5,
            supporting_signals=20,
            contradicting_signals=1,
        )
    )
    assert result.score <= 0.69
    assert result.band != "VERY_HIGH"
    assert result.band != "HIGH"


def test_low_source_or_telemetry_reliability_scales_the_score_down():
    reliable = compute_confidence(
        ConfidenceInput(required_signals_present=1, required_signals_total=1)
    )
    unreliable = compute_confidence(
        ConfidenceInput(
            required_signals_present=1,
            required_signals_total=1,
            telemetry_reliability=0.5,
        )
    )
    assert unreliable.score < reliable.score
    assert unreliable.score == pytest.approx(reliable.score * 0.5)


def test_no_declared_requirements_uses_a_neutral_baseline_not_zero_or_one():
    result = compute_confidence(ConfidenceInput())
    assert 0.0 < result.score < 1.0


def test_default_bands_match_the_specified_ranges():
    thresholds = ConfidenceThresholds()
    assert thresholds.medium == 0.40
    assert thresholds.high == 0.70
    assert thresholds.very_high == 0.90


def test_thresholds_are_configurable_and_change_the_resulting_band():
    strict = ConfidenceThresholds(medium=0.60, high=0.85, very_high=0.95)
    evidence = ConfidenceInput(required_signals_present=7, required_signals_total=10)
    lenient_band = compute_confidence(evidence).band
    strict_band = compute_confidence(evidence, thresholds=strict).band
    assert lenient_band == "HIGH"
    assert strict_band == "MEDIUM"


def test_thresholds_reject_non_increasing_values():
    with pytest.raises(ValueError, match="strictly increasing"):
        ConfidenceThresholds(medium=0.5, high=0.5, very_high=0.9)


def test_evidence_summary_is_human_readable_and_includes_notes():
    result = compute_confidence(
        ConfidenceInput(
            required_signals_present=1,
            required_signals_total=1,
            evidence_notes=("device offline for 2 hours",),
        )
    )
    assert "1/1 required" in result.evidence_summary
    assert "device offline for 2 hours" in result.evidence_summary


def test_negative_counts_are_rejected():
    with pytest.raises(ValueError, match="must not be negative"):
        ConfidenceInput(supporting_signals=-1)


def test_present_cannot_exceed_total():
    with pytest.raises(ValueError, match="cannot exceed"):
        ConfidenceInput(required_signals_present=5, required_signals_total=2)


def test_reliability_out_of_range_is_rejected():
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        ConfidenceInput(source_reliability=1.5)
