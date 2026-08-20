"""Deterministic, evidence-based confidence scoring (Phase 5).

**The AI provider must never be the source of a confidence number.** Before
this module, ``helpdesktool/ai/provider.py``'s ``OpenAICompatibleProvider``
prompt literally asked the model to invent a ``confidence`` field directly
— exactly the failure mode this module exists to close. An LLM has no
principled way to know how reliable a diagnosis actually is; it can only
produce a plausible-sounding number. This module computes confidence from
structured, countable evidence signals instead — the same deterministic
spirit as ``helpdesktool/incidents.py``'s rule-based detection and
``helpdesktool/policy.py``'s rule-based automation-level classification.
The AI may still *explain* a confidence band in prose (why this evidence
supports or undermines the diagnosis); it may never manufacture the
underlying score. See ``helpdesktool/ai/provider.py`` and ``api.py``'s
``diagnose_incident`` for exactly where this replaces the provider's own
self-reported number before anything is persisted or shown to an operator.

Bands are configurable per tenant/policy (``ConfidenceThresholds``) but
default to the bands the mandate specifies:

    0.00-0.39  LOW
    0.40-0.69  MEDIUM
    0.70-0.89  HIGH
    0.90-1.00  VERY_HIGH
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ConfidenceThresholds:
    """Tenant/policy-configurable band boundaries. Each value is the
    *minimum* score that band starts at; bands must be strictly increasing.
    """

    medium: float = 0.40
    high: float = 0.70
    very_high: float = 0.90

    def __post_init__(self) -> None:
        if not (0.0 < self.medium < self.high < self.very_high <= 1.0):
            raise ValueError("thresholds must be strictly increasing and within (0, 1]")


DEFAULT_THRESHOLDS = ConfidenceThresholds()


@dataclass(frozen=True, slots=True)
class ConfidenceInput:
    """Structured evidence signals -- every field is a plain count or a
    0-1 reliability estimate, never free text an LLM produced. Callers
    (e.g. ``api.py``'s ``diagnose_incident``) derive these from real,
    inspectable data: how many of an issue definition's required signals
    were actually observed, how many corroborating vs. contradicting
    signals exist, how fresh/trustworthy the telemetry is, and so on.
    """

    required_signals_present: int = 0
    required_signals_total: int = 0
    supporting_signals: int = 0
    contradicting_signals: int = 0
    missing_signals: int = 0
    source_reliability: float = 1.0
    telemetry_reliability: float = 1.0
    historical_baseline_matches: int = 0
    evidence_notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("source_reliability", "telemetry_reliability"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        for name in (
            "required_signals_present",
            "required_signals_total",
            "supporting_signals",
            "contradicting_signals",
            "missing_signals",
            "historical_baseline_matches",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must not be negative")
        if self.required_signals_present > self.required_signals_total:
            raise ValueError(
                "required_signals_present cannot exceed required_signals_total"
            )


@dataclass(frozen=True, slots=True)
class ConfidenceResult:
    score: float
    band: str
    evidence_summary: str


def _band_for(score: float, thresholds: ConfidenceThresholds) -> str:
    if score >= thresholds.very_high:
        return "VERY_HIGH"
    if score >= thresholds.high:
        return "HIGH"
    if score >= thresholds.medium:
        return "MEDIUM"
    return "LOW"


def compute_confidence(
    evidence: ConfidenceInput, thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS
) -> ConfidenceResult:
    """Deterministic scoring: start from the fraction of required signals
    actually present (the load-bearing term — an issue definition's
    required evidence not being present should dominate the score), then
    nudge up for each supporting signal and down for each contradicting
    one with diminishing returns (``x / (x + 2)``, so signal count 1 -> a
    third of the max nudge, further signals add progressively less rather
    than letting a long list of weak signals alone reach VERY_HIGH), then
    scale the whole result by source and telemetry reliability. A single
    contradicting signal can never be fully offset by many supporting
    ones — it caps the achievable score — because corroborating evidence
    for the wrong conclusion is not the same claim as absence of
    contradiction.
    """
    if evidence.required_signals_total > 0:
        base = evidence.required_signals_present / evidence.required_signals_total
    else:
        base = 0.5  # no declared requirements: a neutral, unopinionated start

    def _diminishing(count: int) -> float:
        return count / (count + 2) if count > 0 else 0.0

    support_bonus = 0.35 * _diminishing(evidence.supporting_signals)
    contradiction_penalty = 0.5 * _diminishing(evidence.contradicting_signals)
    missing_penalty = 0.1 * _diminishing(evidence.missing_signals)
    baseline_bonus = 0.1 * _diminishing(evidence.historical_baseline_matches)

    raw = (
        base + support_bonus + baseline_bonus - contradiction_penalty - missing_penalty
    )
    raw = max(0.0, min(1.0, raw))
    reliability = evidence.source_reliability * evidence.telemetry_reliability
    score = round(raw * reliability, 4)

    if evidence.contradicting_signals > 0:
        # A contradicting signal caps achievable confidence regardless of
        # how much supporting evidence exists -- see the function docstring.
        score = min(score, 0.69)

    band = _band_for(score, thresholds)
    summary = (
        f"{evidence.required_signals_present}/{evidence.required_signals_total} required "
        f"signal(s) present, {evidence.supporting_signals} supporting, "
        f"{evidence.contradicting_signals} contradicting, "
        f"{evidence.missing_signals} missing; source reliability "
        f"{evidence.source_reliability:.2f}, telemetry reliability "
        f"{evidence.telemetry_reliability:.2f}"
    )
    if evidence.evidence_notes:
        summary += "; " + "; ".join(evidence.evidence_notes)
    return ConfidenceResult(score=score, band=band, evidence_summary=summary)


__all__ = [
    "DEFAULT_THRESHOLDS",
    "ConfidenceInput",
    "ConfidenceResult",
    "ConfidenceThresholds",
    "compute_confidence",
]
