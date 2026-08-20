"""Deterministic security classification from correlated evidence
(Phase 4).

**Never classify something malicious solely because of:** high CPU, high
RAM, a port number, PowerShell, Python, shell execution, unsigned
software, unknown software, a failed login, an unusual process name, one
Windows Event ID, or one Sysmon event. Each of those is, alone, an
ordinary and frequently benign occurrence — see
``docs/KNOWLEDGE_BASE_AUDIT.md`` for the specific research corrections
this module's design responds to (Windows Event ID 4688 is process
creation, not LSASS access; MITRE T1059 is Command and Scripting
Interpreter, not "any command line"; cryptominer detection does not
automatically imply T1059; etc.).

The rule enforced here is structural, not a tunable threshold an operator
could accidentally weaken into unsafety: classification above
``MISCONFIGURATION``/``POLICY_VIOLATION`` requires signals spanning **at
least two distinct evidence categories** (e.g. an anomalous process *and*
an anomalous network connection *and/or* an anomalous auth event — not
three signals that are all just "process" observations). A single
category, no matter how many signals it contains, can never on its own
justify ``SUSPICIOUS`` or worse.

``CONFIRMED_COMPROMISE`` is reachable **only** via an explicit
``confirmed_by_authoritative_source`` flag this module never sets itself —
it is not a signal-count outcome at all. That flag represents a human
analyst's or an authoritative external system's (a real EDR platform's own
"confirmed malicious" verdict, not this codebase re-deriving one) explicit
determination, passed in by the caller. Ambiguous evidence, no matter how
much of it accumulates, tops out at ``LIKELY_COMPROMISED``.

Security classification is a completely different axis from automation
level (``helpdesktool/policy.py``'s ``AutomationLevel``) — a suspicious
finding does not automatically imply L5; what response is *appropriate*
for a given classification is a policy decision made elsewhere, not
computed by this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import SecurityClassification


@dataclass(frozen=True, slots=True)
class SecuritySignal:
    """One observed, named piece of evidence. ``category`` groups signals
    for the correlation rule above — use a small, stable vocabulary (e.g.
    ``"process"``, ``"network"``, ``"authentication"``, ``"file_integrity"``,
    ``"edr_alert"``, ``"resource_usage"``), not a free-text description,
    so correlation counting is meaningful rather than accidentally counting
    near-duplicate categories as independent.
    """

    category: str
    name: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not self.category.strip() or not self.name.strip():
            raise ValueError("category and name must not be empty")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0, 1]")


@dataclass(frozen=True, slots=True)
class SecurityClassificationResult:
    classification: SecurityClassification
    distinct_categories: int
    total_weight: float
    rationale: str


def classify_security_state(
    signals: tuple[SecuritySignal, ...] = (),
    *,
    policy_violation: bool = False,
    confirmed_by_authoritative_source: bool = False,
) -> SecurityClassificationResult:
    categories = {signal.category for signal in signals}
    total_weight = sum(signal.weight for signal in signals)

    if confirmed_by_authoritative_source:
        return SecurityClassificationResult(
            SecurityClassification.CONFIRMED_COMPROMISE,
            len(categories),
            total_weight,
            "confirmed by an authoritative source (explicit human/EDR "
            "determination, not derived from signal accumulation)",
        )

    if not signals:
        if policy_violation:
            return SecurityClassificationResult(
                SecurityClassification.POLICY_VIOLATION,
                0,
                0.0,
                "no anomalous signals; explicit policy violation only",
            )
        return SecurityClassificationResult(
            SecurityClassification.NORMAL, 0, 0.0, "no signals observed"
        )

    if len(categories) < 2:
        # A single evidence category, however many signals it contains,
        # can never alone justify suspicion -- see module docstring.
        classification = (
            SecurityClassification.POLICY_VIOLATION
            if policy_violation
            else SecurityClassification.MISCONFIGURATION
        )
        return SecurityClassificationResult(
            classification,
            len(categories),
            total_weight,
            f"signals confined to a single category ({next(iter(categories))!r}) "
            "-- correlation across categories is required to elevate beyond this",
        )

    if len(categories) >= 3 and total_weight >= 2.0:
        return SecurityClassificationResult(
            SecurityClassification.LIKELY_COMPROMISED,
            len(categories),
            total_weight,
            f"{len(categories)} distinct correlated evidence categories, "
            f"total weight {total_weight:.2f}",
        )

    return SecurityClassificationResult(
        SecurityClassification.SUSPICIOUS,
        len(categories),
        total_weight,
        f"{len(categories)} distinct correlated evidence categories, "
        f"total weight {total_weight:.2f} -- below the threshold for "
        "LIKELY_COMPROMISED",
    )


__all__ = [
    "SecurityClassificationResult",
    "SecuritySignal",
    "classify_security_state",
]
