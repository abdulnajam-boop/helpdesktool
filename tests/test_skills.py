"""Unit tests for helpdesktool.skills: manifest hashing/integrity and the
shape-only parameter schema validator.
"""

from __future__ import annotations

from helpdesktool.models import RiskLevel
from helpdesktool.skills import (
    ParameterSpec,
    SkillManifest,
    compute_manifest_hash,
    validate_parameters,
)


def _manifest(**overrides) -> SkillManifest:
    defaults = dict(
        skill_id="service.restart",
        version=1,
        risk=RiskLevel.MEDIUM,
        supported_os=frozenset({"linux", "windows"}),
        timeout_seconds=30,
        rollback_skill_id="service.restore",
        parameters={"service": ParameterSpec("string", required=True)},
    )
    defaults.update(overrides)
    return SkillManifest(**defaults)


def test_content_hash_is_deterministic_regardless_of_field_ordering():
    a = compute_manifest_hash(
        skill_id="service.restart",
        version=1,
        risk=RiskLevel.MEDIUM,
        supported_os=frozenset({"windows", "linux"}),
        timeout_seconds=30,
        rollback_skill_id="service.restore",
        parameters={"service": ParameterSpec("string", True)},
    )
    b = compute_manifest_hash(
        skill_id="service.restart",
        version=1,
        risk=RiskLevel.MEDIUM,
        supported_os=frozenset({"linux", "windows"}),
        timeout_seconds=30,
        rollback_skill_id="service.restore",
        parameters={"service": ParameterSpec("string", True)},
    )
    assert a == b


def test_content_hash_changes_when_any_policy_field_changes():
    base = _manifest()
    changed_risk = _manifest(risk=RiskLevel.HIGH)
    changed_timeout = _manifest(timeout_seconds=60)
    changed_params = _manifest(
        parameters={"service": ParameterSpec("string", required=False)}
    )
    hashes = {
        base.content_hash(),
        changed_risk.content_hash(),
        changed_timeout.content_hash(),
        changed_params.content_hash(),
    }
    assert len(hashes) == 4


def test_hash_from_stored_plain_dict_parameters_matches_live_parameter_spec():
    """A manifest loaded back from the JSON column (plain dicts) must hash
    identically to the ParameterSpec objects that produced it — this is the
    exact comparison api.load_active_skill_manifests performs on every read.
    """
    live_hash = compute_manifest_hash(
        skill_id="service.restart",
        version=1,
        risk=RiskLevel.MEDIUM,
        supported_os=frozenset({"linux", "windows"}),
        timeout_seconds=30,
        rollback_skill_id="service.restore",
        parameters={"service": ParameterSpec("string", True)},
    )
    stored_hash = compute_manifest_hash(
        skill_id="service.restart",
        version=1,
        risk=RiskLevel.MEDIUM,
        supported_os=["linux", "windows"],
        timeout_seconds=30,
        rollback_skill_id="service.restore",
        parameters={"service": {"type": "string", "required": True}},
    )
    assert live_hash == stored_hash


def test_tampering_with_a_stored_manifest_is_detected():
    manifest = _manifest()
    stored_hash = manifest.content_hash()
    tampered = _manifest(risk=RiskLevel.LOW)  # e.g. a direct DB edit
    assert tampered.content_hash() != stored_hash


def test_validate_parameters_accepts_exact_match():
    manifest = _manifest()
    assert validate_parameters(manifest, {"service": "nginx"}) is None


def test_validate_parameters_rejects_missing_required_parameter():
    manifest = _manifest()
    error = validate_parameters(manifest, {})
    assert error is not None
    assert "missing required parameter" in error


def test_validate_parameters_rejects_unexpected_parameter():
    manifest = _manifest()
    error = validate_parameters(manifest, {"service": "nginx", "extra": "x"})
    assert error is not None
    assert "unexpected parameter" in error


def test_validate_parameters_rejects_wrong_type():
    manifest = _manifest()
    error = validate_parameters(manifest, {"service": 123})
    assert error is not None
    assert "must be a string" in error


def test_validate_parameters_allows_missing_optional_parameter():
    manifest = _manifest(
        parameters={"service": ParameterSpec("string", required=False)}
    )
    assert validate_parameters(manifest, {}) is None


def test_validate_parameters_distinguishes_number_from_boolean():
    manifest = _manifest(parameters={"count": ParameterSpec("number", required=True)})
    assert validate_parameters(manifest, {"count": 3}) is None
    assert validate_parameters(manifest, {"count": 3.5}) is None
    error = validate_parameters(manifest, {"count": True})
    assert error is not None
    assert "must be a number" in error


def test_manifest_converts_to_skill_definition_with_same_policy_fields():
    manifest = _manifest()
    definition = manifest.to_skill_definition()
    assert definition.skill_id == manifest.skill_id
    assert definition.risk == manifest.risk
    assert definition.supported_os == manifest.supported_os
    assert definition.timeout_seconds == manifest.timeout_seconds
    assert definition.rollback_skill_id == manifest.rollback_skill_id
