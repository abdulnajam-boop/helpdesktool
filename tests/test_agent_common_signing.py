"""Unit tests for agent_common.signing: the canonical payload, signature
verification, and full envelope verification (device/tenant/expiry/skill
version) that every agent runs before trusting a claimed job.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_common.signing import EnvelopeError, verify_envelope, verify_signature
from helpdesktool.job_signing import public_key_pem, sign_envelope

SEED = "test-seed"


def _envelope(**overrides) -> dict:
    now = datetime.now(UTC)
    envelope = {
        "job_id": "action-1:1",
        "action_id": "action-1",
        "device_id": "device-1",
        "tenant_id": "tenant-1",
        "skill_id": "service.restart",
        "skill_version": 1,
        "parameters": {"service": "demo.service"},
        "device_os": "linux",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "nonce": "nonce-1",
        "key_version": 1,
    }
    envelope.update(overrides)
    envelope["signature"] = sign_envelope(envelope, SEED)
    envelope["claim_token"] = "claim-token"
    envelope["attempt"] = 1
    return envelope


def test_valid_envelope_verifies_successfully():
    envelope = _envelope()
    verify_envelope(
        envelope,
        public_key_pem=public_key_pem(SEED),
        expected_device_id="device-1",
        expected_tenant_id="tenant-1",
        supported_skill_versions={"service.restart": frozenset({1})},
    )


def test_signature_verification_fails_with_wrong_key():
    envelope = _envelope()
    assert not verify_signature(
        envelope, envelope["signature"], public_key_pem("a-different-seed")
    )


def test_any_field_tampering_after_signing_invalidates_signature():
    envelope = _envelope()
    tampered = dict(envelope)
    tampered["parameters"] = {"service": "different-service"}
    assert not verify_signature(tampered, envelope["signature"], public_key_pem(SEED))


@pytest.mark.parametrize(
    "overrides,expected_substring",
    [
        ({"device_id": "device-2"}, "different device"),
        ({"tenant_id": "tenant-2"}, "different tenant"),
        ({"skill_version": 99}, "unsupported skill version"),
        ({"skill_id": "shell.execute"}, "unsupported skill version"),
    ],
)
def test_verify_envelope_rejects_addressing_and_version_mismatches(
    overrides, expected_substring
):
    envelope = _envelope(**overrides)
    with pytest.raises(EnvelopeError, match=expected_substring):
        verify_envelope(
            envelope,
            public_key_pem=public_key_pem(SEED),
            expected_device_id="device-1",
            expected_tenant_id="tenant-1",
            supported_skill_versions={"service.restart": frozenset({1})},
        )


def test_verify_envelope_rejects_expired_envelope():
    envelope = _envelope(
        expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    )
    with pytest.raises(EnvelopeError, match="expired"):
        verify_envelope(
            envelope,
            public_key_pem=public_key_pem(SEED),
            expected_device_id="device-1",
            expected_tenant_id="tenant-1",
            supported_skill_versions={"service.restart": frozenset({1})},
        )


def test_verify_envelope_rejects_missing_fields():
    envelope = _envelope()
    del envelope["nonce"]
    with pytest.raises(EnvelopeError, match="malformed"):
        verify_envelope(
            envelope,
            public_key_pem=public_key_pem(SEED),
            expected_device_id="device-1",
            expected_tenant_id="tenant-1",
            supported_skill_versions={"service.restart": frozenset({1})},
        )


def test_verify_envelope_rejects_invalid_signature():
    envelope = _envelope()
    envelope["signature"] = "not-a-real-signature"
    with pytest.raises(EnvelopeError, match="invalid job envelope signature"):
        verify_envelope(
            envelope,
            public_key_pem=public_key_pem(SEED),
            expected_device_id="device-1",
            expected_tenant_id="tenant-1",
            supported_skill_versions={"service.restart": frozenset({1})},
        )


def test_public_key_derivation_is_stable_and_seed_specific():
    assert public_key_pem(SEED) == public_key_pem(SEED)
    assert public_key_pem(SEED) != public_key_pem("another-seed")
