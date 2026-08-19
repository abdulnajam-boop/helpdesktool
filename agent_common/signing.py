"""Signed, versioned job envelope verification.

Trust model
-----------
Every job the control plane hands an agent (``POST
/v1/devices/{id}/jobs/{action_id}/claim``'s response) is a signed envelope,
not a bare instruction: job id, action id, device id, tenant id, skill id +
version, parameters, issue/expiry timestamps, a random nonce, a key version,
and an Ed25519 signature over all of the above (``canonical_payload``). This
is a defense-in-depth layer *independent of TLS* -- it protects against
tampering or misdirection anywhere between the control plane signing the
envelope and the agent trusting it (a compromised intermediary, a caching
proxy, a replayed old HTTP response), not just against a passive network
observer, which TLS alone already handles.

``verify_envelope`` is what every agent calls before it will let a job reach
its executor. It fails closed on every dimension explicitly, in a fixed
order (structure, then signature, then addressing, then freshness, then
skill-version support) so the reported error always names the *first* thing
wrong rather than a generic "invalid job":

- malformed envelope (missing required fields)
- invalid signature (tampering, or a key the agent didn't pin)
- wrong device (misaddressed / a forged envelope for a different device)
- wrong tenant (cross-tenant misaddressing)
- expired (the same short window used for the claim lease)
- unsupported skill id/version (the agent's own hardcoded allowlist, from
  ``linux_agent/executor.py`` / ``windows_agent/executor.py``, is still the
  sole authority over what can actually execute -- this is an *additional*
  check, not a replacement for it)

Replay protection (the ``nonce`` field, and ``job_id`` being unique per
claim *attempt* rather than reused across requeues) is enforced by the
caller against the durable local journal (``agent_common.journal``), not
here -- that requires local state this pure-function module deliberately
doesn't hold.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ENVELOPE_SIGNED_FIELDS: tuple[str, ...] = (
    "job_id",
    "action_id",
    "device_id",
    "tenant_id",
    "skill_id",
    "skill_version",
    "parameters",
    "device_os",
    "issued_at",
    "expires_at",
    "nonce",
    "key_version",
)

REQUIRED_ENVELOPE_FIELDS: frozenset[str] = frozenset(
    {*ENVELOPE_SIGNED_FIELDS, "signature", "claim_token", "attempt"}
)


class EnvelopeError(RuntimeError):
    """Raised when a job envelope fails verification before execution."""


def canonical_payload(envelope: dict[str, Any]) -> bytes:
    """The exact bytes that get signed/verified -- sorted-key, separator-
    tight JSON over just the signed fields, so signer and verifier can never
    disagree about field order or incidental whitespace.
    """
    try:
        body = {key: envelope[key] for key in ENVELOPE_SIGNED_FIELDS}
    except KeyError as exc:
        raise EnvelopeError(f"malformed job envelope: missing {exc}") from exc
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def verify_signature(
    envelope: dict[str, Any], signature_b64: str, public_key_pem: str
) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(base64.b64decode(signature_b64), canonical_payload(envelope))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error, EnvelopeError):
        return False


def verify_envelope(
    envelope: dict[str, Any],
    *,
    public_key_pem: str,
    expected_device_id: str,
    expected_tenant_id: str,
    supported_skill_versions: dict[str, frozenset[int]],
    now: datetime | None = None,
) -> None:
    """Raises ``EnvelopeError`` with a specific reason on the first failed
    check; returns normally only once every check has passed.
    """
    missing = REQUIRED_ENVELOPE_FIELDS - set(envelope)
    if missing:
        raise EnvelopeError(f"malformed job envelope: missing {sorted(missing)}")
    if not verify_signature(envelope, str(envelope["signature"]), public_key_pem):
        raise EnvelopeError("invalid job envelope signature")
    if envelope["device_id"] != expected_device_id:
        raise EnvelopeError("job envelope is addressed to a different device")
    if envelope["tenant_id"] != expected_tenant_id:
        raise EnvelopeError("job envelope is addressed to a different tenant")
    moment = now or datetime.now(UTC)
    try:
        expires_at = datetime.fromisoformat(str(envelope["expires_at"]))
    except ValueError as exc:
        raise EnvelopeError("malformed job envelope expiration") from exc
    if expires_at.tzinfo is None:
        raise EnvelopeError("malformed job envelope expiration")
    if expires_at <= moment:
        raise EnvelopeError("job envelope has expired")
    skill_id = str(envelope["skill_id"])
    skill_version = envelope["skill_version"]
    allowed_versions = supported_skill_versions.get(skill_id)
    if not allowed_versions or skill_version not in allowed_versions:
        raise EnvelopeError(f"unsupported skill version: {skill_id} v{skill_version}")
