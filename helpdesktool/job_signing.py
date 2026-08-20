"""Control-plane side of signed job envelopes: derives Ed25519 signing
keypairs and signs outgoing envelopes. See ``agent_common.signing`` for the
verification side every agent runs, and for the shared ``canonical_payload``
definition both sides use -- there is exactly one definition of "what bytes
get signed" so the signer and every verifier can never disagree about it.

Key derivation, not storage
----------------------------
There is no keys table and no key file. A version's private key is
deterministically derived from ``Settings.job_signing_seed`` (an ordinary
environment secret, validated the same way every other secret in this
codebase is -- ``Settings.validate_security`` rejects the placeholder
default outside development) *and its own version number* via SHA-256 into
a 32-byte Ed25519 seed. This keeps the same dev-safe-default pattern used
throughout this codebase (the platform works out of the box with zero extra
configuration) while giving a *stable* keypair per version across process
restarts, which matters here specifically: agents pin a public key per
version the first time they see it (trust-on-first-use, at enrollment or
via ``GET /v1/devices/{id}/signing-key``), so a keypair that silently
changed on every control-plane restart would make every previously-enrolled
agent reject every future job.

Key rotation
------------
Because a version's key depends on the version number as well as the seed,
rotation is a config change, not a new secret or a code deploy:
``Settings.job_signing_key_version`` is the version new envelopes get
signed with; bumping it derives a genuinely different keypair from the
*same* seed. The previous version's key is still derivable (and thus still
verifiable) from that same seed, so ``active_public_keys`` exposes a small
trailing window (``Settings.job_signing_key_rotation_window``, default 1)
of still-trusted versions alongside the current one -- an agent that
already pinned the previous version's key keeps working through the
transition window without any manual intervention; see
``linux_agent/agent.py``/``windows_agent/agent.py``'s ``ensure_signing_key``
for the agent side of this (it refreshes its locally-trusted key set every
cycle, only ever *adding* newly-introduced versions, never overwriting an
already-pinned version's value). Retiring a version permanently (so an
agent still stuck on it starts failing closed) is simply letting it fall
out of the window as ``job_signing_key_version`` advances further; a full
break-glass rotation that invalidates *every* existing version at once
still requires changing ``job_signing_seed`` itself, which is intentionally
a separate, heavier action (every agent must then re-pin from scratch).
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_common.signing import canonical_payload


@lru_cache(maxsize=32)
def _private_key(seed_secret: str, version: int) -> Ed25519PrivateKey:
    seed = hashlib.sha256(
        f"helpdesktool-job-signing-key-v{version}:{seed_secret}".encode()
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_pem(seed_secret: str, version: int = 1) -> str:
    key = _private_key(seed_secret, version)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode()


def sign_envelope(envelope: dict[str, Any], seed_secret: str, version: int = 1) -> str:
    key = _private_key(seed_secret, version)
    signature = key.sign(canonical_payload(envelope))
    return base64.b64encode(signature).decode()


def active_public_keys(
    seed_secret: str, current_version: int, window: int = 1
) -> dict[int, str]:
    """The set of key versions an agent should currently trust:
    ``current_version`` down through ``current_version - window`` (never
    below version 1). Used by every endpoint that hands an agent signing
    keys (enrollment, the dedicated signing-key refresh endpoint) so a
    rotation's transition window is expressed in exactly one place.
    """
    lowest = max(1, current_version - window)
    return {
        version: public_key_pem(seed_secret, version)
        for version in range(lowest, current_version + 1)
    }
