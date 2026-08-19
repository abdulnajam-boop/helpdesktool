"""Control-plane side of signed job envelopes: derives the Ed25519 signing
keypair and signs outgoing envelopes. See ``agent_common.signing`` for the
verification side every agent runs, and for the shared ``canonical_payload``
definition both sides use -- there is exactly one definition of "what bytes
get signed" so the signer and every verifier can never disagree about it.

Key derivation, not storage
----------------------------
There is no keys table and no key file. The private key is deterministically
derived from ``Settings.job_signing_seed`` (an ordinary environment secret,
validated the same way every other secret in this codebase is --
``Settings.validate_security`` rejects the placeholder default outside
development) via SHA-256 into a 32-byte Ed25519 seed. This keeps the same
dev-safe-default pattern used throughout this codebase (the platform works
out of the box with zero extra configuration) while giving a *stable* keypair
across process restarts, which matters here specifically: agents pin the
public key the first time they see it (trust-on-first-use, at enrollment or
via ``GET /v1/agent/signing-key``), so a keypair that silently changed on
every control-plane restart would make every previously-enrolled agent
reject every future job.

Key rotation is deliberately out of scope for this pass: only
``CURRENT_KEY_VERSION`` exists today, and an agent that has already pinned a
public key will fail closed (reject every envelope) if the control plane's
derived key ever changes -- which is the correct, safe failure mode, but
recovering from it today requires an operator to clear the agent's local
``signing_public_key_pem`` to force a fresh trust-on-first-use fetch. A real
rotation story (publishing a new key alongside the old one for a transition
window, agents accepting either during that window) is future work.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_common.signing import canonical_payload

CURRENT_KEY_VERSION = 1


@lru_cache(maxsize=4)
def _private_key(seed_secret: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(
        f"helpdesktool-job-signing-key-v{CURRENT_KEY_VERSION}:{seed_secret}".encode()
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_pem(seed_secret: str) -> str:
    key = _private_key(seed_secret)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode()


def sign_envelope(envelope: dict[str, Any], seed_secret: str) -> str:
    key = _private_key(seed_secret)
    signature = key.sign(canonical_payload(envelope))
    return base64.b64encode(signature).decode()
