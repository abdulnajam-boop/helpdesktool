from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(slots=True)
class AgentConfig:
    server_url: str
    external_id: str
    tenant_id: str
    user_id: str
    device_id: str | None = None
    agent_token: str | None = None
    heartbeat_seconds: int = 60
    inventory_seconds: int = 3600
    allowed_services: tuple[str, ...] = ()
    monitored_services: tuple[str, ...] = ()
    # Every signing-key version this agent currently trusts, keyed by
    # version number -- supports a key-rotation transition window (see
    # helpdesktool/job_signing.py) where both the previous and current
    # version verify successfully. Once a version is pinned here its PEM
    # value is never overwritten; only genuinely new versions are ever
    # added (agent.py's ensure_signing_key).
    signing_public_keys: dict[int, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        values = json.loads(path.read_text())
        for key in ("allowed_services", "monitored_services"):
            values[key] = tuple(values.get(key, ()))
        # Migrates a pre-rotation config (a single signing_public_key_pem/
        # signing_key_version pair) into the new per-version dict shape,
        # so an agent enrolled before this change keeps its already-pinned
        # key rather than losing trust and needing to re-pin from scratch.
        legacy_pem = values.pop("signing_public_key_pem", None)
        legacy_version = values.pop("signing_key_version", None)
        signing_public_keys = {
            int(version): pem
            for version, pem in values.get("signing_public_keys", {}).items()
        }
        if legacy_pem and legacy_version is not None:
            signing_public_keys.setdefault(int(legacy_version), legacy_pem)
        values["signing_public_keys"] = signing_public_keys
        return cls(**values)

    def save(self, path: Path) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(self), indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(path)
