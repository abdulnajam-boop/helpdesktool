from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
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
    signing_public_key_pem: str | None = None
    signing_key_version: int | None = None

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        values = json.loads(path.read_text())
        for key in ("allowed_services", "monitored_services"):
            values[key] = tuple(values.get(key, ()))
        return cls(**values)

    def save(self, path: Path) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(self), indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(path)
