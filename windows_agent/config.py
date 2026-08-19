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

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        values = json.loads(path.read_text())
        for key in ("allowed_services", "monitored_services"):
            values[key] = tuple(values.get(key, ()))
        return cls(**values)

    def save(self, path: Path) -> None:
        # NTFS does not have POSIX permission bits; os.chmod is a best-effort
        # no-op here. Real protection for the credential file at rest comes
        # from running the agent as a dedicated, low-privilege Windows
        # service account and restricting the config directory's ACL to
        # that account plus Administrators — an operator/deployment
        # concern (see deploy/), the same way the Linux agent relies on
        # running as its own unprivileged user rather than root.
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(self), indent=2))
        os.chmod(temporary, 0o600)
        temporary.replace(path)
