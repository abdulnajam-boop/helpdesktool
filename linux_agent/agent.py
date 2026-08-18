from __future__ import annotations

import argparse
import json
import logging
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .client import ApiError, ControlPlaneClient
from .collectors import collect_inventory
from .config import AgentConfig
from .executor import ServiceRestartExecutor

LOG = logging.getLogger("helpdesktool-linux-agent")


class LinuxAgent:
    def __init__(
        self,
        config: AgentConfig,
        config_path: Path,
        client: ControlPlaneClient | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.client = client or ControlPlaneClient(config.server_url)
        self.processed_path = config_path.with_suffix(".processed.json")
        self.processed = self._load_processed()
        self.last_inventory_at = 0.0
        self.executor = (
            ServiceRestartExecutor(config.allowed_services)
            if config.allowed_services
            else None
        )

    def enroll(self) -> None:
        if self.config.device_id and self.config.agent_token:
            return
        result = self.client.enroll(
            self.config.tenant_id,
            self.config.user_id,
            self.config.external_id,
            socket.gethostname(),
        )
        self.config.device_id = result["device_id"]
        self.config.agent_token = result["agent_token"]
        self.config.save(self.config_path)
        LOG.info("enrolled device %s", self.config.device_id)

    def run_once(self) -> None:
        self.enroll()
        device_id, token = self._identity()
        headers = self.client.agent_headers(token, str(uuid4()))
        self.client.request(
            "POST",
            f"/v1/devices/{device_id}/heartbeat",
            payload={"status": {"agent_version": "0.1.0"}},
            headers=headers,
        )
        if time.monotonic() - self.last_inventory_at >= self.config.inventory_seconds:
            inventory = collect_inventory(self.config.monitored_services)
            self.client.request(
                "POST",
                f"/v1/devices/{device_id}/inventory",
                payload={
                    "collected_at": datetime.now(UTC).isoformat(),
                    "payload": inventory,
                },
                headers=self.client.agent_headers(token, str(uuid4())),
            )
            self.last_inventory_at = time.monotonic()
        self.process_jobs()

    def process_jobs(self) -> None:
        device_id, token = self._identity()
        jobs = self.client.request(
            "GET",
            f"/v1/devices/{device_id}/jobs",
            headers=self.client.agent_headers(token),
        )
        for summary in jobs:
            action_id = summary.get("id")
            if not isinstance(action_id, str) or action_id in self.processed:
                continue
            claim = self.client.request(
                "POST",
                f"/v1/devices/{device_id}/jobs/{action_id}/claim",
                payload={},
                headers=self.client.agent_headers(token, f"claim-{action_id}"),
            )
            result = self.execute_job(claim)
            self.client.request(
                "POST",
                f"/v1/devices/{device_id}/jobs/{action_id}/result",
                payload=result,
                headers={
                    **self.client.agent_headers(
                        token, f"result-{action_id}-{claim['attempt']}"
                    ),
                    "X-Claim-Token": claim["claim_token"],
                },
            )
            self.processed.add(action_id)
            self._save_processed()

    def execute_job(self, job: dict[str, Any]) -> dict[str, Any]:
        device_id, _ = self._identity()
        required = {
            "id",
            "skill_id",
            "parameters",
            "device_id",
            "attempt",
            "lease_expires_at",
            "claim_token",
        }
        if set(job) != required or job.get("device_id") != device_id:
            return self._invalid("invalid or misaddressed job envelope")
        if job.get("skill_id") != "service.restart":
            return self._invalid("unsupported skill")
        if self.executor is None:
            return self._invalid("service remediation is disabled: allowlist is empty")
        try:
            expires = datetime.fromisoformat(str(job["lease_expires_at"]))
            if expires.tzinfo is None or expires <= datetime.now(UTC):
                return self._invalid("job lease expired")
            parameters = job["parameters"]
            if not isinstance(parameters, dict):
                return self._invalid("invalid parameters")
            return self.executor.execute(parameters)
        except (PermissionError, ValueError) as exc:
            return self._invalid(str(exc))

    def _identity(self) -> tuple[str, str]:
        if not self.config.device_id or not self.config.agent_token:
            raise RuntimeError("agent is not enrolled")
        return self.config.device_id, self.config.agent_token

    def _load_processed(self) -> set[str]:
        try:
            return set(json.loads(self.processed_path.read_text()))
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def _save_processed(self) -> None:
        recent = sorted(self.processed)[-1000:]
        self.processed_path.write_text(json.dumps(recent))
        self.processed_path.chmod(0o600)

    @staticmethod
    def _invalid(error: str) -> dict[str, Any]:
        return {
            "success": False,
            "verified": False,
            "output": {},
            "error": error,
            "rollback_attempted": False,
            "rollback_succeeded": None,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Helpdesktool Linux endpoint agent")
    parser.add_argument(
        "--config", type=Path, default=Path.home() / ".config/helpdesktool/agent.json"
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    config = AgentConfig.load(args.config)
    agent = LinuxAgent(config, args.config)
    while True:
        try:
            agent.run_once()
        except (ApiError, OSError) as exc:
            LOG.error("agent cycle failed: %s", exc)
        if args.once:
            break
        time.sleep(config.heartbeat_seconds)


if __name__ == "__main__":
    main()
