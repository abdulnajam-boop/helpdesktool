from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Protocol


SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")


class Runner(Protocol):
    def __call__(
        self, command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]: ...


def run_command(
    command: list[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False
    )


@dataclass(frozen=True)
class ServiceState:
    load: str
    active: str
    sub: str


class ServiceRestartExecutor:
    def __init__(
        self,
        allowed_services: tuple[str, ...],
        runner: Runner = run_command,
        timeout_seconds: float = 15.0,
    ) -> None:
        if not allowed_services or any(
            not SERVICE_PATTERN.fullmatch(item) for item in allowed_services
        ):
            raise ValueError("a valid, non-empty service allowlist is required")
        self.allowed = frozenset(allowed_services)
        self.runner = runner
        self.timeout = timeout_seconds

    def state(self, service: str) -> ServiceState:
        result = self.runner(
            [
                "systemctl",
                "show",
                service,
                "--property=LoadState,ActiveState,SubState",
                "--no-pager",
            ],
            timeout=min(self.timeout, 5.0),
        )
        values = dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )
        return ServiceState(
            values.get("LoadState", "unknown"),
            values.get("ActiveState", "unknown"),
            values.get("SubState", "unknown"),
        )

    def execute(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if set(parameters) != {"service"} or not isinstance(
            parameters.get("service"), str
        ):
            raise ValueError("service.restart accepts only a string service parameter")
        service = parameters["service"]
        if service not in self.allowed:
            raise PermissionError("service is not allowlisted")
        try:
            before = self.state(service)
        except (OSError, subprocess.TimeoutExpired):
            return self._failure(
                "service precheck failed", ServiceState("unknown", "unknown", "unknown")
            )
        if before.load != "loaded":
            return self._failure("service unit is not loaded", before)
        try:
            restarted = self.runner(
                ["systemctl", "restart", service], timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return self._rollback(service, before, "restart timed out")
        if restarted.returncode != 0:
            return self._rollback(service, before, "restart failed")
        try:
            after = self.state(service)
        except (OSError, subprocess.TimeoutExpired):
            return self._rollback(service, before, "post-restart verification failed")
        if after.active == "active" and after.sub == "running":
            return {
                "success": True,
                "verified": True,
                "output": {
                    "service": service,
                    "before": asdict(before),
                    "after": asdict(after),
                },
                "error": None,
                "rollback_attempted": False,
                "rollback_succeeded": None,
            }
        return self._rollback(service, before, "post-restart verification failed")

    def _rollback(
        self, service: str, before: ServiceState, error: str
    ) -> dict[str, Any]:
        command = [
            "systemctl",
            "restart" if before.active == "active" else "stop",
            service,
        ]
        try:
            result = self.runner(command, timeout=self.timeout)
            current = self.state(service)
            restored = result.returncode == 0 and current.active == before.active
        except (OSError, subprocess.TimeoutExpired):
            restored = False
        return {
            "success": False,
            "verified": False,
            "output": {"service": service, "before": asdict(before)},
            "error": error,
            "rollback_attempted": True,
            "rollback_succeeded": restored,
        }

    @staticmethod
    def _failure(error: str, before: ServiceState) -> dict[str, Any]:
        return {
            "success": False,
            "verified": False,
            "output": {"before": asdict(before)},
            "error": error,
            "rollback_attempted": False,
            "rollback_succeeded": None,
        }
