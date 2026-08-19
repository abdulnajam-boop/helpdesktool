"""Deterministic, allowlisted Windows service remediation.

Mirrors ``linux_agent.executor.ServiceRestartExecutor``'s contract exactly:
validate parameters, enforce a local allowlist, capture before-state,
restart, verify the post-restart state, and roll back to the prior state on
any failure. The real service control implementation
(``windows_agent.win32_service_manager.Win32ServiceManager``) talks to the
Windows Service Control Manager directly through the Win32 API (via
pywin32) — it never spawns a shell, ``cmd.exe``, ``sc.exe``, or PowerShell,
which is a *stronger* guarantee against arbitrary command execution than
even a fixed subprocess argument vector, since no process is spawned at
all. ``ServiceManager`` here is a Protocol purely so this module (and its
tests) can be imported and exercised on any platform without pywin32
installed; only actually constructing ``Win32ServiceManager`` requires
Windows.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Protocol

SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9_.\- ]{1,256}$")


class ServiceControlError(RuntimeError):
    """Raised by a ServiceManager when a service-control operation fails."""


@dataclass(frozen=True, slots=True)
class ServiceState:
    exists: bool
    state: str  # "running" | "stopped" | "*_pending" | "paused" | "unknown"


class ServiceManager(Protocol):
    def query_state(self, service: str) -> ServiceState: ...
    def restart(self, service: str, timeout_seconds: float) -> None: ...
    def stop(self, service: str, timeout_seconds: float) -> None: ...
    def start(self, service: str, timeout_seconds: float) -> None: ...


class ServiceRestartExecutor:
    def __init__(
        self,
        allowed_services: tuple[str, ...],
        service_manager: ServiceManager,
        timeout_seconds: float = 20.0,
    ) -> None:
        if not allowed_services or any(
            not SERVICE_PATTERN.fullmatch(item) for item in allowed_services
        ):
            raise ValueError("a valid, non-empty service allowlist is required")
        self.allowed = frozenset(allowed_services)
        self.manager = service_manager
        self.timeout = timeout_seconds

    def execute(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if set(parameters) != {"service"} or not isinstance(
            parameters.get("service"), str
        ):
            raise ValueError("service.restart accepts only a string service parameter")
        service = parameters["service"]
        if service not in self.allowed:
            raise PermissionError("service is not allowlisted")
        try:
            before = self.manager.query_state(service)
        except ServiceControlError:
            return self._failure(
                "service precheck failed", ServiceState(False, "unknown")
            )
        if not before.exists:
            return self._failure("service is not installed", before)
        try:
            self.manager.restart(service, self.timeout)
        except ServiceControlError:
            return self._rollback(service, before, "restart failed")
        try:
            after = self.manager.query_state(service)
        except ServiceControlError:
            return self._rollback(service, before, "post-restart verification failed")
        if after.state == "running":
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
        try:
            if before.state == "running":
                self.manager.start(service, self.timeout)
            else:
                self.manager.stop(service, self.timeout)
            current = self.manager.query_state(service)
            restored = current.state == before.state
        except ServiceControlError:
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
