"""Tests for windows_agent.executor's allowlisted service-restart logic.

Uses a fake ServiceManager (the Protocol windows_agent.executor defines) so
this exercises the exact same safety-critical decision logic
(allowlist/rollback/verification) the real Win32ServiceManager drives,
without needing pywin32 or a real Windows service — mirrors
tests/test_linux_executor.py's approach for the Linux executor.
"""

from __future__ import annotations

import pytest

from windows_agent.executor import (
    ServiceControlError,
    ServiceRestartExecutor,
    ServiceState,
)


class FakeServiceManager:
    def __init__(self, states: list[ServiceState | Exception]) -> None:
        self._states = iter(states)
        self.calls: list[tuple[str, str]] = []

    def _next(self) -> ServiceState:
        value = next(self._states)
        if isinstance(value, Exception):
            raise value
        return value

    def query_state(self, service: str) -> ServiceState:
        self.calls.append(("query", service))
        return self._next()

    def restart(self, service: str, timeout_seconds: float) -> None:
        self.calls.append(("restart", service))
        self._next()

    def stop(self, service: str, timeout_seconds: float) -> None:
        self.calls.append(("stop", service))
        self._next()

    def start(self, service: str, timeout_seconds: float) -> None:
        self.calls.append(("start", service))
        self._next()


RUNNING = ServiceState(True, "running")
STOPPED = ServiceState(True, "stopped")
MISSING = ServiceState(False, "unknown")


def test_successful_allowlisted_restart_and_verification():
    manager = FakeServiceManager([RUNNING, None, RUNNING])
    result = ServiceRestartExecutor(("Spooler",), manager).execute(
        {"service": "Spooler"}
    )
    assert result["success"] is True
    assert result["verified"] is True
    assert manager.calls == [
        ("query", "Spooler"),
        ("restart", "Spooler"),
        ("query", "Spooler"),
    ]


def test_non_allowlisted_and_malformed_parameters_are_rejected_without_calls():
    manager = FakeServiceManager([])
    executor = ServiceRestartExecutor(("Spooler",), manager)
    with pytest.raises(PermissionError):
        executor.execute({"service": "NotAllowed"})
    with pytest.raises(ValueError):
        executor.execute({"service": "Spooler", "extra": "field"})
    assert manager.calls == []


def test_uninstalled_service_fails_without_attempting_restart():
    manager = FakeServiceManager([MISSING])
    result = ServiceRestartExecutor(("Spooler",), manager).execute(
        {"service": "Spooler"}
    )
    assert result["success"] is False
    assert result["error"] == "service is not installed"
    assert result["rollback_attempted"] is False
    assert manager.calls == [("query", "Spooler")]


def test_restart_failure_attempts_rollback_and_reports_failure_to_restore():
    manager = FakeServiceManager(
        [RUNNING, ServiceControlError("boom"), ServiceControlError("boom again")]
    )
    result = ServiceRestartExecutor(("Spooler",), manager).execute(
        {"service": "Spooler"}
    )
    assert result["success"] is False
    assert result["error"] == "restart failed"
    assert result["rollback_attempted"] is True
    assert result["rollback_succeeded"] is False
    # Rollback from a "running" before-state tries to start it back up.
    assert manager.calls[-1] == ("start", "Spooler")


def test_post_restart_verification_failure_rolls_back_to_prior_state():
    manager = FakeServiceManager([RUNNING, None, STOPPED, None, RUNNING])
    result = ServiceRestartExecutor(("Spooler",), manager).execute(
        {"service": "Spooler"}
    )
    assert result["success"] is False
    assert result["error"] == "post-restart verification failed"
    assert result["rollback_attempted"] is True
    assert result["rollback_succeeded"] is True


def test_rollback_from_a_stopped_before_state_stops_it_back_down():
    # before=stopped, restart() itself fails -> rollback must try to reach
    # "stopped" again by calling stop(), not start().
    manager = FakeServiceManager([STOPPED, ServiceControlError("boom"), None, STOPPED])
    result = ServiceRestartExecutor(("Spooler",), manager).execute(
        {"service": "Spooler"}
    )
    assert result["rollback_succeeded"] is True
    assert ("stop", "Spooler") in manager.calls
    assert ("start", "Spooler") not in manager.calls


def test_construction_requires_a_valid_nonempty_allowlist():
    with pytest.raises(ValueError):
        ServiceRestartExecutor((), FakeServiceManager([]))
    with pytest.raises(ValueError):
        ServiceRestartExecutor(("bad;name",), FakeServiceManager([]))
