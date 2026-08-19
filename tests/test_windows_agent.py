"""Tests for windows_agent.agent's job-envelope validation.

Injects a fake ServiceManager (see test_windows_executor.py) so this runs on
any platform without pywin32 — mirrors test_linux_agent.py's coverage of
the equivalent Linux agent logic exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from windows_agent.agent import WindowsAgent
from windows_agent.config import AgentConfig
from windows_agent.executor import ServiceState


class FakeServiceManager:
    def query_state(self, service: str) -> ServiceState:
        return ServiceState(True, "running")

    def restart(self, service: str, timeout_seconds: float) -> None:
        return None

    def stop(self, service: str, timeout_seconds: float) -> None:
        return None

    def start(self, service: str, timeout_seconds: float) -> None:
        return None


def build_agent(tmp_path: Path) -> WindowsAgent:
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant",
        "user",
        "device-1",
        "token",
        allowed_services=("Spooler",),
    )
    return WindowsAgent(
        config, tmp_path / "agent.json", service_manager=FakeServiceManager()
    )


def test_rejects_misaddressed_unknown_and_expired_jobs(tmp_path):
    agent = build_agent(tmp_path)
    base = {
        "id": "action",
        "skill_id": "service.restart",
        "parameters": {"service": "Spooler"},
        "device_id": "device-2",
        "attempt": 1,
        "lease_expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "claim_token": "claim",
    }
    assert "misaddressed" in agent.execute_job(base)["error"]
    base["device_id"] = "device-1"
    base["skill_id"] = "shell.execute"
    assert agent.execute_job(base)["error"] == "unsupported skill"
    base["skill_id"] = "service.restart"
    base["lease_expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert agent.execute_job(base)["error"] == "job lease expired"


def test_successful_job_executes_and_verifies():
    from windows_agent.executor import ServiceRestartExecutor

    executor = ServiceRestartExecutor(("Spooler",), FakeServiceManager())
    result = executor.execute({"service": "Spooler"})
    assert result["success"] is True
    assert result["verified"] is True


def test_agent_with_no_allowed_services_disables_remediation(tmp_path):
    config = AgentConfig(
        "http://localhost", "agent-1", "tenant", "user", "device-1", "token"
    )
    agent = WindowsAgent(
        config, tmp_path / "agent.json", service_manager=FakeServiceManager()
    )
    assert agent.executor is None
    job = {
        "id": "action",
        "skill_id": "service.restart",
        "parameters": {"service": "Spooler"},
        "device_id": "device-1",
        "attempt": 1,
        "lease_expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "claim_token": "claim",
    }
    result = agent.execute_job(job)
    assert result["success"] is False
    assert "disabled" in result["error"]


def test_config_round_trips(tmp_path):
    path = tmp_path / "nested" / "agent.json"
    config = AgentConfig(
        "http://localhost", "agent", "tenant", "user", "device", "secret"
    )
    config.save(path)
    assert AgentConfig.load(path).agent_token == "secret"
