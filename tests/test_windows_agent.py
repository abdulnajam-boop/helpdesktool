"""Tests for windows_agent.agent's signed job-envelope verification and
durable-journal crash recovery.

Injects a fake ServiceManager (see test_windows_executor.py) so this runs on
any platform without pywin32 — mirrors test_linux_agent.py's coverage of
the equivalent Linux agent logic exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.support import agent_signing_public_key_pem, build_signed_job_envelope
from windows_agent.agent import WindowsAgent
from windows_agent.config import AgentConfig
from windows_agent.executor import ServiceRestartExecutor, ServiceState


class FakeServiceManager:
    def query_state(self, service: str) -> ServiceState:
        return ServiceState(True, "running")

    def restart(self, service: str, timeout_seconds: float) -> None:
        return None

    def stop(self, service: str, timeout_seconds: float) -> None:
        return None

    def start(self, service: str, timeout_seconds: float) -> None:
        return None


def build_agent(tmp_path: Path, *, service_manager=None) -> WindowsAgent:
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant-1",
        "user",
        "device-1",
        "token",
        allowed_services=("Spooler",),
        signing_public_key_pem=agent_signing_public_key_pem(),
        signing_key_version=1,
    )
    return WindowsAgent(
        config,
        tmp_path / "agent.json",
        service_manager=service_manager or FakeServiceManager(),
    )


def test_rejects_misaddressed_wrong_tenant_and_expired_jobs(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-2", tenant_id="tenant-1", parameters={"service": "Spooler"}
    )
    assert "different device" in agent.execute_job(envelope, job_id=None)["error"]

    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-other",
        parameters={"service": "Spooler"},
    )
    assert "different tenant" in agent.execute_job(envelope, job_id=None)["error"]

    expired = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "Spooler"},
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert "expired" in agent.execute_job(expired, job_id=None)["error"]


def test_rejects_unsupported_skill_version(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        skill_id="service.restart",
        skill_version=99,
        parameters={"service": "Spooler"},
    )
    assert (
        "unsupported skill version" in agent.execute_job(envelope, job_id=None)["error"]
    )


def test_rejects_tampered_signature(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-1", tenant_id="tenant-1", parameters={"service": "Spooler"}
    )
    envelope["parameters"] = {"service": "a-different-service"}
    assert "invalid" in agent.execute_job(envelope, job_id=None)["error"]


def test_successful_job_executes_and_verifies():
    executor = ServiceRestartExecutor(("Spooler",), FakeServiceManager())
    result = executor.execute({"service": "Spooler"})
    assert result["success"] is True
    assert result["verified"] is True


def test_agent_with_no_allowed_services_disables_remediation(tmp_path):
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant-1",
        "user",
        "device-1",
        "token",
        signing_public_key_pem=agent_signing_public_key_pem(),
        signing_key_version=1,
    )
    agent = WindowsAgent(
        config, tmp_path / "agent.json", service_manager=FakeServiceManager()
    )
    assert agent.executor is None
    envelope = build_signed_job_envelope(
        device_id="device-1", tenant_id="tenant-1", parameters={"service": "Spooler"}
    )
    result = agent.execute_job(envelope, job_id=None)
    assert result["success"] is False
    assert "disabled" in result["error"]


def test_recovery_after_crash_during_execution_verifies_without_reexecuting(tmp_path):
    agent = build_agent(tmp_path)
    reported: list[dict] = []

    def _capture(device_id, token, action_id, idem, claim_token, result):
        reported.append(result)

    agent._report_result = _capture  # type: ignore[method-assign]

    agent.journal.record_claimed(
        job_id="action-1:1",
        action_id="action-1",
        attempt=1,
        nonce="n",
        claim_token="claim-token",
        idempotency_key="result-action-1-1",
        skill_id="service.restart",
        parameters={"service": "Spooler"},
    )
    agent.journal.mark_executing("action-1:1")

    agent.recover_interrupted_jobs()

    assert len(reported) == 1
    assert reported[0]["success"] is True
    assert reported[0]["output"]["recovered"] is True
    assert agent.journal._entries["action-1:1"].state == "reported"


def test_recovery_after_crash_following_execution_resends_stored_result(tmp_path):
    agent = build_agent(tmp_path)
    reported: list[dict] = []

    def _capture(device_id, token, action_id, idem, claim_token, result):
        reported.append(result)

    agent._report_result = _capture  # type: ignore[method-assign]

    stored_result = {
        "success": True,
        "verified": True,
        "output": {"service": "Spooler"},
        "error": None,
        "rollback_attempted": False,
        "rollback_succeeded": None,
    }
    agent.journal.record_claimed(
        job_id="action-1:1",
        action_id="action-1",
        attempt=1,
        nonce="n",
        claim_token="claim-token",
        idempotency_key="result-action-1-1",
        skill_id="service.restart",
        parameters={"service": "Spooler"},
    )
    agent.journal.mark_executing("action-1:1")
    agent.journal.mark_executed("action-1:1", stored_result)

    agent.recover_interrupted_jobs()

    assert reported == [stored_result]
    assert agent.journal._entries["action-1:1"].state == "reported"


def test_config_round_trips(tmp_path):
    path = tmp_path / "nested" / "agent.json"
    config = AgentConfig(
        "http://localhost", "agent", "tenant", "user", "device", "secret"
    )
    config.save(path)
    assert AgentConfig.load(path).agent_token == "secret"
