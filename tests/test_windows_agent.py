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


class FakeDnsResolver:
    def __init__(self, succeeds: bool = True) -> None:
        self.succeeds = succeeds
        self.calls = 0

    def flush(self) -> bool:
        self.calls += 1
        return self.succeeds


def build_agent(
    tmp_path: Path, *, service_manager=None, dns_resolver=None
) -> WindowsAgent:
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
        dns_resolver=dns_resolver or FakeDnsResolver(),
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
        config,
        tmp_path / "agent.json",
        service_manager=FakeServiceManager(),
        dns_resolver=FakeDnsResolver(),
    )
    assert agent.executor is None
    envelope = build_signed_job_envelope(
        device_id="device-1", tenant_id="tenant-1", parameters={"service": "Spooler"}
    )
    result = agent.execute_job(envelope, job_id=None)
    assert result["success"] is False
    assert "no executor available" in result["error"]


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


class _FakeTokenEnrollClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def enroll_with_token(self, token, external_id, hostname):
        self.calls.append((token, external_id, hostname))
        return self.response


def test_enroll_with_token_populates_config_including_tenant_id(tmp_path):
    """Unlike admin-mediated enroll(), a self-enrolling agent never learns
    its tenant_id any other way -- it must come from the enrollment
    response, since the whole point of token-based enrollment is not
    needing tenant_id known upfront.
    """
    config = AgentConfig("http://localhost", "desktop-1", "", "")
    config_path = tmp_path / "agent.json"
    fake_client = _FakeTokenEnrollClient(
        {
            "device_id": "device-42",
            "tenant_id": "tenant-42",
            "agent_token": "secret-token",
            "signing_public_key_pem": "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n",
            "signing_key_version": 1,
        }
    )
    agent = WindowsAgent(
        config, config_path, client=fake_client, service_manager=FakeServiceManager()
    )

    agent.enroll_with_token("one-time-token")

    assert fake_client.calls == [
        ("one-time-token", "desktop-1", fake_client.calls[0][2])
    ]
    assert agent.config.device_id == "device-42"
    assert agent.config.tenant_id == "tenant-42"
    assert agent.config.agent_token == "secret-token"
    reloaded = AgentConfig.load(config_path)
    assert reloaded.tenant_id == "tenant-42"
    assert reloaded.device_id == "device-42"


def test_dns_flush_cache_job_dispatches_to_dns_executor_and_executes(tmp_path):
    agent = build_agent(tmp_path, dns_resolver=FakeDnsResolver(succeeds=True))
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        skill_id="dns.flush_cache",
        parameters={},
    )
    result = agent.execute_job(envelope, job_id=None)
    assert result["success"] is True
    assert result["verified"] is True


def test_dns_flush_cache_failure_does_not_touch_service_restart_executor(tmp_path):
    class _ExplodingServiceManager(FakeServiceManager):
        def restart(self, service: str, timeout_seconds: float) -> None:
            raise AssertionError("service.restart executor should not run for this job")

    agent = build_agent(
        tmp_path,
        service_manager=_ExplodingServiceManager(),
        dns_resolver=FakeDnsResolver(succeeds=True),
    )
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        skill_id="dns.flush_cache",
        parameters={},
    )
    result = agent.execute_job(envelope, job_id=None)
    assert result["success"] is True


def test_enroll_with_token_is_a_noop_once_already_enrolled(tmp_path):
    config = AgentConfig(
        "http://localhost",
        "desktop-1",
        "tenant-1",
        "",
        device_id="device-1",
        agent_token="already-have-one",
    )
    fake_client = _FakeTokenEnrollClient(
        {"device_id": "x", "tenant_id": "y", "agent_token": "z"}
    )
    agent = WindowsAgent(
        config,
        tmp_path / "agent.json",
        client=fake_client,
        service_manager=FakeServiceManager(),
    )

    agent.enroll_with_token("some-token")

    assert fake_client.calls == []
    assert agent.config.agent_token == "already-have-one"
