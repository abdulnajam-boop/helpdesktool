import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from linux_agent.agent import LinuxAgent
from linux_agent.config import AgentConfig
from linux_agent.executor import ServiceRestartExecutor
from tests.support import agent_signing_public_key_pem, build_signed_job_envelope


def build_agent(tmp_path: Path, *, runner=None) -> LinuxAgent:
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant-1",
        "user",
        "device-1",
        "token",
        allowed_services=("demo.service",),
        signing_public_key_pem=agent_signing_public_key_pem(),
        signing_key_version=1,
    )
    agent = LinuxAgent(config, tmp_path / "agent.json")
    if runner is not None:
        agent.executor = ServiceRestartExecutor(("demo.service",), runner=runner)
    return agent


def _running(*_args, **_kwargs):
    return subprocess.CompletedProcess(
        [], 0, stdout="LoadState=loaded\nActiveState=active\nSubState=running\n"
    )


def test_rejects_misaddressed_wrong_tenant_and_expired_jobs(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-2",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
    )
    assert "different device" in agent.execute_job(envelope, job_id=None)["error"]

    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-other",
        parameters={"service": "demo.service"},
    )
    assert "different tenant" in agent.execute_job(envelope, job_id=None)["error"]

    expired = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
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
        parameters={"service": "demo.service"},
    )
    assert (
        "unsupported skill version" in agent.execute_job(envelope, job_id=None)["error"]
    )

    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        skill_id="shell.execute",
        parameters={},
    )
    assert (
        "unsupported skill version" in agent.execute_job(envelope, job_id=None)["error"]
    )


def test_rejects_tampered_signature(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
    )
    envelope["parameters"] = {"service": "a-different-service"}  # tamper post-signing
    assert "invalid" in agent.execute_job(envelope, job_id=None)["error"]


def test_rejects_malformed_envelope_missing_fields(tmp_path):
    agent = build_agent(tmp_path)
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
    )
    del envelope["nonce"]
    assert "malformed" in agent.execute_job(envelope, job_id=None)["error"]


def test_rejects_when_no_signing_key_is_pinned(tmp_path):
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant-1",
        "user",
        "device-1",
        "token",
        allowed_services=("demo.service",),
    )
    agent = LinuxAgent(config, tmp_path / "agent.json")
    envelope = build_signed_job_envelope(
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
    )
    assert (
        "no pinned job-signing key" in agent.execute_job(envelope, job_id=None)["error"]
    )


def test_successful_execution_journals_every_transition(tmp_path):
    agent = build_agent(tmp_path, runner=_running)
    envelope = build_signed_job_envelope(
        action_id="action-1",
        device_id="device-1",
        tenant_id="tenant-1",
        parameters={"service": "demo.service"},
    )
    job_id = envelope["job_id"]
    agent.journal.record_claimed(
        job_id=job_id,
        action_id="action-1",
        attempt=1,
        nonce=envelope["nonce"],
        claim_token=envelope["claim_token"],
        idempotency_key="result-action-1-1",
        skill_id="service.restart",
        parameters=envelope["parameters"],
    )
    result = agent.execute_job(envelope, job_id=job_id)
    assert result["success"] is True
    entry = agent.journal._entries[job_id]
    assert entry.state == "executed"
    assert entry.result == result


def test_recovery_after_crash_during_execution_verifies_without_reexecuting(tmp_path):
    """Simulates a crash after mark_executing but before mark_executed: the
    journal only knows the job was claimed/executing, with no result -- on
    restart, recovery must observe current state (verify_only) rather than
    call execute() again.
    """
    agent = build_agent(tmp_path, runner=_running)
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
        parameters={"service": "demo.service"},
    )
    agent.journal.mark_executing("action-1:1")

    agent.recover_interrupted_jobs()

    assert len(reported) == 1
    assert reported[0]["success"] is True
    assert reported[0]["output"]["recovered"] is True
    entry = agent.journal._entries["action-1:1"]
    assert entry.state == "reported"


def test_recovery_after_crash_following_execution_resends_stored_result(tmp_path):
    """Simulates a crash after mark_executed (result already known) but
    before the report reached the control plane: recovery must resend the
    exact stored result, never call execute() or verify_only() again.
    """
    agent = build_agent(tmp_path)

    def _fail_if_called(*_a, **_k):
        raise AssertionError("executor should not be invoked during this recovery path")

    agent.executor = ServiceRestartExecutor(("demo.service",), runner=_fail_if_called)
    reported: list[dict] = []
    agent._report_result = (
        lambda device_id, token, action_id, idem, claim_token, result: reported.append(
            result
        )
    )

    stored_result = {
        "success": True,
        "verified": True,
        "output": {"service": "demo.service"},
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
        parameters={"service": "demo.service"},
    )
    agent.journal.mark_executing("action-1:1")
    agent.journal.mark_executed("action-1:1", stored_result)

    agent.recover_interrupted_jobs()

    assert reported == [stored_result]
    assert agent.journal._entries["action-1:1"].state == "reported"


def test_config_persists_credentials_with_owner_only_permissions(tmp_path):
    path = tmp_path / "nested" / "agent.json"
    config = AgentConfig(
        "http://localhost", "agent", "tenant", "user", "device", "secret"
    )
    config.save(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert AgentConfig.load(path).agent_token == "secret"
