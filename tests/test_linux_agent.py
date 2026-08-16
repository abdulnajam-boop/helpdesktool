from datetime import UTC, datetime, timedelta
from pathlib import Path

from linux_agent.agent import LinuxAgent
from linux_agent.config import AgentConfig


def build_agent(tmp_path: Path) -> LinuxAgent:
    config = AgentConfig(
        "http://localhost",
        "agent-1",
        "tenant",
        "user",
        "device-1",
        "token",
        allowed_services=("demo.service",),
    )
    return LinuxAgent(config, tmp_path / "agent.json")


def test_rejects_misaddressed_unknown_and_expired_jobs(tmp_path):
    agent = build_agent(tmp_path)
    base = {
        "id": "action",
        "skill_id": "service.restart",
        "parameters": {"service": "demo.service"},
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


def test_config_persists_credentials_with_owner_only_permissions(tmp_path):
    path = tmp_path / "nested" / "agent.json"
    config = AgentConfig(
        "http://localhost", "agent", "tenant", "user", "device", "secret"
    )
    config.save(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert AgentConfig.load(path).agent_token == "secret"
