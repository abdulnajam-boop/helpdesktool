import subprocess

import pytest

from linux_agent.executor import ServiceRestartExecutor


def completed(command, returncode=0, output=""):
    return subprocess.CompletedProcess(command, returncode, output, "")


class SequenceRunner:
    def __init__(self, results):
        self.results = iter(results)
        self.commands = []

    def __call__(self, command, *, timeout):
        self.commands.append(command)
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


ACTIVE = "LoadState=loaded\nActiveState=active\nSubState=running\n"
FAILED = "LoadState=loaded\nActiveState=failed\nSubState=failed\n"


def test_successful_allowlisted_restart_and_verification():
    runner = SequenceRunner(
        [completed([], output=ACTIVE), completed([]), completed([], output=ACTIVE)]
    )
    result = ServiceRestartExecutor(("demo.service",), runner=runner).execute(
        {"service": "demo.service"}
    )
    assert result["success"] is True
    assert result["verified"] is True
    assert runner.commands[1] == ["systemctl", "restart", "demo.service"]


def test_non_allowlisted_and_malicious_parameters_are_rejected_without_commands():
    runner = SequenceRunner([])
    executor = ServiceRestartExecutor(("demo.service",), runner=runner)
    with pytest.raises(PermissionError):
        executor.execute({"service": "ssh.service"})
    with pytest.raises(ValueError):
        executor.execute({"service": "demo.service", "command": "rm -rf /"})
    assert runner.commands == []


def test_failed_restart_attempts_rollback_and_escalates_on_restore_failure():
    runner = SequenceRunner(
        [
            completed([], output=ACTIVE),
            completed([], 1),
            completed([], 1),
            completed([], output=FAILED),
        ]
    )
    result = ServiceRestartExecutor(("demo.service",), runner=runner).execute(
        {"service": "demo.service"}
    )
    assert result["success"] is False
    assert result["rollback_attempted"] is True
    assert result["rollback_succeeded"] is False


def test_verification_failure_rolls_back_to_prior_state():
    runner = SequenceRunner(
        [
            completed([], output=ACTIVE),
            completed([]),
            completed([], output=FAILED),
            completed([]),
            completed([], output=ACTIVE),
        ]
    )
    result = ServiceRestartExecutor(("demo.service",), runner=runner).execute(
        {"service": "demo.service"}
    )
    assert result["error"] == "post-restart verification failed"
    assert result["rollback_succeeded"] is True


def test_timeout_triggers_rollback():
    timeout = subprocess.TimeoutExpired(["systemctl"], 1)
    runner = SequenceRunner(
        [
            completed([], output=ACTIVE),
            timeout,
            completed([]),
            completed([], output=ACTIVE),
        ]
    )
    result = ServiceRestartExecutor(
        ("demo.service",), runner=runner, timeout_seconds=1
    ).execute({"service": "demo.service"})
    assert result["error"] == "restart timed out"
    assert result["rollback_succeeded"] is True
