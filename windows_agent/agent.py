from __future__ import annotations

import argparse
import logging
import os
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from agent_common.journal import ExecutionJournal
from agent_common.signing import EnvelopeError, verify_envelope

from .client import ApiError, ControlPlaneClient
from .collectors import collect_inventory
from .config import AgentConfig
from .executor import (
    DnsFlushCacheExecutor,
    DnsFlushResolver,
    ServiceManager,
    ServiceRestartExecutor,
)

LOG = logging.getLogger("helpdesktool-windows-agent")

# The agent's own hardcoded authority over what can execute, independent of
# anything the control plane's skill registry (helpdesktool/skills.py)
# declares — a manifest existing there is necessary but not sufficient; the
# agent must also recognize the exact skill_id/version pair.
SUPPORTED_SKILL_VERSIONS: dict[str, frozenset[int]] = {
    "service.restart": frozenset({1}),
    "dns.flush_cache": frozenset({1}),
}


class _JobExecutor(Protocol):
    def execute(self, parameters: dict[str, Any]) -> dict[str, Any]: ...


def _default_config_path() -> Path:
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    return Path(program_data) / "helpdesktool" / "agent.json"


class WindowsAgent:
    def __init__(
        self,
        config: AgentConfig,
        config_path: Path,
        client: ControlPlaneClient | None = None,
        service_manager: ServiceManager | None = None,
        dns_resolver: DnsFlushResolver | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.client = client or ControlPlaneClient(config.server_url)
        self.journal = ExecutionJournal(config_path.with_suffix(".journal.json"))
        self.last_inventory_at = 0.0
        self.executor = (
            ServiceRestartExecutor(
                config.allowed_services, service_manager or self._default_manager()
            )
            if config.allowed_services
            else None
        )
        # Always available: unlike service.restart, dns.flush_cache targets
        # no caller-chosen resource, so there is nothing to allowlist.
        self.dns_executor: DnsFlushCacheExecutor | None = DnsFlushCacheExecutor(
            dns_resolver or self._default_dns_resolver()
        )

    @staticmethod
    def _default_manager() -> ServiceManager:
        # Imported lazily so this module (and constructing a WindowsAgent
        # with an explicitly injected service_manager, as tests do) stays
        # usable without pywin32 installed — only building a *real*,
        # unconfigured-injection executor requires it.
        from .win32_service_manager import Win32ServiceManager

        return Win32ServiceManager()

    @staticmethod
    def _default_dns_resolver() -> DnsFlushResolver:
        # Imported lazily for the same reason as _default_manager() above —
        # Win32DnsResolver only needs ctypes.WinDLL, which doesn't exist on
        # non-Windows platforms, so the import must not happen at module
        # level or on a test-injected WindowsAgent.
        from .win32_dns_resolver import Win32DnsResolver

        return Win32DnsResolver()

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
        if result.get("signing_public_key_pem"):
            self.config.signing_public_key_pem = result["signing_public_key_pem"]
            self.config.signing_key_version = result.get("signing_key_version")
        self.config.save(self.config_path)
        LOG.info("enrolled device %s", self.config.device_id)

    def enroll_with_token(self, token: str) -> None:
        """Self-enrollment with a one-time, admin-issued token
        (``POST /v1/devices/enrollment-tokens``) instead of an authenticated
        admin session — unlike ``enroll``, this doesn't require ``tenant_id``
        to already be known: the response supplies it, since the token
        itself already identifies which tenant this device belongs to. Lets
        an installer bootstrap a fresh config from nothing but a server URL
        and a token — see ``deploy/install-windows-agent.ps1``.
        """
        if self.config.device_id and self.config.agent_token:
            return
        result = self.client.enroll_with_token(
            token, self.config.external_id, socket.gethostname()
        )
        self.config.device_id = result["device_id"]
        self.config.agent_token = result["agent_token"]
        self.config.tenant_id = result["tenant_id"]
        if result.get("signing_public_key_pem"):
            self.config.signing_public_key_pem = result["signing_public_key_pem"]
            self.config.signing_key_version = result.get("signing_key_version")
        self.config.save(self.config_path)
        LOG.info("enrolled device %s via enrollment token", self.config.device_id)

    def ensure_signing_key(self) -> None:
        """Trust-on-first-use pinning for agents enrolled before signed job
        envelopes existed, or whose config lost the key some other way. Once
        pinned, the key is never silently replaced — a control-plane key
        change makes every future envelope fail verification (fail closed)
        until an operator clears ``signing_public_key_pem`` locally to
        deliberately re-pin, rather than the agent trusting a new key
        automatically.
        """
        if self.config.signing_public_key_pem:
            return
        device_id, token = self._identity()
        response = self.client.request(
            "GET",
            f"/v1/devices/{device_id}/signing-key",
            headers=self.client.agent_headers(token),
        )
        self.config.signing_public_key_pem = response["public_key_pem"]
        self.config.signing_key_version = response.get("key_version")
        self.config.save(self.config_path)
        LOG.info(
            "pinned job-signing key version %s for device %s",
            self.config.signing_key_version,
            device_id,
        )

    def run_once(self) -> None:
        self.enroll()
        self.ensure_signing_key()
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
        self.recover_interrupted_jobs()
        device_id, token = self._identity()
        jobs = self.client.request(
            "GET",
            f"/v1/devices/{device_id}/jobs",
            headers=self.client.agent_headers(token),
        )
        for summary in jobs:
            action_id = summary.get("id")
            if not isinstance(action_id, str):
                continue
            envelope = self.client.request(
                "POST",
                f"/v1/devices/{device_id}/jobs/{action_id}/claim",
                payload={},
                headers=self.client.agent_headers(token, f"claim-{action_id}"),
            )
            job_id = envelope.get("job_id")
            if isinstance(job_id, str) and self.journal.seen(job_id):
                continue
            self._handle_claimed_job(device_id, token, action_id, envelope, job_id)

    def _handle_claimed_job(
        self,
        device_id: str,
        token: str,
        action_id: str,
        envelope: dict[str, Any],
        job_id: Any,
    ) -> None:
        attempt = envelope.get("attempt")
        result_idem = f"result-{action_id}-{attempt}"
        if isinstance(job_id, str):
            parameters = envelope.get("parameters")
            self.journal.record_claimed(
                job_id=job_id,
                action_id=action_id,
                attempt=int(attempt) if isinstance(attempt, int) else 0,
                nonce=str(envelope.get("nonce", "")),
                claim_token=str(envelope.get("claim_token", "")),
                idempotency_key=result_idem,
                skill_id=str(envelope.get("skill_id", "")),
                parameters=parameters if isinstance(parameters, dict) else {},
            )
        result = self.execute_job(
            envelope, job_id=job_id if isinstance(job_id, str) else None
        )
        self._report_result(
            device_id,
            token,
            action_id,
            result_idem,
            str(envelope.get("claim_token", "")),
            result,
        )
        if isinstance(job_id, str):
            self.journal.mark_reported(job_id)
        self.journal.prune_reported()

    def _report_result(
        self,
        device_id: str,
        token: str,
        action_id: str,
        idempotency_key: str,
        claim_token: str,
        result: dict[str, Any],
    ) -> None:
        self.client.request(
            "POST",
            f"/v1/devices/{device_id}/jobs/{action_id}/result",
            payload=result,
            headers={
                **self.client.agent_headers(token, idempotency_key),
                "X-Claim-Token": claim_token,
            },
        )

    def recover_interrupted_jobs(self) -> None:
        """Reconciles the local journal against reality after a crash,
        service restart, or host reboot — see ``agent_common.journal``'s
        module docstring for exactly what each state means and why. Runs at
        the start of every cycle, not just at startup, so a crash mid-cycle
        is recovered on the very next tick rather than waiting for a process
        restart.
        """
        pending = self.journal.pending()
        if not pending:
            return
        device_id, token = self._identity()
        for entry in pending:
            if entry.state == "executed" and entry.result is not None:
                result = entry.result
            else:
                result = self._verify_only_result(entry.skill_id, entry.parameters)
            try:
                self._report_result(
                    device_id,
                    token,
                    entry.action_id,
                    entry.idempotency_key,
                    entry.claim_token,
                    result,
                )
            except ApiError as exc:
                LOG.error("failed to report recovered job %s: %s", entry.job_id, exc)
                continue
            self.journal.mark_reported(entry.job_id)
        self.journal.prune_reported()

    def _verify_only_result(
        self, skill_id: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        if skill_id != "service.restart" or self.executor is None:
            return self._invalid(
                "interrupted before completion; unable to safely verify outcome"
            )
        service = parameters.get("service")
        if not isinstance(service, str):
            return self._invalid(
                "interrupted before completion; unable to safely verify outcome"
            )
        return self.executor.verify_only(service)

    def execute_job(
        self, envelope: dict[str, Any], *, job_id: str | None
    ) -> dict[str, Any]:
        device_id, _ = self._identity()
        public_key = self.config.signing_public_key_pem
        if not public_key:
            return self._invalid("no pinned job-signing key available")
        try:
            verify_envelope(
                envelope,
                public_key_pem=public_key,
                expected_device_id=device_id,
                expected_tenant_id=self.config.tenant_id,
                supported_skill_versions=SUPPORTED_SKILL_VERSIONS,
            )
        except EnvelopeError as exc:
            return self._invalid(str(exc))
        skill_id = str(envelope.get("skill_id", ""))
        executor = self._executor_for(skill_id)
        if executor is None:
            return self._invalid(
                "no executor available for this skill (allowlist empty or unknown skill)"
            )
        parameters = envelope.get("parameters")
        if not isinstance(parameters, dict):
            return self._invalid("invalid parameters")
        if job_id:
            self.journal.mark_executing(job_id)
        try:
            result = executor.execute(parameters)
        except (PermissionError, ValueError) as exc:
            result = self._invalid(str(exc))
        if job_id:
            self.journal.mark_executed(job_id, result)
        return result

    def _executor_for(self, skill_id: str) -> _JobExecutor | None:
        if skill_id == "service.restart":
            return self.executor
        if skill_id == "dns.flush_cache":
            return self.dns_executor
        return None

    def _identity(self) -> tuple[str, str]:
        if not self.config.device_id or not self.config.agent_token:
            raise RuntimeError("agent is not enrolled")
        return self.config.device_id, self.config.agent_token

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
    parser = argparse.ArgumentParser(description="Helpdesktool Windows endpoint agent")
    parser.add_argument("--config", type=Path, default=_default_config_path())
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--server-url",
        default=None,
        help="Control plane URL; only needed to bootstrap a config that doesn't exist yet",
    )
    parser.add_argument(
        "--enrollment-token",
        default=None,
        help=(
            "One-time admin-issued token (POST /v1/devices/enrollment-tokens) for "
            "self-enrollment -- no tenant_id/user_id need to be known upfront"
        ),
    )
    parser.add_argument(
        "--external-id", default=None, help="Defaults to this host's hostname"
    )
    parser.add_argument(
        "--allowed-services",
        default=None,
        help="Comma-separated Windows service names this agent may restart",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    if args.config.exists():
        config = AgentConfig.load(args.config)
    else:
        if not args.server_url or not args.enrollment_token:
            raise SystemExit(
                f"{args.config} does not exist yet; provide --server-url and "
                "--enrollment-token to bootstrap it (first-run self-enrollment)"
            )
        services = (
            tuple(args.allowed_services.split(",")) if args.allowed_services else ()
        )
        config = AgentConfig(
            server_url=args.server_url,
            external_id=args.external_id or socket.gethostname(),
            tenant_id="",
            user_id="",
            allowed_services=services,
            monitored_services=services,
        )
    agent = WindowsAgent(config, args.config)
    if args.enrollment_token and not (config.device_id and config.agent_token):
        agent.enroll_with_token(args.enrollment_token)
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
