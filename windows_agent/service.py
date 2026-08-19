"""Windows Service wrapper for the endpoint agent.

Registers ``helpdesk-windows-agent`` as a real Windows Service via pywin32's
``win32serviceutil.ServiceFramework`` — the SCM-integrated equivalent of the
Linux agent's systemd unit (``deploy/helpdesk-linux-agent.service``): starts
on boot, restarts on failure (configure via ``sc failure``, see
``deploy/README-windows-agent.md``), and stops cleanly on an SCM stop
request rather than being killed. This module is Windows-only by nature
(``win32serviceutil.ServiceFramework`` cannot be subclassed without
pywin32) and is never imported by anything except the
``helpdesk-windows-agent-service`` entry point, so it does not affect
``windows_agent``'s cross-platform testability elsewhere.

Install (elevated PowerShell/cmd):
    helpdesk-windows-agent-service --startup auto install
    helpdesk-windows-agent-service start

Uninstall:
    helpdesk-windows-agent-service stop
    helpdesk-windows-agent-service remove
"""

from __future__ import annotations

import logging
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

from .agent import WindowsAgent, _default_config_path
from .client import ApiError
from .config import AgentConfig

LOG = logging.getLogger("helpdesktool-windows-agent-service")


class HelpdeskAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "HelpdeskWindowsAgent"
    _svc_display_name_ = "Helpdesktool Endpoint Agent"
    _svc_description_ = (
        "Reports device telemetry and executes approved, allowlisted "
        "remediation jobs from the Helpdesktool control plane."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._worker: threading.Thread | None = None
        self._stopping = threading.Event()

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stopping.set()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
        )
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        self._worker.join(timeout=30)

    def _run(self) -> None:
        config_path = _default_config_path()
        config = AgentConfig.load(config_path)
        agent = WindowsAgent(config, config_path)
        while not self._stopping.is_set():
            try:
                agent.run_once()
            except (ApiError, OSError) as exc:
                LOG.error("agent cycle failed: %s", exc)
            self._stopping.wait(config.heartbeat_seconds)


def main() -> None:
    win32serviceutil.HandleCommandLine(HelpdeskAgentService)


if __name__ == "__main__":
    main()
