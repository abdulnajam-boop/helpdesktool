"""Real Windows Service Control Manager access via pywin32.

Talks to SCM entirely through the Win32 API (``win32service``) — no shell,
no ``cmd.exe``, no ``sc.exe``, no PowerShell, no subprocess at all. This
module is Windows-only and imports pywin32 at module load time on purpose:
it is only ever imported lazily, from ``windows_agent.agent``, when a real
agent process actually needs to control a service, so that
``windows_agent.executor`` (the pure logic this module implements) stays
importable and testable on any platform.
"""

from __future__ import annotations

import time
from typing import Any

import pywintypes
import win32service
import winerror

from .executor import ServiceControlError, ServiceManager, ServiceState

_STATE_NAMES = {
    win32service.SERVICE_STOPPED: "stopped",
    win32service.SERVICE_START_PENDING: "start_pending",
    win32service.SERVICE_STOP_PENDING: "stop_pending",
    win32service.SERVICE_RUNNING: "running",
    win32service.SERVICE_CONTINUE_PENDING: "continue_pending",
    win32service.SERVICE_PAUSE_PENDING: "pause_pending",
    win32service.SERVICE_PAUSED: "paused",
}

_POLL_INTERVAL_SECONDS = 0.25


class Win32ServiceManager(ServiceManager):
    def __init__(self, machine: str | None = None) -> None:
        self.machine = machine

    def _open_scm(self, access: int) -> Any:
        try:
            return win32service.OpenSCManager(self.machine, None, access)
        except pywintypes.error as exc:
            raise ServiceControlError(str(exc)) from exc

    def _open_service(self, scm: Any, service: str, access: int) -> Any | None:
        try:
            return win32service.OpenService(scm, service, access)
        except pywintypes.error as exc:
            if exc.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
                return None
            raise ServiceControlError(str(exc)) from exc

    def query_state(self, service: str) -> ServiceState:
        scm = self._open_scm(win32service.SC_MANAGER_CONNECT)
        try:
            handle = self._open_service(scm, service, win32service.SERVICE_QUERY_STATUS)
            if handle is None:
                return ServiceState(False, "unknown")
            try:
                return self._state_from_handle(handle)
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)

    def _state_from_handle(self, handle: Any) -> ServiceState:
        try:
            status = win32service.QueryServiceStatus(handle)
        except pywintypes.error as exc:
            raise ServiceControlError(str(exc)) from exc
        current_state = status[1]
        return ServiceState(True, _STATE_NAMES.get(current_state, "unknown"))

    def _wait_for(
        self, handle: Any, target_states: frozenset[int], timeout_seconds: float
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                status = win32service.QueryServiceStatus(handle)
            except pywintypes.error as exc:
                raise ServiceControlError(str(exc)) from exc
            if status[1] in target_states:
                return
            time.sleep(_POLL_INTERVAL_SECONDS)
        raise ServiceControlError(
            f"timed out waiting for service state in {sorted(target_states)}"
        )

    def stop(self, service: str, timeout_seconds: float) -> None:
        scm = self._open_scm(win32service.SC_MANAGER_CONNECT)
        try:
            handle = self._open_service(
                scm,
                service,
                win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_STOP,
            )
            if handle is None:
                raise ServiceControlError("service is not installed")
            try:
                status = win32service.QueryServiceStatus(handle)
                if status[1] != win32service.SERVICE_STOPPED:
                    try:
                        win32service.ControlService(
                            handle, win32service.SERVICE_CONTROL_STOP
                        )
                    except pywintypes.error as exc:
                        raise ServiceControlError(str(exc)) from exc
                self._wait_for(
                    handle, frozenset({win32service.SERVICE_STOPPED}), timeout_seconds
                )
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)

    def start(self, service: str, timeout_seconds: float) -> None:
        scm = self._open_scm(win32service.SC_MANAGER_CONNECT)
        try:
            handle = self._open_service(
                scm,
                service,
                win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START,
            )
            if handle is None:
                raise ServiceControlError("service is not installed")
            try:
                status = win32service.QueryServiceStatus(handle)
                if status[1] != win32service.SERVICE_RUNNING:
                    try:
                        win32service.StartService(handle, None)
                    except pywintypes.error as exc:
                        raise ServiceControlError(str(exc)) from exc
                self._wait_for(
                    handle, frozenset({win32service.SERVICE_RUNNING}), timeout_seconds
                )
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)

    def restart(self, service: str, timeout_seconds: float) -> None:
        half = max(timeout_seconds / 2, 1.0)
        self.stop(service, half)
        self.start(service, half)
