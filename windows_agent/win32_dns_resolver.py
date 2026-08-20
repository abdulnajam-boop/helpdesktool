"""Real ``DnsFlushResolver`` backed by the Win32 ``DnsFlushResolverCache`` API.

Calls ``dnsapi.dll``'s ``DnsFlushResolverCache`` directly via ``ctypes`` --
no shell, no ``ipconfig`` subprocess, no PowerShell. This is a *stronger*
guarantee against arbitrary command execution than even a fixed argument
vector (see ``executor.ServiceRestartExecutor``'s docstring for that same
reasoning applied to service control): no process is spawned at all, only a
single documented, parameterless Win32 API call.

``ctypes`` itself is stdlib and safe to import on any platform, but
``ctypes.WinDLL`` only exists on Windows -- constructing this module's
``Win32DnsResolver`` and calling ``.flush()`` requires Windows, exactly like
``win32_service_manager.Win32ServiceManager`` requires pywin32. Unlike most
of this codebase's other Windows-only pieces, this one *was* exercised
against a real Windows host directly (this development pass ran on a real
Windows machine): ``Win32DnsResolver().flush()`` was called live and
returned ``True``, and ``executor.DnsFlushCacheExecutor(Win32DnsResolver())
.execute({})`` returned a genuine ``success: True`` result -- not merely
reasoned about or mocked. The unit-test suite still exercises the decision
logic (parameter validation, failure reporting) indirectly via
``executor.DnsFlushCacheExecutor``'s ``DnsFlushResolver`` Protocol with a
fake, exactly like ``win32_service_manager.py`` is covered only through the
``ServiceManager`` Protocol, since CI itself still runs on Linux.
"""

from __future__ import annotations

import ctypes

from .executor import ServiceControlError


class Win32DnsResolver:
    def flush(self) -> bool:
        try:
            dnsapi = ctypes.WinDLL("dnsapi")  # type: ignore[attr-defined]
        except (AttributeError, OSError) as exc:
            raise ServiceControlError(f"dnsapi.dll unavailable: {exc}") from exc
        dnsapi.DnsFlushResolverCache.restype = ctypes.c_int
        try:
            result = dnsapi.DnsFlushResolverCache()
        except OSError as exc:
            raise ServiceControlError(
                f"DnsFlushResolverCache call failed: {exc}"
            ) from exc
        return bool(result)
