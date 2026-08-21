"""Windows inventory collectors.

Deliberately mirrors ``linux_agent.collectors.collect_inventory``'s payload
shape — the same ``filesystems[].{mountpoint,total_bytes,free_bytes}`` keys
in particular — so ``helpdesktool.incidents.detect_inventory_incidents``
(e.g. low-disk detection) works identically regardless of which OS an
endpoint reports from; the control plane never needs to know or care.

Uses ``psutil`` (cross-platform, genuinely installable and importable
everywhere) for CPU/memory/disk/network/process data, and the stdlib
``winreg`` module (Windows-only, imported lazily inside the functions that
need it, never at module level) for registry-only reads: DNS servers,
installed applications, and pending-reboot state. Nothing here spawns a
shell, ``ipconfig``, ``wmic``, or PowerShell.
"""

from __future__ import annotations

import platform
import socket
import time
from typing import Any

import psutil


def cpu_inventory(sample_seconds: float = 0.1) -> dict[str, Any]:
    utilization = psutil.cpu_percent(interval=sample_seconds)
    return {
        "logical_cpus": psutil.cpu_count(logical=True) or 0,
        "model": platform.processor() or "unknown",
        "utilization_percent": round(max(0.0, min(100.0, utilization)), 2),
    }


def memory_inventory() -> dict[str, int]:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "swap_total_bytes": swap.total,
        "swap_free_bytes": swap.free,
    }


def filesystem_inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        if not part.fstype or "cdrom" in part.opts:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        rows.append(
            {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "filesystem": part.fstype,
                "total_bytes": usage.total,
                "free_bytes": usage.free,
            }
        )
    return rows


def _dns_servers_from_registry() -> list[str]:
    import winreg

    servers: list[str] = []
    interfaces_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, interfaces_path
        ) as interfaces_key:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(interfaces_key, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(interfaces_key, subkey_name) as subkey:
                        for value_name in ("NameServer", "DhcpNameServer"):
                            try:
                                value, _ = winreg.QueryValueEx(subkey, value_name)
                            except FileNotFoundError:
                                continue
                            for server in str(value).replace(",", " ").split():
                                if server and server not in servers:
                                    servers.append(server)
                except OSError:
                    continue
    except OSError:
        return []
    return servers


def network_inventory() -> dict[str, Any]:
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        addresses = [
            addr.address
            for addr in addrs
            if addr.family in (socket.AF_INET, socket.AF_INET6)
        ]
        interfaces.append({"name": name, "addresses": addresses})
    return {"interfaces": interfaces, "dns_servers": _dns_servers_from_registry()}


def service_inventory(services: tuple[str, ...]) -> list[dict[str, Any]]:
    from .executor import ServiceState
    from .win32_service_manager import Win32ServiceManager

    manager = Win32ServiceManager()
    results = []
    for service in services:
        try:
            state = manager.query_state(service)
        except Exception:
            state = ServiceState(False, "unknown")
        results.append(
            {"service": service, "exists": state.exists, "state": state.state}
        )
    return results


def installed_applications() -> list[dict[str, str]]:
    import winreg

    apps: list[dict[str, str]] = []
    uninstall_paths = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    for path in uninstall_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as uninstall_key:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(uninstall_key, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(uninstall_key, subkey_name) as subkey:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            try:
                                version, _ = winreg.QueryValueEx(
                                    subkey, "DisplayVersion"
                                )
                            except FileNotFoundError:
                                version = ""
                            apps.append({"name": str(name), "version": str(version)})
                    except (OSError, FileNotFoundError):
                        continue
        except OSError:
            continue
    return apps


def pending_reboot() -> bool:
    import winreg

    key_only_checks = (
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ),
    )
    for hive, path in key_only_checks:
        try:
            with winreg.OpenKey(hive, path):
                return True
        except OSError:
            continue
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
        ) as key:
            winreg.QueryValueEx(key, "PendingFileRenameOperations")
            return True
    except (OSError, FileNotFoundError):
        return False


def _sampled_processes(sample_seconds: float = 0.1) -> list[dict[str, Any]]:
    """One CPU+memory sample of every running process. ``Process.
    cpu_percent()`` needs priming -- its first call always returns a
    meaningless value (either 0.0 or a since-process-start average,
    depending on psutil version) -- so every process is primed once,
    then re-read after ``sample_seconds`` for a real interval-based
    figure, mirroring ``cpu_inventory``'s own sampling window. Read-only,
    no shell, no mutation: this exists purely to give the
    ``high_cpu_usage`` reference issue's ``collect_evidence`` step
    (``helpdesktool/knowledge.py``, migration ``0013``) the
    ``top_processes_by_...`` evidence it already describes wanting.
    """
    tracked: list[psutil.Process] = []
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
            tracked.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(sample_seconds)
    processes: list[dict[str, Any]] = []
    for proc in tracked:
        try:
            processes.append(
                {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "memory_percent": round(proc.memory_percent() or 0.0, 2),
                    "cpu_percent": round(proc.cpu_percent(None), 2),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def process_inventory(limit: int = 25) -> list[dict[str, Any]]:
    processes = _sampled_processes()
    processes.sort(key=lambda row: row["memory_percent"], reverse=True)
    return processes[:limit]


def collect_inventory(monitored_services: tuple[str, ...] = ()) -> dict[str, Any]:
    release, version, _, _ = platform.win32_ver()
    # One shared CPU+memory process sample feeds both rankings below --
    # sampling twice would double the (small but real) time this blocks
    # the heartbeat cycle for no benefit.
    sampled = _sampled_processes()
    return {
        "hostname": socket.gethostname(),
        "distribution": f"Windows {release}".strip(),
        "distribution_version": version or "unknown",
        "kernel": platform.version(),
        "architecture": platform.machine(),
        "cpu": cpu_inventory(),
        "memory": memory_inventory(),
        "filesystems": filesystem_inventory(),
        "uptime_seconds": max(0.0, time.time() - psutil.boot_time()),
        "network": network_inventory(),
        "services": service_inventory(monitored_services),
        "installed_applications": installed_applications(),
        "pending_reboot": pending_reboot(),
        "process_count": len(psutil.pids()),
        "top_processes_by_memory": sorted(
            sampled, key=lambda row: row["memory_percent"], reverse=True
        )[:25],
        "top_processes_by_cpu": sorted(
            sampled, key=lambda row: row["cpu_percent"], reverse=True
        )[:25],
    }
