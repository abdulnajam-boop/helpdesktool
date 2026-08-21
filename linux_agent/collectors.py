from __future__ import annotations

import os
import platform
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any


def _read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(errors="replace").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    return values


def _cpu_sample() -> tuple[int, int]:
    fields = [
        int(item) for item in Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    ]
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields), idle


def cpu_inventory(sample_seconds: float = 0.1) -> dict[str, Any]:
    info = _read_key_values(Path("/proc/cpuinfo"))
    first_total, first_idle = _cpu_sample()
    time.sleep(sample_seconds)
    second_total, second_idle = _cpu_sample()
    total_delta = max(second_total - first_total, 1)
    utilization = 100.0 * (1 - (second_idle - first_idle) / total_delta)
    return {
        "logical_cpus": os.cpu_count(),
        "model": info.get("model name", "unknown"),
        "utilization_percent": round(max(0.0, min(100.0, utilization)), 2),
    }


def memory_inventory() -> dict[str, int]:
    values = _read_key_values(Path("/proc/meminfo"))

    def convert(key: str) -> int:
        return int(values.get(key, "0 kB").split()[0]) * 1024

    return {
        "total_bytes": convert("MemTotal"),
        "available_bytes": convert("MemAvailable"),
        "swap_total_bytes": convert("SwapTotal"),
        "swap_free_bytes": convert("SwapFree"),
    }


def filesystem_inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in Path("/proc/mounts").read_text(errors="replace").splitlines():
        device, mountpoint, fs_type, *_ = line.split()
        if mountpoint in seen or fs_type in {
            "proc",
            "sysfs",
            "devpts",
            "cgroup",
            "cgroup2",
        }:
            continue
        seen.add(mountpoint)
        try:
            stat = os.statvfs(mountpoint)
        except OSError:
            continue
        rows.append(
            {
                "device": device,
                "mountpoint": mountpoint,
                "filesystem": fs_type,
                "total_bytes": stat.f_blocks * stat.f_frsize,
                "free_bytes": stat.f_bavail * stat.f_frsize,
            }
        )
    return rows


def network_inventory() -> dict[str, Any]:
    interfaces = []
    ipv6: dict[str, list[str]] = {}
    inet6 = Path("/proc/net/if_inet6")
    if inet6.exists():
        for line in inet6.read_text().splitlines():
            address, _, _, _, _, name = line.split()
            rendered = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(address))
            ipv6.setdefault(name, []).append(rendered)
    for _, name in socket.if_nameindex():
        addresses = list(ipv6.get(name, []))
        try:
            import fcntl

            packed = fcntl.ioctl(
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).fileno(),
                0x8915,
                struct.pack("256s", name[:15].encode()),
            )
            addresses.append(socket.inet_ntoa(packed[20:24]))
        except OSError:
            pass
        interfaces.append({"name": name, "addresses": addresses})
    dns = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        dns = [
            line.split()[1]
            for line in resolv.read_text(errors="replace").splitlines()
            if line.strip().startswith("nameserver ")
        ]
    return {"interfaces": interfaces, "dns_servers": dns}


def _process_cpu_ticks(pid: int) -> int | None:
    """Returns a process's cumulative (utime + stime) in clock ticks --
    fields 14/15 of ``/proc/<pid>/stat`` (see ``proc(5)``) -- or ``None``
    if the process has already exited. ``comm`` (field 2) is parenthesized
    and may itself contain spaces or parens, so every remaining field is
    read relative to the *last* ``)`` rather than by a fixed split index.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (OSError, FileNotFoundError):
        return None
    after_comm = raw.rsplit(")", 1)[-1].split()
    try:
        utime = int(after_comm[11])
        stime = int(after_comm[12])
    except (IndexError, ValueError):
        return None
    return utime + stime


def _process_name(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip() or "unknown"
    except (OSError, FileNotFoundError):
        return "unknown"


def process_inventory(
    limit: int = 25, sample_seconds: float = 0.1
) -> list[dict[str, Any]]:
    """Top processes by CPU usage over a short sampling window -- the
    same two-sample-delta technique ``cpu_inventory`` already uses for the
    aggregate figure, applied per process. Read-only, no shell, no
    mutation: this exists purely to give the ``high_cpu_usage`` reference
    issue's ``collect_evidence`` step (``helpdesktool/knowledge.py``,
    migration ``0013``) the ``top_processes_by_...`` evidence it already
    describes wanting but that no collector produced until this pass.
    Processes that exit mid-sample are silently skipped, never raised.
    """
    try:
        pids = [entry.name for entry in Path("/proc").iterdir() if entry.name.isdigit()]
    except OSError:
        return []
    first_samples = {pid: _process_cpu_ticks(int(pid)) for pid in pids}
    time.sleep(sample_seconds)
    clock_ticks = os.sysconf("SC_CLK_TCK")
    cpu_count = max(os.cpu_count() or 1, 1)
    processes: list[dict[str, Any]] = []
    for pid in pids:
        first = first_samples.get(pid)
        second = _process_cpu_ticks(int(pid))
        if first is None or second is None:
            continue
        delta_ticks = max(second - first, 0)
        cpu_percent = 100.0 * (delta_ticks / clock_ticks) / sample_seconds
        processes.append(
            {
                "pid": int(pid),
                "name": _process_name(int(pid)),
                "cpu_percent": round(max(0.0, min(cpu_percent, 100.0 * cpu_count)), 2),
            }
        )
    processes.sort(key=lambda row: row["cpu_percent"], reverse=True)
    return processes[:limit]


def service_inventory(
    services: tuple[str, ...], timeout: float = 3.0
) -> list[dict[str, str]]:
    results = []
    for service in services:
        try:
            completed = subprocess.run(
                [
                    "systemctl",
                    "show",
                    service,
                    "--property=LoadState,ActiveState,SubState",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            states = dict(
                line.split("=", 1)
                for line in completed.stdout.splitlines()
                if "=" in line
            )
            results.append(
                {
                    "service": service,
                    "load": states.get("LoadState", "unknown"),
                    "active": states.get("ActiveState", "unknown"),
                    "sub": states.get("SubState", "unknown"),
                }
            )
        except (OSError, subprocess.TimeoutExpired):
            results.append(
                {
                    "service": service,
                    "load": "unknown",
                    "active": "unknown",
                    "sub": "unknown",
                }
            )
    return results


def collect_inventory(monitored_services: tuple[str, ...] = ()) -> dict[str, Any]:
    os_release = {}
    path = Path("/etc/os-release")
    if path.exists():
        os_release = {
            key: value.strip('"')
            for key, value in (
                line.split("=", 1)
                for line in path.read_text().splitlines()
                if "=" in line
            )
        }
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    return {
        "hostname": socket.gethostname(),
        "distribution": os_release.get("NAME", "Linux"),
        "distribution_version": os_release.get("VERSION_ID", "unknown"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": cpu_inventory(),
        "memory": memory_inventory(),
        "filesystems": filesystem_inventory(),
        "uptime_seconds": uptime,
        "network": network_inventory(),
        "services": service_inventory(monitored_services),
        "process_count": sum(1 for p in Path("/proc").iterdir() if p.name.isdigit()),
        "top_processes_by_cpu": process_inventory(),
    }
