"""Tests for windows_agent.collectors' psutil-backed functions --
cpu_inventory/memory_inventory/process_inventory never touch winreg (that
only happens lazily inside DNS-server/installed-application/pending-
reboot collection), so these run for real on Linux CI too, exactly like
production code exercising these same functions does; only
collect_inventory itself needs a real Windows host.

No test_windows_collectors.py existed before this pass -- these
functions had no dedicated test coverage at all.
"""

from __future__ import annotations

from windows_agent.collectors import cpu_inventory, memory_inventory, process_inventory


def test_cpu_and_memory_values_are_bounded():
    cpu = cpu_inventory(0.01)
    memory = memory_inventory()
    assert 0 <= cpu["utilization_percent"] <= 100
    assert cpu["logical_cpus"] > 0
    assert memory["total_bytes"] > 0
    assert 0 <= memory["available_bytes"] <= memory["total_bytes"]


def test_process_inventory_returns_structured_rows_sorted_by_memory():
    processes = process_inventory(limit=5)
    assert processes  # this process, if nothing else, is always running
    assert len(processes) <= 5
    for row in processes:
        assert row["pid"] >= 0
        assert row["name"]
        assert row["memory_percent"] >= 0
        assert row["cpu_percent"] >= 0
    memory_values = [row["memory_percent"] for row in processes]
    assert memory_values == sorted(memory_values, reverse=True)
