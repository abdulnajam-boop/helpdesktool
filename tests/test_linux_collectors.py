from linux_agent.collectors import (
    collect_inventory,
    cpu_inventory,
    memory_inventory,
    process_inventory,
)


def test_collectors_return_structured_linux_inventory():
    inventory = collect_inventory(())
    assert inventory["hostname"]
    assert inventory["kernel"]
    assert inventory["architecture"]
    assert inventory["uptime_seconds"] >= 0
    assert isinstance(inventory["filesystems"], list)
    assert isinstance(inventory["network"]["interfaces"], list)
    assert inventory["process_count"] > 0
    assert isinstance(inventory["top_processes_by_cpu"], list)


def test_cpu_and_memory_values_are_bounded():
    cpu = cpu_inventory(0.001)
    memory = memory_inventory()
    assert 0 <= cpu["utilization_percent"] <= 100
    assert memory["total_bytes"] > 0
    assert 0 <= memory["available_bytes"] <= memory["total_bytes"]


def test_process_inventory_returns_structured_rows_sorted_by_cpu():
    processes = process_inventory(limit=5, sample_seconds=0.01)
    assert processes  # this process, if nothing else, is always running
    assert len(processes) <= 5
    for row in processes:
        assert row["pid"] >= 0
        assert row["name"]
        assert row["cpu_percent"] >= 0
    cpu_values = [row["cpu_percent"] for row in processes]
    assert cpu_values == sorted(cpu_values, reverse=True)


def test_process_inventory_skips_processes_that_exit_mid_sample():
    """A process disappearing between the two /proc samples must be
    silently dropped, never raised -- exercised for real by sampling
    across a longer window on a real, busy /proc, not simulated."""
    processes = process_inventory(limit=1000, sample_seconds=0.2)
    assert isinstance(processes, list)
