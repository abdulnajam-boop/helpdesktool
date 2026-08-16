from linux_agent.collectors import collect_inventory, cpu_inventory, memory_inventory


def test_collectors_return_structured_linux_inventory():
    inventory = collect_inventory(())
    assert inventory["hostname"]
    assert inventory["kernel"]
    assert inventory["architecture"]
    assert inventory["uptime_seconds"] >= 0
    assert isinstance(inventory["filesystems"], list)
    assert isinstance(inventory["network"]["interfaces"], list)


def test_cpu_and_memory_values_are_bounded():
    cpu = cpu_inventory(0.001)
    memory = memory_inventory()
    assert 0 <= cpu["utilization_percent"] <= 100
    assert memory["total_bytes"] > 0
    assert 0 <= memory["available_bytes"] <= memory["total_bytes"]
