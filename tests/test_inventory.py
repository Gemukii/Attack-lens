"""Tests for local runtime inventory collection."""

from attacklens.inventory import collect_inventory


def test_collect_inventory_returns_safe_machine_metadata() -> None:
    """Inventory should expose stable sections without process arguments."""
    inventory = collect_inventory("test")

    assert inventory["scope"] == "test"
    assert inventory["hostname"]
    assert inventory["os"]["system"]
    assert "logical_count" in inventory["cpu"]
    assert "percent_used" in inventory["memory"]
    assert isinstance(inventory["disks"], list)
    assert isinstance(inventory["network_addresses"], list)
    assert isinstance(inventory["processes"], list)
    assert isinstance(inventory["packages"], list)
    assert all(package["name"] and package["version"] for package in inventory["packages"])
    assert all("cmdline" not in process for process in inventory["processes"])
