"""Local host inventory collection for AttackLens."""

import getpass
from importlib.metadata import distributions
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def _network_addresses() -> list[dict[str, str]]:
    """Return non-empty addresses known by the local runtime."""
    addresses: list[dict[str, str]] = []
    for interface, entries in psutil.net_if_addrs().items():
        for entry in entries:
            if entry.address:
                addresses.append(
                    {
                        "interface": interface,
                        "family": str(entry.family),
                        "address": entry.address,
                    }
                )
    return addresses


def _disks() -> list[dict[str, Any]]:
    """Return mounted filesystem usage without reading user files."""
    disks: list[dict[str, Any]] = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except OSError:
            continue
        disks.append(
            {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "filesystem": partition.fstype,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent_used": usage.percent,
            }
        )
    return disks


def _processes() -> list[dict[str, Any]]:
    """Return a bounded process inventory with no command-line arguments."""
    processes: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "name", "username", "status"]):
        try:
            data = process.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        processes.append(
            {
                "pid": data.get("pid"),
                "name": data.get("name") or "unknown",
                "username": data.get("username"),
                "status": data.get("status"),
            }
        )
    return sorted(processes, key=lambda item: (item["name"], item["pid"] or 0))[:200]


def _packages() -> list[dict[str, str]]:
    """Return installed Python distributions visible to the API runtime."""
    packages: list[dict[str, str]] = []
    for distribution in distributions():
        name = distribution.metadata.get("Name")
        version = distribution.version
        if name and version:
            packages.append({"name": name, "version": version})
    return sorted(packages, key=lambda item: item["name"].lower())


def collect_inventory(scope: str = "runtime") -> dict[str, Any]:
    """Collect safe system metadata from the process runtime."""
    memory = psutil.virtual_memory()
    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "hostname": socket.gethostname(),
        "current_user": getpass.getuser(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "cpu": {
            "logical_count": psutil.cpu_count(logical=True),
            "physical_count": psutil.cpu_count(logical=False),
            "percent_used": psutil.cpu_percent(interval=0.1),
        },
        "memory": {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "percent_used": memory.percent,
        },
        "disks": _disks(),
        "network_addresses": _network_addresses(),
        "processes": _processes(),
        "packages": _packages(),
        "python_path": str(Path(os.getcwd())),
    }
