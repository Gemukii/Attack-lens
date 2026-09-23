"""Safe baseline security posture checks for the AttackLens runtime."""

import os
from pathlib import Path
from typing import Any


def _is_root() -> bool | None:
    """Return whether the current process is root on POSIX systems."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else None


def collect_posture(scope: str = "runtime") -> dict[str, Any]:
    """Collect configuration signals without changing the host state."""
    checks: list[dict[str, Any]] = []

    running_as_root = _is_root()
    checks.append(
        {
            "id": "runtime-root",
            "title": "API runtime privileges",
            "status": "fail" if running_as_root else "pass" if running_as_root is False else "unknown",
            "severity": "high" if running_as_root else "info",
            "description": (
                "The API process runs with root privileges."
                if running_as_root
                else "The API process does not run as root."
                if running_as_root is False
                else "Privilege level is not available on this platform."
            ),
            "remediation": "Run the API with a dedicated unprivileged user.",
        }
    )

    docker_socket = Path("/var/run/docker.sock").exists()
    checks.append(
        {
            "id": "docker-socket",
            "title": "Docker socket exposure",
            "status": "fail" if docker_socket else "pass",
            "severity": "critical" if docker_socket else "info",
            "description": (
                "The Docker socket is accessible to the API runtime."
                if docker_socket
                else "The Docker socket is not accessible to the API runtime."
            ),
            "remediation": "Do not mount the Docker socket unless it is strictly required.",
        }
    )

    secret_names = sorted(
        name
        for name in os.environ
        if any(token in name.upper() for token in ("PASSWORD", "SECRET", "TOKEN", "API_KEY"))
    )
    checks.append(
        {
            "id": "runtime-secrets",
            "title": "Secrets in environment variables",
            "status": "warn" if secret_names else "pass",
            "severity": "medium" if secret_names else "info",
            "description": (
                f"{len(secret_names)} sensitive variable name(s) are visible to the API runtime."
                if secret_names
                else "No sensitive environment variable names were detected."
            ),
            "remediation": "Prefer a dedicated secret manager and avoid exposing secrets broadly.",
            "evidence": secret_names,
        }
    )

    checks.append(
        {
            "id": "host-firewall",
            "title": "Host firewall visibility",
            "status": "unknown" if scope == "container" else "not_checked",
            "severity": "info",
            "description": "The host firewall cannot be assessed from the API container."
            if scope == "container"
            else "Firewall inspection is not implemented yet.",
            "remediation": "Run a native host agent to inspect firewall policy.",
        }
    )

    return {
        "scope": scope,
        "checks": checks,
        "summary": {
            "failures": sum(check["status"] == "fail" for check in checks),
            "warnings": sum(check["status"] == "warn" for check in checks),
            "unknown": sum(check["status"] == "unknown" for check in checks),
        },
    }
