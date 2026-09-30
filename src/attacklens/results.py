"""Scan result persistence for AttackLens."""

import json
import os
import tempfile
from threading import Lock
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacklens.models import Finding


_WRITE_LOCK = Lock()
SEVERITY_WEIGHTS = {"critical": 35, "high": 20, "medium": 10, "low": 4}


def calculate_score(findings: list[Finding]) -> int:
    """Calculate the bounded network risk score."""
    penalty = sum(SEVERITY_WEIGHTS.get(finding.severity.lower(), 0) for finding in findings)
    return max(0, min(100, 100 - penalty))


def _atomic_write_json(data: dict[str, Any], path: Path) -> None:
    """Write JSON beside the destination, then replace it atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = file.name
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def save_results(
    findings: list[Finding],
    path: Path,
    target: str,
    scan_type: str,
    duration_seconds: float | None = None,
    scan_id: str | None = None,
    history_path: Path | None = None,
) -> dict[str, Any]:
    """Save scan findings to a JSON file."""
    data: dict[str, Any] = {
        "target": target,
        "scan_type": scan_type,
        "findings": [finding.to_dict() for finding in findings],
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    if scan_id is not None:
        data["scan_id"] = scan_id

    if duration_seconds is not None:
        data["duration_seconds"] = round(duration_seconds, 3)

    data["score"] = calculate_score(findings)
    data["open_ports"] = [
        finding.port
        for finding in findings
        if finding.category == "network" and finding.port is not None
    ]
    data["services"] = [
        {
            "name": finding.service or finding.title,
            "port": finding.port,
            "protocol": finding.protocol,
            "version": finding.version,
            "banner": finding.banner,
        }
        for finding in findings
        if finding.category == "network"
    ]

    with _WRITE_LOCK:
        _atomic_write_json(data, path)
        if history_path is not None:
            _atomic_write_json(data, history_path)
    return data