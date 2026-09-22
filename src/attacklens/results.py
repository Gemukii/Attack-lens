"""Scan result persistence for AttackLens."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacklens.models import Finding


def save_results(
    findings: list[Finding],
    path: Path,
    target: str,
    scan_type: str,
    duration_seconds: float | None = None,
) -> None:
    """Save scan findings to a JSON file."""
    data: dict[str, Any] = {
        "target": target,
        "scan_type": scan_type,
        "findings": [finding.to_dict() for finding in findings],
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    if duration_seconds is not None:
        data["duration_seconds"] = round(duration_seconds, 3)

    severity_weights = {"critical": 35, "high": 20, "medium": 10, "low": 4}
    score = 100 - sum(
        severity_weights.get(finding.severity.lower(), 0)
        for finding in findings
    )
    data["score"] = max(0, min(100, score))
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
        }
        for finding in findings
        if finding.category == "network"
    ]

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)