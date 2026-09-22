"""Scan result persistence for AttackLens."""

import json
from pathlib import Path
from typing import Any

from attacklens.models import Finding


def save_results(
    findings: list[Finding],
    path: Path,
    target: str,
    scan_type: str,
) -> None:
    """Save scan findings to a JSON file."""
    data: dict[str, Any] = {
        "target": target,
        "scan_type": scan_type,
        "findings": [finding.to_dict() for finding in findings],
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)