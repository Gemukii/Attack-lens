"""Tests for AttackLens result persistence."""

import json

from attacklens.models import Finding
from attacklens.results import save_results


def test_save_results(tmp_path) -> None:
    """Scan results should be saved as JSON."""
    output = tmp_path / "results" / "latest.json"

    findings = [
        Finding(
            category="network",
            severity="medium",
            title="Test finding",
            description="Test description",
            evidence="127.0.0.1:22/tcp",
            remediation="Restrict access.",
        )
    ]

    save_results(
        findings=findings,
        path=output,
        target="127.0.0.1",
        scan_type="network",
    )

    assert output.exists()

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["target"] == "127.0.0.1"
    assert data["scan_type"] == "network"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Test finding"