"""Tests for AttackLens result persistence."""

import json

from attacklens.models import Finding
from attacklens.results import calculate_score, save_results


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
            port=22,
            service="SSH",
            protocol="tcp",
            version="OpenSSH_9.0",
            banner="SSH-2.0-OpenSSH_9.0",
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
    assert data["score"] == 90
    assert data["open_ports"] == [22]
    assert data["services"][0]["version"] == "OpenSSH_9.0"
    assert data["findings"][0]["finding_id"] == findings[0].stable_id()


def test_score_is_bounded_and_unknown_severity_is_neutral() -> None:
    """Score calculations stay in range for extreme and unknown severities."""
    findings = [
        Finding("network", "critical", "one", "one"),
        Finding("network", "critical", "two", "two"),
        Finding("network", "unknown", "three", "three"),
    ]

    assert calculate_score(findings) == 30
    assert calculate_score([]) == 100