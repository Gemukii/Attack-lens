"""Tests for AttackLens data models."""

from attacklens.models import Finding


def test_finding_to_dict() -> None:
    """A finding should be convertible to a dictionary."""
    finding = Finding(
        category="network",
        severity="medium",
        title="Test finding",
        description="Test description",
        evidence="127.0.0.1:22/tcp",
        remediation="Restrict access.",
    )

    result = finding.to_dict()

    assert result["category"] == "network"
    assert result["severity"] == "medium"
    assert result["title"] == "Test finding"
    assert result["evidence"] == "127.0.0.1:22/tcp"