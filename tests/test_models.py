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
    assert result["finding_id"] == finding.stable_id()


def test_finding_id_ignores_volatile_evidence() -> None:
    """A service remains the same finding when its banner changes."""
    first = Finding(
        category="network",
        severity="medium",
        title="SSH",
        description="old",
        evidence="old banner",
        port=22,
        service="SSH",
        protocol="tcp",
        version="1.0",
    )
    second = Finding(
        category="network",
        severity="high",
        title="SSH",
        description="new",
        evidence="new banner",
        port=22,
        service="SSH",
        protocol="tcp",
        version="2.0",
    )

    assert first.stable_id() == second.stable_id()