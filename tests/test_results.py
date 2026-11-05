"""Tests for AttackLens result documents."""

from attacklens.models import Finding
from attacklens.results import (
    apply_triage,
    build_document,
    calculate_score,
    compare_documents,
    severity_at_least,
)


def _finding(severity: str = "medium", port: int = 22) -> Finding:
    return Finding(
        category="network",
        severity=severity,
        title=f"Port {port}",
        description="Test description",
        target="127.0.0.1",
        port=port,
        service="SSH",
        protocol="tcp",
        version="OpenSSH_9.0",
    )


def test_build_document() -> None:
    """A scan document should carry findings, score, and network summaries."""
    finding = _finding()

    data = build_document([finding], "127.0.0.1", "network", coverage={"ports_checked": 1})

    assert data["scan_id"]
    assert data["status"] == "complete"
    assert data["score"] == 90
    assert data["open_ports"] == [22]
    assert data["coverage"] == {"ports_checked": 1}
    assert data["services"][0]["version"] == "OpenSSH_9.0"
    assert data["findings"][0]["finding_id"] == finding.stable_id()


def test_scan_without_observation_has_no_score() -> None:
    """Nothing observed must never become a perfect score."""
    data = build_document([], "192.0.2.1", "network", status="no_response")

    assert data["score"] is None


def test_score_is_bounded_and_unknown_severity_is_neutral() -> None:
    """Score calculations stay in range for extreme and unknown severities."""
    findings = [
        Finding("network", "critical", "one", "one"),
        Finding("network", "critical", "two", "two"),
        Finding("network", "unknown", "three", "three"),
    ]

    assert calculate_score(findings) == 30
    assert calculate_score([]) == 100


def test_severity_at_least() -> None:
    """Thresholds follow severity order and ignore unknown values."""
    assert severity_at_least("high", "medium")
    assert severity_at_least("HIGH", "high")
    assert not severity_at_least("low", "medium")
    assert not severity_at_least("unknown", "info")
    assert not severity_at_least(None, "info")


def test_apply_triage_removes_dismissed_findings_from_the_score() -> None:
    """An accepted risk should stop lowering the score, and stay visible."""
    accepted = _finding("high", 445)
    document = build_document([accepted, _finding("medium", 22)], "127.0.0.1", "network")

    triaged = apply_triage(document, {accepted.stable_id(): {"status": "accepted", "reason": "lab"}})

    assert document["score"] == 70
    assert triaged["raw_score"] == 70
    assert triaged["score"] == 90
    assert triaged["findings"][0]["triage_status"] == "accepted"
    assert triaged["findings"][0]["triage_reason"] == "lab"
    assert triaged["findings"][1]["triage_status"] == "open"


def test_apply_triage_keeps_a_missing_score_missing() -> None:
    """Triage must not invent a score for a scan that observed nothing."""
    document = build_document([], "192.0.2.1", "network", status="no_response")

    assert apply_triage(document, {})["score"] is None


def test_compare_documents_classifies_changes() -> None:
    """Comparison reports new, fixed, and persistent findings."""
    before = build_document([_finding(port=22), _finding(port=80)], "h", "network")
    after = build_document([_finding(port=22), _finding(port=443)], "h", "network")

    data = compare_documents(before, after)

    assert data["score_delta"] == 0
    assert [item["port"] for item in data["new_findings"]] == [443]
    assert [item["port"] for item in data["fixed_findings"]] == [80]
    assert [item["port"] for item in data["persistent_findings"]] == [22]
    assert data["ports_added"] == [443]
    assert data["ports_removed"] == [80]


def test_compare_documents_without_score() -> None:
    """A delta cannot be computed against a scan that has no score."""
    before = build_document([], "h", "network", status="no_response")
    after = build_document([_finding()], "h", "network")

    assert compare_documents(before, after)["score_delta"] is None
