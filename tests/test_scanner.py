"""Tests for the AttackLens network scanner."""

from attacklens.scanner import check_port, scan_network


def test_check_port_closed() -> None:
    """A port that is not listening should be reported as closed."""
    assert check_port("127.0.0.1", 1) is False


def test_scan_network_returns_findings() -> None:
    """The network scanner should return a list of findings."""
    findings = scan_network("127.0.0.1")

    assert isinstance(findings, list)

    for finding in findings:
        assert finding.category == "network"
        assert finding.severity == "info"