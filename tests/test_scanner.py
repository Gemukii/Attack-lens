"""Tests for the AttackLens network scanner."""

from attacklens.scanner import check_port, classify_service, scan_network


def test_check_port_closed() -> None:
    """A port that is not listening should be reported as closed."""
    assert check_port("127.0.0.1", 1) is False


def test_scan_network_returns_findings() -> None:
    """The network scanner should classify detected services."""
    findings = scan_network("127.0.0.1")

    assert isinstance(findings, list)

    for finding in findings:
        assert finding.category == "network"
        assert finding.severity in {"critical", "high", "medium", "low", "info"}
        assert finding.risk_reason


def test_classify_service_assigns_risk_levels() -> None:
    """Known risky ports should have explicit severity rules."""
    assert classify_service(23)[0] == "critical"
    assert classify_service(6379)[0] == "critical"
    assert classify_service(21)[0] == "high"
    assert classify_service(22)[0] == "medium"
    assert classify_service(80)[0] == "low"


def test_scan_network_uses_service_classification(monkeypatch) -> None:
    """A detected Telnet service should become a critical finding."""
    monkeypatch.setattr(
        "attacklens.scanner.check_port",
        lambda host, port: port == 23,
    )
    monkeypatch.setattr(
        "attacklens.scanner.identify_service",
        lambda host, port, service: ("OpenSSH_9.0", "SSH-2.0-OpenSSH_9.0"),
    )

    findings = scan_network("example.test")

    assert len(findings) == 1
    assert findings[0].service == "Telnet"
    assert findings[0].severity == "critical"
    assert "without encryption" in findings[0].risk_reason


def test_scan_network_keeps_service_identity(monkeypatch) -> None:
    """Service version and banner should be included when detected."""
    monkeypatch.setattr(
        "attacklens.scanner.check_port",
        lambda host, port: port == 22,
    )
    monkeypatch.setattr(
        "attacklens.scanner.identify_service",
        lambda host, port, service: ("OpenSSH_9.0", "SSH-2.0-OpenSSH_9.0"),
    )

    findings = scan_network("example.test")

    assert findings[0].version == "OpenSSH_9.0"
    assert findings[0].banner == "SSH-2.0-OpenSSH_9.0"