"""Tests for runtime security posture checks."""

from attacklens.posture import collect_posture


def test_collect_posture_returns_actionable_checks(monkeypatch) -> None:
    """Posture checks should include status, severity, and remediation."""
    monkeypatch.setattr("attacklens.posture._is_root", lambda: False)
    report = collect_posture("container")

    assert report["scope"] == "container"
    assert report["checks"]
    assert all("status" in check for check in report["checks"])
    assert all("remediation" in check for check in report["checks"])
    firewall = next(check for check in report["checks"] if check["id"] == "host-firewall")
    assert firewall["status"] == "unknown"
