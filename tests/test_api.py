"""Tests for the AttackLens HTTP API contract."""

from pathlib import Path

from fastapi.testclient import TestClient

from attacklens.models import Finding
from attacklens.web import api


client = TestClient(api.app)


def test_get_results_returns_404_when_no_scan_exists(tmp_path, monkeypatch) -> None:
    """The dashboard should be able to distinguish no scan from an empty scan."""
    monkeypatch.setattr(api, "RESULTS_PATH", tmp_path / "missing.json")

    response = client.get("/api/results")

    assert response.status_code == 404
    assert response.json()["detail"] == "No scan results available."


def test_post_scan_returns_persisted_result(tmp_path, monkeypatch) -> None:
    """POST /api/scan should synchronously return the stored result document."""
    monkeypatch.setattr(api, "RESULTS_PATH", tmp_path / "latest.json")
    monkeypatch.setattr(
        api,
        "scan_network",
        lambda target: [
            Finding(
                category="network",
                severity="high",
                title="SSH service detected",
                description="TCP port 22 is accepting connections.",
                evidence=f"{target}:22/tcp",
                port=22,
                service="SSH",
                protocol="tcp",
            )
        ],
    )

    response = client.post("/api/scan", json={"target": "example.test"})

    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "example.test"
    assert data["findings"][0]["severity"] == "high"
    assert data["open_ports"] == [22]
    assert data["services"] == [{"name": "SSH", "port": 22, "protocol": "tcp"}]
    assert data["score"] == 80
    assert data["duration_seconds"] >= 0
    assert Path(api.RESULTS_PATH).exists()


def test_post_scan_accepts_empty_findings(tmp_path, monkeypatch) -> None:
    """A successful scan with no findings should still return a complete result."""
    monkeypatch.setattr(api, "RESULTS_PATH", tmp_path / "latest.json")
    monkeypatch.setattr(api, "scan_network", lambda target: [])

    response = client.post("/api/scan", json={"target": "127.0.0.1"})

    assert response.status_code == 200
    assert response.json()["findings"] == []
    assert response.json()["score"] == 100
    assert response.json()["open_ports"] == []
