"""Tests for the AttackLens HTTP API contract."""

import json
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
    monkeypatch.setattr(api, "HISTORY_PATH", tmp_path / "history")
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
    assert data["services"] == [
        {
            "name": "SSH",
            "port": 22,
            "protocol": "tcp",
            "version": None,
            "banner": None,
        }
    ]
    assert data["score"] == 80
    assert data["duration_seconds"] >= 0
    assert Path(api.RESULTS_PATH).exists()
    assert len(list((tmp_path / "history").glob("*.json"))) == 1


def test_post_scan_accepts_empty_findings(tmp_path, monkeypatch) -> None:
    """A successful scan with no findings should still return a complete result."""
    monkeypatch.setattr(api, "RESULTS_PATH", tmp_path / "latest.json")
    monkeypatch.setattr(api, "HISTORY_PATH", tmp_path / "history")
    monkeypatch.setattr(api, "scan_network", lambda target: [])

    response = client.post("/api/scan", json={"target": "127.0.0.1"})

    assert response.status_code == 200
    assert response.json()["findings"] == []
    assert response.json()["score"] == 100
    assert response.json()["open_ports"] == []


def test_compare_scans_classifies_changes(tmp_path, monkeypatch) -> None:
    """The comparison endpoint should report new, fixed, and persistent findings."""
    monkeypatch.setattr(api, "HISTORY_PATH", tmp_path / "history")
    api.HISTORY_PATH.mkdir()
    before = {
        "scan_id": "before",
        "score": 70,
        "open_ports": [22, 80],
        "findings": [
            {"category": "network", "service": "SSH", "port": 22, "protocol": "tcp", "title": "SSH"},
            {"category": "network", "service": "HTTP", "port": 80, "protocol": "tcp", "title": "HTTP"},
        ],
    }
    after = {
        "scan_id": "after",
        "score": 85,
        "open_ports": [22, 443],
        "findings": [
            {"category": "network", "service": "SSH", "port": 22, "protocol": "tcp", "title": "SSH"},
            {"category": "network", "service": "HTTPS", "port": 443, "protocol": "tcp", "title": "HTTPS"},
        ],
    }
    (api.HISTORY_PATH / "before.json").write_text(json.dumps(before), encoding="utf-8")
    (api.HISTORY_PATH / "after.json").write_text(json.dumps(after), encoding="utf-8")

    response = client.get("/api/scans/compare?before_id=before&after_id=after")

    assert response.status_code == 200
    data = response.json()
    assert data["score_delta"] == 15
    assert len(data["new_findings"]) == 1
    assert len(data["fixed_findings"]) == 1
    assert len(data["persistent_findings"]) == 1
    assert data["ports_added"] == [443]
    assert data["ports_removed"] == [80]
