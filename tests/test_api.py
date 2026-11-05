"""Tests for the AttackLens HTTP API contract."""

import importlib

import pytest
from fastapi.testclient import TestClient

from attacklens.models import Finding
from attacklens.results import build_document
from attacklens.scanner import NetworkScan, TargetResolutionError
from attacklens.web import api


def _finding(target: str = "example.test", port: int = 22, severity: str = "high") -> Finding:
    return Finding(
        category="network",
        severity=severity,
        title=f"Service on {port}",
        description=f"TCP port {port} is accepting connections.",
        evidence=f"{target}:{port}/tcp",
        target=target,
        port=port,
        service="SSH",
        protocol="tcp",
    )


@pytest.fixture
def scan_result(monkeypatch):
    """Replace the scanner with a fixed result."""
    scan = NetworkScan([_finding()], ports_checked=1, ports_open=1)
    monkeypatch.setattr(api, "scan_network", lambda target: scan)
    return scan


def test_scan_rejects_url_like_targets(client) -> None:
    """The scan endpoint should accept hosts, not arbitrary URLs or paths."""
    response = client.post("/api/scan", json={"target": "http://example.test"})

    assert response.status_code == 422


def test_scan_enforces_the_allowlist_on_the_default_target(client, monkeypatch) -> None:
    """An empty body must not bypass the allowed targets."""
    monkeypatch.setattr(api, "ALLOWED_TARGETS", {"192.168.1.10"})

    assert client.post("/api/scan", json={}).status_code == 422
    assert client.post("/api/scan", json={"target": "10.0.0.1"}).status_code == 422


def test_get_results_returns_404_when_no_scan_exists(client) -> None:
    """The dashboard should be able to distinguish no scan from an empty scan."""
    response = client.get("/api/results")

    assert response.status_code == 404
    assert response.json()["detail"] == "No scan results available."


def test_post_scan_returns_the_stored_result(client, store, scan_result) -> None:
    """POST /api/scan should synchronously return the stored result document."""
    response = client.post("/api/scan", json={"target": "example.test"})

    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "example.test"
    assert data["status"] == "complete"
    assert data["findings"][0]["severity"] == "high"
    assert data["findings"][0]["triage_status"] == "open"
    assert data["open_ports"] == [22]
    assert data["score"] == 80
    assert data["coverage"]["ports_checked"] == 1
    assert data["duration_seconds"] >= 0
    assert store.get_scan(data["scan_id"]) is not None
    assert client.get("/api/results").json()["scan_id"] == data["scan_id"]


def test_silent_target_has_no_score(client, monkeypatch) -> None:
    """The API must not present an unreachable host as 100/100."""
    monkeypatch.setattr(
        api, "scan_network", lambda target: NetworkScan(status="no_response", ports_checked=36)
    )

    data = client.post("/api/scan", json={"target": "192.0.2.1"}).json()

    assert data["status"] == "no_response"
    assert data["score"] is None


def test_scan_of_a_host_without_findings_keeps_a_score(client, monkeypatch) -> None:
    """A host that answered and exposes nothing does deserve a clean score."""
    monkeypatch.setattr(
        api, "scan_network", lambda target: NetworkScan(ports_checked=36, ports_closed=36)
    )

    data = client.post("/api/scan", json={"target": "127.0.0.1"}).json()

    assert data["findings"] == []
    assert data["score"] == 100


def test_unresolvable_target_is_a_client_error(client, monkeypatch) -> None:
    """DNS failures are explained to the caller."""

    def fail(target):
        raise TargetResolutionError("Unable to resolve target 'x'.")

    monkeypatch.setattr(api, "scan_network", fail)

    response = client.post("/api/scan", json={"target": "x"})

    assert response.status_code == 422
    assert "resolve" in response.json()["detail"]


def test_concurrent_scan_is_refused(client, scan_result) -> None:
    """Only one network scan runs at a time."""
    api.SCAN_LIMIT.acquire()
    try:
        assert client.post("/api/scan", json={"target": "x"}).status_code == 429
    finally:
        api.SCAN_LIMIT.release()


def test_compare_rejects_invalid_identifiers(client) -> None:
    """Identifiers are validated before reaching the database."""
    response = client.get("/api/scans/compare?before_id=../secret&after_id=after")

    assert response.status_code == 422


def test_compare_classifies_changes(client, store) -> None:
    """The comparison endpoint should report new, fixed, and persistent findings."""
    before = build_document([_finding(port=22), _finding(port=80)], "h", "network")
    after = build_document([_finding(port=22), _finding(port=443)], "h", "network")
    store.save_scan(before)
    store.save_scan(after)

    response = client.get(
        f"/api/scans/compare?before_id={before['scan_id']}&after_id={after['scan_id']}"
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["new_findings"]) == 1
    assert len(data["fixed_findings"]) == 1
    assert len(data["persistent_findings"]) == 1
    assert data["ports_added"] == [443]
    assert data["ports_removed"] == [80]


def test_compare_refuses_different_assets(client, store) -> None:
    """Comparing two hosts would report meaningless changes."""
    first = build_document([_finding("a")], "a", "network")
    second = build_document([_finding("b")], "b", "network")
    store.save_scan(first)
    store.save_scan(second)

    response = client.get(
        f"/api/scans/compare?before_id={first['scan_id']}&after_id={second['scan_id']}"
    )

    assert response.status_code == 422


def test_same_port_on_two_hosts_has_distinct_identities() -> None:
    """Findings belong to an asset."""
    assert _finding("a").stable_id() != _finding("b").stable_id()


def test_history_is_filtered_and_limited(client, store) -> None:
    """The dashboard asks for one asset at a time."""
    store.save_scan(build_document([], "a", "network"))
    store.save_scan(build_document([], "b", "network"))
    store.save_scan(build_document([], "a", "host"))

    assert len(client.get("/api/scans").json()) == 3
    assert len(client.get("/api/scans?limit=1").json()) == 1
    assert len(client.get("/api/scans?target=a&scan_type=network").json()) == 1
    assert client.get("/api/scans?limit=0").status_code == 422


def _report(**overrides) -> dict:
    return {**build_document([_finding("pc")], "pc", "host"), **overrides}


def test_report_is_stored_and_served(client) -> None:
    """A host agent report reaches the dashboard through the API."""
    response = client.post("/api/reports", json=_report(listeners={"items": []}))

    assert response.status_code == 201
    data = client.get("/api/host").json()
    assert data["target"] == "pc"
    assert data["listeners"] == {"items": []}
    assert client.get("/api/host?target=other").status_code == 404


def test_report_triggers_alerts(client) -> None:
    """Pushed reports go through the same change detection as API scans."""
    client.post("/api/reports", json=build_document([], "pc", "host"))

    response = client.post("/api/reports", json=_report())

    assert response.json()["alerts"] == 1
    assert client.get("/api/alerts").json()[0]["target"] == "pc"


@pytest.mark.parametrize(
    "overrides",
    [
        {"scan_type": "unknown"},
        {"status": "unknown"},
        {"scan_id": "../escape"},
        {"score": 1000},
        {"findings": [{"title": "no identity"}]},
    ],
)
def test_invalid_report_is_rejected(client, overrides) -> None:
    """Reports come from outside the process and are validated."""
    assert client.post("/api/reports", json=_report(**overrides)).status_code == 422


def test_triage_updates_findings_and_score(client, store) -> None:
    """Accepting a risk changes the score everywhere, and reopening restores it."""
    finding = _finding()
    store.save_scan(build_document([finding], "example.test", "network"))
    url = f"/api/findings/{finding.stable_id()}/triage"

    response = client.put(url, json={"status": "accepted", "reason": "lab"})

    assert response.status_code == 200
    data = client.get("/api/results").json()
    assert data["score"] == 100
    assert data["raw_score"] == 80
    assert data["findings"][0]["triage_status"] == "accepted"
    assert data["findings"][0]["triage_reason"] == "lab"

    client.put(url, json={"status": "open"})
    assert client.get("/api/results").json()["score"] == 80


@pytest.mark.parametrize(
    ("finding_id", "body"),
    [("not-a-hash", {"status": "accepted"}), ("a" * 64, {"status": "ignored"})],
)
def test_triage_validation(client, finding_id, body) -> None:
    """Identifiers and statuses are closed sets."""
    assert client.put(f"/api/findings/{finding_id}/triage", json=body).status_code == 422


def test_vulnerabilities_are_disabled_by_default(client, monkeypatch) -> None:
    """The dashboard must not send package names to OSV unless the user opted in."""
    monkeypatch.delenv("ATTACKLENS_ENABLE_OSV", raising=False)

    def forbidden(packages):
        raise AssertionError("OSV must not be contacted")

    monkeypatch.setattr(api, "query_package_vulnerabilities", forbidden)

    assert client.get("/api/vulnerabilities").json()["status"] == "disabled"


def test_unknown_host_header_is_rejected(store) -> None:
    """DNS rebinding reaches the API with the attacker's hostname."""
    client = TestClient(api.app, base_url="http://attacker.example")

    assert client.get("/api/health").status_code == 400


def test_requests_pass_without_a_configured_key(client, monkeypatch) -> None:
    """Without a key the API stays open for local development."""
    monkeypatch.setattr(api, "API_KEY", None)

    assert client.get("/api/alerts").status_code == 200


def test_configured_key_is_enforced(client, monkeypatch) -> None:
    """Protected endpoints need the right key, health stays public."""
    monkeypatch.setattr(api, "API_KEY", "secret")

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/alerts", headers={"X-API-Key": "secret"}).status_code == 200


def test_empty_key_from_compose_means_no_key(monkeypatch) -> None:
    """Compose passes an empty variable: this must not lock every client out."""
    monkeypatch.setenv("ATTACKLENS_API_KEY", "")
    try:
        reloaded = importlib.reload(api)
        assert reloaded.API_KEY is None
        reloaded.require_api_key(None)
    finally:
        monkeypatch.undo()
        importlib.reload(api)
