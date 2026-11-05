"""Tests for change detection and alerting."""

import json

import pytest

from attacklens import pipeline
from attacklens.models import Finding
from attacklens.pipeline import format_alert, ingest, send_webhook
from attacklens.results import build_document


def _finding(port: int, severity: str = "high") -> Finding:
    return Finding(
        category="network",
        severity=severity,
        title=f"Service on {port}",
        description="d",
        target="host",
        port=port,
        service="S",
        protocol="tcp",
    )


def _scan(*findings: Finding, status: str = "complete") -> dict:
    document = build_document(list(findings), "host", "network", status=status)
    return document


@pytest.fixture(autouse=True)
def no_webhook(monkeypatch) -> None:
    """Keep the tests away from any configured webhook."""
    monkeypatch.delenv("ATTACKLENS_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ATTACKLENS_ALERT_MIN_SEVERITY", raising=False)


def test_first_scan_is_a_baseline(store) -> None:
    """Existing services are not news on the first scan."""
    assert ingest(store, _scan(_finding(22))) == []
    assert store.list_alerts() == []


def test_new_port_raises_an_alert(store) -> None:
    """The core promise: a service that appears gets noticed."""
    ingest(store, _scan(_finding(22)))

    alerted = ingest(store, _scan(_finding(22), _finding(3389)))

    assert [finding["port"] for finding in alerted] == [3389]
    alert = store.list_alerts()[0]
    assert "1 new finding(s) on host" in alert["message"]
    assert "[HIGH] Service on 3389" in alert["message"]
    assert alert["delivered"] is False


def test_unchanged_scan_stays_quiet(store) -> None:
    """Persistent findings must not alert on every run."""
    ingest(store, _scan(_finding(22)))
    ingest(store, _scan(_finding(22)))

    assert store.list_alerts() == []


def test_info_findings_stay_below_the_default_threshold(store) -> None:
    """Loopback services should not wake anybody up."""
    ingest(store, _scan())
    ingest(store, _scan(_finding(6463, "info")))

    assert store.list_alerts() == []


def test_threshold_is_configurable(store, monkeypatch) -> None:
    """Users can restrict alerts to serious findings."""
    monkeypatch.setenv("ATTACKLENS_ALERT_MIN_SEVERITY", "critical")
    ingest(store, _scan())
    ingest(store, _scan(_finding(22, "high")))

    assert store.list_alerts() == []


def test_dismissed_finding_does_not_alert_when_it_returns(store) -> None:
    """A service accepted once and restarted later is not news."""
    finding = _finding(3389)
    store.set_triage(finding.stable_id(), "accepted", "needed")
    ingest(store, _scan())

    assert ingest(store, _scan(finding)) == []


def test_silent_scan_neither_alerts_nor_replaces_the_baseline(store) -> None:
    """A network hiccup must not turn every service into a new finding."""
    ingest(store, _scan(_finding(22)))
    ingest(store, _scan(status="no_response"))

    assert ingest(store, _scan(_finding(22))) == []


def test_format_alert_stays_within_webhook_limits() -> None:
    """Discord refuses messages above 2000 characters."""
    findings = [_finding(port).to_dict() for port in range(1, 500)]

    assert len(format_alert("host", findings)) < 2000


def test_webhook_payload_suits_discord_and_slack(monkeypatch) -> None:
    """Both field names are sent, each service reads its own."""
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["url"] = request.full_url
        return Response()

    monkeypatch.setattr(pipeline, "urlopen", fake_urlopen)
    monkeypatch.setenv("ATTACKLENS_ALERT_WEBHOOK_URL", "https://example.test/hook")

    assert send_webhook("hello") is True
    assert captured == {
        "body": {"content": "hello", "text": "hello"},
        "url": "https://example.test/hook",
    }


def test_webhook_failure_is_recorded_and_not_fatal(store, monkeypatch) -> None:
    """A broken webhook must not lose the scan or the alert."""

    def fail(request, timeout):
        raise OSError("offline")

    monkeypatch.setattr(pipeline, "urlopen", fail)
    monkeypatch.setenv("ATTACKLENS_ALERT_WEBHOOK_URL", "https://example.test/hook")
    ingest(store, _scan())

    ingest(store, _scan(_finding(22)))

    assert store.list_alerts()[0]["delivered"] is False
    assert len(store.list_scans()) == 2


def test_no_webhook_means_no_network_call(monkeypatch) -> None:
    """Without configuration nothing leaves the machine."""

    def forbidden(request, timeout):
        raise AssertionError("unexpected network call")

    monkeypatch.setattr(pipeline, "urlopen", forbidden)

    assert send_webhook("hello") is False
