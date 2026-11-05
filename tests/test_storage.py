"""Tests for the SQLite store."""

import json

from attacklens.models import Finding, finding_identity
from attacklens.results import build_document
from attacklens.storage import Store


def _scan(target: str = "host", scan_type: str = "network", status: str = "complete") -> dict:
    return build_document([], target, scan_type, status=status)


def test_saved_scan_can_be_read_back(store) -> None:
    """A document should survive storage unchanged."""
    document = _scan()

    store.save_scan(document)

    assert store.get_scan(document["scan_id"]) == document
    assert store.get_scan("missing") is None


def test_list_scans_filters_and_orders(store) -> None:
    """History is newest first and can be narrowed to one asset."""
    first, second, other = _scan(), _scan(), _scan(target="other", scan_type="host")
    first["completed_at"] = "2026-01-01T00:00:00+00:00"
    second["completed_at"] = "2026-01-02T00:00:00+00:00"
    for document in (first, second, other):
        store.save_scan(document)

    assert [s["scan_id"] for s in store.list_scans(target="host")] == [
        second["scan_id"],
        first["scan_id"],
    ]
    assert store.latest_scan("host")["scan_id"] == other["scan_id"]
    assert len(store.list_scans(limit=1)) == 1


def test_previous_complete_scan_skips_unusable_baselines(store) -> None:
    """A scan that observed nothing cannot be the baseline of the next one."""
    complete, silent, current = _scan(), _scan(status="no_response"), _scan()
    complete["completed_at"] = "2026-01-01T00:00:00+00:00"
    silent["completed_at"] = "2026-01-02T00:00:00+00:00"
    store.save_scan(complete)
    store.save_scan(silent)
    store.save_scan(_scan(target="other"))

    assert store.previous_complete_scan(current)["scan_id"] == complete["scan_id"]


def test_triage_can_be_set_and_reopened(store) -> None:
    """Reopening a finding removes the decision."""
    store.set_triage("abc", "accepted", "lab machine")
    assert store.triage_statuses()["abc"]["reason"] == "lab machine"

    store.set_triage("abc", "open", None)
    assert store.triage_statuses() == {}


def test_alerts_are_listed_newest_first(store) -> None:
    """Alerts keep their findings and delivery state."""
    store.add_alert("s1", "host", "first", [{"title": "a"}], delivered=False)
    store.add_alert("s2", "host", "second", [], delivered=True)

    alerts = store.list_alerts()

    assert [alert["message"] for alert in alerts] == ["second", "first"]
    assert alerts[0]["delivered"] is True
    assert alerts[1]["findings"] == [{"title": "a"}]


def test_legacy_results_are_imported_once(tmp_path) -> None:
    """JSON results from earlier versions move to the database."""
    legacy = tmp_path / "results"
    (legacy / "history").mkdir(parents=True)
    old_scan = {
        "scan_id": "old",
        "target": "host.docker.internal",
        "scan_type": "network",
        "score": 80,
        "open_ports": [445],
        "completed_at": "2026-09-23T06:23:41+00:00",
        "findings": [
            {
                "category": "network",
                "severity": "high",
                "title": "SMB service detected",
                "port": 445,
                "service": "SMB",
                "protocol": "tcp",
                "finding_id": "identifier-without-target",
            }
        ],
    }
    (legacy / "history" / "old.json").write_text(json.dumps(old_scan), encoding="utf-8")
    (legacy / "history" / "broken.json").write_text("{broken", encoding="utf-8")
    (legacy / "latest.json").write_text(json.dumps(old_scan), encoding="utf-8")
    path = tmp_path / "attacklens.db"

    store = Store(path, legacy_directory=legacy)
    Store(path, legacy_directory=legacy)

    scans = store.list_scans()
    assert len(scans) == 1
    finding = scans[0]["findings"][0]
    assert scans[0]["status"] == "complete"
    assert finding["target"] == "host.docker.internal"
    assert finding["finding_id"] == finding_identity(
        "host.docker.internal", "network", "SMB", 445, "tcp", "SMB service detected"
    )


def test_imported_findings_match_new_scans(tmp_path) -> None:
    """Old and new scans of a host must be comparable after the import."""
    new = Finding(
        category="network",
        severity="high",
        title="SMB service detected",
        description="d",
        target="h",
        port=445,
        service="SMB",
        protocol="tcp",
    )
    legacy = tmp_path / "results"
    legacy.mkdir()
    (legacy / "latest.json").write_text(
        json.dumps(
            {
                "target": "h",
                "findings": [
                    {
                        "category": "network",
                        "title": "SMB service detected",
                        "port": 445,
                        "service": "SMB",
                        "protocol": "tcp",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    store = Store(tmp_path / "db.sqlite", legacy_directory=legacy)

    assert store.list_scans()[0]["findings"][0]["finding_id"] == new.stable_id()
