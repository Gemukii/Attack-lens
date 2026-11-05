"""Tests for agent identity, the audit log, backups, and retention."""

import json
import sqlite3
import stat
import sys
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from attacklens import cli, pipeline, service
from attacklens.client import api_post
from attacklens.models import Finding
from attacklens.results import build_document
from attacklens.storage import Store
from attacklens.web import api


def _enroll(client, hostname: str = "pc") -> str:
    code = client.post("/api/agents/enrollment").json()["code"]
    return client.post("/api/agents/enroll", json={"code": code, "hostname": hostname}).json()[
        "token"
    ]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _poll(client, token: str, hostname: str = "pc"):
    return client.post("/api/agent/poll", json={"hostname": hostname}, headers=_bearer(token))


def test_agent_endpoints_refuse_anonymous_calls(client) -> None:
    """Agent routes stay closed even when the API has no key."""
    assert client.post("/api/agent/poll", json={"hostname": "pc"}).status_code == 401
    assert client.post("/api/agent/jobs/x/result", json={"status": "done"}).status_code == 401


def test_enrollment_code_works_once(client) -> None:
    """A leaked code cannot enroll a second machine."""
    code = client.post("/api/agents/enrollment").json()["code"]

    first = client.post("/api/agents/enroll", json={"code": code, "hostname": "pc"})
    second = client.post("/api/agents/enroll", json={"code": code, "hostname": "evil"})

    assert first.status_code == 200
    assert second.status_code == 401


def test_expired_code_is_refused(client, store) -> None:
    """Codes are short-lived."""
    code = client.post("/api/agents/enrollment").json()["code"]
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with store._connect() as connection:
        connection.execute("UPDATE enrollment_codes SET expires_at = ?", (past,))

    answer = client.post("/api/agents/enroll", json={"code": code, "hostname": "pc"})

    assert answer.status_code == 401


def test_secrets_are_stored_hashed(client, store) -> None:
    """A copy of the database must not reveal working credentials."""
    code = client.post("/api/agents/enrollment").json()["code"]
    token = _enroll(client)

    with store._connect() as connection:
        dump = "\n".join(connection.iterdump())

    assert token not in dump
    assert code not in dump


def test_identity_comes_from_the_token(client, store) -> None:
    """An agent cannot pose as another machine by naming it."""
    token = _enroll(client, "pc")

    _poll(client, token, hostname="server")

    assert [agent["hostname"] for agent in store.list_agents()] == ["pc"]


def test_agent_cannot_report_for_another_machine(client) -> None:
    """A compromised agent must not be able to declare a server clean."""
    token = _enroll(client, "pc")
    server = _enroll(client, "server")
    _poll(client, server, "server")

    answer = client.post(
        "/api/reports", json=build_document([], "server", "host"), headers=_bearer(token)
    )
    network = client.post(
        "/api/reports", json=build_document([], "server", "network"), headers=_bearer(token)
    )

    assert answer.status_code == 403
    assert network.status_code == 403
    assert client.get("/api/audit").json()[0]["action"] == "report_refused"


def test_agent_reports_about_itself(client) -> None:
    """Its own reports go through."""
    token = _enroll(client, "pc")

    answer = client.post(
        "/api/reports", json=build_document([], "pc", "host"), headers=_bearer(token)
    )

    assert answer.status_code == 201


def test_agent_can_report_a_scanned_device(client) -> None:
    """Scanning another device of the network stays possible."""
    token = _enroll(client, "pc")

    answer = client.post(
        "/api/reports", json=build_document([], "192.168.1.20", "network"), headers=_bearer(token)
    )

    assert answer.status_code == 201


def test_host_report_needs_a_matching_identity(client) -> None:
    """A host report cannot be filed under a machine that never enrolled either."""
    token = _enroll(client, "pc")

    answer = client.post(
        "/api/reports", json=build_document([], "ghost", "host"), headers=_bearer(token)
    )

    assert answer.status_code == 403


def test_agent_cannot_finish_another_agents_job(client) -> None:
    """An order belongs to its machine."""
    first = _enroll(client, "pc")
    second = _enroll(client, "server")
    _poll(client, first, "pc")
    job = client.post("/api/jobs", json={}).json()
    _poll(client, first, "pc")

    answer = client.post(
        f"/api/agent/jobs/{job['job_id']}/result",
        json={"status": "done"},
        headers=_bearer(second),
    )

    assert answer.status_code == 404


def test_revoked_agent_is_locked_out_at_once(client) -> None:
    """Revocation has to work for a stolen laptop."""
    token = _enroll(client)
    assert _poll(client, token).status_code == 200

    assert client.delete("/api/agents/pc").status_code == 200

    assert _poll(client, token).status_code == 401


def test_key_protects_enrollment(client, monkeypatch) -> None:
    """Only an administrator can create codes."""
    monkeypatch.setattr(api, "API_KEY", "secret")

    assert client.post("/api/agents/enrollment").status_code == 401
    assert client.post("/api/agents/enrollment", headers={"X-API-Key": "secret"}).status_code == 200


def test_key_protects_reports_but_tokens_still_work(client, monkeypatch) -> None:
    """With a key, anonymous reports stop and enrolled agents continue."""
    token = _enroll(client)
    monkeypatch.setattr(api, "API_KEY", "secret")
    document = build_document([], "pc", "host")

    assert client.post("/api/reports", json=document).status_code == 401
    assert client.post("/api/reports", json=document, headers=_bearer(token)).status_code == 201


def test_token_does_not_open_admin_routes(client, monkeypatch) -> None:
    """An agent token is not an administrator key."""
    token = _enroll(client)
    monkeypatch.setattr(api, "API_KEY", "secret")

    assert client.get("/api/results", headers=_bearer(token)).status_code == 401
    assert client.post("/api/agents/enrollment", headers=_bearer(token)).status_code == 401


def test_sensitive_actions_are_audited(client, store) -> None:
    """Who accepted which risk must stay answerable."""
    finding = Finding("network", "high", "SMB", "d", target="h", port=445)
    store.save_scan(build_document([finding], "h", "network"))
    url = f"/api/findings/{finding.stable_id()}/triage"
    actor = {"X-AttackLens-Actor": "dashboard"}

    client.put(url, json={"status": "accepted", "reason": "lab"}, headers=actor)
    client.put(url, json={"status": "open"}, headers=actor)

    entries = client.get("/api/audit").json()
    assert [entry["action"] for entry in entries] == ["finding_reopened", "finding_accepted"]
    assert entries[1]["actor"] == "dashboard"
    assert "SMB: lab" in entries[1]["detail"]


def test_backup_is_a_working_copy(client, store, tmp_path, monkeypatch) -> None:
    """A backup only counts if it can be restored."""
    document = build_document([], "h", "network")
    store.save_scan(document)
    monkeypatch.setenv("ATTACKLENS_BACKUP_DIR", str(tmp_path / "backups"))

    name = client.post("/api/backups").json()["backup"]

    restored = Store(tmp_path / "backups" / name)
    assert restored.get_scan(document["scan_id"]) == document


def test_backup_needs_a_directory(client, monkeypatch) -> None:
    """No silent no-op."""
    monkeypatch.delenv("ATTACKLENS_BACKUP_DIR", raising=False)

    assert client.post("/api/backups").status_code == 409


def test_only_recent_backups_are_kept(store, tmp_path) -> None:
    """The directory must not fill the disk."""
    directory = tmp_path / "backups"
    directory.mkdir()
    for index in range(5):
        (directory / f"attacklens-2026010{index}-000000.db").write_bytes(b"old")

    pipeline.run_backup(store, directory, keep=3)

    assert len(list(directory.glob("attacklens-*.db"))) == 3


def test_failed_backup_is_recorded(store, monkeypatch, tmp_path) -> None:
    """A backup that fails quietly is the worst kind."""
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ATTACKLENS_BACKUP_DIR", str(blocker / "sub"))

    pipeline.daily_maintenance(store)

    assert store.list_audit()[0]["action"] == "backup_failed"


def _aged(store, days: int, target: str = "h", scan_type: str = "network") -> dict:
    document = build_document([], target, scan_type)
    document["completed_at"] = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    store.save_scan(document)
    return document


def test_retention_removes_old_scans(store) -> None:
    """Scans hold sensitive data and should not live forever."""
    old = _aged(store, 400)
    recent = _aged(store, 10)

    assert store.prune(365) == 1
    assert store.get_scan(old["scan_id"]) is None
    assert store.get_scan(recent["scan_id"]) is not None


def test_retention_keeps_the_last_view_of_an_asset(store) -> None:
    """A machine must not vanish because nobody scanned it for a year."""
    only = _aged(store, 800, target="old-server")

    assert store.prune(365) == 0
    assert store.get_scan(only["scan_id"]) is not None


def test_enroll_command_saves_a_private_identity(client, monkeypatch, capsys) -> None:
    """The token goes to a file only this user can read."""
    code = client.post("/api/agents/enrollment").json()["code"]

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

        def read(self):
            return self.body

    def forward(request, timeout):
        payload = json.loads(request.data)
        return Response(client.post("/api/agents/enroll", json=payload).content)

    monkeypatch.setattr("attacklens.client.urlopen", forward)
    monkeypatch.setattr(sys, "argv", ["attacklens", "enroll", code])

    with pytest.raises(SystemExit) as outcome:
        cli.main()

    assert outcome.value.code == 0
    saved = service.load_agent_config()
    assert saved["token"]
    assert saved["api_url"] == "http://127.0.0.1:8000"
    if sys.platform != "win32":
        mode = stat.S_IMODE(service.agent_config_path().stat().st_mode)
        assert mode == 0o600


def test_client_sends_the_agent_token(monkeypatch) -> None:
    """Once enrolled, every call carries the machine's identity."""
    service.save_agent_config("http://127.0.0.1:8000", "machine-token")
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout):
        captured["auth"] = request.get_header("Authorization")
        return Response()

    monkeypatch.setattr("attacklens.client.urlopen", fake_urlopen)

    api_post("http://127.0.0.1:8000", "/api/agent/poll", {})

    assert captured["auth"] == "Bearer machine-token"


def test_unknown_host_is_refused_on_enrollment(store) -> None:
    """Enrollment stays behind the Host check, like every route."""
    client = TestClient(api.app, base_url="http://attacker.example")

    answer = client.post("/api/agents/enroll", json={"code": "x" * 10, "hostname": "pc"})

    assert answer.status_code == 400


def test_database_upgrade_keeps_data(tmp_path) -> None:
    """Version 3 databases gain the new tables."""
    path = tmp_path / "attacklens.db"
    store = Store(path)
    document = build_document([], "h", "network")
    store.save_scan(document)
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE agent_tokens")
    connection.execute("DROP TABLE audit_log")
    connection.execute("PRAGMA user_version=3")
    connection.commit()
    connection.close()

    upgraded = Store(path)

    assert upgraded.get_scan(document["scan_id"]) == document
    assert upgraded.list_audit() == []
