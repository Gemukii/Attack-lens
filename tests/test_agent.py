"""Tests for the host agent and the scan orders it receives."""

import socket
from datetime import UTC, datetime, timedelta

import pytest

from attacklens import agent, storage
from attacklens.agent import primary_address, run_job, scan_this_machine, watch
from attacklens.client import ApiError
from attacklens.models import Finding
from attacklens.results import build_document
from attacklens.scanner import NetworkScan, TargetResolutionError
from attacklens.web import api

POLL = {"hostname": "pc", "platform": "Windows", "version": "0.1.0", "address": "10.0.0.5"}


class StopWatching(Exception):
    """Ends the otherwise endless watch loop in tests."""


@pytest.fixture
def online_agent(client) -> None:
    """Enroll a live agent: the client then speaks as this agent."""
    code = client.post("/api/agents/enrollment").json()["code"]
    token = client.post("/api/agents/enroll", json={"code": code, "hostname": "pc"}).json()["token"]
    client.headers["Authorization"] = f"Bearer {token}"
    client.post("/api/agent/poll", json=POLL)


def test_primary_address_is_usable() -> None:
    """The address must be one this machine can bind."""
    address = primary_address()

    with socket.socket() as server:
        server.bind((address, 0))


def test_no_agent_means_no_job(client) -> None:
    """The dashboard must be told that nothing will run the scan."""
    assert client.post("/api/jobs", json={}).status_code == 409


def test_poll_marks_the_agent_online(client, online_agent) -> None:
    """A heartbeat makes the agent visible."""
    agents = client.get("/api/agents").json()

    assert agents[0]["hostname"] == "pc"
    assert agents[0]["online"] is True
    assert agents[0]["address"] == "10.0.0.5"


def test_silent_agent_goes_offline(client, online_agent, monkeypatch) -> None:
    """An agent that stopped polling is not available."""
    monkeypatch.setattr(api, "AGENT_ONLINE_SECONDS", -1)

    assert client.get("/api/agents").json()[0]["online"] is False
    assert client.post("/api/jobs", json={}).status_code == 409


def test_job_lifecycle(client, online_agent) -> None:
    """An order goes from the dashboard to the agent and back."""
    created = client.post("/api/jobs", json={})
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    assert created.json()["target"] is None
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "queued"

    job = client.post("/api/agent/poll", json=POLL).json()["job"]
    assert job["job_id"] == job_id
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "running"

    done = client.post(
        f"/api/agent/jobs/{job_id}/result", json={"status": "done", "scan_id": "abc"}
    )
    assert done.status_code == 200
    final = client.get(f"/api/jobs/{job_id}").json()
    assert final["status"] == "done"
    assert final["scan_id"] == "abc"


def test_order_is_delivered_once(client, online_agent) -> None:
    """A second poll must not run the same scan twice."""
    client.post("/api/jobs", json={})
    client.post("/api/agent/poll", json=POLL)

    assert client.post("/api/agent/poll", json=POLL).json()["job"] is None


def test_second_order_is_refused_while_one_is_active(client, online_agent) -> None:
    """Only one scan runs at a time."""
    client.post("/api/jobs", json={})

    assert client.post("/api/jobs", json={}).status_code == 429


def test_failure_is_reported(client, online_agent) -> None:
    """The agent's error reaches the dashboard."""
    job_id = client.post("/api/jobs", json={"target": "nas.local"}).json()["job_id"]
    client.post("/api/agent/poll", json=POLL)

    client.post(
        f"/api/agent/jobs/{job_id}/result", json={"status": "failed", "error": "Unable to resolve"}
    )

    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed"
    assert job["error"] == "Unable to resolve"


def test_result_for_an_unknown_job_is_refused(client, online_agent) -> None:
    """Results only apply to running orders."""
    response = client.post("/api/agent/jobs/nope/result", json={"status": "done"})

    assert response.status_code == 404


@pytest.mark.parametrize("target", ["http://x", "a b", "x;rm -rf /"])
def test_job_target_is_validated(client, online_agent, target) -> None:
    """Targets are checked before reaching the agent."""
    assert client.post("/api/jobs", json={"target": target}).status_code == 422


def test_job_target_respects_the_allowlist(client, online_agent, monkeypatch) -> None:
    """The allowlist also applies to the agent, except for its own machine."""
    monkeypatch.setattr(api, "ALLOWED_TARGETS", {"192.168.1.10"})

    assert client.post("/api/jobs", json={"target": "10.0.0.1"}).status_code == 422
    assert client.post("/api/jobs", json={}).status_code == 202


def test_blank_target_means_this_machine(client, online_agent) -> None:
    """An empty input in the dashboard is not a target."""
    assert client.post("/api/jobs", json={"target": "  "}).json()["target"] is None


def test_unclaimed_job_expires(store) -> None:
    """A crashed agent must not leave the dashboard waiting forever."""
    job = store.create_job("pc", None)
    past = datetime.now(UTC) - timedelta(seconds=storage.JOB_QUEUE_LIMIT_SECONDS + 1)
    with store._connect() as connection:
        connection.execute("UPDATE agent_jobs SET created_at = ?", (past.isoformat(),))

    expired = store.get_job(job["job_id"])

    assert expired["status"] == "failed"
    assert "did not pick up" in expired["error"]
    assert store.create_job("pc", None) is not None


def test_stuck_job_expires(store) -> None:
    """An agent that dies mid-scan frees the queue."""
    job = store.create_job("pc", None)
    store.claim_job("pc")
    past = datetime.now(UTC) - timedelta(seconds=storage.JOB_RUN_LIMIT_SECONDS + 1)
    with store._connect() as connection:
        connection.execute("UPDATE agent_jobs SET started_at = ?", (past.isoformat(),))

    assert store.get_job(job["job_id"])["status"] == "failed"


def test_agents_only_receive_their_own_orders(store) -> None:
    """An order for one machine must not run on another."""
    store.create_job("pc", None)

    assert store.claim_job("other") is None
    assert store.claim_job("pc") is not None


def test_existing_database_gains_the_new_tables(tmp_path) -> None:
    """Upgrading must keep existing data."""
    path = tmp_path / "attacklens.db"
    first = storage.Store(path)
    document = build_document([], "h", "network")
    first.save_scan(document)
    with first._connect() as connection:
        connection.execute("DROP TABLE agent_jobs")
        connection.execute("DROP TABLE agents")
        connection.execute("PRAGMA user_version=1")

    upgraded = storage.Store(path)

    assert upgraded.get_scan(document["scan_id"]) is not None
    assert upgraded.list_agents() == []


def test_scan_this_machine_uses_the_stable_hostname(monkeypatch) -> None:
    """The address may change, the asset must not."""
    calls = {}

    def fake_scan(host, asset=None):
        calls.update(host=host, asset=asset)
        finding = Finding("network", "high", "SMB", "d", target=asset, port=445)
        return NetworkScan([finding], port_states={445: "open"})

    monkeypatch.setattr(agent, "scan_network", fake_scan)
    monkeypatch.setattr(agent, "primary_address", lambda: "192.168.1.20")

    document = scan_this_machine()

    assert calls == {"host": "192.168.1.20", "asset": socket.gethostname()}
    assert document["target"] == socket.gethostname()
    assert document["port_states"] == {"445": "open"}
    assert document["vantage"] == "host"


@pytest.fixture
def sent(monkeypatch) -> dict:
    """Capture what the agent sends to the API."""
    captured = {"reports": [], "results": []}
    monkeypatch.setattr(
        agent, "send_report", lambda document, url: captured["reports"].append(document)
    )
    monkeypatch.setattr(
        agent,
        "api_post",
        lambda url, path, payload, timeout=30: captured["results"].append((path, payload)),
    )
    monkeypatch.setattr(
        agent, "collect_host_report", lambda: build_document([], "pc", "host")
    )
    return captured


def test_local_job_sends_network_and_host_reports(sent, monkeypatch) -> None:
    """Scanning this machine refreshes both views."""
    monkeypatch.setattr(
        agent, "scan_this_machine", lambda: build_document([], "pc", "network", scan_id="s1")
    )

    run_job({"job_id": "j1", "target": None}, "http://api")

    assert [report["scan_type"] for report in sent["reports"]] == ["network", "host"]
    path, payload = sent["results"][0]
    assert path == "/api/agent/jobs/j1/result"
    assert payload == {"status": "done", "error": None, "scan_id": "s1"}


def test_remote_job_scans_the_target_only(sent, monkeypatch) -> None:
    """A host report only describes this machine, not the scanned target."""
    monkeypatch.setattr(
        agent, "scan_target", lambda target: build_document([], target, "network")
    )

    run_job({"job_id": "j1", "target": "nas.local"}, "http://api")

    assert [report["target"] for report in sent["reports"]] == ["nas.local"]


def test_failed_scan_is_reported_to_the_api(sent, monkeypatch) -> None:
    """The dashboard must learn why a scan failed."""

    def fail(target):
        raise TargetResolutionError("Unable to resolve target 'x'.")

    monkeypatch.setattr(agent, "scan_target", fail)

    run_job({"job_id": "j1", "target": "x"}, "http://api")

    assert sent["reports"] == []
    assert sent["results"][0][1]["status"] == "failed"
    assert "Unable to resolve" in sent["results"][0][1]["error"]


def test_agent_refuses_an_invalid_target_from_the_api(sent, monkeypatch) -> None:
    """The agent does not trust the API blindly."""

    def forbidden(target):
        raise AssertionError("must not scan")

    monkeypatch.setattr(agent, "scan_target", forbidden)

    run_job({"job_id": "j1", "target": "x; rm -rf /"}, "http://api")

    assert sent["results"][0][1]["status"] == "failed"


def _stop_after(count: int):
    calls = {"count": 0}

    def wait(seconds: float) -> None:
        calls["count"] += 1
        if calls["count"] >= count:
            raise StopWatching

    return wait


def test_watch_reports_on_start_then_runs_orders(monkeypatch) -> None:
    """The dashboard gets fresh data as soon as the agent starts."""
    reports, jobs = [], []
    answers = iter([{"job": {"job_id": "j1", "target": None}}, {"job": None}])
    monkeypatch.setattr(agent, "collect_host_report", lambda: {"scan_type": "host"})
    monkeypatch.setattr(agent, "send_report", lambda document, url: reports.append(document))
    monkeypatch.setattr(agent, "api_post", lambda url, path, payload, timeout=30: next(answers))
    monkeypatch.setattr(agent, "run_job", lambda job, url: jobs.append(job["job_id"]))

    with pytest.raises(StopWatching):
        watch("http://api", log=lambda message: None, wait=_stop_after(2))

    assert len(reports) == 1
    assert jobs == ["j1"]


def test_watch_survives_an_api_outage(monkeypatch) -> None:
    """The agent keeps retrying, and logs the outage once rather than on every poll."""
    messages = []
    answers = iter([ApiError("down."), ApiError("down."), {"job": None}])

    def post(url, path, payload, timeout=30):
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(agent, "collect_host_report", dict)
    monkeypatch.setattr(agent, "send_report", lambda document, url: None)
    monkeypatch.setattr(agent, "api_post", post)

    with pytest.raises(StopWatching):
        watch("http://api", log=messages.append, wait=_stop_after(3))

    assert messages == [
        "down. Waiting for it to come back.",
        "Connected to http://api. Waiting for orders from the dashboard.",
    ]


def test_watch_does_nothing_while_the_api_is_down(monkeypatch) -> None:
    """Without Docker the agent must sleep: no collection, and rare connection attempts."""
    delays = []

    def post(url, path, payload, timeout=30):
        raise ApiError("down.")

    def forbidden():
        raise AssertionError("nothing to collect while the API is down")

    def wait(seconds: float) -> None:
        delays.append(seconds)
        if len(delays) >= 5:
            raise StopWatching

    monkeypatch.setattr(agent, "collect_host_report", forbidden)
    monkeypatch.setattr(agent, "api_post", post)

    with pytest.raises(StopWatching):
        watch("http://api", log=lambda message: None, wait=wait)

    assert delays == [agent.IDLE_SECONDS] * 5


def test_watch_sends_a_fresh_report_each_time_the_api_comes_back(monkeypatch) -> None:
    """Starting Docker gives an up-to-date view, once, without any continuous scan."""
    reports = []
    answers = iter([{"job": None}, {"job": None}, ApiError("down."), {"job": None}, {"job": None}])

    def post(url, path, payload, timeout=30):
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(agent, "collect_host_report", lambda: {"scan_type": "host"})
    monkeypatch.setattr(agent, "send_report", lambda document, url: reports.append(document))
    monkeypatch.setattr(agent, "api_post", post)

    with pytest.raises(StopWatching):
        watch("http://api", log=lambda message: None, wait=_stop_after(5))

    assert len(reports) == 2
