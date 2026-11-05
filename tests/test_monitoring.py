"""Tests for silence detection, triage expiry, and the background agent."""

from datetime import UTC, datetime, timedelta

import pytest

from attacklens import pipeline, service
from attacklens.models import Finding
from attacklens.pipeline import SilenceMonitor
from attacklens.results import (
    active_decision,
    apply_triage,
    build_document,
    finding_fingerprint,
)
from attacklens.storage import Store

THRESHOLD = 300
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_webhook(monkeypatch) -> None:
    """Keep the tests away from any configured webhook."""
    monkeypatch.delenv("ATTACKLENS_ALERT_WEBHOOK_URL", raising=False)


def _seen_at(store, moment: datetime) -> None:
    store.touch_agent("pc", "Windows", "0.1.0", "10.0.0.5")
    with store._connect() as connection:
        connection.execute("UPDATE agents SET last_seen = ?", (moment.isoformat(),))


def _monitor_past_grace(store) -> tuple[SilenceMonitor, datetime]:
    monitor = SilenceMonitor(store, THRESHOLD)
    monitor.tick(START)
    now = START
    while now <= START + timedelta(seconds=THRESHOLD):
        now += timedelta(seconds=30)
        monitor.tick(now)
    return monitor, now


def test_silent_agent_raises_one_alert(store) -> None:
    """Silence is reported once, not on every check."""
    _seen_at(store, START)
    monitor, now = _monitor_past_grace(store)

    monitor.tick(now + timedelta(seconds=30))
    monitor.tick(now + timedelta(seconds=60))

    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert "stopped reporting" in alerts[0]["message"]
    assert alerts[0]["target"] == "pc"
    assert store.list_agents()[0]["silent_since"]


def test_returning_agent_clears_the_silence(store) -> None:
    """The user learns when monitoring is back."""
    _seen_at(store, START)
    monitor, now = _monitor_past_grace(store)

    _seen_at(store, now)
    monitor.tick(now + timedelta(seconds=30))

    assert "reporting again" in store.list_alerts()[0]["message"]
    assert store.list_agents()[0]["silent_since"] is None


def test_healthy_agent_stays_quiet(store) -> None:
    """An agent calling in regularly raises nothing."""
    monitor = SilenceMonitor(store, THRESHOLD)
    now = START
    for _ in range(30):
        _seen_at(store, now)
        monitor.tick(now)
        now += timedelta(seconds=30)

    assert store.list_alerts() == []


def test_no_alert_right_after_the_api_starts(store) -> None:
    """After a reboot the API may start before the agent."""
    _seen_at(store, START - timedelta(hours=9))
    monitor = SilenceMonitor(store, THRESHOLD)

    monitor.tick(START)
    monitor.tick(START + timedelta(seconds=30))

    assert store.list_alerts() == []


def test_no_alert_when_the_machine_just_woke_up(store) -> None:
    """During sleep both the API and the agent stop: that is not an incident."""
    _seen_at(store, START)
    monitor, now = _monitor_past_grace(store)
    store.set_agent_silent("pc", None)
    with store._connect() as connection:
        connection.execute("DELETE FROM alerts")

    monitor.tick(now + timedelta(hours=8))

    assert store.list_alerts() == []


def test_touch_keeps_the_silence_marker(store) -> None:
    """The monitor, not the heartbeat, closes a silence: that is what raises the alert."""
    store.touch_agent("pc", "Windows", "0.1.0", "10.0.0.5")
    store.set_agent_silent("pc", START.isoformat())

    store.touch_agent("pc", "Windows", "0.1.0", "10.0.0.5")

    assert store.list_agents()[0]["silent_since"] == START.isoformat()


def test_silence_threshold_is_configurable(monkeypatch) -> None:
    """Too low a value would alert on every restart."""
    monkeypatch.setenv("ATTACKLENS_AGENT_SILENCE_SECONDS", "600")
    assert pipeline.silence_threshold() == 600
    monkeypatch.setenv("ATTACKLENS_AGENT_SILENCE_SECONDS", "1")
    assert pipeline.silence_threshold() == 30
    monkeypatch.setenv("ATTACKLENS_AGENT_SILENCE_SECONDS", "soon")
    assert pipeline.silence_threshold() == pipeline.DEFAULT_SILENCE_SECONDS


def _finding(version: str | None = "1.0") -> Finding:
    return Finding(
        "network", "high", "SMB", "d", target="h", port=445, service="SMB", version=version
    )


def _decision(**overrides) -> dict:
    finding = _finding().to_dict()
    return {
        "status": "accepted",
        "reason": "lab",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "fingerprint": finding_fingerprint(finding),
        **overrides,
    }


def test_decision_applies_while_nothing_changed() -> None:
    """A valid acceptance stays in force."""
    decision, lapsed = active_decision(_finding().to_dict(), _decision())

    assert decision["status"] == "accepted"
    assert lapsed is None


def test_decision_lapses_at_expiry() -> None:
    """Accepted risks do not stay accepted forever."""
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()

    assert active_decision(_finding().to_dict(), _decision(expires_at=past)) == ({}, "expired")


def test_decision_lapses_when_the_finding_changes() -> None:
    """A new version is not what was accepted."""
    changed = _finding(version="2.0").to_dict()

    assert active_decision(changed, _decision()) == ({}, "changed")


def test_lapsed_decision_counts_in_the_score_again() -> None:
    """A lapsed acceptance must reopen the finding everywhere."""
    finding = _finding()
    document = build_document([finding], "h", "network")
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()

    triaged = apply_triage(document, {finding.stable_id(): _decision(expires_at=past)})

    assert triaged["findings"][0]["triage_status"] == "open"
    assert triaged["findings"][0]["triage_lapsed"] == "expired"
    assert triaged["score"] == 80


def test_decisions_from_earlier_versions_keep_working() -> None:
    """Rows without expiry or fingerprint stay valid until reviewed."""
    decision, lapsed = active_decision(_finding().to_dict(), {"status": "accepted"})

    assert decision["status"] == "accepted"
    assert lapsed is None


def test_api_sets_a_default_expiry_and_fingerprint(client, store) -> None:
    """Accepting without a duration still has an end date."""
    finding = _finding()
    store.save_scan(build_document([finding], "h", "network"))

    answer = client.put(f"/api/findings/{finding.stable_id()}/triage", json={"status": "accepted"})

    expires_at = datetime.fromisoformat(answer.json()["expires_at"])
    assert timedelta(days=89) < expires_at - datetime.now(UTC) < timedelta(days=91)
    assert store.triage_statuses()[finding.stable_id()]["fingerprint"]


def test_api_accepts_a_custom_duration(client, store) -> None:
    """The user can decide for how long."""
    finding = _finding()
    store.save_scan(build_document([finding], "h", "network"))

    answer = client.put(
        f"/api/findings/{finding.stable_id()}/triage", json={"status": "accepted", "days": 7}
    )

    expires_at = datetime.fromisoformat(answer.json()["expires_at"])
    assert expires_at - datetime.now(UTC) < timedelta(days=8)


def test_api_refuses_to_triage_an_unknown_finding(client) -> None:
    """A decision needs something to apply to."""
    answer = client.put(f"/api/findings/{'a' * 64}/triage", json={"status": "accepted"})

    assert answer.status_code == 404


def test_old_database_gains_the_new_columns(tmp_path) -> None:
    """Upgrading must keep existing decisions."""
    path = tmp_path / "attacklens.db"
    store = Store(path)
    store.set_triage("abc", "accepted", "old")
    with store._connect() as connection:
        connection.execute("ALTER TABLE finding_triage DROP COLUMN expires_at")
        connection.execute("ALTER TABLE finding_triage DROP COLUMN fingerprint")
        connection.execute("ALTER TABLE agents DROP COLUMN silent_since")
        connection.execute("PRAGMA user_version=2")

    upgraded = Store(path)

    assert upgraded.triage_statuses()["abc"]["expires_at"] is None
    assert upgraded.list_agents() == []


def test_windows_task_runs_with_limited_rights() -> None:
    """The background agent must not run elevated."""
    script = service.windows_install_script("http://127.0.0.1:8000")

    assert "-RunLevel Limited" in script
    assert "-AtLogOn" in script
    assert "-RestartCount" in script
    assert "--watch" in script
    assert "SYSTEM" not in script


def test_reinstall_replaces_the_running_agent() -> None:
    """Otherwise an update would keep running the old code."""
    script = service.windows_install_script("http://127.0.0.1:8000")

    assert script.index("Stop-ScheduledTask") < script.index("Register-ScheduledTask")


def test_powershell_quoting_survives_an_apostrophe() -> None:
    """A path such as C:\\Users\\d'Arc must not break out of the string."""
    assert service._quote("C:\\Users\\d'Arc") == "'C:\\Users\\d''Arc'"


def test_systemd_unit_restarts_the_agent() -> None:
    """The Linux unit stays unprivileged and restarts on failure."""
    unit = service.systemd_unit("http://127.0.0.1:8000")

    assert "Restart=always" in unit
    assert "NoNewPrivileges=true" in unit
    assert "agent --watch" in unit


def test_file_logger_rotates(tmp_path, monkeypatch) -> None:
    """The log of a permanent agent must not grow forever."""
    monkeypatch.setattr(service, "MAX_LOG_BYTES", 10)
    path = tmp_path / "agent.log"
    log = service.file_logger(str(path))

    log("first message, long enough")
    log("second message")

    assert "second" in path.read_text(encoding="utf-8")
    assert "first" in path.with_suffix(".old.log").read_text(encoding="utf-8")


def test_agent_survives_a_failing_collector(monkeypatch) -> None:
    """A transient OS error must not end a permanent agent."""
    from attacklens import agent

    calls = {"count": 0}

    def fail():
        raise OSError("transient")

    def stop(seconds: float) -> None:
        calls["count"] += 1
        if calls["count"] >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent, "collect_host_report", fail)
    monkeypatch.setattr(agent, "api_post", lambda *args, **kwargs: {"job": None})
    messages: list[str] = []

    with pytest.raises(KeyboardInterrupt):
        agent.watch("http://api", log=messages.append, wait=stop)

    assert "Collection failed: transient" in messages
