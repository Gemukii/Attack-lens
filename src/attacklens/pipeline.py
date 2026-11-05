"""What happens to a finished scan: storage, change detection, and alerting."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from attacklens.results import (
    ACTIVE_TRIAGE_STATUS,
    SEVERITY_ORDER,
    active_decision,
    compare_documents,
    severity_at_least,
)
from attacklens.storage import Store

MAX_MESSAGE_LENGTH = 1900
DEFAULT_ALERT_SEVERITY = "low"
DEFAULT_SILENCE_SECONDS = 300
MONITOR_INTERVAL_SECONDS = 30
BACKUPS_KEPT = 14
DEFAULT_RETENTION_DAYS = 365
# Only present in reports that carry a posture section.
POSTURE_CATEGORIES = {"posture", "persistence", "software"}


def alert_threshold() -> str:
    """Return the lowest severity worth an alert."""
    configured = os.getenv("ATTACKLENS_ALERT_MIN_SEVERITY", DEFAULT_ALERT_SEVERITY).strip().lower()
    return configured if configured in SEVERITY_ORDER else DEFAULT_ALERT_SEVERITY


def format_alert(target: str, findings: list[dict[str, Any]]) -> str:
    """Summarize new findings, within the size accepted by chat webhooks."""
    lines = [f"AttackLens: {len(findings)} new finding(s) on {target}"]
    lines += [f"- [{finding['severity'].upper()}] {finding['title']}" for finding in findings]
    message = "\n".join(lines)
    return message if len(message) <= MAX_MESSAGE_LENGTH else f"{message[:MAX_MESSAGE_LENGTH]}..."


def send_webhook(message: str) -> bool:
    """Post an alert to the user's webhook. Discord reads content, Slack reads text."""
    url = os.getenv("ATTACKLENS_ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return False
    request = Request(
        url,
        data=json.dumps({"content": message, "text": message}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "AttackLens/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5):
            return True
    except (OSError, URLError, TimeoutError, ValueError):
        return False


def has_full_posture(document: dict[str, Any]) -> bool:
    """Return whether every posture collector of a report succeeded."""
    return (
        document.get("posture", {}).get("status") == "complete"
        and document.get("outdated_status") == "complete"
    )


def _new_posture_findings(
    baseline: dict[str, Any] | None, document: dict[str, Any]
) -> list[dict[str, Any]]:
    """Compare posture findings with the last report where they could all be read.

    A collection can fail once. Its report lists nothing, and must not make everything
    look new in the next one.
    """
    if baseline is None or not has_full_posture(document):
        return []
    known = {finding.get("finding_id") for finding in baseline.get("findings", [])}
    return [
        finding
        for finding in document["findings"]
        if finding.get("category") in POSTURE_CATEGORIES and finding["finding_id"] not in known
    ]


def new_alertable_findings(
    previous: dict[str, Any],
    document: dict[str, Any],
    statuses: dict[str, dict[str, Any]],
    posture_baseline: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return findings that appeared since the baseline and that nobody dismissed."""
    threshold = alert_threshold()
    other_findings = [
        finding
        for finding in compare_documents(previous, document)["new_findings"]
        if finding.get("category") not in POSTURE_CATEGORIES
    ]
    return [
        finding
        for finding in [*other_findings, *_new_posture_findings(posture_baseline, document)]
        # A new autostart entry is informational by itself, and still always worth a look.
        if severity_at_least(finding.get("severity"), threshold)
        or finding.get("category") == "persistence"
        if active_decision(finding, statuses.get(finding["finding_id"]))[0].get(
            "status", ACTIVE_TRIAGE_STATUS
        )
        == ACTIVE_TRIAGE_STATUS
    ]


def ingest(store: Store, document: dict[str, Any]) -> list[dict[str, Any]]:
    """Store a scan and alert on new findings. Return the findings alerted on.

    The first scan of an asset is a baseline, and a scan that observed nothing cannot
    show that anything changed, so neither produces alerts.
    """
    previous = store.previous_complete_scan(document)
    store.save_scan(document)
    if previous is None or document.get("status") != "complete":
        return []

    baseline = next(
        (
            scan
            for scan in store.list_scans(
                limit=20, scan_type=document["scan_type"], target=document["target"]
            )
            if scan["scan_id"] != document["scan_id"] and has_full_posture(scan)
        ),
        None,
    )
    findings = new_alertable_findings(previous, document, store.triage_statuses(), baseline)
    if findings:
        message = format_alert(document["target"], findings)
        store.add_alert(
            scan_id=document["scan_id"],
            target=document["target"],
            message=message,
            findings=findings,
            delivered=send_webhook(message),
        )
    return findings


def backup_directory() -> Path | None:
    """Return where daily backups go, if configured."""
    configured = os.getenv("ATTACKLENS_BACKUP_DIR", "").strip()
    return Path(configured) if configured else None


def run_backup(store: Store, directory: Path, keep: int = BACKUPS_KEPT) -> Path:
    """Write a dated backup and remove the oldest ones."""
    destination = directory / f"attacklens-{datetime.now(UTC):%Y%m%d-%H%M%S}.db"
    store.backup(destination)
    for old in sorted(directory.glob("attacklens-*.db"))[:-keep]:
        old.unlink()
    return destination


def daily_maintenance(store: Store) -> None:
    """Apply the retention policy and back the database up."""
    try:
        days = int(os.getenv("ATTACKLENS_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
    except ValueError:
        days = DEFAULT_RETENTION_DAYS
    store.prune(max(days, 1))
    directory = backup_directory()
    if directory is not None:
        try:
            run_backup(store, directory)
        except OSError as error:
            store.add_audit("system", "backup_failed", str(error))


def silence_threshold() -> int:
    """Return how long an agent may stay quiet before it is reported."""
    try:
        return max(30, int(os.getenv("ATTACKLENS_AGENT_SILENCE_SECONDS", "")))
    except ValueError:
        return DEFAULT_SILENCE_SECONDS


class SilenceMonitor:
    """Reports agents that stopped calling in.

    A monitoring tool that goes quiet looks exactly like a healthy machine, and killing
    the agent is the first thing an intruder would do. The API therefore has to notice
    the absence itself. It waits one full threshold after starting, or after the machine
    slept, so that an agent gets the time to reconnect.
    """

    def __init__(self, store: Store, threshold: int | None = None) -> None:
        self.store = store
        self.threshold = timedelta(seconds=threshold or silence_threshold())
        self.grace_until: datetime | None = None
        self.last_tick: datetime | None = None

    def _report(self, hostname: str, message: str) -> None:
        self.store.add_alert(
            scan_id="",
            target=hostname,
            message=message,
            findings=[],
            delivered=send_webhook(message),
        )

    def tick(self, now: datetime | None = None) -> None:
        """Compare each agent's last call with the current time."""
        now = now or datetime.now(UTC)
        interrupted = self.last_tick is not None and (
            now - self.last_tick > timedelta(seconds=MONITOR_INTERVAL_SECONDS * 3)
        )
        if self.last_tick is None or interrupted:
            self.grace_until = now + self.threshold
        self.last_tick = now
        if self.grace_until is not None and now < self.grace_until:
            return

        for agent in self.store.list_agents():
            last_seen = datetime.fromisoformat(agent["last_seen"])
            quiet = now - last_seen > self.threshold
            if quiet and not agent.get("silent_since"):
                self.store.set_agent_silent(agent["hostname"], now.isoformat())
                self._report(
                    agent["hostname"],
                    f"AttackLens: the agent on {agent['hostname']} stopped reporting. "
                    "The machine is no longer monitored.",
                )
            elif not quiet and agent.get("silent_since"):
                self.store.set_agent_silent(agent["hostname"], None)
                self._report(
                    agent["hostname"],
                    f"AttackLens: the agent on {agent['hostname']} is reporting again.",
                )
