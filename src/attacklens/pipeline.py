"""What happens to a finished scan: storage, change detection, and alerting."""

import json
import os
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from attacklens.results import (
    ACTIVE_TRIAGE_STATUS,
    SEVERITY_ORDER,
    compare_documents,
    severity_at_least,
)
from attacklens.storage import Store

MAX_MESSAGE_LENGTH = 1900
DEFAULT_ALERT_SEVERITY = "low"


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


def new_alertable_findings(
    previous: dict[str, Any], document: dict[str, Any], statuses: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return findings that appeared since the baseline and that nobody dismissed."""
    threshold = alert_threshold()
    return [
        finding
        for finding in compare_documents(previous, document)["new_findings"]
        if severity_at_least(finding.get("severity"), threshold)
        if statuses.get(finding["finding_id"], {}).get("status", ACTIVE_TRIAGE_STATUS)
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

    findings = new_alertable_findings(previous, document, store.triage_statuses())
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
