"""Scan result documents for AttackLens."""

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from attacklens.models import Finding

SEVERITY_WEIGHTS = {"critical": 35, "high": 20, "medium": 10, "low": 4}
# A service proved unreachable from outside weighs less than one nobody has tested.
REACHABILITY_WEIGHTS = {"exposed": 1.0, "unverified": 1.0, "shielded": 0.25, "local": 0.1}
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
ACTIVE_TRIAGE_STATUS = "open"


def score_from_severities(severities: Iterable[str]) -> int:
    """Calculate the bounded exposure score from finding severities."""
    penalty = sum(SEVERITY_WEIGHTS.get(severity.lower(), 0) for severity in severities)
    return max(0, min(100, 100 - penalty))


def calculate_score(findings: list[Finding]) -> int:
    """Calculate the bounded exposure score of a list of findings."""
    return score_from_severities(finding.severity for finding in findings)


def severity_at_least(severity: str | None, threshold: str) -> bool:
    """Return whether a severity reaches a threshold."""
    value = (severity or "").lower()
    return value in SEVERITY_ORDER and (
        SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(threshold)
    )


def build_document(
    findings: list[Finding],
    target: str,
    scan_type: str,
    status: str = "complete",
    duration_seconds: float | None = None,
    scan_id: str | None = None,
    coverage: dict[str, int] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the document stored and returned for one scan."""
    document: dict[str, Any] = {
        "scan_id": scan_id or str(uuid4()),
        "target": target,
        "scan_type": scan_type,
        "status": status,
        "findings": [finding.to_dict() for finding in findings],
        "completed_at": datetime.now(UTC).isoformat(),
        # A scan that observed nothing proves nothing, so it has no score.
        "score": calculate_score(findings) if status == "complete" else None,
        "coverage": coverage or {},
        "open_ports": [
            finding.port
            for finding in findings
            if finding.category == "network" and finding.port is not None
        ],
        "services": [
            {
                "name": finding.service or finding.title,
                "port": finding.port,
                "protocol": finding.protocol,
                "version": finding.version,
                "banner": finding.banner,
            }
            for finding in findings
            if finding.category == "network"
        ],
    }
    if duration_seconds is not None:
        document["duration_seconds"] = round(duration_seconds, 3)
    if extra:
        document.update(extra)
    return document


def network_document(
    scan: Any, target: str, duration_seconds: float, vantage: str = "host"
) -> dict[str, Any]:
    """Build the document of a finished network scan, run from `vantage`."""
    return build_document(
        findings=scan.findings,
        target=target,
        scan_type="network",
        status=scan.status,
        duration_seconds=duration_seconds,
        coverage=scan.coverage(),
        extra={
            "vantage": vantage,
            "port_states": {str(port): state for port, state in scan.port_states.items()},
        },
    )


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Summarize what a triage decision was based on."""
    values = [finding.get(key) for key in ("severity", "version", "exposure", "service")]
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()[:16]


def active_decision(
    finding: dict[str, Any], decision: dict[str, Any] | None
) -> tuple[dict[str, Any], str | None]:
    """Return the decision still in force, and why it lapsed if it did.

    Accepting a risk is a judgment about a situation at a point in time: it stops
    applying when it expires, or as soon as the finding is not what was accepted.
    """
    if not decision:
        return {}, None
    expires_at = decision.get("expires_at")
    if expires_at and expires_at <= datetime.now(UTC).isoformat():
        return {}, "expired"
    fingerprint = decision.get("fingerprint")
    if fingerprint and fingerprint != finding_fingerprint(finding):
        return {}, "changed"
    return decision, None


def probe_document(scan: Any, target: str, duration_seconds: float) -> dict[str, Any]:
    """Build the document of a scan run from another machine."""
    return {
        **network_document(scan, target, duration_seconds, vantage="external"),
        "scan_type": "probe",
    }


def apply_triage(document: dict[str, Any], statuses: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Return a copy of a scan with triage decisions and an updated score."""
    findings = []
    for finding in document.get("findings", []):
        decision, lapsed = active_decision(finding, statuses.get(finding.get("finding_id", "")))
        findings.append(
            {
                **finding,
                "triage_status": decision.get("status", ACTIVE_TRIAGE_STATUS),
                "triage_reason": decision.get("reason"),
                "triage_expires_at": decision.get("expires_at"),
                "triage_lapsed": lapsed,
            }
        )

    triaged = {**document, "findings": findings}
    if document.get("score") is not None:
        triaged["raw_score"] = document["score"]
        penalty = sum(
            SEVERITY_WEIGHTS.get((finding.get("severity") or "").lower(), 0)
            * REACHABILITY_WEIGHTS.get(finding.get("reachability"), 1.0)
            for finding in findings
            if finding["triage_status"] == ACTIVE_TRIAGE_STATUS
        )
        triaged["score"] = max(0, min(100, round(100 - penalty)))
    return triaged


def compare_documents(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Classify the changes between two scans of the same asset."""
    before_findings = {finding["finding_id"]: finding for finding in before["findings"]}
    after_findings = {finding["finding_id"]: finding for finding in after["findings"]}
    before_keys = set(before_findings)
    after_keys = set(after_findings)
    before_ports = set(before.get("open_ports", []))
    after_ports = set(after.get("open_ports", []))
    scores_known = before.get("score") is not None and after.get("score") is not None

    return {
        "before_id": before.get("scan_id"),
        "after_id": after.get("scan_id"),
        "score_delta": after["score"] - before["score"] if scores_known else None,
        "finding_count_delta": len(after_findings) - len(before_findings),
        "new_findings": [after_findings[key] for key in sorted(after_keys - before_keys)],
        "fixed_findings": [before_findings[key] for key in sorted(before_keys - after_keys)],
        "persistent_findings": [after_findings[key] for key in sorted(after_keys & before_keys)],
        "ports_added": sorted(after_ports - before_ports),
        "ports_removed": sorted(before_ports - after_ports),
    }
