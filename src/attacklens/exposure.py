"""Correlates the inside and outside views of a machine.

The agent knows what listens, but connecting to your own address does not go through
your firewall. A probe from another machine knows what is reachable, but not what
listens. A verdict needs both.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from attacklens.storage import Store

PROBE_VALID_DAYS = 7

LOCAL = "local"
SHIELDED = "shielded"
EXPOSED = "exposed"
UNVERIFIED = "unverified"


def find_probe(store: Store, host_report: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the latest recent probe of this machine."""
    if host_report is None:
        return None
    names = {host_report["target"], *host_report.get("addresses", [])}
    limit = (datetime.now(UTC) - timedelta(days=PROBE_VALID_DAYS)).isoformat()
    for probe in store.list_scans(limit=50, scan_type="probe"):
        if probe["target"] in names and probe.get("completed_at", "") >= limit:
            return probe
    return None


def port_verdict(bound_to: str | None, port: int, probe: dict[str, Any] | None) -> str:
    """Return how far a listening port can really be reached."""
    if bound_to == "loopback":
        return LOCAL
    if probe is None:
        return UNVERIFIED
    if probe.get("status") == "no_response":
        return SHIELDED
    state = (probe.get("port_states") or {}).get(str(port))
    if state is None:
        return UNVERIFIED
    return EXPOSED if state == "open" else SHIELDED


def annotate(
    document: dict[str, Any], host_report: dict[str, Any] | None, probe: dict[str, Any] | None
) -> dict[str, Any]:
    """Return a copy of a scan where each port finding says if it is really reachable."""
    if host_report is None:
        return document
    bound = {
        listener["port"]: listener["exposure"]
        for listener in host_report.get("listeners", {}).get("items", [])
    }
    findings = [
        {**finding, "reachability": port_verdict(bound.get(finding["port"]), finding["port"], probe)}
        if finding.get("port")
        else finding
        for finding in document.get("findings", [])
    ]
    return {**document, "findings": findings}


def exposure_report(
    host_report: dict[str, Any] | None, probe: dict[str, Any] | None
) -> dict[str, Any]:
    """Summarize the verdict for each listening port."""
    if host_report is None:
        return {"status": "no_host_report", "listeners": [], "summary": {}, "probe": None}

    listeners = [
        {
            "port": listener["port"],
            "process": listener["process"],
            "bound_to": listener["exposure"],
            "verdict": port_verdict(listener["exposure"], listener["port"], probe),
        }
        for listener in host_report.get("listeners", {}).get("items", [])
    ]
    counts = {verdict: 0 for verdict in (EXPOSED, SHIELDED, UNVERIFIED, LOCAL)}
    for listener in listeners:
        counts[listener["verdict"]] += 1

    addresses = host_report.get("addresses") or ["<address of this machine>"]
    ports = sorted({item["port"] for item in listeners if item["bound_to"] != "loopback"})
    command = f"attacklens probe {addresses[0]} --ports {','.join(map(str, ports))} --output probe.json"
    return {
        "status": "verified" if probe else "unverified",
        "listeners": listeners,
        "summary": counts,
        "probe": (
            {
                "target": probe["target"],
                "completed_at": probe.get("completed_at"),
                "status": probe.get("status"),
            }
            if probe
            else None
        ),
        "probe_command": command,
    }
