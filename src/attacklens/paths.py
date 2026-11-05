"""Attack paths: how separate findings chain into a real compromise.

Each rule describes a known way in. A path only exists when every link is backed by a
finding, and it says how certain it is: `confirmed` when reachability was proved from
another machine, `potential` otherwise. The result answers the question that matters
most to whoever has limited time: which single fix breaks the most paths?
"""

from collections import Counter
from typing import Any

REMOTE_ACCESS_PORTS = {135, 139, 445, 3389, 5985, 5986, 22, 5900, 23}
DATA_PORTS = {1433, 3306, 5432, 6379, 9200, 11211, 27017}
DOCKER_PORTS = {2375, 2376}
SHIELDED_VERDICTS = {"local", "shielded"}


def _step(stage: str, label: str, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Describe one link of a chain."""
    return {
        "stage": stage,
        "label": label,
        "finding_id": finding.get("finding_id") if finding else None,
    }


def _reachable(findings: list[dict[str, Any]], ports: set[int]) -> list[dict[str, Any]]:
    """Return findings on these ports that another machine may be able to reach."""
    return [
        finding
        for finding in findings
        if finding.get("port") in ports
        and finding.get("exposure", "all") != "loopback"
        and finding.get("reachability") not in SHIELDED_VERDICTS
    ]


def _titled(findings: list[dict[str, Any]], title: str) -> dict[str, Any] | None:
    """Return the finding with this title."""
    return next((finding for finding in findings if finding.get("title") == title), None)


def _certainty(entries: list[dict[str, Any]]) -> str:
    """A path is confirmed once an entry point was proved reachable from outside."""
    proved = any(entry.get("reachability") == "exposed" for entry in entries)
    return "confirmed" if proved else "potential"


def _name(finding: dict[str, Any]) -> str:
    """Return a short name for a service finding."""
    label = finding.get("service") or finding.get("process") or "service"
    return f"{label} ({finding.get('port')}/tcp)"


def _remote_takeover(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    entries = _reachable(findings, REMOTE_ACCESS_PORTS)
    admin = _titled(findings, "The daily account is an administrator")
    if not entries or admin is None:
        return None
    return {
        "id": "remote-takeover",
        "title": "Remote takeover through an administration service",
        "severity": "high",
        "certainty": _certainty(entries),
        "steps": [
            _step("Entry", f"Reach {_name(entries[0])} from the network", entries[0]),
            _step("Access", "Stolen or guessed credentials of the daily account"),
            _step("Privilege", "That account is an administrator", admin),
            _step("Impact", "Full control of the machine"),
        ],
    }


def _data_theft(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    entries = _reachable(findings, DATA_PORTS)
    if not entries:
        return None
    entry = next((item for item in entries if item.get("verification") == "confirmed"), entries[0])
    open_door = entry.get("verification") == "confirmed"
    return {
        "id": "data-theft",
        "title": "Direct access to a database",
        "severity": "critical" if open_door else "high",
        "certainty": "confirmed" if open_door else _certainty(entries),
        "steps": [
            _step("Entry", f"Reach {_name(entry)} from the network", entry),
            _step(
                "Access",
                "No authentication is required" if open_door else "Guess or reuse a password",
            ),
            _step("Impact", "Read or alter the stored data"),
        ],
    }


def _docker_takeover(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    entries = _reachable(findings, DOCKER_PORTS)
    if not entries:
        return None
    return {
        "id": "docker-takeover",
        "title": "Host takeover through the Docker API",
        "severity": "critical",
        "certainty": _certainty(entries),
        "steps": [
            _step("Entry", f"Reach {_name(entries[0])}", entries[0]),
            _step("Access", "Start a privileged container"),
            _step("Impact", "Root access to the host"),
        ],
    }


def _exploited_flaw(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    flaw = next((item for item in findings if item.get("known_exploited")), None)
    if flaw is None:
        return None
    return {
        "id": "exploited-flaw",
        "title": "A flaw used by attackers today",
        "severity": "critical",
        "certainty": "confirmed",
        "steps": [
            _step("Entry", f"{flaw.get('cve') or flaw.get('title')} is in the CISA KEV list", flaw),
            _step("Impact", "Public exploits exist for this flaw"),
        ],
    }


def _malware_chain(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    outdated = [item for item in findings if item.get("category") == "software"]
    admin = _titled(findings, "The daily account is an administrator")
    if not outdated or admin is None:
        return None
    return {
        "id": "malware-chain",
        "title": "A malicious file escalates to full control",
        "severity": "medium",
        "certainty": "potential",
        "steps": [
            _step("Entry", f"Malicious file targets one of {len(outdated)} outdated programs"),
            _step("Execution", "Code runs in the daily session"),
            _step("Privilege", "One consent prompt from administrator rights", admin),
            _step("Impact", "Persistence and full control of the machine"),
        ],
    }


def _device_theft(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    disk = _titled(findings, "The system disk is not encrypted")
    if disk is None:
        return None
    return {
        "id": "device-theft",
        "title": "A stolen laptop gives up its data",
        "severity": "medium",
        "certainty": "confirmed",
        "steps": [
            _step("Entry", "Physical access to the laptop"),
            _step("Access", "The disk can be read from another system", disk),
            _step("Impact", "All local files and saved credentials"),
        ],
    }


def _open_firewall(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    firewall = _titled(findings, "Host firewall does not block inbound traffic")
    entries = _reachable(findings, REMOTE_ACCESS_PORTS | DATA_PORTS)
    if firewall is None or not entries:
        return None
    return {
        "id": "open-firewall",
        "title": "Nothing stands between the network and these services",
        "severity": "high",
        "certainty": "confirmed",
        "steps": [
            _step("Entry", "The firewall lets inbound traffic through", firewall),
            _step("Access", f"{len(entries)} sensitive services are directly reachable", entries[0]),
            _step("Impact", "Each of them becomes a way in"),
        ],
    }


ENTRY_PORTS = {
    "remote-takeover": REMOTE_ACCESS_PORTS,
    "data-theft": DATA_PORTS,
    "docker-takeover": DOCKER_PORTS,
    "open-firewall": REMOTE_ACCESS_PORTS | DATA_PORTS,
}


def _entry_ids(path_id: str, findings: list[dict[str, Any]]) -> list[str]:
    """Return every finding that can start a path, not only the one it names."""
    ports = ENTRY_PORTS.get(path_id, set())
    return [item["finding_id"] for item in _reachable(findings, ports) if item.get("finding_id")]


RULES = (
    _exploited_flaw,
    _docker_takeover,
    _data_theft,
    _open_firewall,
    _remote_takeover,
    _malware_chain,
    _device_theft,
)
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def attack_paths(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the attack paths backed by these findings, and the best fix."""
    active = [item for item in findings if item.get("triage_status", "open") == "open"]
    paths = [path for rule in RULES if (path := rule(active)) is not None]
    for path in paths:
        path["entries"] = _entry_ids(path["id"], active)
    paths.sort(
        key=lambda path: (SEVERITY_RANK[path["severity"]], path["certainty"] != "confirmed")
    )

    links = Counter(
        step["finding_id"]
        for path in paths
        for step in path["steps"]
        if step["finding_id"]
    )
    best_cut = None
    if links:
        finding_id, broken = links.most_common(1)[0]
        finding = next(item for item in active if item.get("finding_id") == finding_id)
        best_cut = {
            "finding_id": finding_id,
            "title": finding.get("title"),
            "remediation": finding.get("remediation"),
            "paths_broken": broken,
        }
    return {"paths": paths, "best_cut": best_cut}
