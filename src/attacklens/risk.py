"""Risk model: how urgent is a finding, really?

Risk = impact x reachability x exploitability. A flaw used by attackers on a service
anyone can reach comes before ten theoretical ones behind a firewall. Every factor is
returned, so that a priority can always be explained.
"""

from typing import Any

IMPACT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.05}
REACHABILITY = {"exposed": 1.0, "unverified": 0.7, "shielded": 0.3, "local": 0.1}
# A finding without a port is about the machine itself, not about a network path.
NO_NETWORK_PATH = 0.6

BASE_EXPLOITABILITY = 0.6
CONFIRMED_EXPLOITABILITY = 1.0
MITIGATED_EXPLOITABILITY = 0.25
LIKELY_EPSS = 0.5

NOW_THRESHOLD = 60
SOON_THRESHOLD = 21


def exploitability(finding: dict[str, Any]) -> tuple[float, str]:
    """Return how easily a finding can be used, and why."""
    if finding.get("known_exploited"):
        return CONFIRMED_EXPLOITABILITY, "exploited in the wild (CISA KEV)"
    if finding.get("verification") == "confirmed":
        return CONFIRMED_EXPLOITABILITY, "confirmed by an active check"
    if finding.get("verification") == "mitigated":
        return MITIGATED_EXPLOITABILITY, "mitigated, checked actively"
    epss = finding.get("epss")
    if epss is not None and epss >= LIKELY_EPSS:
        return max(BASE_EXPLOITABILITY, epss), f"EPSS {epss:.0%}"
    return BASE_EXPLOITABILITY, "assumed"


def assess(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the risk of one finding, with the factors behind it."""
    impact = IMPACT.get((finding.get("severity") or "").lower(), IMPACT["info"])
    reachability_name = finding.get("reachability")
    reach = REACHABILITY.get(reachability_name, NO_NETWORK_PATH)
    exploit, reason = exploitability(finding)
    score = round(100 * impact * reach * exploit)

    if score >= NOW_THRESHOLD:
        priority = "now"
    elif score >= SOON_THRESHOLD:
        priority = "soon"
    else:
        priority = "later"
    return {
        "score": score,
        "priority": priority,
        "impact": impact,
        "reachability": reachability_name or "no network path",
        "exploitability": reason,
    }


def assess_document(document: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a scan with the risk of each finding."""
    return {
        **document,
        "findings": [
            {**finding, "risk": assess(finding)} for finding in document.get("findings", [])
        ],
    }
