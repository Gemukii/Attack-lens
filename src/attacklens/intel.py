"""Exploitation intelligence: which vulnerabilities attackers really use.

CISA KEV lists vulnerabilities exploited in the wild, and EPSS estimates how likely
exploitation is. KEV is a plain download. EPSS receives the CVE identifiers, so both
stay behind the same opt-in as OSV.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
EPSS_BATCH = 100
KEV_CACHE_HOURS = 24

_kev_cache: dict[str, Any] = {"loaded_at": None, "cves": set()}


def _get_json(url: str, timeout: float) -> Any:
    """Download a JSON document."""
    request = Request(url, headers={"User-Agent": "AttackLens/0.1"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def known_exploited(timeout: float = 15.0) -> set[str] | None:
    """Return the CVEs of the KEV catalog, or None if it could not be read."""
    loaded_at = _kev_cache["loaded_at"]
    if loaded_at and datetime.now(UTC) - loaded_at < timedelta(hours=KEV_CACHE_HOURS):
        return _kev_cache["cves"]
    try:
        body = _get_json(KEV_URL, timeout)
        cves = {item["cveID"] for item in body["vulnerabilities"]}
    except (OSError, URLError, TimeoutError, ValueError, KeyError, TypeError):
        return None
    _kev_cache.update(loaded_at=datetime.now(UTC), cves=cves)
    return cves


def epss_scores(cves: list[str], timeout: float = 15.0) -> dict[str, float]:
    """Return the probability of exploitation of each CVE, for those known to EPSS."""
    scores: dict[str, float] = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = ",".join(quote(cve) for cve in cves[start : start + EPSS_BATCH])
        try:
            body = _get_json(f"{EPSS_URL}{batch}", timeout)
            scores.update({item["cve"]: float(item["epss"]) for item in body["data"]})
        except (OSError, URLError, TimeoutError, ValueError, KeyError, TypeError):
            continue
    return scores


def cve_of(entry: dict[str, Any]) -> str | None:
    """Return the CVE identifier of an advisory."""
    candidates = [entry.get("id") or "", *entry.get("aliases", [])]
    for candidate in candidates:
        if candidate.startswith("CVE-"):
            return candidate
        if "-CVE-" in candidate:
            return candidate[candidate.index("CVE-") :]
    return None


def enrich(report: dict[str, Any]) -> dict[str, Any]:
    """Add the exploitation data to a vulnerability report."""
    entries = report.get("vulnerabilities", [])
    for entry in entries:
        entry["cve"] = cve_of(entry)
    cves = sorted({entry["cve"] for entry in entries if entry["cve"]})
    if not cves:
        return report

    catalog = known_exploited()
    scores = epss_scores(cves)
    for entry in entries:
        entry["known_exploited"] = None if catalog is None else entry["cve"] in catalog
        entry["epss"] = scores.get(entry["cve"])
    return report
