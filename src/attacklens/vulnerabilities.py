"""Package vulnerability lookup through the OSV public database.

The batch endpoint only returns advisory identifiers, so each advisory is then
fetched individually. Lookups send package names to a third party and are therefore
opt-in through ``ATTACKLENS_ENABLE_OSV``.
"""

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 1000
MAX_ADVISORY_DETAILS = 200
DETAIL_WORKERS = 8

_details_cache: dict[tuple[str, str | None], dict[str, Any]] = {}


def osv_enabled() -> bool:
    """Return whether the user allowed package names to be sent to OSV."""
    return os.getenv("ATTACKLENS_ENABLE_OSV", "").strip().lower() in {"1", "true", "yes"}


def _request_json(url: str, timeout: float, payload: dict[str, Any] | None = None) -> Any:
    """Call OSV and decode its JSON response."""
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json", "User-Agent": "AttackLens/0.1"},
        method="POST" if payload is not None else "GET",
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _query_identifiers(
    queries: list[dict[str, Any]], timeout: float
) -> list[list[dict[str, Any]]] | None:
    """Return advisory references per query, following OSV pagination."""
    references: list[list[dict[str, Any]]] = [[] for _ in queries]
    pending = list(enumerate(queries))

    while pending:
        batch, pending = pending[:OSV_BATCH_SIZE], pending[OSV_BATCH_SIZE:]
        try:
            body = _request_json(OSV_BATCH_URL, timeout, {"queries": [q for _, q in batch]})
        except (OSError, URLError, TimeoutError, json.JSONDecodeError):
            return None
        if not isinstance(body, dict) or not isinstance(body.get("results"), list):
            return None

        for (index, query), result in zip(batch, body["results"], strict=False):
            if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                continue
            references[index].extend(
                item for item in result.get("vulns", []) if isinstance(item, dict)
            )
            if result.get("next_page_token"):
                pending.append((index, {**query, "page_token": result["next_page_token"]}))

    return references


def _fetch_details(reference: dict[str, Any], timeout: float) -> dict[str, Any] | None:
    """Return one full advisory, reusing it while OSV reports no modification."""
    identifier = reference.get("id")
    if not identifier:
        return None
    key = (identifier, reference.get("modified"))
    if key in _details_cache:
        return _details_cache[key]
    try:
        details = _request_json(f"{OSV_VULN_URL}{quote(identifier, safe='')}", timeout)
    except (OSError, URLError, TimeoutError, json.JSONDecodeError):
        return None
    if not isinstance(details, dict):
        return None
    _details_cache[key] = details
    return details


def _normalize(name: str) -> str:
    """Normalize a package name the way PyPI does."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _fixed_versions(advisory: dict[str, Any], package: str) -> list[str]:
    """Return the versions fixing this advisory for this package only."""
    fixed: set[str] = set()
    for affected in advisory.get("affected", []):
        if not isinstance(affected, dict):
            continue
        affected_name = (affected.get("package") or {}).get("name")
        if affected_name and _normalize(affected_name) != _normalize(package):
            continue
        for version_range in affected.get("ranges", []):
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events", []):
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _next_fixed_version(fixed_versions: list[str], installed: str) -> str | None:
    """Return the closest fix above the installed version."""
    try:
        current = Version(installed)
        candidates = sorted(
            (Version(version), version)
            for version in fixed_versions
            if Version(version) > current
        )
    except InvalidVersion:
        return fixed_versions[-1] if fixed_versions else None
    return candidates[0][1] if candidates else None


def _severity(advisory: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return the severity label and the CVSS vector of an advisory."""
    database = advisory.get("database_specific")
    label = database.get("severity") if isinstance(database, dict) else None
    vector = next(
        (
            item.get("score")
            for item in advisory.get("severity", [])
            if isinstance(item, dict) and item.get("score")
        ),
        None,
    )
    return (label.lower() if isinstance(label, str) else None), vector


def _map_advisory(
    reference: dict[str, Any], advisory: dict[str, Any] | None, package: dict[str, str]
) -> dict[str, Any]:
    """Build a report entry, keeping the identifier when details are missing."""
    details = advisory or {}
    fixed_versions = _fixed_versions(details, package["name"])
    next_fix = _next_fixed_version(fixed_versions, package["version"])
    severity, cvss_vector = _severity(details)
    references = [
        item["url"]
        for item in details.get("references", [])
        if isinstance(item, dict) and item.get("url")
    ]
    return {
        "id": reference.get("id"),
        "aliases": details.get("aliases", []),
        "summary": details.get("summary") or details.get("details", ""),
        "details": details.get("details", ""),
        "modified": details.get("modified") or reference.get("modified"),
        "package": package["name"],
        "version": package["version"],
        "fixed_versions": fixed_versions,
        "references": references,
        "severity": severity,
        "cvss_vector": cvss_vector,
        "remediation": (
            f"Upgrade {package['name']} to version {next_fix} or newer."
            if next_fix
            else f"Upgrade {package['name']} to the latest secure version and review the advisory."
        ),
    }


def query_package_vulnerabilities(
    packages: list[dict[str, str]],
    ecosystem: str = "PyPI",
    timeout_seconds: float = 10.0,
    max_details: int = MAX_ADVISORY_DETAILS,
) -> dict[str, Any]:
    """Look up packages and return a non-fatal vulnerability report."""
    checked_packages = [
        package for package in packages if package.get("name") and package.get("version")
    ]
    if not checked_packages:
        return {"status": "complete", "packages_checked": 0, "vulnerabilities": []}

    queries = [
        {
            "package": {"name": package["name"], "ecosystem": ecosystem},
            "version": package["version"],
        }
        for package in checked_packages
    ]
    references_by_package = _query_identifiers(queries, timeout_seconds)
    if references_by_package is None:
        return {
            "status": "unavailable",
            "packages_checked": len(checked_packages),
            "vulnerabilities": [],
        }

    matches = [
        (package, reference)
        for package, references in zip(checked_packages, references_by_package, strict=True)
        for reference in references
    ]
    selected = matches[:max_details]
    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as executor:
        advisories = list(
            executor.map(lambda match: _fetch_details(match[1], timeout_seconds), selected)
        )

    incomplete = len(matches) > len(selected) or any(item is None for item in advisories)
    return {
        "status": "partial" if incomplete else "complete",
        "packages_checked": len(checked_packages),
        "advisories_found": len(matches),
        "vulnerabilities": [
            _map_advisory(reference, advisory, package)
            for (package, reference), advisory in zip(selected, advisories, strict=True)
        ],
    }
