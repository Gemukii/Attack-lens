"""Package vulnerability lookup through the OSV public database."""

import json
from urllib.error import URLError
from urllib.request import Request, urlopen
from typing import Any

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def query_package_vulnerabilities(
    packages: list[dict[str, str]],
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Look up PyPI packages and return a non-fatal vulnerability report."""
    checked_packages = [
        package for package in packages if package.get("name") and package.get("version")
    ]
    queries = [
        {
            "package": {"name": package["name"], "ecosystem": "PyPI"},
            "version": package["version"],
        }
        for package in checked_packages
    ]
    if not queries:
        return {"status": "complete", "packages_checked": 0, "vulnerabilities": []}

    payload = json.dumps({"queries": queries}).encode("utf-8")
    request = Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "AttackLens/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, json.JSONDecodeError):
        return {
            "status": "unavailable",
            "packages_checked": len(queries),
            "vulnerabilities": [],
        }

    vulnerabilities: list[dict[str, Any]] = []
    for package, result in zip(checked_packages, body.get("results", []), strict=False):
        for vulnerability in result.get("vulns", []):
            fixed_versions = sorted(
                {
                    change["fixed"]
                    for affected in vulnerability.get("affected", [])
                    for version_range in affected.get("ranges", [])
                    for change in version_range.get("events", [])
                    if change.get("fixed")
                }
            )
            references = [
                reference["url"]
                for reference in vulnerability.get("references", [])
                if reference.get("url")
            ]
            severity = next(
                (
                    item.get("score")
                    for item in vulnerability.get("severity", [])
                    if item.get("score")
                ),
                None,
            )
            vulnerabilities.append(
                {
                    "id": vulnerability.get("id"),
                    "aliases": vulnerability.get("aliases", []),
                    "summary": vulnerability.get("summary") or vulnerability.get("details", ""),
                    "details": vulnerability.get("details", ""),
                    "modified": vulnerability.get("modified"),
                    "package": package["name"],
                    "version": package["version"],
                    "fixed_versions": fixed_versions,
                    "references": references,
                    "severity": severity,
                    "remediation": (
                        f"Upgrade {package['name']} to version {fixed_versions[0]} or newer."
                        if fixed_versions
                        else f"Upgrade {package['name']} to the latest secure version and review the advisory."
                    ),
                }
            )

    return {
        "status": "complete",
        "packages_checked": len(queries),
        "vulnerabilities": vulnerabilities,
    }
