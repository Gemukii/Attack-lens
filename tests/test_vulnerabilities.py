"""Tests for package vulnerability lookup.

The fake below reproduces the real OSV contract: `querybatch` only returns `id` and
`modified`, and details come from `GET /v1/vulns/{id}`.
"""

import io
import json

import pytest

from attacklens import vulnerabilities

ADVISORY = {
    "id": "GHSA-test-0001",
    "modified": "2026-01-01T00:00:00Z",
    "aliases": ["CVE-2026-0001"],
    "summary": "Test advisory",
    "details": "Test details",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "HIGH"},
    "references": [{"url": "https://example.test/advisory"}],
    "affected": [
        {
            "package": {"name": "example-package", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}],
        },
        {
            "package": {"name": "example-package", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "2.0.1"}]}],
        },
        {
            "package": {"name": "unrelated", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"fixed": "9.9.9"}]}],
        },
    ],
}


class FakeOSV:
    """Answer like api.osv.dev."""

    def __init__(self) -> None:
        self.batch_results = [
            {"vulns": [{"id": ADVISORY["id"], "modified": ADVISORY["modified"]}]}
        ]
        self.advisories = {ADVISORY["id"]: ADVISORY}
        self.requests: list[str] = []
        self.batches: list[dict] = []

    def __call__(self, request, timeout):
        self.requests.append(request.full_url)
        if request.full_url == vulnerabilities.OSV_BATCH_URL:
            self.batches.append(json.loads(request.data))
            return io.BytesIO(json.dumps({"results": self.batch_results}).encode())
        identifier = request.full_url.rsplit("/", 1)[1]
        if identifier not in self.advisories:
            raise OSError("not found")
        return io.BytesIO(json.dumps(self.advisories[identifier]).encode())


@pytest.fixture
def osv(monkeypatch) -> FakeOSV:
    """Replace the network with a fake OSV."""
    fake = FakeOSV()
    monkeypatch.setattr(vulnerabilities, "urlopen", fake)
    vulnerabilities._details_cache.clear()
    return fake


PACKAGE = [{"name": "example-package", "version": "1.2.3"}]


def test_details_are_fetched_after_the_batch_query(osv) -> None:
    """The batch only names advisories: details need a second request."""
    report = vulnerabilities.query_package_vulnerabilities(PACKAGE)

    assert report["status"] == "complete"
    assert report["packages_checked"] == 1
    entry = report["vulnerabilities"][0]
    assert entry["id"] == "GHSA-test-0001"
    assert entry["package"] == "example-package"
    assert entry["summary"] == "Test advisory"
    assert entry["severity"] == "high"
    assert entry["cvss_vector"].startswith("CVSS:3.1")
    assert entry["references"] == ["https://example.test/advisory"]


def test_fix_versions_belong_to_the_checked_package(osv) -> None:
    """Fixes of other packages in the same advisory must be ignored."""
    entry = vulnerabilities.query_package_vulnerabilities(PACKAGE)["vulnerabilities"][0]

    assert entry["fixed_versions"] == ["1.2.4", "2.0.1"]
    assert entry["remediation"] == "Upgrade example-package to version 1.2.4 or newer."


def test_remediation_targets_the_fix_above_the_installed_version(osv) -> None:
    """A fix older than the installed version would be useless advice."""
    packages = [{"name": "example-package", "version": "2.0.0"}]

    entry = vulnerabilities.query_package_vulnerabilities(packages)["vulnerabilities"][0]

    assert entry["remediation"] == "Upgrade example-package to version 2.0.1 or newer."


def test_pagination_is_followed(osv, monkeypatch) -> None:
    """OSV paginates per query through next_page_token."""
    pages = iter(
        [
            [{"vulns": [{"id": ADVISORY["id"]}], "next_page_token": "page-2"}],
            [{"vulns": [{"id": ADVISORY["id"], "modified": "other"}]}],
        ]
    )
    original = osv.__call__

    def paginated(request, timeout):
        if request.full_url == vulnerabilities.OSV_BATCH_URL:
            osv.batch_results = next(pages)
        return original(request, timeout)

    monkeypatch.setattr(vulnerabilities, "urlopen", paginated)

    report = vulnerabilities.query_package_vulnerabilities(PACKAGE)

    assert len(report["vulnerabilities"]) == 2
    assert osv.batches[1]["queries"][0]["page_token"] == "page-2"


def test_missing_details_make_the_report_partial(osv) -> None:
    """An advisory without details stays listed, and the report says it is incomplete."""
    osv.advisories.clear()

    report = vulnerabilities.query_package_vulnerabilities(PACKAGE)

    assert report["status"] == "partial"
    assert report["vulnerabilities"][0]["id"] == "GHSA-test-0001"


def test_detail_limit_makes_the_report_partial(osv) -> None:
    """Truncating the advisories must be visible in the status."""
    report = vulnerabilities.query_package_vulnerabilities(PACKAGE, max_details=0)

    assert report["status"] == "partial"
    assert report["advisories_found"] == 1
    assert report["vulnerabilities"] == []


def test_ecosystem_is_forwarded(osv) -> None:
    """System packages are looked up in their own ecosystem."""
    vulnerabilities.query_package_vulnerabilities(PACKAGE, ecosystem="Debian:12")

    assert osv.batches[0]["queries"][0]["package"]["ecosystem"] == "Debian:12"


def test_unavailable_service_is_non_fatal(monkeypatch) -> None:
    """An unavailable advisory service should return an explicit status."""

    def fail(request, timeout):
        raise OSError("offline")

    monkeypatch.setattr(vulnerabilities, "urlopen", fail)

    report = vulnerabilities.query_package_vulnerabilities(PACKAGE)

    assert report["status"] == "unavailable"
    assert report["vulnerabilities"] == []


def test_malformed_response_is_tolerated(osv) -> None:
    """Unexpected OSV shapes should not break the API endpoint."""
    osv.batch_results = [None]

    report = vulnerabilities.query_package_vulnerabilities(PACKAGE)

    assert report["status"] == "complete"
    assert report["vulnerabilities"] == []


def test_osv_is_opt_in(monkeypatch) -> None:
    """Package names must not leave the machine by default."""
    monkeypatch.delenv("ATTACKLENS_ENABLE_OSV", raising=False)
    assert vulnerabilities.osv_enabled() is False

    monkeypatch.setenv("ATTACKLENS_ENABLE_OSV", "true")
    assert vulnerabilities.osv_enabled() is True
