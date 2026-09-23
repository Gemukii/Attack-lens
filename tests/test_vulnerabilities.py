"""Tests for package vulnerability lookup."""

import json

from attacklens import vulnerabilities


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "PYSEC-TEST-0001",
                                "aliases": ["CVE-2026-0001"],
                                "summary": "Test advisory",
                                "details": "Test details",
                                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                                "references": [{"url": "https://example.test/advisory"}],
                                "affected": [
                                    {"ranges": [{"events": [{"fixed": "1.2.4"}]}]}
                                ],
                            }
                        ]
                    }
                ]
            }
        ).encode()


def test_query_package_vulnerabilities_maps_osv_results(monkeypatch) -> None:
    """OSV results should retain package and version context."""
    monkeypatch.setattr(vulnerabilities, "urlopen", lambda request, timeout: FakeResponse())

    report = vulnerabilities.query_package_vulnerabilities(
        [{"name": "example-package", "version": "1.2.3"}]
    )

    assert report["status"] == "complete"
    assert report["packages_checked"] == 1
    assert report["vulnerabilities"][0]["id"] == "PYSEC-TEST-0001"
    assert report["vulnerabilities"][0]["package"] == "example-package"
    assert report["vulnerabilities"][0]["fixed_versions"] == ["1.2.4"]
    assert report["vulnerabilities"][0]["remediation"] == "Upgrade example-package to version 1.2.4 or newer."
    assert report["vulnerabilities"][0]["references"] == ["https://example.test/advisory"]
    assert report["vulnerabilities"][0]["severity"] == "9.8"


def test_query_package_vulnerabilities_is_non_fatal(monkeypatch) -> None:
    """An unavailable advisory service should return an explicit status."""
    def fail(request, timeout):
        raise OSError("offline")

    monkeypatch.setattr(vulnerabilities, "urlopen", fail)

    report = vulnerabilities.query_package_vulnerabilities(
        [{"name": "example-package", "version": "1.2.3"}]
    )

    assert report["status"] == "unavailable"
    assert report["vulnerabilities"] == []