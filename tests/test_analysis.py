"""Tests for active checks, exploitation data, risk, attack paths, and audit support."""

import io
import json
import socketserver
import struct
import threading
from datetime import UTC, datetime, timedelta

import pytest

from attacklens import audit, checks, host, intel
from attacklens.audit import OutOfScope, enforce_scope, is_in_scope, parse_scope, render_report
from attacklens.checks import (
    CONFIRMED,
    MITIGATED,
    check_docker_api,
    check_elasticsearch,
    check_memcached,
    check_redis,
    check_smb,
    smb_negotiate_request,
    verify_service,
)
from attacklens.models import Finding
from attacklens.paths import attack_paths
from attacklens.results import apply_triage, build_document
from attacklens.risk import assess
from attacklens.scanner import resolve_target
from attacklens.web import api


def test_redis_without_authentication_is_proved() -> None:
    """An open Redis stops being a guess."""
    result = check_redis(b"+PONG\r\n")

    assert (result.state, result.severity) == (CONFIRMED, "critical")


def test_redis_with_authentication_is_downgraded() -> None:
    """A protected Redis is not the same risk."""
    result = check_redis(b"-NOAUTH Authentication required.\r\n")

    assert (result.state, result.severity) == (MITIGATED, "medium")


def test_unknown_answers_prove_nothing() -> None:
    """Another service on the port must not be misread."""
    assert check_redis(b"HTTP/1.1 400 Bad Request") is None
    assert check_memcached(b"ERROR") is None
    assert check_docker_api(b"HTTP/1.1 404 Not Found\r\n\r\n") is None
    assert check_elasticsearch(b"HTTP/1.1 500 Oops\r\n\r\n") is None


def test_docker_api_and_elasticsearch_are_recognized() -> None:
    """These answers are specific enough to conclude."""
    docker = b'HTTP/1.1 200 OK\r\n\r\n{"ApiVersion":"1.45"}'
    elastic = b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"x"}'

    assert check_docker_api(docker).severity == "critical"
    assert check_elasticsearch(elastic).state == CONFIRMED
    assert check_elasticsearch(b"HTTP/1.1 401 Unauthorized\r\n\r\n").state == MITIGATED
    assert check_memcached(b"VERSION 1.6.21\r\n").state == CONFIRMED


def _smb_response(security_mode: int) -> bytes:
    message = b"\xfeSMB" + b"\x00" * 60 + struct.pack("<HH", 65, security_mode) + b"\x00" * 60
    return struct.pack(">I", len(message)) + message


def test_smb_signing_is_read_from_the_negotiation() -> None:
    """The flag comes before any authentication."""
    assert check_smb(_smb_response(0x0001)).state == CONFIRMED
    assert check_smb(_smb_response(0x0003)).state == MITIGATED
    assert check_smb(b"garbage") is None


def test_smb_request_is_a_valid_frame() -> None:
    """The NetBIOS length must match, or a real server drops the connection."""
    request = smb_negotiate_request()

    assert struct.unpack(">I", request[:4])[0] == len(request) - 4
    assert request[4:8] == b"\xfeSMB"
    assert struct.unpack_from("<H", request, 4 + 64)[0] == 36


class Echo(socketserver.BaseRequestHandler):
    """Answers like a Redis server without a password."""

    def handle(self) -> None:
        self.request.recv(64)
        self.request.sendall(b"+PONG\r\n")


def test_check_runs_over_a_real_socket(monkeypatch) -> None:
    """The exchange works against a real listener."""
    server = socketserver.TCPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    real_exchange = checks._exchange
    monkeypatch.setattr(
        checks,
        "_exchange",
        lambda address, _, request, timeout: real_exchange(address, port, request, timeout),
    )

    result = verify_service("127.0.0.1", resolve_target("127.0.0.1"), 6379)

    server.shutdown()
    server.server_close()
    assert result.state == CONFIRMED


def test_tls_failure_does_not_skip_the_legacy_test(monkeypatch) -> None:
    """Regression: a server limited to TLS 1.0 made the first handshake fail."""
    attempts = []

    class FakeContext:
        check_hostname = True
        verify_mode = None
        minimum_version = None
        maximum_version = None

        def set_ciphers(self, ciphers) -> None:
            pass

        def wrap_socket(self, raw, server_hostname):
            attempts.append(self.maximum_version)
            if self.maximum_version is None:
                raise checks.ssl.SSLError("no shared protocol")
            return raw

    server = socketserver.TCPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    monkeypatch.setattr(checks.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(checks.ssl, "SSLContext", lambda protocol: FakeContext())

    result = checks.check_tls("127.0.0.1", resolve_target("127.0.0.1"), port, 1)

    server.shutdown()
    server.server_close()
    assert len(attempts) == 2
    assert result.detail == "TLS 1.0 or 1.1 is still accepted."


def test_failed_check_proves_nothing() -> None:
    """A closed port or an error is not evidence."""
    assert verify_service("127.0.0.1", resolve_target("127.0.0.1"), 6379, timeout=0.2) is None


def test_ports_without_a_check_are_skipped() -> None:
    """No request is sent where no check exists."""
    assert verify_service("127.0.0.1", resolve_target("127.0.0.1"), 22) is None


class FakeFeeds:
    """Answers like CISA and FIRST."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, request, timeout):
        self.urls.append(request.full_url)
        if request.full_url == intel.KEV_URL:
            body = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        else:
            body = {"data": [{"cve": "CVE-2024-0001", "epss": "0.97"}]}
        return io.BytesIO(json.dumps(body).encode())


@pytest.fixture
def feeds(monkeypatch) -> FakeFeeds:
    """Replace the network with fake feeds."""
    fake = FakeFeeds()
    monkeypatch.setattr(intel, "urlopen", fake)
    intel._kev_cache.update(loaded_at=None, cves=set())
    return fake


def test_exploitation_data_reaches_the_advisory(feeds) -> None:
    """KEV and EPSS apply through CVE aliases."""
    report = {
        "vulnerabilities": [
            {"id": "GHSA-x", "aliases": ["CVE-2024-0001"]},
            {"id": "DEBIAN-CVE-2024-0002", "aliases": []},
        ]
    }

    intel.enrich(report)

    first, second = report["vulnerabilities"]
    assert first["known_exploited"] is True
    assert first["epss"] == 0.97
    assert second["cve"] == "CVE-2024-0002"
    assert second["known_exploited"] is False


def test_catalog_is_cached(feeds) -> None:
    """The catalog does not change on every scan."""
    intel.known_exploited()
    intel.known_exploited()

    assert feeds.urls.count(intel.KEV_URL) == 1


def test_unavailable_catalog_is_not_a_clean_answer(monkeypatch) -> None:
    """No data must stay distinguishable from `not exploited`."""

    def fail(request, timeout):
        raise OSError("offline")

    monkeypatch.setattr(intel, "urlopen", fail)
    intel._kev_cache.update(loaded_at=None, cves=set())
    report = {"vulnerabilities": [{"id": "CVE-2024-0001", "aliases": []}]}

    intel.enrich(report)

    assert report["vulnerabilities"][0]["known_exploited"] is None


def test_exploited_flaw_becomes_critical_even_without_a_fix() -> None:
    """Active exploitation outranks the advisory's own rating."""
    report = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "package": "openssl",
                "version": "3.0",
                "summary": "Bad",
                "severity": "low",
                "remediation": "Upgrade",
                "references": [],
                "fixed_versions": [],
                "known_exploited": True,
                "cve": "CVE-2024-0001",
            }
        ]
    }

    findings = host.vulnerability_findings("pc", report)

    assert findings[0].severity == "critical"
    assert findings[0].known_exploited is True


def _risk(**fields) -> dict:
    return assess({"severity": "high", **fields})


def test_reachability_drives_the_priority() -> None:
    """The same flaw is not as urgent behind a firewall."""
    exposed = _risk(reachability="exposed", verification="confirmed")
    shielded = _risk(reachability="shielded", verification="confirmed")

    assert exposed["priority"] == "now"
    assert shielded["priority"] == "soon"
    assert exposed["score"] > shielded["score"]


def test_exploitation_drives_the_priority() -> None:
    """A flaw used by attackers comes first."""
    known = _risk(reachability="exposed", known_exploited=True)
    plain = _risk(reachability="exposed")

    assert known["score"] > plain["score"]
    assert "CISA KEV" in known["exploitability"]


def test_mitigated_service_drops_in_priority() -> None:
    """Proof of protection counts as much as proof of weakness."""
    assert _risk(reachability="exposed", verification="mitigated")["priority"] == "later"


def test_high_epss_raises_exploitability() -> None:
    """EPSS below the threshold changes nothing."""
    assert "EPSS 90%" in _risk(epss=0.9)["exploitability"]
    assert _risk(epss=0.1)["exploitability"] == "assumed"


def test_risk_explains_itself() -> None:
    """A priority without a reason would not be trusted."""
    risk = assess({"severity": "low"})

    assert risk["reachability"] == "no network path"
    assert set(risk) == {"score", "priority", "impact", "reachability", "exploitability"}


def test_shielded_service_weighs_less_in_the_score() -> None:
    """Proving the firewall blocks a port raises the score."""
    finding = Finding("network", "high", "SMB", "d", target="h", port=445)
    document = build_document([finding], "h", "network")
    document["findings"][0]["reachability"] = "shielded"

    assert apply_triage(document, {})["score"] == 95


def _finding(**fields) -> dict:
    defaults = {"severity": "high", "triage_status": "open", "finding_id": fields.get("title", "x")}
    return {**defaults, **fields}


ADMIN = _finding(title="The daily account is an administrator", remediation="Use a standard account")
SMB = _finding(title="SMB", port=445, service="SMB", remediation="Stop SMB")
POSTGRES = _finding(title="DB", port=5432, service="PostgreSQL", remediation="Bind to localhost")


def _ids(result: dict) -> list[str]:
    return [path["id"] for path in result["paths"]]


def test_chain_needs_every_link() -> None:
    """A reachable service alone is not a takeover path."""
    assert _ids(attack_paths([SMB])) == []
    assert _ids(attack_paths([ADMIN])) == []
    assert _ids(attack_paths([SMB, ADMIN])) == ["remote-takeover"]


def test_shielded_entry_breaks_the_chain() -> None:
    """A port proved blocked is not a way in."""
    shielded = {**SMB, "reachability": "shielded"}

    assert _ids(attack_paths([shielded, ADMIN])) == []


def test_loopback_service_is_not_an_entry() -> None:
    """Other machines cannot reach it."""
    local = {**POSTGRES, "exposure": "loopback"}

    assert _ids(attack_paths([local])) == []


def test_certainty_follows_the_evidence() -> None:
    """Only a probe from outside confirms an entry point."""
    assert attack_paths([SMB, ADMIN])["paths"][0]["certainty"] == "potential"
    exposed = {**SMB, "reachability": "exposed"}
    assert attack_paths([exposed, ADMIN])["paths"][0]["certainty"] == "confirmed"


def test_open_database_is_a_confirmed_critical_path() -> None:
    """A database answering without a password needs no more proof."""
    redis = _finding(title="Redis", port=6379, service="Redis", verification="confirmed")

    path = attack_paths([redis])["paths"][0]

    assert path["severity"] == "critical"
    assert path["certainty"] == "confirmed"


def test_dismissed_findings_do_not_build_paths() -> None:
    """An accepted link is a decision that was taken."""
    accepted = {**SMB, "triage_status": "accepted"}

    assert attack_paths([accepted, ADMIN])["paths"] == []


def test_paths_are_sorted_and_the_best_cut_is_named() -> None:
    """The answer to `what do I fix first?`."""
    outdated = _finding(title="Update available: Git", category="software", severity="low")

    result = attack_paths([SMB, POSTGRES, ADMIN, outdated])

    assert _ids(result)[0] == "data-theft"
    assert result["best_cut"]["title"] == ADMIN["title"]
    assert result["best_cut"]["paths_broken"] == 2


def test_path_lists_every_possible_entry() -> None:
    """The dashboard draws each entry point, not only the one the path names."""
    rdp = _finding(title="RDP", port=3389, service="RDP")

    path = attack_paths([SMB, rdp, ADMIN])["paths"][0]

    assert set(path["entries"]) == {SMB["finding_id"], rdp["finding_id"]}


def test_clean_machine_has_no_path() -> None:
    """No finding, no invented story."""
    assert attack_paths([]) == {"paths": [], "best_cut": None}


def test_scope_accepts_networks_only() -> None:
    """Names are refused: they can be repointed after the authorization."""
    assert parse_scope(["192.168.1.0/24", " 10.0.0.5 "]) == ["192.168.1.0/24", "10.0.0.5/32"]
    with pytest.raises(ValueError, match="Invalid scope"):
        parse_scope(["client.example"])
    with pytest.raises(ValueError, match="at least one"):
        parse_scope([])


def test_every_address_must_be_in_scope() -> None:
    """A name resolving partly outside the scope is refused."""
    assert is_in_scope({"192.168.1.5"}, ["192.168.1.0/24"])
    assert not is_in_scope({"192.168.1.5", "8.8.8.8"}, ["192.168.1.0/24"])
    assert not is_in_scope(set(), ["192.168.1.0/24"])


def _engagement(start: int = -1, end: int = 1, scope: tuple = ("127.0.0.0/8",)) -> dict:
    now = datetime.now(UTC)
    return {
        "name": "Test",
        "authorized_by": "Owner",
        "reference": "REF-1",
        "scope": list(scope),
        "starts_at": (now + timedelta(days=start)).isoformat(),
        "ends_at": (now + timedelta(days=end)).isoformat(),
    }


def test_scope_uses_the_resolved_address() -> None:
    """The check looks at where a target really points."""
    assert enforce_scope("127.0.0.1", [_engagement()])["name"] == "Test"
    with pytest.raises(OutOfScope, match="outside the scope"):
        enforce_scope("127.0.0.1", [_engagement(scope=("10.0.0.0/8",))])


def test_expired_engagement_authorizes_nothing() -> None:
    """Authorization has dates."""
    with pytest.raises(OutOfScope, match="no engagement"):
        enforce_scope("127.0.0.1", [_engagement(start=-3, end=-2)])


def test_audit_mode_blocks_scans_outside_the_scope(client, store, monkeypatch) -> None:
    """Enforced by the API, not by good intentions."""
    monkeypatch.setenv("ATTACKLENS_AUDIT_MODE", "true")

    answer = client.post("/api/scan", json={"target": "127.0.0.1"})

    assert answer.status_code == 403
    assert store.list_audit()[0]["action"] == "scan_refused"


def test_audit_mode_allows_scans_inside_the_scope(client, monkeypatch) -> None:
    """Within the engagement, scans run normally."""
    from attacklens.scanner import NetworkScan

    monkeypatch.setenv("ATTACKLENS_AUDIT_MODE", "true")
    monkeypatch.setattr(api, "scan_network", lambda target: NetworkScan(ports_closed=1))
    assert client.post("/api/engagements", json=_engagement()).status_code == 201

    assert client.post("/api/scan", json={"target": "127.0.0.1"}).status_code == 200


def test_engagement_validation(client) -> None:
    """Scope and dates are checked when the engagement is recorded."""
    assert client.post("/api/engagements", json=_engagement(scope=("client.example",))).status_code == 422
    assert client.post("/api/engagements", json=_engagement(start=2, end=1)).status_code == 422


def test_scope_is_not_enforced_outside_audit_mode(monkeypatch) -> None:
    """Personal use keeps working without engagements."""
    monkeypatch.delenv("ATTACKLENS_AUDIT_MODE", raising=False)

    assert audit.audit_mode_enabled() is False


def test_report_escapes_what_came_from_the_network() -> None:
    """A hostile banner must not become a script in the report."""
    hostile = {
        "title": "<script>alert(1)</script>",
        "severity": "high",
        "evidence": "<img src=x onerror=alert(1)>",
        "risk": {"priority": "now", "score": 90},
    }
    html = render_report(
        "<b>pc</b>",
        {"findings": [hostile]},
        None,
        {"paths": [], "best_cut": None},
        None,
    )

    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "SHA-256 of this report" in html


def test_report_is_served_with_paths_and_sorted_findings(client, store) -> None:
    """The report brings the views of a machine together."""
    findings = [
        Finding("network", "low", "HTTP", "d", target="pc", port=80),
        Finding("network", "critical", "Telnet", "d", target="pc", port=23, service="Telnet"),
    ]
    store.save_scan(build_document(findings, "pc", "network"))
    store.save_scan(build_document([], "pc", "host"))

    answer = client.get("/api/report?target=pc")

    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith("text/html")
    assert answer.text.index("Telnet") < answer.text.index("HTTP")
    assert store.list_audit()[0]["action"] == "report_generated"


def test_report_without_data_is_a_404(client) -> None:
    """Nothing to report is not an empty report."""
    assert client.get("/api/report").status_code == 404


def test_api_serves_paths_and_risk(client, store) -> None:
    """The dashboard reads priorities and chains from the API."""
    store.save_scan(
        build_document(
            [Finding("network", "high", "SMB", "d", target="pc", port=445, service="SMB")],
            "pc",
            "network",
        )
    )
    admin = Finding("posture", "low", "The daily account is an administrator", "d", target="pc")
    store.save_scan(build_document([admin], "pc", "host"))

    assert client.get("/api/results").json()["findings"][0]["risk"]["priority"]
    assert client.get("/api/paths").json()["paths"][0]["id"] == "remote-takeover"
