"""Tests for the AttackLens network scanner."""

import http.server
import socket
import threading

import pytest

from attacklens import scanner
from attacklens.scanner import (
    STATUS_COMPLETE,
    STATUS_NO_RESPONSE,
    NetworkScan,
    TargetResolutionError,
    classify_service,
    identify_service,
    parse_server_header,
    parse_ssh_version,
    probe_port,
    resolve_target,
    scan_network,
)


class QuietHandler(http.server.BaseHTTPRequestHandler):
    """Answer like a real web server, with a Server header."""

    server_version = "nginx/1.18.0"
    sys_version = ""

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def http_server():
    """Run a real HTTP server on a free local port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_probe_port_detects_open_port(http_server) -> None:
    """An accepting socket is open."""
    assert probe_port(resolve_target("127.0.0.1"), http_server) == "open"


def test_probe_port_detects_closed_port() -> None:
    """A refused connection proves the host is alive and the port closed."""
    assert probe_port(resolve_target("127.0.0.1"), 1) == "closed"


def test_probe_port_reports_silence_as_filtered(monkeypatch) -> None:
    """A timeout says nothing about the port, so it must not read as closed."""

    class SilentSocket:
        def __init__(self, *args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

        def settimeout(self, timeout) -> None:
            pass

        def connect(self, address) -> None:
            raise TimeoutError

    monkeypatch.setattr(scanner.socket, "socket", SilentSocket)

    assert probe_port(resolve_target("127.0.0.1"), 80, timeout=0.1) == "filtered"


def test_identify_service_reads_server_header_from_a_real_server(http_server) -> None:
    """The version must come from an actual HTTP response, not from a stub."""
    address = resolve_target("127.0.0.1")

    version, banner = identify_service("127.0.0.1", address, http_server, "HTTP")

    assert version == "nginx/1.18.0"
    assert "nginx/1.18.0" in banner


def test_parse_server_header_ignores_case_and_body() -> None:
    """Only the header section is parsed."""
    response = "HTTP/1.1 200 OK\r\nserver: Caddy\r\n\r\nServer: fake"

    assert parse_server_header(response) == "Caddy"
    assert parse_server_header("HTTP/1.1 200 OK\r\n\r\n") is None


def test_parse_ssh_version() -> None:
    """The SSH identification string carries the software version."""
    assert parse_ssh_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n") == "OpenSSH_9.6p1"
    assert parse_ssh_version("220 smtp ready") is None


def test_resolve_target_supports_ipv6_literals() -> None:
    """IPv6 targets must resolve instead of crashing on an IPv4-only socket."""
    assert resolve_target("::1").family == socket.AF_INET6


def test_unresolvable_target_raises_a_clear_error() -> None:
    """A DNS failure is not a scan result."""
    with pytest.raises(TargetResolutionError):
        scan_network("does-not-exist.invalid")


def test_scan_without_any_answer_is_no_response(monkeypatch) -> None:
    """A silent host must not look like a clean one."""
    monkeypatch.setattr(scanner, "probe_port", lambda address, port, timeout: "filtered")

    scan = scan_network("192.0.2.1")

    assert scan.status == STATUS_NO_RESPONSE
    assert scan.findings == []
    assert scan.ports_filtered == scan.ports_checked


def test_scan_with_a_refused_port_is_complete(monkeypatch) -> None:
    """One refused connection is enough to know the host answered."""
    monkeypatch.setattr(
        scanner,
        "probe_port",
        lambda address, port, timeout: "closed" if port == 80 else "filtered",
    )

    scan = scan_network("127.0.0.1")

    assert scan.status == STATUS_COMPLETE
    assert scan.ports_closed == 1


def test_scan_network_returns_a_coherent_report() -> None:
    """A real scan of the local machine accounts for every port."""
    scan = scan_network("127.0.0.1")

    assert isinstance(scan, NetworkScan)
    assert scan.status == STATUS_COMPLETE
    assert scan.ports_open + scan.ports_closed + scan.ports_filtered == scan.ports_checked
    for finding in scan.findings:
        assert finding.category == "network"
        assert finding.severity in {"critical", "high", "medium", "low", "info"}
        assert finding.risk_reason
        assert finding.target == "127.0.0.1"


def test_classify_service_assigns_risk_levels() -> None:
    """Known risky ports should have explicit severity rules."""
    assert classify_service(23)[0] == "critical"
    assert classify_service(6379)[0] == "critical"
    assert classify_service(2375)[0] == "critical"
    assert classify_service(3389)[0] == "high"
    assert classify_service(21)[0] == "high"
    assert classify_service(22)[0] == "medium"
    assert classify_service(80)[0] == "low"


def test_every_risk_rule_targets_a_scanned_port() -> None:
    """A rule on a port that is never scanned would be dead configuration."""
    assert set(scanner.SERVICE_RISK_RULES) <= set(scanner.COMMON_PORTS)


def test_scan_network_keeps_service_identity(monkeypatch) -> None:
    """Service classification, version, and banner should reach the finding."""
    monkeypatch.setattr(
        scanner, "probe_port", lambda address, port, timeout: "open" if port == 23 else "closed"
    )
    monkeypatch.setattr(
        scanner,
        "identify_service",
        lambda host, address, port, service: ("1.0", "telnetd 1.0"),
    )

    scan = scan_network("127.0.0.1")
    findings = scan.findings

    assert len(findings) == 1
    assert findings[0].service == "Telnet"
    assert findings[0].severity == "critical"
    assert findings[0].version == "1.0"
    assert findings[0].banner == "telnetd 1.0"
    assert scan.port_states[23] == "open"
    assert scan.port_states[80] == "closed"


def test_asset_name_replaces_the_changing_address(monkeypatch) -> None:
    """Findings follow the machine when its address changes."""
    monkeypatch.setattr(
        scanner, "probe_port", lambda address, port, timeout: "open" if port == 22 else "closed"
    )
    monkeypatch.setattr(
        scanner, "identify_service", lambda host, address, port, service: (None, None)
    )

    first = scan_network("127.0.0.1", asset="laptop").findings[0]
    second = scan_network("127.0.0.2", asset="laptop").findings[0]

    assert first.stable_id() == second.stable_id()
    assert first.evidence == "127.0.0.1:22/tcp"


@pytest.mark.parametrize(
    ("target", "valid"),
    [
        ("192.168.1.10", True),
        ("::1", True),
        ("my-host.local", True),
        ("http://example.test", False),
        ("a b", False),
        ("x;rm -rf", False),
        ("", False),
    ],
)
def test_is_valid_target(target, valid) -> None:
    """Targets are plain names or addresses."""
    assert scanner.is_valid_target(target) is valid
