"""Tests for native host collection."""

import json
import socket
import sys
from collections import namedtuple

import psutil
import pytest

from attacklens import host
from attacklens.host import (
    classify_exposure,
    collect_host_report,
    collect_listeners,
    firewall_findings,
    listener_findings,
    osv_ecosystem,
    parse_dpkg_output,
    parse_os_release,
    vulnerability_findings,
)

Address = namedtuple("Address", "ip port")
Connection = namedtuple("Connection", "laddr status pid")


def _listener(port: int, exposure: str = "all", process: str = "postgres.exe") -> dict:
    return {
        "port": port,
        "protocol": "tcp",
        "process": process,
        "pid": 42,
        "addresses": ["0.0.0.0"],
        "exposure": exposure,
    }


@pytest.mark.parametrize(
    ("address", "exposure"),
    [
        ("0.0.0.0", "all"),
        ("::", "all"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("192.168.1.10", "interface"),
        ("fe80::1%eth0", "interface"),
    ],
)
def test_classify_exposure(address, exposure) -> None:
    """The bind address decides how far a service can be reached."""
    assert classify_exposure(address) == exposure


def test_collect_listeners_groups_addresses_and_keeps_the_widest_exposure(monkeypatch) -> None:
    """IPv4, IPv6, and per-interface sockets of a service are one listener."""
    connections = [
        Connection(Address("127.0.0.1", 139), psutil.CONN_LISTEN, 4),
        Connection(Address("192.168.1.5", 139), psutil.CONN_LISTEN, 4),
        Connection(Address("10.0.0.5", 50000), psutil.CONN_ESTABLISHED, 4),
    ]
    monkeypatch.setattr(host.psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(host, "_process_name", lambda pid: "System")

    items = collect_listeners()["items"]

    assert len(items) == 1
    assert items[0]["addresses"] == ["127.0.0.1", "192.168.1.5"]
    assert items[0]["exposure"] == "interface"


def test_collect_listeners_reports_denied_access(monkeypatch) -> None:
    """Being refused must not read as a machine with no listeners."""

    def denied(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(host.psutil, "net_connections", denied)

    assert collect_listeners()["status"] == "unknown"


def test_collect_listeners_sees_a_real_socket() -> None:
    """The collector must observe an actual listening socket on this machine."""
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]

        items = collect_listeners()["items"]

    match = next(item for item in items if item["port"] == port)
    assert match["exposure"] == "loopback"


def test_exposed_listener_uses_the_service_rule() -> None:
    """A database on all interfaces keeps its severity, and states what is unknown."""
    finding = listener_findings("pc", [_listener(5432)], "enabled")[0]

    assert finding.severity == "high"
    assert finding.service == "PostgreSQL"
    assert finding.process == "postgres.exe"
    assert "was not tested" in finding.risk_reason


def test_loopback_listener_is_informational() -> None:
    """Other machines cannot reach a loopback socket directly."""
    finding = listener_findings("pc", [_listener(5432, "loopback")], "enabled")[0]

    assert finding.severity == "info"


def test_unknown_exposed_port_is_low_severity() -> None:
    """No rule does not mean no risk when a port is reachable."""
    finding = listener_findings("pc", [_listener(12345, process="thing")], "enabled")[0]

    assert finding.severity == "low"


def test_widening_a_bind_address_creates_a_new_finding() -> None:
    """Moving a service from loopback to all interfaces must be detected as a change."""
    local = listener_findings("pc", [_listener(5432, "loopback")], "enabled")[0]
    exposed = listener_findings("pc", [_listener(5432, "all")], "enabled")[0]

    assert local.stable_id() != exposed.stable_id()


def test_dynamic_ports_are_grouped_by_process(monkeypatch) -> None:
    """A dynamic port changes at each boot, so the identity follows the process."""
    monkeypatch.setattr(host, "dynamic_port_start", lambda: 49152)
    first = [_listener(49664, process="svchost.exe"), _listener(49665, process="svchost.exe")]
    second = [_listener(50111, process="svchost.exe")]

    before = listener_findings("pc", first, "enabled")
    after = listener_findings("pc", second, "enabled")

    assert len(before) == 1
    assert before[0].evidence == "49664/tcp, 49665/tcp"
    assert before[0].stable_id() == after[0].stable_id()


def test_new_process_on_a_dynamic_port_is_a_new_finding(monkeypatch) -> None:
    """Grouping must not hide a backdoor on a high port."""
    monkeypatch.setattr(host, "dynamic_port_start", lambda: 49152)

    known = listener_findings("pc", [_listener(50000, process="svchost.exe")], "enabled")
    unknown = listener_findings("pc", [_listener(50000, process="evil.exe")], "enabled")

    assert known[0].stable_id() != unknown[0].stable_id()
    assert unknown[0].severity == "low"


def test_enabled_firewall_produces_no_finding() -> None:
    """A healthy firewall is not an issue."""
    assert firewall_findings("pc", {"status": "enabled", "profiles": []}) == []


def test_disabled_profile_is_high_severity() -> None:
    """A disabled profile exposes every service."""
    firewall = {
        "status": "partial",
        "source": "windows",
        "profiles": [
            {"name": "Private", "enabled": True, "inbound_allowed_by_default": False},
            {"name": "Public", "enabled": False, "inbound_allowed_by_default": False},
        ],
    }

    finding = firewall_findings("pc", firewall)[0]

    assert finding.severity == "high"
    assert finding.evidence == "Public"


def test_unknown_firewall_is_reported_and_not_assumed_safe() -> None:
    """What could not be observed must stay visible."""
    finding = firewall_findings("pc", {"status": "unknown", "profiles": []})[0]

    assert finding.severity == "info"
    assert "unknown" in finding.title


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        ([{"Name": "Public", "Enabled": 1, "DefaultInboundAction": 0}], "enabled"),
        ([{"Name": "Public", "Enabled": 1, "DefaultInboundAction": 4}], "enabled"),
        ([{"Name": "Public", "Enabled": 0, "DefaultInboundAction": 0}], "disabled"),
        ([{"Name": "Public", "Enabled": 1, "DefaultInboundAction": 2}], "disabled"),
        (
            [
                {"Name": "Private", "Enabled": 1, "DefaultInboundAction": 0},
                {"Name": "Public", "Enabled": 0, "DefaultInboundAction": 0},
            ],
            "partial",
        ),
        ({"Name": "Public", "Enabled": 1, "DefaultInboundAction": 0}, "enabled"),
    ],
)
def test_windows_firewall_states(monkeypatch, raw, status) -> None:
    """Parse the output format of Get-NetFirewallProfile."""
    monkeypatch.setattr(host, "_run", lambda command: json.dumps(raw))

    assert host._windows_firewall()["status"] == status


def test_windows_firewall_unreadable(monkeypatch) -> None:
    """A failed command is unknown, not disabled."""
    monkeypatch.setattr(host, "_run", lambda command: None)

    assert host._windows_firewall()["status"] == "unknown"


def test_linux_firewall_unknown_without_tools(monkeypatch) -> None:
    """Unprivileged users usually cannot read the rules."""
    monkeypatch.setattr(host.shutil, "which", lambda name: None)

    assert host._linux_firewall()["status"] == "unknown"


def test_linux_firewall_reads_ufw(monkeypatch) -> None:
    """ufw reports its state in plain text."""
    monkeypatch.setattr(host.shutil, "which", lambda name: name == "ufw")
    monkeypatch.setattr(host, "_run", lambda command: "Status: inactive\n")

    assert host._linux_firewall()["status"] == "disabled"


def test_parse_os_release() -> None:
    """Values may be quoted."""
    content = 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\n'

    assert parse_os_release(content)["VERSION_ID"] == "24.04"


@pytest.mark.parametrize(
    ("os_release", "ecosystem"),
    [
        ({"ID": "debian", "VERSION_ID": "12"}, "Debian:12"),
        ({"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.1 LTS"}, "Ubuntu:24.04:LTS"),
        ({"ID": "ubuntu", "VERSION_ID": "25.10", "VERSION": "25.10"}, None),
        ({"ID": "fedora", "VERSION_ID": "41"}, None),
        ({}, None),
    ],
)
def test_osv_ecosystem(os_release, ecosystem) -> None:
    """Only distributions indexed by OSV get an ecosystem."""
    assert osv_ecosystem(os_release) == ecosystem


def test_parse_dpkg_output_deduplicates_source_packages() -> None:
    """Several binary packages come from one source package."""
    output = "openssl\t3.0.13\nopenssl\t3.0.13\nbash\t5.2\nbroken-line\n"

    assert parse_dpkg_output(output) == [
        {"name": "bash", "version": "5.2"},
        {"name": "openssl", "version": "3.0.13"},
    ]


def test_vulnerability_findings_keep_actionable_advisories() -> None:
    """Advisories without a fix would only add noise to the findings."""
    report = {
        "vulnerabilities": [
            {
                "id": "DSA-1",
                "package": "openssl",
                "version": "3.0.13",
                "summary": "Bad",
                "severity": None,
                "remediation": "Upgrade",
                "references": [],
                "fixed_versions": ["3.0.14"],
            },
            {
                "id": "DSA-2",
                "package": "openssl",
                "version": "3.0.13",
                "summary": "Unfixed",
                "severity": "critical",
                "remediation": "Wait",
                "references": [],
                "fixed_versions": [],
            },
        ]
    }

    findings = vulnerability_findings("pc", report)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].category == "vulnerability"


def test_host_report_never_contacts_osv_unless_enabled(monkeypatch) -> None:
    """Package names stay local by default."""
    monkeypatch.delenv("ATTACKLENS_ENABLE_OSV", raising=False)
    monkeypatch.setattr(
        host,
        "collect_packages",
        lambda: {"status": "complete", "ecosystem": "Debian:12", "items": [{"name": "a"}]},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("OSV must not be contacted")

    monkeypatch.setattr(host, "query_package_vulnerabilities", forbidden)
    monkeypatch.setattr(host, "collect_firewall", lambda: {"status": "enabled", "profiles": []})

    assert collect_host_report()["vulnerabilities"]["status"] == "disabled"


def test_host_report_without_listener_access_is_partial(monkeypatch) -> None:
    """An incomplete view must not produce a score."""
    monkeypatch.setattr(
        host, "collect_listeners", lambda: {"status": "unknown", "items": []}
    )
    monkeypatch.setattr(host, "collect_firewall", lambda: {"status": "enabled", "profiles": []})
    monkeypatch.setattr(
        host, "collect_packages", lambda: {"status": "complete", "ecosystem": None, "items": []}
    )

    report = collect_host_report()

    assert report["status"] == "partial"
    assert report["score"] is None


def test_real_host_report_is_serializable_and_complete() -> None:
    """The real collectors must run on this machine and produce a storable report."""
    report = collect_host_report()

    assert report["scan_type"] == "host"
    assert report["target"] == socket.gethostname()
    assert report["score"] is None
    assert report["listeners"]["status"] in {"complete", "unknown"}
    assert json.loads(json.dumps(report))["scan_id"] == report["scan_id"]


@pytest.mark.skipif(sys.platform != "win32", reason="reads the Windows registry")
def test_windows_packages_reads_the_registry() -> None:
    """Every Windows machine has installed programs."""
    packages = host._windows_packages()

    assert packages["items"]
    assert packages["ecosystem"] is None
