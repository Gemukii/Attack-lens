"""Native host collection: what runs on this machine, seen from the inside.

This module runs on the analyzed host, as an unprivileged user. Anything the current
user cannot observe is reported as unknown rather than as a clean result.
"""

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

import psutil

from attacklens.models import Finding
from attacklens.results import build_document
from attacklens.scanner import COMMON_PORTS, SERVICE_RISK_RULES
from attacklens.vulnerabilities import osv_enabled, query_package_vulnerabilities

COMMAND_TIMEOUT_SECONDS = 15
EXPOSURE_RANK = {"loopback": 0, "interface": 1, "all": 2}
EXPOSURE_LABELS = {
    "loopback": "this machine only",
    "interface": "specific interfaces",
    "all": "all interfaces",
}
# NET_FW_ACTION values returned by Get-NetFirewallProfile.
WINDOWS_ACTION_ALLOW = 2
WINDOWS_ENABLED_TRUE = 1


def _run(command: list[str]) -> str | None:
    """Run a read-only command and return its output, or None when it fails."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def dynamic_port_start() -> int:
    """Return where the operating system starts allocating dynamic ports."""
    return 49152 if sys.platform == "win32" else 32768


def classify_exposure(address: str) -> str:
    """Return how widely a socket bound to this address can be reached."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "interface"
    if ip.is_unspecified:
        return "all"
    return "loopback" if ip.is_loopback else "interface"


def _process_name(pid: int | None) -> str:
    """Return a process name, which unprivileged users cannot always read."""
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return "unknown"


def collect_listeners() -> dict[str, Any]:
    """Return listening TCP sockets, grouped by port and process."""
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError) as error:
        return {"status": "unknown", "detail": str(error), "items": []}

    grouped: dict[tuple[int, str], dict[str, Any]] = {}
    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        process = _process_name(connection.pid)
        entry = grouped.setdefault(
            (connection.laddr.port, process),
            {
                "port": connection.laddr.port,
                "protocol": "tcp",
                "process": process,
                "pid": connection.pid,
                "addresses": set(),
                "exposure": "loopback",
            },
        )
        entry["addresses"].add(connection.laddr.ip)
        exposure = classify_exposure(connection.laddr.ip)
        if EXPOSURE_RANK[exposure] > EXPOSURE_RANK[entry["exposure"]]:
            entry["exposure"] = exposure

    items = [
        {**entry, "addresses": sorted(entry["addresses"])}
        for _, entry in sorted(grouped.items())
    ]
    return {"status": "complete", "items": items}


def _windows_firewall() -> dict[str, Any]:
    """Read the state of the Windows Firewall profiles."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    powershell = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    output = _run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction "
                "| ConvertTo-Json -Compress"
            ),
        ]
    )
    if not output:
        return {"status": "unknown", "source": "windows", "profiles": []}
    try:
        raw = json.loads(output)
    except ValueError:
        return {"status": "unknown", "source": "windows", "profiles": []}

    profiles = [
        {
            "name": profile.get("Name"),
            "enabled": profile.get("Enabled") == WINDOWS_ENABLED_TRUE,
            "inbound_allowed_by_default": profile.get("DefaultInboundAction")
            == WINDOWS_ACTION_ALLOW,
        }
        for profile in (raw if isinstance(raw, list) else [raw])
    ]
    weak = [
        profile
        for profile in profiles
        if not profile["enabled"] or profile["inbound_allowed_by_default"]
    ]
    if not weak:
        status = "enabled"
    elif len(weak) == len(profiles):
        status = "disabled"
    else:
        status = "partial"
    return {"status": status, "source": "windows", "profiles": profiles}


def _linux_firewall() -> dict[str, Any]:
    """Read the firewall state with the tools an unprivileged user can run."""
    if shutil.which("firewall-cmd"):
        output = _run(["firewall-cmd", "--state"])
        if output is not None:
            status = "enabled" if output.strip() == "running" else "disabled"
            return {"status": status, "source": "firewalld", "profiles": []}
    if shutil.which("ufw"):
        output = _run(["ufw", "status"])
        if output is not None:
            status = "enabled" if "Status: active" in output else "disabled"
            return {"status": status, "source": "ufw", "profiles": []}
    return {
        "status": "unknown",
        "source": "linux",
        "profiles": [],
        "detail": "No firewall state is readable without elevated privileges.",
    }


def collect_firewall() -> dict[str, Any]:
    """Return the host firewall state."""
    if sys.platform == "win32":
        return _windows_firewall()
    if sys.platform.startswith("linux"):
        return _linux_firewall()
    return {"status": "unknown", "source": sys.platform, "profiles": []}


def _windows_packages() -> dict[str, Any]:
    """Read installed programs from the Windows uninstall registry keys."""
    import winreg

    uninstall_paths = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    programs: dict[tuple[str, str], dict[str, str]] = {}
    for hive, path in uninstall_paths:
        try:
            parent = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with parent:
            for index in range(winreg.QueryInfoKey(parent)[0]):
                try:
                    with winreg.OpenKey(parent, winreg.EnumKey(parent, index)) as key:
                        name = winreg.QueryValueEx(key, "DisplayName")[0]
                        version = winreg.QueryValueEx(key, "DisplayVersion")[0]
                except OSError:
                    continue
                if name and version:
                    programs[(name, version)] = {"name": name, "version": version}

    return {
        "status": "complete",
        "source": "windows-registry",
        "ecosystem": None,
        "items": sorted(programs.values(), key=lambda item: item["name"].lower()),
    }


def parse_os_release(content: str) -> dict[str, str]:
    """Parse the content of /etc/os-release."""
    fields: dict[str, str] = {}
    for line in content.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip().strip('"')
    return fields


def osv_ecosystem(os_release: dict[str, str]) -> str | None:
    """Return the OSV ecosystem of a Linux distribution, when OSV covers it."""
    distribution = os_release.get("ID")
    version = os_release.get("VERSION_ID", "")
    if distribution == "debian" and version:
        return f"Debian:{version}"
    if distribution == "ubuntu" and version:
        return f"Ubuntu:{version}:LTS" if "LTS" in os_release.get("VERSION", "") else None
    return None


def parse_dpkg_output(output: str) -> list[dict[str, str]]:
    """Parse `source<TAB>version` lines, since OSV indexes Debian source packages."""
    packages: dict[tuple[str, str], dict[str, str]] = {}
    for line in output.splitlines():
        name, separator, version = line.partition("\t")
        if separator and name and version:
            packages[(name, version)] = {"name": name, "version": version}
    return sorted(packages.values(), key=lambda item: item["name"])


def _linux_packages() -> dict[str, Any]:
    """Read installed packages with the system package manager."""
    try:
        os_release = parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    except OSError:
        os_release = {}

    if shutil.which("dpkg-query"):
        output = _run(["dpkg-query", "-W", "-f=${source:Package}\t${Version}\n"])
        if output is not None:
            return {
                "status": "complete",
                "source": "dpkg",
                "ecosystem": osv_ecosystem(os_release),
                "items": parse_dpkg_output(output),
            }
    if shutil.which("rpm"):
        output = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        if output is not None:
            return {
                "status": "complete",
                "source": "rpm",
                "ecosystem": None,
                "items": parse_dpkg_output(output),
            }
    return {"status": "unknown", "source": "linux", "ecosystem": None, "items": []}


def collect_packages() -> dict[str, Any]:
    """Return the software installed on the host."""
    if sys.platform == "win32":
        return _windows_packages()
    if sys.platform.startswith("linux"):
        return _linux_packages()
    return {"status": "unknown", "source": sys.platform, "ecosystem": None, "items": []}


def _dynamic_listener_findings(target: str, listeners: list[dict[str, Any]]) -> list[Finding]:
    """Group dynamic ports by process: the port changes, the process should not."""
    by_process: dict[str, list[dict[str, Any]]] = {}
    for listener in listeners:
        by_process.setdefault(listener["process"], []).append(listener)

    findings = []
    for process, entries in sorted(by_process.items()):
        exposure = max(
            (entry["exposure"] for entry in entries), key=lambda item: EXPOSURE_RANK[item]
        )
        ports = sorted(entry["port"] for entry in entries)
        findings.append(
            Finding(
                category="listener",
                severity="info" if exposure == "loopback" else "low",
                title=f"{process} listens on dynamic ports ({EXPOSURE_LABELS[exposure]})",
                description=f"{process} accepts connections on {len(ports)} dynamic port(s).",
                evidence=", ".join(f"{port}/tcp" for port in ports),
                remediation="Verify that this process is expected to accept connections.",
                risk_reason="Dynamic ports are common for system services, and for backdoors.",
                target=target,
                protocol="tcp",
                process=process,
                exposure=exposure,
            )
        )
    return findings


def _listener_finding(target: str, listener: dict[str, Any], firewall_status: str) -> Finding:
    """Rate one listener by the service it offers and how far it is reachable."""
    port = listener["port"]
    process = listener["process"]
    exposure = listener["exposure"]
    service = COMMON_PORTS.get(port)
    severity, risk_reason, remediation = SERVICE_RISK_RULES.get(
        port,
        (
            "low",
            "This service accepts connections and has no specific risk rule.",
            "Verify that this service is required and bind it to loopback if it is local.",
        ),
    )
    if exposure == "loopback":
        severity = "info"
        risk_reason = "The socket is bound to loopback: other machines cannot reach it directly."
    else:
        risk_reason = (
            f"{risk_reason} The host firewall is {firewall_status}; reachability from other "
            "machines was not tested from this vantage point."
        )

    return Finding(
        category="listener",
        severity=severity,
        title=f"{process} listens on {port}/tcp ({EXPOSURE_LABELS[exposure]})",
        description=f"{process} accepts TCP connections on port {port}.",
        evidence=", ".join(listener["addresses"]),
        remediation=remediation,
        risk_reason=risk_reason,
        target=target,
        port=port,
        service=service,
        protocol="tcp",
        process=process,
        exposure=exposure,
    )


def listener_findings(
    target: str, listeners: list[dict[str, Any]], firewall_status: str
) -> list[Finding]:
    """Turn listening sockets into findings."""
    start = dynamic_port_start()
    dynamic = [entry for entry in listeners if entry["port"] >= start]
    fixed = [entry for entry in listeners if entry["port"] < start]
    return [
        *(_listener_finding(target, entry, firewall_status) for entry in fixed),
        *_dynamic_listener_findings(target, dynamic),
    ]


def firewall_findings(target: str, firewall: dict[str, Any]) -> list[Finding]:
    """Report a weak firewall, or the fact that it could not be observed."""
    status = firewall["status"]
    if status == "enabled":
        return []
    if status == "unknown":
        return [
            Finding(
                category="firewall",
                severity="info",
                title="Host firewall state unknown",
                description="The firewall state could not be read by the current user.",
                remediation="Check the firewall manually, or run this check with elevated rights.",
                target=target,
            )
        ]
    weak_profiles = [
        profile["name"]
        for profile in firewall.get("profiles", [])
        if not profile["enabled"] or profile["inbound_allowed_by_default"]
    ]
    return [
        Finding(
            category="firewall",
            severity="high",
            title="Host firewall does not block inbound traffic",
            description="At least one firewall profile is disabled or allows inbound traffic.",
            evidence=", ".join(weak_profiles) or firewall.get("source", ""),
            remediation="Enable the firewall and block inbound traffic by default.",
            risk_reason="Every listening service may be reachable from the network.",
            target=target,
        )
    ]


def vulnerability_findings(target: str, report: dict[str, Any]) -> list[Finding]:
    """Turn OSV advisories that have a fix into findings."""
    severities = {"critical", "high", "medium", "low"}
    return [
        Finding(
            category="vulnerability",
            severity=item["severity"] if item["severity"] in severities else "medium",
            risk_reason=(
                ""
                if item["severity"] in severities
                else "The advisory gives no severity label: medium is assumed."
            ),
            title=f"{item['id']} in {item['package']}",
            description=item["summary"] or "See the advisory.",
            evidence=f"{item['package']} {item['version']}",
            remediation=item["remediation"],
            references=item["references"][:5],
            target=target,
            service=item["package"],
        )
        for item in report["vulnerabilities"]
        if item["fixed_versions"]
    ]


def _check_vulnerabilities(packages: dict[str, Any]) -> dict[str, Any]:
    """Query OSV when the user allowed it and OSV covers this platform."""
    if not packages.get("ecosystem"):
        return {"status": "not_covered", "packages_checked": 0, "vulnerabilities": []}
    if not osv_enabled():
        return {"status": "disabled", "packages_checked": 0, "vulnerabilities": []}
    return query_package_vulnerabilities(packages["items"], ecosystem=packages["ecosystem"])


def collect_host_report() -> dict[str, Any]:
    """Collect the host and build its scan document."""
    started_at = perf_counter()
    target = socket.gethostname()
    listeners = collect_listeners()
    firewall = collect_firewall()
    packages = collect_packages()
    vulnerabilities = _check_vulnerabilities(packages)

    findings = [
        *listener_findings(target, listeners["items"], firewall["status"]),
        *firewall_findings(target, firewall),
        *vulnerability_findings(target, vulnerabilities),
    ]
    return build_document(
        findings=findings,
        target=target,
        scan_type="host",
        status="complete" if listeners["status"] == "complete" else "partial",
        duration_seconds=perf_counter() - started_at,
        extra={
            # A listening socket is not proof of reachability, so a host report
            # lists findings without claiming an exposure score.
            "score": None,
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
            },
            "listeners": listeners,
            "firewall": firewall,
            "packages": packages,
            "vulnerabilities": {
                "status": vulnerabilities["status"],
                "packages_checked": vulnerabilities["packages_checked"],
                "advisories_found": vulnerabilities.get("advisories_found", 0),
                "fixable": sum(
                    bool(item["fixed_versions"]) for item in vulnerabilities["vulnerabilities"]
                ),
            },
        },
    )
