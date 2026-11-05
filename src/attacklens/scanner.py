"""Network scanning functionality for AttackLens."""

import re
import socket
import ssl
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from attacklens.checks import verify_service
from attacklens.models import Finding

# Windows retries a refused connection for about two seconds, so a shorter timeout
# reports closed ports as filtered. Ports are probed in parallel to absorb the cost.
DEFAULT_TIMEOUT_SECONDS = 3.0
BANNER_TIMEOUT_SECONDS = 1.0
MAX_WORKERS = 32

STATUS_COMPLETE = "complete"
STATUS_NO_RESPONSE = "no_response"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    902: "VMware Auth",
    1433: "MSSQL",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3000: "HTTP alternate",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP alternate",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP alternate",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    8888: "HTTP alternate",
    9200: "Elasticsearch",
    10250: "Kubelet",
    11211: "Memcached",
    27017: "MongoDB",
}

_DATABASE_RISK = "A database exposed on the network increases the risk of data compromise."

SERVICE_RISK_RULES = {
    21: (
        "high",
        "FTP can expose credentials and files, especially without encryption.",
        "Disable FTP when possible or replace it with SFTP and restrict access.",
    ),
    22: (
        "medium",
        "SSH is an administration service that should be tightly restricted.",
        "Restrict SSH to trusted networks and use key-based authentication.",
    ),
    23: (
        "critical",
        "Telnet sends credentials and traffic without encryption.",
        "Disable Telnet and replace it with SSH.",
    ),
    80: (
        "low",
        "HTTP traffic is unencrypted and can expose transmitted information.",
        "Prefer HTTPS and verify that the service is intentionally public.",
    ),
    111: (
        "medium",
        "RPCBind discloses the RPC services running on the host.",
        "Disable RPCBind if unused or restrict it to trusted networks.",
    ),
    135: (
        "medium",
        "MS-RPC is a frequent entry point for enumeration and lateral movement.",
        "Block inbound RPC at the firewall except from trusted management hosts.",
    ),
    139: (
        "high",
        "NetBIOS exposure can disclose host information and enable lateral movement.",
        "Disable NetBIOS or restrict it to the required private network.",
    ),
    443: (
        "low",
        "HTTPS is encrypted, but the service should still be kept up to date.",
        "Keep the web service and TLS configuration patched and restricted.",
    ),
    445: (
        "high",
        "SMB exposure can enable file-sharing attacks and lateral movement.",
        "Restrict SMB to trusted networks and block inbound Internet access.",
    ),
    902: (
        "medium",
        "The VMware authentication service exposes the hypervisor management plane.",
        "Restrict this port to the host itself or to trusted management hosts.",
    ),
    1433: (
        "high",
        _DATABASE_RISK,
        "Keep MSSQL private and allow access only from approved application hosts.",
    ),
    2049: (
        "high",
        "NFS exports can expose files to any host allowed by the export rules.",
        "Restrict NFS to trusted hosts and review the export list.",
    ),
    2375: (
        "critical",
        "An unencrypted Docker API usually grants full control of the host.",
        "Disable the TCP socket or protect it with mutual TLS.",
    ),
    2376: (
        "high",
        "The Docker API grants full control of the host when its TLS client check is weak.",
        "Require client certificates and restrict access to trusted hosts.",
    ),
    3306: (
        "high",
        _DATABASE_RISK,
        "Keep MySQL private and allow access only from approved application hosts.",
    ),
    3389: (
        "high",
        "RDP is heavily targeted by brute-force attacks and remote exploits.",
        "Restrict RDP to a VPN or trusted hosts and require Network Level Authentication.",
    ),
    5432: (
        "high",
        _DATABASE_RISK,
        "Keep PostgreSQL private and allow access only from approved application hosts.",
    ),
    5900: (
        "high",
        "VNC often relies on weak authentication and unencrypted sessions.",
        "Tunnel VNC through SSH or a VPN and restrict access.",
    ),
    5985: (
        "high",
        "WinRM over HTTP provides remote administration of the host.",
        "Restrict WinRM to management hosts and prefer HTTPS.",
    ),
    5986: (
        "medium",
        "WinRM provides remote administration of the host.",
        "Restrict WinRM to management hosts.",
    ),
    6379: (
        "critical",
        "Redis is often deployed without authentication and can expose application data.",
        "Bind Redis to a private interface and require authentication.",
    ),
    6443: (
        "high",
        "The Kubernetes API controls the whole cluster.",
        "Restrict API access to trusted networks and review anonymous access.",
    ),
    9200: (
        "high",
        "Elasticsearch deployments can expose indexed data without authentication.",
        "Keep Elasticsearch private and enable authentication.",
    ),
    10250: (
        "high",
        "The Kubelet API can allow command execution in containers.",
        "Restrict the port and disable anonymous Kubelet authentication.",
    ),
    11211: (
        "high",
        "Memcached has no authentication by default and can leak cached data.",
        "Bind Memcached to a private interface.",
    ),
    27017: (
        "high",
        _DATABASE_RISK,
        "Keep MongoDB private and enable authentication.",
    ),
}


class TargetResolutionError(Exception):
    """The scan target could not be resolved to an IP address."""


def is_valid_target(target: str) -> bool:
    """Return whether a target is a plain hostname or IP address."""
    return re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", target) is not None


@dataclass(frozen=True)
class Address:
    """A resolved scan target."""

    family: int
    sockaddr: tuple[Any, ...]

    def for_port(self, port: int) -> tuple[Any, ...]:
        """Return a socket address for one port, for IPv4 and IPv6."""
        return (self.sockaddr[0], port, *self.sockaddr[2:])


@dataclass
class NetworkScan:
    """Outcome of a network scan, including what could not be observed."""

    findings: list[Finding] = field(default_factory=list)
    status: str = STATUS_COMPLETE
    ports_checked: int = 0
    ports_open: int = 0
    ports_closed: int = 0
    ports_filtered: int = 0
    port_states: dict[int, str] = field(default_factory=dict)

    def coverage(self) -> dict[str, int]:
        """Return the port accounting stored with the scan."""
        return {
            "ports_checked": self.ports_checked,
            "ports_open": self.ports_open,
            "ports_closed": self.ports_closed,
            "ports_filtered": self.ports_filtered,
        }


def classify_service(port: int) -> tuple[str, str, str]:
    """Return severity, risk explanation, and remediation for a port."""
    return SERVICE_RISK_RULES.get(
        port,
        (
            "info",
            "The service is reachable but no specific risk rule is configured.",
            "Verify that this service is required and properly secured.",
        ),
    )


def resolve_target(host: str) -> Address:
    """Resolve a hostname or IP literal once, for IPv4 and IPv6 targets."""
    try:
        family, _, _, _, sockaddr = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0]
    except (OSError, UnicodeError, IndexError) as error:
        raise TargetResolutionError(f"Unable to resolve target '{host}'.") from error
    return Address(family=family, sockaddr=sockaddr)


def probe_port(address: Address, port: int, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Return whether a TCP port is open, closed, or filtered."""
    with socket.socket(address.family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(address.for_port(port))
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "filtered"
    return "open"


def parse_server_header(response: str) -> str | None:
    """Return the Server header of a raw HTTP response."""
    head = response.replace("\r\n", "\n").split("\n\n", 1)[0]
    for line in head.split("\n")[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "server":
            return value.strip() or None
    return None


def parse_ssh_version(response: str) -> str | None:
    """Return the software version announced by an SSH identification string."""
    match = re.match(r"SSH-[\d.]+-(\S+)", response)
    return match.group(1) if match else None


def _http_request(host: str, address: Address) -> bytes:
    """Build a HEAD request with a valid Host header for IPv4, IPv6, and names."""
    host_header = f"[{host}]" if address.family == socket.AF_INET6 and ":" in host else host
    return f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode()


def _read_response(host: str, address: Address, port: int, service: str, timeout: float) -> str:
    """Read the first bytes a service sends, speaking TLS on HTTPS ports."""
    with socket.socket(address.family, socket.SOCK_STREAM) as raw_connection:
        raw_connection.settimeout(timeout)
        raw_connection.connect(address.for_port(port))
        if service.startswith("HTTPS"):
            # Identification only: the certificate is not trusted for anything here.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw_connection, server_hostname=host) as connection:
                connection.sendall(_http_request(host, address))
                return connection.recv(1024).decode("utf-8", errors="replace")
        if service.startswith("HTTP"):
            raw_connection.sendall(_http_request(host, address))
        return raw_connection.recv(1024).decode("utf-8", errors="replace")


def identify_service(
    host: str,
    address: Address,
    port: int,
    service: str,
    timeout: float = BANNER_TIMEOUT_SECONDS,
) -> tuple[str | None, str | None]:
    """Collect a small, non-invasive service banner when one is available."""
    try:
        response = _read_response(host, address, port, service, timeout)
    except (OSError, UnicodeError):
        return None, None

    printable = "".join(char if char.isprintable() else " " for char in response)
    banner = " ".join(printable.split())[:240]
    if not banner:
        return None, None

    version = None
    if service.startswith("HTTP"):
        version = parse_server_header(response)
    elif service == "SSH":
        version = parse_ssh_version(response)
    return version, banner


def _build_finding(
    host: str, asset: str, address: Address, port: int, service: str
) -> Finding:
    """Turn an open port into a classified finding."""
    severity, risk_reason, remediation = classify_service(port)
    version, banner = identify_service(host, address, port, service)
    verification = verify_service(host, address, port)
    if verification is not None:
        severity = verification.severity or severity
        risk_reason = verification.detail
    return Finding(
        category="network",
        severity=severity,
        title=f"{service} service detected",
        description=f"TCP port {port} is accepting connections.",
        evidence=f"{host}:{port}/tcp",
        remediation=remediation,
        risk_reason=risk_reason,
        target=asset,
        port=port,
        service=service,
        protocol="tcp",
        version=version,
        banner=banner,
        verification=verification.state if verification else None,
    )


def scan_network(
    host: str = "127.0.0.1",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    asset: str | None = None,
    extra_ports: Iterable[int] = (),
) -> NetworkScan:
    """Scan common TCP ports on a host and report what could be observed.

    Findings belong to `asset`, which defaults to the scanned host. A machine scanned
    through an address that changes keeps its findings under a stable name this way.
    """
    address = resolve_target(host)
    ports = sorted({*COMMON_PORTS, *extra_ports})

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        states = dict(
            zip(
                ports,
                executor.map(lambda port: probe_port(address, port, timeout), ports),
                strict=True,
            )
        )
        open_ports = [port for port in ports if states[port] == "open"]
        findings = list(
            executor.map(
                lambda port: _build_finding(
                    host, asset or host, address, port, COMMON_PORTS.get(port, "Unknown")
                ),
                open_ports,
            )
        )

    closed = sum(state == "closed" for state in states.values())
    # Without a single answer nothing is known about the host: it may be down or
    # fully filtered, and reporting "no findings" would read as a clean result.
    status = STATUS_COMPLETE if open_ports or closed else STATUS_NO_RESPONSE
    return NetworkScan(
        findings=findings,
        status=status,
        ports_checked=len(ports),
        ports_open=len(open_ports),
        ports_closed=closed,
        ports_filtered=sum(state == "filtered" for state in states.values()),
        port_states=states,
    )
