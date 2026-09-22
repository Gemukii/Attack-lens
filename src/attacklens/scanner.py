"""Network scanning functionality for AttackLens."""

import socket

from attacklens.models import Finding


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
}


def check_port(host: str, port: int, timeout: float = 0.2) -> bool:
    """Check whether a TCP port is accepting connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan_network(host: str = "127.0.0.1") -> list[Finding]:
    """Scan common TCP ports on a host."""
    findings: list[Finding] = []

    for port, service in COMMON_PORTS.items():
        if check_port(host, port):
            findings.append(
                Finding(
                    category="network",
                    severity="info",
                    title=f"{service} service detected",
                    description=f"TCP port {port} is accepting connections.",
                    evidence=f"{host}:{port}/tcp",
                    remediation=(
                        "Verify that this service is required and "
                        "properly secured."
                    ),
                )
            )

    return findings