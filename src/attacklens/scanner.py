"""Network scanning functionality for AttackLens."""

import socket
from email.parser import Parser

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
    139: (
        "high",
        "NetBIOS exposure can disclose host information and enable lateral movement.",
        "Disable NetBIOS or restrict it to the required private network.",
    ),
    445: (
        "high",
        "SMB exposure can enable file-sharing attacks and lateral movement.",
        "Restrict SMB to trusted networks and block inbound Internet access.",
    ),
    3306: (
        "high",
        "A database exposed on the network increases the risk of data compromise.",
        "Keep MySQL private and allow access only from approved application hosts.",
    ),
    5432: (
        "high",
        "A database exposed on the network increases the risk of data compromise.",
        "Keep PostgreSQL private and allow access only from approved application hosts.",
    ),
    6379: (
        "critical",
        "Redis is often deployed without authentication and can expose application data.",
        "Bind Redis to a private interface and require authentication.",
    ),
    80: (
        "low",
        "HTTP traffic is unencrypted and can expose transmitted information.",
        "Prefer HTTPS and verify that the service is intentionally public.",
    ),
    443: (
        "low",
        "HTTPS is encrypted, but the service should still be kept up to date.",
        "Keep the web service and TLS configuration patched and restricted.",
    ),
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


def identify_service(host: str, port: int, service: str) -> tuple[str | None, str | None]:
    """Collect a small, non-invasive service banner when one is available."""
    try:
        with socket.create_connection((host, port), timeout=0.5) as connection:
            connection.settimeout(0.5)
            if service.startswith("HTTP"):
                connection.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )

            response = connection.recv(1024).decode("utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None, None

    banner = " ".join(response.replace("\x00", " ").split())[:240]
    if not banner:
        return None, None

    version = None
    if service.startswith("HTTP") and "\r\n" in response:
        headers = Parser().parsestr(response.replace("\r\n", "\n"))
        version = headers.get("Server") or None

    return version, banner


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
            severity, risk_reason, remediation = classify_service(port)
            version, banner = identify_service(host, port, service)
            findings.append(
                Finding(
                    category="network",
                    severity=severity,
                    title=f"{service} service detected",
                    description=f"TCP port {port} is accepting connections.",
                    evidence=f"{host}:{port}/tcp",
                    remediation=remediation,
                    risk_reason=risk_reason,
                    port=port,
                    service=service,
                    protocol="tcp",
                    version=version,
                    banner=banner,
                )
            )

    return findings