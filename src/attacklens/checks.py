"""Non-invasive service checks: turning "might be exposed" into evidence.

Each check sends one harmless request and reads the answer. None of them tries a
password, sends a payload, or changes anything on the target. Only run them against
systems you own or are authorized to assess.
"""

import socket
import ssl
import struct
from dataclasses import dataclass
from typing import Any

CHECK_TIMEOUT_SECONDS = 2.0

CONFIRMED = "confirmed"
MITIGATED = "mitigated"
TLS_PORTS = {443, 2376, 5986, 8443}


@dataclass(frozen=True)
class Verification:
    """What a check proved about a service."""

    state: str
    detail: str
    severity: str | None = None


def _exchange(address: Any, port: int, request: bytes, timeout: float) -> bytes:
    """Send one request and read the first answer."""
    with socket.socket(address.family, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(address.for_port(port))
        connection.sendall(request)
        return connection.recv(4096)


def check_redis(answer: bytes) -> Verification | None:
    """Interpret the answer to PING."""
    if answer.startswith(b"+PONG"):
        return Verification(CONFIRMED, "Redis answered without any authentication.", "critical")
    if b"NOAUTH" in answer:
        return Verification(MITIGATED, "Redis requires authentication.", "medium")
    return None


def check_memcached(answer: bytes) -> Verification | None:
    """Interpret the answer to `version`."""
    if answer.startswith(b"VERSION"):
        return Verification(CONFIRMED, "Memcached answered without authentication.", "critical")
    return None


def check_docker_api(answer: bytes) -> Verification | None:
    """Interpret the answer to GET /version."""
    if answer.startswith(b"HTTP/1.") and b" 200 " in answer[:20] and b"ApiVersion" in answer:
        return Verification(
            CONFIRMED,
            "The Docker API answered without authentication: full control of the host.",
            "critical",
        )
    return None


def check_elasticsearch(answer: bytes) -> Verification | None:
    """Interpret the answer to GET /."""
    if b"cluster_name" in answer and b" 200 " in answer[:20]:
        return Verification(
            CONFIRMED, "Elasticsearch answered without authentication.", "critical"
        )
    if b" 401 " in answer[:20]:
        return Verification(MITIGATED, "Elasticsearch requires authentication.", "medium")
    return None


def smb_negotiate_request() -> bytes:
    """Build an SMB2 NEGOTIATE request, which happens before any authentication."""
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    header = (
        b"\xfeSMB"
        + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        + b"\x00" * 16
    )
    body = (
        struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0)
        + b"\x00" * 16
        + struct.pack("<Q", 0)
        + struct.pack(f"<{len(dialects)}H", *dialects)
    )
    message = header + body
    return struct.pack(">I", len(message)) + message


def check_smb(answer: bytes) -> Verification | None:
    """Read the SecurityMode of an SMB2 NEGOTIATE response."""
    if len(answer) < 72 or answer[4:8] != b"\xfeSMB":
        return None
    security_mode = struct.unpack_from("<H", answer, 4 + 64 + 2)[0]
    if security_mode & 0x0002:
        return Verification(MITIGATED, "SMB signing is required.", "medium")
    return Verification(
        CONFIRMED, "SMB signing is not required: traffic can be relayed.", "high"
    )


def check_tls(host: str, address: Any, port: int, timeout: float) -> Verification | None:
    """Check the certificate and whether obsolete TLS versions are still accepted."""
    with socket.socket(address.family, socket.SOCK_STREAM) as raw:
        raw.settimeout(timeout)
        raw.connect(address.for_port(port))
        verifying = ssl.create_default_context()
        verifying.check_hostname = False
        try:
            with verifying.wrap_socket(raw, server_hostname=host):
                certificate_problem = None
        except ssl.SSLCertVerificationError as error:
            certificate_problem = error.verify_message
        except (ssl.SSLError, OSError):
            # A server limited to obsolete versions fails here: the next test tells.
            certificate_problem = None

    legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    legacy.check_hostname = False
    legacy.verify_mode = ssl.CERT_NONE
    try:
        legacy.minimum_version = ssl.TLSVersion.TLSv1
        legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        legacy.set_ciphers("ALL:@SECLEVEL=0")
        with socket.socket(address.family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect(address.for_port(port))
            with legacy.wrap_socket(raw, server_hostname=host):
                return Verification(CONFIRMED, "TLS 1.0 or 1.1 is still accepted.", "high")
    except (ssl.SSLError, OSError, ValueError):
        pass

    if certificate_problem and "expired" in certificate_problem:
        return Verification(CONFIRMED, "The TLS certificate has expired.", "medium")
    if certificate_problem:
        return Verification(CONFIRMED, f"TLS certificate: {certificate_problem}.", "low")
    return None


def verify_service(
    host: str, address: Any, port: int, timeout: float = CHECK_TIMEOUT_SECONDS
) -> Verification | None:
    """Run the check of a port, if it has one. A failed check proves nothing."""
    http_get = f"GET {{}} HTTP/1.0\r\nHost: {host}\r\n\r\n"
    exchanges = {
        445: (smb_negotiate_request(), check_smb),
        2375: (http_get.format("/version").encode(), check_docker_api),
        6379: (b"PING\r\n", check_redis),
        9200: (http_get.format("/").encode(), check_elasticsearch),
        11211: (b"version\r\n", check_memcached),
    }
    try:
        if port in TLS_PORTS:
            return check_tls(host, address, port, timeout)
        if port in exchanges:
            request, interpret = exchanges[port]
            return interpret(_exchange(address, port, request, timeout))
    except (OSError, struct.error, UnicodeError):
        return None
    return None
