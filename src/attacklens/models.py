"""Data models used by AttackLens."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def finding_identity(
    target: str | None,
    category: str | None,
    service: str | None,
    port: int | None,
    protocol: str | None,
    title: str | None,
) -> str:
    """Return the identity of a finding on one asset, ignoring volatile evidence."""
    identity = {
        "target": target,
        "category": category,
        "service": service,
        "port": port,
        "protocol": protocol,
        "title": title,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class Finding:
    """Represents a security finding."""

    category: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    risk_reason: str = ""
    references: list[str] = field(default_factory=list)
    target: str | None = None
    port: int | None = None
    service: str | None = None
    protocol: str | None = None
    version: str | None = None
    banner: str | None = None
    process: str | None = None
    exposure: str | None = None
    cve: str | None = None
    cvss: float | None = None

    def stable_id(self) -> str:
        """Return an identity that survives changes to volatile evidence."""
        return finding_identity(
            self.target, self.category, self.service, self.port, self.protocol, self.title
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""
        data = asdict(self)
        data["finding_id"] = self.stable_id()
        return data
