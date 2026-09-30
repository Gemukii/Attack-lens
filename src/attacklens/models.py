"""Data models used by AttackLens."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any


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
    port: int | None = None
    service: str | None = None
    protocol: str | None = None
    version: str | None = None
    banner: str | None = None
    cve: str | None = None
    cvss: float | None = None

    def stable_id(self) -> str:
        """Return an identity that survives changes to volatile evidence."""
        identity = {
            "category": self.category,
            "service": self.service,
            "port": self.port,
            "protocol": self.protocol,
            "title": self.title,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""
        data = asdict(self)
        data["finding_id"] = self.stable_id()
        return data