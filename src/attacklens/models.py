"""Data models used by AttackLens."""

from dataclasses import asdict, dataclass, field
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
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""
        return asdict(self)