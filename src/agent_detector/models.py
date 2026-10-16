from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Observation:
    kind: str
    value: str
    pid: int | None = None
    port: int | None = None
    host: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    component: str
    category: str
    confidence: float
    state: str
    version: str | None = None
    version_source: str | None = None
    pid: int | None = None
    port: int | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
