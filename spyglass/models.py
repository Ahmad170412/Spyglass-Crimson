from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .cache import Cache
from .config import Settings
from .http import HttpClient


@dataclass(frozen=True)
class Target:
    kind: str  # domain | ip | cidr | asn
    value: str
    raw: str = ""
    host: str | None = None
    ip: Any | None = None
    network: Any | None = None
    asn: int | None = None

    @property
    def label(self) -> str:
        if self.kind == "asn":
            return f"AS{self.asn}"
        return self.value


@dataclass
class SourceContext:
    settings: Settings
    cache: Cache
    http: HttpClient


@dataclass
class SourceResult:
    source: str
    status: str = "ok"  # ok | empty | not_found | partial
    data: dict[str, Any] = field(default_factory=dict)
    record_count: int = 0
    errors: dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "data": self.data,
            "record_count": self.record_count,
            "errors": self.errors,
            "truncated": self.truncated,
            "provider": self.provider,
        }


class SourceError(Exception):
    """An adapter could not produce a result."""

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable
