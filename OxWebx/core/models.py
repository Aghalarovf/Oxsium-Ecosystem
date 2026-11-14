from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from core.exceptions import TargetError
from core.utils import is_ip, normalize_host, registered_domain, tld_of, valid_hostname


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            raise ValueError(f"unknown severity: {value}")


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    kind: str

    @property
    def is_ip(self) -> bool:
        return self.kind == "ip"

    @property
    def registered_domain(self) -> str:
        return self.host if self.is_ip else registered_domain(self.host)

    @property
    def tld(self) -> Optional[str]:
        return None if self.is_ip else tld_of(self.host)

    @classmethod
    def parse(cls, raw: str) -> "Target":
        host = normalize_host(raw)
        if not host:
            raise TargetError(f"empty target: {raw!r}")
        if is_ip(host):
            return cls(raw=raw, host=host, kind="ip")
        if not valid_hostname(host):
            raise TargetError(f"invalid target: {raw!r}")
        return cls(raw=raw, host=host, kind="domain")

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.raw,
            "host": self.host,
            "kind": self.kind,
            "registered_domain": self.registered_domain,
            "tld": self.tld,
        }


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    module: str
    check: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    tags: list[str] = field(default_factory=list)
    confidence: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "module": self.module,
            "check": self.check,
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "tags": self.tags,
            "confidence": self.confidence,
        }


@dataclass
class ModuleResult:
    module: str
    status: str = "pending"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    skipped_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 3),
            "skipped_reason": self.skipped_reason,
            "checks": self.checks,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


@dataclass
class ScanReport:
    tool: str
    version: str
    target: Target
    profile: str
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0
    scope: dict[str, Any] = field(default_factory=dict)
    modules: dict[str, ModuleResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def all_errors(self) -> list[str]:
        items = list(self.errors)
        for name, result in self.modules.items():
            for message in result.errors:
                items.append(message if message.startswith(f"{name}:") else f"{name}: {message}")
        return list(dict.fromkeys(items))

    def findings(self) -> list[Finding]:
        items: list[Finding] = []
        for result in self.modules.values():
            items.extend(result.findings)
        return sorted(items, key=lambda f: (-f.severity.rank, f.module, f.id))

    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in reversed(SEVERITY_ORDER)}
        for finding in self.findings():
            counts[finding.severity.value] += 1
        return counts

    def highest_severity(self) -> Optional[Severity]:
        items = self.findings()
        return items[0].severity if items else None

    def summary(self) -> dict[str, Any]:
        highest = self.highest_severity()
        return {
            "findings_total": len(self.findings()),
            "findings_by_severity": self.severity_counts(),
            "highest_severity": highest.value if highest else None,
            "modules": {name: res.status for name, res in self.modules.items()},
            "errors": len(self.all_errors()),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target.to_dict(),
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 3),
            "scope": self.scope,
            "config": self.config,
            "summary": self.summary(),
            "errors": self.all_errors(),
            "modules": {name: res.to_dict() for name, res in self.modules.items()},
        }