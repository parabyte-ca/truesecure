from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}


@dataclass
class Finding:
    scanner: str
    severity: Severity
    title: str
    detail: str
    host: Optional[str] = None
    cve_id: Optional[str] = None

    def sort_key(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ScanResult:
    scanner: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
