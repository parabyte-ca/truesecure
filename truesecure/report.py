from __future__ import annotations

import socket
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}


def aggregate(results: list[ScanResult]) -> list[Finding]:
    """Flatten and sort all findings by severity."""
    all_findings: list[Finding] = []
    for r in results:
        all_findings.extend(r.findings)
    return sorted(all_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def collect_errors(results: list[ScanResult]) -> list[str]:
    errors: list[str] = []
    for r in results:
        for e in r.errors:
            errors.append(f"[{r.scanner}] {e}")
    return errors


def summary_text(
    findings: list[Finding],
    scan_profile: str,
    duration_s: float,
    hostname: Optional[str] = None,
    errors: Optional[list[str]] = None,
) -> str:
    host = hostname or socket.gethostname()
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]

    lines = [
        f"TrueSecure Security Report",
        f"Host: {host}  |  Profile: {scan_profile}  |  {now}",
        f"Duration: {duration_s:.1f}s",
        "",
    ]

    if not findings:
        lines.append("Status: CLEAN — No threats found.")
    else:
        lines.append(
            f"Status: {len(critical)} CRITICAL, {len(warnings)} WARNING, {len(infos)} INFO"
        )

    def _section(label: str, items: list[Finding]) -> None:
        if not items:
            return
        lines.append(f"\n=== {label} ({len(items)}) ===")
        for f in items:
            host_str = f" [{f.host}]" if f.host else ""
            cve_str = f" ({f.cve_id})" if f.cve_id else ""
            lines.append(f"  [{f.scanner}] {f.title}{cve_str}{host_str}")
            if f.detail:
                lines.append(f"    {f.detail[:300]}")

    _section("CRITICAL", critical)
    _section("WARNING", warnings)
    _section("INFO", infos)

    if errors:
        lines.append(f"\n=== SCAN ERRORS ({len(errors)}) ===")
        for e in errors:
            lines.append(f"  {e}")

    return "\n".join(lines)


def exit_code(findings: list[Finding], errors: Optional[list[str]] = None) -> int:
    """0=clean, 1=findings present, 2=scan errors only."""
    if errors:
        return 2
    if findings:
        return 1
    return 0
