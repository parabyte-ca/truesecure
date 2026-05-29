from __future__ import annotations

import logging
import subprocess
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# rkhunter log path
_RKHUNTER_LOG = "/var/log/rkhunter.log"


def scan(
    rkhunter_bin: str = "rkhunter",
    timeout_s: int = 600,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    cmd = [
        rkhunter_bin,
        "--check",
        "--skip-keypress",
        "--quiet",
        "--nocolors",
        "--report-warnings-only",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError:
        errors.append(
            f"rkhunter not found at '{rkhunter_bin}' — install with: apt-get install rkhunter"
        )
        return ScanResult(scanner="rootkit", ok=True, errors=errors, duration_s=time.time() - t0)
    except subprocess.TimeoutExpired:
        errors.append(f"rkhunter timed out after {timeout_s}s")
        return ScanResult(scanner="rootkit", ok=False, errors=errors, duration_s=time.time() - t0)

    # Parse stdout/stderr for warnings
    output = result.stdout + result.stderr
    warnings = _parse_rkhunter_output(output)

    for w in warnings:
        # Distinguish between high-confidence warnings and informational notes
        severity = _classify_warning(w)
        findings.append(Finding(
            scanner="rootkit",
            severity=severity,
            title=f"rkhunter: {w[:80]}",
            detail=w,
        ))

    # rkhunter exit codes: 0=clean, 1=warnings, 2=fatal
    if result.returncode == 2:
        errors.append("rkhunter exited with fatal error — check /var/log/rkhunter.log")

    return ScanResult(
        scanner="rootkit",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )


def _parse_rkhunter_output(output: str) -> list[str]:
    """Extract warning lines from rkhunter output."""
    warnings: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if "warning" in lower or "found" in lower or "suspicious" in lower:
            # Skip trivial rkhunter boilerplate
            if any(skip in lower for skip in [
                "checking for", "performing", "checking system",
                "running checks", "info:", "note:",
            ]):
                continue
            warnings.append(line)
    return warnings


def _classify_warning(warning: str) -> Severity:
    """Heuristically classify rkhunter warning severity."""
    lower = warning.lower()
    high_signals = [
        "rootkit", "backdoor", "trojan", "malware",
        "hidden file", "hidden process", "suspicious file in",
        "loaded kernel module", "shared memory",
    ]
    if any(s in lower for s in high_signals):
        return Severity.CRITICAL
    return Severity.WARNING
