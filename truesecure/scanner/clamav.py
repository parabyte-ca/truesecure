from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


def scan(
    directories: list[str],
    clamav_bin: str = "clamscan",
    extra_args: Optional[list[str]] = None,
    timeout_s: int = 7200,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    if extra_args is None:
        extra_args = ["--recursive", "--infected", "--no-summary"]

    # Wrap with ionice for idle I/O priority only if ionice is available
    if shutil.which("ionice"):
        cmd = ["ionice", "-c", "3", clamav_bin] + extra_args + [d for d in directories if d]
    else:
        logger.debug("ionice not found — running clamscan without I/O priority adjustment")
        cmd = [clamav_bin] + extra_args + [d for d in directories if d]

    if not shutil.which(clamav_bin):
        errors.append(
            f"ClamAV not found at '{clamav_bin}' — install with: apt-get install clamav"
        )
        return ScanResult(scanner="clamav", ok=True, errors=errors, duration_s=time.time() - t0)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        errors.append(f"Failed to launch scanner: {exc}")
        return ScanResult(scanner="clamav", ok=True, errors=errors, duration_s=time.time() - t0)
    except subprocess.TimeoutExpired:
        errors.append(f"ClamAV scan timed out after {timeout_s}s")
        return ScanResult(scanner="clamav", ok=False, errors=errors, duration_s=time.time() - t0)

    # clamscan exit code: 0=clean, 1=virus found, 2=error
    if result.returncode == 2:
        for line in result.stderr.splitlines():
            if line.strip():
                errors.append(f"clamscan: {line.strip()}")

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or "FOUND" not in line:
            continue
        # Format: /path/to/file: ThreatName FOUND
        parts = line.rsplit(":", 2)
        path = parts[0].strip() if parts else line
        threat = parts[1].strip() if len(parts) > 1 else "unknown threat"
        threat = threat.replace(" FOUND", "").strip()

        findings.append(Finding(
            scanner="clamav",
            severity=Severity.CRITICAL,
            title=f"Malware detected: {threat}",
            detail=f"ClamAV found {threat!r} at: {path}",
            host=path,
        ))

    return ScanResult(
        scanner="clamav",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )
