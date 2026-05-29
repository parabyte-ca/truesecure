from __future__ import annotations

import logging
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity
from truesecure.state import (
    build_baseline,
    collect_crontabs,
    collect_suid_binaries,
    collect_systemd_units,
    load_baseline,
    save_baseline,
)

logger = logging.getLogger(__name__)


def scan(
    state_dir: str = "/var/lib/truesecure",
    suid_search_roots: Optional[list[str]] = None,
    check_crontabs: bool = True,
    check_systemd_units: bool = True,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    if suid_search_roots is None:
        suid_search_roots = ["/usr", "/bin", "/sbin"]

    baseline = load_baseline(state_dir)

    if not baseline:
        errors.append(
            "No integrity baseline found — run 'truesecure baseline --reset' to create one"
        )
        return ScanResult(
            scanner="integrity",
            ok=True,
            errors=errors,
            duration_s=time.time() - t0,
        )

    # --- SUID binary diff ---
    baseline_suid: dict[str, str] = baseline.get("suid_binaries", {})
    current_suid = collect_suid_binaries(suid_search_roots)

    new_suid = set(current_suid) - set(baseline_suid)
    changed_suid = {
        p for p in set(current_suid) & set(baseline_suid)
        if current_suid[p] != baseline_suid[p]
    }

    for path in sorted(new_suid):
        findings.append(Finding(
            scanner="integrity",
            severity=Severity.WARNING,
            title=f"New SUID/SGID binary: {path}",
            detail="This file was not present in the baseline — verify it is expected",
            host=path,
        ))

    for path in sorted(changed_suid):
        findings.append(Finding(
            scanner="integrity",
            severity=Severity.CRITICAL,
            title=f"SUID/SGID binary hash changed: {path}",
            detail=(
                f"Expected SHA256: {baseline_suid[path][:16]}... "
                f"Got: {current_suid[path][:16]}... — may indicate tampering"
            ),
            host=path,
        ))

    # --- Crontab diff ---
    if check_crontabs:
        baseline_cron: dict[str, str] = baseline.get("crontabs", {})
        current_cron = collect_crontabs()

        new_cron = set(current_cron) - set(baseline_cron)
        changed_cron = {
            p for p in set(current_cron) & set(baseline_cron)
            if current_cron[p] != baseline_cron[p]
        }

        for path in sorted(new_cron):
            findings.append(Finding(
                scanner="integrity",
                severity=Severity.WARNING,
                title=f"New crontab file: {path}",
                detail="Crontab not present in baseline — review contents",
                host=path,
            ))

        for path in sorted(changed_cron):
            findings.append(Finding(
                scanner="integrity",
                severity=Severity.WARNING,
                title=f"Crontab modified: {path}",
                detail="Crontab hash changed since baseline — review for suspicious entries",
                host=path,
            ))

    # --- Systemd unit diff ---
    if check_systemd_units:
        baseline_units: dict[str, str] = baseline.get("systemd_units", {})
        current_units = collect_systemd_units()

        new_units = set(current_units) - set(baseline_units)
        changed_units = {
            p for p in set(current_units) & set(baseline_units)
            if current_units[p] != baseline_units[p]
        }

        for path in sorted(new_units):
            findings.append(Finding(
                scanner="integrity",
                severity=Severity.INFO,
                title=f"New systemd unit: {path}",
                detail="Unit not in baseline — may be a newly installed service",
                host=path,
            ))

        for path in sorted(changed_units):
            findings.append(Finding(
                scanner="integrity",
                severity=Severity.WARNING,
                title=f"Systemd unit modified: {path}",
                detail="Unit file hash changed since baseline — review for unauthorized changes",
                host=path,
            ))

    return ScanResult(
        scanner="integrity",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )


def reset_baseline(state_dir: str, suid_search_roots: list[str]) -> None:
    """Build and save a fresh baseline."""
    logger.info("Building integrity baseline...")
    data = build_baseline(suid_search_roots)
    save_baseline(state_dir, data)
    suid_count = len(data.get("suid_binaries", {}))
    cron_count = len(data.get("crontabs", {}))
    unit_count = len(data.get("systemd_units", {}))
    logger.info(
        "Baseline saved: %d SUID binaries, %d crontab files, %d systemd units",
        suid_count, cron_count, unit_count,
    )
