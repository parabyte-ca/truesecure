from __future__ import annotations

import logging
import os
import re
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# Known miner process name patterns
_MINER_PATTERNS = [
    re.compile(r"xmrig", re.I),
    re.compile(r"minerd", re.I),
    re.compile(r"cpuminer", re.I),
    re.compile(r"ccminer", re.I),
    re.compile(r"ethminer", re.I),
    re.compile(r"t-rex", re.I),
    re.compile(r"nbminer", re.I),
    re.compile(r"lolminer", re.I),
    re.compile(r"cgminer", re.I),
    re.compile(r"bfgminer", re.I),
]


def _read_proc_comm(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def _read_proc_exe(pid: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _read_proc_cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        return ""


def _read_proc_stat_cpu(pid: str) -> Optional[float]:
    """Return total CPU ticks (utime+stime) for a process."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        if len(parts) >= 15:
            return float(parts[13]) + float(parts[14])
    except (OSError, ValueError):
        pass
    return None


def _get_total_cpu_ticks() -> Optional[float]:
    try:
        with open("/proc/stat") as f:
            first_line = f.readline()
        parts = first_line.split()
        if parts[0] == "cpu":
            return sum(float(x) for x in parts[1:])
    except (OSError, ValueError):
        pass
    return None


def _get_all_pids() -> list[str]:
    try:
        return [e for e in os.listdir("/proc") if e.isdigit()]
    except OSError:
        return []


def scan(
    cpu_threshold_pct: float = 80.0,
    suspicious_dirs: Optional[list[str]] = None,
    check_deleted_exe: bool = True,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    if suspicious_dirs is None:
        suspicious_dirs = ["/tmp", "/dev/shm", "/run/shm"]

    if not os.access("/proc/1/exe", os.R_OK) and not os.path.exists("/proc/1"):
        errors.append("/proc not accessible — process scanning skipped")
        return ScanResult(scanner="processes", ok=True, errors=errors, duration_s=time.time() - t0)

    pids = _get_all_pids()
    total_ticks_start = _get_total_cpu_ticks()
    # Small delay to measure CPU usage
    time.sleep(1)
    total_ticks_end = _get_total_cpu_ticks()
    total_delta = (total_ticks_end or 0) - (total_ticks_start or 1)
    if total_delta <= 0:
        total_delta = 1

    for pid in pids:
        exe = _read_proc_exe(pid)
        comm = _read_proc_comm(pid)
        cmdline = _read_proc_cmdline(pid)

        # 1. Deleted executable (process running from a file that no longer exists on disk)
        if check_deleted_exe and exe.endswith(" (deleted)"):
            real_exe = exe.replace(" (deleted)", "")
            # Exclude kernel threads and known transient executables
            if real_exe and not real_exe.startswith("/memfd:"):
                findings.append(Finding(
                    scanner="processes",
                    severity=Severity.WARNING,
                    title=f"Process running from deleted executable: {comm or pid}",
                    detail=f"PID {pid} exe={real_exe} (deleted from disk) — may indicate in-memory malware",
                    host=pid,
                ))

        # 2. Process launched from suspicious directory
        for sus_dir in suspicious_dirs:
            if exe.startswith(sus_dir) and not exe.endswith(" (deleted)"):
                findings.append(Finding(
                    scanner="processes",
                    severity=Severity.WARNING,
                    title=f"Process running from suspicious directory: {sus_dir}",
                    detail=f"PID {pid} comm={comm!r} exe={exe!r} cmdline={cmdline[:100]!r}",
                    host=pid,
                ))
                break

        # 3. Known miner pattern match
        name_to_check = f"{comm} {cmdline}".lower()
        for pattern in _MINER_PATTERNS:
            if pattern.search(name_to_check):
                findings.append(Finding(
                    scanner="processes",
                    severity=Severity.CRITICAL,
                    title=f"Possible crypto miner detected: {comm or pid}",
                    detail=f"PID {pid} matched miner pattern '{pattern.pattern}' — cmdline: {cmdline[:150]}",
                    host=pid,
                ))
                break

    # 4. High single-process CPU (re-read stats after delay)
    for pid in _get_all_pids():
        ticks = _read_proc_stat_cpu(pid)
        if ticks is None:
            continue
        # Simple heuristic: if ticks / total_delta > threshold, flag it
        cpu_pct = (ticks / total_delta) * 100
        if cpu_pct > cpu_threshold_pct:
            comm = _read_proc_comm(pid)
            exe = _read_proc_exe(pid)
            # Skip expected high-CPU system daemons
            if comm in ("kworker", "ksoftirqd", "migration", "rcu_sched"):
                continue
            findings.append(Finding(
                scanner="processes",
                severity=Severity.WARNING,
                title=f"High CPU process: {comm or pid} ({cpu_pct:.0f}%)",
                detail=f"PID {pid} exe={exe!r} consuming ~{cpu_pct:.0f}% CPU — possible miner or runaway process",
                host=pid,
            ))

    return ScanResult(
        scanner="processes",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )
