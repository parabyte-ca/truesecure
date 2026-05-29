from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any


def _hash_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unreadable"


def collect_suid_binaries(search_roots: list[str]) -> dict[str, str]:
    """Return {path: sha256} for all SUID/SGID binaries under search_roots."""
    result: dict[str, str] = {}
    for root in search_roots:
        try:
            out = subprocess.check_output(
                ["find", root, "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
        for line in out.splitlines():
            path = line.strip()
            if path:
                result[path] = _hash_file(path)
    return result


def collect_crontabs() -> dict[str, str]:
    """Return {description: sha256} for all crontab files."""
    result: dict[str, str] = {}
    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
    ]
    cron_files = ["/etc/crontab", "/var/spool/cron/crontabs"]

    for path in cron_files:
        if os.path.isfile(path):
            result[path] = _hash_file(path)

    for d in cron_dirs:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            full = os.path.join(d, name)
            if os.path.isfile(full):
                result[full] = _hash_file(full)

    spool = "/var/spool/cron/crontabs"
    if os.path.isdir(spool):
        for name in os.listdir(spool):
            full = os.path.join(spool, name)
            if os.path.isfile(full):
                result[full] = _hash_file(full)

    return result


def collect_systemd_units() -> dict[str, str]:
    """Return {unit_path: sha256} for all enabled/active user-installed systemd units."""
    unit_dirs = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
    ]
    result: dict[str, str] = {}
    for d in unit_dirs:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name.endswith((".service", ".timer", ".socket", ".path")):
                full = os.path.join(d, name)
                if os.path.isfile(full):
                    result[full] = _hash_file(full)
    return result


def build_baseline(suid_search_roots: list[str]) -> dict[str, Any]:
    return {
        "suid_binaries": collect_suid_binaries(suid_search_roots),
        "crontabs": collect_crontabs(),
        "systemd_units": collect_systemd_units(),
    }


def load_baseline(state_dir: str) -> dict[str, Any]:
    path = os.path.join(state_dir, "baseline.json")
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def save_baseline(state_dir: str, data: dict[str, Any]) -> None:
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, "baseline.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
