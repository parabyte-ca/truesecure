from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from typing import Optional

import requests

from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_SIZE = 1000  # OSV allows up to 1000 queries per batch request
_CACHE_FILENAME = "cve_cache.json"


def get_installed_packages() -> list[tuple[str, str]]:
    """Return [(name, version), ...] from dpkg --list."""
    try:
        out = subprocess.check_output(
            ["dpkg", "--list"], stderr=subprocess.DEVNULL, text=True, timeout=30
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    packages: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            name = parts[1].split(":")[0]  # strip :amd64 suffix
            version = parts[2]
            packages.append((name, version))
    return packages


def _load_cache(cache_path: str) -> dict:
    if not os.path.isfile(cache_path):
        return {}
    try:
        with open(cache_path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache_path: str, cache: dict) -> None:
    if dir_part := os.path.dirname(cache_path):
        os.makedirs(dir_part, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(cache, f)


def _query_osv_batch(
    packages: list[tuple[str, str]],
    timeout_s: int = 60,
) -> dict[str, list[dict]]:
    """Query OSV.dev for a batch of packages. Returns {pkg_key: [vuln, ...]}."""
    results: dict[str, list[dict]] = {}

    queries = []
    keys = []
    for name, version in packages:
        queries.append({
            "version": version,
            "package": {"name": name, "ecosystem": "Debian"},
        })
        keys.append(f"{name}=={version}")

    # Process in batches
    for i in range(0, len(queries), _OSV_BATCH_SIZE):
        batch_queries = queries[i:i + _OSV_BATCH_SIZE]
        batch_keys = keys[i:i + _OSV_BATCH_SIZE]
        try:
            resp = requests.post(
                _OSV_BATCH_URL,
                json={"queries": batch_queries},
                timeout=timeout_s,
            )
            resp.raise_for_status()
            data = resp.json()
            batch_results = data.get("results", [])
            for key, result in zip(batch_keys, batch_results):
                vulns = result.get("vulns", [])
                if vulns:
                    results[key] = vulns
        except Exception as exc:
            logger.warning("OSV batch query failed (batch %d): %s", i // _OSV_BATCH_SIZE, exc)

    return results


def _severity_from_osv(vuln: dict) -> Severity:
    """Map OSV severity to our Severity enum."""
    severity_str = ""
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if score:
            severity_str = str(score).upper()
            break
    if "CRITICAL" in severity_str or "HIGH" in severity_str:
        return Severity.CRITICAL
    if "MEDIUM" in severity_str:
        return Severity.WARNING
    return Severity.INFO


def scan(
    state_dir: str = "/var/lib/truesecure",
    cache_ttl_hours: int = 24,
    osv_enabled: bool = True,
    nvd_api_key: Optional[str] = None,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    if not osv_enabled:
        return ScanResult(scanner="cve", ok=True, duration_s=time.time() - t0)

    packages = get_installed_packages()
    if not packages:
        errors.append("Could not list installed packages (dpkg not available?)")
        return ScanResult(scanner="cve", ok=True, errors=errors, duration_s=time.time() - t0)

    cache_path = os.path.join(state_dir, _CACHE_FILENAME)
    cache = _load_cache(cache_path)
    now = time.time()
    ttl_s = cache_ttl_hours * 3600

    # Only query packages not in cache or with stale/changed version
    to_query: list[tuple[str, str]] = []
    for name, version in packages:
        key = f"{name}=={version}"
        entry = cache.get(key)
        if entry is None or (now - entry.get("ts", 0)) > ttl_s:
            to_query.append((name, version))

    logger.info(
        "CVE scan: %d packages installed, %d need querying",
        len(packages), len(to_query),
    )

    if to_query:
        new_results = _query_osv_batch(to_query)
        for name, version in to_query:
            key = f"{name}=={version}"
            vulns = new_results.get(key, [])
            cache[key] = {"ts": now, "vulns": vulns}
        _save_cache(cache_path, cache)

    # Collect findings from cache
    for name, version in packages:
        key = f"{name}=={version}"
        entry = cache.get(key, {})
        vulns = entry.get("vulns", [])
        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No summary")
            severity = _severity_from_osv(vuln)

            # Extract CVE alias if available
            cve_id = None
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            findings.append(Finding(
                scanner="cve",
                severity=severity,
                title=f"Vulnerable package: {name} {version} ({vuln_id})",
                detail=f"{summary}",
                host=f"{name}=={version}",
                cve_id=cve_id or vuln_id,
            ))

    return ScanResult(
        scanner="cve",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )
