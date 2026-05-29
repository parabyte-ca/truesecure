from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from typing import Optional

from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# Capabilities considered dangerous when granted to containers
_DANGEROUS_CAPS = {
    "cap_sys_admin", "cap_net_admin", "cap_sys_ptrace", "cap_sys_module",
    "cap_dac_override", "cap_dac_read_search", "cap_setuid", "cap_setgid",
    "cap_chown", "cap_sys_rawio", "cap_sys_boot",
}


def _run(cmd: list[str], timeout: int = 15) -> Optional[str]:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def _docker_available() -> bool:
    return _run(["docker", "info"], timeout=5) is not None


def _kubectl_available() -> bool:
    return _run(["k3s", "kubectl", "version", "--client"], timeout=5) is not None


def _list_docker_containers() -> list[dict]:
    out = _run(["docker", "ps", "--no-trunc", "--format", "{{json .}}"])
    if not out:
        return []
    containers = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return containers


def _inspect_docker_container(container_id: str) -> Optional[dict]:
    out = _run(["docker", "inspect", container_id])
    if not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if isinstance(data, list) and data else None
    except (json.JSONDecodeError, IndexError):
        return None


def _list_k3s_pods() -> list[dict]:
    out = _run(["k3s", "kubectl", "get", "pods", "-A", "-o", "json"])
    if not out:
        return []
    try:
        data = json.loads(out)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def scan(
    allowed_images: Optional[list[str]] = None,
    sensitive_mount_paths: Optional[list[str]] = None,
    clamav_overlay_scan: bool = False,
    clamav_bin: str = "clamscan",
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    if allowed_images is None:
        allowed_images = []
    if sensitive_mount_paths is None:
        sensitive_mount_paths = ["/etc", "/root", "/var/lib/truesecure", "/proc", "/sys"]

    allowed_image_set = set(allowed_images)
    has_docker = _docker_available()
    has_k3s = _kubectl_available()

    if not has_docker and not has_k3s:
        logger.debug("No Docker or k3s available — container scan skipped")
        return ScanResult(scanner="containers", ok=True, errors=errors, duration_s=time.time() - t0)

    # --- Docker containers ---
    if has_docker:
        containers = _list_docker_containers()
        overlay_dirs: list[str] = []

        for container in containers:
            c_id = container.get("ID", container.get("Id", ""))[:12]
            image = container.get("Image", "unknown")
            names = container.get("Names", "")

            label = f"{names or c_id} ({image})"

            # 1. Unknown image (not in allowlist)
            if allowed_image_set and image not in allowed_image_set:
                # Strip digest for matching too
                image_name = image.split("@")[0].split(":")[0]
                if image_name not in allowed_image_set and image not in allowed_image_set:
                    findings.append(Finding(
                        scanner="containers",
                        severity=Severity.WARNING,
                        title=f"Container running unlisted image: {image}",
                        detail=(
                            f"Container {label} uses an image not in containers.allowed_images. "
                            "Add it to silence this alert if expected."
                        ),
                        host=c_id,
                    ))

            # Inspect for detailed checks
            inspect = _inspect_docker_container(c_id)
            if not inspect:
                continue

            host_config = inspect.get("HostConfig", {})
            config = inspect.get("Config", {})

            # 2. Privileged container
            if host_config.get("Privileged"):
                findings.append(Finding(
                    scanner="containers",
                    severity=Severity.CRITICAL,
                    title=f"Privileged container running: {label}",
                    detail=(
                        f"Container {c_id} is running with --privileged. "
                        "This grants full host access and is a significant security risk."
                    ),
                    host=c_id,
                ))

            # 3. Dangerous capabilities
            caps_add = host_config.get("CapAdd") or []
            for cap in caps_add:
                if cap.lower() in _DANGEROUS_CAPS:
                    findings.append(Finding(
                        scanner="containers",
                        severity=Severity.WARNING,
                        title=f"Container has dangerous capability: {cap}",
                        detail=f"Container {label} was granted {cap}",
                        host=c_id,
                    ))

            # 4. Sensitive bind mounts — use only Mounts (canonical parsed form);
            # HostConfig.Binds is the raw string representation of the same data.
            mounts = inspect.get("Mounts", [])
            all_source_paths = list({
                m.get("Source", "")
                for m in mounts
                if m.get("Type") == "bind" and m.get("Source")
            })

            for src in all_source_paths:
                for sensitive in sensitive_mount_paths:
                    if src == sensitive or src.startswith(sensitive + "/"):
                        findings.append(Finding(
                            scanner="containers",
                            severity=Severity.WARNING,
                            title=f"Container mounts sensitive host path: {src}",
                            detail=f"Container {label} has bind mount from {src}",
                            host=c_id,
                        ))
                        break

            # 5. Collect overlay dirs for optional ClamAV scan
            if clamav_overlay_scan:
                graph_driver = inspect.get("GraphDriver", {})
                data = graph_driver.get("Data", {})
                upper_dir = data.get("UpperDir", "")
                if upper_dir and os.path.isdir(upper_dir):
                    overlay_dirs.append(upper_dir)

        # Optional ClamAV scan of overlay filesystems
        if clamav_overlay_scan and overlay_dirs:
            findings.extend(_scan_overlay_dirs(overlay_dirs, clamav_bin))

    # --- k3s / Kubernetes pods ---
    if has_k3s:
        pods = _list_k3s_pods()
        for pod in pods:
            meta = pod.get("metadata", {})
            spec = pod.get("spec", {})
            pod_name = f"{meta.get('namespace', '')}/{meta.get('name', '')}"

            for container in spec.get("containers", []) + spec.get("initContainers", []):
                c_name = container.get("name", "")
                image = container.get("image", "unknown")
                sc = container.get("securityContext", {})

                # Privileged
                if sc.get("privileged"):
                    findings.append(Finding(
                        scanner="containers",
                        severity=Severity.CRITICAL,
                        title=f"Privileged k3s container: {pod_name}/{c_name}",
                        detail=f"Container {c_name} in pod {pod_name} runs privileged",
                        host=pod_name,
                    ))

                # runAsRoot
                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    findings.append(Finding(
                        scanner="containers",
                        severity=Severity.WARNING,
                        title=f"k3s container runs as root: {pod_name}/{c_name}",
                        detail=f"Container {c_name} in pod {pod_name} runs as UID 0",
                        host=pod_name,
                    ))

            # Host path volumes
            for volume in spec.get("volumes", []):
                host_path = (volume.get("hostPath") or {}).get("path", "")
                if not host_path:
                    continue
                for sensitive in (sensitive_mount_paths or []):
                    if host_path == sensitive or host_path.startswith(sensitive + "/"):
                        findings.append(Finding(
                            scanner="containers",
                            severity=Severity.WARNING,
                            title=f"k3s pod mounts sensitive host path: {host_path}",
                            detail=f"Pod {pod_name} mounts {host_path} as hostPath volume",
                            host=pod_name,
                        ))
                        break

    return ScanResult(
        scanner="containers",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )


def _scan_overlay_dirs(overlay_dirs: list[str], clamav_bin: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        cmd = [
            "ionice", "-c", "3",
            clamav_bin, "--recursive", "--infected", "--no-summary",
        ] + overlay_dirs
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=1800)
        for line in out.splitlines():
            if "FOUND" in line:
                parts = line.rsplit(":", 2)
                path = parts[0] if parts else line
                threat = parts[1].strip() if len(parts) > 1 else "unknown"
                findings.append(Finding(
                    scanner="containers",
                    severity=Severity.CRITICAL,
                    title=f"Malware in container overlay FS: {threat}",
                    detail=f"ClamAV detected {threat} at {path}",
                    host=path,
                ))
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        logger.warning("ClamAV overlay scan failed: %s", exc)
    return findings
