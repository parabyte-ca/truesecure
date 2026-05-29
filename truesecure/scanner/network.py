from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess
import time
from typing import Optional

from truesecure.feeds.manager import (
    extract_feodo_ips,
    extract_urlhaus_domains,
    extract_urlhaus_ips,
    load_feed,
)
from truesecure.scanner.base import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# RFC1918 + loopback + link-local — always considered safe
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Common ports expected to be open on TrueNAS — not flagged as unusual listeners
_COMMON_PORTS = {
    22, 80, 443, 111, 2049, 445, 139, 137, 138,  # SSH, HTTP, HTTPS, NFS, SMB
    6000, 6100, 8006, 9000, 9001, 9090,            # TrueNAS middleware, Portainer, etc.
    3260, 860,                                      # iSCSI
    5000, 5001,                                     # Syncthing / misc apps
    32400,                                          # Plex
}

_SS_HEADER_RE = re.compile(r"^Netid\s+State")


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _parse_addr(addr: str) -> tuple[str, str]:
    """Split 'IP:port' or '[IPv6]:port' into (ip, port)."""
    if addr.startswith("["):
        # Bracketed IPv6: [::1]:22
        try:
            bracket_end = addr.index("]")
        except ValueError:
            return addr, ""
        ip = addr[1:bracket_end]
        port = addr[bracket_end + 2:] if bracket_end + 2 < len(addr) else ""
    elif addr.count(":") == 1:
        # IPv4 with port: 1.2.3.4:8080
        ip, port = addr.rsplit(":", 1)
    elif ":" not in addr:
        # Bare IPv4 with no port (e.g. raw/ICMP sockets)
        ip, port = addr, ""
    else:
        # Bare IPv6 without brackets (multiple colons, no port)
        ip, port = addr, ""
    return ip, port


def parse_ss_output(raw: str) -> list[dict]:
    """Parse `ss -tunp` output into list of connection dicts."""
    connections: list[dict] = []
    for line in raw.splitlines():
        if not line or _SS_HEADER_RE.match(line):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        local_raw = parts[4] if len(parts) > 4 else ""
        remote_raw = parts[5] if len(parts) > 5 else ""
        process_info = " ".join(parts[6:]) if len(parts) > 6 else ""

        local_ip, local_port = _parse_addr(local_raw)
        remote_ip, remote_port = _parse_addr(remote_raw)

        # Extract pid/process from `users:(("nginx",pid=1234,fd=5))`
        pid = ""
        proc_name = ""
        pid_match = re.search(r'pid=(\d+)', process_info)
        name_match = re.search(r'"([^"]+)"', process_info)
        if pid_match:
            pid = pid_match.group(1)
        if name_match:
            proc_name = name_match.group(1)

        connections.append({
            "proto": proto,
            "state": state,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
            "process": proc_name,
        })
    return connections


def _get_ss_connections(netns: Optional[str] = None) -> list[dict]:
    cmd = ["ss", "-tunp"]
    if netns:
        cmd = ["ip", "netns", "exec", netns] + cmd
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=15)
        return parse_ss_output(out)
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        logger.warning("ss failed%s: %s", f" in netns {netns}" if netns else "", exc)
        return []


def _list_network_namespaces() -> list[str]:
    netns_dir = "/var/run/netns"
    if not os.path.isdir(netns_dir):
        return []
    try:
        return os.listdir(netns_dir)
    except OSError:
        return []


def scan(
    feeds_dir: str = "/var/lib/truesecure/feeds",
    allowlisted_ips: Optional[list[str]] = None,
    check_container_namespaces: bool = True,
) -> ScanResult:
    t0 = time.time()
    findings: list[Finding] = []
    errors: list[str] = []

    # Build allowlist networks
    allowed_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in (allowlisted_ips or []):
        try:
            allowed_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("Invalid allowlisted CIDR: %s", cidr)

    def _is_allowed(ip: str) -> bool:
        if _is_private(ip):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in allowed_nets)
        except ValueError:
            return False

    # Load threat intel
    feodo_data = load_feed("feodo_ips", feeds_dir)
    urlhaus_data = load_feed("urlhaus", feeds_dir)
    blocked_ips: set[str] = set()
    blocked_domains: set[str] = set()
    if feodo_data:
        blocked_ips |= extract_feodo_ips(feodo_data)
    if urlhaus_data:
        blocked_ips |= extract_urlhaus_ips(urlhaus_data)
        blocked_domains |= extract_urlhaus_domains(urlhaus_data)

    if not blocked_ips and not blocked_domains:
        errors.append("No threat feed data available — run 'truesecure feeds update'")

    # Collect connections from host + container namespaces
    all_connections: list[tuple[Optional[str], dict]] = []
    for conn in _get_ss_connections():
        all_connections.append((None, conn))

    if check_container_namespaces:
        for ns in _list_network_namespaces():
            for conn in _get_ss_connections(netns=ns):
                all_connections.append((ns, conn))

    seen_remote: set[str] = set()
    for netns, conn in all_connections:
        remote_ip = conn["remote_ip"]
        if not remote_ip or remote_ip in ("*", "0.0.0.0", "::", ""):
            continue
        if _is_allowed(remote_ip):
            continue

        ns_label = f" [netns:{netns}]" if netns else ""
        proc_label = f"{conn['process']}(pid={conn['pid']})" if conn["process"] else "unknown"

        # Check against blocked IPs
        if remote_ip in blocked_ips and remote_ip not in seen_remote:
            seen_remote.add(remote_ip)
            findings.append(Finding(
                scanner="network",
                severity=Severity.CRITICAL,
                title=f"Connection to known C2/malware IP: {remote_ip}",
                detail=(
                    f"Process {proc_label} has an active {conn['proto']} connection "
                    f"to {remote_ip}:{conn['remote_port']}{ns_label} "
                    f"(listed in Feodo/URLhaus threat feed)"
                ),
                host=remote_ip,
            ))

    # Check listening ports — flag unexpected high-numbered listeners
    listening_external: list[dict] = []
    for _, conn in all_connections:
        if conn["state"] not in ("LISTEN", "UNCONN"):
            continue
        lip = conn["local_ip"]
        if lip in ("127.0.0.1", "::1", ""):
            continue
        try:
            port = int(conn["local_port"])
        except (ValueError, TypeError):
            continue
        # Flag high ports that aren't common services (heuristic)
        if port > 1024 and port not in _COMMON_PORTS:
            listening_external.append(conn)

    if len(listening_external) > 10:
        # Summarize rather than individual findings to avoid noise
        ports = ", ".join(str(c["local_port"]) for c in listening_external[:10])
        findings.append(Finding(
            scanner="network",
            severity=Severity.INFO,
            title=f"{len(listening_external)} unusual external listening ports",
            detail=f"Ports: {ports}... — review with 'ss -tunlp'",
        ))
    else:
        for conn in listening_external:
            proc_label = f"{conn['process']}(pid={conn['pid']})" if conn["process"] else "unknown"
            findings.append(Finding(
                scanner="network",
                severity=Severity.INFO,
                title=f"Unusual listening port: {conn['local_port']}/{conn['proto']}",
                detail=f"Process {proc_label} listening on {conn['local_ip']}:{conn['local_port']}",
                host=f"{conn['local_ip']}:{conn['local_port']}",
            ))

    return ScanResult(
        scanner="network",
        ok=len(findings) == 0,
        findings=findings,
        errors=errors,
        duration_s=time.time() - t0,
    )

