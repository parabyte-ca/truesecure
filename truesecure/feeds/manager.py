from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

FEEDS: dict[str, dict[str, Any]] = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "filename": "feodo_ips.json",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/json/",
        "filename": "urlhaus.json",
    },
}


def _feed_path(feeds_dir: str, filename: str) -> str:
    return os.path.join(feeds_dir, filename)


def _is_stale(path: str, ttl_hours: int) -> bool:
    if not os.path.isfile(path):
        return True
    age_s = time.time() - os.path.getmtime(path)
    return age_s > ttl_hours * 3600


def update_feeds(
    feeds_dir: str = "/var/lib/truesecure/feeds",
    ttl_hours: int = 6,
    force: bool = False,
    timeout_s: int = 30,
) -> dict[str, bool]:
    os.makedirs(feeds_dir, exist_ok=True)
    results: dict[str, bool] = {}

    for name, meta in FEEDS.items():
        path = _feed_path(feeds_dir, meta["filename"])
        if not force and not _is_stale(path, ttl_hours):
            logger.debug("Feed %s is fresh, skipping download", name)
            results[name] = True
            continue

        logger.info("Downloading feed: %s", name)
        try:
            resp = requests.get(meta["url"], timeout=timeout_s)
            resp.raise_for_status()
            with open(path, "wb") as f:
                f.write(resp.content)
            results[name] = True
            logger.info("Feed %s updated (%d bytes)", name, len(resp.content))
        except Exception as exc:
            logger.warning("Failed to update feed %s: %s", name, exc)
            results[name] = False

    return results


def load_feed(
    feed_name: str,
    feeds_dir: str = "/var/lib/truesecure/feeds",
) -> Any:
    meta = FEEDS.get(feed_name)
    if not meta:
        logger.warning("Unknown feed: %s", feed_name)
        return None
    path = _feed_path(feeds_dir, meta["filename"])
    if not os.path.isfile(path):
        logger.warning("Feed file not found: %s (run 'truesecure feeds update')", path)
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to load feed %s: %s", feed_name, exc)
        return None


def extract_feodo_ips(feed_data: list[dict]) -> set[str]:
    """Extract blocked IPs from Feodo Tracker JSON feed."""
    ips: set[str] = set()
    if not isinstance(feed_data, list):
        return ips
    for entry in feed_data:
        ip = entry.get("ip_address") or entry.get("ip")
        if ip:
            ips.add(str(ip).strip())
    return ips


def extract_urlhaus_domains(feed_data: dict) -> set[str]:
    """Extract malicious domains/hosts from URLhaus JSON feed."""
    domains: set[str] = set()
    if not isinstance(feed_data, dict):
        return domains
    urls = feed_data.get("urls", [])
    for entry in urls:
        host = entry.get("host") or entry.get("url_host")
        if host:
            domains.add(str(host).strip().lower())
    return domains


def extract_urlhaus_ips(feed_data: dict) -> set[str]:
    """Extract IPs from URLhaus that are plain IP addresses (not hostnames)."""
    ips: set[str] = set()
    for host in extract_urlhaus_domains(feed_data):
        # Simple heuristic: if it looks like an IP, include it
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            ips.add(host)
    return ips
