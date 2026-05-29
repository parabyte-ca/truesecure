from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml


class ConfigError(Exception):
    pass


@dataclass
class TelegramConfig:
    bot_token: str
    chat_id: str
    notify_on_info: bool = False


@dataclass
class ScanConfig:
    clamav_dirs: list[str] = field(default_factory=lambda: [
        "/home", "/root", "/tmp", "/var/tmp", "/dev/shm"
    ])
    clamav_bin: str = "clamscan"
    clamav_extra_args: list[str] = field(default_factory=lambda: [
        "--recursive", "--infected", "--no-summary"
    ])
    rkhunter_bin: str = "rkhunter"
    cpu_threshold_pct: float = 80.0
    suspicious_dirs: list[str] = field(default_factory=lambda: [
        "/tmp", "/dev/shm", "/run/shm"
    ])
    cve_osv_enabled: bool = True
    cve_nvd_api_key: Optional[str] = None
    allowlisted_ips: list[str] = field(default_factory=list)


@dataclass
class IntegrityConfig:
    suid_search_roots: list[str] = field(default_factory=lambda: ["/usr", "/bin", "/sbin"])
    check_crontabs: bool = True
    check_systemd_units: bool = True


@dataclass
class ContainersConfig:
    enabled: bool = True
    # Image names/digests that are expected on this system
    allowed_images: list[str] = field(default_factory=list)
    # Scan container overlay FS with ClamAV (full profile only, opt-in — high I/O)
    clamav_overlay_scan: bool = False
    # Host paths that should never be bind-mounted into containers
    sensitive_mount_paths: list[str] = field(default_factory=lambda: [
        "/etc", "/root", "/var/lib/truesecure", "/proc", "/sys"
    ])


@dataclass
class FeedsConfig:
    ttl_hours: int = 6
    feeds_dir: str = "/var/lib/truesecure/feeds"


@dataclass
class AppConfig:
    telegram: TelegramConfig
    scan: ScanConfig = field(default_factory=ScanConfig)
    integrity: IntegrityConfig = field(default_factory=IntegrityConfig)
    containers: ContainersConfig = field(default_factory=ContainersConfig)
    feeds: FeedsConfig = field(default_factory=FeedsConfig)
    state_dir: str = "/var/lib/truesecure"
    log_level: str = "INFO"


_SEARCH_PATHS = [
    "/etc/truesecure/config.yaml",
    os.path.expanduser("~/.truesecure/config.yaml"),
    "config.yaml",
]


def load_config(path: Optional[str] = None) -> AppConfig:
    if path is None:
        for candidate in _SEARCH_PATHS:
            if os.path.isfile(candidate):
                path = candidate
                break

    if path is None:
        raise ConfigError(
            "No config file found. Create one at /etc/truesecure/config.yaml "
            "(see config.yaml.example) and set telegram.bot_token and telegram.chat_id."
        )

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    tg = raw.get("telegram", {})
    bot_token = tg.get("bot_token", "")
    chat_id = tg.get("chat_id", "")

    # Allow env var overrides for secrets
    bot_token = os.environ.get("TRUESECURE_BOT_TOKEN", bot_token)
    chat_id = os.environ.get("TRUESECURE_CHAT_ID", chat_id)

    if not bot_token or bot_token == "YOUR_BOT_TOKEN_HERE":
        raise ConfigError(
            "telegram.bot_token is not set in config. "
            "Get a token from @BotFather on Telegram."
        )
    if not chat_id or chat_id == "YOUR_CHAT_ID_HERE":
        raise ConfigError(
            "telegram.chat_id is not set in config. "
            "Set it to your numeric chat ID or @channel_name."
        )

    telegram = TelegramConfig(
        bot_token=bot_token,
        chat_id=str(chat_id),
        notify_on_info=tg.get("notify_on_info", False),
    )

    s = raw.get("scan", {})
    scan = ScanConfig(
        clamav_dirs=s.get("clamav_dirs", ScanConfig.__dataclass_fields__["clamav_dirs"].default_factory()),
        clamav_bin=s.get("clamav_bin", "clamscan"),
        clamav_extra_args=s.get("clamav_extra_args", ScanConfig.__dataclass_fields__["clamav_extra_args"].default_factory()),
        rkhunter_bin=s.get("rkhunter_bin", "rkhunter"),
        cpu_threshold_pct=float(s.get("cpu_threshold_pct", 80.0)),
        suspicious_dirs=s.get("suspicious_dirs", ScanConfig.__dataclass_fields__["suspicious_dirs"].default_factory()),
        cve_osv_enabled=s.get("cve_osv_enabled", True),
        cve_nvd_api_key=s.get("cve_nvd_api_key"),
        allowlisted_ips=s.get("allowlisted_ips", []),
    )

    ig = raw.get("integrity", {})
    integrity = IntegrityConfig(
        suid_search_roots=ig.get("suid_search_roots", IntegrityConfig.__dataclass_fields__["suid_search_roots"].default_factory()),
        check_crontabs=ig.get("check_crontabs", True),
        check_systemd_units=ig.get("check_systemd_units", True),
    )

    cg = raw.get("containers", {})
    containers = ContainersConfig(
        enabled=cg.get("enabled", True),
        allowed_images=cg.get("allowed_images", []),
        clamav_overlay_scan=cg.get("clamav_overlay_scan", False),
        sensitive_mount_paths=cg.get(
            "sensitive_mount_paths",
            ContainersConfig.__dataclass_fields__["sensitive_mount_paths"].default_factory(),
        ),
    )

    fg = raw.get("feeds", {})
    feeds = FeedsConfig(
        ttl_hours=int(fg.get("ttl_hours", 6)),
        feeds_dir=fg.get("feeds_dir", "/var/lib/truesecure/feeds"),
    )

    return AppConfig(
        telegram=telegram,
        scan=scan,
        integrity=integrity,
        containers=containers,
        feeds=feeds,
        state_dir=raw.get("state_dir", "/var/lib/truesecure"),
        log_level=raw.get("log_level", "INFO"),
    )
