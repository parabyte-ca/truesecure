"""
truesecure — TrueNAS SCALE security scanner.

Usage:
  truesecure scan [--quick|--full|--network|--malware|--cve|--integrity|--process|--containers]
                  [--dry-run] [--config PATH]
  truesecure baseline [--reset] [--config PATH]
  truesecure feeds update [--force] [--config PATH]
  truesecure test-notify [--config PATH]
"""
from __future__ import annotations

# IMPORTANT: This tool is alert-only. It NEVER kills processes, deletes files,
# modifies iptables rules, or takes any automated remediation action.

import argparse
import logging
import socket
import sys
import time
from typing import Optional

from truesecure import __version__
from truesecure.config import AppConfig, ConfigError, load_config
from truesecure.scanner.base import Finding, ScanResult


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
    )


def _run_scan_profile(
    profile: str,
    config: AppConfig,
    dry_run: bool = False,
) -> int:
    from truesecure import report
    from truesecure.feeds import manager as feeds
    from truesecure.notify.telegram import (
        TelegramNotifyError,
        format_clean_message,
        format_findings_message,
        send_alert,
    )
    from truesecure.scanner import (
        clamav,
        containers,
        cve,
        integrity,
        network,
        processes,
        rootkit,
    )

    t_start = time.time()
    results: list[ScanResult] = []
    logger = logging.getLogger("truesecure.cli")

    logger.info("Starting scan profile: %s", profile)

    # Always update feeds first (they're cached, so this is fast when fresh)
    logger.info("Updating threat feeds...")
    feeds.update_feeds(
        feeds_dir=config.feeds.feeds_dir,
        ttl_hours=config.feeds.ttl_hours,
    )

    # Quick profile: fast checks only (startup scan target: <30s total)
    if profile in ("quick", "full", "network"):
        logger.info("Running: network scanner")
        results.append(network.scan(
            feeds_dir=config.feeds.feeds_dir,
            allowlisted_ips=config.scan.allowlisted_ips,
        ))

    if profile in ("quick", "full", "process"):
        logger.info("Running: process scanner")
        results.append(processes.scan(
            cpu_threshold_pct=config.scan.cpu_threshold_pct,
            suspicious_dirs=config.scan.suspicious_dirs,
        ))

    if profile in ("quick", "full", "integrity"):
        logger.info("Running: integrity scanner")
        results.append(integrity.scan(
            state_dir=config.state_dir,
            suid_search_roots=config.integrity.suid_search_roots,
            check_crontabs=config.integrity.check_crontabs,
            check_systemd_units=config.integrity.check_systemd_units,
        ))

    if profile in ("quick", "full", "containers"):
        logger.info("Running: container scanner")
        results.append(containers.scan(
            allowed_images=config.containers.allowed_images,
            sensitive_mount_paths=config.containers.sensitive_mount_paths,
            clamav_overlay_scan=(
                config.containers.clamav_overlay_scan and profile == "full"
            ),
            clamav_bin=config.scan.clamav_bin,
        ))

    # Full profile: heavier checks (daily scan)
    if profile in ("full", "malware"):
        logger.info("Running: ClamAV malware scan (this may take a while...)")
        results.append(clamav.scan(
            directories=config.scan.clamav_dirs,
            clamav_bin=config.scan.clamav_bin,
            extra_args=config.scan.clamav_extra_args,
        ))
        logger.info("Running: rootkit scanner (rkhunter)")
        results.append(rootkit.scan(rkhunter_bin=config.scan.rkhunter_bin))

    if profile in ("full", "cve"):
        logger.info("Running: CVE scanner")
        results.append(cve.scan(
            state_dir=config.state_dir,
            osv_enabled=config.scan.cve_osv_enabled,
            nvd_api_key=config.scan.cve_nvd_api_key,
        ))

    duration = time.time() - t_start
    all_findings = report.aggregate(results)
    all_errors = report.collect_errors(results)

    # Filter by notification level
    notifiable = all_findings
    if not config.telegram.notify_on_info:
        from truesecure.scanner.base import Severity
        notifiable = [f for f in all_findings if f.severity != Severity.INFO]

    summary = report.summary_text(
        all_findings,
        scan_profile=profile,
        duration_s=duration,
        errors=all_errors,
    )
    print(summary)

    if not dry_run:
        try:
            hostname = socket.gethostname()
            if notifiable:
                title, body = format_findings_message(notifiable, hostname, profile)
                send_alert(
                    bot_token=config.telegram.bot_token,
                    chat_id=config.telegram.chat_id,
                    title=title,
                    body=body,
                    severity=notifiable[0].severity.value if notifiable else "info",
                    hostname=hostname,
                )
                logger.info("Telegram alert sent (%d finding(s))", len(notifiable))
            else:
                msg = format_clean_message(profile, duration)
                from truesecure.notify.telegram import send_message
                send_message(config.telegram.bot_token, config.telegram.chat_id, msg)
                logger.info("Telegram clean-status message sent")
        except TelegramNotifyError as exc:
            logger.error("Telegram notification failed: %s", exc)
    else:
        logger.info("[dry-run] Telegram notification skipped")

    return report.exit_code(all_findings, all_errors if all_errors else None)


def _cmd_scan(args: argparse.Namespace, config: AppConfig) -> int:
    if args.quick:
        profile = "quick"
    elif args.full:
        profile = "full"
    elif args.network:
        profile = "network"
    elif args.malware:
        profile = "malware"
    elif args.cve:
        profile = "cve"
    elif args.integrity:
        profile = "integrity"
    elif args.process:
        profile = "process"
    elif args.containers:
        profile = "containers"
    else:
        profile = "quick"  # default

    return _run_scan_profile(profile, config, dry_run=args.dry_run)


def _cmd_baseline(args: argparse.Namespace, config: AppConfig) -> int:
    from truesecure.scanner.integrity import reset_baseline
    if args.reset:
        reset_baseline(config.state_dir, config.integrity.suid_search_roots)
        print("Baseline saved to", config.state_dir)
    else:
        import json
        from truesecure.state import load_baseline
        baseline = load_baseline(config.state_dir)
        if not baseline:
            print("No baseline found — run: truesecure baseline --reset")
            return 1
        suid = len(baseline.get("suid_binaries", {}))
        cron = len(baseline.get("crontabs", {}))
        units = len(baseline.get("systemd_units", {}))
        print(f"Baseline: {suid} SUID binaries, {cron} crontabs, {units} systemd units")
    return 0


def _cmd_feeds(args: argparse.Namespace, config: AppConfig) -> int:
    from truesecure.feeds.manager import update_feeds
    results = update_feeds(
        feeds_dir=config.feeds.feeds_dir,
        ttl_hours=config.feeds.ttl_hours,
        force=getattr(args, "force", False),
    )
    for name, ok in results.items():
        status = "OK" if ok else "FAILED"
        print(f"  {name}: {status}")
    return 0 if all(results.values()) else 1


def _cmd_test_notify(args: argparse.Namespace, config: AppConfig) -> int:
    from truesecure.notify.telegram import TelegramNotifyError, send_alert
    try:
        send_alert(
            bot_token=config.telegram.bot_token,
            chat_id=config.telegram.chat_id,
            title="TrueSecure test notification",
            body="✅ Telegram notifications are configured correctly.\n"
                 f"Host: {socket.gethostname()}\nVersion: {__version__}",
            severity="info",
        )
        print("Test notification sent successfully.")
        return 0
    except TelegramNotifyError as exc:
        print(f"Notification failed: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="truesecure",
        description="TrueNAS SCALE security scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", metavar="PATH", help="Path to config.yaml")

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Run a security scan")
    profile_group = scan_p.add_mutually_exclusive_group()
    profile_group.add_argument("--quick", action="store_true", help="Fast profile (default, used by startup service)")
    profile_group.add_argument("--full", action="store_true", help="Full profile (ClamAV + rkhunter + CVE, used by daily timer)")
    profile_group.add_argument("--network", action="store_true", help="Network connections only")
    profile_group.add_argument("--malware", action="store_true", help="ClamAV + rkhunter only")
    profile_group.add_argument("--cve", action="store_true", help="CVE scan only")
    profile_group.add_argument("--integrity", action="store_true", help="File integrity only")
    profile_group.add_argument("--process", action="store_true", help="Process inspection only")
    profile_group.add_argument("--containers", action="store_true", help="Container audit only")
    scan_p.add_argument("--dry-run", action="store_true", help="Print findings but skip Telegram notification")

    # baseline
    baseline_p = sub.add_parser("baseline", help="Manage integrity baseline")
    baseline_p.add_argument("--reset", action="store_true", help="Build and save a new baseline")

    # feeds
    feeds_p = sub.add_parser("feeds", help="Manage threat intelligence feeds")
    feeds_sub = feeds_p.add_subparsers(dest="feeds_command", required=True)
    update_p = feeds_sub.add_parser("update", help="Download latest threat feeds")
    update_p.add_argument("--force", action="store_true", help="Force re-download even if feeds are fresh")

    # test-notify
    sub.add_parser("test-notify", help="Send a test Telegram notification")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    _setup_logging(config.log_level)

    if args.command == "scan":
        sys.exit(_cmd_scan(args, config))
    elif args.command == "baseline":
        sys.exit(_cmd_baseline(args, config))
    elif args.command == "feeds":
        sys.exit(_cmd_feeds(args, config))
    elif args.command == "test-notify":
        sys.exit(_cmd_test_notify(args, config))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
