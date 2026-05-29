from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from truesecure.scanner.base import Finding, Severity

_API_BASE = "https://api.telegram.org/bot{token}/sendMessage"
_MAX_MSG_LEN = 4096

_SEVERITY_ICONS = {
    "critical": "\U0001f6a8",  # 🚨
    "warning": "⚠️",  # ⚠️
    "info": "ℹ️",  # ℹ️
}

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


class TelegramNotifyError(Exception):
    pass


def send_message(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a single raw message. Returns True on success."""
    url = _API_BASE.format(token=bot_token)
    resp = requests.post(
        url,
        json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
        timeout=15,
    )
    if not resp.ok:
        raise TelegramNotifyError(
            f"Telegram API error {resp.status_code}: {resp.text[:200]}"
        )
    return True


def send_alert(
    bot_token: str,
    chat_id: str,
    title: str,
    body: str,
    severity: str = "warning",
    hostname: str | None = None,
) -> bool:
    icon = _SEVERITY_ICONS.get(severity, "⚠️")
    host = hostname or socket.gethostname()
    header = f"{icon} <b>{title}</b>\n<b>Host:</b> {host}\n\n"

    # Paginate the body first, then prepend the header (with page number if
    # multiple chunks) so every message has identifying context.
    body_chunks = _paginate(body) if body else [""]
    total = len(body_chunks)
    for i, chunk in enumerate(body_chunks, 1):
        page_suffix = f"\n\n<i>(page {i}/{total})</i>" if total > 1 else ""
        send_message(bot_token, chat_id, header + chunk + page_suffix)
    return True


def format_findings_message(
    findings: list[Finding],
    hostname: str,
    scan_profile: str,
) -> tuple[str, str]:
    """Returns (title, body) for send_alert()."""
    from truesecure.scanner.base import Severity

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]

    if critical:
        title = f"TrueSecure [{scan_profile}]: {len(critical)} CRITICAL finding(s)"
        severity = "critical"
    elif warnings:
        title = f"TrueSecure [{scan_profile}]: {len(warnings)} warning(s)"
        severity = "warning"
    else:
        title = f"TrueSecure [{scan_profile}]: {len(infos)} info finding(s)"
        severity = "info"

    lines: list[str] = []

    def _add_section(label: str, items: list[Finding]) -> None:
        if not items:
            return
        lines.append(f"<b>— {label} ({len(items)}) —</b>")
        for f in items:
            host_str = f" [{f.host}]" if f.host else ""
            cve_str = f" ({f.cve_id})" if f.cve_id else ""
            lines.append(f"• <b>{f.title}</b>{cve_str}{host_str}")
            if f.detail:
                lines.append(f"  {f.detail[:200]}")

    _add_section("CRITICAL", critical)
    _add_section("WARNING", warnings)
    _add_section("INFO", infos)

    body = "\n".join(lines)
    return title, body


def format_clean_message(scan_profile: str, duration_s: float) -> str:
    return (
        f"✅ <b>TrueSecure [{scan_profile}]</b>: No threats found. "
        f"(scan took {duration_s:.1f}s)"
    )


def _paginate(text: str) -> list[str]:
    if len(text) <= _MAX_MSG_LEN:
        return [text]
    chunks: list[str] = []
    while text:
        if len(text) <= _MAX_MSG_LEN:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, _MAX_MSG_LEN)
        if split_at == -1:
            split_at = _MAX_MSG_LEN
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks
