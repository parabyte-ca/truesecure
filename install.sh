#!/usr/bin/env bash
# TrueSecure install script for TrueNAS SCALE
#
# IMPORTANT: On TrueNAS SCALE the root filesystem is IMMUTABLE and wiped on OS updates.
# All paths below default to /usr/local and /var/lib, which WILL be cleared on updates.
#
# For persistence across TrueNAS updates:
#   1. Change PERSISTENT_BASE below to a path on your ZFS pool, e.g. /mnt/tank/truesecure
#   2. Set state_dir and feeds.feeds_dir in /etc/truesecure/config.yaml to the same path
#   3. Add this script as a TrueNAS Post-Init script in the UI:
#      System > Advanced > Init/Shutdown Scripts > Add (type=Script, when=Post Init)
#
set -euo pipefail

PERSISTENT_BASE=""   # e.g. /mnt/tank/truesecure — leave empty to use default paths
INSTALL_PREFIX="/usr/local"
CONFIG_DIR="/etc/truesecure"
SYSTEMD_DIR="/etc/systemd/system"

if [[ -n "$PERSISTENT_BASE" ]]; then
    STATE_DIR="$PERSISTENT_BASE/state"
    FEEDS_DIR="$PERSISTENT_BASE/feeds"
    CLAMAV_DB_DIR="$PERSISTENT_BASE/clamav"
else
    STATE_DIR="/var/lib/truesecure"
    FEEDS_DIR="/var/lib/truesecure/feeds"
    CLAMAV_DB_DIR="/var/lib/clamav"
fi

echo "=============================="
echo " TrueSecure Installer"
echo "=============================="
echo "Install prefix: $INSTALL_PREFIX"
echo "Config dir:     $CONFIG_DIR"
echo "State dir:      $STATE_DIR"
echo ""

# --- 1. System dependencies ---
echo "[1/7] Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    clamav \
    clamav-freshclam \
    rkhunter \
    python3 \
    python3-pip \
    python3-venv \
    iproute2 \
    curl \
    ionice 2>/dev/null || true

# --- 2. Update ClamAV virus definitions ---
echo "[2/7] Updating ClamAV signatures..."
if [[ -n "$PERSISTENT_BASE" ]]; then
    mkdir -p "$CLAMAV_DB_DIR"
    freshclam --datadir="$CLAMAV_DB_DIR" || echo "[warn] freshclam failed — definitions may be outdated"
else
    freshclam || echo "[warn] freshclam failed — definitions may be outdated"
fi

# --- 3. Install Python package ---
echo "[3/7] Installing truesecure Python package..."
# --break-system-packages is required on Debian 12+ (PEP 668)
pip3 install --quiet --break-system-packages --prefix="$INSTALL_PREFIX" .

# --- 4. Create directories ---
echo "[4/7] Creating directories..."
install -d -m 750 "$CONFIG_DIR"
install -d -m 755 "$STATE_DIR"
install -d -m 755 "$FEEDS_DIR"

# --- 5. Install config ---
echo "[5/7] Installing config..."
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    install -m 640 config.yaml.example "$CONFIG_DIR/config.yaml"
    echo ""
    echo "  *** ACTION REQUIRED ***"
    echo "  Edit $CONFIG_DIR/config.yaml and set:"
    echo "    telegram.bot_token  — from @BotFather on Telegram"
    echo "    telegram.chat_id    — your chat ID"
    if [[ -n "$PERSISTENT_BASE" ]]; then
        echo "    state_dir           — change to $STATE_DIR"
        echo "    feeds.feeds_dir     — change to $FEEDS_DIR"
    fi
    echo ""
else
    echo "  [skip] Config already exists at $CONFIG_DIR/config.yaml"
fi

# --- 6. Install and enable systemd units ---
echo "[6/7] Installing systemd units..."
install -m 644 systemd/truesecure-startup.service "$SYSTEMD_DIR/"
install -m 644 systemd/truesecure-daily.service   "$SYSTEMD_DIR/"
install -m 644 systemd/truesecure-daily.timer      "$SYSTEMD_DIR/"

systemctl daemon-reload
systemctl enable truesecure-startup.service
systemctl enable --now truesecure-daily.timer
echo "  Startup service enabled."
echo "  Daily timer enabled (runs at 2:00am)."

# --- 7. rkhunter initial setup ---
echo "[7/7] Initialising rkhunter..."
# Update rkhunter data files
rkhunter --update --nocolors 2>/dev/null || echo "[warn] rkhunter --update failed"
# Build rkhunter's file property database for this system
# Must be re-run after every TrueNAS OS update: rkhunter --propupd
rkhunter --propupd --nocolors 2>/dev/null || echo "[warn] rkhunter --propupd failed"

# --- Build integrity baseline ---
echo ""
echo "Building integrity baseline..."
"$INSTALL_PREFIX/bin/truesecure" baseline --reset \
    || echo "[warn] Baseline build failed — run 'truesecure baseline --reset' after configuring"

echo ""
echo "=============================="
echo " Installation complete!"
echo "=============================="
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/config.yaml  (set bot_token + chat_id)"
echo "  2. Run: truesecure test-notify   (verify Telegram works)"
echo "  3. Run: truesecure scan --quick --dry-run"
echo "  4. Run: truesecure scan --full  --dry-run"
echo ""
echo "TrueNAS update note:"
echo "  After each TrueNAS OS update, re-run this script to restore packages."
echo "  Add it as a Post-Init script in: System > Advanced > Init/Shutdown Scripts"
echo ""
echo "Logs:  journalctl -u truesecure-startup -u truesecure-daily -f"
echo "Timer: systemctl list-timers truesecure-daily"
