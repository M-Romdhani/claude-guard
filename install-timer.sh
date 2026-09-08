#!/usr/bin/env bash
# Install (or remove) the Claude Guard systemd timer.
#
#   sudo ./install-timer.sh              # install and start a daily scan
#   sudo ./install-timer.sh --uninstall  # remove it again
#
# The timer runs as root so the scan can read firewall rules and unit state.
# The API key is copied to /etc/claude-guard/env, root-owned and mode 600, so
# the headless run never depends on a user's home directory being readable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR=/etc/systemd/system
KEY_DIR=/etc/claude-guard

[ "$(id -u)" -eq 0 ] || { echo "Run me with sudo."; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now claude-guard.timer 2>/dev/null || true
    rm -f "$UNIT_DIR/claude-guard.service" "$UNIT_DIR/claude-guard.timer"
    systemctl daemon-reload
    echo "Timer removed. $KEY_DIR and /var/lib/claude-guard were left in place."
    exit 0
fi

[ -x "$SCRIPT_DIR/.venv/bin/python" ] || { echo "No venv at $SCRIPT_DIR/.venv -- create it first."; exit 1; }

# Copy the invoking user's key into a root-owned location.
if [ ! -f "$KEY_DIR/env" ]; then
    USER_ENV="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.config/claude-guard/env"
    [ -f "$USER_ENV" ] || { echo "No key found at $USER_ENV -- create it first."; exit 1; }
    install -d -m 700 "$KEY_DIR"
    install -m 600 -o root -g root "$USER_ENV" "$KEY_DIR/env"
    echo "Copied API key to $KEY_DIR/env (root-owned, 600)"
fi

cat > "$UNIT_DIR/claude-guard.service" <<UNIT
[Unit]
Description=Claude Guard security scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_DIR/scan.sh
Environment=CLAUDE_GUARD_ENV_FILE=$KEY_DIR/env
# The scan only reads system state; it never applies a fix on its own.
ProtectHome=read-only
NoNewPrivileges=no
UNIT

cat > "$UNIT_DIR/claude-guard.timer" <<'UNIT'
[Unit]
Description=Run Claude Guard daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
# Catch up after the laptop has been off or asleep.
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# So the installing user -- and nobody else -- can read their own reports.
OWNER_GROUP="$(id -gn "${SUDO_USER:-root}")"
install -d -m 0750 -o root -g "$OWNER_GROUP" /var/lib/claude-guard
chmod 0640 /var/lib/claude-guard/*.json 2>/dev/null || true
chgrp "$OWNER_GROUP" /var/lib/claude-guard/*.json 2>/dev/null || true
echo "Reports in /var/lib/claude-guard are readable by root and group $OWNER_GROUP only."

systemctl daemon-reload
systemctl enable --now claude-guard.timer
echo
echo "Installed. Next run:"
systemctl list-timers claude-guard.timer --no-pager | sed -n '1,2p'
echo
echo "  Run one now:      sudo systemctl start claude-guard.service"
echo "  See the output:   journalctl -u claude-guard.service -n 30 --no-pager"
echo "  Latest report:    sudo cat /var/lib/claude-guard/latest.json"
