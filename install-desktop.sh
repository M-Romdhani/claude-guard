#!/usr/bin/env bash
# Add Claude Guard to your applications menu. No sudo needed -- this is per-user.
#
#   ./install-desktop.sh              # install
#   ./install-desktop.sh --uninstall
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/applications/claude-guard.desktop"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$DEST"
    update-desktop-database "$(dirname "$DEST")" 2>/dev/null || true
    echo "Removed from the applications menu."
    exit 0
fi

mkdir -p "$(dirname "$DEST")"
cat > "$DEST" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Claude Guard
Comment=Explains what actually matters about this machine's security
# Absolute interpreter on purpose: an activated venv has no PyGObject.
Exec=/usr/bin/python3 $SRC_DIR/app.py
Path=$SRC_DIR
Icon=security-high
Terminal=false
Categories=System;Security;Settings;
Keywords=security;firewall;updates;audit;
DESKTOP
chmod 644 "$DEST"
update-desktop-database "$(dirname "$DEST")" 2>/dev/null || true
echo "Added to your applications menu: $DEST"
echo "Search for 'Claude Guard' in the GNOME activities overview."
