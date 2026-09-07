#!/usr/bin/env bash
# Install the privileged helper and its polkit policy.
#
#   sudo ./install-helper.sh
#   sudo ./install-helper.sh --uninstall
#
# The helper must be owned by root and writable by nobody else. If a normal user
# can edit it, they can edit what runs as root -- which would make this strictly
# worse than no helper at all. The install verifies that rather than assuming it.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER=/usr/libexec/claude-guard-helper
POLICY=/usr/share/polkit-1/actions/org.claudeguard.helper.policy

[ "$(id -u)" -eq 0 ] || { echo "Run me with sudo."; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$HELPER" "$POLICY"
    echo "Helper and policy removed."
    exit 0
fi

install -d -m 755 -o root -g root /usr/libexec
install -m 755 -o root -g root "$SRC_DIR/claude-guard-helper" "$HELPER"
install -m 644 -o root -g root "$SRC_DIR/org.claudeguard.helper.policy" "$POLICY"

# Verify, don't assume.
perms=$(stat -c '%U:%G:%a' "$HELPER")
[ "$perms" = "root:root:755" ] || { echo "FAILED: $HELPER is $perms, expected root:root:755"; exit 1; }
if [ -w "$HELPER" ] && [ "$(stat -c '%a' "$HELPER" | cut -c3)" -gt 5 ]; then
    echo "FAILED: $HELPER is group/world writable"; exit 1
fi

echo "Installed:"
echo "  $HELPER   ($perms)"
echo "  $POLICY"
echo
echo "The GUI calls it as the normal user like this -- polkit prompts, the app never sees the password:"
echo "  pkexec $HELPER ufw-enable"
echo "  pkexec $HELPER service-disable smbd"
echo
echo "Actions available:"
"$HELPER" --list
