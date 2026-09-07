#!/usr/bin/env bash
# Scheduled Claude Guard scan, run by claude-guard.service.
#
# Stores the report under /var/lib/claude-guard and raises a desktop
# notification on every logged-in graphical session if anything needs attention.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/.venv/bin/python"
STATE_DIR="/var/lib/claude-guard"
REPORT="$STATE_DIR/latest.json"

mkdir -p "$STATE_DIR"

if ! "$PYTHON" "$SCRIPT_DIR/guard.py" --json > "$STATE_DIR/.tmp.json" 2>"$STATE_DIR/last-error.log"; then
    echo "scan failed -- see $STATE_DIR/last-error.log" >&2
    exit 1
fi
mv "$STATE_DIR/.tmp.json" "$REPORT"
cp "$REPORT" "$STATE_DIR/report-$(date +%Y%m%d-%H%M%S).json"
# Keep the 30 most recent reports so you can see drift over time.
ls -1t "$STATE_DIR"/report-*.json 2>/dev/null | tail -n +31 | xargs -r rm -f

read -r COUNT OVERALL <<<"$("$PYTHON" - "$REPORT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
bad = [f for f in d.get("findings", []) if f.get("severity") in ("critical", "high", "medium")]
print(len(bad), d.get("overall", "unknown"))
PY
)"

echo "scan complete: overall=$OVERALL, $COUNT item(s) needing attention"
[ "${COUNT:-0}" -eq 0 ] && exit 0

# Notify each logged-in user's graphical session.
while read -r uid _rest; do
    bus="/run/user/$uid/bus"
    [ -S "$bus" ] || continue
    sudo -u "#$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" \
        notify-send -u normal -i security-medium \
        "Claude Guard: $COUNT item(s) need attention" \
        "Run: sudo $PYTHON $SCRIPT_DIR/guard.py" 2>/dev/null || true
done < <(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}')
