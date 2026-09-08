"""Remembers what you decided about each finding, across scans.

Without this the app re-lists everything after every scan and you cannot tell
"I fixed this" from "I skipped this" from "I never looked at this". For a
security tool that ambiguity is the worst failure it has: it lets someone
believe they are finished when they are not.

Findings carry no id of their own, and the model rewrites titles between runs,
so a title hash would churn. The key is derived from what the fix *does* -- the
helper action ids it maps to -- which stays the same however the finding is
phrased. Only when nothing maps do we fall back to hashing the command text.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import actions

# How long after applying a fix its reappearance still counts as "applied"
# rather than "came back".
RECENT = timedelta(hours=6)

APPLIED = "applied"
IGNORED = "ignored"

STATE_FILE = (
    Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    / "claude-guard" / "decisions.json"
)


def key_for(finding: dict) -> str:
    cmd = (finding.get("fix_command") or "").strip()
    plan = actions.plan(cmd) if cmd else None
    if plan:
        return "|".join(f"{s.action_id}:{s.param or ''}" for s in plan)
    basis = cmd or finding.get("title", "")
    return "sha:" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def load() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def record(finding: dict, status: str) -> None:
    data = load()
    data[key_for(finding)] = {
        "status": status,
        "title": finding.get("title", ""),
        "when": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(STATE_FILE)


def forget(finding: dict) -> None:
    data = load()
    if data.pop(key_for(finding), None) is not None:
        STATE_FILE.write_text(json.dumps(data, indent=2))


def status_of(finding: dict, data: dict | None = None) -> str | None:
    entry = (data if data is not None else load()).get(key_for(finding))
    return entry["status"] if entry else None


def annotate(findings: list[dict]) -> dict[str, tuple[str, str]]:
    """Map finding key -> badge text for a whole report, in one read.

    A finding recorded as applied that is present again is the interesting case:
    either the fix did not hold or something switched it back on. Saying so is
    more useful than silently listing it as new.
    """
    data = load()
    now = datetime.now(timezone.utc)
    out = {}
    for f in findings:
        entry = data.get(key_for(f))
        if not entry:
            continue
        when = entry.get("when", "")
        if entry["status"] == IGNORED:
            out[key_for(f)] = ("ignored", when)
            continue
        # A fix applied minutes ago that is still reported has usually not
        # failed -- apt holds packages back, a service needs a reboot. Calling
        # that "came back" reads as an accusation and is often wrong. Only a
        # finding that returns much later has actually returned.
        try:
            age = now - datetime.fromisoformat(when)
        except ValueError:
            age = timedelta.max
        out[key_for(f)] = (("applied" if age < RECENT else "came back"), when)
    return out
