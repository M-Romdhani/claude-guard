"""Maps a model-proposed fix command onto privileged helper actions.

The model writes a shell command for a human to read. This module decides
whether that command corresponds to something the helper already knows how to
do. It never passes the string on to be executed -- it either recognises the
intent and returns fixed action ids, or it gives up and the UI tells the user to
run the command themselves.

Giving up is the normal, safe outcome. A command we do not recognise is not a
command we should find a way to run; the CLI's typed-confirmation path still
covers those, with a human reading the string first.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

# Kept in step with UNIT_ALLOWLIST in helper/claude-guard-helper. The helper
# re-checks it anyway -- this copy is for showing the user what will happen,
# never the thing that authorises it.
UNIT_ALLOWLIST = {
    "smbd", "nmbd", "samba-ad-dc",
    "gnome-remote-desktop", "vino-server", "xrdp",
    "ssh", "sshd",
    "openvpn", "sssd",
    "ubiquity",
    "cups-browsed", "avahi-daemon",
    "vsftpd", "telnetd", "rpcbind", "nfs-server",
}


@dataclass(frozen=True)
class Step:
    action_id: str
    param: str | None
    summary: str


def _one(tokens: list[str]) -> list[Step] | None:
    """Map a single command (already stripped of sudo) to zero or more steps."""
    if not tokens:
        return None
    cmd, args = tokens[0], tokens[1:]

    if cmd == "ufw":
        # Only enabling. Disabling a firewall is never offered as a "fix".
        if [a for a in args if not a.startswith("-")] == ["enable"]:
            return [Step("ufw-enable", None, "Turn the firewall on")]
        return None

    if cmd in ("apt", "apt-get"):
        verbs = [a for a in args if not a.startswith("-")]
        if verbs == ["update"]:
            return [Step("apt-update", None, "Refresh the package lists")]
        if verbs and verbs[0] in ("upgrade", "full-upgrade", "dist-upgrade"):
            return [Step("apt-upgrade", None, "Install pending package updates")]
        return None

    if cmd == "systemctl":
        verbs = [a for a in args if not a.startswith("-")]
        if not verbs:
            return None
        if verbs[0] == "reboot":
            return [Step("reboot", None, "Restart the machine")]
        if verbs[0] in ("disable", "mask"):
            action = "service-disable" if verbs[0] == "disable" else "service-mask"
            units = verbs[1:]
            # One command may name several units; each becomes its own step, so
            # each is checked and authorised on its own terms.
            if units and all(u in UNIT_ALLOWLIST for u in units):
                verb = "Stop and disable" if action == "service-disable" else "Stop and mask"
                return [Step(action, u, f"{verb} {u}") for u in units]
        return None

    return None


def plan(fix_command: str) -> list[Step] | None:
    """Return the steps for a fix command, or None if it is not fully mappable.

    All-or-nothing on purpose: half-applying a compound command would leave the
    machine in a state neither the user nor the report describes.
    """
    if not fix_command.strip():
        return None

    steps: list[Step] = []
    for part in fix_command.split("&&"):
        try:
            tokens = shlex.split(part.strip())
        except ValueError:
            return None
        if tokens and tokens[0] == "sudo":
            tokens = tokens[1:]
        mapped = _one(tokens)
        if mapped is None:
            return None
        steps.extend(mapped)

    return steps or None
