"""Deterministic, read-only system collectors.

Nothing in this module calls an LLM, and nothing here changes system state.
Every command is a fixed argv list in COLLECTORS -- there is no path by which
model output can become a command executed here. That property is the point:
detection stays deterministic, and the LLM only ever interprets what we hand it.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, asdict

MAX_OUTPUT_CHARS = 6000


@dataclass
class Observation:
    name: str
    description: str
    command: str
    output: str
    ok: bool

    def as_dict(self) -> dict:
        return asdict(self)


# name -> (human description, argv)
COLLECTORS: dict[str, tuple[str, list[str]]] = {
    "kernel": ("Running kernel version", ["uname", "-r"]),
    "os_release": ("Distribution and version", ["lsb_release", "-ds"]),
    "listening_ports": (
        "Sockets the machine is listening on. Addresses on 127.0.0.1/::1 are "
        "local-only; 0.0.0.0/[::] are reachable from the network.",
        ["ss", "-tuln"],
    ),
    "firewall_service": ("Whether the ufw systemd unit is loaded", ["systemctl", "is-active", "ufw"]),
    "firewall_rules": ("ufw rule set (needs root; may be denied)", ["ufw", "status", "verbose"]),
    "ssh_service": ("Whether an SSH server is accepting logins", ["systemctl", "is-active", "ssh"]),
    "dpkg_health": ("Half-installed packages (empty output = healthy)", ["dpkg", "-C"]),
    "upgradable": ("Packages with pending updates", ["apt", "list", "--upgradable"]),
    "reboot_required": ("Pending-reboot marker", ["cat", "/var/run/reboot-required"]),
    "auto_updates": ("Unattended-upgrades config", ["cat", "/etc/apt/apt.conf.d/20auto-upgrades"]),
    "sudo_group": ("Accounts holding sudo rights", ["getent", "group", "sudo"]),
    "lan_neighbours": ("Other devices seen on the local network", ["ip", "neigh", "show"]),
    "recent_logins": ("Recent login history", ["last", "-n", "5"]),
    "enabled_services": (
        "Services set to start automatically at next boot. A service listed here "
        "but NOT currently listening may still open a network port after a reboot "
        "-- treat newly enabled network services (file sharing, remote desktop, "
        "databases, remote login) as a change in attack surface.",
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled",
         "--no-pager", "--no-legend"],
    ),
}


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n... [truncated, {len(text)} chars total]"


def run_one(name: str) -> Observation:
    description, argv = COLLECTORS[name]
    command = " ".join(argv)

    if shutil.which(argv[0]) is None and argv[0] != "cat":
        return Observation(name, description, command, f"({argv[0]} not installed)", False)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        output = (proc.stdout + proc.stderr).strip() or "(no output)"
        return Observation(name, description, command, _truncate(output), proc.returncode == 0)
    except subprocess.TimeoutExpired:
        return Observation(name, description, command, "(timed out)", False)
    except OSError as exc:
        return Observation(name, description, command, f"({exc})", False)


def collect_all(on_progress=None) -> list[Observation]:
    """Run every collector, optionally reporting progress as each one finishes.

    on_progress(index, total, name) is called after each command so a caller can
    show which command is running. Collection is the part a user can be shown
    honestly -- the interpretation step afterwards has no measurable progress.
    """
    total = len(COLLECTORS)
    results = []
    for i, name in enumerate(COLLECTORS, start=1):
        results.append(run_one(name))
        if on_progress is not None:
            on_progress(i, total, name)
    return results
