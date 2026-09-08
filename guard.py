#!/usr/bin/env python3
"""Claude Guard -- a security advisor for ordinary Linux desktops.

    python3 guard.py                 # scan and explain (never changes anything)
    python3 guard.py --json          # machine-readable output
    python3 guard.py --apply         # additionally offer fixes, one confirmation each
    python3 guard.py --model claude-haiku-4-5   # cheap routine run

Design: deterministic collectors gather facts, Claude interprets them, and a
human approves every change. The model never executes anything itself.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

import brain
from collectors import Observation, collect_all

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
COLOUR = {
    "critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[94m", "info": "\033[90m",
}
BADGE = {"good": "\033[92mGOOD\033[0m", "needs_attention": "\033[93mNEEDS ATTENTION\033[0m",
         "at_risk": "\033[91mAT RISK\033[0m"}

def _invoking_home() -> Path:
    """Home directory of the human who ran us -- correct under sudo.

    Under `sudo`, Path.home() is /root, but the config belongs to the person who
    typed the command. sudo sets SUDO_USER to their name, so honour it. Without
    this, `sudo guard.py` -- the run that can actually read firewall rules --
    looks for the key in the wrong place and fails.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def _env_file() -> Path:
    """Where the API key lives.

    Checked in order: an explicit override, the invoking user's config, then the
    system-wide root-owned file. The last one matters for the systemd timer,
    which runs as root with no SUDO_USER and no home to speak of.
    """
    override = os.environ.get("CLAUDE_GUARD_ENV_FILE")
    if override:
        return Path(override)
    user_file = _invoking_home() / ".config" / "claude-guard" / "env"
    return user_file if user_file.is_file() else Path("/etc/claude-guard/env")


ENV_FILE = _env_file()


def load_env_file(path: Path = ENV_FILE) -> None:
    """Read KEY=VALUE lines from a permission-locked file.

    A real environment variable always wins, so this never overrides a key you
    exported deliberately. Dependency-free on purpose -- one less thing to trust.
    """
    if not path.is_file():
        return

    if path.stat().st_mode & 0o077:
        print(f"{COLOUR['medium']}warning{RESET} {path} is readable by other "
              f"users on this machine. Fix it with: chmod 600 {path}", file=sys.stderr)

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\'\""))

# Commands we refuse to run under --apply no matter what the model proposed.
# The model is instructed not to produce these; this is the belt-and-braces check.
FORBIDDEN = [
    (re.compile(r"\brm\s+(-\w*\s+)*-\w*[rf]", re.I), "deletes files recursively/forcibly"),
    (re.compile(r"\b(mkfs|fdisk|parted)\b", re.I), "formats or repartitions disks"),
    (re.compile(r"\bdd\b.*\bof=/dev/", re.I), "writes directly to a device"),
    (re.compile(r"(curl|wget)[^|;&]*[|]\s*(sudo\s+)?(ba)?sh", re.I), "pipes a download into a shell"),
    (re.compile(r"\bufw\s+disable\b", re.I), "disables the firewall"),
    (re.compile(r"\bchmod\s+(-\w+\s+)*777\b", re.I), "makes files world-writable"),
    (re.compile(r">\s*/etc/(passwd|shadow|sudoers)", re.I), "overwrites a critical auth file"),
    (re.compile(r":\(\)\s*\{.*\};:", re.I), "is a fork bomb"),
]


def veto(command: str) -> str | None:
    for pattern, reason in FORBIDDEN:
        if pattern.search(command):
            return reason
    return None


def print_report(report: brain.Report) -> None:
    print(f"\n{BOLD}Claude Guard{RESET}  ->  {BADGE.get(report.overall, report.overall)}\n")
    print(f"{report.headline}\n")
    for point in report.points:
        print(f"  - {point}")
    print()

    if not report.findings:
        print(f"{DIM}No findings.{RESET}")
        return

    for i, f in enumerate(report.findings, 1):
        tint = COLOUR.get(f.severity, "")
        print(f"{tint}{BOLD}[{f.severity.upper()}]{RESET} {BOLD}{i}. {f.title}{RESET}")
        print(f"   {f.what_it_means}")
        print(f"   {DIM}evidence: {f.evidence}{RESET}")
        if f.fix_command:
            print(f"   {BOLD}fix:{RESET} {f.fix_command}")
            print(f"   {DIM}{f.fix_explanation}{RESET}")
        print()


def offer_fixes(report: brain.Report) -> None:
    """The approval gate. Nothing here runs without the user typing 'yes'."""
    actionable = [f for f in report.findings if f.fix_command.strip()]
    if not actionable:
        print(f"{DIM}Nothing to apply.{RESET}")
        return

    print(f"{BOLD}--- Proposed fixes ({len(actionable)}) ---{RESET}")
    print(f"{DIM}Each one needs an explicit 'yes'. Anything else skips it.{RESET}\n")

    for f in actionable:
        reason = veto(f.fix_command)
        if reason:
            print(f"{COLOUR['high']}REFUSED{RESET} {f.title}")
            print(f"   {DIM}proposed: {f.fix_command}{RESET}")
            print(f"   Blocked because it {reason}. Not offered.\n")
            continue

        print(f"{BOLD}{f.title}{RESET}  [{f.severity}]")
        print(f"   $ {f.fix_command}")
        print(f"   {DIM}{f.fix_explanation}{RESET}")
        try:
            answer = input("   Run it? type 'yes' to confirm: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nStopped.")
            return

        if answer != "yes":
            print(f"   {DIM}skipped{RESET}\n")
            continue

        # Runs in the user's own shell, so sudo prompts them for their password.
        # Claude Guard never holds or supplies credentials.
        result = subprocess.run(f.fix_command, shell=True)
        status = "ok" if result.returncode == 0 else f"exit {result.returncode}"
        print(f"   {DIM}-> {status}{RESET}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Explain what actually matters about this machine's security.")
    parser.add_argument("--model", default=brain.DEFAULT_MODEL,
                        help=f"model id (default: {brain.DEFAULT_MODEL})")
    parser.add_argument("--json", action="store_true", help="print the report as JSON and exit")
    parser.add_argument("--observations", metavar="PATH",
                        help="read collector output from PATH ('-' for stdin) instead of collecting. "
                             "Lets the privileged helper do the collecting while this process, "
                             "running unprivileged, makes the API call and parses the reply")
    parser.add_argument("--apply", action="store_true",
                        help="after reporting, offer each fix with a separate confirmation")
    args = parser.parse_args()

    load_env_file()
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print(f"No API key found.\n\n"
              f"  mkdir -p {ENV_FILE.parent}\n"
              f"  nano {ENV_FILE}      # add:  ANTHROPIC_API_KEY=sk-ant-...\n"
              f"  chmod 600 {ENV_FILE}\n", file=sys.stderr)
        return 1

    if args.observations:
        raw = sys.stdin.read() if args.observations == "-" else Path(args.observations).read_text()
        try:
            observations = [Observation(**o) for o in json.loads(raw)]
        except (ValueError, TypeError) as exc:
            print(f"Could not read observations: {exc}", file=sys.stderr)
            return 1
        print(f"{DIM}Using {len(observations)} pre-collected observations...{RESET}", file=sys.stderr)
    else:
        print(f"{DIM}Collecting system state (read-only)...{RESET}", file=sys.stderr)

        def progress(i, total, name):
            # Parsed by the GUI; harmless noise in a terminal.
            print(f"@@PROGRESS {i}/{total} {name}", file=sys.stderr, flush=True)

        observations = collect_all(on_progress=progress)

    print("@@PHASE analysing", file=sys.stderr, flush=True)
    print(f"{DIM}Asking {args.model} to interpret it...{RESET}", file=sys.stderr)
    try:
        report = brain.analyse(observations, model=args.model)
    except Exception as exc:  # surfaced plainly -- this is a CLI, not a library
        print(f"Scan failed: {brain.explain_failure(exc)}", file=sys.stderr)
        return 1

    if args.json:
        # The observations ride along so a UI can show a finding's evidence as
        # the collector's real output rather than a description of it.
        payload = report.model_dump()
        payload["observations"] = [o.as_dict() for o in observations]
        print(json.dumps(payload, indent=2))
        return 0

    print_report(report)
    if args.apply:
        offer_fixes(report)
    else:
        print(f"{DIM}Read-only run. Re-run with --apply to be offered these fixes one by one.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
