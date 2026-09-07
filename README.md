# Claude Guard

A security advisor for ordinary Linux desktops. It does not try to be another
scanner -- `ss`, `ufw`, `dpkg` and `lynis` already detect things perfectly well.
It closes the gap those tools leave: **telling a normal person which of it
matters and what single command to run.**

## Install

```bash
git clone https://github.com/M-Romdhani/claude-guard.git
cd claude-guard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...    # or run: ant auth login
```

## Use

```bash
python3 guard.py                      # scan and explain -- changes nothing
python3 guard.py --json               # machine-readable, for cron or a dashboard
python3 guard.py --apply              # offer each fix, one confirmation each
python3 guard.py --model claude-haiku-4-5   # cheap routine run
sudo python3 guard.py                 # fuller data (ufw rules need root)
```

## Design

Three layers, deliberately separated:

| Layer | File | Responsibility |
|---|---|---|
| **Collectors** | `collectors.py` | Fixed, read-only commands. No LLM. No state change. |
| **Brain** | `brain.py` | Claude interprets, ranks, and explains. No tools, no execution. |
| **Gate** | `guard.py` | Every change needs a typed `yes` from a human. |

Detection stays deterministic; the model only ever does interpretation. That is
what makes the output reproducible enough to trust.

## Desktop app

```bash
./install-desktop.sh     # adds it to the applications menu (no sudo)
```

Then search for **Claude Guard** in the activities overview. From a terminal:

```bash
/usr/bin/python3 app.py
```

Spell out `/usr/bin/python3`. GTK/PyGObject is a system package and is not in
`.venv`, and inside an activated venv both `python3` and `#!/usr/bin/env python3`
resolve to the venv's interpreter -- so "use the system python" is not advice a
shell can follow. Launched the wrong way the app now says so instead of raising
`ModuleNotFoundError: No module named 'gi'`. The venv is still used internally
for the scan; that split is deliberate.

GTK4 + libadwaita. Runs as your normal user and never as root. Findings are
grouped into "need action" and "for information" rather than shown as five
severities, and the clean state is a real screen rather than an empty list.

Applying a fix maps the model's command through `actions.py` and calls the
polkit helper, so the password prompt is your desktop's own. A command that does
**not** map to a known helper action offers *Copy command* instead of *Apply*,
and says plainly that Claude Guard will not run it -- the fail-closed path is a
normal explained state, not an error.

While a scan runs the app shows a progress bar and **the actual command being
run**, with "Nothing has been sent yet" until collection finishes -- the same
trick as the privacy notice, done at the moment it is true. Applying a fix shows
one row per privileged action, each ticking over as it completes.

The summary is a headline plus standalone one-line points rather than a
paragraph -- a block of bold prose does not get read.

Decisions persist across scans in `~/.local/state/claude-guard/decisions.json`.
Applying a fix records it; a finding can also be ignored. Findings have no id of
their own and the model rewrites titles between runs, so the key is derived from
what the fix *does* (the helper action ids it maps to), which survives being
reworded. A finding recorded as applied that shows up again is badged **came
back** -- either the fix did not hold or something switched it back on, and both
are worth knowing. Delete that file to start over.

On first run the app shows a consent panel rather than an empty screen: what the
two scan modes differ on, the exact commands that will be read (expandable), and
what cannot happen. That is the only moment where saying what leaves the machine
means anything -- afterwards it already has.

The state of background scanning is shown permanently in the footer, including
the case that matters most: **on but never run yet**. A timer that looks
installed and is protecting nobody is the failure this project exists to avoid,
so it is never left to silence.

Not yet built, from the design: history/drift, the first-run key screen, timer
settings, and in-place confirmation instead of a dialog.

## Scheduled scanning (systemd timer)

Turns Guard from something you remember to run into something that watches.

```bash
sudo ./install-timer.sh
```

**That is the only command you need.** From then on the scan runs daily by
itself and notifies you if something needs attention -- there is nothing to
remember and nothing else to start. Everything below is optional: ways to check
on it, or to remove it.

The timer runs as root so the scan can read firewall rules and unit state -- the
things a plain user run cannot see. It writes `/var/lib/claude-guard/latest.json`,
keeps the last 30 reports so you can watch drift over time, and raises a desktop
notification only when something is at medium severity or above.

The API key is copied to `/etc/claude-guard/env` (root-owned, mode 600) so the
headless run does not depend on any user's home directory.

```bash
sudo systemctl start claude-guard.service          # run one now
journalctl -u claude-guard.service -n 30           # what happened
sudo cat /var/lib/claude-guard/latest.json         # the report
```

```bash
sudo ./install-timer.sh --uninstall   # stop and remove the timer
```

**The timer never applies a fix.** It reports and notifies; you decide.

## Privileged helper (for the desktop app)

The GUI runs as your normal user and never as root. Privileged work goes through
a small helper authorised by polkit, so the authentication prompt is your
desktop's own and no password ever reaches Claude Guard.

```bash
sudo helper/install-helper.sh          # installs the helper + polkit policy
sudo helper/install-helper.sh --uninstall
helper/claude-guard-helper --list      # what it can do
```

**The helper never accepts a command to run.** It takes an *action id* from a
fixed table, plus -- for the parameterised actions -- a unit name checked against
an allowlist. The command string the model wrote is used only to *look up* an
action, then discarded:

```
model says:  sudo systemctl disable --now smbd nmbd
mapped to:   service-disable(smbd), service-disable(nmbd)
executed:    /usr/bin/systemctl disable --now smbd     (fixed argv, no shell)
             /usr/bin/systemctl disable --now nmbd
```

Anything that does not map -- `ufw disable`, `systemctl disable systemd-logind`,
`rm -rf ...`, a piped download -- is not run at all. The UI shows the command and
the user runs it themselves. **Giving up is the normal, safe outcome.**

This is deliberately stronger than the CLI's `FORBIDDEN` deny-list. A deny-list
fails open: whatever nobody anticipated gets through. An allowlist fails closed.
When the string comes from a language model and the target is root, that
difference is the whole design.

### Privileged scanning, without root touching the network

A plain user run cannot read firewall rules, so it reports "could not be read"
every time -- noise that teaches people to ignore findings. The `collect` action
fixes that without handing the whole scan to root:

```
pkexec helper collect     root runs the read-only collectors, prints JSON
        |
        v
guard.py --observations - unprivileged: makes the API call, parses the reply
```

Root reads the machine; it never parses anything that arrived over the network.
That is the whole reason this is a `collect` action rather than a `scan` action.
The helper imports its collector table from a fixed root-owned path and refuses
to run if that file is writable by anyone else -- a caller-supplied path would
let any user choose what runs as root.

In the app this is the **Full scan…** button; `Scan now` stays unprivileged.

Each action re-authenticates (`auth_admin`, not `auth_admin_keep`) -- a cached
root credential inside a tool that runs privileged commands is precisely what
brief local access would wait for.

## Security properties

These are the reasons the code is shaped the way it is:

1. **The model cannot execute anything.** It has no tools. It returns a
   structured report. Commands it proposes are strings that a human reads and
   approves.
2. **Collected output is treated as untrusted data.** Log lines, filenames,
   package descriptions and device names can all contain attacker-chosen text.
   They are passed inside a `<system_data>` delimiter and the system prompt
   forbids following instructions found there -- and asks the model to *report*
   such text as a finding. This is the single most important control here: an
   agent that reads `/var/log` and obeys what it finds is an exploit, not a tool.
3. **No credential ever reaches the model or this program.** `--apply` runs the
   command in your own shell, so `sudo` prompts *you* for your password.
4. **A deny-list backstops the model.** `FORBIDDEN` in `guard.py` refuses to run
   anything that deletes data, pipes a download into a shell, or disables the
   firewall -- regardless of what came back from the API.
5. **No passwordless sudo, ever.** Do not "fix" the root-only collectors by
   adding a NOPASSWD sudoers rule. A security tool with standing root is a
   better target than the threats it looks for.

## Cost

One run is a few thousand input tokens. At Opus 5 rates ($5/$25 per MTok) that
is fractions of a cent; a daily cron job is negligible. If you run it often:

- Use `--model claude-haiku-4-5` ($1/$5) for routine passes and escalate to
  `claude-opus-5` when something is flagged.
- The system prompt is stable, so add `cache_control={"type": "ephemeral"}` in
  `brain.py` once the prompt grows past ~1K tokens.
- Run it event-driven or scheduled. Do not poll in a loop.

## Hardening for a real release

- **Refusal fallbacks.** Production `claude-opus-5` code should opt into
  server-side fallbacks so a policy decline retries on another model instead of
  stopping: `client.beta.messages.create(..., betas=["server-side-fallback-2026-07-01"], fallbacks="default")`.
  This prototype uses `client.messages.parse` and raises on `stop_reason == "refusal"` instead.
- **Let it investigate.** Right now it takes one snapshot. To let it ask its own
  follow-up questions ("that port is odd, what owns it?"), move the loop to the
  **Claude Agent SDK** (`pip install claude-agent-sdk`), which gives you Bash
  plus a real permission/hook system: <https://code.claude.com/docs/en/agent-sdk>.
  Keep the gate: `--apply` semantics become a permission callback.
- **Add collectors, not cleverness.** `lynis`, `debsums -c`, `aureport`,
  `systemd-analyze security` all slot straight into `COLLECTORS`.
- **Privacy.** This sends system state to an API. Say so plainly in your UI, and
  consider redacting hostnames, usernames and MACs before sending.

## Licence

MIT — see [LICENSE](LICENSE).
