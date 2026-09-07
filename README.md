# Claude Guard

A security advisor for ordinary Linux desktops. It does not try to be another
scanner -- `ss`, `ufw`, `dpkg` and `lynis` already detect things perfectly well.
It closes the gap those tools leave: **telling a normal person which of it
matters and what single command to run.**

## Install

```bash
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

## Scheduled scanning (systemd timer)

Turns Guard from something you remember to run into something that watches.

```bash
sudo ./install-timer.sh          # daily scan, desktop notification on findings
sudo ./install-timer.sh --uninstall
```

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

**The timer never applies a fix.** It reports and notifies; you decide.

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
