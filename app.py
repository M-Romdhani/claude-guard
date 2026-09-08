#!/usr/bin/python3
"""Claude Guard -- GTK4/libadwaita desktop app.

Runs as your normal user and never as root. It renders the same report the CLI
produces, and applying a fix goes through the polkit helper, so the password
prompt is the desktop's own and this process never sees it.

    python3 app.py
"""

from __future__ import annotations

import json
import subprocess
import re
import tempfile
import threading
from datetime import datetime
from pathlib import Path

try:
    import gi
except ModuleNotFoundError:  # almost always: launched from an activated venv
    import sys as _sys
    _sys.exit(
        "Claude Guard's window needs PyGObject, which is a system package and is\n"
        "not inside .venv. You are most likely running this from an activated\n"
        "virtualenv, where `python3` means the venv's interpreter.\n\n"
        "Run it with the system interpreter instead:\n"
        "    /usr/bin/python3 app.py\n"
        "or leave the venv first with:  deactivate\n\n"
        "(The venv is still used internally for the scan itself.)"
    )

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

import actions  # noqa: E402
import decisions  # noqa: E402

HERE = Path(__file__).resolve().parent
PYTHON = HERE / ".venv" / "bin" / "python"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
STATE_DIR = Path("/var/lib/claude-guard")
CACHED_REPORT = STATE_DIR / "latest.json"
HELPER = "/usr/libexec/claude-guard-helper"

# Shown live while collecting, so "read-only" is inspectable rather than asserted.
def read_history(limit: int = 30) -> list[dict]:
    """Past reports, newest first.

    Read directly rather than through the helper: install-timer.sh gives the
    state directory to the installing user's group, so this needs no privilege
    and therefore no password prompt just to look at your own history.
    """
    out = []
    try:
        files = sorted(STATE_DIR.glob("report-*.json"), reverse=True)[:limit]
    except OSError:
        return out
    for f in files:
        try:
            report = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        stamp = f.stem.removeprefix("report-")
        try:
            when = datetime.strptime(stamp, "%Y%m%d-%H%M%S").strftime("%a %d %b, %H:%M")
        except ValueError:
            when = stamp
        out.append({"when": when, "report": report})
    return out


def helper_actions() -> dict:
    """What the helper says it would run, read from the helper itself.

    Deliberately not a copy of its table: a second copy would drift, and what is
    shown to the user must be what actually runs.
    """
    try:
        out = subprocess.run([HELPER, "--list"], capture_output=True, text=True, timeout=5)
        return json.loads(out.stdout).get("actions", {})
    except Exception:
        return {}


def resolved_argv(step) -> str:
    spec = helper_actions().get(step.action_id)
    if not spec or not spec.get("argv"):
        return ""
    return " ".join(a.format(unit=step.param) if step.param else a for a in spec["argv"])


try:
    from collectors import COLLECTORS
    COLLECTOR_CMD = {k: " ".join(v[1]) for k, v in COLLECTORS.items()}
except Exception:
    COLLECTOR_CMD = {}

NEEDS_ACTION = ("critical", "high", "medium")

# Severity pill colours, light and dark, from the redesign's libadwaita palette.
# GTK CSS has no prefers-color-scheme, so the provider is swapped when the
# system theme changes instead.
_PILLS = {
    "light": {"critical": ("#a51d2d", "rgba(224,27,36,0.20)"),
              "high":     ("#c64600", "rgba(255,123,99,0.20)"),
              "medium":   ("#895900", "rgba(245,194,17,0.28)"),
              "low":      ("#1a5fb4", "rgba(120,174,237,0.25)"),
              "info":     ("#5e5c64", "rgba(154,153,150,0.25)")},
    "dark":  {"critical": ("#ff938c", "rgba(224,27,36,0.28)"),
              "high":     ("#ff7b63", "rgba(224,27,36,0.22)"),
              "medium":   ("#f8e45c", "rgba(245,194,17,0.20)"),
              "low":      ("#78aeed", "rgba(53,132,228,0.28)"),
              "info":     ("#c0bfbc", "rgba(154,153,150,0.20)")},
}
VERDICT_ICON = {"good": "security-high-symbolic",
                "needs_attention": "dialog-warning-symbolic",
                "at_risk": "dialog-error-symbolic"}


def pill_css(dark: bool) -> str:
    rules = [".cg-pill{font-size:.85em;font-weight:700;padding:2px 9px;"
             "border-radius:9999px;min-width:52px;}"]
    for sev, (fg, bg) in _PILLS["dark" if dark else "light"].items():
        rules.append(f".cg-pill.cg-{sev}{{color:{fg};background:{bg};}}")
    rules.append(".cg-tag{font-size:.8em;font-weight:700;padding:1px 7px;"
                 "border-radius:6px;border:1px solid alpha(currentColor,.4);}")
    # AdwStatusPage draws its icon at 128px, which overflows and gets clipped in
    # a short window. Fixed and smaller so the whole shield always shows.
    rules.append("statuspage > scrolledwindow > viewport > box > .icon"
                 "{-gtk-icon-size:72px;min-width:72px;min-height:72px;"
                 "margin-top:0;margin-bottom:6px;}")
    return "".join(rules)
ACCENT = {"critical": "#c01c28", "high": "#ff7b63", "medium": "#f5c211",
          "low": "#78aeed", "info": "#9a9996"}
OVERALL = {"good": ("Nothing needs your attention", "#33d17a"),
           "needs_attention": ("Needs attention", "#f5c211"),
           "at_risk": ("At risk", "#c01c28")}


def timer_status() -> dict:
    """Whether background scanning is set up, and whether it has ever run.

    "Enabled but never run" is its own state and deserves saying out loud: the
    timer looks installed and is protecting nobody yet. A guard that quietly is
    not one is the failure this whole project exists to avoid.
    """
    def show(unit: str, prop: str) -> str:
        return subprocess.run(["systemctl", "show", unit, "-p", prop, "--value"],
                              capture_output=True, text=True).stdout.strip()

    enabled = subprocess.run(["systemctl", "is-enabled", "claude-guard.timer"],
                             capture_output=True, text=True).stdout.strip()
    if enabled not in ("enabled", "enabled-runtime"):
        return {"installed": False,
                "text": "Daily scanning is not set up — run  sudo ./install-timer.sh"}

    ever = bool(show("claude-guard.service", "ExecMainStartTimestamp"))
    nxt = show("claude-guard.timer", "NextElapseUSecRealtime") or "unknown"
    nxt = " ".join(nxt.split()[:3]) if nxt != "unknown" else nxt
    if not ever:
        return {"installed": True, "ever": False,
                "text": f"Daily scan is on but has never run yet · first run {nxt}"}
    last = " ".join(show("claude-guard.service", "ExecMainStartTimestamp").split()[:3])
    return {"installed": True, "ever": True,
            "text": f"Daily scan is on · last ran {last} · next {nxt}"}


def dot(severity: str) -> Gtk.Widget:
    d = Gtk.DrawingArea(content_width=10, content_height=10, valign=Gtk.Align.CENTER)
    colour = ACCENT.get(severity, "#9a9996")
    r, g, b = (int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5))

    def draw(_area, cr, w, h):
        cr.arc(w / 2, h / 2, 5, 0, 6.2832)
        cr.set_source_rgb(r, g, b)
        cr.fill()

    d.set_draw_func(draw)
    return d


class GuardWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Claude Guard",
                         default_width=900, default_height=720)
        self.report: dict | None = None
        self.nav = Adw.NavigationView()
        self.set_content(self.nav)
        self.nav.push(self._report_page())
        self.load_cached()

    # ---------- pages ----------

    def _report_page(self) -> Adw.NavigationPage:
        for name, cb in (
            ("full-scan", lambda *_: self.run_scan(privileged=True)),
            ("haiku-scan", lambda *_: self.run_scan(model="claude-haiku-4-5")),
            ("what-gets-read", lambda *_: self.nav.push(self._what_is_read_page())),
            ("history", lambda *_: self.nav.push(self._history_page())),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", cb)
            self.add_action(action)

        menu = Gio.Menu()
        menu.append("Full scan…", "win.full-scan")
        menu.append("Quick scan with Haiku", "win.haiku-scan")
        menu.append("What gets read…", "win.what-gets-read")
        menu.append("Scan history", "win.history")

        self.scan_btn = Adw.SplitButton(label="Scan now", menu_model=menu)
        self.scan_btn.connect("clicked", lambda _b: self.run_scan())
        # Kept so the existing enable/disable calls still have something to talk to.
        self.full_btn = self.scan_btn

        header = Adw.HeaderBar()
        header.pack_start(self.scan_btn)
        self.subtitle = Adw.WindowTitle(title="Claude Guard", subtitle="No scan yet")
        header.set_title_widget(self.subtitle)

        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                            margin_top=18, margin_bottom=18,
                            margin_start=18, margin_end=18)
        scroller = Gtk.ScrolledWindow(vexpand=True, child=self.body)

        self.banner = Adw.Banner(
            title="Scans send your system state to the Anthropic API",
            revealed=False)

        # Permanent, not just on the empty screen: "is the timer actually
        # working" is worth knowing every day, and nothing else surfaces it.
        self.timer_icon = Gtk.Image(icon_name="alarm-symbolic")
        self.timer_label = Gtk.Label(xalign=0, wrap=True, hexpand=True)
        self.timer_label.add_css_class("caption")
        self.timer_btn = Gtk.Button(valign=Gtk.Align.CENTER)
        self.timer_btn.add_css_class("flat")
        self.timer_btn.connect("clicked", lambda _b: self._timer_action())
        self.timer_bar = Gtk.Box(spacing=10, margin_top=6, margin_bottom=6,
                                 margin_start=14, margin_end=8)
        self.timer_bar.append(self.timer_icon)
        self.timer_bar.append(self.timer_label)
        self.timer_bar.append(self.timer_btn)
        self.refresh_timer_label()

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(self.banner)
        toolbar.add_bottom_bar(self.timer_bar)
        toolbar.set_content(scroller)
        return Adw.NavigationPage(title="Claude Guard", child=toolbar)

    def refresh_timer_label(self) -> None:
        status = timer_status()
        self.timer_label.set_text(status["text"])
        healthy = status["installed"] and status.get("ever")
        for w in (self.timer_label, self.timer_icon):
            w.remove_css_class("warning")
            w.remove_css_class("dim-label")
            w.add_css_class("dim-label" if healthy else "warning")
        self.timer_icon.set_from_icon_name(
            "alarm-symbolic" if healthy else "dialog-warning-symbolic")
        if healthy:
            self.timer_btn.set_visible(False)
        else:
            self.timer_btn.set_visible(True)
            self.timer_btn.set_label(
                "Run it now" if status["installed"] else "Set it up…")
        self._timer_installed = status["installed"]
        self._timer_cmd = "cd ~/Desktop/claude-guard && sudo ./install-timer.sh"

    def _timer_action(self) -> None:
        """Starting the timer's own unit is an allowlisted helper action.

        Installing it is not, and deliberately so: install-timer.sh lives in a
        user-writable directory, and running a user-writable script as root
        would hand away everything the allowlist protects.
        """
        if self._timer_installed:
            self.show_progress("Running the scheduled scan", "")
            self.set_progress(None, "pkexec claude-guard-helper timer-run-now", "",
                              "Your desktop is asking for your password.",
                              "Running the same scan the timer runs.")

            def work():
                subprocess.run(["pkexec", HELPER, "timer-run-now"], capture_output=True)
                GLib.idle_add(self.after_timer_run)

            threading.Thread(target=work, daemon=True).start()
            return
        self._timer_help()

    def after_timer_run(self) -> bool:
        self.refresh_timer_label()
        self.load_cached()
        return False

    def _timer_help(self) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Run this in a terminal",
            body=f"{self._timer_cmd}\n\nClaude Guard does not run this for you yet — "
                 "starting or installing a system unit is a privileged action, and it "
                 "is not one of the actions the helper is allowed to perform.")
        dialog.add_response("close", "Close")
        dialog.add_response("copy", "Copy command")
        dialog.set_response_appearance("copy", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda _d, r: r == "copy" and
                       self.get_clipboard().set(self._timer_cmd))
        dialog.present()

    def _what_is_read_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                      margin_top=20, margin_bottom=20, margin_start=20, margin_end=20)
        box.append(Gtk.Label(
            label="Every command below is a fixed argv list in collectors.py. "
                  "Nothing here is chosen by the model, and none of it writes.",
            xalign=0, wrap=True))
        group = Adw.PreferencesGroup()
        for name, cmd in COLLECTOR_CMD.items():
            row = Adw.ActionRow(title=cmd, subtitle=f"{name} · read-only")
            row.set_use_markup(False)
            row.add_css_class("monospace")
            group.add(row)
        box.append(group)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(Gtk.ScrolledWindow(vexpand=True, child=box))
        return Adw.NavigationPage(title="What gets read", child=toolbar)

    def _detail_page(self, finding: dict) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20,
                      margin_top=22, margin_bottom=22, margin_start=22, margin_end=22)

        header_row = Gtk.Box(spacing=10)
        sev = Gtk.Label(label=finding["severity"], valign=Gtk.Align.CENTER)
        sev.add_css_class("cg-pill")
        sev.add_css_class(f"cg-{finding['severity']}")
        header_row.append(sev)
        mark = decisions.annotate([finding]).get(decisions.key_for(finding))
        if mark:
            tag = Gtk.Label(label=mark[0], valign=Gtk.Align.CENTER)
            tag.add_css_class("cg-tag")
            tag.add_css_class("warning" if mark[0] == "came back" else "dim-label")
            header_row.append(tag)
            said = (f"You applied this fix on {mark[1][:10]} and it is back"
                    if mark[0] == "came back" else f"You ignored this on {mark[1][:10]}")
            header_row.append(Gtk.Label(label=said, xalign=0, wrap=True,
                                        valign=Gtk.Align.CENTER,
                                        css_classes=["caption", "dim-label"]))
        box.append(header_row)

        title = Gtk.Label(label=finding["title"], xalign=0, wrap=True)
        title.add_css_class("title-2")
        box.append(title)

        meaning = Gtk.Label(label=finding["what_it_means"], xalign=0, wrap=True)
        box.append(meaning)

        # The collector's real output, verbatim, alongside the model's reading of
        # it. Showing only the reading under a heading like "Evidence" puts a
        # trust claim on text the model wrote about its own reasoning.
        observations = {o["name"]: o for o in (self.report or {}).get("observations", [])}
        obs = observations.get(finding.get("evidence_collector", ""))

        ev_group = Adw.PreferencesGroup(title="Evidence")
        if obs:
            ev_group.set_description(f"{obs['name']} · collector output, unmodified")
            lines = obs["output"].splitlines()
            shown = "\n".join(lines[:12])
            if len(lines) > 12:
                shown += f"\n… {len(lines) - 12} more lines"
            raw = Adw.ActionRow(title=f"$ {obs['command']}", subtitle=shown,
                                subtitle_lines=0)
            raw.set_use_markup(False)   # collector output is text, not markup
            raw.add_css_class("monospace")
            ev_group.add(raw)
        reading = Adw.ActionRow(title=finding["evidence"], title_lines=0,
                                subtitle="Claude's reading of that output")
        ev_group.add(reading)
        box.append(ev_group)

        note = Gtk.Label(
            label="Collected by fixed, read-only commands. Claude read this output "
                  "and ranked it; it did not run anything.",
            xalign=0, wrap=True)
        note.add_css_class("dim-label")
        note.add_css_class("caption")
        box.append(note)

        cmd = finding.get("fix_command", "").strip()
        if cmd:
            fix_group = Adw.PreferencesGroup(title="Proposed fix")
            cmd_row = Adw.ActionRow(title=cmd, title_lines=0)
            # A shell command is not markup: `apt update && apt upgrade` contains
            # an unescaped &, which Pango rejects, and the row renders blank.
            cmd_row.set_use_markup(False)
            cmd_row.add_css_class("monospace")
            fix_group.add(cmd_row)
            box.append(fix_group)

            box.append(Gtk.Label(label=finding.get("fix_explanation", ""),
                                 xalign=0, wrap=True))

            plan = actions.plan(cmd)
            if plan:
                steps = Adw.PreferencesGroup(
                    description="What this maps to in the polkit helper")
                for n, step in enumerate(plan, start=1):
                    argv = resolved_argv(step)
                    row = Adw.ActionRow(
                        title=step.summary,
                        subtitle=step.action_id + (f" · {argv}" if argv else ""))
                    row.set_use_markup(False)
                    row.add_css_class("monospace")
                    marker = Gtk.Label(label=str(n), valign=Gtk.Align.CENTER)
                    marker.add_css_class("cg-pill")
                    marker.add_css_class("cg-info")
                    row.add_prefix(marker)
                    row.add_suffix(Gtk.Label(label="helper action",
                                             css_classes=["caption", "dim-label"],
                                             valign=Gtk.Align.CENTER))
                    steps.add(row)
                box.append(steps)

            buttons = Gtk.Box(spacing=10)
            if plan:
                apply_btn = Gtk.Button(label="Apply this fix…")
                apply_btn.add_css_class("suggested-action")
                apply_btn.connect("clicked", lambda _b: self.confirm(finding, plan))
                buttons.append(apply_btn)
                hint = (f"Runs {len(plan)} privileged action"
                        f"{'s' if len(plan) > 1 else ''} via polkit. "
                        "Your desktop asks for your password; Claude Guard never sees it.")
            else:
                hint = ("This command is not one of the actions the helper knows, so "
                        "Claude Guard will not run it. Copy it and run it yourself.")
            copy_btn = Gtk.Button(label="Copy command")
            copy_btn.connect("clicked", lambda _b: self.get_clipboard().set(cmd))
            buttons.append(copy_btn)

            current = decisions.status_of(finding)
            if current == decisions.IGNORED:
                un = Gtk.Button(label="Stop ignoring")
                un.connect("clicked", lambda _b, fi=finding: self.decide(fi, None))
                buttons.append(un)
            else:
                ign = Gtk.Button(label="Ignore this finding")
                ign.connect("clicked", lambda _b, fi=finding: self.decide(fi, decisions.IGNORED))
                buttons.append(ign)
            box.append(buttons)

            h = Gtk.Label(label=hint, xalign=0, wrap=True)
            h.add_css_class("dim-label")
            h.add_css_class("caption")
            box.append(h)

        header = Adw.HeaderBar()
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(Gtk.ScrolledWindow(vexpand=True, child=box))
        return Adw.NavigationPage(title="Finding", child=toolbar)

    def _first_run_panel(self) -> Gtk.Widget:
        """Consent, not a menu.

        This is the one moment where telling someone what leaves their machine
        actually means anything -- afterwards it has already gone. So the first
        screen explains what will be read and what cannot happen, and the button
        that starts a scan is the thing they press having read it.
        """
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20,
                      margin_top=12, margin_bottom=12)

        head = Gtk.Label(label="Before the first scan", xalign=0)
        head.add_css_class("title-2")
        box.append(head)
        intro = Gtk.Label(
            label="Claude Guard runs read-only commands, sends the output to Claude "
                  "to be interpreted, and explains what actually matters. It changes "
                  "nothing on its own.",
            xalign=0, wrap=True)
        box.append(intro)

        modes = Adw.PreferencesGroup(title="Two ways to scan")
        modes.add(Adw.ActionRow(
            title="Scan now",
            subtitle="Reads what your user account can see. No password needed.",
            subtitle_lines=0))
        modes.add(Adw.ActionRow(
            title="Full scan…",
            subtitle="Asks for your password, then also reads firewall rules and "
                     "service state. Without it, findings about your firewall cannot "
                     "be confirmed.",
            subtitle_lines=0))
        box.append(modes)

        reads = Adw.PreferencesGroup(title=f"What gets read ({len(COLLECTOR_CMD)} read-only commands)")
        expander = Adw.ExpanderRow(title="Show the exact commands")
        for name, cmd in COLLECTOR_CMD.items():
            row = Adw.ActionRow(title=cmd, subtitle=name)
            row.add_css_class("monospace")
            expander.add_row(row)
        reads.add(expander)
        box.append(reads)

        trust = Adw.PreferencesGroup(title="Nothing changes without you")
        for line in (
            "The model is given no tools. It returns a report; it cannot run anything.",
            "Every fix is applied only after you confirm it, one at a time.",
            "Your password is never handled by Claude Guard — your desktop asks for it.",
        ):
            row = Adw.ActionRow(title=line, title_lines=0)
            row.add_prefix(Gtk.Image(icon_name="object-select-symbolic"))
            trust.add(row)
        box.append(trust)

        privacy = Gtk.Label(
            label="Your system state is sent to the Anthropic API to be interpreted. "
                  "A scan costs a fraction of a cent.",
            xalign=0, wrap=True)
        privacy.add_css_class("caption")
        privacy.add_css_class("dim-label")
        box.append(privacy)

        buttons = Gtk.Box(spacing=10, halign=Gtk.Align.START)
        primary = Gtk.Button(label="Run the first scan")
        primary.add_css_class("suggested-action")
        primary.add_css_class("pill")
        primary.connect("clicked", lambda _b: self.run_scan())
        buttons.append(primary)
        full = Gtk.Button(label="Full scan…")
        full.add_css_class("pill")
        full.connect("clicked", lambda _b: self.run_scan(privileged=True))
        buttons.append(full)
        box.append(buttons)
        return box

    def _history_page(self) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16,
                      margin_top=20, margin_bottom=20, margin_start=20, margin_end=20)
        entries = read_history()

        if not entries:
            box.append(Adw.StatusPage(
                icon_name="document-open-recent-symbolic",
                title="No past scans",
                description="The daily timer keeps its last 30 reports in "
                            "/var/lib/claude-guard.", vexpand=True))
        else:
            box.append(Gtk.Label(
                label="Kept by the daily timer so you can see how this machine drifts. "
                      "Selecting one shows it in place of the current report.",
                xalign=0, wrap=True, css_classes=["dim-label", "caption"]))
            group = Adw.PreferencesGroup()
            for entry in entries:
                r = entry["report"]
                findings = r.get("findings", [])
                act = [f for f in findings if f["severity"] in NEEDS_ACTION]
                overall = r.get("overall", "")
                row = Adw.ActionRow(
                    title=entry["when"],
                    subtitle=f"{len(act)} needing action · {len(findings)} findings",
                    activatable=True)
                pill = Gtk.Label(label=OVERALL.get(overall, (overall, ""))[0],
                                 valign=Gtk.Align.CENTER)
                pill.add_css_class("cg-pill")
                pill.add_css_class("cg-info" if overall == "good" else
                                   "cg-medium" if overall == "needs_attention" else "cg-high")
                row.add_prefix(pill)
                row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                row.connect("activated", lambda _r, rep=r, w=entry["when"]:
                            self.show_past(rep, w))
                group.add(row)
            box.append(group)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(Gtk.ScrolledWindow(vexpand=True, child=box))
        return Adw.NavigationPage(title="Scan history", child=toolbar)

    def show_past(self, report: dict, when: str) -> None:
        self.report = report
        self.subtitle.set_subtitle(f"Showing the scan from {when}")
        self.render()
        self.nav.pop()

    # ---------- progress ----------

    def show_progress(self, title: str, note: str) -> None:
        """A live view of what is happening right now.

        A security tool that goes quiet while running privileged commands is
        unsettling -- working and hung look identical. Collection has real
        progress, so it is shown; the interpretation step has none, so the bar
        pulses rather than inventing some.
        """
        while (child := self.body.get_first_child()) is not None:
            self.body.remove(child)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20,
                      margin_top=48, margin_start=24, margin_end=24,
                      valign=Gtk.Align.START)
        self.p_title = Gtk.Label(label=title, xalign=0)
        self.p_title.add_css_class("title-3")
        box.append(self.p_title)

        bar_row = Gtk.Box(spacing=14)
        self.p_bar = Gtk.ProgressBar(hexpand=True, valign=Gtk.Align.CENTER)
        bar_row.append(self.p_bar)
        self.p_count = Gtk.Label(label="")
        self.p_count.add_css_class("caption")
        self.p_count.add_css_class("dim-label")
        self.p_count.add_css_class("numeric")
        bar_row.append(self.p_count)
        box.append(bar_row)

        self.p_row = Adw.ActionRow(title="", subtitle="")
        self.p_row.add_css_class("monospace")
        self.p_spinner = Gtk.Spinner(valign=Gtk.Align.CENTER)
        self.p_spinner.start()
        self.p_row.add_suffix(self.p_spinner)
        group = Adw.PreferencesGroup()
        group.add(self.p_row)
        box.append(group)

        self.p_note_head = Gtk.Label(label="Nothing has been sent yet.", xalign=0, wrap=True)
        self.p_note_head.add_css_class("heading")
        box.append(self.p_note_head)
        self.p_note = Gtk.Label(label=note, xalign=0, wrap=True)
        self.p_note.add_css_class("caption")
        self.p_note.add_css_class("dim-label")
        box.append(self.p_note)
        self.body.append(box)

    def set_progress(self, fraction, command: str, counter: str = "",
                     caption: str | None = None, headline: str | None = None) -> bool:
        if not hasattr(self, "p_bar"):
            return False
        if fraction is None:
            self.p_bar.pulse()
        else:
            self.p_bar.set_fraction(fraction)
        self.p_count.set_text(counter)
        self.p_row.set_title(command)
        if caption is not None:
            self.p_note.set_text(caption)
        if headline is not None:
            self.p_note_head.set_text(headline)
        return False

    def set_progress_row(self, command: str, name: str) -> bool:
        if hasattr(self, "p_row"):
            self.p_row.set_title(command)
            self.p_row.set_subtitle(f"{name} · read-only")
        return False

    def show_steps(self, plan: list) -> None:
        """One row per privileged action, updated as each finishes."""
        while (child := self.body.get_first_child()) is not None:
            self.body.remove(child)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                      margin_top=40, margin_start=24, margin_end=24, valign=Gtk.Align.START)
        heading = Gtk.Label(label=f"Applying {len(plan)} action{'s' if len(plan) > 1 else ''}", xalign=0)
        heading.add_css_class("title-3")
        box.append(heading)

        group = Adw.PreferencesGroup()
        self.step_rows = []
        for step in plan:
            row = Adw.ActionRow(title=step.summary, subtitle=step.action_id)
            status = Gtk.Label(label="waiting")
            status.add_css_class("caption")
            status.add_css_class("dim-label")
            spinner = Gtk.Spinner(valign=Gtk.Align.CENTER)
            row.add_prefix(spinner)
            row.add_suffix(status)
            self.step_rows.append((row, spinner, status))
            group.add(row)
        box.append(group)

        note = Gtk.Label(
            label="Your desktop asks for your password once per action -- Claude Guard "
                  "does not cache it, so a two-part fix prompts twice.",
            xalign=0, wrap=True)
        note.add_css_class("caption")
        note.add_css_class("dim-label")
        box.append(note)
        self.body.append(box)

    def mark_step(self, index: int, ok: bool, running_next: bool) -> bool:
        row, spinner, status = self.step_rows[index]
        spinner.stop()
        spinner.set_visible(False)
        icon = Gtk.Image(icon_name="object-select-symbolic" if ok else "dialog-error-symbolic")
        icon.add_css_class("success" if ok else "error")
        row.add_prefix(icon)
        status.set_text("done" if ok else "did not complete")
        if running_next and index + 1 < len(self.step_rows):
            self.step_rows[index + 1][1].start()
            self.step_rows[index + 1][2].set_text("waiting for your password")
        return False

    # ---------- rendering ----------

    def _pill(self, severity: str) -> Gtk.Widget:
        """Severity as a badge in a fixed-width column, so a list can be scanned
        down one edge instead of read row by row."""
        label = Gtk.Label(label=severity, valign=Gtk.Align.CENTER)
        label.add_css_class("cg-pill")
        label.add_css_class(f"cg-{severity}")
        box = Gtk.Box(valign=Gtk.Align.CENTER, width_request=76)
        box.append(label)
        return box

    def _verdict_card(self, overall: str, headline: str, points: list[str]) -> Gtk.Widget:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        card.add_css_class("card")

        head = Gtk.Box(spacing=16, margin_top=18, margin_bottom=18,
                       margin_start=18, margin_end=18)
        icon = Gtk.Image(icon_name=VERDICT_ICON.get(overall, "security-medium-symbolic"),
                         pixel_size=32, valign=Gtk.Align.START)
        head.append(icon)
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5, hexpand=True)
        title = Gtk.Label(label=OVERALL.get(overall, (overall, ""))[0], xalign=0)
        title.add_css_class("title-3")
        text.append(title)
        if headline:
            text.append(Gtk.Label(label=headline, xalign=0, wrap=True))
        head.append(text)
        card.append(head)

        if points:
            card.append(Gtk.Separator())
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9,
                           margin_top=14, margin_bottom=16, margin_start=18, margin_end=18)
            for text_line in points:
                row = Gtk.Box(spacing=10, valign=Gtk.Align.START)
                bullet = Gtk.Label(label="\u2022", valign=Gtk.Align.START)
                bullet.add_css_class("dim-label")
                row.append(bullet)
                lab = Gtk.Label(label=text_line, xalign=0, wrap=True, hexpand=True)
                lab.add_css_class("caption")
                row.append(lab)
                body.append(row)
            card.append(body)
        return card

    def _finding_row(self, f: dict, badge: tuple | None) -> Adw.ActionRow:
        subtitle = GLib.markup_escape_text(f.get("what_it_means", ""))
        # What the fix actually does, without having to open it. Comes straight
        # from the same mapper that decides whether Apply is offered at all.
        cmd = (f.get("fix_command") or "").strip()
        plan = actions.plan(cmd) if cmd else None
        if plan:
            n = len(plan)
            hint = f"{n} privileged action{'s' if n > 1 else ''} · {cmd}"
            subtitle += f"\n<tt><small>{GLib.markup_escape_text(hint)}</small></tt>"

        row = Adw.ActionRow(title=f["title"], subtitle=subtitle,
                            activatable=True, subtitle_lines=3)
        row.add_prefix(self._pill(f["severity"]))
        if badge:
            tag = Gtk.Label(label=badge[0], valign=Gtk.Align.CENTER)
            tag.add_css_class("cg-tag")
            tag.add_css_class("warning" if badge[0] == "came back"
                              else "success" if badge[0] == "applied" else "dim-label")
            row.add_suffix(tag)
        row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
        row.connect("activated", lambda _r, fi=f: self.nav.push(self._detail_page(fi)))
        return row

    def render(self) -> None:
        while (child := self.body.get_first_child()) is not None:
            self.body.remove(child)

        r = self.report or {}
        findings = r.get("findings", [])
        headline = r.get("headline") or r.get("summary", "")
        points = r.get("points") or []
        self.banner.set_revealed(True)

        act = [f for f in findings if f["severity"] in NEEDS_ACTION]
        info = [f for f in findings if f["severity"] not in NEEDS_ACTION]

        if not act:
            # Clean state lists what was verified, not that it passed. "ufw is
            # active and denying incoming" is checkable; "you're protected" is not.
            hero = Adw.StatusPage(icon_name="security-high-symbolic",
                                  title="Nothing needs your attention",
                                  description=headline)
            hero.set_vexpand(False)
            self.body.append(hero)
            if points:
                group = Adw.PreferencesGroup()
                for text_line in points:
                    row = Adw.ActionRow(title=text_line, title_lines=0)
                    tick = Gtk.Image(icon_name="object-select-symbolic")
                    tick.add_css_class("success")
                    row.add_prefix(tick)
                    group.add(row)
                self.body.append(group)
        else:
            self.body.append(self._verdict_card(r.get("overall", ""), headline, points))

        privacy = Gtk.Label(
            label=f"Your system state is read by {len(COLLECTOR_CMD)} fixed commands and "
                  "sent to Claude to be interpreted. Nothing is written, and no fix runs "
                  "until you say so.",
            xalign=0, wrap=True)
        privacy.add_css_class("caption")
        privacy.add_css_class("dim-label")
        self.body.append(privacy)

        badges = decisions.annotate(findings)
        for title, items in (("Need action", act), ("For information", info)):
            if not items:
                continue
            group = Adw.PreferencesGroup(
                title=title,
                description=f"{len(items)} finding{'s' if len(items) > 1 else ''}")
            for f in items:
                group.add(self._finding_row(f, badges.get(decisions.key_for(f))))
            self.body.append(group)

    # ---------- actions ----------

    def confirm(self, finding: dict, plan: list) -> None:
        steps = "\n".join(f"• {s.summary}" for s in plan)
        dialog = Adw.MessageDialog(
            transient_for=self, heading="Apply this fix?",
            body=f"{finding['title']}\n\n{steps}\n\n"
                 "Your desktop will ask for your password. Claude Guard never sees it.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("apply", "Apply")
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda _d, resp: resp == "apply" and self.apply(finding, plan))
        dialog.present()

    def decide(self, finding: dict, status: str | None) -> None:
        if status is None:
            decisions.forget(finding)
        else:
            decisions.record(finding, status)
        self.nav.pop()
        self.render()

    def apply(self, finding: dict, plan: list) -> None:
        self.nav.pop()          # back to the report, where progress is shown
        self.show_steps(plan)
        if self.step_rows:
            self.step_rows[0][1].start()
            self.step_rows[0][2].set_text("waiting for your password")

        def work():
            failures = []
            for i, step in enumerate(plan):
                argv = ["pkexec", HELPER, step.action_id]
                if step.param:
                    argv.append(step.param)
                ok = subprocess.run(argv, capture_output=True).returncode == 0
                if not ok:
                    failures.append(step.summary)
                GLib.idle_add(self.mark_step, i, ok, True)
            if not failures:
                decisions.record(finding, decisions.APPLIED)
            GLib.idle_add(self.after_apply, failures)

        threading.Thread(target=work, daemon=True).start()

    def after_apply(self, failures: list) -> bool:
        self.toast("Applied." if not failures
                   else f"{len(failures)} action(s) did not complete.")
        self.run_scan()
        return False

    def toast(self, message: str) -> None:
        self.subtitle.set_subtitle(message)

    # ---------- data ----------

    def load_cached(self) -> None:
        try:
            self.report = json.loads(CACHED_REPORT.read_text())
            self.subtitle.set_subtitle("Last scan by the daily timer")
            self.render()
        except (OSError, ValueError):
            self.body.append(self._first_run_panel())

    def run_scan(self, privileged: bool = False, model: str | None = None) -> None:
        self.scan_btn.set_sensitive(False)
        self.full_btn.set_sensitive(False)
        self.subtitle.set_subtitle(
            "Authenticating…" if privileged else "Reading system state…")

        self.show_progress(
            "Authenticating…" if privileged else "Reading system state",
            "Nothing has been sent yet.")

        def work():
            argv = [str(PYTHON), str(HERE / "guard.py"), "--json"]
            if model:
                argv += ["--model", model]
            observations = None
            if privileged:
                # Root collects; this process still makes the API call and parses
                # the reply, so nothing from the network is parsed with privilege.
                GLib.idle_add(self.set_progress, None,
                              "pkexec claude-guard-helper collect", "",
                              "Your desktop is asking for your password.",
                              "Nothing has been sent yet.")
                collected = subprocess.run(["pkexec", HELPER, "collect"],
                                           capture_output=True, text=True)
                if collected.returncode != 0:
                    GLib.idle_add(self.scan_done, collected)
                    return
                observations = collected.stdout
                argv += ["--observations", "-"]

            # stdout to a file so a full pipe can never deadlock us while we
            # follow stderr line by line for progress.
            with tempfile.TemporaryFile("w+") as out:
                proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE if observations else None,
                                        text=True)
                if observations:
                    proc.stdin.write(observations)
                    proc.stdin.close()
                notes = []
                for line in proc.stderr:
                    line = ANSI.sub("", line).strip()
                    if line and not line.startswith("@@"):
                        notes.append(line)
                    if line.startswith("@@PROGRESS"):
                        counter, name = line.split(None, 2)[1:]
                        done, total = (int(x) for x in counter.split("/"))
                        GLib.idle_add(self.set_progress, done / total,
                                      COLLECTOR_CMD.get(name, name), f"{done} / {total}",
                                      "The collected output goes to Claude only once "
                                      f"all {total} commands have finished.",
                                      "Nothing has been sent yet.")
                        GLib.idle_add(self.set_progress_row,
                                      COLLECTOR_CMD.get(name, name), name)
                    elif line.startswith("@@PHASE analysing"):
                        GLib.idle_add(self.set_progress, None, "", "",
                                      "Waiting for its reading of the collected output.",
                                      "Sent to Claude.")
                proc.wait()
                out.seek(0)
                stdout = out.read()

            GLib.idle_add(self.scan_done,
                          subprocess.CompletedProcess(argv, proc.returncode, stdout,
                                                      "\n".join(notes)))

        threading.Thread(target=work, daemon=True).start()

    def scan_done(self, proc) -> bool:
        self.scan_btn.set_sensitive(True)
        self.full_btn.set_sensitive(True)
        if proc.returncode != 0:
            self.subtitle.set_subtitle("Scan failed")
            reason = (proc.stderr or "").strip()
            reason = reason.split("Scan failed:", 1)[-1].strip() or \
                "The scan did not finish, and gave no reason."
            while (child := self.body.get_first_child()) is not None:
                self.body.remove(child)
            page = Adw.StatusPage(icon_name="dialog-error-symbolic",
                                  title="Scan failed", description=reason)
            page.set_vexpand(False)
            self.body.append(page)
            retry = Gtk.Button(label="Try again", halign=Gtk.Align.CENTER)
            retry.add_css_class("suggested-action")
            retry.add_css_class("pill")
            retry.connect("clicked", lambda _b: self.run_scan())
            self.body.append(retry)
            return False
        self.report = json.loads(proc.stdout)
        self.subtitle.set_subtitle("Scanned just now")
        self.refresh_timer_label()
        self.render()
        return False


class GuardApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="org.claudeguard.App")
        self._css = Gtk.CssProvider()

    def _apply_css(self, *_args) -> None:
        dark = Adw.StyleManager.get_default().get_dark()
        self._css.load_from_data(pill_css(dark), -1)

    def do_activate(self):
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), self._css,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        manager = Adw.StyleManager.get_default()
        manager.connect("notify::dark", self._apply_css)
        self._apply_css()
        (self.props.active_window or GuardWindow(self)).present()


if __name__ == "__main__":
    raise SystemExit(GuardApp().run(None))
