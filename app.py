#!/usr/bin/env python3
"""Claude Guard -- GTK4/libadwaita desktop app.

Runs as your normal user and never as root. It renders the same report the CLI
produces, and applying a fix goes through the polkit helper, so the password
prompt is the desktop's own and this process never sees it.

    python3 app.py
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

import actions  # noqa: E402

HERE = Path(__file__).resolve().parent
PYTHON = HERE / ".venv" / "bin" / "python"
CACHED_REPORT = Path("/var/lib/claude-guard/latest.json")
HELPER = "/usr/libexec/claude-guard-helper"

NEEDS_ACTION = ("critical", "high", "medium")
ACCENT = {"critical": "#c01c28", "high": "#ff7b63", "medium": "#f5c211",
          "low": "#78aeed", "info": "#9a9996"}
OVERALL = {"good": ("Nothing needs your attention", "#33d17a"),
           "needs_attention": ("Needs attention", "#f5c211"),
           "at_risk": ("At risk", "#c01c28")}


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
        self.scan_btn = Gtk.Button(label="Scan now")
        self.scan_btn.connect("clicked", lambda _b: self.run_scan())
        self.full_btn = Gtk.Button(label="Full scan…")
        self.full_btn.set_tooltip_text(
            "Collects with administrator access so firewall rules and unit state "
            "are visible. Only the collectors run as root; the API call does not.")
        self.full_btn.connect("clicked", lambda _b: self.run_scan(privileged=True))

        header = Adw.HeaderBar()
        header.pack_start(self.scan_btn)
        header.pack_start(self.full_btn)
        self.subtitle = Adw.WindowTitle(title="Claude Guard", subtitle="No scan yet")
        header.set_title_widget(self.subtitle)

        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                            margin_top=18, margin_bottom=18,
                            margin_start=18, margin_end=18)
        scroller = Gtk.ScrolledWindow(vexpand=True, child=self.body)

        self.banner = Adw.Banner(
            title="Scans send your system state to the Anthropic API",
            revealed=False)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(self.banner)
        toolbar.set_content(scroller)
        return Adw.NavigationPage(title="Claude Guard", child=toolbar)

    def _detail_page(self, finding: dict) -> Adw.NavigationPage:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20,
                      margin_top=22, margin_bottom=22, margin_start=22, margin_end=22)

        sev = Gtk.Label(label=finding["severity"].upper(), xalign=0)
        sev.add_css_class("caption-heading")
        box.append(sev)

        title = Gtk.Label(label=finding["title"], xalign=0, wrap=True)
        title.add_css_class("title-2")
        box.append(title)

        meaning = Gtk.Label(label=finding["what_it_means"], xalign=0, wrap=True)
        box.append(meaning)

        ev_group = Adw.PreferencesGroup(title="Evidence")
        ev_row = Adw.ActionRow(title=finding["evidence"], title_lines=0)
        ev_row.add_css_class("monospace")
        ev_group.add(ev_row)
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
            cmd_row.add_css_class("monospace")
            fix_group.add(cmd_row)
            box.append(fix_group)

            box.append(Gtk.Label(label=finding.get("fix_explanation", ""),
                                 xalign=0, wrap=True))

            plan = actions.plan(cmd)
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

    # ---------- rendering ----------

    def render(self) -> None:
        while (child := self.body.get_first_child()) is not None:
            self.body.remove(child)

        r = self.report or {}
        findings = r.get("findings", [])
        label, colour = OVERALL.get(r.get("overall", ""), ("Unknown", "#9a9996"))
        self.banner.set_revealed(True)

        act = [f for f in findings if f["severity"] in NEEDS_ACTION]
        info = [f for f in findings if f["severity"] not in NEEDS_ACTION]

        if not act:
            status = Adw.StatusPage(
                icon_name="security-high-symbolic",
                title="Nothing needs your attention",
                description=r.get("summary", ""), vexpand=True)
            self.body.append(status)
        else:
            head = Gtk.Label(label=label.upper(), xalign=0)
            head.add_css_class("caption-heading")
            self.body.append(head)
            summary = Gtk.Label(label=r.get("summary", ""), xalign=0, wrap=True)
            summary.add_css_class("title-4")
            self.body.append(summary)

        for group_title, items in (
            (f"{len(act)} need action", act),
            (f"{len(info)} for information", info),
        ):
            if not items:
                continue
            group = Adw.PreferencesGroup(title=group_title)
            for f in items:
                row = Adw.ActionRow(title=f["title"], subtitle=f["what_it_means"],
                                    activatable=True, subtitle_lines=2)
                row.add_prefix(dot(f["severity"]))
                row.add_suffix(Gtk.Label(label=f["severity"], css_classes=["dim-label"]))
                row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                row.connect("activated", lambda _r, fi=f: self.nav.push(self._detail_page(fi)))
                group.add(row)
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
        dialog.connect("response", lambda _d, resp: resp == "apply" and self.apply(plan))
        dialog.present()

    def apply(self, plan: list) -> None:
        def work():
            failures = []
            for step in plan:
                argv = ["pkexec", HELPER, step.action_id]
                if step.param:
                    argv.append(step.param)
                if subprocess.run(argv, capture_output=True).returncode != 0:
                    failures.append(step.summary)
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
            self.body.append(Adw.StatusPage(
                icon_name="security-medium-symbolic",
                title="No scan yet",
                description="Press Scan now to check this machine.", vexpand=True))

    def run_scan(self, privileged: bool = False) -> None:
        self.scan_btn.set_sensitive(False)
        self.full_btn.set_sensitive(False)
        self.subtitle.set_subtitle(
            "Authenticating…" if privileged else "Reading system state…")

        def work():
            argv = [str(PYTHON), str(HERE / "guard.py"), "--json"]
            observations = None
            if privileged:
                # Root collects; this process still makes the API call and parses
                # the reply, so nothing from the network is parsed with privilege.
                collected = subprocess.run(["pkexec", HELPER, "collect"],
                                           capture_output=True, text=True)
                if collected.returncode != 0:
                    GLib.idle_add(self.scan_done, collected)
                    return
                observations = collected.stdout
                argv += ["--observations", "-"]
            proc = subprocess.run(argv, input=observations, capture_output=True, text=True)
            GLib.idle_add(self.scan_done, proc)

        threading.Thread(target=work, daemon=True).start()

    def scan_done(self, proc) -> bool:
        self.scan_btn.set_sensitive(True)
        self.full_btn.set_sensitive(True)
        if proc.returncode != 0:
            self.subtitle.set_subtitle("Scan failed")
            return False
        self.report = json.loads(proc.stdout)
        self.subtitle.set_subtitle("Scanned just now")
        self.render()
        return False


class GuardApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="org.claudeguard.App")

    def do_activate(self):
        (self.props.active_window or GuardWindow(self)).present()


if __name__ == "__main__":
    raise SystemExit(GuardApp().run(None))
