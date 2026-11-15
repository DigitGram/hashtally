# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""VerifyWindow: check every file a hash file lists (ring, verdict, problems grouped by kind, GPG signature)."""
import itertools
import os
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Pango

import core
from i18n import N_, _, _n
from ui_common import badge, BaseWindow, column_page, fmt_duration, group, Hero, ICONS, Job, progress_text, Row, short_path, show_in_folder, signature_row, signature_texts, size_text, status_page

# Problem kinds of a checked file that is there, in the order of their groups: (label, icon, colour class); the label
# is translated where it is shown, so a language picked in the settings applies to the next window. A file that is
# not there is no problem as long as others are (see VerifyWindow).
PROBLEMS = {
    "bad": (N_("Mismatch"), "action-unavailable-symbolic", "error"),
    "unknown": (N_("Unknown"), "dialog-warning-symbolic", "error"),
    "error": (N_("Error"), "dialog-warning-symbolic", "error"),
}


# The kinds the overview lists, and the statuses each one holds.
KINDS = {"ok": ("ok",), "missing": ("missing",), "bad": tuple(PROBLEMS)}
ALL = "all"
TINTS = {"bad": "error", "unknown": "error", "error": "error", "missing": "warning"}  # the colour of a row that is not fine


class KindRow(Adw.ActionRow):
    """One line of the overview: badge, title, how many, and an arrow once there is something to open."""

    def __init__(self, icon, color, **kw):
        super().__init__(use_markup=False, activatable=False, sensitive=False, **kw)  # grey while it holds nothing
        self.color, self.muted = color, False  # muted: grey even with files, as when matching proves nothing
        self.badge = badge(icon, color)
        self.add_prefix(self.badge)
        self.count = Gtk.Label(css_classes=["numeric"])
        self.add_suffix(self.count)
        self.arrow = Gtk.Image(icon_name="go-next-symbolic", visible=False)
        self.add_suffix(self.arrow)

    def show(self, n):
        self.count.set_label(str(n) if n or self.color not in ("error", "warning") else "–")  # a dash says "none" more quietly than a nought
        self.set_sensitive(n > 0)
        self.set_activatable(n > 0)
        self.arrow.set_visible(n > 0)
        self.badge.set_css_classes(["ht-badge", *([self.color] if self.color and n and not self.muted else [])])  # its disc takes its colour: grey while there is none
        if self.color in ("error", "warning"):  # a problem tints its line and its figure
            for widget, css in ((self, f"ht-tint-{self.color}"), (self.count, self.color)):
                (widget.add_css_class if n else widget.remove_css_class)(css)
            (self.remove_css_class if n else self.add_css_class)("ht-empty")  # no card while there is nothing in it


class DetailWindow(Adw.Window):
    """Every file of the list in a table, filtered by kind, filling in while the check runs. A Gtk.ColumnView only draws
    the lines in sight, so tens of thousands of files are no trouble."""

    def __init__(self, parent, kind):
        super().__init__(title=parent.get_title(), default_width=860, default_height=480)  # on its own, not transient: only a window of its own has minimize and maximize
        self.parent_window, self.kind = parent, kind
        self.filter = Gtk.CustomFilter.new(lambda row: self.kind == ALL or row.status in KINDS[self.kind])
        self.shown = Gtk.FilterListModel(model=parent.store, filter=self.filter)
        view = Gtk.ColumnView(model=Gtk.NoSelection(model=self.shown),
                              show_row_separators=True, css_classes=["data-table", "ht-table"])
        for title, bind, width in ((_("Status"), self._status, self._status_width()), (_("File"), self._file, 200), (_("Size"), self._size, 90),
                                   (_("Algorithm"), self._algo, 100), (_("Expected hash"), self._expected, 200), (_("Found hash"), self._found, 200)):
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._setup)
            factory.connect("bind", lambda f, item, bind=bind: self._bound(item, bind))
            view.append_column(Gtk.ColumnViewColumn(title=title, factory=factory, fixed_width=width, expand=title == _("File"), resizable=True))
        self.buttons, self.tab_labels, first = {}, {}, None
        switch = Gtk.Box(css_classes=["linked"])
        for key, dot in ((ALL, None), ("ok", "success"), ("missing", "warning"), ("bad", "error")):
            button = Gtk.ToggleButton(group=first, active=key == kind)
            first = first or button
            content = Gtk.Box(spacing=6)
            if dot:
                content.append(Gtk.Label(label="●", css_classes=[dot]))
            self.tab_labels[key] = Gtk.Label()
            content.append(self.tab_labels[key])
            button.set_child(content)
            button.connect("toggled", lambda b, key=key: b.get_active() and self.show_kind(key))
            self.buttons[key] = button
            switch.append(button)
        header = Adw.HeaderBar(title_widget=switch)
        page = Adw.ToolbarView(content=Gtk.ScrolledWindow(child=view))
        page.add_top_bar(header)
        self.signature, self.summary = Gtk.Box(spacing=8, hexpand=True, margin_end=24), Gtk.Box(spacing=6)
        footer = Gtk.Box(margin_start=12, margin_end=12, margin_top=8, margin_bottom=8)
        footer.append(self.signature)
        footer.append(self.summary)
        page.add_bottom_bar(footer)
        self.set_content(page)
        self.refresh()

    @staticmethod
    def _status_width():
        """As wide as the longest status word in this language, so none is cut off: a dot, the word, the cell's margins."""
        probe = Gtk.Label()
        words = [_("Verified"), _("Missing"), _("Pending"), *(_(PROBLEMS[k][0]) for k in PROBLEMS)]
        widths = []
        for word in words:
            probe.set_label("●  " + word)
            widths.append(probe.measure(Gtk.Orientation.HORIZONTAL, -1)[1])
        return max(widths) + 32

    def show_kind(self, kind):
        self.kind = kind
        self.buttons[kind].set_active(True)
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    def refresh(self):
        """The tabs' counts and the footer: the signature on the left, the sums on the right."""
        win = self.parent_window
        counts, problems = win.counts, sum(win.counts[k] for k in PROBLEMS)
        shown = {ALL: (_("All"), len(win.rows)), "ok": (_("Verified"), counts["ok"]),
                 "missing": (_("Missing"), counts["missing"]), "bad": (_("Mismatch"), problems)}
        for key, (label, n) in shown.items():
            self.tab_labels[key].set_label(f"{label} {n}")
        sig = []
        if win.sig:
            icon, color, title = signature_texts(win.sig)
            title = _("Signature valid") if win.sig.status == "good" else title  # short here: the overview says by whom
            sig = [Gtk.Image(icon_name=icon, css_classes=[color]), Gtk.Label(label=title, tooltip_text=title, ellipsize=Pango.EllipsizeMode.END, css_classes=["dim-label"])]
        parts = [(_n("{n} mismatch", "{n} mismatches", problems).format(n=problems), "error")] if problems else []
        parts.append((_n("{n} file matches", "{n} files match", counts["ok"]).format(n=counts["ok"]) if win._distrusted()
                      else _n("{n} verified", "{n} verified", counts["ok"]).format(n=counts["ok"]), "dim-label"))
        if counts["missing"]:
            parts.append((_n("{n} missing", "{n} missing", counts["missing"]).format(n=counts["missing"]), "dim-label"))
        if win.outcome == "done":
            parts.append((" · ".join((core.human_size(win.total), fmt_duration(win.spent))), "dim-label"))
        dots = [widget for t, c in parts for widget in (Gtk.Label(label="·", css_classes=["dim-label"]), Gtk.Label(label=t, css_classes=[c]))][1:]
        for box, widgets in ((self.signature, sig), (self.summary, dots)):
            while child := box.get_first_child():
                box.remove(child)
            for widget in widgets:
                box.append(widget)

    # -- the cells
    def _setup(self, _factory, item):
        label = Gtk.Label(xalign=0, hexpand=True, margin_start=10, margin_end=10, margin_top=9, margin_bottom=9, ellipsize=Pango.EllipsizeMode.END)
        click = Gtk.GestureClick(button=3)  # a right click: copy, show in folder
        click.connect("pressed", lambda g, n, x, y: self._menu(label, label.row))
        label.add_controller(click)
        cell = Gtk.Box()  # fills the cell, and carries the tint of its row: a style class on GTK's own row widget made the list assert
        cell.append(label)
        item.set_child(cell)

    def _bound(self, item, bind):
        cell, row = item.get_child(), item.get_item()
        label = cell.get_first_child()
        label.row = row
        text, css, tip = bind(row)
        label.set_label(text)
        label.set_css_classes(css)
        label.set_tooltip_text(tip or None)
        for tint in ("error", "warning"):  # tinted in the colour of its problem
            cell.remove_css_class(f"ht-tint-{tint}")
        if kind := TINTS.get(row.status):
            cell.add_css_class(f"ht-tint-{kind}")

    def _status(self, row):
        if row.status == "waiting":
            return ("●  " + _("Pending") if self.parent_window.outcome is None else "–"), ["dim-label"], None
        label, _icon, color = PROBLEMS.get(row.status, (None, None, None))
        if row.status == "ok":
            label, color = N_("Verified"), "success"
        elif row.status == "missing":
            label, color = N_("Missing"), "warning"
        return f"●  {_(label)}", [color], None

    def _file(self, row):
        name = core.shown(row.name)
        return name, ["dim-label" if row.status == "ok" else "heading"], name  # the files that are fine stay in the background

    def _size(self, row):
        return size_text(row) or "–", ["numeric", *([] if row.status in PROBLEMS else ["dim-label"])], None

    def _algo(self, row):
        """The hash file names it per line (or its length does), so a list from several hash files can mix them."""
        return (core.algo_name(row.entry.algo) if row.entry.algo else "–"), ["dim-label"], None

    @staticmethod
    def _short(digest):
        return f"{digest[:10]}…{digest[-10:]}" if len(digest) > 24 else digest  # the ends are what the eye compares

    def _expected(self, row):
        return self._short(row.entry.digest), ["ht-hash", *(["dim-label"] if row.status == "ok" else [])], row.entry.digest

    def _found(self, row):
        if row.status in ("ok", "bad"):
            return self._short(row.found), ["ht-hash", "error" if row.status == "bad" else "dim-label"], row.found
        if row.status == "error":
            text = core.shown(row.found)  # the OS message
            return text, ["dim-label"], text
        return "–", ["dim-label"], None

    def _menu(self, widget, row):
        """Copy a hash, or look at the file in its folder."""
        window, box = self.parent_window, Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        popover = Gtk.Popover(child=box, has_arrow=False)
        popover.set_parent(widget)
        popover.connect("closed", lambda p: GLib.idle_add(p.unparent))
        offers = [(_("Copy expected hash"), lambda: window._copy(row.entry.digest))]
        if row.status in ("ok", "bad"):
            offers.append((_("Copy found hash"), lambda: window._copy(row.found)))
        if path := core.resolve(window.base, row.name):
            offers.append((_("Show in folder"), lambda: show_in_folder(window, path)))
        for label, act in offers:
            button = Gtk.Button(label=label, css_classes=["flat"])
            button.connect("clicked", lambda b, act=act: (popover.popdown(), act()))
            box.append(button)
        popover.popup()


class VerifyWindow(BaseWindow):
    """An overview of fixed size: the Hero sums up, three lines count the files that are verified, missing from the
    folder, or differ, and the signature tells whether the list itself can be trusted. A line with files opens them in
    a DetailWindow. Hashing runs in a Job and counts while it runs; gpg runs alongside.

    Files the list names but the folder lacks are a problem only when none is found: a SHA256SUMS of a distribution
    lists every image, and one downloads one of them."""

    WIDTH = 520
    RESERVE = 60  # room for the results that need more than the page at the start: a bad signature's long note, a longer language

    def __init__(self, app, hashfile):
        name = os.path.basename(hashfile)
        super().__init__(app, name, size=(self.WIDTH, 200))
        self.base = os.path.dirname(hashfile)
        self.detail = None  # before the pages that end here: _on_close asks for it
        try:
            self.raw = core.read_hashfile(hashfile)  # read once: the list and gpg see the same bytes, even if the file changes
            entries = core.parse(hashfile, self.raw)
        except OSError as exc:
            self.show_page("error", status_page("dialog-error-symbolic", _("Cannot read file"), str(exc)))
            return
        if not entries:
            self.show_page("error", status_page("dialog-warning-symbolic", _("No checksums found"), name))
            return

        self.rows = [Row(e.name, core.file_size(p) if (p := core.resolve(self.base, e.name)) else None, e) for e in entries]
        self.counts = dict.fromkeys(("ok", "missing", *PROBLEMS), 0)
        self.store = Gio.ListStore(item_type=Row)  # every file, for the DetailWindow
        self.store.splice(0, 0, self.rows)
        self.connect("destroy", lambda w: self.detail and self.detail.destroy())  # the table goes with its window
        self.index = self.checked = self.listed = 0  # the job's row and how many it checked (set by its thread); how many the page lists
        self.at = None  # the place in the queue that the page shows as being checked
        self._plan(list(range(len(self.rows))))
        self.sig = self.sig_row = self.outcome = self.ended = None  # gpg's verdict, its row, how the job ended and, once listed, the check: "done", "cancelled" or the exception
        self.signature_args = core.signature_args(hashfile, self.raw)
        self.started = time.monotonic()
        self._build_page()
        self.cancel_btn = Gtk.Button(label=_("Cancel"))
        self.cancel_btn.connect("clicked", self.cancel)
        self.header.pack_start(self.cancel_btn)
        self._fit_height(start=True)
        self.job = Job(self.total, self._work, self._progressed, self._ended)
        GLib.timeout_add(30, self._pump)
        if self.signature_args:  # gpg runs alongside the hashing
            self._check_signature()

    def _build_page(self):
        """Hero, the signature (with the verdict), the file being checked, the three lines."""
        self.hero = Hero()
        self.signature_group = group()
        self.signature_group.set_visible(bool(self.signature_args))
        self.sig_row = Adw.ActionRow(title=_("Checking signature …"), subtitle="\u00a0", use_markup=False)  # two lines, like the row that replaces it
        self.sig_row.add_prefix(Gtk.Spinner(spinning=True, width_request=34))
        self.signature_group.add(self.sig_row)
        self.current = Adw.ActionRow(use_markup=False, title_lines=1)  # one line: a long name must not change the page
        self.current.add_prefix(Gtk.Spinner(spinning=True, width_request=34))
        self.file_bar = Gtk.ProgressBar(valign=Gtk.Align.CENTER, width_request=120)
        self.current.add_suffix(self.file_bar)
        self.all_row = KindRow("view-list-symbolic", None, visible=False)  # takes the place of the file being checked, so nothing moves when that is done
        self.all_row.set_title(_("All files"))
        self.all_row.connect("activated", lambda r: self._open(ALL))
        self.current_group = group(self.current, self.all_row)
        self.kind_rows = {"ok": KindRow("object-select-symbolic", "success"), "missing": KindRow("dialog-warning-symbolic", "warning"),
                          "bad": KindRow(PROBLEMS["bad"][1], "error")}
        self.kind_rows["missing"].set_title(_("Missing"))
        self.kind_rows["bad"].set_title(_("Mismatch"))
        for kind, row in self.kind_rows.items():
            row.connect("activated", lambda r, kind=kind: self._open(kind))
        self.files_group = group(*self.kind_rows.values())
        self.retry_btn = Gtk.Button(label=_("Retry failed"), halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER, vexpand=True,
                                    css_classes=["pill"], sensitive=False)  # always there, so no room stands empty: grey until something failed; in the middle of any room that is left
        self.retry_btn.connect("clicked", lambda b: self._retry())
        self.page, scrolled = column_page(self.hero, self.signature_group, self.current_group, self.files_group, self.retry_btn)
        scrolled.set_propagate_natural_height(True)  # so _fit_height can ask the page how tall it is
        self.page.set_vexpand(True)
        self.page.get_parent().set_vexpand(True)  # the clamp: the page fills a window that is taller than it needs
        self.show_page("result", scrolled)
        self._progressed(0)
        self._show_counts()

    def _fit_height(self, start=False):
        """As tall as the page: at the start, with a reserve; at the end of the check only taller,
        for a result that needs more room (a bad signature has a long note). A window keeps its place on screen while
        it keeps its size, so it is never made smaller, and nothing is ever cut off."""
        if self.is_maximized():
            return
        monitor = self.get_surface() and self.get_display().get_monitor_at_surface(self.get_surface())
        limit = int(monitor.get_geometry().height * 0.85) if monitor else 900
        height = self.get_content().measure(Gtk.Orientation.VERTICAL, self.get_default_size()[0])[1] + (self.RESERVE if start else 0)
        self.set_default_size(self.get_default_size()[0], min(max(height, self.get_default_size()[1]), limit))

    def _on_close(self, *args):
        if self.detail:
            self.detail.destroy()  # the table goes with its window
            self.detail = None
        return super()._on_close(*args)

    def _open(self, kind):
        if self.detail:
            self.detail.show_kind(kind)
        else:
            self.detail = DetailWindow(self, kind)
            self.detail.set_application(self.get_application())
            self.detail.connect("close-request", lambda w: setattr(self, "detail", None))  # not "destroy": that waits for the last reference, which this window holds
        self.detail.present()

    # -- checking
    def _plan(self, queue):
        """The files the job checks, by row: all of them, or the failed ones again; with the bytes before each."""
        self.queue = queue
        self.total = sum(self.rows[i].size or 0 for i in queue)
        self.offsets = [0, *itertools.accumulate(self.rows[i].size or 0 for i in queue)]

    def _work(self, job):
        """In the job's thread. It only counts on: the page reads the rows in _pump, on its own clock."""
        for pos, i in enumerate(self.queue):
            self.index = pos
            row = self.rows[i]
            row.status, row.found = core.check(self.base, row.entry, job.progress)
            self.checked = pos + 1
        return True

    FAILED = ("bad", "error", "missing")  # what a second look can change: a file fetched again, or put in the folder

    def _retry(self):
        """Check again the files that failed, and only those; what is fine is not hashed twice."""
        queue = [i for i, row in enumerate(self.rows) if row.status in self.FAILED]
        for i in queue:
            row = self.rows[i]
            self.counts[row.status] -= 1
            row.status, row.found = "waiting", None
            row.size = core.file_size(path) if (path := core.resolve(self.base, row.name)) else None  # it may be another file now
            self.store.items_changed(i, 1, 1)
        self._plan(queue)
        self.index = self.checked = self.listed = 0
        self.at = self.outcome = self.ended = None
        self.started = time.monotonic()
        self.retry_btn.set_sensitive(False)
        self.cancel_btn.set_visible(True)
        self.current.set_visible(True)
        self.all_row.set_visible(False)
        self._show_counts()
        self._progressed(0)
        self.job = Job(self.total, self._work, self._progressed, self._ended)
        GLib.timeout_add(30, self._pump)

    def _pump(self):
        """Brings the page up to the job, 20 ms of work at most per call: entries that need no reading (not in the folder,
        an unknown format) are checked by the thousand in an instant, and an update each would freeze the window."""
        if self.at != self.index:
            self._checking(self.index)
        stop, listed = time.monotonic() + 0.02, self.listed
        while self.listed < self.checked and time.monotonic() < stop:
            self._checked(self.listed)
            self.listed += 1
        if self.listed > listed:
            self._show_counts()
        if self.ended is None or self.listed < self.checked:
            return GLib.SOURCE_CONTINUE
        self._finished()
        return GLib.SOURCE_REMOVE

    def _checking(self, index):
        row, self.at = self.rows[self.queue[index]], index
        self.current.set_title(core.shown(row.name))
        self.current.set_tooltip_text(core.shown(row.name))  # the name may be cut off
        self.current.set_subtitle(" · ".join(filter(None, (core.algo_name(row.entry.algo), size_text(row)))))
        self._progressed(self.offsets[index] / max(self.total, 1))  # the Hero counts on at once, even for files too small to report progress

    def _checked(self, pos):
        i = self.queue[pos]
        self.counts[self.rows[i].status] += 1
        self.store.items_changed(i, 1, 1)  # a DetailWindow shows the new status

    def _progressed(self, frac):
        row = self.rows[self.queue[self.index]]
        if row.size:
            self.file_bar.set_fraction(min(max((frac * self.total - self.offsets[self.index]) / row.size, 0), 1))
        if self.outcome is None:
            self.hero.ring.show([("accent", frac)], f"{frac:.0%}")
            self.hero.set(_("Checking file {i} of {n}").format(i=self.index + 1, n=len(self.queue)),
                          progress_text(frac, self.total, time.monotonic() - self.started))

    def _ended(self, _result, error):
        self.ended, self.spent = error or "done", time.monotonic() - self.started  # the verdict waits until _pump lists every row

    def _finished(self):
        self.cancel_btn.set_visible(False)
        self.current.set_visible(False)
        self.all_row.set_visible(True)
        self.all_row.show(len(self.rows))
        self.outcome = self.ended
        self.retry_btn.set_sensitive(self.outcome == "done" and any(row.status in self.FAILED for row in self.rows))
        self._show_result()

    def _show_counts(self):
        totals = {kind: sum(self.counts[k] for k in KINDS[kind]) for kind in KINDS}
        for kind, n in totals.items():
            self.kind_rows[kind].show(n)
        self.kind_rows["ok"].set_title(_("Matches") if self._distrusted() else _("Verified"))
        if self.detail:
            self.detail.refresh()

    # -- signature
    def _check_signature(self):
        """Run gpg alone, so checking again never re-hashes the files."""
        Job(0, lambda job: core.verify_signature(self.signature_args, self.raw), None, self._signature_done)

    def _signature_done(self, sig, error):
        self.sig = sig or core.Signature("error", detail=str(error))  # error: gpg hung or crashed
        if self.sig_row:  # drop the previous result
            self.signature_group.remove(self.sig_row)
        self.sig_row = signature_row(self.sig, self._copy, self._check_signature)
        self.signature_group.add(self.sig_row)
        self._show_result()

    def _distrusted(self):
        return self.sig is not None and self.sig.status in ("bad", "revoked")  # a revoked key may mean a stolen one

    # -- the verdict
    def _show_result(self):
        """The Hero once the files are checked. It waits for gpg unless a file failed already, so it never sits
        calm before a "do not trust this hash file"; a bad signature then outranks every file result."""
        distrusted = self._distrusted()
        self.kind_rows["ok"].muted = distrusted  # matching a forged list proves nothing: grey, not green
        self.kind_rows["ok"].set_subtitle(_("Without a valid signature this says nothing about whether the files are genuine.") if distrusted else "")
        self._show_counts()
        if self.outcome is None:
            return
        if self.outcome == "done" and self.signature_args and self.sig is None and not self.counts["bad"]:  # the files are done, gpg is not: say what it waits for
            self.hero.ring.show([("accent", 1)], "100%")
            self.hero.set(_("Checking signature …"))
            return
        ok, missing = self.counts["ok"], self.counts["missing"]
        found = ok + sum(self.counts[k] for k in PROBLEMS)  # files that are there and were checked
        problems = found - ok
        total = found + missing
        n = max(total, 1)
        # one rule for every result: green what matches, red what differs, yellow what is not in the folder; as in the lines below
        parts = [("success", ok / n), ("error", problems / n), ("warning", missing / n)]
        figure, icon, emblem = f"{ok}/{total}", None, False
        lines, details = [], []  # the notes on the result; the figures, last
        if distrusted:
            parts, icon, title, lines = [("error", 1)], "emblem-important-symbolic", signature_texts(self.sig)[2], []  # an exclamation mark in a disc, as big as the ring
        elif self.outcome == "cancelled":
            title = _("Cancelled")
        elif self.outcome != "done":
            title, lines = _("Error"), [str(self.outcome)]
        elif not found:  # a wrong folder, or the downloads went elsewhere
            parts, icon, title, lines = [("warning", 1)], ICONS["warning"], _("None of the files were found"), [short_path(self.base)]
        elif not problems:  # the check only when the whole ring is green
            icon = None if missing else ICONS["success"]
            emblem = bool(icon) and bool(self.sig and self.sig.status != "good")  # the files are fine, but nothing vouches for the list: key missing or expired, or gpg failed (a bad signature never gets here)
            title = _n("{n} file matches", "{n} files match", ok).format(n=ok)
        elif problems == self.counts["bad"]:
            title = _n("{n} file differs", "{n} files differ", problems).format(n=problems)
        elif not self.counts["bad"]:
            title = _n("{n} file could not be checked", "{n} files could not be checked", problems).format(n=problems)
        else:
            title = _n("{n} file with problems", "{n} files with problems", problems).format(n=problems)
        if found and self.outcome == "done" and not distrusted:
            details = [" · ".join((core.human_size(sum(r.size or 0 for r in self.rows)), fmt_duration(self.spent)))]  # the counts are in the lines below
        self.hero.ring.show(parts, figure, icon, plain=distrusted, emblem=emblem)
        self.hero.set(title, "\n".join(lines + details))
        self._fit_height()
