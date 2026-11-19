# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""CompareWindow: show all hashes of one file and compare them with a pasted value."""
import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Pango

import core
from i18n import _
from ui_common import BaseWindow, column_page, group, hash_label, Hero, ICONS, Job, plain_row, progress_page, set_class, short_path, status_page

def file_details(path):
    """(type icon, "size · modified · folder") of a file."""
    try:
        info = Gio.File.new_for_path(path).query_info("standard::symbolic-icon,time::modified", Gio.FileQueryInfoFlags.NONE, None)
        icon, modified = info.get_symbolic_icon(), info.get_modification_date_time()
    except GLib.Error:
        icon, modified = Gio.ThemedIcon.new("text-x-generic-symbolic"), None
    details = [core.human_size(os.path.getsize(path))]
    if modified:  # ISO order: "%x" would follow the system locale, not the language chosen in HashTally
        details.append(modified.to_local().format("%Y-%m-%d %H:%M"))
    return icon, " · ".join(details + [short_path(os.path.dirname(path))])


class CompareWindow(BaseWindow):
    """Hashes a file with the algorithms chosen in the settings (all by default) in one pass;
    a pasted hash is matched against the results, and the Hero shows the verdict."""

    def __init__(self, app, paths):
        algos, path = core.compare_algos(), paths[0]  # run() makes sure there is a first one
        # measured: the page is 323 px, the title bar 47 and a hash row 55, plus 11 for each line of its hash beyond two
        # (a hash is four 8-character blocks to a line); shortcut: fixed pixels, off with other fonts: the page then scrolls
        digits = {name: n for n, name in core.DIGEST_LEN.items()}
        rows = sum(55 + 11 * max(0, -(-digits[a] // 32) - 2) for a in algos)
        super().__init__(app, _("Show or compare hash"), os.path.basename(path), (620, 370 + 12 + rows))
        self.path, self.entry, self.algos = path, None, algos
        self.listed = self.filled = None  # what a hash file lists for the file / the value it put into the field
        self.auto = None  # (value, note) of an automatic fill: the note shows under the field while the value stays in it
        self.connect("notify::is-active", lambda *a: self._autofill())
        self.header.get_title_widget().set_subtitle("")  # the file name stands large below; the window title keeps it
        if len(paths) != 1 or not os.path.isfile(path):
            self.show_page("error", status_page("dialog-warning-symbolic", _("Please select one or two files")))
            return
        page, show = progress_page(core.shown(os.path.basename(path)), os.path.getsize(path), self.cancel)
        self.show_page("progress", page)
        self.job = Job(os.path.getsize(path), self._work, show, self._hashed)

    def _work(self, job):
        # BLAKE2b is as long as SHA-512, so a pasted b2sum (Arch publishes one) would read as a SHA-512 that does not match: it is
        # calculated wherever SHA-512 is, without a row of its own
        extra = ["blake2b"] if "sha512" in self.algos else []
        digests = core.hash_file(self.path, [*self.algos, *extra], job.progress)
        self.listed = core.expected_hash(self.path, self.algos)  # here, not on the UI thread: a folder of big files takes seconds
        job.progress(0)  # raises Cancelled if the user gave up meanwhile
        return digests

    def _hashed(self, digests, error):
        if error == "cancelled":
            self.close()
            return
        if error:
            self.show_page("error", status_page("dialog-error-symbolic", _("Error"), str(error)))
            return
        self.digests, self.hash_rows = digests, {}
        self.icon, self.details = self._file_details()
        self.hero = Hero()
        self.entry = Adw.EntryRow(title=_("Paste expected hash"))
        paste = Gtk.Button(icon_name="edit-paste-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                           tooltip_text=_("Paste from clipboard"))
        paste.connect("clicked", lambda b: self.get_clipboard().read_text_async(None, self._pasted, True))
        self.entry.add_suffix(paste)
        self.entry.connect("changed", self._compare)
        self.note = Gtk.Label(label="\u00a0", xalign=0, wrap=True, margin_start=12, css_classes=["caption", "dim-label"])  # always there, so the spacing never jumps
        field = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        field.append(group(self.entry))
        field.append(self.note)
        hashes = group(*(self._hash_row(algo, digests[algo]) for algo in self.algos))
        self.show_page("result", column_page(self.hero, field, hashes)[1])
        self._compare()
        self._autofill()

    def _file_details(self):
        return file_details(self.path)

    def _hash_row(self, algo, digest):
        """One line: algorithm, the hash in blocks (four to a line, the copy button takes it whole), and a check
        mark that appears when the pasted hash matches."""
        mark = Gtk.Image(icon_name="object-select-symbolic", css_classes=["success"], opacity=0)  # keeps its space
        copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                          tooltip_text=_("Copy"))
        copy.connect("clicked", lambda b: self._copy(digest))
        box = Gtk.Box(spacing=10, margin_start=14, margin_end=6, margin_top=8, margin_bottom=8)
        box.append(Gtk.Label(label=core.ALGOS[algo], xalign=0, yalign=0, width_chars=11, css_classes=["dim-label"]))
        box.append(hash_label(digest))
        box.append(Gtk.Box(hexpand=True))
        box.append(mark)
        box.append(copy)
        row = plain_row(box)  # not focusable: a click on the row would draw the focus ring, which only the input field should show
        self.hash_rows[algo] = (row, mark)
        return row

    def _autofill(self):
        """Fill in a copied hash, or else the one a hash file next to the file lists. Wayland only lets a window
        read the clipboard once it has focus, so this also runs on every activation (while the field is still empty)."""
        if not (self.entry and self.is_active()) or self.entry.get_text() not in ("", self.filled):
            return  # a value from the hash file counts as empty: a hash copied since then is the better one
        if core.load_config()["clipboard"]:
            self.get_clipboard().read_text_async(None, self._pasted, False)
        else:
            self._from_hash_file()

    def _pasted(self, clipboard, result, force):
        try:
            text = clipboard.read_text_finish(result)
        except GLib.Error:
            text = None
        if text and (force or (core.looks_like_digest(text) and text.strip() not in (self.copied, core.load_config()["copied"]))):  # not our own result, compared with itself
            self.auto = None if force else (text.strip(), _("Filled in automatically from the <b>clipboard</b>."))
            self.entry.set_text(text.strip())
            if not force:
                self.set_focus(None)  # filled by itself: no focus ring on top of the match outline (an empty field keeps the focus, to paste into)
        elif not force and self.entry.get_text() in ("", self.filled):
            self._from_hash_file()  # nothing copied: what a hash file next to the download says

    def _from_hash_file(self):
        if self.listed:
            self.filled = self.listed[0]
            self.auto = (self.filled, GLib.markup_escape_text(_("Filled in automatically from {file}.")).format(
                file="<b>" + GLib.markup_escape_text(core.shown(self.listed[1])) + "</b>"))
            self.entry.set_text(self.filled)
            self.set_focus(None)  # as above: the focus ring would add to the match outline
            self.entry.set_tooltip_text(self.listed[1])  # where it came from

    def _compare(self, *args):
        if self.entry.get_text() != self.filled:
            self.entry.set_tooltip_text(None)  # no longer the value of the hash file
        auto = self.auto is not None and self.entry.get_text() == self.auto[0]   # typed over or pasted: no longer automatic
        self.note.set_markup(self.auto[1] if auto else "\u00a0")   # a no-break space keeps the line's height
        wanted = core.norm_hash(self.entry.get_text())
        hits = [a for a, d in self.digests.items() if d == wanted]
        for algo, (row, mark) in self.hash_rows.items():
            mark.set_opacity(algo in hits)
            set_class(row, "ht-row-match", algo in hits)
        text, css = self._verdict(wanted, hits)
        name = core.shown(os.path.basename(self.path))
        if text:
            self.hero.ring.show([(css, 1)], icon=ICONS[css], plain=css == "error")  # a mismatch is the cross in a circle, not a cross in a ring: that looks like a close button
            self.hero.set(text, name)
        else:  # nothing to judge yet: the file itself
            self.hero.ring.show([], icon=self.icon)
            self.hero.set(name, self.details)
        outline = {"success": "ht-match", "error": "ht-mismatch"}.get(css)  # a warning or nothing: no outline
        for cls in ("ht-match", "ht-mismatch"):
            set_class(self.entry, cls, cls == outline)

    def _verdict(self, wanted, hits):
        """(text, css) for the pasted hash; no text while there is nothing to judge yet."""
        if not wanted:
            return "", None
        if hits:
            return _("{algo} matches").format(algo=core.ALGOS.get(hits[0]) or core.algo_name(hits[0])), "success"
        if core.is_partial_hash(wanted, self.digests.values()):
            return "", None
        off = core.DIGEST_LEN.get(len(wanted)) if core.looks_like_digest(wanted) else None
        if off and off not in core.ALGOS:  # SHA-224 or SHA-384: never calculated here, so no verdict rather than a false "No match"
            return "", None
        if off in core.ALGOS and off not in self.algos:  # never calculated, so not a "no match"
            return _("This looks like {algo}, which is switched off in the settings").format(algo=core.ALGOS[off]), "warning"
        return _("No match"), "error"


class CompareFilesWindow(BaseWindow):
    """Two files side by side: identical or not, with the SHA-256 of each. Files of different sizes differ without being read."""

    def __init__(self, app, paths):
        super().__init__(app, _("Compare files"), size=(560, 480))
        self.paths = paths
        total = sum(os.path.getsize(p) for p in paths)
        page, show = progress_page(_("Calculating hashes …"), total, self.cancel)
        self.show_page("progress", page)
        self.job = Job(total, lambda job: core.compare_files(*paths, job.progress), show, self._compared)

    def _fit(self):
        """Taller when the hashes are shown, so they are not hidden behind a scrollbar; back to the old height when folded."""
        width = self.get_default_size()[0]
        want = self.get_content().measure(Gtk.Orientation.VERTICAL, width)[1] + 16
        monitor = self.get_surface() and self.get_display().get_monitor_at_surface(self.get_surface())
        limit = int(monitor.get_geometry().height * 0.85) if monitor else 900
        expanded = hasattr(self, "hashes") and self.hashes.get_expanded()
        self.set_default_size(width, max(self.resting, min(want, limit)) if expanded else self.resting)
        return GLib.SOURCE_REMOVE

    def _compared(self, result, error):
        if error == "cancelled":
            self.close()
            return
        if error:
            self.show_page("error", status_page("dialog-error-symbolic", _("Error"), str(error)))
            return
        same, *digests = result
        self.hero = hero = Hero()
        css = "success" if same else "error"
        hero.ring.show([(css, 1)], icon=ICONS[css], plain=not same)  # a mismatch is the cross in a circle, as in the compare window
        if same:
            hero.set(_("Files are identical"), _("{algo} matches").format(algo=core.ALGOS["sha256"]))
        else:
            hero.set(_("Files differ"), "" if digests[0] else _("The files have different sizes"))
        def box(path, *extra):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, margin_start=14, margin_end=14, margin_top=10, margin_bottom=10)
            box.append(Gtk.Label(label=core.shown(os.path.basename(path)), xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                                 css_classes=["heading"]))
            for widget in extra:
                box.append(widget)
            return plain_row(box)

        parts = [hero, group(*(box(p, Gtk.Label(label=core.shown(file_details(p)[1]), xalign=0, wrap=True, css_classes=["caption", "dim-label"]))
                               for p in self.paths))]
        if digests[0]:  # files of different sizes were not read: no hashes
            self.hashes = Adw.ExpanderRow(title=core.ALGOS["sha256"], expanded=not same)  # a mismatch is when one wants to see them
            for path, digest in zip(self.paths, digests):
                self.hashes.add_row(box(path, hash_label(digest)))
            parts.append(group(self.hashes))
            self.hashes.connect("notify::expanded", lambda *a: GLib.timeout_add(300, self._fit))  # after the unfolding has run
        page = column_page(*parts)[1]
        page.set_propagate_natural_height(True)  # so _fit can ask how tall the page wants to be
        self.show_page("result", page)
        self.resting = self.get_default_size()[1]
        GLib.idle_add(self._fit)
        self.set_focus(None)  # the first selectable hash would take the focus and show up as selected
