# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""CreateWindow: pick an algorithm and write a new hash file for the selected files."""
import os
import tempfile

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

import core
from i18n import _, _n
from ui_common import BaseWindow, column_page, FilesDialog, group, Hero, ICONS, Job, progress_page, short_path, show_in_folder, status_page, warning_dialog

class CreateWindow(BaseWindow):
    """Options page (algorithm, file name, folder), then a progress page, then a "done" page."""

    def __init__(self, app, paths):
        super().__init__(app, _("Create hash file"), size=(520, 600))
        self.paths, self.name_edited, self.base_edited = paths, False, False
        self.plan, self.syncing, self.summary = None, False, None  # the update the target file allows; a toggle set by us; what an update did
        try:
            self.files = core.collect_files(paths)
        except OSError as exc:  # e.g. a folder we may not read: better no hash file than an incomplete one
            self.show_page("error", status_page("dialog-error-symbolic", _("Error"), str(exc)))
            return

        hero = Hero()
        hero.ring.show([], icon="document-new-symbolic")
        hero.set(_n("{n} file, {size}", "{n} files, {size}", len(self.files)).format(
            n=len(self.files), size=core.human_size(core.total_size(self.files))))
        listing = Gtk.Button(label=_("Show files"), halign=Gtk.Align.CENTER, css_classes=["flat"])
        listing.connect("clicked", lambda b: FilesDialog(self.files, self.base, _("Selected files")).present(self))
        hero.append(listing)

        algo = core.load_config()["algorithm"]
        choice = Gtk.Box(css_classes=["linked"], homogeneous=True)
        self.algo_buttons = {}
        for key, label in core.ALGOS.items():  # one click instead of a drop-down: only five choices
            button = Gtk.ToggleButton(label=label.split(" ")[0], tooltip_text=label, active=key == algo)  # "CRC32 (SFV)" is too wide for its fifth
            button.set_group(next(iter(self.algo_buttons.values()), None))
            button.connect("toggled", lambda b, key=key: b.get_active() and not self.syncing and self._algo_changed(key))
            choice.append(button)
            self.algo_buttons[key] = button
        if not any(b.get_active() for b in self.algo_buttons.values()):  # a default from an older version that is gone
            algo = "sha256"
            self.algo_buttons[algo].set_active(True)

        self.name = Adw.EntryRow(title=_("Hash file name"))
        self.name.connect("changed", self._name_changed)
        self.location = Adw.ActionRow(title=_("Location"), use_markup=False, subtitle_selectable=True)
        choose = Gtk.Button(icon_name="folder-open-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                            tooltip_text=_("Choose folder"))
        choose.connect("clicked", self._choose_folder)
        self.location.add_suffix(choose)
        self.choice = choice
        # an existing hash file may be added to instead of replaced; shown only when the target is one that can be
        self.update_row = Adw.ComboRow(title=_("File already exists"), model=Gtk.StringList.new([_("Update"), _("Overwrite")]),
                                       tooltip_text=_("Only files that are new or changed since the hash file was written are hashed. "
                                                      "The other entries are kept as they are and are not checked again."))
        self.update_row.connect("notify::selected", lambda *a: self._name_changed())
        self.drop_row = Adw.SwitchRow(title=_("Remove entries of deleted files"))
        self.update_group = group(self.update_row, self.drop_row)
        self.update_group.set_visible(False)
        options = column_page(hero, group(choice, title=_("Algorithm")), group(self.name, self.location), self.update_group)[1]
        options.set_propagate_natural_height(True)  # so _fit_height can ask the page how tall it is
        self.show_page("options", options)

        self.start_btn = Gtk.Button(label=_("Create"), halign=Gtk.Align.CENTER, margin_top=12, margin_bottom=12,
                                    css_classes=["suggested-action", "pill"])
        self.start_btn.connect("clicked", self._start)
        self.toolbar.add_bottom_bar(self.start_btn)
        self._algo_changed(algo)
        self._fit_height()

    def _fit_height(self):
        """As tall as the options page needs in its worst case, with the warning that a file is replaced: the window
        keeps its size, so nothing is cut off then and no room stands empty otherwise. A little over for a long path.
        The rows for adding to an existing hash file are not in that case: they make the window taller when they show (_grow)."""
        monitor = self.get_surface() and self.get_display().get_monitor_at_surface(self.get_surface())
        limit = int(monitor.get_geometry().height * 0.85) if monitor else 900
        shown = self.location.get_subtitle()
        self.location.set_subtitle(short_path(self.base) + "\n" + _("⚠ File exists and will be overwritten"))
        height = self.get_content().measure(Gtk.Orientation.VERTICAL, self.get_default_size()[0])[1] + 16
        self.location.set_subtitle(shown)
        self.set_default_size(self.get_default_size()[0], min(height, limit))

    def _grow(self):
        """Taller, never smaller, for the rows that add to an existing hash file."""
        height = self.get_content().measure(Gtk.Orientation.VERTICAL, self.get_default_size()[0])[1] + 16
        monitor = self.get_surface() and self.get_display().get_monitor_at_surface(self.get_surface())
        limit = int(monitor.get_geometry().height * 0.85) if monitor else 900
        width, current = self.get_default_size()
        self.set_default_size(width, max(current, min(height, limit)))
        return GLib.SOURCE_REMOVE

    def _algo(self):
        return next(key for key, button in self.algo_buttons.items() if button.get_active())

    def _updating(self):
        """True when the target is a hash file that can be added to and that is what the user chose."""
        return self.plan is not None and self.update_row.get_selected() == 0

    def _algo_changed(self, algo):
        base, default = core.default_target(self.paths, algo)
        if not self.base_edited:  # a folder the user picked stays, like the file name below
            self.base = base
        if not self.name_edited:  # keep the user's own file name when switching algorithm
            self.name.set_text(core.shown(default))  # shortcut: a name that is no UTF-8 names the hash file with U+FFFD; its lines keep the real bytes
        self._name_changed()

    def _choose_folder(self, *args):
        Gtk.FileDialog(title=_("Choose folder"), initial_folder=Gio.File.new_for_path(self.base)).select_folder(
            self, None, self._folder_chosen)

    def _folder_chosen(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:  # dismissed
            return
        if path := folder.get_path():  # None for a location without a local path
            self.base, self.base_edited = path, True
            self._name_changed()

    def _name_changed(self, *args):
        name = self.name.get_text().strip()
        self.name_edited = name != core.shown(core.default_target(self.paths, self._algo())[1])
        out = os.path.join(self.base, name)
        exists = os.path.lexists(out)  # a dangling link too: it is replaced
        self.plan = core.plan_update(self.files, self.base, out) if exists and name not in ("", ".", "..") else None
        updating = self._updating()
        self.update_group.set_visible(self.plan is not None)
        self.drop_row.set_visible(updating and self.plan.gone > 0)
        if self.plan:
            self.update_row.set_subtitle(core.update_text(self.plan))
        self.syncing = True  # the file keeps its algorithm: show it, and keep the others from being picked
        if updating:
            self.algo_buttons[self.plan.algo].set_active(True)
        self.choice.set_sensitive(not updating)
        self.syncing = False
        if self.plan:
            GLib.idle_add(self._grow)  # once the rows have their text
        self.start_btn.set_label(_("Update") if updating else _("Create"))
        self.location.set_subtitle(short_path(self.base) + ("\n" + _("⚠ File exists and will be overwritten") if exists and not updating else ""))
        self.start_btn.set_sensitive(bool(self.files) and name not in ("", ".", "..") and "/" not in name)

    def _start(self, *args):
        try:
            tempfile.TemporaryFile(dir=self.base).close()  # a folder that cannot be written says so now, not after every file was read
        except OSError as exc:
            self.toasts.add_toast(Adw.Toast(title=core.shown(str(exc)), use_markup=False))  # the page stays: another folder can be chosen
            return
        out = os.path.join(self.base, self.name.get_text().strip())
        if self._updating():
            return self._update(out)
        if not os.path.lexists(out):
            return self._create(out)
        warning_dialog(self, _("Overwrite file?"),
                       _("“{name}” already exists in this folder and will be replaced.").format(name=core.shown(os.path.basename(out)))
                       + "\n\n" + _("Are you really sure?"), _("Cancel"), _("Overwrite"), lambda yes: yes and self._create(out))

    def _create(self, out):
        algo, self.out = self._algo(), out
        self.toolbar.set_reveal_bottom_bars(False)
        total = core.total_size(self.files)
        page, show = progress_page(_("Calculating hashes …"), total, self.cancel)
        self.show_page("progress", page)
        self.job = Job(total, lambda job: core.write_hashfile(self.files, self.base, algo, self.out, job.progress),
                       show, self._created)

    def _update(self, out):
        plan, drop, self.out = self.plan, self.drop_row.get_visible() and self.drop_row.get_active(), out
        self.summary = core.update_text(plan, drop)
        self.toolbar.set_reveal_bottom_bars(False)
        total = sum(core.file_size(f) or 0 for f, _key in plan.todo)
        page, show = progress_page(_("Calculating hashes …"), total, self.cancel)
        self.show_page("progress", page)
        self.job = Job(total, lambda job: core.write_update(plan, self.base, out, drop, job.progress), show, self._created)

    def _created(self, _count, error):
        if error == "cancelled":
            self.close()
            return
        if error:
            self.show_page("done", status_page("dialog-error-symbolic", _("Error"), str(error)))
            return
        hero = Hero()
        hero.ring.show([("success", 1)], icon=ICONS["success"])
        name = core.shown(os.path.basename(self.out))
        hero.set(_("Hash file updated") if self.summary else _("Hash file created"), name + (f"\n{self.summary}" if self.summary else ""))
        folder = Gtk.Button(label=_("Show in folder"), css_classes=["pill"])
        folder.connect("clicked", lambda b: show_in_folder(self, self.out))
        close = Gtk.Button(label=_("Close"), css_classes=["pill", "suggested-action"])
        close.connect("clicked", lambda *a: self.close())
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        for button in (folder, close):
            buttons.append(button)
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, valign=Gtk.Align.CENTER, margin_start=24, margin_end=24)
        page.append(hero)
        page.append(buttons)
        self.show_page("done", page)
