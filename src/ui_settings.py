# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""SettingsWindow: language, default algorithm, clipboard behaviour, compare algorithms, About."""

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

import core
from i18n import _
from ui_common import BaseWindow, SpeedDialog, combo_row, warning_dialog

class SettingsWindow(BaseWindow):
    """Every change is saved at once (no OK button), like GNOME settings."""

    HAS_MENU = False

    def __init__(self, app):
        super().__init__(app, _("Settings"), size=(720, 720))
        cfg = core.load_config()
        general, menu, updates = Adw.PreferencesPage(), Adw.PreferencesPage(), Adw.PreferencesPage()
        general.add(self._general_group(cfg))
        general.add(self._info_group())
        menu.add(self._context_group(cfg))
        if core.update_check_offered():
            updates.add(self._update_row())
        stack = Adw.ViewStack()
        for page, title, icon in ((general, _("General"), "preferences-system-symbolic"),
                                  (menu, _("Context menu"), "view-list-symbolic"),
                                  (updates, _("Updates"), "software-update-available-symbolic")):
            if page is updates and not core.update_check_offered():  # a Flatpak updates through its store
                continue
            stack.add_titled_with_icon(page, title, title, icon)
        self.header.set_title_widget(Adw.ViewSwitcher(stack=stack, policy=Adw.ViewSwitcherPolicy.WIDE))
        self.show_page("settings", stack)

    def _general_group(self, cfg):
        prefs = Adw.PreferencesGroup()  # the tab is called "General"
        for key, (title, options, subtitle) in core.setting_choices().items():
            prefs.add(combo_row(title, options, cfg[key], lambda value, key=key: self.apply(key, value), subtitle))
        clipboard = Adw.SwitchRow(title=_("Compare with clipboard automatically"),
                                  subtitle=_("Fill in a copied hash when comparing"), active=cfg["clipboard"])
        clipboard.connect("notify::active", lambda r, _p: self.apply("clipboard", r.get_active()))
        prefs.add(clipboard)
        unlisted = Adw.SwitchRow(title=_("Look for files not in the list"),
                                 subtitle=_("When verifying, count the files in the list's folders that it does not name. A hint only: the result stays the same."),
                                 active=cfg["unlisted"])
        unlisted.connect("notify::active", lambda r, _p: self.apply("unlisted", r.get_active()))
        prefs.add(unlisted)
        prefs.add(self._algo_expander())
        prefs.add(self._speed_row())
        return prefs

    def _speed_row(self):
        """A button that measures every algorithm on this computer and shows the result in a window of its own."""
        self.speed_button = Gtk.Button(label=_("Test"), valign=Gtk.Align.CENTER)
        self.speed_button.connect("clicked", self.test_speeds)
        row = Adw.ActionRow(title=_("Algorithm speed"), subtitle=_("Measures how fast this computer calculates each algorithm and recommends one."))
        row.add_suffix(self.speed_button)
        row.set_activatable_widget(self.speed_button)
        return row

    def test_speeds(self, button):
        button.set_sensitive(False)
        button.set_label(_("Testing…"))
        threading.Thread(target=lambda: GLib.idle_add(self.show_speeds, core.hash_speeds()), daemon=True).start()

    def show_speeds(self, speeds):
        self.speed_button.set_label(_("Test"))
        self.speed_button.set_sensitive(True)
        SpeedDialog(speeds).present(self)

    def _algo_expander(self):
        """Which algorithms the compare window calculates. One folded row stays small however many algorithms
        there will be; its subtitle shows the current choice. Fewer algorithms are much faster on large files."""
        self.algo_expander = Adw.ExpanderRow(title=_("Algorithms when comparing"),
                                             tooltip_text=_("Fewer algorithms are faster for large files."))
        self.algo_rows, chosen = {}, core.compare_algos()
        for algo, label in core.ALGOS.items():
            row = Adw.SwitchRow(title=label, active=algo in chosen)
            row.connect("notify::active", self._algo_toggled, algo)
            self.algo_rows[algo] = row
            self.algo_expander.add_row(row)
        self._show_chosen_algos()
        return self.algo_expander

    def _context_group(self, cfg):
        """Two ways to get the right-click entries, exactly one on: the Scripts folder (with its menu style) or a separate entry
        of its own (with its name). Each switch greys the settings of the other way."""
        available = core.extension_available()
        own = cfg["extension"] and available
        self.scripts_row = Adw.SwitchRow(title=_("Context menu in the Scripts folder"), active=not own)
        self.entries_row = combo_row(_("Entries"), {"scripts": _("Under Scripts"), "folder": _("In a submenu")}, cfg["menu"],
                                     lambda value: self.apply("menu", value),
                                     _("In the submenu “HashTally” they take one more click."))
        self.entries_row.set_sensitive(not own)
        self.extension_row = Adw.SwitchRow(title=_("Separate entry in the context menu"), active=own, sensitive=available,
                                           subtitle=_("Only the entries that fit what you selected.") if available
                                           else _("Needs the package python3-nautilus: sudo apt install python3-nautilus"))
        self.name_row = Adw.EntryRow(title=_("Name of the entry"), text=cfg["menu_name"] or core.MENU_DIR, show_apply_button=True, sensitive=own)
        self.name_row.connect("apply", lambda row: self.apply("menu_name", "" if row.get_text().strip() in ("", core.MENU_DIR) else row.get_text()))
        self.scripts_row.connect("notify::active", lambda row, _p: self._way_toggled(row, self.extension_row, False))
        self.extension_row.connect("notify::active", lambda row, _p: self._way_toggled(row, self.scripts_row, True))
        context = Adw.PreferencesGroup()
        for row in (self.scripts_row, self.entries_row, self.extension_row, self.name_row):
            context.add(row)
        return context

    def _way_toggled(self, row, other, own):
        """`row` was switched; `own`: it is the separate entry. Exactly one way is on: switching one on switches the other off,
        and switching the one that is on off switches the other on (they act like one toggle).
        shortcut: no way to have no entry at all; upgrade if users ask for it."""
        if getattr(self, "_switching", False) or self.scripts_row.get_active() != self.extension_row.get_active():
            return  # ours, or a late notice of a change we made: exactly one is on, nothing to do
        self._switching = True
        try:
            other.set_active(not row.get_active())
            self.entries_row.set_sensitive(not self.extension_row.get_active())
            self.name_row.set_sensitive(self.extension_row.get_active())
        finally:
            self._switching = False
        self.apply("extension", self.extension_row.get_active())

    def _info_group(self):
        reset = Gtk.Button(label=_("Reset"), valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
        reset.connect("clicked", self.confirm_reset)
        reset_row = Adw.ActionRow(title=_("Reset settings"), subtitle=_("Back to the default values."))
        reset_row.add_suffix(reset)
        about = Adw.ActionRow(title=_("About HashTally"), activatable=True)
        about.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        about.connect("activated", self._about)
        info = Adw.PreferencesGroup(title=_("Other"))
        info.add(reset_row)
        info.add(about)
        return info

    def _update_row(self):
        """A switch for the weekly check at start (off by default) and a button that checks right now."""
        row = Adw.SwitchRow(title=_("Check for updates weekly"),
                            subtitle=_("Asks GitHub once a week for the newest version. Nothing is sent and nothing is installed."),
                            active=core.load_config()["update_check"])
        row.connect("notify::active", lambda r, _p: self.apply("update_check", r.get_active()))
        self.update_button = Gtk.Button(label=_("Check now"), valign=Gtk.Align.CENTER)
        self.update_button.connect("clicked", self.check_update)
        self.update_page = None  # set once a newer release is found: the button then opens its page
        self.update_row = now = Adw.ActionRow(title=_("Installed version: {version}").format(version=core.__version__))
        now.add_suffix(self.update_button)
        now.set_activatable_widget(self.update_button)
        group = Adw.PreferencesGroup()  # the tab is called "Updates"
        group.add(row)
        group.add(now)
        if core.update_found:  # the weekly check at start already found one
            self._show_found(core.update_found)
        return group

    def check_update(self, button):
        if self.update_page:
            Gtk.UriLauncher(uri=self.update_page).launch(self, None, None)
            return
        button.set_sensitive(False)

        def work():
            try:
                found, error = core.newer_release(), None
            except (OSError, ValueError, KeyError) as e:
                found, error = None, e
            GLib.idle_add(self.show_update, found, error)
        threading.Thread(target=work, daemon=True).start()

    def show_update(self, found, error):
        self.update_button.set_sensitive(True)
        if error:
            self.toast(_("Could not check for updates. Are you online?"))
        else:
            if found:
                core.update_found = found
                self._show_found(found)
            else:
                self.update_row.set_title(_("HashTally is up to date."))
                self.update_row.set_subtitle(_("Installed version: {version}").format(version=core.__version__))

    def _show_found(self, found):
        """The row says it, and its button leads to the release notes and the way to update."""
        self.update_page = found[1]
        self.update_row.set_title(_("Update available: {version}").format(version=found[0]))
        self.update_row.set_subtitle(_("Installed version: {version}").format(version=core.__version__))
        self.update_button.set_label(_("Release notes"))

    def _algo_toggled(self, row, pspec, algo):
        chosen = [a for a in core.ALGOS if self.algo_rows[a].get_active()]
        if chosen:
            self.apply("compare_algos", chosen)
            self._show_chosen_algos()
        else:  # at least one algorithm must stay on
            row.set_active(True)

    def _show_chosen_algos(self):
        self.algo_expander.set_subtitle(", ".join(core.ALGOS[a] for a in core.compare_algos()))

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, use_markup=False))  # an error text may hold a path with "&"

    def apply(self, key, value):
        """Saves one setting at once; a new language or menu style renames or moves the right-click entries."""
        before = core.menu_entries()
        error = core.set_option(key, value)
        # idle: a language change replaces this window, which must not happen inside its own drop-down's signal
        GLib.idle_add(self.finish_change, before, error, key == "language", key == "extension")

    def finish_change(self, before, error, reopen, forced=False):
        """Shows the error, or offers a restart to each running file manager that would list other entries than before."""
        window = self.reopen() if reopen else self
        if error:
            window.toast(error)
        elif (forced or core.menu_entries() != before) and (running := core.files_running(core.file_managers())):
            window.offer_restart(running)

    def reopen(self):
        """A new window shows the new language or the defaults."""
        fresh = SettingsWindow(self.get_application())
        fresh.present()
        self.close()
        return fresh

    def confirm_reset(self, *a):
        warning_dialog(self, _("Reset all settings?"), _("Language, algorithm and everything else go back to their defaults."),
                       _("Cancel"), _("Reset"), self.reset_chosen)

    def reset_chosen(self, yes):
        if yes:
            before = core.menu_entries()
            GLib.idle_add(self.finish_change, before, core.reset_config(), True)  # like apply(): not inside the dialog's answer

    def offer_restart(self, programs):
        """The file managers only show changed script entries after a restart."""
        if programs == ["nautilus"]:
            # TRANSLATORS: "Files" is the name of the GNOME file manager (Nautilus), "Dateien" in German; put the name in quotes the way your language does
            text = _("The file manager (“Files”) has to restart to show the new entries. Open windows close, and running file operations may be cancelled.")
        else:
            # TRANSLATORS: {names} is a list of program names, such as "Nautilus, Nemo"
            text = _("A restart of {names} applies the change. Open windows close, and running file operations may be cancelled.").format(
                names=", ".join(fm.title() for fm in programs))
        warning_dialog(self, _("Restart the file manager?"), text, _("Later"), _("Restart"),
                       lambda yes: self.restart_chosen(yes, programs), style=Adw.ResponseAppearance.SUGGESTED)

    def restart_chosen(self, yes, programs):
        if yes:
            core.restart_files(self.get_application(), self.toast, programs)
