# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""GTK 4 / libadwaita front end: one window class per action.

    VerifyWindow    open a hash file and check every file it lists: a ring and the verdict on top, the problems
                    below grouped by kind, the files that are fine folded away; plus the GPG signature when one
                    is found next to the file
    CreateWindow    pick an algorithm and write a new hash file for the selected files
    CompareWindow   show all hashes of one file and compare them with a pasted value;
                    CompareFilesWindow: two files, identical or not
    SettingsWindow  language, default algorithm, clipboard behaviour, compare algorithms, About

All windows derive from BaseWindow and open with the same Hero: a Ring, a big title and a line of detail.
Long-running work (reading files) runs in a Job thread, because GTK widgets may only be touched from the
main thread: the thread reports back with GLib.idle_add (the verify window reads its rows on a timer instead).
Shared parts are in ui_common.py, one window per ui_*.py module.
The logic itself (parsing, hashing, settings) lives in core.py; this file only shows it.
"""
import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

import core
from core import APP_ID
from i18n import _
from ui_common import BaseWindow, CSS, status_page
from ui_verify import SignedFileWindow, VerifyWindow
from ui_create import CreateWindow
from ui_compare import CompareFilesWindow, CompareWindow
from ui_settings import SettingsWindow


def load_css():
    provider = Gtk.CssProvider()
    provider.load_from_string(CSS)
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                              Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


def _window_for(app, path):
    """A hash file gets the verify window; a detached signature (install.sh.asc) the window of the file it signs, or of its
    hash list if that is one (SHA256SUMS.asc opens SHA256SUMS, which finds the signature itself)."""
    try:
        target = core.signed_file(path)
    except OSError:
        target = None  # the verify window says it cannot read the file
    if target is None:
        return VerifyWindow(app, path)
    if os.path.isfile(target) and core.parse(target):
        return VerifyWindow(app, target)
    return SignedFileWindow(app, path, target)


def verify_windows(app, paths):
    """A window per hash file. Files without checksums share one: a few hundred photos sent here by a slip in the
    Scripts menu must not open a window each."""
    windows = [_window_for(app, path) for path in paths]
    empty = [window for window in windows if window.job is None]  # ended on "No checksums found" or "Cannot read file"
    if len(empty) < 2:
        return windows
    for window in empty:
        window.destroy()
    names = [os.path.basename(path) for path, window in zip(paths, windows) if window in empty]
    shared = BaseWindow(app, _("No checksums found"), size=(420, 420))
    shared.show_page("error", status_page("dialog-warning-symbolic", _("No checksums found"), "\n".join(names[:10] + ["…"] * (len(names) > 10))))
    return [window for window in windows if window not in empty] + [shared]


def pick_second(app, first):
    """One file selected: ask for the one to compare it with (Files cannot select across folders), then compare."""
    def chosen(dialog, result):
        try:
            second = dialog.open_finish(result).get_path()
        except GLib.Error:  # cancelled
            second = None
        if second:
            CompareFilesWindow(app, [first, second]).present()
        app.release()

    app.hold()  # no window yet while the dialog is open
    Gtk.FileDialog(title=_("Choose the second file"), initial_folder=Gio.File.new_for_path(os.path.dirname(first))).open(None, None, chosen)


def run(mode, paths):
    """Open the window(s) for `mode` and enter the GTK main loop."""
    GLib.set_prgname(APP_ID)  # window class = app id, so the shell finds our .desktop file and icon
    GLib.set_application_name("HashTally")
    app = Adw.Application(application_id=APP_ID, flags=Gio.ApplicationFlags.NON_UNIQUE)

    def activate(app):
        Gtk.Window.set_default_icon_name(APP_ID)
        load_css()
        if mode != "settings" and not paths:  # e.g. the Scripts menu of Files' empty background
            window = BaseWindow(app, _("No file selected"), size=(420, 300))
            window.show_page("error", status_page("dialog-warning-symbolic", _("No file selected")))
            windows = [window]
        elif mode == "verify":
            windows = verify_windows(app, paths)
        elif mode == "create":
            windows = [CreateWindow(app, paths)]
        elif mode == "compare":
            windows = [CompareFilesWindow(app, paths) if len(paths) == 2 and all(os.path.isfile(p) for p in paths) else CompareWindow(app, paths)]
        elif mode == "compare-files" and len(paths) == 1 and os.path.isfile(paths[0]):
            pick_second(app, paths[0])
            return
        elif mode == "compare-files":
            if len(paths) == 2 and all(os.path.isfile(p) for p in paths):
                windows = [CompareFilesWindow(app, paths)]
            else:
                windows = [BaseWindow(app, _("Compare files"), size=(480, 420))]  # the text may wrap to two lines
                windows[0].show_page("error", status_page("dialog-warning-symbolic", _("Please select one or two files")))
        else:
            windows = [SettingsWindow(app)]
        for window in windows:
            window.present()

    app.connect("activate", activate)
    app.run([])
