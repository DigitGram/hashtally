# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""GTK smoke test: the verify window must hand gpg and the list the same bytes it read once, whatever the file becomes after;
the windows group, order and word their results as designed.
Run on a desktop, without opening windows on it and without touching its portals or session bus:
  R=$(mktemp -d); chmod 700 $R
  xvfb-run -a env -u WAYLAND_DISPLAY -u DBUS_SESSION_BUS_ADDRESS GDK_BACKEND=x11 XDG_RUNTIME_DIR=$R GDK_DEBUG=no-portals \\
      GTK_USE_PORTAL=0 /usr/bin/python3 tests/smoke_gtk.py
(needs python3-gi, python3-gi-cairo, gir1.2-adw-1; CI runs the same file in a clean runner with `xvfb-run -a dbus-run-session`)"""
import hashlib
import os
import sys
import tempfile
import threading
import traceback
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
scratch = tempfile.TemporaryDirectory()  # the settings are read at import: the test must never touch the real ones
os.environ.update(GSETTINGS_BACKEND="memory", GTK_A11Y="none", XDG_CONFIG_HOME=scratch.name)
import core  # noqa: E402
import ui_common  # noqa: E402
import ui_compare  # noqa: E402
import ui_create  # noqa: E402
import ui_gtk  # noqa: E402
import ui_settings  # noqa: E402
import ui_verify  # noqa: E402
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

A = hashlib.sha256(b"alpha").hexdigest()
SIGNED = f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{A}  a.txt\n-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n".encode()
EVIL = f"{A}  evil.exe\n".encode()


def asked(app, first, later):
    """(what gpg is given, the names in the table) when the file reads as `first` and is `later` on disk right after."""
    calls, windows = [], []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "SUMS")
        path.write_bytes(first)

        def read(p):
            data = Path(p).read_bytes()
            Path(p).write_bytes(later)  # the swap an attacker with write access to the folder makes
            return data

        def verify(args, data=None):
            calls.append(data)
            return core.Signature("good", "AB12", "Real Publisher", "A" * 40)

        with mock.patch.object(core, "read_hashfile", read), mock.patch.object(core, "verify_signature", verify):
            window = ui_verify.VerifyWindow(app, str(path))
            windows.append(window)
            end = time.monotonic() + 1.5
            while time.monotonic() < end:  # the signature job runs in a thread and reports through the main loop
                GLib.MainContext.default().iteration(False)
            if window.signature_args:  # "Check again" must ask about the same bytes, not the file as it is now
                window._check_signature()
                end = time.monotonic() + 1.5
                while time.monotonic() < end:
                    GLib.MainContext.default().iteration(False)
        names = [row.name for row in window.rows]
        window.destroy()
    return calls, names


def spin(seconds=0.6):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        GLib.MainContext.default().iteration(False)


def wait(until, seconds=5):
    """Run the main loop until `until()` is true (the jobs report through it), at most `seconds`."""
    end = time.monotonic() + seconds
    while not until() and time.monotonic() < end:
        GLib.MainContext.default().iteration(False)
    return until()


def order(window):
    """The groups of a verify page, top to bottom, by the name the window keeps them under."""
    names = {window.hero: "hero", window.current_group: "slot", window.files_group: "files", window.signature_group: "signature", window.retry_btn: "retry"}
    child, seen = window.page.get_first_child(), []
    while child:
        if child.get_visible():
            seen.append(names[child])
        child = child.get_next_sibling()
    return seen


def verify(app, sums, files=(), sig=None, until=lambda w: w.outcome, seconds=5):
    """A verify window over a folder with `files` (name -> bytes) and the hash file text `sums`, once `until` holds;
    `sig` is gpg's answer, or a function that gives it."""
    tmp = tempfile.TemporaryDirectory()
    for name, data in dict(files).items():
        Path(tmp.name, name).write_bytes(data)
    Path(tmp.name, "SUMS").write_bytes(sums)
    with mock.patch.object(core, "verify_signature", sig if callable(sig) else lambda args, data=None: sig):
        window = ui_verify.VerifyWindow(app, str(Path(tmp.name, "SUMS")))
        window.present()
        wait(lambda: until(window), seconds)
    window.tmp = tmp  # the folder lives as long as the window
    return window


def counts_open_their_files(app):
    """Three lines count the files; a line with files opens them in a table of their own, filtered by its kind."""
    window = verify(app, f"{A}  gone.txt\n{A}  a.txt\n{'0' * 64}  b.txt\n".encode(), {"a.txt": b"alpha", "b.txt": b"alpha"})
    seen = [order(window), window.hero.title.get_label(), window.hero.detail.get_label().split(" · ")[0],
            [(row.count.get_label(), row.get_sensitive()) for row in window.kind_rows.values()]]
    window._open("bad")
    spin(0.2)
    seen += [window.detail.shown.get_n_items(), window.detail.tab_labels["bad"].get_label()]
    window._open("missing")
    window.detail.show_kind(ui_verify.ALL)
    seen.append(window.detail.shown.get_n_items())
    window.destroy()
    return seen == [["hero", "slot", "files", "retry"], "1 file differs", "10 B",
                    [("1", True)] * 3, 1, "Mismatch 1", 3] or seen


def detail_window_opens_again_after_closing(app):
    """Closed, the table opens as a new window that can be closed again; closing the verify window takes it along."""
    window = verify(app, f"{A}  a.txt\n{'0' * 64}  b.txt\n".encode(), {"a.txt": b"alpha", "b.txt": b"alpha"})
    window._open("all")
    first = window.detail
    first.close()
    spin(0.2)
    window._open("all")
    second = window.detail
    spin(0.2)
    seen = [second is not first, second.is_visible()]
    second.close()
    spin(0.2)
    window._open("bad")
    third = window.detail
    window.close()
    spin(0.2)
    seen += [window.detail is None, third.get_realized()]
    window.destroy()
    return seen == [True, True, True, False] or seen


def failed_files_are_checked_again(app):
    """"Retry failed" checks what failed again, a file fetched anew or put in the folder, and nothing else."""
    window = verify(app, f"{A}  a.txt\n{A}  b.txt\n{A}  gone.txt\n".encode(), {"a.txt": b"alpha", "b.txt": b"beta"})
    before = (window.retry_btn.get_sensitive(), window.counts["ok"], window.counts["bad"], window.counts["missing"])
    Path(window.tmp.name, "b.txt").write_bytes(b"alpha")  # fetched again
    Path(window.tmp.name, "gone.txt").write_bytes(b"alpha")  # put in the folder
    window.retry_btn.emit("clicked")
    wait(lambda: window.outcome)
    seen = (before, window.counts["ok"], window.counts["bad"], window.counts["missing"], window.hero.title.get_label(), window.retry_btn.get_sensitive())
    window.destroy()
    return seen == ((True, 1, 1, 1), 3, 0, 0, "3 files match", False) or seen


def user_ids_split_and_keys_need_a_full_fingerprint(app):
    """A user ID falls into name, comment and e-mail; a key is fetched by a full fingerprint only."""
    seen = (core.split_user_id("Jane Doe (work) <jane@example.org>"), core.split_user_id("Plain Name"), core.split_user_id("A (b) (c) <d>"),
            bool(core.import_key("D94AA3F0EFE21092")), bool(core.import_key("")))
    return seen == (("Jane Doe", "work", "jane@example.org"), ("Plain Name", "", ""), ("A (b)", "c", "d"), True, True) or seen


def fingerprint_is_copied_without_spaces(app):
    """The fingerprint is shown in blocks to compare; selected and copied, it has no spaces."""
    fp, got = "843938DF228D22F7B3742BC0D94AA3F0EFE21092", []
    parent = Adw.ApplicationWindow(application=app)
    window = ui_common.SignatureWindow(parent, core.Signature("nokey", "D94AA3F0EFE21092", "", fp), got.append, print)
    window.present()
    spin(0.3)
    label = ui_common._find_label(window, core.format_fingerprint(fp))
    label.select_region(0, -1)
    label.activate_action("clipboard.copy", None)
    spin(0.2)
    window.destroy()
    parent.destroy()
    return got == [fp] or got


def import_asks_twice_and_only_then_fetches(app):
    """Fetching a key takes two yeses, and the second asks whether the fingerprint was compared: "Not yet" fetches nothing."""
    fp, fetched, refreshed = "843938DF228D22F7B3742BC0D94AA3F0EFE21092", [], []
    parent = ui_common.BaseWindow(app, "t")
    window = ui_common.SignatureWindow(parent, core.Signature("nokey", "D94AA3F0EFE21092", "", fp), print, lambda: refreshed.append(True))
    window.present()
    spin(0.3)

    def answer(*words):
        for word in words:
            window.get_visible_dialog().emit("response", word)
            spin(0.3)
    with mock.patch.object(core, "import_key", lambda f: fetched.append(f) or ""):
        window.import_btn.emit("clicked")
        spin(0.3)
        answer("no")  # cancel at the first question
        window.import_btn.emit("clicked")
        spin(0.3)
        answer("yes", "no")  # "Not yet" at the second
        seen = [list(fetched)]
        window.import_btn.emit("clicked")
        spin(0.3)
        answer("yes", "yes")
        wait(lambda: fetched)
    seen += [fetched, refreshed]
    parent.destroy()
    return seen == [[], [fp], [True]] or seen


def empty_lines_stay_grey(app):
    """A line that holds no file is grey and opens nothing."""
    window = verify(app, f"{A}  a.txt\n".encode(), {"a.txt": b"alpha"})
    seen = [(row.count.get_label(), row.get_sensitive(), row.get_activatable()) for row in window.kind_rows.values()]
    discs = ["success" in window.kind_rows["ok"].badge.get_css_classes(), "warning" in window.kind_rows["missing"].badge.get_css_classes(),
             "error" in window.kind_rows["bad"].badge.get_css_classes()]
    window.destroy()
    return (seen == [("1", True, True), ("–", False, False), ("–", False, False)] and discs == [True, False, False]) or (seen, discs)  # verified, missing, mismatch; a disc has its colour only with files


def copy_leaves_blocks_out(app):
    """A hash copied by hand from its blocks has no spaces or line breaks, and the window knows it copied it."""
    window = ui_common.BaseWindow(app, "t")
    label = ui_common.hash_label("ab" * 32)
    window.show_page("hash", label)
    window.present()
    label.select_region(4, 30)
    label.activate_action("clipboard.copy", None)
    got = {}
    label.get_clipboard().read_text_async(None, lambda c, r: got.setdefault("text", c.read_text_finish(r)))
    wait(lambda: got)
    window.destroy()
    return got.get("text") == window.copied == ("ab" * 32)[4:27] or (got, window.copied)


def own_hash_copied_by_hand_is_no_match(app):
    """The compare window never takes a hash it showed itself back as "expected", copied by button or by hand."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "big.iso").write_bytes(b"alpha")
        window = ui_compare.CompareWindow(app, [str(Path(tmp, "big.iso"))])
        window.present()
        wait(lambda: window.entry)
        label = window.hash_rows["sha256"][0].get_child().get_first_child().get_next_sibling()
        label.select_region(0, -1)
        label.activate_action("clipboard.copy", None)
        spin()
        window._autofill()  # what coming back to the window does
        spin()
        seen = (window.entry.get_text(), window.hero.title.get_label())
        window.destroy()
    return seen == ("", "big.iso") or seen


def names_that_are_no_utf8_open(app):
    """A hash file or a selected file whose name is no UTF-8 still gets its window."""
    with tempfile.TemporaryDirectory() as tmp:
        name = os.fsdecode(b"\xff")
        Path(tmp, name + ".sha256").write_text(f"{A}  a.txt\n")
        Path(tmp, name).write_bytes(b"alpha")
        windows = [ui_verify.VerifyWindow(app, str(Path(tmp, name + ".sha256"))), ui_create.CreateWindow(app, [str(Path(tmp, name))])]
        seen = [windows[0].get_title(), windows[1].name.get_text()]
        for w in windows:
            w.destroy()
    return all("\ufffd" in title for title in seen) or seen


def thousands_never_freeze(app):
    """Entries that need no reading are checked by the thousand at once; the window must keep drawing meanwhile."""
    sums = "".join(f"{'a' * 33}  {i}.txt\n" for i in range(3000)).encode()  # an unknown digest length: each one is a problem row
    longest, last = 0.0, time.monotonic()

    def done(window):
        nonlocal longest, last
        longest, last = max(longest, time.monotonic() - last), time.monotonic()
        return window.outcome
    window = verify(app, sums, until=done, seconds=60)
    seen = (window.outcome, window.counts["unknown"], round(longest, 2))
    window.destroy()
    return (seen[:2] == ("done", 3000) and longest < 0.5) or seen


def gpg_is_awaited_aloud(app):
    """Files done before gpg: the Hero says it waits for the signature, then shows the verdict. A cancelled check is
    not done: it says so at once, never "100 %" and "Checking signature …"."""
    answer = threading.Event()

    def slow_gpg(args, data=None):
        answer.wait(5)
        return core.Signature("good", "AB12", "Real Publisher <a@b.c>", "A" * 40)
    window = verify(app, SIGNED, {"a.txt": b"alpha"}, slow_gpg, lambda w: w.outcome)
    waiting = window.hero.title.get_label()
    window.outcome = "cancelled"  # as if Cancel came before the last file: gpg is still running
    window._show_result()
    cancelled = window.hero.title.get_label()
    window.outcome = "done"
    answer.set()
    wait(lambda: window.sig)
    seen = (waiting, cancelled, window.hero.title.get_label())
    window.destroy()
    return seen == ("Checking signature …", "Cancelled", "1 file matches") or seen


def paths_read_as_in_files(app):
    """~ for the home folder; a network share as its smb:// address, even when GVfs does not map it back itself."""
    seen = (ui_common.short_path(os.path.expanduser("~/Downloads")),
            ui_common.short_path("/run/user/1000/gvfs/smb-share:server=nas,share=media/iso"))
    return seen == ("~/Downloads", "smb://nas/media/iso") or seen


def none_found_is_the_problem(app):
    """Only when no file of the list is in the folder is that the verdict."""
    window = verify(app, f"{A}  gone.txt\n".encode())
    seen = (window.hero.title.get_label(), window.kind_rows["missing"].count.get_label(), window.kind_rows["ok"].get_sensitive())
    window.destroy()
    return seen == ("None of the files were found", "1", False) or seen


def signature_comes_first(app):
    """The signature stands right below the verdict, above the lines."""
    good = core.Signature("good", "AB12", "Real Publisher <a@b.c>", "A" * 40)
    window = verify(app, SIGNED, {"a.txt": b"alpha"}, good, lambda w: w.outcome and w.sig)
    seen = order(window)
    window.destroy()
    return seen == ["hero", "signature", "slot", "files", "retry"] or seen


def bad_signature_takes_over(app):
    """A bad signature takes over the verdict and turns the files' check from green to grey."""
    window = verify(app, SIGNED, {"a.txt": b"alpha"}, core.Signature("bad", "AB12"), lambda w: w.outcome and w.sig)
    seen = (window.hero.title.get_label(), "success" in window.kind_rows["ok"].badge.get_css_classes(), window.kind_rows["ok"].get_title())
    window.destroy()
    return seen == ("Invalid signature: do not trust this hash file", False, "Matches") or seen


def size_is_fixed(app):
    """The window is as big for a clean result as for many problems: nothing grows, so it keeps its place on screen."""
    clean = verify(app, f"{A}  a.txt\n".encode(), {"a.txt": b"alpha"})
    wrong = verify(app, "".join(f"{'0' * 64}  {i}.txt\n" for i in range(6)).encode(), {f"{i}.txt": b"x" for i in range(6)})
    spin()
    seen = (clean.get_default_size(), wrong.get_default_size(), clean.get_height(), wrong.get_height())
    clean.destroy()
    wrong.destroy()
    return seen[0] == seen[1] and seen[2] == seen[3] and 300 < seen[2] <= 900 or seen


def missing_files_show_in_the_ring(app):
    """The check stands only for a whole green ring; entries not in the folder are a yellow part of it, no emblem."""
    clean = verify(app, f"{A}  a.txt\n".encode(), {"a.txt": b"alpha"})
    noted = verify(app, f"{A}  a.txt\n{A}  gone.txt\n".encode(), {"a.txt": b"alpha"})
    seen = [(w.hero.ring.icon.get_visible(), w.hero.ring.arcs["success"].length > 0, w.hero.ring.arcs["warning"].length > 0) for w in (clean, noted)]
    seen.append(noted.hero.ring.label.get_label())
    clean.destroy()
    noted.destroy()
    return seen == [(True, True, False), (False, True, True), "1/2"] or seen


def unchecked_signature_marks_the_green_ring(app):
    """All files fine but the signature does not vouch for the list (key expired or missing, gpg failed): the check keeps a
    small warning triangle; with a good signature it stands alone."""
    expired = core.Signature("expired", "AB12", "Old <o@x.org>", "A" * 40)
    good = core.Signature("good", "AB12", "Real <r@x.org>", "A" * 40)
    seen = []
    for sig in (expired, core.Signature("nokey", "AB12", "", "A" * 40), core.Signature("error", detail="gpg is not installed"), good):
        window = verify(app, SIGNED, {"a.txt": b"alpha"}, sig, lambda w: w.outcome and w.sig)
        seen.append(window.hero.ring.emblem.get_visible())
        window.destroy()
    return seen == [True, True, True, False] or seen


def ring_parts_fit(app):
    """Parts follow each other clockwise all round, a gap between any two; a tiny share keeps a place of its own,
    even between two big ones. A screen reader sees the ring as a progress bar."""
    ring = ui_common.Ring()
    for parts in ([("success", 0.998), ("error", 0.002)], [("success", 0.499), ("error", 0.001), ("warning", 0.5)]):
        ring.show(parts)
        arcs = [ring.arcs[kind] for kind, _share in parts]
        gaps = [(b.start - a.start - a.length) % 1 for a, b in zip(arcs, arcs[1:] + arcs[:1])]
        if min(gaps) < ring.gap * 0.99 or ring.arcs["accent"].length:
            return parts, gaps
    return ring.get_accessible_role() == Gtk.AccessibleRole.PROGRESS_BAR or ring.get_accessible_role()


def compare_shows_the_verdict(app):
    """The pasted hash decides the Hero: the file before, the verdict after."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "big.iso").write_bytes(b"alpha")
        with mock.patch.object(core, "load_config", lambda: {**core.DEFAULTS, "clipboard": False}):
            window = ui_compare.CompareWindow(app, [str(Path(tmp, "big.iso"))])
            wait(lambda: window.entry)
            before = window.hero.title.get_label()
            window.entry.set_text(A)
            after = window.hero.title.get_label()
            window.entry.set_text(hashlib.blake2b(b"alpha").hexdigest())  # as long as a SHA-512: must not read as one that differs
            b2sum = window.hero.title.get_label()
        window.destroy()
    return (before, after, b2sum) == ("big.iso", "SHA-256 matches", "BLAKE2b matches") or (before, after, b2sum)


def autofill_says_where_it_came_from(app):
    """A value from a hash file shows a note under the field with the file's name, until the value is changed."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "big.iso").write_bytes(b"alpha")
        Path(tmp, "SHA256SUMS").write_text(f"{A}  big.iso\n")
        with mock.patch.object(core, "load_config", lambda: {**core.DEFAULTS, "clipboard": False}):
            window = ui_compare.CompareWindow(app, [str(Path(tmp, "big.iso"))])
            wait(lambda: window.entry)
            window.is_active = lambda: True
            window._autofill()
            shown, text = True, window.note.get_text()
            window.entry.set_text("abc")
            gone = window.note.get_text().strip() == ""
        window.destroy()
    return (shown, "SHA256SUMS" in text, gone) == (True, True, True) or (shown, text, gone)


def overwrite_is_confirmed(app):
    """A hash file that exists is not replaced before the dialog was answered."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_text("x")
        window = ui_create.CreateWindow(app, [str(Path(tmp, "a.txt"))])
        window.present()
        spin()
        out = Path(window.base, window.name.get_text())
        out.write_text("precious")
        window._start()
        spin()
        dialog = window.get_visible_dialog()
        kept = out.read_text() == "precious" and window.job is None and dialog.get_width() <= window.get_width()  # the question fits the window
        window.destroy()
        return kept


def unwritable_folder_stops_before_hashing(app):
    """A folder that cannot be written says so at the click on Create, and the options stay to choose another one."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_text("x")
        window = ui_create.CreateWindow(app, [str(Path(tmp, "a.txt"))])
        with mock.patch.object(tempfile, "TemporaryFile", side_effect=PermissionError(13, "Permission denied")):  # root may write anywhere, so fake it
            window._start()
        stopped = window.job is None and window.stack.get_visible_child_name() == "options"
        window._start()  # the real folder can be written
        created = wait(lambda: window.stack.get_visible_child_name() == "done") and Path(window.out).is_file()
        window.destroy()
    return (stopped, created) == (True, True) or (stopped, created)


def a_window_without_checksums_closes(app):
    """The page for a file that is no hash file closes like any other window."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "notes.txt").write_text("just text\n")
        window = ui_verify.VerifyWindow(app, str(Path(tmp, "notes.txt")))
        closed = window._on_close() is False
        window.destroy()
    return closed


def files_without_checksums_share_one_window(app):
    """Many files that are no hash files give one window that names them; every real hash file keeps its own."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        Path(tmp, "SUMS").write_text(f"{A}  a.txt\n")
        photos = [str(Path(tmp, f"photo{i}.jpg")) for i in range(12)]
        for photo in photos:
            Path(photo).write_text("no hash here\n")
        windows = ui_gtk.verify_windows(app, [*photos, str(Path(tmp, "SUMS"))])
        alone = ui_gtk.verify_windows(app, [photos[0]])  # a single one is shown as before
        wait(lambda: windows[0].outcome)
        seen = (len(windows), isinstance(windows[0], ui_verify.VerifyWindow), len(alone), isinstance(alone[0], ui_verify.VerifyWindow))
        for window in (*windows, *alone):
            window.destroy()
    return seen == (2, True, 1, True) or seen


def create_window_fits_its_page(app):
    """The create window is as tall as its options page needs, also with the warning that a file is replaced: no scrolling."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_text("x")
        Path(tmp, "SHA256SUMS").write_text("old")  # the default name exists: the warning shows
        window = ui_create.CreateWindow(app, [str(Path(tmp, "a.txt"))])
        window.present()
        spin()
        adj = window.stack.get_child_by_name("options").get_vadjustment()
        seen = (adj.get_upper() <= adj.get_page_size() + 1, window.get_height() < 600)
        window.destroy()
    return seen == (True, True) or seen


def question_fits_a_fresh_window(app):
    """The settings reopen in a new language and ask about the restart at once, before the window has a width."""
    window = ui_settings.SettingsWindow(app)
    window.present()
    ui_common.warning_dialog(window, "t", "x", "no", "yes", print)
    width = window.get_visible_dialog().get_extra_child().get_size_request()[0]
    window.destroy()
    return 0 < width <= 480 or width


def speed_test_opens_its_window(app):
    """The button measures in a thread and opens a window with a bar per algorithm; no setting changes."""
    window = ui_settings.SettingsWindow(app)
    window.present()
    saved = dict(core.load_config())
    window.speed_button.emit("clicked")
    end = time.monotonic() + 15
    while not window.speed_button.get_sensitive() and time.monotonic() < end:
        spin()
    opened = window.get_visible_dialog() is not None and core.load_config() == saved
    ui_common.SpeedDialog({"crc32": 3000e6, "sha256": 1100e6, "sha512": 500e6, "sha1": 1200e6, "md5": 500e6})  # every kind of remark
    ui_common.SpeedDialog({"crc32": 900e6, "sha256": 300e6, "sha512": 600e6, "sha1": 100e6, "md5": 100e6})
    window.destroy()
    return opened or "no window, or a setting changed"


def two_files_are_compared(app):
    """Two files: identical, different content of the same size, or different sizes (not read at all)."""
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("a", b"alpha"), ("b", b"alpha"), ("c", b"alphb"), ("d", b"longer")):
            Path(tmp, name).write_bytes(data)
        seen = []
        for other in "bcd":
            window = ui_compare.CompareFilesWindow(app, [str(Path(tmp, "a")), str(Path(tmp, other))])
            window.present()
            wait(lambda: hasattr(window, "hero"))
            seen.append((window.hero.title.get_label(), window.hero.detail.get_label()))
            folded = getattr(window, "hashes", None)  # closed when identical, open when different, absent when not read
            seen.append(None if folded is None else folded.get_expanded())
            if window.get_focus() is not None:
                return "a hash is selected without being asked"
            if folded is not None:
                before = window.get_default_size()[1]
                folded.set_expanded(not folded.get_expanded())
                wait(lambda: window.get_default_size()[1] != before)  # the window follows the folding, up or down
            window.destroy()
    return seen == [("Files are identical", "SHA-256 matches"), False, ("Files differ", ""), True, ("Files differ", "The files have different sizes"), None] or seen


def unlisted_files_get_a_line_that_is_no_verdict(app):
    """Files in the folder that the list does not name are counted and can be opened; the verdict ignores them."""
    sums, files = f"{A}  a.txt\n{hashlib.sha256(b'beta').hexdigest()}  b.txt\n".encode(), {"a.txt": b"alpha", "b.txt": b"beta", "new.txt": b"x", "other.pdf": b"y"}
    window = verify(app, sums, files)  # off by default
    off = window.unlisted_row.get_visible()
    window.destroy()
    with mock.patch.object(core, "load_config", lambda: {**core.DEFAULTS, "unlisted": True}):
        window = verify(app, sums, files)
        seen = (window.unlisted_row.get_visible(), window.unlisted_row.count.get_label(), window.hero.title.get_label())
        window.destroy()
    return (off, *seen) == (False, True, "2", "2 files match") or (off, *seen)


def an_existing_hash_file_is_added_to(app):
    """The create window offers to add to an existing hash file, keeps its algorithm and writes only what is new."""
    with tempfile.TemporaryDirectory() as tmp:
        a, b, out = (str(Path(tmp, n)) for n in ("a.txt", "b.txt", "SHA256SUMS"))
        Path(a).write_bytes(b"alpha")
        core.write_hashfile([a], tmp, "sha256", out)
        os.utime(out, (time.time() + 10, time.time() + 10))
        Path(b).write_bytes(b"beta")
        window = ui_create.CreateWindow(app, [a, b])
        window.present()
        spin()
        spin()
        adj = window.stack.get_child_by_name("options").get_vadjustment()
        fits = adj.get_upper() <= adj.get_page_size() + 1  # the window grew for the rows: no scrolling
        offered = (fits, window.update_group.get_visible(), window.update_row.get_selected(), window.start_btn.get_label(), window.choice.get_sensitive())
        window.update_row.set_selected(1)  # replace: the usual page again
        replace = (window.start_btn.get_label(), window.choice.get_sensitive())
        window.update_row.set_selected(0)
        window._start()
        wait(lambda: window.stack.get_visible_child_name() == "done")
        names = [e.name for e in core.parse(out)]
        title = window.hero_title if hasattr(window, "hero_title") else ""
        window.destroy()
    return (offered, replace, names) == ((True, True, 0, "Update", False), ("Create", True), ["a.txt", "b.txt"]) or (offered, replace, names, title)


def main():
    app = Adw.Application(application_id=core.APP_ID + ".smoke", flags=Gio.ApplicationFlags.NON_UNIQUE)
    failures = []

    def activate(app):
        try:
            checks(app)
        except Exception:
            failures.append("a check raised: " + traceback.format_exc())
        finally:
            app.quit()

    def checks(app):
        ui_gtk.load_css()
        if asked(app, SIGNED, EVIL) != ([SIGNED, SIGNED], ["a.txt"]):
            failures.append("gpg was not asked about the bytes the list shows")
        if asked(app, EVIL + SIGNED, SIGNED)[0]:
            failures.append("a plain list got a verdict because the file on disk is clear-signed now")
        forged = core.Signature("good", "AB12", "Real Publisher" + " " * 300 + "Fingerprint: " + "B" * 40, "A" * 40)
        row = ui_common.signature_row(forged, print, print)
        if row.get_subtitle_lines() != 1 or row.get_title_lines() != 1:
            failures.append("a user ID can wrap into a line of its own, such as a fake fingerprint line")
        for check in (counts_open_their_files, detail_window_opens_again_after_closing, failed_files_are_checked_again, user_ids_split_and_keys_need_a_full_fingerprint, fingerprint_is_copied_without_spaces, import_asks_twice_and_only_then_fetches, empty_lines_stay_grey, gpg_is_awaited_aloud, paths_read_as_in_files, copy_leaves_blocks_out, own_hash_copied_by_hand_is_no_match,
                      names_that_are_no_utf8_open, thousands_never_freeze, none_found_is_the_problem, signature_comes_first,
                      bad_signature_takes_over, size_is_fixed, missing_files_show_in_the_ring, unchecked_signature_marks_the_green_ring, ring_parts_fit, compare_shows_the_verdict, autofill_says_where_it_came_from,
                      unwritable_folder_stops_before_hashing, a_window_without_checksums_closes, files_without_checksums_share_one_window, create_window_fits_its_page, question_fits_a_fresh_window, two_files_are_compared, speed_test_opens_its_window, unlisted_files_get_a_line_that_is_no_verdict, an_existing_hash_file_is_added_to):
            if (result := check(app)) is not True:
                failures.append(f"{check.__name__}: {result}")
        if not overwrite_is_confirmed(app):
            failures.append("an existing hash file was replaced without asking, or the question is wider than the window")
        early, late, none = ui_common.time_left(0.5, 4.9), ui_common.time_left(0.25, 60), ui_common.time_left(0, 60)
        if (early, late, none) != ("", "3 min 0 s", ""):
            failures.append(f"time left: {early}, {late}, {none}")  # only after 5 s and with progress
        if core.KEYSERVER.split("//")[-1] not in ui_common.IMPORT_TEXT or core.KEYSERVER not in ui_common.import_command(core.Signature("nokey")):
            failures.append("the import warning or the import command names another keyserver than the one the key is fetched from")
        ui_common.progress_page("t", 100, print)[1](0.5)  # the page builds and takes a fraction
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "big.iso").write_bytes(b"x")
            window = ui_compare.CompareWindow(app, [str(Path(tmp, "big.iso"))])
            names = []

            def labels(widget):  # the labels of a page, depth first
                while widget:
                    if isinstance(widget, Gtk.Label):
                        names.append(widget.get_label())
                    labels(widget.get_first_child())
                    widget = widget.get_next_sibling()
            labels(window.stack.get_child_by_name("progress"))
            if "big.iso" not in names or window.header.get_title_widget().get_subtitle():
                failures.append(f"the progress page does not show the file header: {names}")
        app.quit()

    app.connect("activate", activate)
    app.run([])
    if failures:
        sys.exit("; ".join(failures))
    print("GTK smoke test ok")


if __name__ == "__main__":
    main()
