# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# ruff: noqa: E402
"""Shared parts of the GTK front end: constants, formatters, widgets (Ring, Hero) and BaseWindow."""
import math
import os
import re
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gsk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GObject, Gio, GLib, Graphene, Gsk, Gtk, Pango

import core
from core import APP_ID, Cancelled
from i18n import N_, _

if Adw.get_minor_version() < 5:  # AboutDialog needs libadwaita 1.5 (GNOME 46, which brings the GTK 4.14 the Ring draws with)
    raise ImportError("libadwaita >= 1.5 required")

# Colours come from libadwaita's named colours and style classes, so they follow light/dark mode and the accent colour.
CSS = """
/* easter egg cat: a popover that shows nothing but the drawing */
popover.k-cat > contents { background: none; border: none; box-shadow: none; padding: 0; }
.ht-hash { font-family: monospace; font-size: 0.9em; }
row.ht-mono .subtitle { font-family: monospace; font-size: 0.9em; }
row.ht-empty { background-color: @window_bg_color; }
.ht-tint-error, row.ht-tint-error { background: alpha(@error_color, 0.045); }
.ht-tint-warning, row.ht-tint-warning { background: alpha(@warning_color, 0.045); }
.ht-emblem { background: @window_bg_color; border-radius: 99px; padding: 3px; }
.ht-badge { min-width: 34px; min-height: 34px; border-radius: 99px; background: alpha(currentColor, 0.14); }
.ht-table cell { padding: 0; }
.ht-cell { padding: 6px 10px; }
statuspage.ht-good image { color: @success_color; opacity: 1; }
statuspage.ht-caution image { color: @warning_color; opacity: 1; }
statuspage.ht-failure image { color: @error_color; opacity: 1; }
.ht-match    { box-shadow: inset 0 0 0 2px @success_color; }
.ht-mismatch { box-shadow: inset 0 0 0 2px @error_color; }
.ht-row-match { background: alpha(@success_bg_color, 0.12); }
"""
# The icon in the middle of a ring that is one colour: done, failed, careful
ICONS = {"success": "object-select-symbolic", "error": "dialog-error-symbolic", "warning": "dialog-warning-symbolic"}


class Job:
    """Run `work(job)` in a thread and hand its result to `on_done(result, error)` on the UI thread.

    `error` is None on success, the string "cancelled" if the user aborted, else the exception.
    """

    def __init__(self, total, work, on_progress, on_done):
        self.cancel = threading.Event()
        self._total, self._done, self._last = max(total, 1), 0, 0.0
        self._on_progress = on_progress
        threading.Thread(target=self._run, args=(work, on_done), daemon=True).start()

    def progress(self, nbytes):
        """Per-chunk callback for core.hash_file; doubles as the cancellation point."""
        if self.cancel.is_set():
            raise Cancelled()
        self._done += nbytes
        if time.monotonic() - self._last > 0.05:  # throttle UI updates
            self._last = time.monotonic()
            GLib.idle_add(self._on_progress, min(self._done / self._total, 1.0))

    def _run(self, work, on_done):
        try:
            result, error = work(self), None
        except Cancelled:
            result, error = None, "cancelled"
        except Exception as exc:  # report anything else in the window instead of dying silently
            result, error = None, exc
        GLib.idle_add(on_done, result, error)


# --------------------------------------------------------------------------- shared widgets

def status_page(icon, title, description=""):
    """A page with a big icon in the colour of its meaning: green for done, yellow for a warning, red for an error."""
    kind = {"object-select-symbolic": "ht-good", "dialog-warning-symbolic": "ht-caution", "dialog-error-symbolic": "ht-failure"}[icon]
    return Adw.StatusPage(icon_name=icon, title=title, description=GLib.markup_escape_text(core.shown(description)), css_classes=[kind])


def fmt_duration(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h} h {m} min"  # units are the same in every language
    return f"{m} min {s} s" if m else f"{s} s"


def time_left(frac, spent):
    """The time left as text, or "" in the first seconds, before the estimate means something.
    shortcut: the estimate is the average speed of the whole run, steady for a plain hash; a disk that slows down late makes it too hopeful."""
    return fmt_duration(spent * (1 - frac) / frac) if spent >= 5 and frac > 0 else ""


def progress_text(frac, total, spent):
    """How far, how fast, how long still: "7.8 GB of 9.2 GB · 410.0 MB/s · 4 s left"."""
    done = int(frac * total)
    parts = [_("{done} of {total}").format(done=core.human_size(done), total=core.human_size(total))]
    if spent >= 1:
        parts.append(core.human_size(int(done / spent)) + "/s")
    if left := time_left(frac, spent):
        parts.append(_("{time} left").format(time=left))
    return " · ".join(parts)


def grouped(digest):
    """A hash in blocks of eight, four to a line, so the eye can compare it block by block; copying always takes it
    without spaces. The lines are broken here, not by a wrapping label: GTK 4.22 (not 4.14) has a Gtk.Grid measure a
    wrapping label at its narrowest width (a block a line) and leaves that height empty. Never wrap a label in a Grid."""
    blocks = [digest[i:i + 8] for i in range(0, len(digest), 8)]
    return "\n".join(" ".join(blocks[i:i + 4]) for i in range(0, len(blocks), 4))


def hash_label(digest, *css):
    """A selectable hash in blocks; copying a selection (Ctrl+C or the context menu) leaves the spaces and line breaks out,
    so a hash copied by hand still compares, and goes through the window's _copy like the copy button, so no compare window
    takes it back as "expected". shortcut: the middle-click (primary) selection keeps them; GTK offers no hook."""
    label = Gtk.Label(label=grouped(digest), xalign=0, yalign=0, selectable=True, css_classes=["ht-hash", *css])
    return spaceless(label, digest, lambda text: label.get_root()._copy(text))


def badge(icon, kind=None):
    """A symbolic icon on a round tint of its colour ("success", "error", "warning", "accent", or grey without)."""
    return Gtk.Image(icon_name=icon, valign=Gtk.Align.CENTER, css_classes=["ht-badge", *([kind] if kind else [])])


class Arc(Gtk.Widget):
    """One coloured part of a Ring. It strokes in the CSS colour of its style class, so libadwaita picks the
    shade for light or dark mode; the track (no class) is the text colour, faint."""

    WIDTH = 8

    def __init__(self, kind=None):
        super().__init__(css_classes=[kind] if kind else [])
        self.track, self.start, self.length = kind is None, 0.0, 1.0 if kind is None else 0.0  # shares of the full circle

    def do_snapshot(self, snapshot):
        if self.length <= 0:
            return
        w, h = self.get_width(), self.get_height()
        cx, cy, r = w / 2, h / 2, min(w, h) / 2 - self.WIDTH / 2
        path = Gsk.PathBuilder.new()
        if self.length >= 1:
            path.add_circle(Graphene.Point().init(cx, cy), r)
        else:  # clockwise from the top
            a0 = 2 * math.pi * self.start - math.pi / 2
            a1 = a0 + 2 * math.pi * self.length
            path.move_to(cx + r * math.cos(a0), cy + r * math.sin(a0))
            path.svg_arc_to(r, r, 0, self.length > 0.5, True, cx + r * math.cos(a1), cy + r * math.sin(a1))
        stroke = Gsk.Stroke.new(self.WIDTH)
        stroke.set_line_cap(Gsk.LineCap.ROUND)
        color = self.get_color()
        if self.track:
            color.alpha *= 0.1
        snapshot.append_stroke(path.to_path(), stroke, color)


class Ring(Gtk.Overlay):
    """Progress or a result as a ring of coloured parts, with a figure or an icon in its middle."""

    def __init__(self, size=96):
        super().__init__(halign=Gtk.Align.CENTER, accessible_role=Gtk.AccessibleRole.PROGRESS_BAR)  # a screen reader follows it as the bar it replaces
        self.update_property([Gtk.AccessibleProperty.VALUE_MIN, Gtk.AccessibleProperty.VALUE_MAX], [0, 1])
        self.size, self.track = size, Arc()
        self.track.set_size_request(size, size)
        self.set_child(self.track)
        self.arcs = {kind: Arc(kind) for kind in ("success", "error", "warning", "accent")}
        self.gap = (Arc.WIDTH + 5) / (math.pi * (size - Arc.WIDTH))  # between two parts: both round caps plus 5 px, as a share of the circle
        self.label = Gtk.Label(css_classes=["title-2", "numeric"])
        self.icon = Gtk.Image(pixel_size=size * 2 // 5)
        self.emblem = Gtk.Image(icon_name="dialog-warning-symbolic", pixel_size=size // 4, halign=Gtk.Align.END,
                                valign=Gtk.Align.END, css_classes=["warning", "ht-emblem"], visible=False)
        for widget in (*self.arcs.values(), self.label, self.icon, self.emblem):
            self.add_overlay(widget)

    def show(self, parts, text="", icon=None, plain=False, emblem=False):
        """`parts`: [(kind, share of the circle)], drawn clockwise in that order; they may add up to less than 1.
        The middle shows `text`, or else `icon` (a name or a Gio.Icon) in the colour of the first part.
        `plain`: no ring, the icon alone as big as the ring was.
        `emblem`: a small warning triangle at the bottom right, over a ring that is otherwise green: the result is fine, but read the note."""
        self.emblem.set_visible(emblem)
        self.track.length = 0.0 if plain else 1.0  # not drawn, but it still gives the ring its size
        self.track.queue_draw()
        self.icon.set_pixel_size(self.size if plain else self.size * 2 // 5)
        parts = [(kind, share) for kind, share in parts if share > 0]
        total = sum(share for _kind, share in parts)
        self.update_property([Gtk.AccessibleProperty.VALUE_NOW, Gtk.AccessibleProperty.VALUE_TEXT], [total, text or f"{total:.0%}"])
        gap, start = self.gap if len(parts) > 1 else 0, 0.0
        room = gap + 0.001  # the least a part takes: a dot and its gap, so a tiny share never hides under the next one's round cap
        lent = sum(max(room - share, 0) for _kind, share in parts)  # the biggest part gives the tiny ones that room
        biggest = max(parts, key=lambda part: part[1], default=(None, 0))[0]
        for arc in self.arcs.values():
            arc.length = 0
        for kind, share in parts:
            share = max(share, room) - (lent if kind == biggest else 0)
            arc = self.arcs[kind]
            arc.start, arc.length = start + gap / 2, max(share - gap, 0.001)  # a tiny share still shows, as a dot
            start += share
        for arc in self.arcs.values():
            arc.set_visible(not plain)
            arc.queue_draw()
        self.label.set_label(text)
        self.label.set_visible(not icon)
        self.icon.set_visible(bool(icon))
        if isinstance(icon, str):
            self.icon.set_from_icon_name(icon)
        elif icon:
            self.icon.set_from_gicon(icon)
        self.icon.set_css_classes([parts[0][0]] if parts else ["dim-label"])


class Hero(Gtk.Box):
    """The top of every window: a Ring, a big title and a dim line of detail."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin_top=12)
        self.ring = Ring()
        self.title = Gtk.Label(wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, justify=Gtk.Justification.CENTER,
                               margin_top=12, css_classes=["title-2"])  # a long file name wraps instead of widening the window
        self.detail = Gtk.Label(wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, justify=Gtk.Justification.CENTER,
                                css_classes=["dim-label"])
        for widget in (self.ring, self.title, self.detail):
            self.append(widget)

    def set(self, title, detail=""):
        self.title.set_label(title)
        self.detail.set_label(detail)
        self.detail.set_visible(bool(detail))


def column_page(*parts):
    """A scrolling page: `parts` one below the other in a column of readable width. Returns (column, page)."""
    column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, margin_bottom=24)
    for part in parts:
        column.append(part)
    clamp = Adw.Clamp(maximum_size=600, margin_start=12, margin_end=12, child=column)
    return column, Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True, child=clamp)


def group(*rows, title=""):
    """A boxed list (Adw.PreferencesGroup) holding `rows`."""
    box = Adw.PreferencesGroup(title=title)
    for row in rows:
        box.add(row)
    return box


def plain_row(child):
    """A list row around our own widget, which neither lights up nor takes the focus when clicked.
    (An Adw.PreferencesRow, not a plain Gtk.ListBoxRow: only those go into a group's boxed list.)"""
    return Adw.PreferencesRow(child=child, activatable=False, focusable=False)


def progress_page(title, total, on_cancel):
    """Ring with the percentage, `title`, how far and how fast, and Cancel; returns (page, show) where show(fraction) updates them."""
    hero, started = Hero(), time.monotonic()
    hero.set(title)
    cancel = Gtk.Button(label=_("Cancel"), halign=Gtk.Align.CENTER, css_classes=["pill"])
    cancel.connect("clicked", on_cancel)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, valign=Gtk.Align.CENTER, margin_start=24, margin_end=24)
    page.append(hero)
    page.append(cancel)

    def show(frac):
        hero.ring.show([("accent", frac)], f"{frac:.0%}")
        hero.detail.set_label(progress_text(frac, total, time.monotonic() - started))
    show(0)
    return page, show


def set_class(widget, name, on):
    if on:
        widget.add_css_class(name)
    else:
        widget.remove_css_class(name)


def combo_row(title, options, current, on_change, subtitle=""):
    """Adw.ComboRow over {value: label}; `on_change(value)` fires when the user picks one."""
    keys = list(options)
    row = Adw.ComboRow(title=title, subtitle=subtitle, model=Gtk.StringList.new(list(options.values())))
    row.set_selected(keys.index(current) if current in keys else 0)
    row.connect("notify::selected", lambda r, _p: on_change(keys[r.get_selected()]))
    return row


def warning_dialog(window, title, text, no, yes, on_answer, css="warning", style=Adw.ResponseAppearance.DESTRUCTIVE, extra=None):
    """Question with a big triangle ("error" = red, "warning" = yellow) beside the text.
    `on_answer(True)` runs for `yes`; `no`, Escape and closing the dialog give `on_answer(False)`."""
    dialog = Adw.AlertDialog.new(title, None)
    box = Gtk.Box(spacing=16, halign=Gtk.Align.CENTER, margin_top=6)
    box.append(Gtk.Image(icon_name="dialog-warning-symbolic", pixel_size=48, css_classes=[css]))
    words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, hexpand=True)
    words.append(Gtk.Label(label=text, xalign=0, wrap=True))
    if extra:  # something below the text, such as a fingerprint to compare: flush with it
        words.append(extra)
    box.append(words)
    # the dialog is as wide as its content (set_content_width crashes here), never wider than the window; a window that is
    # not drawn yet (the settings reopened in a new language) has no width, only its default
    box.set_size_request(min(480, (window.get_width() or window.get_default_size()[0]) - 64), -1)
    dialog.set_extra_child(box)
    dialog.add_response("no", no)
    dialog.add_response("yes", yes)
    dialog.set_response_appearance("yes", style)
    dialog.set_close_response("no")
    dialog.choose(window, None, lambda d, res: on_answer(d.choose_finish(res) == "yes"))


class Row(GObject.Object):
    """One file: its name and size, plus the checked entry and its result when verifying."""

    def __init__(self, name, size, entry=None):
        super().__init__()
        self.name, self.size, self.entry = name, size, entry
        self.status, self.found = "waiting", None


def size_text(row):
    return "" if row.size is None else core.human_size(row.size)


def text_column(title, text_of, xalign=0.0, kind=False, width=-1, expand=False):
    """A table column showing `text_of(row)`; with `kind` a file type icon stands before the text."""
    def setup():
        label = Gtk.Label(xalign=xalign, ellipsize=Pango.EllipsizeMode.MIDDLE, hexpand=True)
        cell = Gtk.Box(spacing=8, css_classes=["ht-cell"])
        if kind:
            cell.append(Gtk.Image())
        cell.append(label)
        return cell

    def bind(cell, row):
        text = core.shown(text_of(row))
        if kind:
            cell.get_first_child().set_from_gicon(Gio.content_type_get_symbolic_icon(Gio.content_type_guess(text, None)[0]))
        cell.get_last_child().set_label(text)
        cell.set_tooltip_text(text)  # names may be cut off

    factory = Gtk.SignalListItemFactory()
    factory.connect("setup", lambda f, item: item.set_child(setup()))
    factory.connect("bind", lambda f, item: bind(item.get_child(), item.get_item()))
    return Gtk.ColumnViewColumn(title=title, factory=factory, resizable=True, expand=expand, fixed_width=width)


def import_command(sig):
    """The gpg command that fetches the signing key. The full fingerprint is much harder to fake than the short key ID, so it is used when gpg gave one."""
    return f"gpg --keyserver {core.KEYSERVER} --recv-keys {sig.fingerprint or sig.key}"


def signature_hint():
    return _("Compare it with the publisher's website; HashTally cannot tell whether this key really belongs to them.")


def signature_texts(sig):
    """(icon, colour class, title) of the row for a core.Signature."""
    return {
        "good": ("object-select-symbolic", "success", _("Good signature from {signer}").format(signer=sig.signer)),
        "nokey": ("dialog-warning-symbolic", "warning", _("Signature not checked: public key missing")),
        "expired": ("dialog-warning-symbolic", "warning", _("Valid signature, but the key has expired")),
        "revoked": ("window-close-symbolic", "error", _("Valid signature, but the key was revoked")),  # gpg: "could mean that the signature is forged"
        "bad": ("window-close-symbolic", "error", _("Invalid signature: do not trust this hash file")),
        "error": ("dialog-warning-symbolic", "warning", _("Signature could not be checked")),
    }[sig.status]


FIXABLE = ("nokey", "expired", "error")  # states the user can fix outside HashTally, then check again
IMPORT_TEXT = N_("HashTally will fetch the key with this fingerprint from keyserver.ubuntu.com and add it to your keyring. "
                 "The server learns your IP address.\n\nBefore you go on, compare this fingerprint with the one on the publisher's website:")


def spaceless(label, plain, on_copy):
    """A selectable label whose copied text has no spaces: a fingerprint is shown in blocks to compare, and pasted without them.
    With nothing selected, Ctrl+C copies `plain`. Goes through `on_copy` as the copy buttons do."""
    def copy(label):
        selected, start, end = label.get_selection_bounds()
        on_copy("".join(label.get_text()[start:end].split()) if selected else plain)
        label.stop_emission_by_name("copy-clipboard")
    label.connect("copy-clipboard", copy)
    return label


def _find_label(widget, text):
    """The Gtk.Label inside `widget` that shows `text` (an Adw row keeps its subtitle label to itself)."""
    child = widget.get_first_child()
    while child:
        if isinstance(child, Gtk.Label) and child.get_label() == text:
            return child
        if found := _find_label(child, text):
            return found
        child = child.get_next_sibling()


COMPARE_TEXT = N_("Only import the key once you have compared its fingerprint with the one on the publisher's official website. "
                  "A forged key makes a forged hash file look genuine, and HashTally cannot tell the difference.\n\n"
                  "If you have not done that yet, do it first. The import is just as quick afterwards.")


def _copy_button(text, tip, on_copy):
    button = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text=tip, valign=Gtk.Align.CENTER, css_classes=["flat"])
    button.connect("clicked", lambda b: on_copy(text))
    return button


def _one_line(text, *css):
    """A label for text from a signature: one ellipsized line, as a long user ID must not wrap into a line of its own
    (a fake "Fingerprint:" under it)."""
    return Gtk.Label(label=text, xalign=0, ellipsize=Pango.EllipsizeMode.END, tooltip_text=text, css_classes=list(css))


def signature_row(sig, on_copy, on_refresh):
    """Two lines: the verdict above ("Signature valid", or what is wrong), below it, small and grey, who signed: "Name (e-mail)",
    cut off with "…" when it is long. A click on the line opens the SignatureWindow, where the buttons are.
    The line itself stays bare, as the other lines of the overview."""
    icon, color, title = signature_texts(sig)
    name, _comment, email = core.split_user_id(core.shown(sig.signer)) if sig.status == "good" else ("", "", "")
    row = Adw.ActionRow(title=_("Signature valid") if sig.status == "good" else title, subtitle=f"{name} ({email})" if name and email else name,
                        use_markup=False, title_lines=1, subtitle_lines=1, activatable=True, tooltip_text=core.shown(sig.signer) or title)
    row.add_prefix(badge(icon, color))
    row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
    row.connect("activated", lambda r: SignatureWindow(r.get_root(), sig, on_copy, on_refresh).present())
    return row


class SignatureWindow(Adw.Window):
    """The whole signature in the manner of a key's page: who signed (name, e-mail), then comment, key ID, fingerprint
    to compare with the publisher's, when the key expires, the hint that a valid signature only proves "made by this
    key", and for a key that is missing the button that fetches it."""

    def __init__(self, parent, sig, on_copy, on_refresh):
        super().__init__(transient_for=parent, destroy_with_parent=True, title=_("Signature"), default_width=520, default_height=620)
        self.parent_window, self.sig, self.on_refresh, self.on_copy = parent, sig, on_refresh, on_copy
        icon, color, title = signature_texts(sig)
        good = sig.status == "good"
        name, comment, email = core.split_user_id(core.shown(sig.signer)) if sig.signer else ("", "", "")

        def field(label, value, mono=False, copy=None):
            """A small grey label above, the value in the normal text below."""
            row = Adw.ActionRow(title=label, subtitle=value, use_markup=False, subtitle_selectable=True, css_classes=["property", *(["ht-mono"] if mono else [])])
            if copy:
                row.add_suffix(_copy_button(copy[0], copy[1], on_copy))
            return row

        avatar = Gtk.Image(icon_name="avatar-default-symbolic" if sig.signer else icon, pixel_size=36, valign=Gtk.Align.CENTER,
                           css_classes=["ht-badge", color])
        avatar.set_size_request(76, 76)
        who = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, valign=Gtk.Align.CENTER, hexpand=True)
        who.append(Gtk.Label(label=name or title, xalign=0, wrap=True, lines=2, ellipsize=Pango.EllipsizeMode.END, tooltip_text=name or None,
                             css_classes=["title-2" if name else "title-3"]))  # big type: two lines at most, it cannot pass for a field
        if email:
            who.append(_one_line(email, "dim-label"))
        if name:  # the verdict, under the name
            who.append(Gtk.Label(label=_("Signature valid") if good else title, xalign=0, wrap=True, margin_top=4, css_classes=[color]))
        head = Gtk.Box(spacing=18, margin_top=18, margin_start=6, margin_end=6)
        head.append(avatar)
        head.append(who)
        rows = []
        if comment:
            rows.append(field(_("Comment"), comment))
        if sig.key:
            rows.append(field(_("Key ID"), sig.key, True, (sig.key, _("Copy"))))
        if sig.fingerprint:
            shown = core.format_fingerprint(sig.fingerprint)
            rows.append(field(_("Fingerprint"), shown, True, (sig.fingerprint, _("Copy"))))
            if label := _find_label(rows[-1], shown):
                spaceless(label, sig.fingerprint, on_copy)
        if sig.expires is not None:
            rows.append(field(_("Expires"), _("Never") if not sig.expires else GLib.DateTime.new_from_unix_local(sig.expires).format("%x")))
        if sig.status == "nokey":
            rows.append(field(_("Import command (terminal)"), import_command(sig), True, (import_command(sig), _("Copy import command"))))
        page = [head]
        if rows:
            page.append(group(*rows))
        note = signature_hint() if sig.status in ("good", "nokey") else (sig.detail if sig.status == "error" else "")
        if note:
            box = Gtk.Box(spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
            box.append(Gtk.Image(icon_name="dialog-information-symbolic", valign=Gtk.Align.START))
            box.append(Gtk.Label(label=core.shown(note), xalign=0, hexpand=True, wrap=True, selectable=True))
            page.append(group(plain_row(box)))
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        if sig.status in FIXABLE:
            again = Gtk.Button(label=_("Check again"), css_classes=["pill"])
            again.connect("clicked", lambda b: (on_refresh(), self.close()))
            buttons.append(again)
        self.import_btn = None
        if sig.status == "nokey" and sig.fingerprint:
            self.import_btn = Gtk.Button(label=_("Import key"), css_classes=["pill", "suggested-action"])
            self.import_btn.connect("clicked", lambda b: self._ask_import())
            buttons.append(self.import_btn)
        if buttons.get_first_child():
            page.append(buttons)
        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_bottom=24)
        for part in page:
            column.append(part)
        view = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, child=Adw.Clamp(maximum_size=500, margin_start=12, margin_end=12, child=column))
        self.connect("map", lambda w: GLib.idle_add(view.get_vadjustment().set_value, 0))  # the first selectable text takes the focus and scrolls to itself
        tools = Adw.ToolbarView(content=view)
        tools.add_top_bar(Adw.HeaderBar())
        self.set_content(tools)
        key = Gtk.ShortcutController()
        key.add_shortcut(Gtk.Shortcut(trigger=Gtk.ShortcutTrigger.parse_string("Escape"), action=Gtk.CallbackAction.new(lambda *a: self.close() or True)))
        self.add_controller(key)

    def _ask_import(self):
        """Fetching a key changes the keyring and tells a server who asks: only after a warning, with the fingerprint to compare."""
        warning_dialog(self, _("Import this key?"), _(IMPORT_TEXT), _("Cancel"), _("Continue"), lambda yes: yes and self._ask_compared(),
                       extra=self._fingerprint_view())

    def _ask_compared(self):
        """The second question, which cannot be clicked through by habit: "Not yet" is the way out, and the import
        is a red button of its own."""
        warning_dialog(self, _("Have you compared the fingerprint?"), _(COMPARE_TEXT), _("Not yet"), _("Yes, import key"),
                       lambda yes: yes and self._import(), css="error", extra=self._fingerprint_view())

    def _fingerprint_view(self):
        """The fingerprint in blocks, to compare and to copy without spaces."""
        label = spaceless(Gtk.Label(label=core.format_fingerprint(self.sig.fingerprint), selectable=True, wrap=True, xalign=0, css_classes=["ht-hash"]),
                          self.sig.fingerprint, self.on_copy)
        label.connect("map", lambda l: GLib.idle_add(l.select_region, 0, 0))  # the first selectable text starts out selected: not this one
        return label

    def _import(self):
        self.import_btn.set_sensitive(False)
        self.import_btn.set_label(_("Importing …"))
        Job(0, lambda job: core.import_key(self.sig.fingerprint), None, self._imported)

    def _imported(self, message, error):
        message = str(error) if error else message
        if message:  # gpg's own words: no dirmngr, no network, key not on the server
            self.import_btn.set_sensitive(True)
            self.import_btn.set_label(_("Import key"))
            failure = Adw.AlertDialog.new(_("Key not imported"), core.shown(message))
            failure.add_response("ok", _("OK"))
            failure.present(self)
            return
        self.parent_window.toasts.add_toast(Adw.Toast(title=_("Key imported"), timeout=2))
        self.on_refresh()
        self.close()


def short_path(path):
    """Readable location: ~ for the home folder, smb://server/share/... for mounted network shares (as TrustCopy shows it)."""
    name = Gio.File.new_for_path(path).get_parse_name()  # GVfs maps its FUSE paths back to the URI Files shows
    m = re.match(r"/run/user/\d+/gvfs/smb-share:server=([^,/]+),share=([^,/]+)[^/]*(.*)", name)  # fallback if it did not
    if m:
        name = f"smb://{m[1]}/{m[2]}{m[3]}"
    home = os.path.expanduser("~")
    return "~" + name[len(home):] if name == home or name.startswith(home + "/") else name


def show_in_folder(window, path):
    Gtk.FileLauncher(file=Gio.File.new_for_path(path)).open_containing_folder(window, None, None)


class BaseWindow(Adw.ApplicationWindow):
    """Header bar plus a page stack; cancels the running job when the window closes."""

    HAS_MENU = True  # the main menu (Settings, About); the settings window has both on its page already

    def __init__(self, app, title, subtitle="", size=(640, 600)):
        title, subtitle = core.shown(title), core.shown(subtitle)  # a hash file's name need not be UTF-8
        super().__init__(application=app, title=f"HashTally – {subtitle or title}",
                         default_width=size[0], default_height=size[1])
        self.job = self.copied = None
        self.header = Adw.HeaderBar(title_widget=Adw.WindowTitle(title=title, subtitle=subtitle))
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.toasts = Adw.ToastOverlay(child=self.stack)
        self.toolbar = Adw.ToolbarView(content=self.toasts)
        self.toolbar.add_top_bar(self.header)
        self.set_content(self.toolbar)
        self.connect("close-request", self._on_close)
        keys = Gtk.ShortcutController()  # Ctrl+W as everywhere in GNOME; Escape as in a dialog, since these windows are one-off tools
        keys.add_shortcut(Gtk.Shortcut(trigger=Gtk.ShortcutTrigger.parse_string("<Control>w|Escape"),
                                       action=Gtk.NamedAction.new("window.close")))
        self.add_controller(keys)
        if self.HAS_MENU:
            self._build_main_menu()

    def _open_settings(self, *args):
        from ui_settings import SettingsWindow  # imported late: ui_settings imports this module for BaseWindow
        SettingsWindow(self.get_application()).present()

    def _build_main_menu(self):
        """Rightmost header button; windows that add buttons later put them to its left."""
        menu = Gio.Menu()
        menu.append(_("Settings"), "win.settings")
        menu.append(_("About HashTally"), "win.about")
        self.on_action("settings", self._open_settings)
        self.on_action("about", self._about)
        self.header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, primary=True,
                                            tooltip_text=_("Main menu")))

    def on_action(self, name, handler):
        """Call `handler` for the menu entry "win.<name>"."""
        action = Gio.SimpleAction.new(name)
        action.connect("activate", handler)
        self.add_action(action)

    def _about(self, *args):
        dialog = Adw.AboutDialog(application_name="HashTally", application_icon=APP_ID, version=core.__version__,
                                 developer_name=core.AUTHOR, developers=[core.AUTHOR], copyright=core.COPYRIGHT,
                                 license_type=Gtk.License.GPL_3_0, comments=core.about_text())
        dialog.present(self)
        import ui_about  # imported late: nothing of it runs unless the About dialog is opened
        import ui_about_art
        ui_about.attach(dialog, ui_about_art.SCENES)

    def show_page(self, name, widget):
        self.stack.add_named(widget, name)
        self.stack.set_visible_child_name(name)

    def cancel(self, *args):
        if self.job:
            self.job.cancel.set()

    def _copy(self, text):
        self.copied = text  # kept in the window too: the config may not be writable
        core.set_option("copied", text)  # and on disk: a later window, even of another process, must not mistake it for a website's hash
        self.get_clipboard().set_content(Gdk.ContentProvider.new_for_value(text))
        self.toasts.add_toast(Adw.Toast(title=_("Copied"), timeout=1))

    def _on_close(self, *args):
        self.cancel()
        return False
