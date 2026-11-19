# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""Terminal mode: the same work as the windows, answered as text. No GTK is imported here.

hashtally.py picks this module when it is started from a terminal. The look follows install.sh: a banner, then one
line per step with [✓] [✗] [!] [i] in front, no colours (a state is a symbol and a word, so it survives a log, a
screen reader and a copy into a bug report). Exit codes: 0 all fine, 1 a mismatch, an error or a forged signature,
2 the command could not run (bad arguments, unreadable file).

shortcut: the labels of the tables (expected, found, MISMATCH, ...) are English in every language, as in sha256sum and
git; the sentences the windows say too come from the translations. Upgrade if somebody asks for more.
"""
import os
import shutil
import sys
import time

import core
from i18n import _

OK, FAILED, USAGE = 0, 1, 2
TICK, CROSS, WARN, INFO = "[✓]", "[✗]", "[!]", "[i]"
BANNER = r"""
   _   _           _   _____     _ _
  | | | | __ _ ___| |_|_   _|_ _| | |_   _
  | |_| |/ _` / __| '_ \| |/ _` | | | | | |
  |  _  | (_| \__ \ | | | | (_| | | | |_| |
  |_| |_|\__,_|___/_| |_|_|\__,_|_|_|\__, |
                                     |___/
"""
TAGLINE = "Checksums for Nautilus  ·  GPL-3.0-or-later"


# --------------------------------------------------------------------------- small helpers

def _width():
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))


def _line(text="", marker=None, indent=2):
    """One line of output: an optional marker, then the text."""
    print(" " * indent + (f"{marker} " if marker else "") + text)


def _rule():
    print("  " + "─" * (_width() - 4))


def _banner(quiet):
    if not quiet:
        print(BANNER + f"  {TAGLINE}\n")


def _cut(text, n):
    """`text` in at most n characters: the ends stay, the middle goes (a name's extension matters)."""
    if len(text) <= n:
        return text
    keep = n - 1
    return text[:keep - keep // 3] + "…" + text[len(text) - keep // 3:]


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def _duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if hours else f"{minutes} min {seconds} s"


def _speed(total, seconds):
    return f"{core.human_size(total / seconds)}/s" if total and seconds > 0.05 else ""


def _date(epoch):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))


def _fail(text):
    print(f"hashtally: {text}", file=sys.stderr)
    return USAGE


class Progress:
    """A bar on stderr that is redrawn in place:  [=========>          ]  45%  120 MB/s  name.
    Nothing is drawn when stderr is no terminal, so a log stays clean. Used as the progress callback of core."""

    def __init__(self, total):
        self.total, self.done, self.label = total, 0, ""
        self.on = sys.stderr.isatty()
        self.start = self.last = time.monotonic()

    def __call__(self, n):
        self.done += n
        if self.on and (now := time.monotonic()) - self.last > 0.1:
            self.last = now
            self.draw(now)

    def draw(self, now):
        frac = min(self.done / self.total, 1) if self.total else 0
        fill = int(frac * 24)
        bar = "=" * fill + (">" if 0 < fill < 24 else "")
        speed = _speed(self.done, now - self.start)
        text = f"  [{bar:<24}] {int(frac * 100):3d}%  {speed:>10}  {self.label}"
        sys.stderr.write("\r\033[K" + _cut(text, _width() - 1))
        sys.stderr.flush()

    def clear(self):
        if self.on:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

    @property
    def seconds(self):
        return time.monotonic() - self.start


# --------------------------------------------------------------------------- verify

def verify(paths, quiet=False):
    if not paths:
        return _fail(_("No file selected"))
    _banner(quiet)
    code = OK
    for hashfile in paths:
        code = max(code, _verify_signed(hashfile, quiet) if _signed(hashfile) else _verify_one(hashfile, quiet))
    return code


def _signed(path):
    """The file a detached signature belongs to (install.sh.asc -> install.sh); None for anything else."""
    try:
        return core.signed_file(path)
    except OSError:
        return None  # _verify_one reports it


def _verify_signed(sigfile, quiet):
    """A detached signature: its hash list if the file next to it is one, else the signature of that file alone."""
    target = _signed(sigfile)
    if not os.path.isfile(target):
        return _fail(_("The signed file is missing") + f": {target}")
    if core.parse(target):
        return _verify_one(target, quiet)
    _line(f"{os.path.basename(sigfile)}  ·  {os.path.basename(target)}", INFO)
    sig = core.verify_signature([sigfile, target])
    _signature(sig, "file")
    print()
    return OK if sig.status == "good" else FAILED


def _verify_one(hashfile, quiet):
    base, name = os.path.dirname(hashfile), os.path.basename(hashfile)
    try:
        raw = core.read_hashfile(hashfile)
        entries = core.parse(hashfile, raw)
    except OSError as exc:
        return _fail(_("Cannot read file") + f": {exc}")
    if not entries:
        return _fail(_("No checksums found") + f": {hashfile}")
    paths = [core.resolve(base, e.name) if e.algo else None for e in entries]
    sizes = [core.file_size(p) or 0 if p else 0 for p in paths]
    algos = sorted({core.algo_name(e.algo) for e in entries if e.algo})
    _line(f"{name}  ·  {_plural(len(entries), 'file', 'files')} ({core.human_size(sum(sizes))})  ·  {', '.join(algos) or '?'}", INFO)
    _line(core.shown(base or "."), indent=6)
    print()

    sig_args = core.signature_args(hashfile, raw)
    counts = dict.fromkeys(("ok", "missing", "bad", "unknown", "error"), 0)
    width = min(max(len(core.shown(e.name)) for e in entries), 44)
    progress = Progress(sum(sizes))
    for entry, size in zip(entries, sizes):
        progress.label = core.shown(entry.name)
        status, found = core.check(base, entry, progress)
        counts[status] += 1
        progress.clear()
        label = _cut(core.shown(entry.name), width).ljust(width)
        if status == "ok":
            if not quiet:
                _line(f"{label}  OK        {core.human_size(size):>9}", TICK)
        elif status == "missing":
            _line(f"{label}  MISSING", WARN)
        elif status == "bad":
            _line(f"{label}  MISMATCH  {core.human_size(size):>9}", CROSS)
            _line(f"expected  {entry.digest}", indent=8)
            _line(f"found     {found}", indent=8)
        elif status == "unknown":
            _line(f"{label}  UNKNOWN   (not a checksum line, or an algorithm HashTally does not know)", CROSS)
        else:
            _line(f"{label}  ERROR", CROSS)
            _line(core.shown(found), indent=8)
    print()

    sig = core.verify_signature(sig_args, raw) if sig_args else None
    if sig:
        _signature(sig)
    problems = counts["bad"] + counts["unknown"] + counts["error"]
    distrusted = bool(sig and sig.status in ("bad", "revoked"))
    nothing_found = counts["missing"] == len(entries)  # like the window: files the list names but the folder lacks only count when none is there
    _rule()
    parts = [_plural(counts["ok"], "file verified", "files verified")]
    if problems:
        parts.insert(0, _plural(problems, "mismatch" if counts["bad"] == problems else "problem", "mismatches" if counts["bad"] == problems else "problems"))
    if counts["missing"]:
        parts.append(f"{counts['missing']} missing")
    failed = bool(problems or nothing_found or distrusted)
    _line(("FAILED" if failed else "SUCCESS") + "  ·  " + "  ·  ".join(parts), CROSS if failed else (WARN if counts["missing"] else TICK))
    if counts["missing"] and not nothing_found:
        _line("Files the list names but this folder lacks are not a problem as long as others were found.", indent=6)
    if nothing_found:
        _line(_("None of the files were found"), indent=6)
    unlisted = core.unlisted_files(base, entries, hashfile) if core.load_config()["unlisted"] else []  # a hint, no verdict; off by default
    if unlisted:
        _line(f"{_plural(len(unlisted), 'file', 'files')} in the folders of this list, but not in it:", WARN)
        for path in unlisted[:10]:
            _line(core.shown(os.path.relpath(path, base)), indent=8)
        if len(unlisted) > 10:
            _line(f"... and {len(unlisted) - 10} more", indent=8)
    if distrusted:
        _line("Matching a forged list proves nothing: do not trust these results.", indent=6)
    _line(f"{core.human_size(sum(sizes))} in {_duration(progress.seconds)}  ({_speed(sum(sizes), progress.seconds) or '-'})", INFO)
    print()
    return FAILED if failed else OK


def _signature(sig, what="hash file"):
    text = {
        "good": _("Good signature from {signer}").format(signer=core.shown(sig.signer)),
        "nokey": _("Signature not checked: public key missing"),
        "expired": _("Valid signature, but the key has expired"),
        "revoked": _("Valid signature, but the key was revoked"),
        "bad": _("Invalid signature: do not trust this hash file") if what == "hash file" else _("Invalid signature: do not trust this file"),
        "error": _("Signature could not be checked"),
    }[sig.status]
    _line(text, {"good": TICK, "bad": CROSS, "revoked": CROSS}.get(sig.status, WARN))
    if sig.status == "error" and sig.detail:
        _line(sig.detail, indent=6)
    if sig.fingerprint:
        _line(f"fingerprint  {core.format_fingerprint(sig.fingerprint)}", indent=6)
    if sig.key and sig.status != "error":
        _line(f"key id       {sig.key}", indent=6)
    if sig.expires:
        _line(f"key expires  {_date(sig.expires)[:10]}", indent=6)
    elif sig.expires == 0:
        _line("key expires  never", indent=6)
    print()


# --------------------------------------------------------------------------- create

def create(paths, algo, out, force, quiet=False, update=False, prune=False):
    if not paths:
        return _fail(_("No file selected"))
    algo = algo or core.load_config()["algorithm"]
    try:
        files = core.collect_files(paths)
    except OSError as exc:
        return _fail(str(exc))
    if not files:
        return _fail(_("No file selected"))
    base, name = core.default_target(paths, algo)
    out = out or os.path.join(base, name)
    exists = os.path.lexists(out)
    if exists and not (force or update):
        return _fail(f"{out} already exists (use --update to add to it, or --force to replace it)")
    if out != os.path.join(base, name):
        base = os.path.dirname(os.path.abspath(out))  # names in the file are relative to where it lies
    plan = core.plan_update(files, base, out) if update and exists else None
    if update and exists and not force and plan is None:
        return _fail(f"{out} cannot be updated: it is a link, signed, or not a plain list of one algorithm (use --force to replace it)")
    if plan:
        algo = plan.algo  # the file keeps its algorithm
    total = sum(core.file_size(f) or 0 for f, _key in plan.todo) if plan else core.total_size(files)
    _banner(quiet)
    _line(f"{os.path.basename(out)}  ·  {_plural(len(files), 'file', 'files')} ({core.human_size(total)})  ·  {core.ALGOS[algo]}", INFO)
    _line(core.shown(os.path.dirname(os.path.abspath(out))), indent=6)
    print()
    progress = Progress(total)
    progress.label = _("Calculating hashes …")
    try:
        count = core.write_update(plan, base, out, prune, progress) if plan else core.write_hashfile(files, base, algo, out, progress)
    except OSError as exc:
        progress.clear()
        return _fail(str(exc))
    progress.clear()
    if not quiet and not plan:
        width = min(max(len(core.shown(e.name)) for e in core.parse(out)), 44)
        for entry in core.parse(out):
            digest = entry.digest if len(entry.digest) <= 24 else f"{entry.digest[:10]}…{entry.digest[-10:]}"
            _line(f"{_cut(core.shown(entry.name), width).ljust(width)}  {digest}", TICK)
        print()
    _rule()
    _line(f"SUCCESS  ·  {'updated' if plan else 'wrote'} {os.path.basename(out)} with {_plural(count, 'checksum', 'checksums')}", TICK)
    if plan:
        _line(core.update_text(plan, prune), INFO)
    _line(f"{core.human_size(total)} in {_duration(progress.seconds)}  ({_speed(total, progress.seconds) or '-'})", INFO)
    print()
    return OK


# --------------------------------------------------------------------------- compare

def compare_files(a, b, quiet=False):
    """Two files: identical or not, by SHA-256 (files of different sizes are not read)."""
    _banner(quiet)
    for path in (a, b):
        _line(f"{os.path.basename(path)}  ·  {core.human_size(os.path.getsize(path))}  ·  modified {_date(os.path.getmtime(path))}", INFO)
        _line(core.shown(os.path.dirname(path)), indent=6)
    print()
    progress = Progress(os.path.getsize(a) + os.path.getsize(b))
    progress.label = _("Calculating hashes …")
    try:
        same, da, db = core.compare_files(a, b, progress)
    except OSError as exc:
        progress.clear()
        return _fail(str(exc))
    progress.clear()
    for digest in (da, db):
        if digest:
            _line(f"{core.ALGOS['sha256']:<12}{digest}", indent=4)
    print()
    _rule()
    if same:
        _line(_("Files are identical"), TICK)
    else:
        _line(_("Files differ") + ("" if da else "  ·  " + _("The files have different sizes")), CROSS)
    print()
    return OK if same else FAILED


def compare_two(args, quiet=False):
    """Exactly two files: are they identical?"""
    if len(args) != 2 or not all(os.path.isfile(a) for a in args):
        return _fail(_("Please name exactly two files"))
    return compare_files(*map(os.path.abspath, args), quiet)


def compare(args, quiet=False):
    """FILE: print its hashes (and what a hash file next to it lists). FILE HASH: say whether HASH is one of them.
    FILE FILE: say whether the two are identical. `args` are as typed: the second one is a hash or a file."""
    if len(args) == 2 and os.path.isfile(args[0]) and os.path.isfile(args[1]):
        return compare_files(*map(os.path.abspath, args), quiet)
    paths = [os.path.abspath(args[0])] + args[1:] if args else []
    if not paths or len(paths) > 2 or not os.path.isfile(paths[0]):
        return _fail(_("Please select one or two files"))
    path = paths[0]
    algos = core.compare_algos()
    extra = ["blake2b"] if "sha512" in algos else []  # a pasted b2sum is as long as a SHA-512
    size = os.path.getsize(path)
    _banner(quiet)
    _line(f"{os.path.basename(path)}  ·  {core.human_size(size)}  ·  modified {_date(os.path.getmtime(path))}", INFO)
    _line(core.shown(os.path.dirname(path)), indent=6)
    print()
    progress = Progress(size)
    progress.label = os.path.basename(path)
    try:
        digests = core.hash_file(path, [*algos, *extra], progress)
    except OSError as exc:
        progress.clear()
        return _fail(str(exc))
    progress.clear()

    listed = core.expected_hash(path, algos) if len(paths) == 1 else None  # what a hash file next to it says
    wanted = core.norm_hash(paths[1]) if len(paths) == 2 else (listed[0] if listed else "")
    hits = [a for a, d in digests.items() if d == wanted] if wanted else []
    for algo in algos:
        mark = "  <== matches" if algo in hits else ""
        _line(f"{core.ALGOS[algo]:<12}{digests[algo]}{mark}", indent=4)
    print()
    _rule()
    if not wanted:
        _line(_("Show or compare hash") + f": hashtally --compare {os.path.basename(path)} HASH", INFO)
        print()
        return OK
    if listed and len(paths) == 1:
        _line(f"{core.shown(listed[1])} lists this file", INFO)
    if hits:
        _line(_("{algo} matches").format(algo=core.ALGOS.get(hits[0]) or core.algo_name(hits[0])), TICK)
    else:
        _line(_("No match"), CROSS)
        _line(f"compared with  {wanted}", indent=6)
    print()
    return OK if hits else FAILED
