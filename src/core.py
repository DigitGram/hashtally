# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""HashTally core: everything except the windows.

Sections below: hashing, reading hash files, checking their GPG signature, creating hash files,
comparing pasted hashes, settings, and the Nautilus right-click scripts. Nothing here imports GTK, so it is easy to test.
"""
import contextlib
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import zlib
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from gi.repository import Gio, GLib  # only restarting the file managers needs them: everything else here runs without PyGObject
except ImportError:
    Gio = GLib = None

import i18n
from i18n import N_, _

__version__ = "1.3"
APP_ID = "io.github.digitgram.HashTally"
AUTHOR = "DigitGram"  # shown in the About dialog; also named in the file headers, README and install.sh
COPYRIGHT = f"© 2026 {AUTHOR}"

# Algorithms offered when creating hash files: hashlib name -> label (crc32 comes from zlib, not hashlib).
ALGOS = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5", "crc32": "CRC32 (SFV)"}  # strongest first: the order of every list in the UI
# Hex digest length -> algorithm, for entries that do not name one.
DIGEST_LEN = {8: "crc32", 32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}


# --------------------------------------------------------------------------- hashing

class Cancelled(Exception):
    """Raised from a progress callback when the user aborts."""


def hash_file(path, algos, progress=None):
    """Return {algo: hexdigest} for several algorithms in one read pass.

    `progress(nbytes)` is called per chunk and may raise Cancelled to abort.
    """
    hashers = {a: hashlib.new(a) for a in algos if a != "crc32"}
    want_crc, crc = "crc32" in algos, [0]  # the CRC costs up to a third more time, so only when asked for

    def add_crc(chunk):
        crc[0] = zlib.crc32(chunk, crc[0])
    updates = [h.update for h in hashers.values()] + [add_crc] * want_crc
    # a thread per algorithm: hashlib and zlib let go of the GIL for a chunk this big, so several algorithms take about as long as the slowest, not the sum
    with open(path, "rb") as f, (ThreadPoolExecutor(len(updates)) if len(updates) > 1 else contextlib.nullcontext()) as pool:
        while chunk := f.read(1 << 20):
            if pool:
                list(pool.map(lambda update: update(chunk), updates))  # list(): waits for all, and raises what one raised
            else:
                for update in updates:
                    update(chunk)
            if progress:
                progress(len(chunk))
    digests = {a: h.hexdigest() for a, h in hashers.items()}
    if want_crc:
        digests["crc32"] = f"{crc[0]:08x}"
    return digests


SECURE = ("sha512", "sha256")  # the algorithms that hold against deliberate changes; CRC32 only finds accidents, MD5 and SHA-1 are broken


def hash_speeds(seconds=0.2):
    """{algorithm: bytes per second} of every algorithm offered for creating hash files, on this machine: one core, from memory (no disk involved).
    Only a guide: a drive is often slower, and a hash file for several algorithms hashes them side by side."""
    block, speeds = os.urandom(1 << 20), {}
    for algo in ALGOS:
        if algo == "crc32":
            crc = [0]
            update = lambda data: crc.__setitem__(0, zlib.crc32(data, crc[0]))  # noqa: E731
        else:
            update = hashlib.new(algo).update
        update(block)  # warm up: the first call pays for the set-up
        done, start = 0, time.perf_counter()
        while (spent := time.perf_counter() - start) < seconds:
            update(block)
            done += len(block)
        speeds[algo] = done / spent
    return speeds


def speed_advice(speeds):
    """(the fastest secure algorithm, the fastest one overall if that is not a secure one else None) from `hash_speeds`."""
    best = max(SECURE, key=speeds.get)
    fastest = max(speeds, key=speeds.get)
    return best, (None if fastest in SECURE else fastest)


# --------------------------------------------------------------------------- reading hash files

Entry = namedtuple("Entry", "algo digest name")  # algo is None if the digest length is unknown

_BSD = re.compile(r"^(MD5|SHA(?:1|224|256|384|512)|BLAKE2b)\s*\((.+)\)\s*=\s*([0-9a-f]+)$", re.I)  # SHA256 (file) = hash
_GNU = re.compile(r"^\\?([0-9a-f]{32,128}) [ *](.+)$", re.I)                              # hash  file
_BARE = re.compile(r"^[0-9a-f]{32,128}$", re.I)                                           # hash only
_CRC = re.compile(r"[0-9a-f]{8}", re.I)  # SFV "file crc32": split with rsplit, a regex over the whole line is quadratic
_PGP_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----"
MAX_HASHFILE = 16 << 20  # bytes; a SHA256SUMS for a whole distribution is far below this


def _signed_lines(lines):
    """The part of a clear-signed file that gpg verified: after the armor headers, before the signature,
    with the dash escaping ("- -x" for "-x") undone. Anything outside it is not covered by the signature."""
    start = next((i + 1 for i, line in enumerate(lines) if not line.strip(" \t\r")), len(lines))  # gpg also ends the armor headers at a line of blanks
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("-----")), len(lines))  # gpg ends the signed text at any line of five dashes, whatever follows
    return [line[2:] if line.startswith("- ") else line for line in lines[start:end]]


def _algo_of(path, digest):
    """The digest length names the algorithm, except where lengths clash: b2sum (BLAKE2b) is as long as SHA-512,
    SHA-3 as SHA-2. There the hash file's name decides, and a clash it cannot settle stays unknown instead of
    being checked with a wrong algorithm."""
    name = os.path.basename(path).lower()
    if "sha3" in name or "b3sum" in name:
        return None
    if "b2sum" in name or "blake2" in name:
        return "blake2b" if len(digest) == 128 else None
    return DIGEST_LEN.get(len(digest))


def _entry_of(path, line, is_sfv):
    """The Entry for one line of the hash file at `path` (blank lines and comments are dealt with by the caller)."""
    if m := _BSD.match(line):
        return Entry(m[1].lower(), m[3].lower(), m[2])
    if is_sfv and len(parts := line.rsplit(None, 1)) == 2 and _CRC.fullmatch(parts[1]):
        return Entry("crc32", parts[1].lower(), parts[0])
    if m := _GNU.match(line):
        name = m[2]
        if line[0] == "\\":  # GNU escapes backslash, newline and carriage return in names
            name = re.sub(r"\\(.)", lambda e: {"n": "\n", "r": "\r"}.get(e[1], e[1]), name)
        return Entry(_algo_of(path, m[1]), m[1].lower(), name)
    if _BARE.match(line) and Path(path).suffix:  # "file.iso.sha256" containing just the digest; without
        return Entry(_algo_of(path, line), line.lower(), Path(path).stem)  # suffix the stem is the file itself
    return Entry(None, "", line)


def read_hashfile(path):
    """The bytes of a hash file; b"" for anything that cannot be one."""
    # shortcut: anything bigger is no hash file (a 4 GB ISO selected by mistake would freeze the window and
    # fill the memory); raise MAX_HASHFILE if a real hash file ever gets that large. getsize comes first so a
    # missing file still raises; a pipe or device reports size 0 and would block forever.
    if os.path.getsize(path) > MAX_HASHFILE or not os.path.isfile(path):
        return b""
    return Path(path).read_bytes()


def parse(path, raw=None):
    """Read a hash file (GNU, BSD, SFV or bare digest) into a list of Entry. A line that is none of these
    comes back as an Entry without algorithm, so it is shown instead of vanishing; a file without a single
    hash is not a hash file and gives an empty list. `raw`: its bytes, if the caller read them already."""
    raw = read_hashfile(path) if raw is None else raw
    if not raw:
        return []
    try:
        text = raw.decode("utf-8-sig")  # also strips the BOM Windows tools write
    except UnicodeDecodeError:  # shortcut: a file with a name that is no UTF-8 is read as Latin-1 as a whole, so that name is not found; upgrade when it matters
        text = raw.decode("latin-1")
    is_sfv = str(path).lower().endswith((".sfv", ".crc"))
    lines = re.split(r"\r?\n", text)  # not splitlines(): it also cuts at U+2028, \x0b and \x85 inside names
    if raw.startswith(_PGP_HEADER.encode()):  # gpg reads the raw bytes: after a BOM the armor is not on line 1, and it checks a later block
        if lines[0].rstrip(" \t\r") != _PGP_HEADER:  # gpg skips such a line and checks a later block instead
            return []
        lines = _signed_lines(lines)
    entries = [_entry_of(path, line, is_sfv) for line in map(str.strip, lines) if line and line[0] not in ";#"]
    return entries if any(e.digest for e in entries) else []


def resolve(base, name):
    """Find `name` next to the hash file; also accepts Windows-style backslash paths."""
    for candidate in (name, name.replace("\\", "/")):
        path = os.path.join(base, candidate)
        if os.path.isfile(path):
            return path
    return None


_HASHFILE_NAME = re.compile(r"sums|sum\.txt$|\.(?:sha\d+|md5|sfv)(?:sum)?$")  # SHA256SUMS, b2sums.txt, sha256sum.txt (Linux Mint), ubuntu.sha256, ...


def expected_hash(path, algos):
    """(digest, hash file name) that a hash file next to `path` lists for it, or None. Only algorithms in `algos`
    count: the compare window could not tell a match from a miss for any other (a BLAKE2b digest is as long as SHA-512).
    With several, the first algorithm in `algos` wins: SHA256SUMS before MD5SUMS.
    shortcut: the signature is not checked here, and a hash file that came with the download proves little; upgrade if that bites."""
    folder, name = os.path.split(path)
    try:
        others = sorted(os.listdir(folder))
    except OSError:
        return None
    found = {}
    for other in [o for o in others if o.lower().startswith(name.lower() + ".") or _HASHFILE_NAME.search(o.lower())][:50]:
        try:
            entries = parse(os.path.join(folder, other))
        except OSError:
            continue
        for e in entries:
            if e.algo in algos and os.path.normpath(e.name.replace("\\", "/")) == name:
                found.setdefault(e.algo, (e.digest, other))
    return next((found[a] for a in algos if a in found), None)


def check(base, entry, progress=None):
    """Verify one entry. Returns (status, found): ok / bad / missing / unknown / error."""
    if entry.algo is None:
        return "unknown", None
    path = resolve(base, entry.name)
    if path is None:
        return "missing", None
    try:
        found = hash_file(path, [entry.algo], progress)[entry.algo]
    except OSError as exc:
        return "error", str(exc)
    return ("ok" if found == entry.digest else "bad"), found


def algo_name(algo):
    """Display name, the same everywhere: sha256 -> SHA-256, md5 -> MD5; "?" if there is none."""
    return "BLAKE2b" if algo == "blake2b" else re.sub(r"^SHA(?=\d)", "SHA-", (algo or "?").upper())


# --------------------------------------------------------------------------- signature (GPG)

SIG_SUFFIXES = (".gpg", ".sig", ".asc", ".sign")  # detached signatures as published by Ubuntu, Arch, Debian, ...
# gpg status keyword -> verdict. ERRSIG means "could not check": missing key or a real error (see below).
_VERDICT = {"GOODSIG": "good", "EXPSIG": "expired", "EXPKEYSIG": "expired", "REVKEYSIG": "revoked",
            "BADSIG": "bad", "ERRSIG": "nokey"}
# status: good | expired | revoked | bad | nokey | error; `detail` carries gpg's own message for "error".
# expires: when the signing key expires (epoch seconds), 0 for never, None when unknown (no key in the keyring).
Signature = namedtuple("Signature", "status key signer fingerprint detail expires", defaults=("", "", "", "", None))


def split_user_id(user_id):
    """(name, comment, email) of a user ID such as "Jane Doe (work) <jane@example.org>"; what does not fit is the name."""
    m = re.fullmatch(r"(.*?)(?: \(([^()]*)\))?(?: <([^<>]*)>)?", user_id.strip())
    return (m.group(1), m.group(2) or "", m.group(3) or "") if m else (user_id, "", "")


def key_expiry(fingerprint):
    """When the key with this fingerprint expires: epoch seconds, 0 for never, None if gpg does not know it."""
    if not re.fullmatch(r"[0-9A-Fa-f]{40,64}", fingerprint or ""):
        return None
    try:
        run = subprocess.run(["gpg", "--batch", "--no-tty", "--with-colons", "--list-keys", fingerprint], capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in run.stdout.decode("utf-8", "replace").split("\n"):
        fields = line.split(":")
        if fields[0] == "pub" and len(fields) > 6:
            return int(fields[6]) if fields[6].isdigit() else 0
    return None


KEYSERVER = "hkps://keyserver.ubuntu.com"


def import_key(fingerprint):
    """Fetch the key with this full fingerprint from the keyserver into the user's keyring. Returns "" or gpg's message.
    Only a full fingerprint: gpg then checks that the key it gets is that key, which it cannot for a short key ID."""
    if not re.fullmatch(r"[0-9A-Fa-f]{40,64}", fingerprint or ""):
        return _("No full fingerprint to fetch the key by")
    try:
        run = subprocess.run(["gpg", "--batch", "--no-tty", "--keyserver", KEYSERVER, "--recv-keys", fingerprint], capture_output=True, timeout=60)
    except FileNotFoundError:
        return _("gpg is not installed")
    except subprocess.TimeoutExpired:
        return _("The keyserver did not answer in time")
    if run.returncode:
        return next((m for m in run.stderr.decode("utf-8", "replace").splitlines() if m.strip()), f"gpg exit code {run.returncode}")
    return ""


def signature_args(path, raw=None):
    """gpg arguments that check `path`, or None if it is unsigned: either a detached signature lies
    next to it (SHA256SUMS + SHA256SUMS.gpg) or the file itself is clear-signed. `raw`: its bytes as parse() read them."""
    for suffix in SIG_SUFFIXES:
        if os.path.isfile(path + suffix):
            return [path + suffix, path]
    raw = read_hashfile(path) if raw is None else raw  # not the file again: gpg skips any text in front of the armor
    return [path] if raw.startswith(_PGP_HEADER.encode()) else None  # gpg does not skip a BOM either; parse() agrees


def signed_file(path, raw=None):
    """The file a detached signature (install.sh.asc, SHA256SUMS.gpg ...) belongs to, as a path next to it; it need not
    exist. None if `path` is no such signature, or lists checksums itself (a clear-signed hash file named .asc)."""
    target, suffix = os.path.splitext(path)
    if suffix.lower() not in SIG_SUFFIXES or parse(path, raw):
        return None
    return target


def _first_signature(status):
    """(verdict, key, signer, fingerprint) of the first signature in gpg's `--status-fd` output; the verdict is None if there is none."""
    verdict, key, signer, fingerprint, key_missing = None, "", "", "", False
    for line in status.split("\n"):  # not splitlines(): it also cuts at U+2028 or U+0085, which gpg leaves in a user ID
        if not line.startswith("[GNUPG:] "):
            continue
        word, _sep, rest = line[9:].partition(" ")
        if word in _VERDICT and verdict is None:
            verdict = _VERDICT[word]
            key, _sep, signer = rest.partition(" ")
            if word == "ERRSIG":  # no user name here; numbers follow, and the signing key's fingerprint last
                fields = rest.split()
                signer = ""
                fingerprint = fields[-1] if len(fields) > 6 and fields[-1] != "-" else ""  # "-": the signature names no fingerprint
        elif word == "VALIDSIG" and not fingerprint:
            fields = rest.split()  # the last field is the primary key, the one publishers print
            fingerprint = fields[9] if len(fields) > 9 else fields[0]
        elif word == "NO_PUBKEY":
            key_missing = True
    if verdict == "nokey" and not key_missing:
        verdict = None  # some other gpg failure
    signer = "".join(c for c in signer if c.isprintable())  # gpg masks ASCII controls only, not Bidi overrides, line separators or C1 controls
    return verdict, key, signer, fingerprint


def verify_signature(args, data=None):
    """Run `gpg --verify` and boil its machine-readable status lines down to one Signature. With `data` (the hash
    file's bytes as parse() read them) gpg checks those from stdin, not the file again, which may have changed since.

    This only reports what gpg says: it never imports keys. A key is fetched only by import_key, on the user's say.
    shortcut: only the first signature is reported; files with several signatures are rare, upgrade
    when someone needs it. A hung gpg raises subprocess.TimeoutExpired, which the caller shows.
    """
    try:
        # a gpg.conf with auto-key-retrieve would fetch keys from a keyserver, one with auto-key-import would take the key a signature carries
        run = subprocess.run(["gpg", "--batch", "--no-tty", "--no-auto-key-retrieve", "--no-auto-key-import", "--status-fd", "1",
                              "--verify", *(args if data is None else [*args[:-1], "-"])],
                             input=data, capture_output=True, timeout=60)
    except FileNotFoundError:
        return Signature("error", detail=_("gpg is not installed"))
    status, errors = run.stdout.decode("utf-8", "replace"), run.stderr.decode("utf-8", "replace")
    verdict, key, signer, fingerprint = _first_signature(status)
    if verdict in ("good", "expired", "revoked") and run.returncode:  # gpg can print GOODSIG for a file it then rejects (bad armor, several plaintexts): its exit code decides
        verdict = "bad" if re.search(r"^\[GNUPG:\] (BADSIG|TRUST_NEVER)\b", status, re.M) else None  # a later bad signature, or a key the user distrusts
    if verdict is None:
        message = next((m for m in errors.splitlines() if m.strip()), f"gpg exit code {run.returncode}")
        return Signature("error", detail=message)
    return Signature(verdict, key, signer, fingerprint, "", key_expiry(fingerprint) if verdict in ("good", "expired", "revoked") else None)


def format_fingerprint(fingerprint):
    """Groups of four characters, the way publishers print them, so that it is easy to compare."""
    return " ".join(fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4))


# --------------------------------------------------------------------------- creating hash files

def _raise(error):
    """os.walk skips folders it cannot read unless its onerror callback raises."""
    raise error


def collect_files(paths):
    """Expand directories recursively; keep plain files (broken symlinks are skipped).
    Raises OSError for a folder that cannot be read or a link to a folder, so a hash file is never
    silently incomplete."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p, onerror=_raise):
                dirs.sort()  # os.walk honours in-place sorting, so the output order is stable
                for name in dirs:  # os.walk lists a link to a folder here but never enters it
                    if os.path.islink(link := os.path.join(root, name)):
                        raise OSError(f"{link}: link to a folder, not followed")
                for name in sorted(names):
                    path = os.path.join(root, name)
                    if os.path.isfile(path):
                        files.append(path)
        elif os.path.isfile(p):
            files.append(p)
    return files


def total_size(files):
    """Sum of the file sizes in bytes; used to scale the progress bar."""
    return sum(file_size(f) or 0 for f in files)  # a file that vanished meanwhile fails later, in the job


def default_target(paths, algo):
    """Directory and name for the new hash file: `<name>.sha256` for one item, else SHA256SUMS."""
    ext = "sfv" if algo == "crc32" else algo
    if len(paths) == 1:
        path = paths[0].rstrip("/")
        return os.path.dirname(path), f"{os.path.basename(path)}.{ext}"
    return os.path.dirname(paths[0]), "checksums.sfv" if algo == "crc32" else f"{algo.upper()}SUMS"


def shown(text):
    """Text for a label: file names need not be valid UTF-8, but GTK only takes text that is."""
    return os.fsencode(text).decode("utf-8", "replace")


def write_atomic(path, text):
    """Replace `path` with `text` all at once, so a crash never leaves half a file. A link stays a link
    and an existing file keeps its mode."""
    path = os.path.realpath(path)  # the rename would replace a link itself
    part = f"{path}.part"
    try:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(part)  # a stale part or a planted link: never write through it
        with open(part, "x", encoding="utf-8", errors="surrogateescape") as f:  # a name that is no UTF-8 goes in byte for byte
            f.write(text)
        with contextlib.suppress(FileNotFoundError):  # a new file keeps the default mode; an old one its own
            shutil.copymode(path, part)
        os.replace(part, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(part)
        raise


def _line(algo, rel, digest):
    """One line of a hash file: SFV for CRC32, else GNU style ("hash  name") with the escaping GNU uses for odd names."""
    if algo == "crc32":
        return f"{rel} {digest}"
    if re.search(r"[\\\n\r]", rel):  # GNU escaping, flagged by a leading backslash
        return f"\\{digest}  " + rel.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
    return f"{digest}  {rel}"


def _store(algo, lines, out):
    """Write the hash file `out` from its lines (an SFV gets its header); a link at `out` is replaced, never written through:
    a SHA256SUMS planted as a link to ~/.bashrc would cost that file."""
    # shortcut: SFV has no escaping, so a name with a line break, or starting with ";" or "#", cannot be
    # written back faithfully (GNU/BSD lines are escaped), and parse() trims blanks at the end of a line, so
    # no format keeps a name that ends in whitespace; upgrade if such names ever show up.
    if algo == "crc32":
        lines = ["; Created by HashTally", *lines]
    if os.path.islink(out):
        os.unlink(out)
    write_atomic(out, "\n".join(lines) + "\n")  # a failure never destroys an existing hash file


def write_hashfile(files, base, algo, out, progress=None):
    """Write one line per file (paths relative to `base`); returns the number of files."""
    files = [f for f in files if os.path.abspath(f) != os.path.abspath(out)]
    lines = [_line(algo, os.path.relpath(f, base), hash_file(f, [algo], progress)[algo]) for f in files]
    _store(algo, lines, out)
    return len(files)


# An existing hash file that gets only what changed: `algo`, its `entries` (as Entry, in file order), `todo` (the files
# to hash, as (path, key) where key names the entry), and the counts shown to the user.
Update = namedtuple("Update", "algo entries todo added changed unchanged gone stamp")  # stamp: when the plan was made, the new date of the hash file


def _key(name, base=None):
    """A file name as the list and the folder spell it alike: "a\\b" and "./a/b" are one file. With `base`, an
    absolute name or one with ".." reads relative to it too, as os.path.relpath(file, base) does."""
    name = os.path.normpath(name.replace("\\", "/"))
    return name if base is None else os.path.relpath(os.path.join(base, name), base)


def plan_update(files, base, out):
    """What updating the hash file `out` with `files` would do, or None if it cannot be updated: it is a link, clear-signed,
    holds lines that are not checksums or more than one algorithm. A file is hashed when no entry names it or when it is newer than the
    hash file; every other entry stays as it is. shortcut: the hash file keeps no dates, so its own date is the cut-off: a
    copy of it made later hides an edit from before the copy. Upgrade if that bites."""
    stamp = time.time_ns()
    try:
        if os.path.islink(out) or any(os.path.lexists(out + s) for s in SIG_SUFFIXES):  # a signature would not fit the new file
            return None
        raw = read_hashfile(out)
        entries = parse(out, raw)
        cutoff = os.stat(out).st_mtime_ns
        raw.decode("utf-8-sig")  # a name that is no UTF-8 was read as Latin-1: writing it back would garble every such name
    except (OSError, UnicodeDecodeError):
        return None
    algos = {e.algo for e in entries}
    if not entries or len(algos) != 1 or None in algos or algos - set(ALGOS) or raw.startswith(_PGP_HEADER.encode()):
        return None
    if any(not e.digest for e in entries):
        return None
    listed = {_key(e.name, base) for e in entries}
    todo, added, changed, unchanged = [], 0, 0, 0
    seen = set()
    for f in files:
        if os.path.abspath(f) == os.path.abspath(out):
            continue
        key = _key(os.path.relpath(f, base))
        if key in seen:
            continue
        seen.add(key)
        if key not in listed:
            todo.append((f, key))
            added += 1
            continue
        try:
            newer = os.stat(f).st_mtime_ns > cutoff
        except OSError:
            newer = True  # unreadable now: the job says why
        if newer:
            todo.append((f, key))
            changed += 1
        else:
            unchanged += 1
    gone = sum(1 for e in entries if resolve(base, e.name) is None)
    return Update(next(iter(algos)), entries, todo, added, changed, unchanged, gone, stamp)


def write_update(plan, base, out, drop_gone, progress=None):
    """Hash what `plan` lists and write the hash file again: old entries as they were (a changed file gets its new hash),
    new ones at the end. With `drop_gone` the entries of files that no longer exist are left out. Returns the number of entries."""
    digests = {key: hash_file(f, [plan.algo], progress)[plan.algo] for f, key in plan.todo}
    lines, kept = [], set()
    for e in plan.entries:
        key = _key(e.name, base)
        if drop_gone and resolve(base, e.name) is None:
            continue
        kept.add(key)
        lines.append(_line(plan.algo, e.name, digests.get(key, e.digest)))
    for f, key in plan.todo:
        if key not in kept:
            lines.append(_line(plan.algo, os.path.relpath(f, base), digests[key]))
            kept.add(key)
    if not plan.todo and len(lines) == len(plan.entries):  # nothing to add, change or drop: the file stays as it is
        return len(lines)
    _store(plan.algo, lines, out)
    with contextlib.suppress(OSError):  # a file edited from the plan on is newer than the list and hashed next time
        os.utime(out, ns=(plan.stamp, plan.stamp))
    return len(lines)


def update_text(plan, prune=False):
    """The counts of an update, one line: "Added: 1 · Changed: 2 · Unchanged: 3" (+ the deleted files' entries)."""
    parts = [_("Added: {n}").format(n=plan.added), _("Changed: {n}").format(n=plan.changed), _("Unchanged: {n}").format(n=plan.unchanged)]
    if plan.gone:
        parts.append((_("Removed: {n}") if prune else _("Missing: {n}")).format(n=plan.gone))
    return " · ".join(parts)


# --------------------------------------------------------------------------- unlisted files

def unlisted_files(base, entries, hashfile):
    """Files in the folders a hash file covers that it does not list, sorted: the files next to it if it lists any,
    and everything below each top-level folder it lists a file in. Other hash files and signatures are no news.
    Empty for a list of one file: that is a download's checksum, and its folder holds other things. Not followed: links to folders."""
    names = [_key(e.name, base) for e in entries]
    if len(names) < 2:
        return []
    try:
        read_hashfile(hashfile).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError):  # names read as Latin-1 would not match the folder: every such file would show as unlisted
        return []
    listed = set(names)
    roots = {n.split(os.sep)[0] for n in names if os.sep in n} - {os.pardir}  # a list that names "../x" does not make the parent folder its business
    skip = {os.path.abspath(hashfile), *(os.path.abspath(hashfile + s) for s in SIG_SUFFIXES)}
    found = []

    def add(path):
        name = os.path.basename(path)
        if os.path.abspath(path) not in skip and _key(os.path.relpath(path, base)) not in listed \
                and not _HASHFILE_NAME.search(name.lower()) and not name.endswith(".part"):
            found.append(path)
    if any(os.sep not in n for n in names):
        with contextlib.suppress(OSError):
            for entry in os.scandir(base):
                if entry.is_file():
                    add(entry.path)
    for top in sorted(roots):
        for root, _dirs, files in os.walk(os.path.join(base, top)):  # an unreadable folder is skipped: this is a hint, not a verdict
            for name in files:
                if os.path.isfile(path := os.path.join(root, name)):
                    add(path)
    return sorted(found)


# --------------------------------------------------------------------------- comparing two files

def compare_files(a, b, progress=None):
    """(same, digest of a, digest of b), by SHA-256. Files of different sizes differ without being read: no digests then."""
    if os.path.getsize(a) != os.path.getsize(b):
        return False, None, None
    da, db = (hash_file(p, ["sha256"], progress)["sha256"] for p in (a, b))
    return da == db, da, db


# --------------------------------------------------------------------------- comparing

def norm_hash(text):
    """Normalise a pasted hash: drop whitespace and a leading 'sha256:' style prefix. A whole line copied
    from a hash file ("<hash>  name" or "SHA256 (name) = <hash>") yields its hash."""
    digest = re.sub(r"\s+", "", text).lower()
    digest = re.sub(r"^(md5|sha\d+|crc32)[:=]", "", digest)
    if re.fullmatch(r"[0-9a-f]*", digest):
        return digest
    # shortcut: the first word with a known digest length wins; a hash file line has exactly one
    words = (w for w in text.split() if len(w) in DIGEST_LEN and re.fullmatch(r"[0-9a-fA-F]+", w))
    return next(words, digest).lower()


def is_partial_hash(text, digests=()):
    """True while the text could still grow into a hash: only hex digits, and either not yet a known digest
    length or the start of one of `digests` (a SHA-256 typed by hand passes the MD5 and SHA-1 lengths).
    The compare window stays quiet then instead of calling a half-typed hash a mismatch."""
    digest = norm_hash(text)
    if re.fullmatch(r"[0-9a-f]+", digest) is None:
        return False
    return ((len(digest) < max(DIGEST_LEN) and len(digest) not in DIGEST_LEN)
            or any(len(d) > len(digest) and d.startswith(digest) for d in digests))


def looks_like_digest(text):
    """True if the text is a hex string with a known digest length (used to auto-fill from the clipboard)."""
    digest = norm_hash(text)
    return len(digest) in DIGEST_LEN and re.fullmatch(r"[0-9a-f]+", digest) is not None


def file_size(path):
    """Size in bytes, or None if the file cannot be read."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def human_size(n):
    """Size like "4.2 GB"; the decimal separator comes from the translation. Units of 1000, as Files shows them."""
    for unit in ("B", "kB", "MB", "GB"):
        if round(n, 1) < 1000:  # what is shown decides: 999,950 bytes are "1.0 MB", not "1000.0 kB"
            break
        n /= 1000
    else:
        unit = "TB"
    # TRANSLATORS: decimal separator in file sizes, e.g. "," for German
    separator = _(".")
    return f"{n:.{0 if unit == 'B' else 1}f}".replace(".", separator) + f" {unit}"


# --------------------------------------------------------------------------- settings

CONFIG_FILE = Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser() / "hashtally" / "config.json"
DEFAULTS = {"language": "auto", "algorithm": "sha256", "clipboard": True, "unlisted": False, "compare_algos": list(ALGOS), "menu": "scripts",
            "update_check": False, "update_last": 0,  # weekly check at start: off until the user switches it on
            "integrated": False,  # the .deb creates the right-click entries at the first start (see first_run_entries)
            "copied": ""}  # the last value a window put on the clipboard itself: no window may take it back as "expected"


def allowed():
    """Settings with a fixed set of values: {key: tuple of values}."""
    return {"algorithm": tuple(ALGOS), "menu": ("scripts", "folder"), "language": ("auto", *i18n.languages())}


def load_config():
    """Saved settings merged over DEFAULTS, so a new setting never needs a migration. A value of the wrong
    type or outside allowed() counts as not saved, so a hand-edited file cannot crash a window.
    shortcut: the items of a list setting are not checked, the code that reads them filters."""
    config = dict(DEFAULTS)
    try:
        saved = json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError):  # missing or corrupt file: use defaults
        return config
    if isinstance(saved, dict):
        choices = allowed()
        config.update({k: v for k, v in saved.items()
                       if k in DEFAULTS and type(v) is type(DEFAULTS[k]) and v in choices.get(k, (v,))})
    return config


def set_option(key, value):
    """Persist one setting. Only values that differ from DEFAULTS are written, so a better default later
    reaches everyone who never chose otherwise.

    The right-click entries depend on the language and the menu style, so changing either rebuilds them;
    returns an error text (file not writable, install_scripts()'s), else None.
    """
    saved = {**load_config(), key: value}
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(CONFIG_FILE, json.dumps({k: v for k, v in saved.items() if v != DEFAULTS.get(k)}, indent=2))
    except OSError as e:
        return str(e)
    if key == "language":
        i18n.set_language(value)
    return install_scripts() if key in ("language", "menu") else None


def reset_config():
    """Back to the defaults: forget every saved setting. Like set_option, returns an error text, else None."""
    try:
        if CONFIG_FILE.exists():  # emptied, not deleted: a link into a dotfiles folder stays a link
            write_atomic(CONFIG_FILE, "{}")
    except OSError as e:
        return str(e)
    i18n.set_language("auto")
    return install_scripts()  # the entries follow the language


# --------------------------------------------------------------------------- update check
# Opt-in and never automatic beyond a notice: one GET to GitHub's "latest release", no data sent, nothing downloaded or installed.
# Updating stays "run the signed install.sh again". Not offered in a Flatpak: its store brings the updates.
RELEASES_API = "https://api.github.com/repos/DigitGram/hashtally/releases/latest"
UPDATE_INTERVAL = 7 * 24 * 3600
update_found = None  # (version, page) of a newer release, once one was found: the settings show it at once


PACKAGED = Path(__file__).resolve().is_relative_to("/usr")  # the .deb: the program sits below /usr, not in the user's home


def update_check_offered():
    return not os.path.exists("/.flatpak-info")


def version_tuple(text):
    """"v1.2.1" -> (1, 2, 1); None if it does not look like a version."""
    parts = re.fullmatch(r"v?(\d+(?:\.\d+)*)", text.strip())
    return tuple(int(n) for n in parts[1].split(".")) if parts else None


def latest_release(timeout=5):
    """(version, page) of the newest release, or raises OSError/ValueError (offline, rate limit, odd answer)."""
    import urllib.request
    request = urllib.request.Request(RELEASES_API, headers={"Accept": "application/vnd.github+json", "User-Agent": f"HashTally/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as answer:
        data = json.load(answer)
    tag, page = data["tag_name"], data["html_url"]
    if not isinstance(tag, str) or version_tuple(tag) is None or not str(page).startswith("https://github.com/DigitGram/"):
        raise ValueError("unexpected answer")
    return tag.lstrip("v"), page


def newer_release():
    """(version, page) if a newer release exists, else None; raises like latest_release()."""
    version, page = latest_release()
    return (version, page) if version_tuple(version) > version_tuple(__version__) else None


def update_due(now=None):
    """True when the weekly check is switched on and the last one is over a week ago."""
    config = load_config()
    return update_check_offered() and config["update_check"] and (now or time.time()) - config["update_last"] >= UPDATE_INTERVAL


def compare_algos():
    """Algorithms the compare window calculates: those switched on in the settings, never none."""
    chosen = load_config()["compare_algos"]
    return [a for a in ALGOS if a in chosen] or list(ALGOS)


def setting_choices():
    """Settings with a fixed set of values: {key: (title, {value: label}, subtitle)}, in the current language."""
    return {
        "language": (_("Language"), {"auto": _("System default"), **i18n.languages()}, ""),
        "algorithm": (_("Default algorithm"), ALGOS, _("Used when creating a checksum file")),
    }


def about_text():
    """Description for the About dialog: what the tool is, then how it works."""
    return _("Create, verify and compare checksums right from Nautilus. Checks hash files such as SHA256SUMS "
             "together with their GPG signature, or compares a file against a hash you paste in.")


# --------------------------------------------------------------------------- Files (Nautilus) integration
# shortcut: Nautilus scripts instead of a nautilus-python extension, so there is no extra dependency;
# the price is that the entries live under "Scripts", flat or in a "HashTally" submenu (setting "menu"), and that
# Files passes individually selected files in one environment variable (Linux caps it at 128 KiB: about 1,500 files of typical path
# length): beyond that the script silently does not start. A selected folder is not affected.
# Upgrade if users ask for a top-level entry.

DATA = Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser()
SCRIPTS_DIR = DATA / "nautilus/scripts"
# Nemo and Caja are forks of Files with its script mechanism: only the folder differs (TrustCopy uses the same table)
FORKS = {"nemo": DATA / "nemo/scripts",
         "caja": Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser() / "caja/scripts"}
SCRIPT_ACTIONS = {"--create": N_("Create hash file"), "--compare": N_("Show or compare hash"),
                  "--compare-files": N_("Compare files"), "--verify": N_("Verify hash file")}
SCRIPT_PREFIX = "HashTally: "  # keeps our entries together and recognisable in a crowded Scripts menu
MENU_DIR = "HashTally"  # the same entries as a submenu: Nautilus shows script folders as submenus


# Never change this text: older entries are recognised only by this line, so a new wording would orphan them all.
MARKER = "# Written by HashTally from its settings, replaced or deleted whenever they change"
LAUNCHER = Path("/usr/bin/hashtally") if PACKAGED else Path("~/.local/bin/hashtally").expanduser()  # where the .deb or install.sh puts it: a run from a checkout must not bind the menu to itself


def script_text(flag):
    """The content of the entry for the command line flag `flag`."""
    return f'#!/bin/sh\n{MARKER}\nexec {shlex.quote(str(LAUNCHER))} {flag} -- "$@"\n'


def script_path(title, folder, base=None):
    """Where the Scripts entry for `title` lives (in `base`, Files' folder by default); its file name is the menu label."""
    base = base or SCRIPTS_DIR
    return base / MENU_DIR / _(title) if folder else base / (SCRIPT_PREFIX + _(title))


def menu_entries(base=None):
    """Paths of the right-click entries for the current language and menu style (what Files will list)."""
    folder = load_config()["menu"] == "folder"
    return [script_path(title, folder, base) for title in SCRIPT_ACTIONS.values()]


def _ours(path):
    """True for an entry we wrote (its second line is MARKER): only those are removed from the submenu folder."""
    try:
        if not path.is_file():  # a folder, or a FIFO, which would block open()
            return False
        with path.open() as f:
            f.readline(200)  # the shebang
            return f.readline(200).rstrip("\n") == MARKER
    except (OSError, ValueError):  # unreadable, or not text
        return False


def file_managers():
    """The file managers that get right-click entries: Files always, a fork when it is installed."""
    return ["nautilus", *(fm for fm in FORKS if shutil.which(fm))]


def install_scripts(remove_only=False):
    """(Re)create the right-click entries in the current language and menu style, dropping stale ones
    (any language, any style, even from an older translation), for Files and for each fork that is installed.
    Returns an error text, or None on success."""
    try:
        seen = set()
        for fm, base in (("nautilus", SCRIPTS_DIR), *FORKS.items()):
            if base.resolve() in seen:  # linked to another one: a second pass would delete what the first wrote
                continue
            seen.add(base.resolve())
            folder = base / MENU_DIR
            for old in [*base.glob(SCRIPT_PREFIX + "*"), *(p for p in folder.glob("*") if _ours(p))]:
                old.unlink()
            with contextlib.suppress(OSError):  # not there, or holds files that are not ours
                folder.rmdir()
            if remove_only or fm not in file_managers():
                continue  # a fork that is not installed gets no folder; its old entries are gone anyway
            for key, script in zip(SCRIPT_ACTIONS, menu_entries(base)):
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text(script_text(key))
                script.chmod(0o755)
    except (OSError, RuntimeError) as e:  # RuntimeError: resolve() on a symlink loop
        return str(e)
    return None


def first_run_entries():
    """The .deb cannot write into the users' homes, so its first start creates the right-click entries, once.
    True if it did now (the file managers then need a restart to show them)."""
    if not PACKAGED or load_config()["integrated"]:
        return False
    return install_scripts() is None and set_option("integrated", True) is None


# --------------------------------------------------------------------------- restarting the file managers

FILE_MANAGERS = {"nautilus": "org.gnome.Nautilus", "nemo": "org.Nemo", "caja": "org.mate.Caja"}  # program: its bus name
# shortcut: nemo-desktop (its own process) is not restarted, so the desktop's right-click menu changes only at the next login;
# and in MATE the session restarts Caja too, so the one we start may win and run outside the session till then. Upgrade if users report it.
waits = []  # the waits for a file manager to quit: at most one per program, whichever window asked for it


def files_running(programs):
    """Those of `programs` that own their bus name, so a restart has something to restart.
    If the bus cannot say, ask for Files anyway, as before; a fork only when the bus says it runs."""
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        return [fm for fm in programs if bus.call_sync(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
            GLib.Variant("(s)", (FILE_MANAGERS[fm],)), GLib.VariantType("(b)"), Gio.DBusCallFlags.NONE, 1000, None).unpack()[0]]
    except GLib.Error:
        return [fm for fm in programs if fm == "nautilus"]


def restart_files(app, toast, programs):
    """Quits each of `programs` and opens it again once it has left the bus (a fixed pause races with it). The app is held
    meanwhile: closing the last window now must not end the program before they are back."""
    for fm in programs:
        if any(watch[2] == fm for watch in waits):  # a restart is under way already
            continue
        try:
            Gio.Subprocess.new([fm, "-q"], Gio.SubprocessFlags.NONE)
        except GLib.Error as e:
            toast(e.message)
            continue
        app.hold()
        watch = (Gio.bus_watch_name(Gio.BusType.SESSION, FILE_MANAGERS[fm], Gio.BusNameWatcherFlags.NONE, None,
                                    functools.partial(files_gone, toast, fm)), app, fm)
        waits.append(watch)
        GLib.timeout_add_seconds(30, stop_waiting, watch)  # a file manager that refuses to quit stays as it is


def stop_waiting(watch):
    """Ends the wait for a file manager, unless it is over already."""
    if watch in waits:
        waits.remove(watch)
        Gio.bus_unwatch_name(watch[0])
        watch[1].release()
    return GLib.SOURCE_REMOVE


def files_gone(toast, fm, connection, name):
    """`fm` has left the bus: open it again. The bus watch passes `connection` and `name`; neither is needed."""
    watch = next((w for w in waits if w[2] == fm), None)
    if not watch:  # we gave up waiting already
        return
    stop_waiting(watch)
    try:
        # the program itself, not the default folder handler: that may be another one, and Caja's starts with --no-desktop
        Gio.Subprocess.new([fm, os.path.expanduser("~")], Gio.SubprocessFlags.NONE)
    except GLib.Error as e:
        toast(e.message)
