# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""Self-check for src/core.py, src/i18n.py and po/de.po. Run: python3 tests/test_core.py"""
import ast
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
import zlib
from pathlib import Path
from unittest import mock

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))
import cli  # noqa: E402
import core  # noqa: E402
import hashtally  # noqa: E402
import nautilus_ext  # noqa: E402
import i18n  # noqa: E402

A = hashlib.sha256(b"alpha").hexdigest()
B = hashlib.sha256(b"beta").hexdigest()


@contextlib.contextmanager
def environment(**values):
    """Environment variables set for the block, restored afterwards."""
    old = dict(os.environ)
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


@contextlib.contextmanager
def settings_sandbox():
    """Scripts folder and settings file in a temporary directory; the language is restored afterwards."""
    old, language = (core.SCRIPTS_DIR, core.CONFIG_FILE, core.FORKS, core.EXTENSION_FILE, core.MENU_FILE), i18n._current
    with tempfile.TemporaryDirectory() as tmp:
        core.SCRIPTS_DIR, core.CONFIG_FILE = Path(tmp, "scripts"), Path(tmp, "cfg", "config.json")
        core.FORKS = {"nemo": Path(tmp, "nemo"), "caja": Path(tmp, "caja")}  # never the real folders
        core.EXTENSION_FILE, core.MENU_FILE = Path(tmp, "ext", "hashtally.py"), Path(tmp, "data", "menu.json")
        try:
            i18n.set_language("en")
            yield Path(tmp)
        finally:
            core.SCRIPTS_DIR, core.CONFIG_FILE, core.FORKS, core.EXTENSION_FILE, core.MENU_FILE = old
            i18n.set_language(language)


def test_every_algorithm_gets_a_speed():
    speeds = core.hash_speeds(0.01)
    assert set(speeds) == set(core.ALGOS) and all(v > 0 for v in speeds.values())


def test_advice_is_the_fastest_secure_one_and_names_a_faster_weak_one():
    speeds = {"crc32": 3000, "sha256": 1100, "sha512": 500, "sha1": 1200, "md5": 500}
    assert core.speed_advice(speeds) == ("sha256", "crc32")
    assert core.speed_advice({**speeds, "crc32": 900}) == ("sha256", "sha1")  # faster, but not secure
    assert core.speed_advice({**speeds, "crc32": 900, "sha1": 800}) == ("sha256", None)  # nothing weak beats it: no remark
    assert core.speed_advice({**speeds, "sha256": 300}) == ("sha512", "crc32")


def test_parse_formats():
    with tempfile.TemporaryDirectory() as tmp:
        def parse(name, content, mode="w", **kw):
            path = Path(tmp, name)
            if mode == "wb":
                path.write_bytes(content)
            else:
                path.write_text(content, **kw)
            return core.parse(path)

        gnu = parse("SHA256SUMS", f"{A}  a.txt\n{B} *sub dir/b.txt\n# comment\n")
        assert gnu == [("sha256", A, "a.txt"), ("sha256", B, "sub dir/b.txt")]
        assert parse("x.sha256", f"SHA256 (a.txt) = {A.upper()}\n") == [("sha256", A, "a.txt")]
        assert parse("x.sfv", "; made by tool\na b.bin DEADBEEF\n") == [("crc32", "deadbeef", "a b.bin")]
        assert parse("file.iso.md5", "d41d8cd98f00b204e9800998ecf8427e\n") == \
            [("md5", "d41d8cd98f00b204e9800998ecf8427e", "file.iso")]
        windows = parse("w.sha256", b"\xef\xbb\xbf" + f"{A}  dir\\a.txt\r\n".encode(), mode="wb")
        assert windows == [("sha256", A, "dir\\a.txt")]
        assert parse("odd.txt", f"{'a' * 33}  a.txt\n")[0].algo is None
        assert parse("SHA256SUMS", f"{A}\n") == []  # no suffix: the "file" would be the hash file itself


def test_parse_clearsigned_reads_only_the_signed_part():
    """gpg checks the block between the headers and the signature, so nothing behind it may be listed."""
    head = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
    tail = "-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n"
    with tempfile.TemporaryDirectory() as tmp:
        sums, sfv = Path(tmp, "CHECKSUM"), Path(tmp, "x.sfv")
        for eol in ("\n", "\r\n"):
            sums.write_bytes(f"{head}{A}  a.txt\n{tail}{B}  evil.exe\n".replace("\n", eol).encode())
            assert [e.name for e in core.parse(sums)] == ["a.txt"], repr(eol)
        for after in (" ", "\t", "\r", "\v", "\u00a0", "XYZ"):  # gpg ends the signed text at any line of five dashes, so a mirror can hide the end
            sums.write_text(f"{head}{A}  a.txt\n{tail.replace('SIGNATURE-----', 'SIGNATURE-----' + after, 1)}{B}  evil.exe\n")
            assert [e.name for e in core.parse(sums)] == ["a.txt"], repr(after)
        sums.write_text(f"{head}{A}  a.txt\n-----\nabc\n{B}  evil.exe\n")
        assert [e.name for e in core.parse(sums)] == ["a.txt"]
        for blank in (" ", "\t", "\r"):  # gpg ends the armor headers at a line of blanks too, so the signed text starts there
            sums.write_bytes(f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n{blank}\n{A}  a.txt\n{tail}\n{B}  evil.exe\n".encode())
            assert [e.name for e in core.parse(sums)] == ["a.txt"], repr(blank)
        for first in ("-----BEGIN PGP SIGNED MESSAGE------", "-----BEGIN PGP SIGNED MESSAGE-----x"):  # gpg skips such a line and checks a later block
            sums.write_text(f"{first}\nHash: SHA512\n\n{B}  evil.exe\n{head}{A}  a.txt\n{tail}")
            assert core.parse(sums) == [], repr(first)
        sfv.write_text(f"{head}- -dash.bin DEADBEEF\n{tail}")  # "- " escapes a line that starts with a dash
        assert core.parse(sfv) == [("crc32", "deadbeef", "-dash.bin")]


def test_a_bom_in_front_of_the_armor_is_no_clearsigned_file():
    """gpg does not skip a BOM and checks a later block instead, so asking it about the file would show a verdict for other lines than we list."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "CHECKSUM")  # the windows pass plain strings
        Path(path).write_bytes(b"\xef\xbb\xbf-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + f"{A}  a.txt\n".encode())
        assert core.signature_args(path) is None
        assert "-----BEGIN PGP SIGNED MESSAGE-----" in [e.name for e in core.parse(path)]  # read as a plain list: nothing here claims a signed part
        Path(path).write_bytes(b"\xef\xbb\xbf" + f"{A}  a.txt\n".encode())  # a plain hash file from Windows is still read
        assert [e.name for e in core.parse(path)] == ["a.txt"]


def test_parse_shows_unrecognised_lines():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "SUMS")
        path.write_text(f"{A}  a.txt\n{A} one-space.txt\nSHA3-256 (x) = {A}\ngarbage\n")
        entries = core.parse(path)
        assert [e.name for e in entries] == ["a.txt", f"{A} one-space.txt", "SHA3-256 (x) = " + A, "garbage"]
        assert [core.check(tmp, e)[0] for e in entries[1:]] == ["unknown"] * 3
        path.write_text("just\nsome text\n")
        assert core.parse(path) == []  # not a hash file at all: "No checksums found"


def test_parse_ignores_files_too_big_to_be_hash_files():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "SUMS")
        path.write_text(f"{A}  a.txt\n")
        assert len(core.parse(path)) == 1
        with path.open("ab") as f:  # sparse padding: no disk space needed, a 4 GB ISO would look the same
            f.truncate(core.MAX_HASHFILE + 1)
        assert core.parse(path) == []


def test_parse_does_not_block_on_a_pipe():
    import signal
    with tempfile.TemporaryDirectory() as tmp:
        fifo = os.path.join(tmp, "x.sha256")
        os.mkfifo(fifo)  # getsize says 0, reading would wait for a writer forever
        signal.alarm(5)  # fail instead of hanging the run if this ever regresses
        try:
            assert core.parse(fifo) == []
        finally:
            signal.alarm(0)


def test_parse_sfv_stays_fast_on_a_long_line():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "x.sfv")
        path.write_text("a" + " " * 50000 + "b\n")  # a regex like (.+?)\s+crc took seconds for 20 000 blanks
        start = time.monotonic()
        core.parse(path)
        assert time.monotonic() - start < 1


def test_hashfile_roundtrip_with_odd_names():
    """Names that splitlines()/strip() used to cut: line separators and control characters inside the name."""
    names = ["a\rb", "a b", "a\x0bb", "a\x85b", "back\\slash", "two\nlines"]
    with tempfile.TemporaryDirectory() as tmp:
        for name in names:
            Path(tmp, name).write_bytes(b"x")
        for algo, skip in (("sha256", ()), ("crc32", ("two\nlines", "back\\slash"))):  # SFV has no escaping
            files = [os.path.join(tmp, n) for n in names if n not in skip]
            out = Path(tmp, "x.sfv" if algo == "crc32" else "x.sha256")
            core.write_hashfile(files, tmp, algo, out)
            assert [e.name for e in core.parse(out)] == [n for n in names if n not in skip], algo
            assert {core.check(tmp, e)[0] for e in core.parse(out)} == {"ok"}, algo
            out.unlink()
        Path(tmp, "end\r").write_bytes(b"x")  # a trailing \r would have been trimmed as a line end
        core.write_hashfile([os.path.join(tmp, "end\r")], tmp, "sha256", Path(tmp, "S2"))
        assert [e.name for e in core.parse(Path(tmp, "S2"))] == ["end\r"]


def test_create_and_verify_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "sub").mkdir()
        Path(tmp, "a.txt").write_bytes(b"alpha")
        Path(tmp, "sub", "b.txt").write_bytes(b"beta")
        files = core.collect_files([tmp])
        for algo in core.ALGOS:
            out = Path(tmp, core.default_target([tmp], algo)[1])
            assert core.write_hashfile(files, tmp, algo, out) == 2
            statuses = [core.check(tmp, e)[0] for e in core.parse(out)]
            assert statuses == ["ok", "ok"], (algo, statuses)
            out.unlink()
        out = Path(tmp, "SHA256SUMS")
        core.write_hashfile(files, tmp, "sha256", out)
        Path(tmp, "a.txt").write_bytes(b"tampered")
        os.remove(Path(tmp, "sub", "b.txt"))
        assert [core.check(tmp, e)[0] for e in core.parse(out)] == ["bad", "missing"]


def test_a_planted_part_link_is_not_written_through():
    with tempfile.TemporaryDirectory() as tmp:
        victim, out = Path(tmp, "victim"), Path(tmp, "x.sha256")
        victim.write_text("precious\n")
        os.symlink(victim, str(out) + ".part")
        core.write_atomic(str(out), "new\n")
        assert victim.read_text() == "precious\n" and out.read_text() == "new\n" and not out.is_symlink()


def test_write_hashfile_keeps_the_old_file_when_writing_fails():
    from unittest import mock
    with tempfile.TemporaryDirectory() as tmp:
        sample, out = Path(tmp, "a.txt"), Path(tmp, "SUMS")
        sample.write_bytes(b"alpha")
        out.write_text("old\n")
        out.chmod(0o600)
        core.write_hashfile([str(sample)], tmp, "sha256", out)
        assert out.stat().st_mode & 0o777 == 0o600  # the rename must not widen the permissions
        assert out.read_text() == f"{A}  a.txt\n" and sorted(os.listdir(tmp)) == ["SUMS", "a.txt"]  # no .part left
        with mock.patch("os.replace", side_effect=OSError("disk full")):
            try:
                core.write_hashfile([str(sample)], tmp, "sha256", out)
            except OSError:
                pass
            else:
                raise AssertionError("the error must reach the caller")
        assert out.read_text() == f"{A}  a.txt\n" and sorted(os.listdir(tmp)) == ["SUMS", "a.txt"]
        link, victim = Path(tmp, "link.sha256"), Path(tmp, "victim")
        victim.write_text("precious\n")
        link.symlink_to(victim)
        core.write_hashfile([str(sample)], tmp, "sha256", link)
        assert victim.read_text() == "precious\n" and not link.is_symlink() and link.read_text() == f"{A}  a.txt\n"  # a planted link costs no file


def test_collect_files_skips_broken_symlinks():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        os.symlink(Path(tmp, "gone"), Path(tmp, "broken"))  # target does not exist
        files = core.collect_files([tmp])
        assert files == [os.path.join(tmp, "a.txt")]
        assert core.total_size(files) == 5  # used to raise FileNotFoundError
        assert core.total_size(files + [os.path.join(tmp, "gone")]) == 5  # a vanished file counts as 0


def test_collect_files_refuses_links_to_folders():
    """os.walk lists them but never enters them: the hash file would silently miss everything inside."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "sub").mkdir()
        Path(tmp, "sub", "two").write_bytes(b"2")
        assert len(core.collect_files([tmp])) == 1
        os.symlink(Path(tmp, "sub"), Path(tmp, "linkdir"))
        try:
            core.collect_files([tmp])
        except OSError as exc:
            assert "linkdir" in str(exc)
        else:
            raise AssertionError("a link to a folder must not be skipped silently")


def test_collect_files_reports_unreadable_folders():
    from unittest import mock
    real = os.scandir

    def scandir(path):  # root can read everything, so fake the permission error
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)

    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "locked").mkdir()
        Path(tmp, "a.txt").write_bytes(b"alpha")
        with mock.patch("os.scandir", scandir):
            try:
                core.collect_files([tmp])
            except PermissionError:
                pass
            else:
                raise AssertionError("an unreadable folder must not be skipped silently")


def test_hash_file_calculates_crc_only_when_asked():
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp, "f")
        sample.write_bytes(b"alpha")
        assert core.hash_file(sample, ["sha256"]) == {"sha256": A}
        assert core.hash_file(sample, ["sha256", "crc32"]) == {"sha256": A, "crc32": f"{zlib.crc32(b'alpha'):08x}"}
        data = os.urandom((3 << 20) + 7)  # several chunks, each algorithm in a thread of its own: every one must see them all, in order
        sample.write_bytes(data)
        algos = ["sha256", "sha512", "sha1", "md5", "blake2b"]
        seen = []
        assert core.hash_file(sample, [*algos, "crc32"], seen.append) == {**{a: hashlib.new(a, data).hexdigest() for a in algos}, "crc32": f"{zlib.crc32(data):08x}"}
        assert sum(seen) == len(data)


def test_gpg_never_fetches_keys():
    """A gpg.conf with auto-key-retrieve would make `gpg --verify` ask a keyserver and change the keyring."""
    from unittest import mock
    with mock.patch("subprocess.run", return_value=mock.Mock(stdout=b"", stderr=b"", returncode=2)) as run:
        core.verify_signature(["x"])
    assert {"--no-auto-key-retrieve", "--no-auto-key-import"} <= set(run.call_args[0][0])  # nor may it take the key a signature carries


def _gpg_says(status, code):
    from unittest import mock
    with mock.patch("subprocess.run", return_value=mock.Mock(stdout=status.encode(), stderr=b"gpg: Signature made", returncode=code)):
        return core.verify_signature(["x"])


def test_what_gpg_rejects_is_never_good_whatever_it_printed():
    good = "[GNUPG:] GOODSIG AB12 Real Publisher\n[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-01-01 1 0 4 0 1 8 00 " + "A" * 40 + "\n"
    assert _gpg_says(good, 0).status == "good"
    for word in ("EXPKEYSIG", "REVKEYSIG"):  # key states: gpg ends with 0, and with anything else the file was rejected
        line = f"[GNUPG:] {word} AB12 Real Publisher\n"
        assert _gpg_says(line, 0).status == {"EXPKEYSIG": "expired", "REVKEYSIG": "revoked"}[word]
        assert _gpg_says(line, 2).status == "error", word
    assert _gpg_says(good + "[GNUPG:] BADSIG CD34 Mallory\n", 1).status == "bad"  # a second, invalid signature
    assert _gpg_says(good + "[GNUPG:] TRUST_NEVER\n", 1).status == "bad"  # a key the user distrusts
    assert _gpg_says(good, 2).status == "error"  # rejected for another reason
    second = "[GNUPG:] GOODSIG CD34 Second Signer\n[GNUPG:] VALIDSIG " + "C" * 40 + " 2026-01-01 1 0 4 0 1 8 00 " + "C" * 40 + "\n"
    assert _gpg_says(good + second, 0)[1:4] == ("AB12", "Real Publisher", "A" * 40)  # name and fingerprint of one and the same signature


def test_the_signer_cannot_hide_behind_bidi_controls_and_a_dash_is_no_fingerprint():
    sig = _gpg_says("[GNUPG:] GOODSIG AB12 Real \u202ePublisher\n", 0)
    assert sig.signer == "Real Publisher"
    fake, real = (f"[GNUPG:] VALIDSIG {c * 40} 2026-01-01 1 0 4 0 1 8 00 {c * 40}" for c in "BA")
    for word in ("GOODSIG", "EXPKEYSIG", "REVKEYSIG"):
        for cut in ("\u2028", "\u2029", "\u0085"):  # gpg leaves these in a user ID: they must not start a status line of their own
            sig = _gpg_says(f"[GNUPG:] {word} AB12 Real Publisher{cut}{fake}\n{real}\n", 0)
            assert sig.fingerprint == "A" * 40 and sig.signer.isprintable(), (word, repr(cut))
    assert core._first_signature("[GNUPG:] ERRSIG 1234567890ABCDEF 1 8 00 1600000000 9 -\n[GNUPG:] NO_PUBKEY 1234567890ABCDEF\n")[3] == ""


def test_a_key_carried_by_the_signature_is_not_imported():
    """With auto-key-import in the user's gpg.conf an attacker could sign with a key of their own, named like the publisher."""
    if not shutil.which("gpg"):
        print("skip test_a_key_carried_by_the_signature_is_not_imported (gpg not installed)")
        return
    old_home = os.environ.get("GNUPGHOME")
    with tempfile.TemporaryDirectory() as attacker, tempfile.TemporaryDirectory() as victim, tempfile.TemporaryDirectory() as tmp:
        def gpg(home, *args):
            return subprocess.run(["gpg", "--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *args],
                                  capture_output=True, text=True)

        try:
            gpg(attacker, "--quick-gen-key", "Real Publisher <real@example.org>", "default", "default", "never")
            Path(tmp, "SUMS").write_text(f"{A}  evil.iso\n")
            gpg(attacker, "--include-key-block", "--clearsign", "-o", os.path.join(tmp, "SUMS.asc"), os.path.join(tmp, "SUMS"))
            Path(victim, "gpg.conf").write_text("auto-key-import\n")
            os.environ["GNUPGHOME"] = victim
            for _ in range(2):  # the key would be in the keyring from the first run on
                assert core.verify_signature([os.path.join(tmp, "SUMS.asc")]).status == "nokey"
            assert not gpg(victim, "--list-keys").stdout.strip()
        finally:
            subprocess.run(["gpgconf", "--homedir", attacker, "--kill", "gpg-agent"], capture_output=True)
            subprocess.run(["gpgconf", "--homedir", victim, "--kill", "gpg-agent"], capture_output=True)
            if old_home is None:
                os.environ.pop("GNUPGHOME", None)
            else:
                os.environ["GNUPGHOME"] = old_home


def test_signature_states():
    """Real gpg with a throw-away keyring: good, clear-signed, tampered, unknown key and unsigned."""
    if not shutil.which("gpg"):
        print("skip test_signature_states (gpg not installed)")
        return
    old_home = os.environ.get("GNUPGHOME")
    with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as empty, \
            tempfile.TemporaryDirectory() as tmp:
        def gpg(*args):
            subprocess.run(["gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback",
                            "--passphrase", "", *args], check=True, capture_output=True)

        try:
            gpg("--quick-gen-key", "Test Signer <test@example.org>", "default", "default", "never")
            sums = os.path.join(tmp, "SHA256SUMS")
            Path(sums).write_text(f"{A}  a.txt\n")
            gpg("--detach-sign", "-o", sums + ".gpg", sums)
            gpg("--clearsign", "-o", os.path.join(tmp, "CHECKSUM"), sums)

            os.environ["GNUPGHOME"] = home
            good = core.verify_signature(core.signature_args(sums))
            assert good.status == "good" and good.signer.startswith("Test Signer"), good
            assert len(good.fingerprint) == 40 and core.format_fingerprint(good.fingerprint).count(" ") == 9

            clear = os.path.join(tmp, "CHECKSUM")  # the signature armor must not confuse the parser
            assert core.signature_args(clear) == [clear]
            assert core.verify_signature([clear]).status == "good"
            assert [e.name for e in core.parse(clear)] == ["a.txt"]
            with open(clear, "a") as f:  # gpg still says "good" for this; the parser must not list the extra line
                f.write(f"{B}  evil.exe\n")
            assert core.verify_signature([clear]).status == "good"
            assert [e.name for e in core.parse(clear)] == ["a.txt"]
            forged = f"{B}  a.txt\n".encode()  # gpg checks the bytes parse() read, not the file again: it may have been swapped meanwhile
            assert core.verify_signature(core.signature_args(sums), forged).status == "bad"
            assert core.verify_signature(core.signature_args(sums), Path(sums).read_bytes()).status == "good"
            Path(sums).write_text(f"{B}  a.txt\n")
            assert core.verify_signature(core.signature_args(sums), f"{A}  a.txt\n".encode()).status == "good"  # the file on disk was swapped after reading
            Path(sums).write_text(f"{A}  a.txt\n")
            assert core.verify_signature([clear], Path(clear).read_bytes()).status == "good"
            assert core.verify_signature([clear], Path(clear).read_bytes().replace(A.encode(), B.encode())).status == "bad"
            broken = os.path.join(tmp, "BROKEN")  # gpg prints GOODSIG for this and then rejects the file (exit 2): that is no good signature
            Path(broken).write_text(Path(clear).read_text().replace("Hash: SHA512\n\n", "Hash: SHA512\nfoo\n", 1))
            assert core.verify_signature([broken]).status == "error"
            twice = os.path.join(tmp, "TWICE")  # two plaintexts: rejected the same way
            Path(twice).write_text(Path(clear).read_text() * 2)
            assert core.verify_signature([twice]).status == "error"
            trap = os.path.join(tmp, "TRAP")  # a BOM and a block of our own in front of the signed one: gpg skips it and says "good" for the later block
            Path(trap).write_bytes(b"\xef\xbb\xbf-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + f"{B}  evil.exe\n-----\n".encode() + Path(clear).read_bytes())
            assert core.signature_args(trap) is None  # no verdict, so none that could sit next to lines it does not cover
            lead = f"{B}  evil.exe\n".encode() + Path(clear).read_bytes()  # gpg skips the text in front of the armor and says "good"
            assert core.verify_signature([clear], lead).status == "good"
            assert core.signature_args(clear, lead) is None  # the file on disk is clear-signed by now, the bytes we list are not

            os.environ["GNUPGHOME"] = empty  # same signature, but nobody imported the key
            unknown = core.verify_signature(core.signature_args(sums))
            assert unknown.status == "nokey" and unknown.key == good.fingerprint[-16:], unknown
            assert unknown.fingerprint == good.fingerprint  # gpg names the full fingerprint of the missing key

            os.environ["GNUPGHOME"] = home
            Path(sums).write_text(f"{B}  a.txt\n")  # modified after signing
            assert core.verify_signature(core.signature_args(sums)).status == "bad"

            plain = os.path.join(tmp, "plain.txt")
            Path(plain).write_text("x")
            assert core.signature_args(plain) is None
        finally:
            subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], capture_output=True)
            if old_home is None:
                os.environ.pop("GNUPGHOME", None)
            else:
                os.environ["GNUPGHOME"] = old_home


def test_norm_hash_takes_the_hash_from_a_pasted_line():
    assert core.norm_hash(f"{A}  ubuntu.iso") == A  # a line from SHA256SUMS
    assert core.norm_hash(f"SHA256 (my file.iso) = {A.upper()}") == A  # a BSD line
    assert core.norm_hash(f"sha256: {A}") == A and core.norm_hash(" ".join([A[:32], A[32:]])) == A
    assert core.norm_hash("hello world") == "helloworld"  # no hash in it: unchanged, so it will not match


def test_install_scripts():
    """Right-click entries: prefixed, in the current language, replaced on a language switch, ours only."""
    with settings_sandbox():
        core.SCRIPTS_DIR.mkdir()
        foreign = core.SCRIPTS_DIR / "My own script"
        foreign.write_text("#!/bin/sh\n")
        i18n.set_language("de")
        core.install_scripts()
        german = core.SCRIPTS_DIR / ("HashTally: " + i18n.translate("Create hash file", "de"))
        assert german.name != "HashTally: Create hash file" and german.is_file() and os.access(german, os.X_OK)
        assert "--create" in german.read_text()
        assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4

        i18n.set_language("en")
        core.install_scripts()  # a language switch must not leave the German entries behind
        assert [p.name for p in sorted(core.SCRIPTS_DIR.glob("HashTally: *"))] == [
            "HashTally: Compare files", "HashTally: Create hash file", "HashTally: Show or compare hash", "HashTally: Verify hash file"]

        core.install_scripts(remove_only=True)
        assert list(core.SCRIPTS_DIR.glob("HashTally: *")) == [] and foreign.is_file()


def test_the_extension_offers_only_what_fits_the_selection():
    assert nautilus_ext.HASHFILE_NAME.pattern == core._HASHFILE_NAME.pattern  # the extension stands alone and keeps its own copy
    with tempfile.TemporaryDirectory() as tmp:
        a, b, c, d = (Path(tmp, n) for n in ("a.iso", "b.iso", "SHA256SUMS", "x.sha256"))
        for f in (a, b, c, d):
            f.write_text("x")
        folder = Path(tmp, "dir")
        folder.mkdir()
        assert nautilus_ext.entries_for([]) == []
        assert nautilus_ext.entries_for([str(a)]) == ["--create", "--compare"]
        assert nautilus_ext.entries_for([str(a), str(b)]) == ["--create", "--compare-files"]
        assert nautilus_ext.entries_for([str(a), str(b), str(c)]) == ["--create"]
        assert nautilus_ext.entries_for([str(c)]) == ["--create", "--compare", "--verify"]
        assert nautilus_ext.entries_for([str(c), str(d)]) == ["--create", "--compare-files", "--verify"]
        assert nautilus_ext.entries_for([str(folder)]) == ["--create"]
        assert nautilus_ext.entries_for([str(a), str(folder)]) == ["--create"]
        assert nautilus_ext.entries_for([str(folder)], folder=True) == ["--create"]


def test_with_the_extension_on_the_scripts_folder_stays_empty_and_back():
    with settings_sandbox(), mock.patch.object(core, "extension_available", lambda: True):
        assert core.set_option("extension", True) is None
        assert core.EXTENSION_FILE.read_text().splitlines()[1] == core.MARKER
        menu = json.loads(core.MENU_FILE.read_text())
        assert menu["name"] == "HashTally" and menu["labels"]["--verify"] == "Verify hash file"
        core.set_option("menu_name", "My sums")  # the name is read when the menu opens: only the file is rewritten
        assert json.loads(core.MENU_FILE.read_text())["name"] == "My sums"
        assert not list(core.SCRIPTS_DIR.glob("HashTally: *"))  # no double entries
        assert core.set_option("extension", False) is None
        assert not core.EXTENSION_FILE.exists() and not core.MENU_FILE.exists() and len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4


def test_without_python3_nautilus_the_extension_setting_falls_back_to_scripts():
    with settings_sandbox(), mock.patch.object(core, "extension_available", lambda: False):
        assert core.set_option("extension", True) is None
        assert not core.EXTENSION_FILE.exists() and len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4


def test_removing_the_entries_also_removes_the_extension_but_not_a_foreign_file():
    with settings_sandbox(), mock.patch.object(core, "extension_available", lambda: True):
        core.set_option("extension", True)
        core.install_scripts(remove_only=True)
        assert not core.EXTENSION_FILE.exists()
        core.EXTENSION_FILE.write_text("# somebody else's\n")
        core.install_scripts(remove_only=True)
        assert core.EXTENSION_FILE.read_text() == "# somebody else's\n"


def test_a_forks_folder_linked_to_the_files_one_keeps_its_entries():
    with settings_sandbox():
        core.FORKS["nemo"].symlink_to(core.SCRIPTS_DIR)  # a common tip: one folder for both managers
        for installed in (False, True):
            with mock.patch.object(core.shutil, "which", lambda name: "/usr/bin/nemo" if installed and name == "nemo" else None):
                assert core.install_scripts() is None
            assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4, installed


def test_a_symlink_loop_as_a_scripts_folder_is_an_error_text_not_a_crash():
    with settings_sandbox():
        core.FORKS["nemo"].parent.mkdir(parents=True, exist_ok=True)
        core.FORKS["nemo"].symlink_to(core.FORKS["nemo"])  # points at itself
        with mock.patch.object(core.shutil, "which", lambda name: "/usr/bin/nemo"):  # installed: its folder is needed (Python 3.13 resolves a loop without an error)
            assert isinstance(core.install_scripts(), str)


def test_forks_get_entries_only_when_installed_and_lose_them_always():
    with settings_sandbox():
        nemo, caja = core.FORKS["nemo"], core.FORKS["caja"]
        caja.mkdir()
        (caja / "HashTally: Verify hash file").write_text(core.script_text("--verify"))  # left from when Caja was installed
        (caja / "My own script").write_text("#!/bin/sh\n")
        with mock.patch.object(core.shutil, "which", lambda name: "/usr/bin/nemo" if name == "nemo" else None):
            assert core.install_scripts() is None
        assert sorted(p.name for p in nemo.iterdir()) == sorted(p.name for p in core.SCRIPTS_DIR.iterdir())
        assert [p.name for p in caja.iterdir()] == ["My own script"]  # not installed: ours went, the user's stays
        core.install_scripts(remove_only=True)
        assert list(nemo.iterdir()) == []


class FakeGio:
    """Stands in for Gio and GLib in core: records what a file manager's restart does and keeps its callbacks."""

    class Error(Exception):
        message = "cannot run nautilus"

    SOURCE_REMOVE = False

    def __init__(self, fail_quit=False, fail_open=False):
        self.events, self.runs, self.timers, self.vanished, self.watches = [], [], [], {}, 0
        self.fail_quit, self.fail_open = fail_quit, fail_open
        self.Subprocess = types.SimpleNamespace(new=self.run)
        self.SubprocessFlags = types.SimpleNamespace(NONE=0)
        self.BusType = types.SimpleNamespace(SESSION=1)
        self.BusNameWatcherFlags = types.SimpleNamespace(NONE=0)

    def run(self, argv, flags):
        quit = argv[1] == "-q"
        if self.fail_quit if quit else self.fail_open:
            raise self.Error()
        self.events.append("quit" if quit else "open")
        self.runs.append(argv)

    def bus_watch_name(self, bus, name, flags, appeared, vanished):
        self.vanished[name] = vanished
        self.events.append("watch")
        self.watches += 1  # every watch gets its own id, as in GLib
        return self.watches

    def bus_unwatch_name(self, watch):
        self.events.append("unwatch")

    def timeout_add_seconds(self, seconds, function, *args):
        self.timers.append((function, args))


class FakeApp:
    def __init__(self):
        self.holds = self.releases = 0

    def hold(self):
        self.holds += 1

    def release(self):
        self.releases += 1


@contextlib.contextmanager
def fake_files_restart(**failures):
    """core's Gio and GLib replaced by FakeGio; yields (bus, app, toasts, restart, quits) where restart(programs)
    asks for a restart and quits(fm) lets that file manager leave the bus."""
    bus, app, toasts = FakeGio(**failures), FakeApp(), []
    old = core.Gio, core.GLib
    core.Gio = core.GLib = bus

    def quits(fm="nautilus"):
        bus.vanished[core.FILE_MANAGERS[fm]](None, core.FILE_MANAGERS[fm])
    try:
        yield bus, app, toasts, lambda programs=("nautilus",): core.restart_files(app, toasts.append, list(programs)), quits
    finally:
        core.Gio, core.GLib = old
        core.waits.clear()


def balanced(app):
    assert app.holds == app.releases and core.waits == []


def test_the_restart_is_only_offered_to_the_file_managers_that_run():
    if core.Gio is None:  # the CI job's own Python has no PyGObject
        print("skip test_the_restart_is_only_offered_to_the_file_managers_that_run (no PyGObject)")
        return
    from unittest import mock

    def says(owners=(), programs=("nautilus", "nemo", "caja"), fail=False):
        bus = mock.Mock()
        bus.call_sync.side_effect = lambda *args: core.GLib.Variant("(b)", (args[4].unpack()[0] in owners,))
        if fail:  # the bus cannot be reached
            bus.call_sync.side_effect = core.GLib.Error("no bus")
        with mock.patch.object(core.Gio, "bus_get_sync", return_value=bus):
            return core.files_running(list(programs))

    assert says({"org.gnome.Nautilus"}) == ["nautilus"]
    assert says({"org.Nemo", "org.mate.Caja"}) == ["nemo", "caja"]  # a Nemo user gets no Nautilus opened
    assert says() == []
    assert says({"org.Nemo"}, ["nautilus"]) == []  # only the ones that get entries
    assert says(fail=True) == ["nautilus"]  # no answer: ask for Files as before, never for a fork


def test_entries_go_to_files_and_each_installed_fork():
    from unittest import mock
    with mock.patch.object(core.shutil, "which", lambda name: "/usr/bin/caja" if name == "caja" else None):
        assert core.file_managers() == ["nautilus", "caja"]


def fire_timer(bus, n=0):
    function, args = bus.timers[n]
    assert function(*args) is False  # the timer must not repeat


def test_files_quits_first_and_the_late_timer_does_nothing():
    with fake_files_restart() as (bus, app, toasts, restart, quits):
        restart()
        assert (bus.events, app.holds, app.releases) == (["quit", "watch"], 1, 0)
        quits()
        assert bus.events == ["quit", "watch", "unwatch", "open"]
        fire_timer(bus)
        assert bus.events[-1] == "open" and app.releases == 1
        balanced(app)


def test_the_timer_gives_up_first_and_a_late_answer_opens_nothing():
    with fake_files_restart() as (bus, app, toasts, restart, quits):
        restart()
        fire_timer(bus)
        assert bus.events == ["quit", "watch", "unwatch"]
        quits()
        assert "open" not in bus.events
        balanced(app)


def test_a_second_restart_request_waits_for_the_first():
    with fake_files_restart() as (bus, app, toasts, restart, quits):
        restart()
        restart()
        assert bus.events.count("quit") == 1 and app.holds == 1
        quits()
        balanced(app)


def test_an_old_timer_does_not_end_a_newer_wait():
    with fake_files_restart() as (bus, app, toasts, restart, quits):
        restart()
        quits()
        restart()
        fire_timer(bus, 0)  # the timer of the first restart
        assert len(core.waits) == 1
        quits()
        assert bus.events.count("open") == 2
        balanced(app)


def test_each_fork_is_quit_and_opened_again_by_itself():
    with fake_files_restart() as (bus, app, toasts, restart, quits):
        restart(["nemo", "caja"])
        assert (bus.runs, app.holds) == ([["nemo", "-q"], ["caja", "-q"]], 2)
        quits("caja")
        assert bus.runs[2:] == [["caja", os.path.expanduser("~")]]  # the program itself: Caja then draws the desktop again
        restart(["nemo"])  # Nemo is still on its way out
        quits("nemo")
        assert bus.runs[3:] == [["nemo", os.path.expanduser("~")]]
        balanced(app)


def test_nautilus_that_cannot_run_is_reported_and_nothing_is_held():
    with fake_files_restart(fail_quit=True) as (bus, app, toasts, restart, quits):
        restart()
        assert (toasts, app.holds, bus.events) == (["cannot run nautilus"], 0, [])
        balanced(app)


def test_a_failing_reopen_is_reported_and_the_hold_is_released():
    with fake_files_restart(fail_open=True) as (bus, app, toasts, restart, quits):
        restart()
        quits()
        assert toasts == ["cannot run nautilus"]
        balanced(app)


def test_partial_hash():
    assert core.is_partial_hash("ab") and core.is_partial_hash("A" * 100)  # could still grow
    assert not core.is_partial_hash("")  # nothing typed
    assert not core.is_partial_hash("a" * 64) and not core.is_partial_hash("a" * 8)  # known lengths: judge them
    assert not core.is_partial_hash("hello") and not core.is_partial_hash("a" * 130)  # cannot become a hash
    # a SHA-256 typed by hand passes the MD5 and SHA-1 lengths; once it differs from the real one it is a mismatch
    assert core.is_partial_hash(A[:32], [A]) and core.is_partial_hash(A[:40], [A]) and core.is_partial_hash(A[:8], [A])
    assert not core.is_partial_hash(A, [A]) and not core.is_partial_hash("0" * 32, [A])
    assert not core.is_partial_hash(A[:32])  # nothing to be the start of: judged as an MD5


def test_compare_algos_setting():
    old_file = core.CONFIG_FILE
    with tempfile.TemporaryDirectory() as tmp:
        core.CONFIG_FILE = Path(tmp) / "config.json"
        try:
            assert core.compare_algos() == list(core.ALGOS)  # default: everything
            core.set_option("compare_algos", ["crc32", "sha256"])
            assert core.compare_algos() == ["sha256", "crc32"]  # in the usual order
            core.set_option("compare_algos", [])
            assert core.compare_algos() == list(core.ALGOS)  # never none
            sample = Path(tmp, "f")
            sample.write_bytes(b"alpha")
            assert core.hash_file(sample, ["crc32"]) == {"crc32": f"{zlib.crc32(b'alpha'):08x}"}
        finally:
            core.CONFIG_FILE = old_file


def test_mime_type_covers_every_algorithm_the_parser_reads():
    globs = set(re.findall(r'glob pattern="([^"]+)"', (SRC.parent / "data" / "hashtally-mime.xml").read_text()))
    for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        assert {f"*.{algo}", f"*.{algo}sum", f"{algo.upper()}SUMS"} <= globs, algo
    assert "*.sfv" in globs


def test_app_id_matches_installer():
    assert f"APP_ID={core.APP_ID}\n" in (SRC.parent / "install.sh").read_text()


def test_helpers():
    assert core.norm_hash(" SHA256: AB cd\n") == "abcd"
    assert core.looks_like_digest(A) and not core.looks_like_digest("hello world")
    assert core.default_target(["/x/a.iso"], "sha256") == ("/x", "a.iso.sha256")
    assert core.default_target(["/x/a", "/x/b"], "sha512") == ("/x", "SHA512SUMS")
    assert core.default_target(["/x/a", "/x/b"], "crc32") == ("/x", "checksums.sfv")
    assert core.human_size(1536) == "1.5 kB" and core.human_size(5) == "5 B"
    assert core.human_size(1_000_000) == "1.0 MB" and core.human_size(4_200_000_000) == "4.2 GB"  # as Files shows it
    assert core.human_size(999_949) == "999.9 kB" and core.human_size(999_950) == "1.0 MB" and core.human_size(999) == "999 B"  # never "1000.0 kB"
    i18n.set_language("de")
    assert core.human_size(1536) == "1,5 kB" and core.human_size(5) == "5 B"  # decimal comma comes from de.po
    i18n.set_language("en")
    assert [core.algo_name(a) for a in ("sha256", "sha1", "sha224", "md5", "crc32", None)] == [
        "SHA-256", "SHA-1", "SHA-224", "MD5", "CRC32", "?"]
    assert i18n.translate("Cancel", "de") == "Abbrechen" and i18n.translate("Cancel", "xx") == "Cancel"


def test_po_parser_reads_plural_forms():
    with tempfile.TemporaryDirectory() as tmp:
        po = Path(tmp, "x.po")
        po.write_text('msgid "{n} file"\nmsgid_plural "{n} files"\nmsgstr[0] "{n} Datei"\nmsgstr[1] "{n} Dateien"\n', encoding="utf-8")
        assert i18n.load_po(po) == {"{n} file": ["{n} Datei", "{n} Dateien"]}


def test_plural_forms_follow_the_language_rule():
    from unittest import mock
    polish = {"": "Plural-Forms: nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\n",
              "{n} file": ["{n} plik", "{n} pliki", "{n} plików"]}
    old = i18n._current
    try:
        with mock.patch.object(i18n, "_catalog", lambda lang: polish):
            i18n._plural_rule.cache_clear()
            assert [i18n._n("{n} file", "{n} files", n) for n in (1, 2, 5, 22, 25)] == [
                "{n} plik", "{n} pliki", "{n} plików", "{n} pliki", "{n} plików"]
        i18n._plural_rule.cache_clear()
        i18n.set_language("en")
        assert (i18n._n("{n} file", "{n} files", 1), i18n._n("{n} file", "{n} files", 2)) == ("{n} file", "{n} files")
        i18n.set_language("de")
        assert i18n._n("{n} file, {size}", "{n} files, {size}", 1) == "{n} Datei, {size}"
        assert i18n._n("{n} file, {size}", "{n} files, {size}", 4) == "{n} Dateien, {size}"
        for lang in i18n.languages():  # every language finds a form for every number
            i18n.set_language(lang)
            for n in range(130):
                assert "{n}" in i18n._n("{n} file, {size}", "{n} files, {size}", n), (lang, n)
    finally:
        i18n._plural_rule.cache_clear()
        i18n.set_language(old)


def test_po_parser():
    with tempfile.TemporaryDirectory() as tmp:
        po = Path(tmp, "x.po")
        po.write_text(r'''msgid ""
msgstr ""
"Language: x\n"

#: a.py:1
#, python-brace-format
msgid "Hello {name}\n"
"second line"
msgstr "Hallo {name}\n"
"zweite Zeile"

#, fuzzy
msgid "Fuzzy"
msgstr "Unsicher"

msgid "Untranslated"
msgstr ""

#~ msgid "Old"
#~ msgstr "Alt"
''', encoding="utf-8")
        assert i18n.load_po(po) == {"": "Language: x\n", "Hello {name}\nsecond line": "Hallo {name}\nzweite Zeile"}  # "" is the header


def test_translations_match_code():
    """Every language must match the code exactly, keep the placeholders and the number of plural forms,
    and the Nautilus menu titles must stay valid file names."""
    wanted = set()
    for path in SRC.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("_", "N_", "_n")
                    and node.args and isinstance(node.args[0], ast.Constant)):
                wanted.add(node.args[0].value)
    fields = lambda text: sorted(re.findall(r"\{[^}]*\}", text))  # noqa: E731
    for po in sorted(i18n.PO_DIR.glob("*.po")):
        catalog = i18n.load_po(po)
        have = set(catalog) - {""}  # "" is the header
        assert not wanted - have, f"missing in {po.name}: {wanted - have}"
        assert not have - wanted, f"unused in {po.name}: {have - wanted}"
        nplurals = int(re.search(r"nplurals=(\d+)", catalog[""])[1])
        for msgid, msgstr in catalog.items():
            if not msgid:
                continue
            for form in msgstr if isinstance(msgstr, list) else [msgstr]:
                assert fields(msgid) == fields(form), f"{po.name}: placeholders differ in {msgid!r}"
            assert not isinstance(msgstr, list) or len(msgstr) == nplurals, f"{po.name}: wrong number of forms in {msgid!r}"
        assert f"Project-Id-Version: HashTally {core.__version__}\n" in catalog[""], po.name
    assert f'"Project-Id-Version: HashTally {core.__version__}\\n"' in (i18n.PO_DIR / "hashtally.pot").read_text()
    for path in SRC.glob("*.py"):  # xgettext skips f-strings: a _("...") inside one drops out of the template at the next refresh
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.JoinedStr):
                assert not [c for c in ast.walk(node) if isinstance(c, ast.Call) and getattr(c.func, "id", "") in ("_", "N_", "_n")
                            and c.args and isinstance(c.args[0], ast.Constant)], f"{path.name}: translated inside an f-string"
    for lang in i18n.languages():
        for title in core.SCRIPT_ACTIONS.values():
            assert "/" not in i18n.translate(title, lang), f"{lang}: '/' in menu title"


def test_menu_style_and_settings():
    with settings_sandbox():
        flat = core.menu_entries()
        assert core.set_option("menu", "folder") is None  # rebuilds the entries by itself
        assert json.loads(core.CONFIG_FILE.read_text()) == {"menu": "folder"}
        assert sorted(p.name for p in (core.SCRIPTS_DIR / "HashTally").iterdir()) == [
            "Compare files", "Create hash file", "Show or compare hash", "Verify hash file"]
        assert core.menu_entries() != flat and all(p.is_file() for p in core.menu_entries())
        core.set_option("menu", "scripts")  # back: the folder is gone, the flat entries are there
        assert not (core.SCRIPTS_DIR / "HashTally").exists()
        assert core.menu_entries() == flat and all(p.is_file() for p in flat)
        assert json.loads(core.CONFIG_FILE.read_text()) == {}  # only deviations from the defaults are saved
        core.set_option("language", "de")  # the entries follow the language, without leftovers
        assert (core.SCRIPTS_DIR / "HashTally: Hash-Datei erstellen").is_file()
        assert len(list(core.SCRIPTS_DIR.iterdir())) == 4


def test_reset_restores_the_system_language_and_its_entries():
    with settings_sandbox(), environment(LANGUAGE="", LC_ALL="", LC_MESSAGES="", LANG="de_DE.UTF-8"):  # whatever this machine speaks
        core.set_option("language", "en")
        core.set_option("menu", "folder")
        core.set_option("algorithm", "md5")
        assert core.reset_config() is None
        assert core.load_config() == core.DEFAULTS and i18n._current == "de"
        assert sorted(p.name for p in core.SCRIPTS_DIR.iterdir()) == sorted(p.name for p in core.menu_entries())
        assert core.menu_entries()[0].name == "HashTally: Hash-Datei erstellen"
        assert core.reset_config() is None  # nothing saved: still fine


def test_unwritable_settings_give_an_error_text():
    if os.geteuid() == 0:  # root can write anywhere
        return
    with settings_sandbox():
        core.CONFIG_FILE.parent.mkdir()
        core.CONFIG_FILE.parent.chmod(0o500)
        try:
            assert isinstance(core.set_option("algorithm", "md5"), str)
        finally:
            core.CONFIG_FILE.parent.chmod(0o700)
        core.SCRIPTS_DIR.mkdir()
        core.SCRIPTS_DIR.chmod(0o500)  # the entries cannot be rebuilt: the error text comes back, not an exception
        try:
            assert isinstance(core.set_option("menu", "folder"), str)
        finally:
            core.SCRIPTS_DIR.chmod(0o700)


def test_invalid_saved_values_fall_back_to_the_defaults():
    with settings_sandbox():
        core.CONFIG_FILE.parent.mkdir()
        for bad in ({"algorithm": "md4"}, {"menu": "tree"}, {"clipboard": "yes"}, {"language": "xx"},
                    [1, 2], "text", None):
            core.CONFIG_FILE.write_text(json.dumps(bad))
            assert core.load_config() == core.DEFAULTS, bad
        core.CONFIG_FILE.write_text(json.dumps({"algorithm": "md5", "menu": "tree", "unknown": 1}))
        assert core.load_config() == {**core.DEFAULTS, "algorithm": "md5"}  # the valid part is kept


def test_saving_settings_is_atomic_keeps_mode_and_links():
    with settings_sandbox() as tmp:
        core.set_option("algorithm", "md5")
        core.CONFIG_FILE.chmod(0o600)
        core.set_option("clipboard", False)
        assert (core.CONFIG_FILE.stat().st_mode & 0o777) == 0o600
        assert os.listdir(core.CONFIG_FILE.parent) == ["config.json"]  # no .part left behind
        real = tmp / "dotfiles" / "config.json"
        real.parent.mkdir()
        core.CONFIG_FILE.replace(real)
        core.CONFIG_FILE.symlink_to(real)
        core.set_option("algorithm", "sha1")
        assert core.CONFIG_FILE.is_symlink() and json.loads(real.read_text())["algorithm"] == "sha1"


def test_stale_entries_go_whatever_their_name_but_foreign_files_stay():
    with settings_sandbox():
        core.SCRIPTS_DIR.mkdir()
        old = core.SCRIPTS_DIR / "HashTally: Old translation"
        old.write_text("#!/bin/sh\n")
        mine = core.SCRIPTS_DIR / "My own script"
        mine.write_text("#!/bin/sh\n")
        core.set_option("menu", "folder")
        folder = core.SCRIPTS_DIR / "HashTally"
        (folder / "Renamed entry").write_text(core.script_text("--verify"))  # ours, named by an older translation
        (folder / "Not ours").write_text("#!/bin/sh\n")
        (folder / "My check").write_text(f'#!/bin/sh\n{core.LAUNCHER} --compare "$@" >> /tmp/log\n')  # calls us, still not ours
        core.install_scripts()
        assert not old.exists()
        assert sorted(p.name for p in folder.iterdir()) == [
            "Compare files", "Create hash file", "My check", "Not ours", "Show or compare hash", "Verify hash file"]
        core.set_option("menu", "scripts")  # the folder holds foreign files, so it stays
        assert (folder / "Not ours").exists() and mine.exists()


def test_entries_are_recognised_whichever_launcher_wrote_them():
    with settings_sandbox():
        core.SCRIPTS_DIR.mkdir()
        entry = core.SCRIPTS_DIR / "entry"
        old = core.LAUNCHER
        core.LAUNCHER = Path("/tmp/it's here/hashtally")  # a checkout run, an apostrophe in the path
        try:
            entry.write_text(core.script_text("--verify"))
        finally:
            core.LAUNCHER = old
        assert core._ours(entry)
        assert not core._ours(core.SCRIPTS_DIR)  # a folder
        entry.write_bytes(b"\xff\xfe\x00binary")
        assert not core._ours(entry)
        entry.unlink()
        os.mkfifo(entry)  # open() would block on it for ever
        assert not core._ours(entry)


def test_reset_without_a_saved_file_creates_nothing():
    with settings_sandbox():
        assert core.reset_config() is None  # not even the settings folder exists yet
        assert not core.CONFIG_FILE.parent.exists()


def test_reset_keeps_a_settings_file_that_is_a_link():
    with settings_sandbox() as tmp:
        real = tmp / "dotfiles" / "config.json"
        real.parent.mkdir()
        real.write_text('{"algorithm": "md5"}')
        core.CONFIG_FILE.parent.mkdir()
        core.CONFIG_FILE.symlink_to(real)
        assert core.reset_config() is None
        assert core.CONFIG_FILE.is_symlink() and core.load_config() == core.DEFAULTS
        assert json.loads(real.read_text()) == {}  # the file behind the link was emptied, not replaced


def test_a_failing_save_keeps_the_old_file_and_leaves_no_part_behind():
    with settings_sandbox():
        core.set_option("algorithm", "md5")
        real_replace = os.replace

        def failing(*args):
            raise OSError("disk full")
        os.replace = failing
        try:
            assert "disk full" in core.set_option("algorithm", "sha1")
        finally:
            os.replace = real_replace
        assert json.loads(core.CONFIG_FILE.read_text()) == {"algorithm": "md5"}
        assert os.listdir(core.CONFIG_FILE.parent) == ["config.json"]


def test_the_value_a_window_copied_outlives_the_window_and_a_reset_forgets_it():
    with settings_sandbox():
        assert core.set_option("copied", A) is None
        assert core.load_config()["copied"] == A  # a later window compares the clipboard with this
        assert core.reset_config() is None
        assert core.load_config()["copied"] == ""


def test_entries_run_the_installed_launcher_not_the_process_that_wrote_them():
    with settings_sandbox():
        core.install_scripts()
        assert core.LAUNCHER == Path.home() / ".local/bin/hashtally"
        for script in core.menu_entries():
            assert str(core.LAUNCHER) in script.read_text()


def test_language_follows_gettext_with_a_fallback_to_the_locale():
    def detect(**env):
        with environment(**{"LANGUAGE": "", "LC_ALL": "", "LC_MESSAGES": "", "LANG": "", **env}):
            return i18n.detect()
    assert detect(LANGUAGE="nds:de", LANG="en_US.UTF-8") == "de"  # every entry of the list
    assert detect(LANGUAGE="xx:yy", LANG="fr_FR.UTF-8") == "fr"  # gettext would give up here, we use the locale
    assert detect(LC_ALL="es_ES.UTF-8", LANG="de_DE.UTF-8") == "es"  # LC_ALL beats LANG
    assert detect(LC_ALL="C", LANG="de_DE.UTF-8") == "en"  # the usual way to force English
    for locale in ("C", "C.UTF-8", "POSIX"):
        assert detect(LANGUAGE="de", LC_ALL=locale) == "en", locale  # LANGUAGE counts for no locale but a real one
    assert detect(LANG="C") == "en"
    assert detect(LANGUAGE="de") == "en"  # no locale at all is "C"
    assert detect() == "en"


def test_a_digest_that_differs_only_late_is_a_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a").write_bytes(b"alpha")
        for algo, digest in (("sha256", A), ("md5", hashlib.md5(b"alpha").hexdigest())):
            assert core.check(tmp, core.Entry(algo, digest, "a"))[0] == "ok"
            assert core.check(tmp, core.Entry(algo, digest[:8] + "0" * (len(digest) - 8), "a"))[0] == "bad", algo


def test_the_hash_file_does_not_hash_itself():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a").write_bytes(b"alpha")
        out = Path(tmp, "SHA256SUMS")
        out.write_text("old\n")
        assert core.write_hashfile([str(Path(tmp, "a")), str(out)], tmp, "sha256", out) == 1
        assert out.read_text() == f"{A}  a\n"


def test_windows_paths_are_found():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "sub").mkdir()
        Path(tmp, "sub", "a.txt").write_bytes(b"alpha")
        assert core.resolve(tmp, "sub\\a.txt") == os.path.join(tmp, "sub/a.txt")
        assert core.check(tmp, core.Entry("sha256", A, "sub\\a.txt"))[0] == "ok"


def test_b2sum_and_sha3_files_are_not_taken_for_sha2():
    """b2sum prints as many digits as SHA-512, SHA-3 as many as SHA-2: the file name settles it."""
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "f").write_bytes(b"alpha")
        cases = {
            "b2sums.txt": (hashlib.blake2b(b"alpha").hexdigest() + "  f\n", ("blake2b", "ok")),
            "tagged.b2": (f"BLAKE2b (f) = {hashlib.blake2b(b'alpha').hexdigest()}\n", ("blake2b", "ok")),
            "sha3sums.txt": (hashlib.sha3_256(b"alpha").hexdigest() + "  f\n", (None, "unknown")),
            "SHA512SUMS": (hashlib.sha512(b"alpha").hexdigest() + "  f\n", ("sha512", "ok")),
            "SHA256SUMS": (A + "  f\n", ("sha256", "ok")),
        }
        for name, (content, expected) in cases.items():
            Path(tmp, name).write_text(content)
            (entry,) = core.parse(Path(tmp, name))
            assert (entry.algo, core.check(tmp, entry)[0]) == expected, name
        assert core.algo_name("blake2b") == "BLAKE2b"


def test_names_that_are_no_utf8_are_written_byte_for_byte_and_shown_with_a_replacement():
    with tempfile.TemporaryDirectory() as tmp:
        bad = os.path.join(os.fsencode(tmp), b"M\xe4rz.txt")
        Path(os.fsdecode(bad)).write_bytes(b"alpha")
        out = Path(tmp, "SHA256SUMS")
        assert core.write_hashfile([os.fsdecode(bad)], tmp, "sha256", out) == 1
        assert out.read_bytes() == A.encode() + b"  M\xe4rz.txt\n" and not Path(tmp, "SHA256SUMS.part").exists()
    assert core.shown(os.fsdecode(b"M\xe4rz.txt")) == "M\ufffdrz.txt" and core.shown("März") == "März"


def test_menu_entries_end_the_options_before_the_names():
    for flag in core.SCRIPT_ACTIONS:
        assert f' {flag} -- "$@"' in core.script_text(flag)  # a name that starts with "-" is no option


def test_desktop_starters_quote_the_launcher():
    for template in (SRC.parent / "data").glob("*.desktop.in"):
        lines = [l for l in template.read_text().splitlines() if l.startswith("Exec=")]
        assert lines and all(l.startswith('Exec="@LAUNCHER@"') for l in lines), template.name  # a home path may hold a space


def test_the_compare_window_finds_the_hash_a_hash_file_lists():
    h = lambda data, algo="sha256": hashlib.new(algo, data).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        iso = os.path.join(tmp, "ubuntu.iso")
        Path(iso).write_bytes(b"alpha")
        assert core.expected_hash(iso, ["sha256"]) is None  # nothing next to it
        Path(tmp, "SHA256SUMS").write_text(f"{h(b'beta')}  other.iso\n{A} *ubuntu.iso\n")  # several files: ours is picked
        assert core.expected_hash(iso, ["sha256"]) == (A, "SHA256SUMS")
        assert core.expected_hash(iso, ["md5"]) is None  # an algorithm the window does not calculate is no answer
        Path(tmp, "SHA256SUMS").write_text(f"{h(b'beta')}  other.iso\n{h(b'x')}  ubuntu.iso.old\n{A}  ./sub/ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256"]) is None  # another name, or another folder, is another file
        Path(tmp, "SHA256SUMS").write_text(f"{A}  .\\ubuntu.iso\n")  # a Windows path in front of the name
        assert core.expected_hash(iso, ["sha256"]) == (A, "SHA256SUMS")
        Path(tmp, "SHA256SUMS").unlink()
        Path(tmp, "ubuntu.iso.hash").write_text(A + "\n")  # any file named after it
        assert core.expected_hash(iso, ["sha256"]) == (A, "ubuntu.iso.hash")
        Path(tmp, "ubuntu.iso.hash").unlink()
        Path(tmp, "ubuntu.iso.sha256").write_text(A + "\n")  # a file with the digest only
        assert core.expected_hash(iso, ["sha256"]) == (A, "ubuntu.iso.sha256")
        Path(tmp, "ubuntu.iso.sha256").unlink()
        Path(tmp, "b2sums.txt").write_text(hashlib.blake2b(b"alpha").hexdigest() + "  ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256", "sha512"]) is None  # as long as SHA-512, but not SHA-512
        Path(tmp, "x.sha256").mkdir()  # a folder or a broken link with such a name is skipped
        os.symlink(os.path.join(tmp, "gone"), os.path.join(tmp, "y.sha256"))
        assert core.expected_hash(iso, ["sha256"]) is None
        assert core.expected_hash(os.path.join(tmp, "nowhere", "f"), ["sha256"]) is None


def test_expected_hash_prefers_the_strongest_algorithm_and_keeps_the_case_of_names():
    with tempfile.TemporaryDirectory() as tmp:
        iso = os.path.join(tmp, "ubuntu.iso")
        Path(iso).write_bytes(b"alpha")
        Path(tmp, "MD5SUMS").write_text(hashlib.md5(b"alpha").hexdigest() + "  ubuntu.iso\n")
        Path(tmp, "SHA256SUMS").write_text(A + "  ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256", "md5"]) == (A, "SHA256SUMS")  # the order of `algos` decides, not the file names
        assert core.expected_hash(iso, ["md5"])[1] == "MD5SUMS"
        Path(tmp, "SHA256SUMS").write_text(A + "  Ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256"]) is None  # another name on a case-sensitive disk is another file
        os.rename(Path(tmp, "SHA256SUMS"), Path(tmp, "sha256sum.txt"))  # the name Linux Mint publishes
        Path(tmp, "sha256sum.txt").write_text(A + " *ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256"]) == (A, "sha256sum.txt")
        assert 'glob pattern="sha256sum.txt"' in (SRC.parent / "data" / "hashtally-mime.xml").read_text()  # and a double-click opens it


def test_expected_hash_skips_a_hash_file_it_cannot_read():
    if os.geteuid() == 0:
        return  # root reads everything
    with tempfile.TemporaryDirectory() as tmp:
        iso = os.path.join(tmp, "ubuntu.iso")
        Path(iso).write_bytes(b"alpha")
        Path(tmp, "AAASUMS").write_text(A + "  ubuntu.iso\n")
        Path(tmp, "AAASUMS").chmod(0)
        Path(tmp, "SHA256SUMS").write_text(A + "  ubuntu.iso\n")
        assert core.expected_hash(iso, ["sha256"]) == (A, "SHA256SUMS")


def test_the_installer_fetches_the_release_it_belongs_to():
    text = (SRC.parent / "install.sh").read_text()
    assert re.search(r'^VERSION="([^"]+)"', text, re.M).group(1) == core.__version__
    assert "refs/heads" not in text  # a branch moves on; a release tag does not
    # a tag can be moved too: the release workflow pins the commit in the copy it attaches, which must then fetch that commit
    assert len(re.findall(r'^COMMIT=""', text, re.M)) == 1 and "archive/${COMMIT:-refs/tags/v$VERSION}.tar.gz" in text
    assert 's/^COMMIT=\\"\\"/COMMIT=' in (SRC.parent / ".github/workflows/release.yml").read_text()


# --------------------------------------------------------------------------- terminal mode (cli.py, and how hashtally.py picks it)

def run_cli(function, *args):
    """(exit code, stdout, stderr) of a cli function, in English and with the settings in a temporary folder."""
    out, err = io.StringIO(), io.StringIO()
    with settings_sandbox(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function(*args)
    return code, out.getvalue(), err.getvalue()


def cli_folder(tmp):
    """a.txt and b.txt with a SHA256SUMS that lists both."""
    Path(tmp, "a.txt").write_bytes(b"alpha")
    Path(tmp, "b.txt").write_bytes(b"beta")
    sums = Path(tmp, "SHA256SUMS")
    sums.write_text(f"{A}  a.txt\n{B}  b.txt\n")
    return str(sums)


def test_cli_verify_says_success_and_lists_every_file():
    with tempfile.TemporaryDirectory() as tmp:
        code, out, err = run_cli(cli.verify, [cli_folder(tmp)])
        assert code == cli.OK and err == "", (code, err)
        assert "SUCCESS" in out and "2 files verified" in out and "a.txt" in out and "b.txt" in out, out
        assert "Checksums for Nautilus" in out  # the banner


def test_cli_verify_reports_a_mismatch_a_missing_file_and_exits_with_one():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        Path(tmp, "a.txt").write_bytes(b"tampered")
        os.remove(Path(tmp, "b.txt"))
        code, out, _err = run_cli(cli.verify, [sums])
        assert code == cli.FAILED, code
        assert "FAILED" in out and "MISMATCH" in out and "MISSING" in out, out
        assert A in out and hashlib.sha256(b"tampered").hexdigest() in out  # expected and found are both printed
        assert "SUCCESS" not in out


def test_cli_verify_a_folder_that_lacks_every_listed_file_fails():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        os.remove(Path(tmp, "a.txt"))
        os.remove(Path(tmp, "b.txt"))
        code, out, _err = run_cli(cli.verify, [sums])
        assert code == cli.FAILED and "FAILED" in out and "None of the files were found" in out, out


def test_cli_verify_some_missing_files_alone_are_no_failure():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        os.remove(Path(tmp, "b.txt"))
        code, out, _err = run_cli(cli.verify, [sums])
        assert code == cli.OK and "MISSING" in out and "1 file verified" in out and "1 missing" in out, out


def test_cli_quiet_leaves_out_the_banner_and_the_files_that_are_fine():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        Path(tmp, "a.txt").write_bytes(b"tampered")
        code, out, _err = run_cli(cli.verify, [sums], True)
        assert code == cli.FAILED and "Checksums for Nautilus" not in out, out
        assert "MISMATCH" in out and "b.txt" not in out  # b.txt is fine and stays out of the list


def test_cli_verify_unusable_input_exits_with_two_and_speaks_on_stderr():
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp, "SHA256SUMS")
        empty.write_text("nothing that is a checksum\n")
        for paths, text in (([], "No file selected"), ([str(Path(tmp, "nope.sha256"))], "Cannot read file"), ([str(empty)], "No checksums found")):
            code, out, err = run_cli(cli.verify, paths)
            assert code == cli.USAGE and err.startswith("hashtally: ") and text in err, (paths, code, err)
            assert "SUCCESS" not in out


def test_cli_verify_several_hash_files_exits_with_the_worst_result():
    with tempfile.TemporaryDirectory() as good, tempfile.TemporaryDirectory() as bad:
        first, second = cli_folder(good), cli_folder(bad)
        Path(bad, "a.txt").write_bytes(b"tampered")
        assert run_cli(cli.verify, [first, second])[0] == cli.FAILED
        assert run_cli(cli.verify, [second, first])[0] == cli.FAILED  # the order does not matter
        assert run_cli(cli.verify, [first, first])[0] == cli.OK


def test_cli_create_writes_a_hash_file_that_verifies_and_never_replaces_one_unasked():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        target = Path(tmp, "a.txt.sha256")
        code, out, _err = run_cli(cli.create, [str(Path(tmp, "a.txt"))], "sha256", None, False)
        assert code == cli.OK and "SUCCESS" in out and "wrote a.txt.sha256 with 1 checksum" in out, out
        assert target.read_text().split()[0] == A
        assert run_cli(cli.verify, [str(target)])[0] == cli.OK
        target.write_text("precious\n")
        code, out, err = run_cli(cli.create, [str(Path(tmp, "a.txt"))], "sha256", None, False)
        assert code == cli.USAGE and "already exists" in err and "--force" in err and target.read_text() == "precious\n"
        code, _out, _err = run_cli(cli.create, [str(Path(tmp, "a.txt"))], "sha256", None, True)  # --force
        assert code == cli.OK and target.read_text().split()[0] == A


def test_cli_create_takes_the_algorithm_and_the_output_name_and_keeps_names_relative_to_the_file():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "sub").mkdir()
        Path(tmp, "sub", "a.txt").write_bytes(b"alpha")
        Path(tmp, "out").mkdir()
        out_file = Path(tmp, "out", "list.md5")
        code, _out, _err = run_cli(cli.create, [str(Path(tmp, "sub"))], "md5", str(out_file), False)
        assert code == cli.OK
        entries = core.parse(str(out_file))
        assert [e.algo for e in entries] == ["md5"] and entries[0].digest == hashlib.md5(b"alpha").hexdigest()
        assert [e.name for e in entries] == ["../sub/a.txt"]  # relative to where the hash file lies
        assert run_cli(cli.verify, [str(out_file)])[0] == cli.OK


def test_cli_create_without_files_or_with_a_missing_one_exits_with_two():
    with tempfile.TemporaryDirectory() as tmp:
        assert run_cli(cli.create, [], "sha256", None, False)[0] == cli.USAGE
        code, _out, err = run_cli(cli.create, [str(Path(tmp, "nope"))], "sha256", None, False)
        assert code == cli.USAGE and err.startswith("hashtally: ")
        assert not list(Path(tmp).iterdir())  # nothing was written


def test_cli_compare_matches_a_pasted_hash_and_says_no_match_otherwise():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "a.txt")
        path.write_bytes(b"alpha")
        code, out, _err = run_cli(cli.compare, [str(path), A.upper()])  # the case of a pasted hash does not matter
        assert code == cli.OK and "matches" in out and "<== matches" in out, out
        code, out, _err = run_cli(cli.compare, [str(path), B])
        assert code == cli.FAILED and "No match" in out and B in out and "<== matches" not in out, out


def test_cli_compare_without_a_hash_shows_them_and_uses_a_hash_file_next_to_the_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, "a.txt")
        path.write_bytes(b"alpha")
        code, out, _err = run_cli(cli.compare, [str(path)])
        assert code == cli.OK and A in out and "hashtally --compare a.txt HASH" in out, out
        Path(tmp, "a.txt.sha256").write_text(f"{A}  a.txt\n")
        code, out, _err = run_cli(cli.compare, [str(path)])
        assert code == cli.OK and "a.txt.sha256 lists this file" in out and "<== matches" in out, out
        Path(tmp, "a.txt.sha256").write_text(f"{B}  a.txt\n")
        assert run_cli(cli.compare, [str(path)])[0] == cli.FAILED  # the list says something else


def test_cli_compare_needs_exactly_one_existing_file():
    with tempfile.TemporaryDirectory() as tmp:
        for args in ([], [str(Path(tmp, "nope"))], [tmp], [str(Path(tmp, "a")), A, A]):
            code, _out, err = run_cli(cli.compare, args)
            assert code == cli.USAGE and "Please select one or two files" in err, args


def test_cli_compares_two_files_and_lists_what_the_hash_file_misses():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        Path(tmp, "copy.txt").write_bytes(b"alpha")
        Path(tmp, "other.txt").write_bytes(b"alphb")
        code, out, _err = run_cli(cli.compare, [str(Path(tmp, "a.txt")), str(Path(tmp, "copy.txt"))])
        assert code == cli.OK and "Files are identical" in out and A in out, out
        code, out, _err = run_cli(cli.compare, [str(Path(tmp, "a.txt")), str(Path(tmp, "other.txt"))])
        assert code == cli.FAILED and "Files differ" in out and "different sizes" not in out, out
        code, out, _err = run_cli(cli.compare, [str(Path(tmp, "a.txt")), str(Path(tmp, "b.txt"))])
        assert code == cli.FAILED and "The files have different sizes" in out, out
        code, out, _err = run_cli(cli.compare_two, [str(Path(tmp, "a.txt")), str(Path(tmp, "copy.txt"))])
        assert code == cli.OK and "Files are identical" in out, out
        code, out, _err = run_cli(cli.compare_two, [str(Path(tmp, "a.txt")), A])  # a hash is no second file here
        assert code == cli.USAGE and "exactly two files" in _err + out, (out, _err)
        code, out, _err = run_cli(cli.verify, [sums])
        assert code == cli.OK and "but not in it" not in out, out  # off by default
        with mock.patch.object(core, "load_config", lambda: {**core.DEFAULTS, "unlisted": True}):
            code, out, _err = run_cli(cli.verify, [sums])
            assert code == cli.OK and "2 files in the folders of this list, but not in it" in out and "copy.txt" in out, out  # a hint, no failure


def test_cli_adds_to_an_existing_hash_file_only_when_asked():
    with tempfile.TemporaryDirectory() as tmp:
        a, b, out_file = (str(Path(tmp, n)) for n in ("a.txt", "b.txt", "SHA256SUMS"))
        Path(a).write_bytes(b"alpha")
        core.write_hashfile([a], tmp, "sha256", out_file)
        os.utime(out_file, (time.time() + 10, time.time() + 10))
        Path(b).write_bytes(b"beta")
        assert run_cli(cli.create, [a, b], "sha256", None, False, True)[0] == cli.USAGE  # it exists, and neither --update nor --force was given
        code, out, _err = run_cli(cli.create, [a, b], "sha256", None, False, True, True)
        assert code == cli.OK and "updated SHA256SUMS" in out and "Added: 1 · Changed: 0 · Unchanged: 1" in out, out
        assert {e.name: e.digest for e in core.parse(out_file)} == {"a.txt": A, "b.txt": B}
        Path(tmp, "bad").write_text("not a hash file\n")
        assert run_cli(cli.create, [a, b], "sha256", str(Path(tmp, "bad")), False, True, True)[0] == cli.USAGE  # cannot be updated: say so


def test_cli_draws_no_progress_bar_and_no_colour_when_it_is_no_terminal():
    with tempfile.TemporaryDirectory() as tmp:
        _code, out, err = run_cli(cli.verify, [cli_folder(tmp)])
        assert "\x1b" not in out + err and "\r" not in out + err, repr(out + err)  # a log stays clean
        assert not cli.Progress(10).on


def test_cli_cut_keeps_both_ends_of_a_long_name():
    assert cli._cut("short.txt", 20) == "short.txt"
    cut = cli._cut("a-very-long-file-name-with-a-tail.tar.gz", 20)
    assert len(cut) == 20 and cut.startswith("a-very") and cut.endswith("tar.gz") and "…" in cut, cut


class TtyOut(io.StringIO):
    def isatty(self):
        return True


def run_main(argv, tty):
    """(exit code, stdout) of hashtally.main() started with `argv`; stdout is a terminal or not. ui_gtk is replaced by a
    stand-in that records what the window would have been asked to open, so no window ever opens."""
    opened = []
    window = types.ModuleType("ui_gtk")
    window.run = lambda mode, paths: opened.append((mode, paths))
    out = TtyOut() if tty else io.StringIO()
    with settings_sandbox(), mock.patch.object(sys, "argv", ["hashtally", *argv]), mock.patch.object(sys, "stdout", out), \
            contextlib.redirect_stderr(io.StringIO()), mock.patch.dict(sys.modules, {"ui_gtk": window}):
        core.CONFIG_FILE.parent.mkdir(parents=True)
        core.CONFIG_FILE.write_text('{"language": "en"}')  # main() reads the language from the settings: not the test machine's
        try:
            hashtally.main()
            code = None
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), opened


def test_a_terminal_gets_text_and_the_file_manager_gets_the_window():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        code, out, opened = run_main([sums], tty=True)
        assert code == 0 and "SUCCESS" in out and opened == [], (code, out)
        code, out, opened = run_main([sums], tty=False)  # Nautilus scripts and launchers: no terminal
        assert code is None and out == "" and opened == [("verify", [sums])], (code, out, opened)


def test_gui_asks_for_the_window_even_in_a_terminal_and_settings_always_is_one():
    with tempfile.TemporaryDirectory() as tmp:
        sums = cli_folder(tmp)
        code, out, opened = run_main(["--gui", sums], tty=True)
        assert code is None and out == "" and opened == [("verify", [sums])]
        code, out, opened = run_main([], tty=True)  # no files: the settings window
        assert code is None and out == "" and opened == [("settings", [])]


def test_prune_without_update_is_an_error_not_silently_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        cli_folder(tmp)
        assert run_main(["--create", "--prune", str(Path(tmp, "a.txt"))], tty=True)[0] == 2  # argparse's usage error
        assert run_main(["--create", "--update", "--prune", str(Path(tmp, "a.txt"))], tty=True)[0] == 0  # together they are accepted


def test_a_file_that_vanishes_before_the_compare_is_an_error_message_not_a_traceback():
    with tempfile.TemporaryDirectory() as tmp:
        a = Path(tmp, "a")
        a.write_bytes(b"x")
        for call in (lambda: cli.compare_files(str(a), str(Path(tmp, "gone"))), lambda: cli.compare_files(str(Path(tmp, "gone")), str(a))):
            code, _out, err = run_cli(call)
            assert code == cli.USAGE and err.startswith("hashtally:"), (code, err)
        with mock.patch("os.path.getsize", side_effect=FileNotFoundError("gone")):  # the only file of a one-file compare vanishes
            assert run_cli(cli.compare, [str(a)])[0] == cli.USAGE


def test_the_terminal_modes_get_their_options_and_hand_back_the_exit_code():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        out_file = Path(tmp, "x.sha1")
        code, out, opened = run_main(["--create", "--algo", "sha1", "-o", str(out_file), "-q", str(Path(tmp, "a.txt"))], tty=True)
        assert code == 0 and opened == [] and "Checksums for Nautilus" not in out, out
        assert core.parse(str(out_file))[0].algo == "sha1"
        code, _out, _opened = run_main(["--create", "--algo", "sha1", "-o", str(out_file), str(Path(tmp, "a.txt"))], tty=True)
        assert code == cli.USAGE  # it exists: --force is needed
        assert run_main(["--create", "--force", "--algo", "sha1", "-o", str(out_file), str(Path(tmp, "a.txt"))], tty=True)[0] == 0
        code, out, _opened = run_main(["--compare", str(Path(tmp, "a.txt")), B], tty=True)
        assert code == cli.FAILED and "No match" in out
        Path(tmp, "a.txt").write_bytes(b"tampered")
        assert run_main(["--verify", str(out_file)], tty=True)[0] == cli.FAILED


def test_two_files_are_compared_by_content():
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("a", b"alpha"), ("b", b"alpha"), ("c", b"alphb"), ("d", b"longer")):
            Path(tmp, name).write_bytes(data)
        p = lambda n: str(Path(tmp, n))
        same, da, db = core.compare_files(p("a"), p("b"))
        assert same and da == db == A
        same, da, db = core.compare_files(p("a"), p("c"))
        assert not same and da != db and da == A  # same size, other content
        assert core.compare_files(p("a"), p("d")) == (False, None, None)  # other size: not read at all


def test_files_the_list_does_not_name_are_found():
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("a.txt", "b.txt", "new.txt", "sub/x.txt", "sub/deep/new.txt", "other/y.txt", "SHA256SUMS.asc", "x.part"):
            Path(tmp, name).parent.mkdir(parents=True, exist_ok=True)
            Path(tmp, name).write_bytes(b"x")
        out = os.path.join(tmp, "SHA256SUMS")
        core.write_hashfile([os.path.join(tmp, n) for n in ("a.txt", "b.txt", "sub/x.txt")], tmp, "sha256", out)
        found = core.unlisted_files(tmp, core.parse(out), out)
        # the list covers the folder itself and "sub"; "other" holds nothing of it; the signature and the leftover are no news
        assert [os.path.relpath(f, tmp) for f in found] == ["new.txt", "sub/deep/new.txt"]
        core.write_hashfile([os.path.join(tmp, "a.txt")], tmp, "sha256", out)
        assert core.unlisted_files(tmp, core.parse(out), out) == []  # one file: a download's checksum, the folder is not its business


def test_a_hash_file_is_updated_with_what_is_new_or_changed():
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("a.txt", b"alpha"), ("b.txt", b"beta"), ("gone.txt", b"x")):
            Path(tmp, name).write_bytes(data)
        out = os.path.join(tmp, "SHA256SUMS")
        core.write_hashfile(core.collect_files([tmp]), tmp, "sha256", out)
        os.utime(out, (time.time() + 10, time.time() + 10))  # written after the files, as in real life
        assert core.plan_update(core.collect_files([tmp]), tmp, out).todo == []  # nothing new, nothing changed
        Path(tmp, "new.txt").write_bytes(b"new")
        Path(tmp, "b.txt").write_bytes(b"beta2")
        os.utime(Path(tmp, "b.txt"), (time.time() + 20, time.time() + 20))
        os.remove(Path(tmp, "gone.txt"))
        files = core.collect_files([tmp])
        plan = core.plan_update(files, tmp, out)
        assert (plan.algo, plan.added, plan.changed, plan.unchanged, plan.gone) == ("sha256", 1, 1, 1, 1), plan  # a.txt untouched
        assert sorted(k for _f, k in plan.todo) == ["b.txt", "new.txt"]
        core.write_update(plan, tmp, out, drop_gone=False)
        got = {e.name: e.digest for e in core.parse(out)}
        assert got == {"a.txt": A, "b.txt": hashlib.sha256(b"beta2").hexdigest(), "gone.txt": hashlib.sha256(b"x").hexdigest(),
                       "new.txt": hashlib.sha256(b"new").hexdigest()}  # the entry of the deleted file stays, in its place
        assert [e.name for e in core.parse(out)] == ["a.txt", "b.txt", "gone.txt", "new.txt"]
        core.write_update(core.plan_update(files, tmp, out), tmp, out, drop_gone=True)
        assert [e.name for e in core.parse(out)] == ["a.txt", "b.txt", "new.txt"]
        assert not os.path.exists(out + ".part")


def test_a_hash_file_that_cannot_be_updated_is_not_offered():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        files = core.collect_files([tmp])
        assert core.plan_update(files, tmp, os.path.join(tmp, "none")) is None  # does not exist
        mixed = Path(tmp, "mixed")
        mixed.write_text(f"{A}  a.txt\n{hashlib.md5(b'alpha').hexdigest()}  b.txt\n")
        assert core.plan_update(files, tmp, str(mixed)) is None  # two algorithms
        junk = Path(tmp, "junk")
        junk.write_text(f"{A}  a.txt\nthis is not a checksum\n")
        assert core.plan_update(files, tmp, str(junk)) is None  # a line that would be lost
        link = Path(tmp, "link")
        os.symlink(mixed, link)
        assert core.plan_update(files, tmp, str(link)) is None
        signed = Path(tmp, "signed")
        signed.write_text(f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{A}  a.txt\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n")
        assert core.plan_update(files, tmp, str(signed)) is None  # rewriting it would break the signature


def test_an_update_keeps_names_and_edits_that_come_in_between():
    with tempfile.TemporaryDirectory() as tmp:
        for name in ("Äpfel.txt", "a.txt", "b.txt"):
            Path(tmp, name).write_bytes(name.encode())
        out = os.path.join(tmp, "SHA256SUMS")
        core.write_hashfile(core.collect_files([tmp]), tmp, "sha256", out)
        os.utime(out, (time.time() + 10, time.time() + 10))
        # an edit after the plan is not lost for good: the new file is dated as of the plan, so the edit is newer than it
        Path(tmp, "c.txt").write_bytes(b"c")
        plan = core.plan_update(core.collect_files([tmp]), tmp, out)
        assert [t for _f, t in plan.todo] == ["c.txt"]
        Path(tmp, "a.txt").write_bytes(b"edited")
        core.write_update(plan, tmp, out, drop_gone=False)
        assert [t for _f, t in core.plan_update(core.collect_files([tmp]), tmp, out).todo] == ["a.txt"]
        # a file that is no UTF-8 reads as Latin-1: not offered, nothing is garbled
        raw = Path(tmp, "caf\udce9.txt")
        raw.write_bytes(b"x")
        bad = Path(tmp, "latin")
        bad.write_bytes(f"{A}  ".encode() + os.fsencode(raw.name) + b"\n" + f"{A}  a.txt\n".encode())
        assert core.plan_update(core.collect_files([tmp]), tmp, str(bad)) is None
        assert core.unlisted_files(tmp, core.parse(str(bad)), str(bad)) == []
        # a detached signature next to the list: not offered
        Path(out + ".asc").write_text("x")
        assert core.plan_update(core.collect_files([tmp]), tmp, out) is None


def test_absolute_and_parent_names_are_one_file_and_no_reason_to_walk_up():
    with tempfile.TemporaryDirectory() as tmp:
        dl = Path(tmp, "dl")
        (dl / "sub").mkdir(parents=True)
        Path(tmp, "other").mkdir()
        Path(tmp, "other", "x.txt").write_bytes(b"x")
        (dl / "a").write_bytes(b"alpha")
        (dl / "b").write_bytes(b"beta")
        out = str(dl / "SHA256SUMS")
        Path(out).write_text(f"{'0' * 64}  {dl / 'a'}\n{A}  b\n{A}  ../other/x.txt\n")
        os.utime(out, (time.time() + 10, time.time() + 10))
        plan = core.plan_update([str(dl / "a"), str(dl / "b")], str(dl), out)
        assert (plan.added, plan.unchanged) == (0, 2)  # the absolute entry is a.txt's, not a stranger
        assert core.unlisted_files(str(dl), core.parse(out), out) == []  # nothing of ../other, and sub/ is empty


def test_an_sfv_is_updated_as_an_sfv():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.txt").write_bytes(b"alpha")
        out = os.path.join(tmp, "x.sfv")
        core.write_hashfile(core.collect_files([tmp]), tmp, "crc32", out)
        os.utime(out, (time.time() + 10, time.time() + 10))
        Path(tmp, "b.txt").write_bytes(b"beta")
        core.write_update(core.plan_update(core.collect_files([tmp]), tmp, out), tmp, out, drop_gone=False)
        text = Path(out).read_text()
        assert text.startswith("; Created by HashTally\n") and [e.name for e in core.parse(out)] == ["a.txt", "b.txt"]
        assert [core.check(tmp, e)[0] for e in core.parse(out)] == ["ok", "ok"]


def test_signed_file():
    """A detached signature names the file it signs; a clear-signed hash list called .asc is a hash file, not a signature."""
    with tempfile.TemporaryDirectory() as tmp:
        sig = Path(tmp, "install.sh.asc")
        sig.write_bytes(b"-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n")
        assert core.signed_file(str(sig)) == str(Path(tmp, "install.sh"))  # the file need not be there: the caller says so
        assert core.signed_file(str(Path(tmp, "install.sh"))) is None
        listing = Path(tmp, "SHA256SUMS.asc")
        listing.write_text("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + "a" * 64 + "  x.txt\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n")
        assert core.signed_file(str(listing)) is None


def test_update_check():
    """Versions compare as numbers, a bad answer is refused, the weekly check is off by default and waits a week."""
    assert core.version_tuple("v1.10") > core.version_tuple("1.9") and core.version_tuple("1.2") == (1, 2)
    assert core.version_tuple("latest") is None and core.version_tuple("1.2-beta") is None

    def answer(tag, url="https://github.com/DigitGram/hashtally/releases/tag/v9"):
        return contextlib.nullcontext(io.BytesIO(json.dumps({"tag_name": tag, "html_url": url}).encode()))
    with mock.patch("urllib.request.urlopen", return_value=answer("v99.0")):
        assert core.newer_release()[0] == "99.0"
    with mock.patch("urllib.request.urlopen", return_value=answer("v" + core.__version__)):
        assert core.newer_release() is None  # the same version is not news
    for bad in (answer("nightly"), answer("v99", "https://evil.example/")):
        with mock.patch("urllib.request.urlopen", return_value=bad):
            try:
                core.newer_release()
            except ValueError:
                continue
            raise AssertionError("a strange answer was accepted")
    old_file = core.CONFIG_FILE
    with tempfile.TemporaryDirectory() as tmp:
        core.CONFIG_FILE = Path(tmp) / "config.json"
        try:
            assert not core.update_due()  # off by default
            core.set_option("update_check", True)
            assert core.update_due()
            core.set_option("update_last", int(time.time()))
            assert not core.update_due()
            assert core.update_due(time.time() + core.UPDATE_INTERVAL + 1)
            with mock.patch("os.path.exists", return_value=True):  # in a Flatpak the store updates
                assert not core.update_due(time.time() + 10 * core.UPDATE_INTERVAL)
        finally:
            core.CONFIG_FILE = old_file


def test_extension_available_is_false_without_the_library():
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(core.glob, "glob", lambda pattern: [tmp]):
        assert core.extension_available() is False
        Path(tmp, "libnautilus-python.so").write_text("")
        assert core.extension_available() is True


def test_the_menu_name_is_tidied_and_empty_means_the_default():
    with settings_sandbox():
        assert core.load_config()["menu_name"] == ""
        core.set_option("menu_name", "  My   hashes \n")
        assert core.load_config()["menu_name"] == "My hashes"
        core.set_option("menu_name", "x" * 100)
        assert len(core.load_config()["menu_name"]) == 40
        core.set_option("menu_name", "")
        assert core.load_config()["menu_name"] == ""


def test_a_file_that_is_not_ours_is_never_replaced_by_the_extension():
    with settings_sandbox(), mock.patch.object(core, "extension_available", lambda: True):
        core.EXTENSION_FILE.parent.mkdir(parents=True)
        core.EXTENSION_FILE.write_text("# somebody else's extension\n")
        error = core.set_option("extension", True)
        assert error and str(core.EXTENSION_FILE) in error
        assert core.EXTENSION_FILE.read_text() == "# somebody else's extension\n" and not core.MENU_FILE.exists()
        assert core.load_config()["extension"] is False  # the setting does not claim what did not happen
        assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4  # the Scripts entries stay


def test_when_python3_nautilus_goes_away_the_scripts_come_back():
    with settings_sandbox():
        with mock.patch.object(core, "extension_available", lambda: True):
            core.set_option("extension", True)
            assert core.EXTENSION_FILE.is_file() and not list(core.SCRIPTS_DIR.glob("HashTally: *"))
        with mock.patch.object(core, "extension_available", lambda: False):
            core.sync_entries()
            assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4
            assert not core.EXTENSION_FILE.exists() and not core.MENU_FILE.exists()
            core.sync_entries()  # nothing left to do: no error and no change
            assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4


def test_a_fork_linked_to_the_files_folder_keeps_its_entries_with_the_extension_on():
    with settings_sandbox(), mock.patch.object(core, "extension_available", lambda: True), \
            mock.patch.object(core.shutil, "which", lambda name: "/usr/bin/nemo" if name == "nemo" else None):
        core.SCRIPTS_DIR.mkdir()
        core.FORKS["nemo"].symlink_to(core.SCRIPTS_DIR)
        assert core.set_option("extension", True) is None
        assert len(list(core.SCRIPTS_DIR.glob("HashTally: *"))) == 4  # Nemo has no extension: it needs them


def test_a_hand_edited_menu_name_is_tidied_when_it_is_read():
    with settings_sandbox():
        core.CONFIG_FILE.parent.mkdir(parents=True)
        core.CONFIG_FILE.write_text(json.dumps({"menu_name": "  a \n  b " + "x" * 100}))
        name = core.load_config()["menu_name"]
        assert name.startswith("a b x") and len(name) == 40


def test_the_extension_survives_a_bad_menu_file_and_shows_a_plain_underscore():
    if nautilus_ext.Nautilus is None:  # CI without python3-nautilus
        return
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(nautilus_ext, "MENU_FILE", Path(tmp, "menu.json")):
        menu, target = nautilus_ext.HashTallyMenu(), str(Path(tmp, "f"))
        Path(target).write_text("x")
        assert menu._menu([target]) == []  # not written yet
        for text in ("[]", "{}", "not json", '{"name": 1, "labels": []}'):
            Path(tmp, "menu.json").write_text(text)
            assert menu._menu([target]) == [], text
        Path(tmp, "menu.json").write_text(json.dumps({"launcher": "/bin/true", "name": "My_sums", "labels": {f: f for f in nautilus_ext.ORDER}}))
        items = menu._menu([target])
        assert [i.props.label for i in items] == ["My__sums"]  # "__" is a plain underscore in a GTK menu



if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
            print("ok", name)

