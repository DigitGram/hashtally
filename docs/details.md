# HashTally in detail

Reference for the things the [README](../README.md) only sums up.

## Verify window

The window puts the verdict first: a ring shows how many files match (green), differ (red) or could not be checked
(yellow), with a one-line summary below it, and the signature right under it. While it runs, the ring shows the progress,
with speed and time left, and the file being checked. Problems are grouped by kind (*Mismatch*, *Unknown*, *Error*); a
mismatch shows the expected and the found hash in blocks of eight, one below the other, so they are easy to compare. The
files that are fine are folded into one row that lists them when unfolded.

Files the list names but the folder lacks are folded the same way, as long as any file of the list was found: a
distribution's `SHA256SUMS` lists all its images, and you usually download one. The summary still counts them, so a file
missing from a backup does not go unnoticed: the ring then shows a yellow part and a figure such as 2/3 instead of the check.
When every file matches but the signature could not be checked (public key missing, key expired, gpg failed), the check
carries a small warning triangle. A plain green check means there is nothing left to read. Only when none of the files is
there is that the verdict.

The window is as tall as its content needs (a clean result stays small) and keeps the size you give it.

## Create and compare

- **Create** names the hash file after the selection: `name.sha256` for a single file or folder (a folder gives
  `Folder.sha256` next to it), `SHA256SUMS` for several items (`checksums.sfv` for CRC32).
- **Compare** accepts a pasted hash, a whole line copied from a hash file, or a BLAKE2b sum from `b2sum` (as long as SHA-512
  is switched on). If nothing useful is on the clipboard, the hash that a file next to it lists for it (`SHA256SUMS`,
  `file.iso.sha256`, ...; SHA-256 before MD5) is filled in, and a hash copied later replaces it; the signature is not checked there.

## Settings

Language, default algorithm, whether a hash found on the clipboard is compared automatically, which algorithms the compare
window calculates (fewer is faster for large files), and whether the right-click entries sit directly under *Scripts* or in a
*HashTally* submenu (one more click). After changing the menu style HashTally offers to restart the running file managers
(Files, and Nemo or Caja when they get entries), which is needed for the new entries to show up; their windows close and a
file operation still running there may be cancelled. The settings page can also reset everything to the defaults, and shows
the version and an About dialog.

## Command line

The output follows the installer: a banner, then one line per step marked `[✓]`, `[✗]`, `[!]` or `[i]`, without colours.

```sh
hashtally --verify ubuntu.iso.sha256       # one line per file, then the GPG verdict
```

## Signature check

When you open a hash file and a signature lies next to it (`SHA256SUMS.gpg`, `.sig`, `.asc` or `.sign`) or the file itself is
clear-signed, HashTally runs `gpg --verify` and shows the result right below the verdict. An invalid signature or a revoked
key decides the verdict; the files then only *match* the list (shown grey), since nobody vouches for it.

A signature file opened on its own (`install.sh.asc`, `.sig`, `.gpg`, `.sign`) checks the file it belongs to, the one with the
same name next to it. If that file is a hash list, the list opens instead. Otherwise the window says whether the file is unchanged since it was
signed, with the same signature row and details as above; a missing file is reported by name.

| Result | Meaning |
| --- | --- |
| Good signature | Made by the key shown. **Compare the fingerprint** with the one on the publisher's website: a valid signature only proves which key signed, not whose key it is. |
| Public key missing | Not checked. The key's fingerprint is shown, and a button fetches the key from a keyserver after a confirmation (a ready-to-copy `gpg --recv-keys` command is there too). |
| Key expired | The signature is valid, but the key should no longer be trusted blindly. |
| Key revoked | The signature is valid, but its owner has revoked the key. That can mean it was stolen and the signature forged: shown in red, do not trust the hash file. |
| Invalid signature | The hash file was changed after signing or is not authentic. Do not trust it. |

HashTally reports what `gpg` says. It changes your keyring only when you press "Import key" and confirm. Example for
Ubuntu ISOs: import the keys listed on ubuntu.com once, then open `SHA256SUMS` from the download folder.

## Supported hash files

GNU (`hash  file`, as written by `sha256sum`), BSD (`SHA256 (file) = hash`), SFV (`file crc32`) and files that contain only a
digest (`file.iso.sha256`). Windows paths with backslashes, UTF-8 BOMs and CRLF line endings are handled. Algorithms:
SHA-256, SHA-512, SHA-1, MD5, CRC32 (plus SHA-224/384 and BLAKE2b from `b2sum` for verifying). Where digests are as long as
SHA-512 or SHA-256 but come from another algorithm, the hash file's name decides: `b2sums.txt` is BLAKE2b, a name with
`sha3` is shown as *Unknown* instead of failing.

A line in none of these formats is listed as *Unknown* instead of being skipped. In a clear-signed file only the signed part
is read, so text added behind the signature is ignored. Anything in front of the signature armor, even a BOM, means the file
is not treated as clear-signed: it is listed as a plain checksum list and gets no verdict (gpg would skip that text and check
a later block).

## Limits

Files hands individually selected files to a script in one environment variable, which Linux caps at 128 KiB (about
1,500 files of typical path length). Beyond that the entry silently does not start; select the folder instead, which has no limit.
