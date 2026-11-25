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

**Not listed.** Off by default; switch on *Look for files not in the list* in the settings. When a list names several files, a further row counts the files that lie in the folders it covers (next to
the list, and below every top-level folder it lists a file in) but are not in it, so a file added to a backup since the list
was made does not go unnoticed. It is a hint and has no say in the verdict. Other hash files and signatures are left out, and
a list of a single file (a download's `.sha256`) never gets the row: its folder holds other things.

## Create and compare

- **Create** names the hash file after the selection: `name.sha256` for a single file or folder (a folder gives
  `Folder.sha256` next to it), `SHA256SUMS` for several items (`checksums.sfv` for CRC32).
- **Compare** accepts a pasted hash, a whole line copied from a hash file, or a BLAKE2b sum from `b2sum` (as long as SHA-512
  is switched on). If nothing useful is on the clipboard, the hash that a file next to it lists for it (`SHA256SUMS`,
  `file.iso.sha256`, ...; SHA-256 before MD5) is filled in, and a hash copied later replaces it; the signature is not checked there.

**Compare two files.** Select two files and choose *Compare files* (*Show or compare hash* does the same when two files are selected): both are hashed with SHA-256 and the window says
whether they are identical (`hashtally --compare-files a b` in a terminal). The result shows the two files; the hashes are folded away and open by themselves when the files differ. Files of different sizes differ without being read.

**Update.** If the hash file you are about to create exists and is a plain list of one algorithm (not clear-signed, not a link),
the window offers *Update* next to *Overwrite*. An update hashes only files that no entry names yet and files changed since the
hash file was written; every other entry stays as it is and is **not checked again**, so use Verify for that. The file keeps its
algorithm. Entries of files that no longer exist stay unless you switch on *Remove entries of deleted files*. The file is written again as a plain list: comments and the BSD style are not kept. It is not offered for a list with a detached signature next to it or with names that are not UTF-8. The hash file does
not store dates, so its own date is the cut-off: a copy of it made later hides an edit made before the copy. In a terminal:
`hashtally --create --update` (and `--prune`).

**Algorithm speed.** In the settings, *Test* measures how fast this computer calculates each algorithm (about a second, from memory, one core) and opens a window with a bar for each, fastest first, marked secure or not, and a recommendation: the fastest secure one, with a note if CRC32, MD5 or SHA-1 is faster but not secure against deliberate changes. Only advice, it changes no setting; a drive is often slower than the algorithm.

## Settings

Language, default algorithm, whether a hash found on the clipboard is compared automatically, whether verifying looks for files the list does not name, which algorithms the compare
window calculates (fewer is faster for large files), and whether the right-click entries sit directly under *Scripts* or in a
*HashTally* submenu (one more click). After changing the menu style HashTally offers to restart the running file managers
(Files, and Nemo or Caja when they get entries), which is needed for the new entries to show up; their windows close and a
file operation still running there may be cancelled. The settings page can also reset everything to the defaults, and shows
the version and an About dialog.

The *Context menu* tab can switch the right-click entries from the *Scripts* folder to a **separate entry** that Files loads from a
`python3-nautilus` extension (the switch stays grey until that package is installed; HashTally never installs it, as that needs root).
The entry is always a submenu, named *HashTally* unless you rename it, and it lists only what fits the selection: *Create* for any
selection (and for an open folder's background), *Show or compare hash* for one file, *Compare files* for two, *Verify* when every
selected file is a hash file. There is no 128 KiB limit, and the *Scripts* entries are removed while it is on, so nothing shows twice.
It is Files only (Nemo and Caja keep their scripts); switching it on or off needs `nautilus -q` once. The settings window itself has two
tabs, *General* and *Context menu*.

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
