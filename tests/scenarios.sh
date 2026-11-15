#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
# Sandbox to play through every HashTally window by hand.  Usage: tests/scenarios.sh
#
# Each case is a folder with its own SHA256SUMS; the table at the end says what HashTally should show.
# The signed cases use a test keyring of their own, which your double-click does not know: open them with
# $T/open NUMBER (it points GNUPGHOME there). Your own keyring is never touched.
# HASHTALLY=src/hashtally.py tests/scenarios.sh runs a checkout instead of the installed launcher.
set -eu
T=/tmp/hashtally-test
HT=$(realpath "${HASHTALLY:-$(command -v hashtally || echo "$(dirname "$0")/../src/hashtally.py")}")  # installed, else this checkout

rm -rf "$T"
mkdir -p "$T"
cd "$T"

# case_dir NAME FILE...: a folder with these small files and a SHA256SUMS over them
case_dir() {
  local dir=$1; shift
  mkdir -p "$dir"
  cd "$dir"
  for file in "$@"; do mkdir -p "$(dirname "$file")"; echo "$file" > "$file"; done
  sha256sum "$@" > SHA256SUMS
  cd "$T"
}

# --- unsigned: double-click SHA256SUMS
case_dir 01-all-ok a.txt sub/b.txt c.txt
case_dir 02-one-missing a.txt b.txt c.txt;           rm 02-one-missing/b.txt
case_dir 03-missing-and-corrupt a.txt b.txt c.txt d.txt
rm 03-missing-and-corrupt/b.txt; echo changed >> 03-missing-and-corrupt/c.txt
case_dir 04-corrupt a.txt b.txt;                     echo changed >> 04-corrupt/a.txt
case_dir 05-none-found a.txt b.txt c.txt;            rm 05-none-found/*.txt
case_dir 06-unreadable a.txt b.txt;                  chmod 000 06-unreadable/b.txt    # (as root every file is readable)
mkdir -p 07-odd/sub; echo beta > 07-odd/sub/b.txt
printf '%s  sub\\b.txt\r\n' "$(sha256sum 07-odd/sub/b.txt | cut -d' ' -f1)" > 07-odd/windows.sha256
printf '%s  sub/b.txt\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > 07-odd/unknown-length.sha256
case_dir 08-formats a.txt c.txt
(cd 08-formats && rm SHA256SUMS && md5sum a.txt c.txt > all-ok.md5 &&
  python3 -c 'import sys, zlib; [print(f, "%08X" % zlib.crc32(open(f, "rb").read())) for f in sys.argv[1:]]' a.txt c.txt > all-ok.sfv)
mkdir 09-big; head -c 1G /dev/zero > 09-big/big.bin; (cd 09-big && sha256sum big.bin > SHA256SUMS)   # 1 GB, no more: /tmp may live in RAM
mkdir 10-many; (cd 10-many && for i in $(seq -f "%05g" 3000); do echo "$i" > "file-$i.txt"; done && sha256sum file-*.txt > SHA256SUMS &&
  echo changed >> file-00100.txt && echo changed >> file-02000.txt && rm file-02500.txt)

# --- signed: $T/open NUMBER
if command -v gpg > /dev/null; then
  export GNUPGHOME="$T/.gnupg"
  mkdir -m 700 "$GNUPGHOME"
  key() { gpg --batch --quiet --passphrase '' "$@" 2> /dev/null; }
  sign() { gpg --batch --quiet --yes --local-user "$1" --detach-sign -o "$2.gpg" "$2" 2> /dev/null; }
  fpr() { gpg --with-colons --list-keys "$1" 2> /dev/null | awk -F: '/^fpr/ {print $10; exit}'; }
  key --quick-generate-key "HashTally Test <test@example.invalid>" ed25519 sign never

  case_dir 11-good a.txt b.txt;              sign test@example.invalid 11-good/SHA256SUMS
  case_dir 12-good-one-missing a.txt b.txt;  sign test@example.invalid 12-good-one-missing/SHA256SUMS; rm 12-good-one-missing/b.txt
  case_dir 13-bad a.txt b.txt;               sign test@example.invalid 13-bad/SHA256SUMS
  (cd 13-bad && echo forged > a.txt && sha256sum a.txt b.txt > SHA256SUMS)   # file and list swapped after signing: everything "matches"
  case_dir 14-clearsigned a.txt b.txt
  (cd 14-clearsigned && gpg --batch --quiet --yes --local-user test@example.invalid --clearsign -o signed SHA256SUMS 2> /dev/null && mv signed SHA256SUMS)

  # a key of someone else: signed with it, then the key is gone
  case_dir 15-key-missing a.txt b.txt
  other="$T/.gnupg-other"
  mkdir -m 700 "$other"
  GNUPGHOME="$other" key --quick-generate-key "Someone Else <else@example.invalid>" ed25519 sign never
  GNUPGHOME="$other" sign else@example.invalid 15-key-missing/SHA256SUMS
  GNUPGHOME="$other" gpgconf --kill gpg-agent
  rm -rf "$other"

  # a key that expired in 2020, made and used back then
  case_dir 16-key-expired a.txt b.txt
  key --faked-system-time 20200101T000000 --quick-generate-key "Expired Test <expired@example.invalid>" ed25519 sign 1d
  gpg --batch --quiet --yes --faked-system-time 20200101T120000 --local-user expired@example.invalid \
      --detach-sign -o 16-key-expired/SHA256SUMS.gpg 16-key-expired/SHA256SUMS 2> /dev/null

  # a key revoked after it signed
  case_dir 17-key-revoked a.txt b.txt
  key --quick-generate-key "Revoked Test <revoked@example.invalid>" ed25519 sign never
  sign revoked@example.invalid 17-key-revoked/SHA256SUMS
  sed 's/^:-----/-----/' "$GNUPGHOME/openpgp-revocs.d/$(fpr revoked@example.invalid).rev" | gpg --batch --quiet --import 2> /dev/null

  gpgconf --kill gpg-agent
  # shellcheck disable=SC2016  # "$1" belongs to the helper, not to this script
  printf '#!/bin/sh\n# open case NUMBER with the test keyring\nGNUPGHOME=%s exec %s --verify %s/"$1"-*/SHA256SUMS\n' "$GNUPGHOME" "$HT" "$T" > open
  chmod +x open
  signed=yes
fi

# --- create and compare
mkdir -p 18-create/folder/sub
echo alpha > 18-create/a.txt; echo old > 18-create/SHA256SUMS; echo beta > 18-create/folder/sub/b.txt
mkdir 19-compare; head -c 20M /dev/urandom > 19-compare/download.iso
(cd 19-compare && sha256sum download.iso > download.iso.sha256)
case_dir 20-many-missing a.txt $(seq -f 'gone-%g.txt' 1 25); rm 20-many-missing/gone-*.txt

cat <<EOF
Sandbox: $T
Unsigned cases: double-click SHA256SUMS (or run $HT FILE). Expected:

 01-all-ok                green check           "3 files match"
 02-one-missing           green/yellow ring "2/3"  "2 files match"; yellow line "Missing 1"
 03-missing-and-corrupt   red/yellow/green ring "1 file differs"; lines "Missing 1", "Mismatch 1"
 04-corrupt               red/green ring        "1 file differs": expected and found hash in blocks
 05-none-found            yellow ⚠              "None of the files were found"
 06-unreadable            yellow/green ring     "1 file could not be checked"  (not as root)
 07-odd                   windows.sha256: green (CRLF, backslash); unknown-length.sha256: "could not be checked"
 08-formats               all-ok.md5 and all-ok.sfv: green
 09-big                   1 GB: progress, speed, time left; on a fast SSD it is done in a second, so for Cancel/Esc
                          verify a big ISO over the network (smb://...) instead
 10-many                  3000 files: "2 files differ", "1 missing"; open "Verified" while it fills
EOF
if [ "${signed:-}" ]; then cat <<EOF

Signed cases: $T/open NUMBER   (e.g. $T/open 11)

 11-good                  green check, "Good signature from HashTally Test", signature right below the ring
 12-good-one-missing      green/yellow ring "1/2", good signature, yellow line "Missing 1"
 13-bad                   red, "Invalid signature: do not trust this hash file", files grey "match"
 14-clearsigned           like 11, with the signature inside SHA256SUMS
 15-key-missing           green check + small ⚠ on the ring, "public key missing", copy and re-check buttons
 16-key-expired           green check + small ⚠ on the ring, "the key has expired"
 17-key-revoked           red, "the key was revoked"
EOF
else echo; echo " (signed cases skipped: gpg is not installed)"; fi
cat <<EOF

 From here on no $T/open: start these by hand, in Files (right-click > Scripts)

 18-create                select a.txt + folder > Create hash file; SHA256SUMS warns that it exists
 19-compare               download.iso > Show or compare hash: the hash from download.iso.sha256 fills in itself,
                          the field is not focused
 20-many-missing          green/yellow ring "1/26"      "25 files not in the folder": a click opens a list of its own, one scroll bar (with 10 or fewer it unfolds in place)
 Keys                     Ctrl+W or Esc closes any window
 Settings                 language, default algorithm, clipboard, compare algorithms
EOF
