#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
#
# HashTally installer: per user, no root needed.
#   From a checkout:  ./install.sh
#   One-liner:        curl -fsSL https://github.com/DigitGram/hashtally/releases/latest/download/install.sh | bash
#   Without curl:     wget -qO- https://github.com/DigitGram/hashtally/releases/latest/download/install.sh | bash
#   Uninstall:        ~/.local/share/hashtally/install.sh --uninstall   (--purge also deletes your settings)
set -euo pipefail
[ "$(id -u)" -ne 0 ] || { echo "Run without sudo: the install is per user." >&2; exit 1; }

REPO="DigitGram/hashtally"   # GitHub owner/name, used by the one-liner
VERSION="1.2"                # equals __version__ (a test checks); the download is this release's tag, never a branch that moves on
COMMIT=""                    # empty in the repository; the release workflow writes the tag's commit here, into the copy it attaches and that gets signed:
ARCHIVE_URL="https://github.com/$REPO/archive/${COMMIT:-refs/tags/v$VERSION}.tar.gz"   # a tag can be moved to other code, a commit names exactly one
PYTHON=/usr/bin/python3      # the system's Python: the GTK bindings are distro packages for it; a conda, pyenv or venv python3 first in PATH has none

APP_ID=io.github.digitgram.HashTally
MIME_ICON=application-x-hashtally   # Files looks up a file's icon by its MIME type name
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
CONFIG_DIR="$CONFIG_HOME/hashtally"
APP_DIR="$DATA/hashtally"
LAUNCHER="$HOME/.local/bin/hashtally"
SRC=""   # the checkout this script lives in; stays empty when piped from curl or wget, wherever that runs
[ -f "${BASH_SOURCE[0]:-}" ] && SRC="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- output helpers
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  GREEN=$'\e[32m'; RED=$'\e[31m'; CYAN=$'\e[36m'; RESET=$'\e[0m'
else
  GREEN=""; RED=""; CYAN=""; RESET=""
fi
TICK="[${GREEN}✓${RESET}]"; CROSS="[${RED}✗${RESET}]"; INFO="[${CYAN}i${RESET}]"

say() { printf '  %s %s\n' "$INFO" "$*"; }
tilde() { printf '%s' "${1/#$HOME/\~}"; }
restart_hint() {  # $1: what the person sees; one line per file manager that is installed, as the entries exist only for those
  say "If the right-click entries $1, restart the file manager:"
  for fm in nautilus nemo caja; do
    if command -v "$fm" >/dev/null 2>&1; then printf '        %s -q\n' "$fm"; fi
  done
  echo
}
closing() { printf '  %s Done. You can close this terminal window now.\n' "$TICK"; }

banner() {
  printf '%s\n' "$CYAN"
  cat <<'BANNER'
   _   _           _   _____     _ _
  | | | | __ _ ___| |_|_   _|_ _| | |_   _
  | |_| |/ _` / __| '_ \| |/ _` | | | | | |
  |  _  | (_| \__ \ | | | | (_| | | | |_| |
  |_| |_|\__,_|___/_| |_|_|\__,_|_|_|\__, |
                                     |___/

BANNER
  printf '%s  Checksums for Nautilus  ·  GPL-3.0-or-later\n\n' "$RESET"
}

# step "message" command...  Runs the command quietly and prints [✓]/[✗]; on failure shows its output and exits.
step() {
  local message=$1 rc; shift
  set +e; ( set -e; "$@" ) >"$TMP/log" 2>&1; rc=$?; set -e   # the subshell keeps `set -e` effective inside functions
  if [ "$rc" -eq 0 ]; then
    printf '  %s %s\n' "$TICK" "$message"
  else
    printf '  %s %s\n' "$CROSS" "$message" >&2
    sed 's/^/      /' "$TMP/log" >&2
    exit 1
  fi
}

# `cmd && other || true` is deliberate here: optional steps must never abort the installer.
# Run an optional system tool if it exists.
# shellcheck disable=SC2015
try() { command -v "$1" >/dev/null && "$@" || true; }

# ---------------------------------------------------------------- install steps
have_gtk() {
  "$PYTHON" -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")
from gi.repository import Adw
raise SystemExit(Adw.get_minor_version() < 5)' 2>/dev/null
}

check_dependencies() {
  [ -x "$PYTHON" ] || { echo "$PYTHON is required."; exit 1; }
  have_gtk && return
  cat <<MSG
HashTally needs GTK 4 + libadwaita 1.5 or newer for Python (GNOME 46+). Install it, for example:
  Debian/Ubuntu: sudo apt install python3-gi gir1.2-adw-1
  Fedora:        sudo dnf install python3-gobject libadwaita
  Arch:          sudo pacman -S python-gobject libadwaita
MSG
  exit 1
}

download() {
  if command -v curl >/dev/null; then curl -fsSL "$ARCHIVE_URL" | tar -xz --strip-components=1 -C "$SRC"
  elif command -v wget >/dev/null; then wget -qO- "$ARCHIVE_URL" | tar -xz --strip-components=1 -C "$SRC"
  else echo "curl or wget is required to download HashTally."; exit 1
  fi
}

install_files() {
  mkdir -p "$APP_DIR/po" "$(dirname "$LAUNCHER")"
  rm -f "${APP_DIR:?}"/*.py "${APP_DIR:?}/po"/*.po      # an update must drop modules and languages that are no longer shipped
  cp "$SRC"/src/*.py "$SRC/install.sh" "$APP_DIR/"      # install.sh is kept for --uninstall
  cp "$SRC"/po/*.po "$APP_DIR/po/"                      # translations are read at runtime
  [ -z "$COMMIT" ] || sed -i "s/^COMMIT=\"\"/COMMIT=\"$COMMIT\"/" "$APP_DIR/install.sh"   # the copy from the archive is not pinned: it must fetch the same commit
  chmod +x "$APP_DIR/hashtally.py" "$APP_DIR/install.sh"
  ln -sf "$APP_DIR/hashtally.py" "$LAUNCHER"
}

install_launcher() {
  mkdir -p "$DATA/applications"
  # The repo keeps icons as hashtally.<ext>; they are installed under the app id, so changing the
  # app id never means renaming files.
  (cd "$SRC/data/icons/hicolor" && find . -type f) | while read -r icon; do
    mkdir -p "$DATA/icons/hicolor/$(dirname "$icon")"
    cp "$SRC/data/icons/hicolor/$icon" "$DATA/icons/hicolor/$(dirname "$icon")/$APP_ID.${icon##*.}"
  done
  install -Dm644 "$SRC/data/$MIME_ICON.svg" "$DATA/icons/hicolor/scalable/mimetypes/$MIME_ICON.svg"
  # The launcher points at the PNG by absolute path: the most reliable way to get the icon into the Shell.
  sed -e "s|@LAUNCHER@|$LAUNCHER|" -e "s|@APP_ID@|$APP_ID|" \
      -e "s|@ICON@|$DATA/icons/hicolor/256x256/apps/$APP_ID.png|" \
      "$SRC/data/hashtally.desktop.in" > "$DATA/applications/$APP_ID.desktop"
}

register_mime() {
  mkdir -p "$DATA/mime/packages"
  cp "$SRC/data/hashtally-mime.xml" "$DATA/mime/packages/hashtally.xml"
  try update-mime-database "$DATA/mime"
  try xdg-mime default "$APP_ID.desktop" application/x-hashtally
}

refresh_desktop() {
  rm -f "$DATA/icons/hicolor/icon-theme.cache"   # a stale cache can hide new icons
  touch "$DATA/icons/hicolor" 2>/dev/null || true
  try update-desktop-database "$DATA/applications"
}

install_app() {
  banner
  if [ -z "$SRC" ] || [ ! -f "$SRC/src/hashtally.py" ]; then      # piped from curl/wget, or not inside a checkout: fetch the sources first
    SRC="$TMP/src"; mkdir "$SRC"
    step "Downloading HashTally" download
  fi
  step "Checking dependencies" check_dependencies
  step "Installing program files" install_files
  step "Installing icons and launcher" install_launcher
  step "Registering the checksum file type" register_mime
  step "Creating right-click entries" "$LAUNCHER" --install-scripts
  step "Refreshing the desktop" refresh_desktop

  echo
  say "$("$LAUNCHER" --version) is installed."
  cat <<MSG

      Verify    double-click a .sha256, .md5 or .sfv file
      Create    select files -> right-click -> Scripts -> "HashTally: ..."
      Settings  open "HashTally" in the Activities overview

MSG
  say "To uninstall later, run:"
  printf '        %s --uninstall    keeps your settings\n' "$(tilde "$APP_DIR/install.sh")"
  printf '        %s --purge        removes the settings too\n\n' "$(tilde "$APP_DIR/install.sh")"
  restart_hint "do not show up"
  say "If the icon or launcher is missing, log out and in once."
  echo
  closing
}

# ---------------------------------------------------------------- uninstall steps
# shellcheck disable=SC2015
remove_scripts()  { [ -x "$LAUNCHER" ] && "$LAUNCHER" --remove-scripts || true; }
remove_files()    { rm -rf "$APP_DIR" "$LAUNCHER"; }
remove_settings() { rm -rf "$CONFIG_DIR"; }
remove_launcher() {
  rm -f "$DATA/applications/$APP_ID.desktop" "$DATA/mime/packages/hashtally.xml"
  find "$DATA/icons/hicolor" \( -name "$APP_ID.*" -o -name "$MIME_ICON.*" \) -delete 2>/dev/null || true
  if [ -f "$CONFIG_HOME/mimeapps.list" ]; then   # the default-app entry `xdg-mime default` made
    sed -i --follow-symlinks '/^application\/x-hashtally=/d' "$CONFIG_HOME/mimeapps.list"
  fi
  try update-mime-database "$DATA/mime"
}

uninstall_app() {
  banner
  step "Removing right-click entries" remove_scripts
  step "Removing program files" remove_files
  step "Removing launcher, icons and file type" remove_launcher
  [ "${1:-}" = purge ] && step "Removing settings" remove_settings
  step "Refreshing the desktop" refresh_desktop
  echo
  if [ "${1:-}" = purge ]; then say "HashTally was removed, including your settings."
  else say "HashTally was removed. Your settings in $(tilde "$CONFIG_DIR") were kept (--purge deletes them too)."; fi
  restart_hint "are still listed"
  closing
}

case "${1:-}" in
  "")          install_app ;;
  --uninstall) uninstall_app ;;
  --purge)     uninstall_app purge ;;
  *)           echo "Usage: $0 [--uninstall | --purge]" >&2; exit 1 ;;
esac
