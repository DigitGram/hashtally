#!/usr/bin/python3
# not "env python3": the GTK bindings are distro packages for the system's Python; a conda, pyenv or venv python3 first in PATH has none
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""HashTally: create and verify checksums from the Nautilus context menu.

Entry point and command line. Nautilus scripts and double-clicks both end up here:
  hashtally.py [--verify|--create|--compare|--compare-files|--settings] FILE...
The mode decides which window ui_gtk.py opens; core.py does the actual work. Started from a terminal (stdout is one),
the answer is text instead (cli.py), unless --gui asks for the window.
"""
import argparse
import os
import sys

import core
import i18n
from i18n import _

MODES = {
    "verify": "verify the given hash files (default when files are given)",
    "create": "create a hash file for the given files or folders",
    "compare": "show hashes of a file, compare them with a pasted value, or compare two files",
    "compare-files": "tell whether two files are identical",
    "settings": "open the settings (default without files)",
    "install-scripts": "(re)create the Nautilus right-click entries",
    "remove-scripts": "remove the Nautilus right-click entries",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="files or folders to work on")
    group = parser.add_mutually_exclusive_group()
    for mode, text in MODES.items():
        group.add_argument(f"--{mode}", dest="mode", action="store_const", const=mode, help=text)
    parser.add_argument("--gui", action="store_true", help="open the window even when started from a terminal")
    parser.add_argument("-q", "--quiet", action="store_true", help="in a terminal: no banner and only the files that are not fine")
    parser.add_argument("--algo", choices=core.ALGOS, help="with --create in a terminal: the algorithm (default: from the settings)")
    parser.add_argument("-o", "--output", help="with --create in a terminal: the hash file to write")
    parser.add_argument("--force", action="store_true", help="with --create in a terminal: replace an existing hash file")
    parser.add_argument("--update", action="store_true", help="with --create in a terminal: add the new and changed files to an existing hash file")
    parser.add_argument("--prune", action="store_true", help="with --update: also drop the entries of files that no longer exist")
    parser.add_argument("--version", action="version", version=f"HashTally {core.__version__}")
    args = parser.parse_args()
    if args.prune and not args.update:
        parser.error("--prune only works together with --update")  # not silently ignored: the entries would stay

    cfg = core.load_config()
    i18n.set_language(cfg["language"])
    core.sync_entries()  # python3-nautilus gone since the last start: back to the Scripts entries
    if args.mode in ("install-scripts", "remove-scripts"):
        sys.exit(core.install_scripts(remove_only=args.mode == "remove-scripts"))  # an error text, or None

    paths = [os.path.abspath(f) for f in args.files]
    mode = args.mode or ("verify" if paths else "settings")
    if mode != "settings" and not args.gui and sys.stdout.isatty():  # Nautilus scripts and launchers have no terminal: they get the window
        import cli
        sys.exit({"verify": lambda: cli.verify(paths, args.quiet), "compare": lambda: cli.compare(args.files, args.quiet),
                  "compare-files": lambda: cli.compare_two(args.files, args.quiet),
                  "create": lambda: cli.create(paths, args.algo, args.output, args.force, args.quiet, args.update, args.prune)}[mode]())
    try:
        import ui_gtk  # imported late: the script modes above work without GTK
    except (ImportError, ValueError):  # python3-gi, GTK 4 or libadwaita >= 1.5 missing
        sys.exit(_("HashTally needs GTK 4 with libadwaita 1.5 or newer (python3-gi, gir1.2-adw-1)."))
    ui_gtk.run(mode, paths)


if __name__ == "__main__":
    main()
