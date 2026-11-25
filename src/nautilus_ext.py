"""The HashTally entries of the right-click menu in Files (Nautilus), as a nautilus-python extension. core.py copies this
file to ~/.local/share/nautilus-python/extensions/ when the setting "extension" is on (it needs python3-nautilus).

It stands alone on purpose: every extension runs in one Python process inside Files, so it must not import the program's
modules (they have common names such as `core` and `i18n`). The texts, the name and the launcher come from menu.json, which
core.py writes and which is read each time the menu opens: a new name or language needs no restart of Files."""
import json
import os
import re
import subprocess
from pathlib import Path

MENU_FILE = Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser() / "hashtally" / "menu.json"
HASHFILE_NAME = re.compile(r"sums|sum\.txt$|\.(?:sha\d+|md5|sfv)(?:sum)?$")  # the same as core._HASHFILE_NAME (a test compares them)
ORDER = ("--create", "--compare", "--compare-files", "--verify")  # the order of the Scripts entries


def entries_for(paths, folder=False):
    """The flags of the entries that fit the selection `paths` (local paths): "--create" for any item, "--compare" for one file,
    "--compare-files" for two, "--verify" when every one is a hash file. `folder`: no selection, the open folder itself."""
    if not paths:
        return []
    if folder:
        return ["--create"]
    files = [p for p in paths if os.path.isfile(p)]
    flags = ["--create"]
    if len(paths) == 1 and len(files) == 1:
        flags.append("--compare")
    if len(paths) == 2 and len(files) == 2:
        flags.append("--compare-files")
    if len(files) == len(paths) and all(HASHFILE_NAME.search(os.path.basename(p).lower()) for p in paths):
        flags.append("--verify")
    return [flag for flag in ORDER if flag in flags]


try:
    import gi
    for _version in ("4.1", "4.0"):  # Files 50 ships the typelib as 4.1, older ones as 4.0
        try:
            gi.require_version("Nautilus", _version)
            break
        except ValueError:
            continue
    from gi.repository import GObject, Nautilus
except (ImportError, ValueError):  # no Files here: the plain function above can still be used
    Nautilus = None

if Nautilus:
    class HashTallyMenu(GObject.GObject, Nautilus.MenuProvider):
        def _menu(self, paths, folder=False):
            try:
                config = json.loads(MENU_FILE.read_text())
                flags = entries_for(paths, folder)
                if not flags:
                    return []
                # always one submenu: four loose entries would crowd the menu; "_" would be taken for a mnemonic, "__" is a plain one
                top = Nautilus.MenuItem(name="HashTally::menu", label=str(config["name"]).replace("_", "__"))
                sub = Nautilus.Menu()
                top.set_submenu(sub)
                for flag in flags:
                    item = Nautilus.MenuItem(name=f"HashTally::{flag.lstrip('-')}", label=str(config["labels"][flag]))
                    item.connect("activate", lambda _item, flag=flag: self._run(config["launcher"], flag, paths))
                    sub.append_item(item)
                return [top]
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                return []  # not written yet, from another version or edited by hand: no entries rather than an error at every right click

        @staticmethod
        def _run(launcher, flag, paths):
            try:
                subprocess.Popen([launcher, flag, "--", *paths], start_new_session=True)
            except OSError:
                pass  # the program is gone (package removed): nothing to start

        @staticmethod
        def _local(file_info):
            """The local path of an item, or None (a remote folder, trash, search results ...)."""
            location = file_info.get_location()
            return location.get_path() if location is not None else None

        def get_file_items(self, files):  # Files 43 and newer pass only the selection
            paths = [self._local(f) for f in files]
            return self._menu(paths) if all(paths) else []

        def get_background_items(self, current_folder):
            path = self._local(current_folder)
            return self._menu([path], folder=True) if path else []
