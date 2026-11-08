"""Start-up checks that must run before any third-party import.

Lets El Doctor be started in every usual way:
    python -m eldoctor        python eldoctor        python el_doctor.py
    python eldoctor/__main__.py                     eldoctor   (after pip install)
and turns a missing dependency into a clear instruction instead of a traceback.
"""
from __future__ import annotations

import importlib.util
import os
import sys

REQUIRED = {"psutil": "psutil>=5.9", "yaml": "PyYAML>=6.0", "cryptography": "cryptography>=41"}


def fix_sys_path(module_file: str) -> None:
    """`python eldoctor` / `python eldoctor/x.py` put the *package folder* on sys.path instead of its
    parent, so `import eldoctor` fails (ModuleNotFoundError after '<frozen runpy>').  Repair that."""
    pkg_dir = os.path.dirname(os.path.abspath(module_file))
    parent = os.path.dirname(pkg_dir)
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != pkg_dir]
    if parent not in sys.path:
        sys.path.insert(0, parent)


def is_frozen() -> bool:
    """Running as a standalone executable (PyInstaller): Python and every dependency are inside the binary."""
    return bool(getattr(sys, "frozen", False))


def executable_name() -> str:
    """How to call this El Doctor in hints: the binary's name when standalone, else 'eldoctor'."""
    if is_frozen():
        return os.path.basename(sys.executable) or "eldoctor"
    return "eldoctor"


def missing_dependencies() -> list:
    if is_frozen():
        return []
    return [pip for mod, pip in REQUIRED.items() if importlib.util.find_spec(mod) is None]


def ensure_dependencies() -> None:
    missing = missing_dependencies()
    if not missing:
        return
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    py = sys.executable or "python"
    req = os.path.join(project, "requirements.txt")
    lines = [
        "",
        f"El Doctor cannot start: missing Python package(s): {', '.join(missing)}",
        f"Python in use: {py} ({sys.version.split()[0]})",
        "",
        "Install them into THIS Python with:",
        f'    "{py}" -m pip install -r "{req}"' if os.path.exists(req) else
        f'    "{py}" -m pip install ' + " ".join(f'"{m}"' for m in missing),
        "",
    ]
    if sys.platform.startswith("win"):
        lines.insert(-1, "(On Windows also install the console library:  "
                         f'"{py}" -m pip install windows-curses)')
    print("\n".join(lines), file=sys.stderr)
    raise SystemExit(1)


def curses_available() -> bool:
    return importlib.util.find_spec("_curses") is not None


def curses_hint() -> str:
    if sys.platform.startswith("win"):
        return f'install it with:  "{sys.executable}" -m pip install windows-curses'
    return "your Python was built without curses (install the ncurses development package and rebuild)"


def tk_problem() -> str:
    """Why the desktop GUI cannot start on this machine ('' if it can)."""
    if is_frozen() and tk_missing():
        return ("this build of El Doctor was made without the desktop GUI. Use the terminal console "
                f"({executable_name()} tui) or download the GUI build for your platform.")
    if importlib.util.find_spec("tkinter") is None or importlib.util.find_spec("_tkinter") is None:
        if sys.platform.startswith("win"):
            return ("Tkinter is missing from this Python. Re-run the Python installer -> Modify -> tick "
                    "'tcl/tk and IDLE' (or install Python from python.org).")
        if sys.platform == "darwin":
            return "Tkinter is missing. Install it with:  brew install python-tk"
        return ("Tkinter is missing. Install it with:  sudo apt install python3-tk   "
                "(Fedora/RHEL: sudo dnf install python3-tkinter)")
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "No graphical display (DISPLAY is not set). Use the terminal console instead:  eldoctor tui"
    return ""


def tk_missing() -> bool:
    try:
        return importlib.util.find_spec("tkinter") is None or importlib.util.find_spec("_tkinter") is None
    except (ImportError, ValueError):
        return True
