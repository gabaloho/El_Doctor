"""GUI runtime auto-provisioning - run the desktop GUI even when *this* Python has no tkinter.

Typical case: Linux system Python without the `python3-tk` package and no sudo rights.
Instead of failing, El Doctor:

 1. looks for another Python >= 3.9 on the machine that does have Tk (uv / pyenv / conda /
    python.org installs, the Windows `py` launcher, Homebrew ...),
 2. optionally installs one without root via `uv python install` (standalone builds ship Tcl/Tk),
 3. creates a private virtual environment from it once (user cache dir), installs psutil + PyYAML + cryptography,
 4. relaunches `python -m eldoctor gui ...` there, running *this* El Doctor source tree against
    the same data directory (users, sessions, alerts are shared).

Override the interpreter with ELDOCTOR_GUI_PYTHON=/path/to/python.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

MIN_VERSION = (3, 9)
PROJECT_ROOT = Path(__file__).resolve().parents[2]          # folder that contains the `eldoctor` package
PROBE = ("import sys, tkinter; t = tkinter.Tcl(); "
         "print('%d.%d.%d' % sys.version_info[:3], t.eval('info patchlevel'))")


def cache_dir() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "ElDoctor"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches" / "eldoctor"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "eldoctor"
    return base / "gui-runtime"


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform.startswith("win") else "bin/python")


def probe(python: str, timeout: float = 20) -> Optional[Tuple[str, str]]:
    """(python version, Tk version) if `python` can import tkinter and start a Tcl interpreter."""
    try:
        r = subprocess.run([python, "-c", PROBE], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    parts = r.stdout.strip().split()
    if len(parts) != 2:
        return None
    ver = tuple(int(x) for x in parts[0].split(".")[:2])
    return (parts[0], parts[1]) if ver >= MIN_VERSION else None


def candidates() -> List[str]:
    """Python interpreters that may exist on this machine, most likely first."""
    home = Path.home()
    found: List[str] = []
    forced = os.environ.get("ELDOCTOR_GUI_PYTHON")
    if forced:
        found.append(forced)
    names = ["python3", "python"] + [f"python3.{m}" for m in range(15, 8, -1)]
    for n in names:
        p = shutil.which(n)
        if p:
            found.append(p)
    patterns = [
        "/opt/uv-python/*/bin/python3.*", str(home / ".local/share/uv/python/*/bin/python3.*"),
        os.path.join(os.environ.get("UV_PYTHON_INSTALL_DIR", "/nonexistent"), "*/bin/python3.*"),
        str(home / ".pyenv/versions/*/bin/python3"), str(home / "miniconda3/bin/python3"),
        str(home / "anaconda3/bin/python3"), str(home / "miniforge3/bin/python3"), "/opt/conda/bin/python3",
        "/usr/local/bin/python3.*", "/usr/bin/python3.*", "/opt/homebrew/bin/python3.*",
        "/Library/Frameworks/Python.framework/Versions/*/bin/python3",
    ]
    if sys.platform.startswith("win"):
        local = os.environ.get("LOCALAPPDATA", "")
        patterns += [os.path.join(local, "Programs", "Python", "Python3*", "python.exe"),
                     "C:\\Python3*\\python.exe", "C:\\Program Files\\Python3*\\python.exe",
                     os.path.join(local, "uv", "python", "*", "python.exe")]
        if shutil.which("py"):
            try:
                out = subprocess.run(["py", "-0p"], capture_output=True, text=True, timeout=15).stdout
                found += re.findall(r"([A-Za-z]:\\[^\r\n*]+?python\.exe)", out)
            except (OSError, subprocess.SubprocessError):
                pass
    for pat in patterns:
        found += sorted(glob.glob(pat), reverse=True)
    if shutil.which("uv"):
        try:
            out = subprocess.run(["uv", "python", "list", "--only-installed"], capture_output=True, text=True,
                                 timeout=20).stdout
            found += [ln.split()[-1] for ln in out.splitlines() if ln.strip() and os.path.sep in ln.split()[-1]]
        except (OSError, subprocess.SubprocessError):
            pass
    seen, out = set(), []
    for p in found:
        if not p or p.endswith(("-config", ".py")):
            continue
        try:
            real = os.path.realpath(p)
        except OSError:
            continue
        if real in seen or not os.path.isfile(real) or not os.access(real, os.X_OK):
            continue
        if os.path.realpath(sys.executable) == real:
            continue                      # the current interpreter is the one without Tk
        seen.add(real)
        out.append(p)
    return out


def find_tk_python(log: Callable[[str], None] = print) -> Optional[Tuple[str, str, str]]:
    best = None
    for p in candidates():
        res = probe(p)
        if res:
            ver = tuple(int(x) for x in res[0].split("."))
            if best is None or ver > best[3]:
                best = (p, res[0], res[1], ver)
    return best[:3] if best else None


def uv_install(log: Callable[[str], None] = print) -> Optional[str]:
    """No-sudo install of a standalone Python (includes Tcl/Tk) through uv, if uv is available."""
    uv = shutil.which("uv")
    if not uv:
        return None
    log("  trying: uv python install 3.12  (standalone Python with Tcl/Tk, no administrator rights needed)")
    try:
        r = subprocess.run([uv, "python", "install", "3.12"], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            log("  uv could not download Python: " + (r.stderr.strip().splitlines() or ["?"])[-1])
            return None
        path = subprocess.run([uv, "python", "find", "3.12"], capture_output=True, text=True, timeout=60).stdout.strip()
        return path if path and probe(path) else None
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"  uv failed: {exc}")
        return None


DEPS_PROBE = "import psutil, yaml, cryptography.hazmat.primitives.asymmetric.ed25519"


def deps_ok(vpy: Path) -> bool:
    try:
        return subprocess.run([str(vpy), "-c", DEPS_PROBE], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def install_deps(vpy: Path, log: Callable[[str], None] = print) -> None:
    req = PROJECT_ROOT / "requirements.txt"
    pkgs = ["-r", str(req)] if req.exists() else ["psutil>=5.9", "PyYAML>=6.0", "cryptography>=41"]
    log("  installing El Doctor's dependencies (psutil, PyYAML, cryptography) into the GUI runtime")
    r = subprocess.run([str(vpy), "-m", "pip", "install", "--disable-pip-version-check", "-q", *pkgs],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("could not install dependencies into the GUI runtime: "
                           + (r.stderr.strip().splitlines() or ["pip failed"])[-1])


def ensure_venv(base_python: str, py_version: str, log: Callable[[str], None] = print) -> Path:
    """Private venv with El Doctor's dependencies, created once per base-Python version."""
    venv = cache_dir() / f"py{'.'.join(py_version.split('.')[:2])}"
    vpy = _venv_python(venv)
    marker = venv / ".eldoctor-ready"
    if marker.exists() and vpy.exists() and probe(str(vpy)):
        if not deps_ok(vpy):                    # runtime built by an older El Doctor: add new dependencies
            install_deps(vpy, log)
        return vpy
    log(f"  creating the GUI runtime in {venv} (one time)")
    venv.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([base_python, "-m", "venv", "--clear", str(venv)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"could not create a virtual environment: {r.stderr.strip()[-300:]}")
    install_deps(vpy, log)
    marker.write_text(base_python + "\n", encoding="utf-8")
    return vpy


def no_tk_help() -> str:
    py = sys.executable
    if sys.platform.startswith("win"):
        return ("Re-run the Python installer -> Modify -> tick 'tcl/tk and IDLE', or install Python from "
                "python.org, then start El Doctor again.")
    return ("No Python with Tk was found on this machine. Without administrator rights you can install one:\n"
            f'    "{py}" -m pip install --user uv\n'
            "    ~/.local/bin/uv python install 3.12\n"
            "then run the same command again - El Doctor picks it up automatically.\n"
            "With administrator rights: sudo apt install python3-tk (Debian/Ubuntu) or "
            "sudo dnf install python3-tkinter (Fedora/RHEL).\n"
            "Meanwhile the terminal console works everywhere:  python3 eldoctor tui")


def relaunch_gui(argv: List[str], log: Callable[[str], None] = print) -> Optional[int]:
    """Run the GUI with a Tk-capable runtime. Returns the exit code, or None if impossible."""
    if os.environ.get("ELDOCTOR_GUI_RUNTIME"):
        return None                                         # already inside a runtime - avoid loops
    log(f"tkinter is not available in this Python ({sys.executable}, {sys.version.split()[0]}).")
    ready = ready_runtime()
    if ready:                                   # fast path: runtime built earlier - one probe, no search
        vpy, ver = ready
        return _run(vpy, ver, argv, log)
    log("Looking for a Python with Tk on this machine ...")
    found = find_tk_python(log)
    if not found:
        path = uv_install(log)
        res = probe(path) if path else None
        found = (path, res[0], res[1]) if path and res else None
    if not found:
        log(no_tk_help())
        return None
    base, ver, tkver = found
    log(f"  found {base} (Python {ver}, Tk {tkver})")
    try:
        vpy = ensure_venv(base, ver, log)
    except RuntimeError as exc:
        log(f"  {exc}")
        log(no_tk_help())
        return None
    return _run(vpy, ver, argv, log)


def ready_runtime() -> Optional[Tuple[Path, str]]:
    """Newest previously built runtime that still works (honours ELDOCTOR_GUI_PYTHON by skipping the cache)."""
    if os.environ.get("ELDOCTOR_GUI_PYTHON") or not cache_dir().is_dir():
        return None
    for venv in sorted(cache_dir().glob("py3.*"), key=lambda p: tuple(int(x) for x in p.name[2:].split(".")),
                       reverse=True):
        vpy = _venv_python(venv)
        if (venv / ".eldoctor-ready").exists() and vpy.exists():
            res = probe(str(vpy))
            if res:
                if not deps_ok(vpy):            # built by an older El Doctor: bring its dependencies up to date
                    try:
                        install_deps(vpy, lambda m: None)
                    except RuntimeError:
                        continue
                return vpy, res[0]
    return None


def _run(vpy: Path, ver: str, argv: List[str], log: Callable[[str], None]) -> int:
    env = dict(os.environ, ELDOCTOR_GUI_RUNTIME=str(vpy))
    env["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    log(f"Starting the El Doctor GUI with Python {ver} ...")
    sys.stdout.flush()
    return subprocess.call([str(vpy), "-m", "eldoctor", *argv], env=env)   # same cwd: relative --config works
