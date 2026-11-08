# PyInstaller spec for the standalone El Doctor executables (no Python needed on the target machine).
#   pyinstaller --clean --noconfirm packaging/eldoctor.spec        (or: python packaging/build_release.py)
# Produces dist/eldoctor[.exe] (console: CLI, TUI, GUI, service); on Windows also dist/"El Doctor.exe" (windowed
# GUI - a different name: Windows and macOS file names ignore case, "ElDoctor.exe" would overwrite eldoctor.exe);
# on macOS dist/"El Doctor.app".
import importlib.util
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))                      # noqa: F821 (SPECPATH is set by PyInstaller)
PKG = os.path.join(ROOT, "eldoctor")
sys.path.insert(0, ROOT)
from eldoctor import __version__  # noqa: E402
ICO = os.path.join(SPECPATH, "assets", "eldoctor.ico")                      # noqa: F821
ICNS = os.path.join(SPECPATH, "assets", "eldoctor.icns")                    # noqa: F821

# the whole package as data: rules, playbooks, default config, IOC lists - and the sources, so deployment bundles
# generated from the standalone build still carry an installable source zip
datas = []
for folder, dirs, files in os.walk(PKG):
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    rel = os.path.relpath(folder, ROOT)
    for f in files:
        if not f.endswith((".pyc", ".pyo")):
            datas.append((os.path.join(folder, f), rel))
for extra in ("LICENSE", "README.md", "requirements.txt", "pyproject.toml"):
    if os.path.exists(os.path.join(ROOT, extra)):
        datas.append((os.path.join(ROOT, extra), "."))

# El Doctor imports most modules lazily (inside functions): list them all explicitly
hidden = collect_submodules("eldoctor") + ["cryptography.hazmat.primitives.asymmetric.ed25519", "yaml", "psutil"]
if sys.platform.startswith("win"):
    hidden += ["_curses", "curses"]
excludes = ["pytest", "_pytest", "pip", "setuptools", "IPython", "numpy", "matplotlib", "PIL"]
HAS_TK = importlib.util.find_spec("tkinter") is not None and importlib.util.find_spec("_tkinter") is not None
if not HAS_TK:
    excludes += ["tkinter", "_tkinter"]
    print("NOTE: this Python has no Tk - the build will not contain the desktop GUI (terminal console only)")

common = dict(pathex=[ROOT], datas=datas, hiddenimports=hidden, excludes=excludes, noarchive=False)

a = Analysis([os.path.join(SPECPATH, "entry_cli.py")], **common)           # noqa: F821
pyz = PYZ(a.pure)                                                           # noqa: F821
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="eldoctor", console=True,   # noqa: F821
          debug=False, strip=False, upx=False, runtime_tmpdir=None,
          icon=ICO if sys.platform.startswith("win") else None,
          version=os.path.join(SPECPATH, "version_info.txt") if sys.platform.startswith("win") else None)  # noqa: F821

if sys.platform.startswith("win") and HAS_TK:
    g = Analysis([os.path.join(SPECPATH, "entry_gui.py")], **common)       # noqa: F821
    gpyz = PYZ(g.pure)                                                      # noqa: F821
    gexe = EXE(gpyz, g.scripts, g.binaries, g.datas, [], name="El Doctor", console=False,   # noqa: F821
               debug=False, strip=False, upx=False, runtime_tmpdir=None, icon=ICO,
               version=os.path.join(SPECPATH, "version_info.txt"))               # noqa: F821

if sys.platform == "darwin" and HAS_TK:
    # "El Doctor.app" for the disk image: double-click opens the desktop GUI (one-folder layout inside the bundle,
    # as PyInstaller recommends for .app bundles)
    m = Analysis([os.path.join(SPECPATH, "entry_gui.py")], **common)       # noqa: F821
    mpyz = PYZ(m.pure)                                                      # noqa: F821
    mexe = EXE(mpyz, m.scripts, [], exclude_binaries=True, name="ElDoctor", console=False,   # noqa: F821
               debug=False, strip=False, upx=False, argv_emulation=False, icon=ICNS)
    mcoll = COLLECT(mexe, m.binaries, m.datas, strip=False, upx=False, name="ElDoctorApp")      # noqa: F821
    app = BUNDLE(mcoll, name="El Doctor.app", icon=ICNS, bundle_identifier="org.eldoctor.ElDoctor",  # noqa: F821
                 version=__version__,
                 info_plist={"CFBundleDisplayName": "El Doctor", "CFBundleName": "El Doctor",
                             "CFBundleShortVersionString": __version__, "CFBundleVersion": __version__,
                             "NSHighResolutionCapable": True, "LSMinimumSystemVersion": "11.0",
                             "NSHumanReadableCopyright": "MIT License - El Doctor contributors"})
