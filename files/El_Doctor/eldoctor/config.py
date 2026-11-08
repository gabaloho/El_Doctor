"""Configuration loading and filesystem layout."""
from __future__ import annotations

import copy
import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
DEFAULT_CONFIG = DATA_DIR / "default_config.yaml"

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
PLATFORM = "windows" if IS_WINDOWS else ("linux" if IS_LINUX else ("macos" if IS_MAC else sys.platform))

MODES = ["monitor", "interactive", "enforce"]
MODE_RANK = {m: i for i, m in enumerate(MODES)}


def package_data(*parts: str) -> Path:
    return DATA_DIR.joinpath(*parts)


def _windows_service_home() -> Optional[Path]:
    """Windows: the data folder of the installed El Doctor service (set by the installer in the registry).  Programs
    started before the installer changed the machine environment still find it."""
    if not IS_WINDOWS:
        return None
    try:  # pragma: no cover - Windows only
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\ElDoctor") as k:
            if winreg.QueryValueEx(k, "Installed")[0]:
                return Path(winreg.QueryValueEx(k, "DataDir")[0])
    except OSError:
        pass
    return None


def home_path() -> Path:
    """Where the data folder is, without creating it (help texts, diagnostics)."""
    env = os.environ.get("ELDOCTOR_HOME")
    return Path(env).expanduser() if env else (_windows_service_home() or Path.home() / ".eldoctor")


def home_dir() -> Path:
    """$ELDOCTOR_HOME, the installed Windows service's folder, or ~/.eldoctor - created with owner-only permissions."""
    env = os.environ.get("ELDOCTOR_HOME")
    path = Path(env).expanduser() if env else (_windows_service_home() or Path.home() / ".eldoctor")
    path.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def client_dir() -> Path:
    """Per-OS-user client state (API session token, GUI preferences) - never inside the agent's data folder.

    In service deployments the data folder belongs to the service account and other users cannot write
    there, so anything that belongs to the *person* using the CLI/TUI/GUI lives here instead."""
    env = os.environ.get("ELDOCTOR_CLIENT_DIR")
    if env:
        path = Path(env).expanduser()
    elif IS_WINDOWS:
        path = Path(os.environ.get("APPDATA") or Path.home()) / "ElDoctor"
    else:
        path = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "eldoctor"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:                       # read-only home (containers): private per-user temp folder instead
        import tempfile
        path = Path(tempfile.gettempdir()) / f"eldoctor-client-{os.getuid() if hasattr(os, 'getuid') else 'user'}"
        path.mkdir(mode=0o700, exist_ok=True)
        if not IS_WINDOWS and (os.lstat(path).st_uid != os.getuid() or path.is_symlink()):
            raise PermissionError(f"{path} is not owned by you - set ELDOCTOR_CLIENT_DIR") from None
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


SYSTEM_SOCKET = "/run/eldoctor/api.sock"      # systemd RuntimeDirectory of the Linux service
SYSTEM_DATA_DIR = "/var/lib/eldoctor"          # data folder of the Linux service (root only)


def system_service_installed() -> bool:
    """A system-wide El Doctor service exists and this shell does not point at another data folder."""
    if os.environ.get("ELDOCTOR_SOCKET"):
        return False
    if IS_WINDOWS:
        svc = _windows_service_home()
        env = os.environ.get("ELDOCTOR_HOME")
        return svc is not None and (not env or os.path.normcase(os.path.abspath(env)) ==
                                    os.path.normcase(os.path.abspath(str(svc))))
    return not os.environ.get("ELDOCTOR_HOME") and os.path.isdir(SYSTEM_DATA_DIR)
_SUN_PATH_MAX = 100                            # sockaddr_un.sun_path is 104-108 bytes depending on the OS


def api_endpoint(cfg: Optional[Dict[str, Any]] = None, server: bool = False) -> str:
    """Address of the agent's local API: a Unix socket path, or a named pipe on Windows.

    Order: $ELDOCTOR_SOCKET > config api.socket > (clients only, when ELDOCTOR_HOME is not set) the system
    service socket if it exists > <data folder>/api.sock.  Server and clients compute the same value."""
    env = os.environ.get("ELDOCTOR_SOCKET")
    if env:
        return env
    conf = ((cfg or {}).get("api") or {}).get("socket")
    if conf:
        return str(conf)
    import hashlib
    home = home_dir()
    if IS_WINDOWS:
        digest = hashlib.sha256(str(home.resolve()).lower().encode()).hexdigest()[:16]
        return rf"\\.\pipe\eldoctor-api-{digest}"
    if not server and not os.environ.get("ELDOCTOR_HOME") and os.path.exists(SYSTEM_SOCKET):
        return SYSTEM_SOCKET
    path = str(home / "api.sock")
    if len(path.encode()) <= _SUN_PATH_MAX:
        return path
    # deep data folders (e.g. test temp dirs) exceed sun_path: use a private per-user runtime folder
    import tempfile
    digest = hashlib.sha256(str(home.resolve()).encode()).hexdigest()[:16]
    run = Path(tempfile.gettempdir()) / f"eldoctor-{os.getuid()}"
    return str(run / f"{digest}.sock")


def subdir(name: str) -> Path:
    p = home_dir() / name
    p.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return p


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def user_config_path() -> Path:
    return home_dir() / "config.yaml"


def load_config(path: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    with open(DEFAULT_CONFIG, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    cfg_path = Path(path) if path else user_config_path()
    if cfg_path.exists():
        check_trusted_file(cfg_path)
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = deep_merge(cfg, yaml.safe_load(fh) or {})
    env_mode = os.environ.get("ELDOCTOR_MODE")
    if env_mode in MODES:
        cfg["agent"]["mode"] = env_mode
    if overrides:
        cfg = deep_merge(cfg, overrides)
    if cfg["agent"]["mode"] not in MODES:
        raise ValueError(f"agent.mode must be one of {MODES}")
    return cfg


class UntrustedFileError(RuntimeError):
    pass


def check_trusted_file(path: Path) -> None:
    """Refuse world-writable config/playbooks when running privileged.

    A root agent that loads a world-writable playbook would let any local user
    make it kill arbitrary processes - classic privilege escalation.
    """
    if IS_WINDOWS:
        return
    try:
        st = os.stat(path)
    except OSError:
        return
    if hasattr(os, "geteuid") and os.geteuid() == 0 and st.st_mode & stat.S_IWOTH:
        raise UntrustedFileError(f"refusing world-writable file while running as root: {path}")


def write_default_config(dest: Optional[Path] = None, force: bool = False) -> Path:
    dest = dest or user_config_path()
    if dest.exists() and not force:
        return dest
    dest.write_text(DEFAULT_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


def is_privileged() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


TRUSTED_BIN_DIRS = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]


def system_tool(name: str) -> str:
    """Absolute path of an OS tool from trusted system directories only - never resolved through PATH.

    A privileged agent (root / SYSTEM) that runs `netsh` or `iptables` via PATH can be hijacked by anyone
    who can write to a PATH directory.  Returns '' when the tool is not installed."""
    if IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        cand = os.path.join(root, "System32", name if name.lower().endswith(".exe") else name + ".exe")
        return cand if os.path.isfile(cand) else ""
    for d in TRUSTED_BIN_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return ""


def safe_url(url: str) -> str:
    """Only http(s) for outbound requests: urllib would otherwise also read file:// and other schemes."""
    from urllib.parse import urlparse
    scheme = urlparse(str(url)).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) URL scheme {scheme!r}")
    return url
