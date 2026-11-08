"""Whole-computer protection: install / remove the El Doctor background service.

One implementation for every installation path - the Windows setup wizard, the Linux .deb / .rpm packages and
`eldoctor install-service` on the command line:

* Windows - data folder ``C:\\ProgramData\\ElDoctor`` (the service locks it to SYSTEM at every start), machine-wide
  ``ELDOCTOR_HOME`` so every user's GUI finds the service, a Scheduled Task running ``eldoctor.exe service`` as
  SYSTEM at boot with restart on failure.
* Linux - ``/var/lib/eldoctor`` (root only), ``/etc/eldoctor/config.yaml``, a systemd unit, optional auditd rules and
  inotify limit, enabled and started.

The first administrator is registered by this (elevated) process, from the arguments or the
``ELDOCTOR_ADMIN_USER / _EMAIL / _NAME / _PASSWORD`` environment variables (the Windows wizard uses the environment,
so nothing typed ever appears on a command line).  An existing installation is upgraded in place: accounts, keys and
records are never touched - on Windows the locked data folder is not even read.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from xml.sax.saxutils import escape

from eldoctor.config import IS_LINUX, IS_WINDOWS, is_privileged, system_tool

TASK_NAME = "ElDoctor Agent"
REG_KEY = r"SOFTWARE\ElDoctor"
LINUX_UNIT_PATH = Path("/etc/systemd/system/eldoctor.service")
LINUX_DATA = Path("/var/lib/eldoctor")
LINUX_ETC = Path("/etc/eldoctor")


class InstallError(RuntimeError):
    pass


# --------------------------------------------------------------------------- the program to run
def agent_command() -> List[str]:
    """How the service starts El Doctor: the standalone executable, or the Python installation."""
    from eldoctor._bootstrap import is_frozen
    if is_frozen():
        return [sys.executable]
    exe = shutil.which("eldoctor")
    if exe:
        return [exe]
    return [sys.executable, "-m", "eldoctor"]


def windows_data_dir() -> Path:
    return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "ElDoctor"


# --------------------------------------------------------------------------- Windows pieces (generated + testable)
def task_xml(command: List[str], config: Path, workdir: Path) -> str:
    """Task Scheduler definition: SYSTEM, at boot, restart every minute on failure, no time limit.
    Element order follows what Windows itself exports."""
    exe, pre = command[0], command[1:]
    args = " ".join(_q(a) for a in pre + ["--config", str(config), "service"])
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>El Doctor: endpoint monitoring, detection, response and user-activity record</Description>
    <URI>\\{escape(TASK_NAME)}</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(_q(exe))}</Command>
      <Arguments>{escape(args)}</Arguments>
      <WorkingDirectory>{escape(str(workdir))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _q(s: str) -> str:
    return f'"{s}"' if (" " in s or not s) else s


def _run(cmd: List[str], check: bool = True, log: Optional[Callable[[str], None]] = None) -> subprocess.CompletedProcess:
    tool = system_tool(cmd[0]) or shutil.which(cmd[0]) or cmd[0]
    r = subprocess.run([tool] + cmd[1:], capture_output=True, text=True, timeout=120)
    if log:
        log(f"$ {' '.join(cmd)} -> {r.returncode} {(r.stdout + r.stderr).strip()[:500]}")
    if check and r.returncode != 0:
        raise InstallError(f"{' '.join(cmd)} failed ({r.returncode}): {(r.stderr or r.stdout).strip()[:500]}")
    return r


def _win_machine_env(name: str, value: Optional[str]) -> None:  # pragma: no cover - Windows only
    import winreg
    key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
        if value is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
    _broadcast_env_change()


def _broadcast_env_change() -> None:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes
    result = wintypes.DWORD()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, ctypes.byref(result))


def _win_marker(data_dir: Optional[Path], installed: bool = True) -> None:  # pragma: no cover - Windows only
    """HKLM\\SOFTWARE\\ElDoctor: DataDir (kept after an uninstall that keeps the records, so a reinstall finds
    its accounts again - the folder is locked to SYSTEM and cannot be inspected) and Installed (0/1)."""
    import winreg
    if data_dir is None:
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY)
        except OSError:
            pass
        return
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY) as k:
        winreg.SetValueEx(k, "DataDir", 0, winreg.REG_SZ, str(data_dir))
        winreg.SetValueEx(k, "Installed", 0, winreg.REG_DWORD, 1 if installed else 0)
        from eldoctor import __version__
        winreg.SetValueEx(k, "Version", 0, winreg.REG_SZ, __version__)


def _win_marker_read() -> Dict[str, Any]:
    if not IS_WINDOWS:
        return {}
    try:  # pragma: no cover - Windows only
        import winreg
        out: Dict[str, Any] = {}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY) as k:
            for name in ("DataDir", "Installed"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
        return out
    except OSError:
        return {}


def windows_installed_data_dir() -> Optional[Path]:
    """Data folder of the *installed* Windows service, or None."""
    m = _win_marker_read()
    return Path(m["DataDir"]) if m.get("DataDir") and m.get("Installed") else None


def windows_previous_data_dir() -> Optional[Path]:
    """Data folder of a current or earlier installation whose records were kept."""
    m = _win_marker_read()
    if m.get("DataDir") and Path(m["DataDir"]).exists():
        return Path(m["DataDir"])
    return None


def request_clean_stop(timeout: float = 20.0, log: Optional[Callable[[str], None]] = None) -> bool:
    """Ask a running agent to stop cleanly (it records a clean shutdown: no monitoring-gap alert on upgrades).
    Only the agent's own OS account or an administrator / root may ask.  Returns True if it stopped."""
    import time
    from eldoctor.api.client import connect
    from eldoctor.config import load_config
    try:
        c = connect(load_config(), client="installer", host=False)      # never start one just to stop it
    except Exception as exc:
        if log:
            log(f"no running agent to stop ({type(exc).__name__})")
        return False
    try:
        c.call("agent.shutdown")
    except Exception as exc:
        if log:
            log(f"agent.shutdown refused: {exc}")
        return False
    finally:
        try:
            c.close()
        except Exception:
            pass
    end = time.time() + timeout
    from eldoctor.agent import running_agent_pid
    while time.time() < end:
        try:
            if not running_agent_pid():
                return True
        except OSError:
            return True                              # data folder not readable: the API answered, trust it
        time.sleep(0.5)
    return False


# --------------------------------------------------------------------------- Linux pieces
def linux_unit(command: List[str], config: Path) -> str:
    from eldoctor.deploy.generator import LINUX_UNIT
    exec_start = " ".join(_q(c) for c in command + ["--config", str(config), "service", "--bootstrap"])
    unit = LINUX_UNIT.replace("ExecStart=/opt/eldoctor/bin/eldoctor --config /etc/eldoctor/config.yaml service "
                              "--bootstrap", f"ExecStart={exec_start}")
    return unit.replace("Documentation=file:///opt/eldoctor/README-DEPLOY.md",
                        "Documentation=file:///usr/share/doc/eldoctor/INSTALL.md")


# --------------------------------------------------------------------------- accounts
def _register_admin(admin: Dict[str, str], log: Callable[[str], None]) -> None:
    """First administrator + the service identity, in the (already selected) data folder."""
    from eldoctor.api.server import create_service_key
    from eldoctor.auth.users import AuthError, UserManager
    from eldoctor.config import home_dir, load_config
    from eldoctor.storage import Store
    cfg = load_config(str(home_dir() / "config.yaml"))
    store = Store()
    try:
        um = UserManager(store, cfg)
        if um.count() == 0:
            missing = [k for k in ("username", "email", "password") if not admin.get(k)]
            if missing:
                raise InstallError("an administrator account is needed: " + ", ".join(missing) + " missing")
            try:
                user, _ = um.register(admin["username"], admin["password"], admin["email"],
                                      admin.get("full_name", ""), admin.get("organization", ""),
                                      admin.get("use_case", "personal"),
                                      "windows" if IS_WINDOWS else "linux")
            except AuthError as exc:
                raise InstallError(f"administrator account: {exc}") from exc
            log(f"registered administrator '{user.username}' <{user.email}>")
        else:
            name = admin.get("username") or um.first_admin()
            user = um.get(name or "")
            if user is None or not user.can("manage_users"):
                raise InstallError("El Doctor already has users; give an existing administrator (--admin-username)")
            if not (home_dir() / "service.key").exists():
                if not admin.get("password"):
                    raise InstallError("the service identity is missing: the administrator's password is needed")
                um.authenticate(user.username, admin["password"])
        if not (home_dir() / "service.key").exists():
            svc_user, kf = create_service_key(um, user)
            log(f"service identity '{svc_user.username}' ready ({kf})")
    finally:
        store.close()


def _write_config(path: Path, target: str, mode: str, admin: Dict[str, str]) -> bool:
    if path.exists():
        return False
    import yaml
    from eldoctor.deploy.generator import tuned_config
    cfg = tuned_config(target, mode, {"email": admin.get("email") or "admin@example.invalid"})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# El Doctor configuration (written by the installer). Edit, then restart the service.\n" +
                    yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
    return True


# --------------------------------------------------------------------------- install / uninstall
def install_service(admin: Optional[Dict[str, str]] = None, mode: str = "interactive", start: bool = True,
                    log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    log = log or (lambda m: None)
    admin = dict(admin or {})
    if not is_privileged():
        raise InstallError("installing the service needs administrator / root rights")
    if IS_WINDOWS:
        return _install_windows(admin, mode, start, log)
    if IS_LINUX:
        return _install_linux(admin, mode, start, log)
    raise InstallError("the background service is available on Windows and Linux; on macOS run El Doctor from the app")


def _install_windows(admin: Dict[str, str], mode: str, start: bool, log) -> Dict[str, Any]:  # pragma: no cover
    existing = windows_previous_data_dir()
    data = existing or windows_data_dir()
    cmd = agent_command()
    config = data / "config.yaml"
    if existing is not None:
        os.environ["ELDOCTOR_HOME"] = str(data)
        request_clean_stop(log=log)
    _run(["schtasks", "/End", "/TN", TASK_NAME], check=False, log=log)
    if existing is None:
        data.mkdir(parents=True, exist_ok=True)
        # SYSTEM + Administrators while we set it up; the service locks it to SYSTEM at every start
        _run(["icacls", str(data), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
              "*S-1-5-32-544:(OI)(CI)F"], log=log)
        os.environ["ELDOCTOR_HOME"] = str(data)
        _write_config(config, "windows", mode, admin)
        _register_admin(admin, log)
        _win_marker(data)
        upgraded = False
    else:
        log(f"existing installation in {data}: upgraded in place (accounts, keys and records kept)")
        _win_marker(data)
        upgraded = True
    _win_machine_env("ELDOCTOR_HOME", str(data))
    xml = task_xml(cmd, config, data)
    fd, tmp = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-16") as fh:
            fh.write(xml)
        _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", tmp, "/F"], log=log)
    finally:
        os.unlink(tmp)
    if start:
        _run(["schtasks", "/Run", "/TN", TASK_NAME], log=log)
    return {"data_dir": str(data), "task": TASK_NAME, "upgraded": upgraded, "command": cmd}


def _install_linux(admin: Dict[str, str], mode: str, start: bool, log) -> Dict[str, Any]:
    if not shutil.which("systemctl") and not system_tool("systemctl"):
        raise InstallError("systemd is required (no systemctl found)")
    cmd = agent_command()
    upgraded = (LINUX_DATA / "eldoctor.db").exists()
    LINUX_ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    LINUX_DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(LINUX_DATA, 0o700)
    config = LINUX_ETC / "config.yaml"
    _write_config(config, "linux", mode, admin)
    os.environ["ELDOCTOR_HOME"] = str(LINUX_DATA)
    if not upgraded:
        _register_admin(admin, log)
    else:
        log(f"existing installation in {LINUX_DATA}: upgraded in place (accounts, keys and records kept)")
    LINUX_UNIT_PATH.write_text(linux_unit(cmd, config), encoding="utf-8")
    os.chmod(LINUX_UNIT_PATH, 0o644)
    rules_dir = Path("/etc/audit/rules.d")
    if rules_dir.is_dir():
        from eldoctor.deploy.generator import AUDIT_RULES
        (rules_dir / "eldoctor.rules").write_text(AUDIT_RULES, encoding="utf-8")
        if system_tool("augenrules"):
            _run(["augenrules", "--load"], check=False, log=log)
    try:
        if int(Path("/proc/sys/fs/inotify/max_user_watches").read_text().strip()) < 524288:
            Path("/etc/sysctl.d/60-eldoctor-inotify.conf").write_text("fs.inotify.max_user_watches = 524288\n")
            _run(["sysctl", "-q", "-p", "/etc/sysctl.d/60-eldoctor-inotify.conf"], check=False, log=log)
    except (OSError, ValueError):
        pass
    _run(["systemctl", "daemon-reload"], log=log)
    _run(["systemctl", "enable", "eldoctor.service"], log=log)
    if start:
        _run(["systemctl", "restart", "eldoctor.service"], log=log)
    return {"data_dir": str(LINUX_DATA), "unit": str(LINUX_UNIT_PATH), "upgraded": upgraded, "command": cmd}


def stop_service(log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Stop the running service cleanly (upgrades replace its program files); it starts again at boot or with
    install-service.  Nothing installed = nothing to do."""
    log = log or (lambda m: None)
    if IS_WINDOWS:  # pragma: no cover - Windows only
        data = windows_installed_data_dir()
        if data is None:
            return {"stopped": False, "note": "no El Doctor service installed"}
        os.environ["ELDOCTOR_HOME"] = str(data)
        clean = request_clean_stop(log=log)
        _run(["schtasks", "/End", "/TN", TASK_NAME], check=False, log=log)
        return {"stopped": True, "clean": clean}
    if IS_LINUX and LINUX_UNIT_PATH.exists():
        _run(["systemctl", "stop", "eldoctor.service"], check=False, log=log)      # SIGTERM: clean stop
        return {"stopped": True, "clean": True}
    return {"stopped": False, "note": "no El Doctor service installed"}


def uninstall_service(purge: bool = False, log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Remove the service.  Records are kept unless ``purge``.  Nothing installed = nothing to do (success)."""
    log = log or (lambda m: None)
    if IS_WINDOWS:  # pragma: no cover - Windows only
        data = windows_installed_data_dir()
        q = _run(["schtasks", "/Query", "/TN", TASK_NAME], check=False)
        if q.returncode != 0 and data is None:
            return {"removed": False, "note": "no El Doctor service installed"}
        if not is_privileged():
            raise InstallError("removing the service needs administrator rights")
        if data is not None:
            os.environ["ELDOCTOR_HOME"] = str(data)
            request_clean_stop(log=log)
        _run(["schtasks", "/End", "/TN", TASK_NAME], check=False, log=log)
        _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], check=False, log=log)
        _win_machine_env("ELDOCTOR_HOME", None)
        if purge or data is None:
            _win_marker(None)
        else:
            _win_marker(data, installed=False)             # a reinstall finds the kept accounts and records
        if purge and data and data.exists():
            _run(["takeown", "/F", str(data), "/R", "/A", "/D", "Y"], check=False, log=log)
            _run(["icacls", str(data), "/grant", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C"], check=False, log=log)
            shutil.rmtree(data, ignore_errors=True)
        return {"removed": True, "purged": bool(purge), "data_dir": str(data) if data else ""}
    if IS_LINUX:
        if not LINUX_UNIT_PATH.exists():
            return {"removed": False, "note": "no El Doctor service installed"}
        if not is_privileged():
            raise InstallError("removing the service needs root")
        _run(["systemctl", "disable", "--now", "eldoctor.service"], check=False, log=log)
        LINUX_UNIT_PATH.unlink()
        for f in (Path("/etc/audit/rules.d/eldoctor.rules"), Path("/etc/sysctl.d/60-eldoctor-inotify.conf")):
            if f.exists():
                f.unlink()
        _run(["systemctl", "daemon-reload"], check=False, log=log)
        if purge:
            shutil.rmtree(LINUX_DATA, ignore_errors=True)
            shutil.rmtree(LINUX_ETC, ignore_errors=True)
        return {"removed": True, "purged": bool(purge), "data_dir": str(LINUX_DATA)}
    return {"removed": False, "note": "no background service on this platform"}
