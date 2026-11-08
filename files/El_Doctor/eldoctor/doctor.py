"""`eldoctor doctor`: is this installation ready?  Every finding comes with what to do about it.

Read-only: it never creates the data folder, the database or keys, and it needs no login.  Exit code 1
when something blocks El Doctor from working (FAIL), 0 otherwise (warnings are advice).
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


@dataclass
class Check:
    area: str
    status: str
    summary: str
    fix: str = ""


def _data_dir() -> Path:
    env = os.environ.get("ELDOCTOR_HOME")
    if env:
        return Path(env).expanduser()
    from eldoctor.config import SYSTEM_DATA_DIR, system_service_installed
    if system_service_installed():
        return Path(SYSTEM_DATA_DIR)
    return Path.home() / ".eldoctor"


def _version(mod: str) -> str:
    try:
        from importlib.metadata import version
        return version({"yaml": "PyYAML"}.get(mod, mod))
    except Exception:
        m = sys.modules.get(mod)
        return getattr(m, "__version__", "?") if m else "?"


def run_checks(cfg_path: Optional[str] = None, network: bool = False) -> List[Check]:
    from eldoctor import __version__
    from eldoctor._bootstrap import curses_available, executable_name, is_frozen, missing_dependencies, tk_problem
    from eldoctor.config import IS_LINUX, IS_WINDOWS, is_privileged
    me = executable_name()
    out: List[Check] = []
    add = lambda *a: out.append(Check(*a))  # noqa: E731

    # ---------------------------------------------------------------- build and runtime
    build = "standalone executable" if is_frozen() else f"Python {platform.python_version()} ({sys.executable})"
    add("version", INFO, f"El Doctor {__version__}, {build}, {platform.system()} {platform.release()} "
                         f"{platform.machine()}")
    if sys.version_info < (3, 9):
        add("python", FAIL, f"Python {platform.python_version()} is too old", "install Python 3.9 or newer")
    missing = missing_dependencies()
    if missing:
        add("dependencies", FAIL, "missing: " + ", ".join(missing),
            f'"{sys.executable}" -m pip install ' + " ".join(f'"{m}"' for m in missing))
    else:
        add("dependencies", OK, ", ".join(f"{m} {_version(m)}" for m in ("psutil", "yaml", "cryptography")))
    add("yara", INFO if importlib.util.find_spec("yara") is None else OK,
        "YARA scanning " + ("off (optional: pip install yara-python)" if importlib.util.find_spec("yara") is None
                            else "available"))

    # ---------------------------------------------------------------- configuration
    cfg: Dict[str, Any] = {}
    try:
        from eldoctor.config import load_config
        path = Path(cfg_path) if cfg_path else _data_dir() / "config.yaml"     # never creates the data folder
        cfg = load_config(str(path))
        src = str(path) if path.exists() else "built-in defaults"
        add("config", OK, f"loaded ({src}); response mode: {cfg['agent']['mode']}")
    except Exception as exc:
        add("config", FAIL, f"cannot load the configuration: {exc}", "fix the YAML error or run: "
                                                                    f"{me} config init --force")

    # ---------------------------------------------------------------- data folder
    d = _data_dir()
    if not d.exists():
        add("data folder", INFO, f"{d} does not exist yet - it is created at the first start (run: {me})")
    else:
        try:
            st = d.stat()
            if not IS_WINDOWS and st.st_mode & 0o077:
                add("data folder", WARN, f"{d} is accessible to other accounts (mode {oct(st.st_mode & 0o777)})",
                    f"chmod 700 {d}  (the service repairs this at every start)")
            else:
                add("data folder", OK, f"{d}")
        except PermissionError:
            add("data folder", OK, f"{d} (owned by the El Doctor service; not readable by this account - expected)")
        usage = shutil.disk_usage(d if d.exists() else d.parent)
        free_mb = usage.free / 1048576
        if free_mb < 100:
            add("disk space", FAIL, f"only {free_mb:.0f} MB free for {d}", "free disk space: records cannot be written")
        elif free_mb < 1024:
            add("disk space", WARN, f"{free_mb:.0f} MB free for {d}", "keep at least 1 GB free for records and evidence")
        else:
            add("disk space", OK, f"{free_mb / 1024:.1f} GB free")
        db = d / "eldoctor.db"
        try:
            if db.exists():
                add("database", OK, f"{db} ({db.stat().st_size / 1048576:.1f} MB)")
            else:
                add("database", INFO, "no database yet - created at the first start (registration comes first)")
        except PermissionError:
            add("database", OK, "present (service-owned)")

    # ---------------------------------------------------------------- agent / service
    try:
        from eldoctor.agent import running_agent_pid
        pid = running_agent_pid() if d.exists() and os.access(d, os.R_OK | os.X_OK) else None
    except Exception:
        pid = None
    from eldoctor.config import api_endpoint
    endpoint = ""
    if d.exists() and os.access(d, os.R_OK | os.X_OK):
        try:
            endpoint = api_endpoint(cfg or None)        # computes the path from the (existing) data folder
        except Exception:
            pass
    reachable = False
    if endpoint and not IS_WINDOWS and os.path.exists(endpoint):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(endpoint)
            s.close()
            reachable = True
        except OSError:
            pass
    if reachable or pid:
        add("agent", OK, "running" + (f" (pid {pid})" if pid else "") + (f", API {endpoint}" if reachable else ""))
    else:
        add("agent", INFO, "not running: the console / GUI host it while open; for 24/7 protection install the "
                           "service", "sudo ./install.sh (Linux bundle) / install.ps1 (Windows) - see INSTALL.md")
    if IS_LINUX:
        unit = Path("/etc/systemd/system/eldoctor.service")
        if unit.exists():
            active = _run(["systemctl", "is-active", "eldoctor.service"]).strip()
            add("service", OK if active == "active" else WARN, f"systemd service installed, {active or 'unknown'}",
                "" if active == "active" else "sudo systemctl restart eldoctor && journalctl -u eldoctor -n 50")
    elif IS_WINDOWS:
        q = _run(["schtasks", "/Query", "/TN", "ElDoctor Agent"])
        if q:
            add("service", OK if "Running" in q else WARN, "Scheduled Task 'ElDoctor Agent' installed" +
                (", running" if "Running" in q else ", not running"),
                "" if "Running" in q else 'Start-ScheduledTask -TaskName "ElDoctor Agent"')

    # ---------------------------------------------------------------- privileges and telemetry
    if is_privileged():
        add("privileges", OK, "administrator/root: every process, firewall blocking and all users' folders")
    else:
        add("privileges", WARN, "running as a normal user: only your own processes and files are monitored and "
                                "acted on; IP blocking falls back to killing the connecting process",
            "install the service for whole-machine protection")
    lc = (cfg or {}).get("logs", {})
    if IS_LINUX:
        readable = [f for f in lc.get("files", []) if os.access(f, os.R_OK)]
        exists = [f for f in lc.get("files", []) if os.path.exists(f)]
        if exists and not readable:
            add("log files", WARN, "auth/system logs exist but are not readable (brute-force and sudo detection off)",
                "run as root (service) or add this account to the 'adm' group")
        elif readable:
            add("log files", OK, ", ".join(readable))
        audit = lc.get("auditd_path", "/var/log/audit/audit.log")
        if os.access(audit, os.R_OK):
            rules = _run(["auditctl", "-l"]) if is_privileged() else ""
            if rules and "eldoctor_file" in rules:
                add("auditd", OK, "readable, El Doctor rules loaded (exec + who deleted/renamed files)")
            elif rules:
                add("auditd", WARN, "readable but the El Doctor rules are not loaded",
                    "install eldoctor-audit.rules from the Linux bundle into /etc/audit/rules.d/ and run augenrules --load")
            else:
                add("auditd", OK, f"{audit} readable")
        else:
            add("auditd", INFO, "not available: very short commands can be missed and file deletions are "
                                "attributed by process evidence instead of the kernel",
                "apt install auditd (the Linux installer adds the El Doctor rules)")
        try:
            watches = int(Path("/proc/sys/fs/inotify/max_user_watches").read_text().strip())
            add("inotify", OK if watches >= 65536 else WARN, f"max_user_watches = {watches:,}",
                "" if watches >= 65536 else "echo fs.inotify.max_user_watches=524288 | sudo tee "
                                            "/etc/sysctl.d/60-eldoctor-inotify.conf && sudo sysctl --system")
        except (OSError, ValueError):
            pass
    if IS_WINDOWS:
        sysmon = _run(["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"])
        add("sysmon", OK if sysmon else WARN, "Sysmon installed" if sysmon else "Sysmon not installed",
            "" if sysmon else "install Sysmon for full process / file / network telemetry (see INSTALL.md)")

    # ---------------------------------------------------------------- activity record and reports
    ac = (cfg or {}).get("activity") or {}
    if ac.get("enabled", True):
        paths = ((ac.get("files") or {}).get("paths")) or "auto"
        if paths == "auto":
            from eldoctor.activity.monitor import default_roots
            paths = default_roots(is_privileged())
        bad = [p for p in paths if not os.path.isdir(p) or not os.access(p, os.R_OK | os.X_OK)]
        add("activity record", WARN if bad else OK, "watching " + ", ".join(paths) +
            (f" - not readable: {', '.join(bad)}" if bad else ""),
            "run the service as root/SYSTEM to record every user's files" if bad else "")
    else:
        add("activity record", INFO, "disabled (activity.enabled: false)")
    rep = (ac.get("report") or {})
    smtp = (rep.get("smtp") or {}).get("smtp_host") or next(
        (c.get("smtp_host") for c in ((cfg or {}).get("notifications") or {}).get("channels") or []
         if c.get("type") == "email" and c.get("enabled", True)), None)
    if not smtp:
        add("admin e-mail", WARN, "no SMTP server: data-wipe reports for the registered admins wait in the outbox",
            "set activity.report.smtp (smtp_host, smtp_port, username, password_env) or enable an 'email' channel "
            "in config.yaml, then restart")
    elif network:
        port = int((rep.get("smtp") or {}).get("smtp_port") or 587)
        try:
            socket.create_connection((smtp, port), timeout=5).close()
            add("admin e-mail", OK, f"SMTP {smtp}:{port} reachable")
        except OSError as exc:
            add("admin e-mail", FAIL, f"SMTP {smtp}:{port} unreachable: {exc}", "check host, port and firewall")
    else:
        add("admin e-mail", OK, f"SMTP server {smtp} configured (check delivery: {me} doctor --network)")
    chans = [c.get("name") or c.get("type") for c in ((cfg or {}).get("notifications") or {}).get("channels") or []
             if c.get("enabled", True)]
    add("notifications", OK if chans else WARN, ", ".join(chans) or "no channel enabled",
        "" if chans else "enable e-mail / Slack / Teams / syslog under notifications.channels")

    # ---------------------------------------------------------------- El Doctor Hub link
    link = d / "hub" / "link.json"
    try:
        if link.exists():
            import json as _json
            info = _json.loads(link.read_text(encoding="utf-8"))
            add("hub", OK, f"enrolled as {info.get('agent_id')} with {info.get('url')} (check-ins: "
                           f"{me} activity status / the hub's agent list)")
        else:
            add("hub", INFO, "not enrolled with an El Doctor Hub (fleet console)",
                f"{me} enroll <TOKEN>  (a hub administrator creates the token)")
    except (OSError, ValueError):
        pass

    # ---------------------------------------------------------------- user interfaces
    problem = tk_problem()
    add("desktop GUI", OK if not problem else INFO, "available" if not problem else problem)
    add("terminal console", OK if curses_available() else WARN,
        "available" if curses_available() else "curses missing - the terminal console (tui) will not start",
        "" if curses_available() else ("pip install windows-curses" if IS_WINDOWS else "use the desktop GUI"))
    return out


def _run(cmd: List[str]) -> str:
    from eldoctor.config import system_tool
    exe = system_tool(cmd[0])
    if not exe:
        return ""
    try:
        r = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=10)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def render(checks: List[Check], color: bool = False) -> str:
    tag = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[info]"}
    col = {OK: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", INFO: "\033[36m"}
    lines = []
    for c in checks:
        t = tag[c.status]
        if color:
            t = col[c.status] + t + "\033[0m"
        lines.append(f"{t} {c.area:<17} {c.summary}")
        if c.fix and c.status in (WARN, FAIL, INFO):
            lines.append(f"       {'':<17} -> {c.fix}")
    fails = sum(c.status == FAIL for c in checks)
    warns = sum(c.status == WARN for c in checks)
    lines.append("")
    lines.append("Ready." if not fails and not warns else
                 f"{fails} problem(s) to fix, {warns} recommendation(s)." if fails else
                 f"Ready, with {warns} recommendation(s).")
    return "\n".join(lines)


def as_json(checks: List[Check]) -> List[Dict[str, Any]]:
    return [asdict(c) for c in checks]


def exit_code(checks: List[Check]) -> int:
    return 1 if any(c.status == FAIL for c in checks) else 0


__all__ = ["run_checks", "render", "as_json", "exit_code", "Check"]
