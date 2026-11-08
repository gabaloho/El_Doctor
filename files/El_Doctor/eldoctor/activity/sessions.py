"""Who is logged in: live sessions (psutil - utmp on Linux/macOS, WTS on Windows), login history from
wtmp (logins that happened while El Doctor was not running), and human-vs-service account checks."""
from __future__ import annotations

import os
import re
import struct
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

IS_WINDOWS = sys.platform.startswith("win")
SERVICE_ACCOUNTS_WIN = ("system", "local service", "network service", "nt authority\\system",
                        "nt authority\\local service", "nt authority\\network service")
SERVICE_PREFIX_WIN = ("dwm-", "umfd-", "window manager\\", "font driver host\\", "nt service\\", "iis apppool\\")
_UID_MIN: Optional[int] = None
_human_cache: Dict[str, bool] = {}


def _uid_min() -> int:
    global _UID_MIN
    if _UID_MIN is None:
        _UID_MIN = 1000
        try:
            with open("/etc/login.defs", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"^\s*UID_MIN\s+(\d+)", line)
                    if m:
                        _UID_MIN = int(m.group(1))
        except OSError:
            pass
    return _UID_MIN


def is_human(username: str) -> bool:
    """A person's account (or root / Administrator), not a daemon / service identity."""
    u = (username or "").strip()
    if not u:
        return False
    if u in _human_cache:
        return _human_cache[u]
    low = u.lower()
    if IS_WINDOWS or "\\" in u:
        res = low not in SERVICE_ACCOUNTS_WIN and not low.startswith(SERVICE_PREFIX_WIN) and not low.endswith("$")
    else:
        try:
            import pwd
            uid = pwd.getpwnam(u).pw_uid
        except (ImportError, KeyError):
            uid = int(u) if u.isdigit() else -1
        res = uid == 0 or (_uid_min() <= uid < 60000 and uid != 65534)
    _human_cache[u] = res
    return res


def home_of(username: str) -> str:
    try:
        import pwd
        return pwd.getpwnam(username).pw_dir
    except (ImportError, KeyError):
        pass
    if IS_WINDOWS:
        base = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
        return os.path.join(base, username.split("\\")[-1])
    return ""


def session_type(terminal: str, host: str) -> str:
    t, h = (terminal or "").lower(), (host or "").strip()
    if h and not h.startswith(":") and h not in ("localhost", "127.0.0.1", "::1"):
        return "remote"
    if re.match(r"^(tty\d+|console|:\d+(\.\d+)?|seat\d+|tty[a-z]?\d*)$", t) or h.startswith(":"):
        return "console"
    if t.startswith("pts"):
        return "terminal"
    return "local" if not t else "other"


def session_key(s: Dict[str, Any]) -> str:
    return f"{s.get('user')}|{s.get('terminal') or ''}|{s.get('host') or ''}|{int(float(s.get('started') or 0))}"


def read_sessions(provider: Optional[Callable[[], List[Any]]] = None) -> List[Dict[str, Any]]:
    try:
        raw = (provider or psutil.users)()
    except Exception:
        return []
    out = []
    for u in raw:
        d = u._asdict() if hasattr(u, "_asdict") else dict(u)
        s = {"user": d.get("name") or d.get("user") or "", "terminal": d.get("terminal") or "",
             "host": d.get("host") or "", "started": float(d.get("started") or 0), "pid": d.get("pid")}
        s["type"] = session_type(s["terminal"], s["host"])
        s["key"] = session_key(s)
        out.append(s)
    return out


class SessionTracker:
    """Diffs the OS session table each cycle: session_start / session_end."""

    def __init__(self, provider: Optional[Callable[[], List[Any]]] = None) -> None:
        self.provider = provider
        self.open: Dict[str, Dict[str, Any]] = {}

    def restore(self, previous: List[Dict[str, Any]], now: float, gap_start: float,
                rebooted: bool) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Reconcile the sessions that were open when the agent last ran with the ones open now.

        Returns (ended_while_down, started_while_down).  A session open before and after a reboot cannot be
        the same one; a session that disappeared ended somewhere between ``gap_start`` and ``now``."""
        current = {s["key"]: s for s in read_sessions(self.provider)}
        prev = {s["key"]: s for s in previous or []}
        ended, started = [], []
        for k, s in prev.items():
            if rebooted or k not in current:
                ended.append(dict(s, ended_between=[gap_start, now], reason="system restarted" if rebooted
                                  else "ended while El Doctor was not running"))
        for k, s in current.items():
            if rebooted or k not in prev:
                started.append(s)
        self.open = current
        return ended, started

    def poll(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        current = {s["key"]: s for s in read_sessions(self.provider)}
        started = [s for k, s in current.items() if k not in self.open]
        ended = [s for k, s in self.open.items() if k not in current]
        self.open = current
        return started, ended

    def current(self) -> List[Dict[str, Any]]:
        return sorted(self.open.values(), key=lambda s: s.get("started") or 0)

    def users(self) -> List[str]:
        return sorted({s["user"] for s in self.open.values() if s.get("user")})


# --------------------------------------------------------------------------- wtmp (Linux / glibc layout)
# struct utmp (bits/utmp.h, 64-bit and 32-bit glibc): 384 bytes
UTMP = struct.Struct("<hxxi32s4s32s256shhiii4i20s")
UT_TYPES = {1: "run_level", 2: "boot", 5: "init", 6: "login", 7: "user", 8: "dead"}


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def read_wtmp(path: str = "/var/log/wtmp", since: float = 0.0, until: float = 0.0,
              max_bytes: int = 64 * 1024 * 1024) -> List[Dict[str, Any]]:
    """Login / logout / boot / shutdown records from wtmp between ``since`` and ``until``."""
    out: List[Dict[str, Any]] = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:                  # newest records only
                fh.seek(size - (max_bytes // UTMP.size) * UTMP.size)
            data = fh.read()
    except OSError:
        return out
    for off in range(0, len(data) - UTMP.size + 1, UTMP.size):
        (ut_type, pid, line, _id, user, host, _t, _e, _sess, sec, usec, _a0, _a1, _a2, _a3,
         _unused) = UTMP.unpack_from(data, off)
        ts = sec + usec / 1e6
        if (since and ts < since) or (until and ts > until) or ut_type not in (1, 2, 7, 8):
            continue
        rec = {"ts": ts, "type": UT_TYPES[ut_type], "pid": pid, "line": _cstr(line), "user": _cstr(user),
               "host": _cstr(host)}
        if ut_type == 1 and rec["user"] == "shutdown":
            rec["type"] = "shutdown"
        elif ut_type == 1:
            continue
        out.append(rec)
    return out


def wtmp_sessions(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pair wtmp USER_PROCESS / DEAD_PROCESS records into sessions (start, end, user, line, host)."""
    open_by_line: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for r in sorted(records, key=lambda x: x["ts"]):
        if r["type"] == "user":
            s = {"user": r["user"], "terminal": r["line"], "host": r["host"], "started": r["ts"], "ended": None,
                 "pid": r["pid"]}
            s["type"] = session_type(s["terminal"], s["host"])
            open_by_line[r["line"]] = s
            out.append(s)
        elif r["type"] == "dead" and r["line"] in open_by_line:
            open_by_line.pop(r["line"])["ended"] = r["ts"]
        elif r["type"] in ("boot", "shutdown"):
            for s in open_by_line.values():
                s["ended"] = r["ts"]
                s["ended_by"] = r["type"]
            open_by_line.clear()
            out.append({"marker": r["type"], "ts": r["ts"]})
    return out


def now() -> float:
    return time.time()
