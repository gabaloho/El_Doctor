"""Who did it: attribution of file events to a user and a process.

inotify / folder scans say *what* changed, never *who*.  Evidence is combined in decreasing order of
strength, and every activity record says which one was used (``attribution``):

  kernel    auditd (Linux) / Sysmon or the Security log (Windows): the OS recorded the process and the
            user - including the *login* user (auid) behind sudo / su.  Authoritative.
  handle    a process had the file open (psutil open files) - strong.
  cmdline   a recently running process named the file or one of its parent folders on its command line
            (rm -rf ~/Documents, shred x.pdf, curl -o y.zip, find . -delete) - strong for short commands.
  self      El Doctor itself (quarantine).
  inferred  no process evidence: the owner of the home folder with an active session, or the only logged-in
            user.  A lead, not proof - stated as such in every report.
  unknown   nothing to go on (typically: changes made while El Doctor was not running).
"""
from __future__ import annotations

import os
import re
import shlex
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import psutil

from eldoctor.activity.sessions import home_of, is_human

DOWNLOADERS = {"curl", "wget", "wget2", "aria2c", "axel", "lftp", "scp", "sftp", "rsync", "yt-dlp", "youtube-dl",
               "transmission-gtk", "transmission-daemon", "qbittorrent", "deluge", "ktorrent", "gio", "bitsadmin.exe",
               "certutil.exe", "curl.exe", "wget.exe", "aria2c.exe"}
BROWSERS = {"firefox", "firefox-bin", "firefox-esr", "chrome", "google-chrome", "chromium", "chromium-browser", "brave",
            "brave-browser", "opera", "vivaldi", "vivaldi-bin", "msedge", "microsoft-edge", "epiphany", "falkon",
            "thunderbird", "firefox.exe", "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "iexplore.exe",
            "thunderbird.exe", "outlook.exe", "teams.exe", "ms-teams.exe", "slack", "slack.exe", "telegram-desktop",
            "discord", "discord.exe", "whatsapp.exe"}
PS_DOWNLOAD_RX = re.compile(r"(invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|downloadfile|start-bitstransfer|"
                            r"net\.webclient)", re.I)
URL_RX = re.compile(r"(?:https?|ftp)://[^\s'\"<>]+", re.I)
DELETERS = {"rm", "rmdir", "unlink", "shred", "find", "srm", "wipe", "mv", "trash", "trash-put", "gio", "rsync",
            "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh", "sdelete.exe", "sdelete64.exe", "robocopy.exe"}
WIPERS = {"shred", "wipe", "srm", "sdelete", "sdelete.exe", "sdelete64.exe", "secure-delete", "bleachbit", "wipefs",
          "blkdiscard", "cipher.exe", "eraser.exe", "nwipe", "dban"}


def exe_name(path_or_name: str) -> str:
    return str(path_or_name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def is_downloader(name: str, cmdline: str = "") -> bool:
    n = exe_name(name)
    if n in DOWNLOADERS or n in BROWSERS:
        return True
    return n in ("powershell.exe", "pwsh.exe", "pwsh", "powershell") and bool(PS_DOWNLOAD_RX.search(cmdline or ""))


def origin_of(path: str) -> Dict[str, str]:
    """Where a downloaded file came from: the xdg origin xattrs (Linux: Chromium, wget/curl --xattr...) or the
    Mark-of-the-Web Zone.Identifier stream (Windows)."""
    out: Dict[str, str] = {}
    if hasattr(os, "getxattr"):
        for attr, key in (("user.xdg.origin.url", "url"), ("user.xdg.referrer.url", "referrer")):
            try:
                out[key] = os.getxattr(path, attr, follow_symlinks=False).decode("utf-8", "replace")[:2048]
            except OSError:
                pass
    if os.name == "nt":
        try:
            with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh.read(8192).splitlines():
                    k, _, v = line.strip().partition("=")
                    if k in ("HostUrl", "ReferrerUrl", "ZoneId"):
                        out[{"HostUrl": "url", "ReferrerUrl": "referrer", "ZoneId": "zone"}[k]] = v
        except OSError:
            pass
    return out


@dataclass
class ProcRecord:
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    user: str
    cwd: str
    ppid: int = 0
    create_time: float = 0.0
    login_user: str = ""
    seen: float = field(default_factory=time.time)
    source: str = "psutil"
    args: List[str] = field(default_factory=list)        # absolute paths named on the command line (cached)
    patterns: List[Any] = field(default_factory=list)    # unexpanded globs (sh -c "rm -rf ~/Documents/*"), compiled

    @property
    def cmd(self) -> str:
        return " ".join(self.cmdline)

    def public(self) -> Dict[str, Any]:
        return {"pid": self.pid, "name": self.name, "exe": self.exe, "cmdline": self.cmd[:1000], "user": self.user,
                "ppid": self.ppid, "create_time": self.create_time, "cwd": self.cwd,
                "login_user": self.login_user}


GLOB_CHARS = set("*?[{")


def glob_regex(pattern: str):
    """Shell glob (with {a,b} and {1..9} braces) -> compiled regex matching whole paths."""
    sep = re.escape(os.sep) + ("/" if os.sep != "/" else "")
    notsep = f"[^{sep}]"
    out, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out += notsep + "*"
        elif c == "?":
            out += notsep
        elif c == "[" and "]" in pattern[i + 2:]:
            j = pattern.index("]", i + 2)
            body = pattern[i + 1:j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out += "[" + body.replace("\\", "\\\\") + "]"
            i = j
        elif c == "{" and "}" in pattern[i:]:
            j = pattern.index("}", i)
            body = pattern[i + 1:j]
            if ".." in body:
                a, _, b = body.partition("..")
                out += r"\d+" if a.lstrip("-").isdigit() and b.lstrip("-").isdigit() else "(?:" + notsep + ")"
            elif "," in body:
                out += "(?:" + "|".join(re.escape(x) for x in body.split(",")) + ")"
            else:
                out += re.escape("{" + body + "}")
            i = j
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out + r"\Z")


def _arg_paths(rec: ProcRecord) -> List[str]:
    """Absolute paths a command line refers to (relative ones resolved against the process cwd)."""
    args: List[str] = []
    for a in rec.cmdline[1:]:
        if " " in a and len(a) < 4000:                 # sh -c "cd x; rm -rf ~/docs && ..." / powershell -c "..."
            try:
                lex = shlex.shlex(a, posix=os.name != "nt", punctuation_chars=True)
                lex.whitespace_split = True
                args += [t for t in lex if t not in (";", "&&", "||", "|", "&", "(", ")", ">", "<", ">>")]
            except ValueError:
                args += a.split()
        else:
            args.append(a)
    home = home_of(rec.user.split("\\")[-1]) if rec.user else ""
    out = []
    for a in args:
        if a.startswith("-") and "=" in a:             # --output=file
            a = a.split("=", 1)[1]
        elif a.startswith("-") or not a or URL_RX.match(a):
            continue
        a = a.strip("'\"")
        if a.startswith("~") and home:
            a = home + a[1:]
        if not os.path.isabs(a):
            if not rec.cwd:
                continue
            a = os.path.join(rec.cwd, a)
        a = os.path.normpath(a)
        if GLOB_CHARS & set(a):
            try:
                rec.patterns.append(glob_regex(a))
            except re.error:
                pass
            continue
        out.append(a)
    return out


class Attributor:
    def __init__(self, window: float = 300.0) -> None:
        self.window = window
        self.recent: Deque[ProcRecord] = deque()
        self.max_recent = 20000
        self.by_pid: Dict[int, ProcRecord] = {}
        self.arg_index: Dict[str, List[ProcRecord]] = {}          # path named on a command line -> processes
        self.pattern_recs: List[ProcRecord] = []                  # processes with unexpanded globs
        self.handles: Dict[str, Tuple[float, ProcRecord]] = {}     # path -> (seen, process holding it open)
        self.kernel: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}   # (path, op) -> kernel record
        self.quarantined: Dict[str, float] = {}
        self.sessions: List[Dict[str, Any]] = []
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ evidence feeds
    def add_process(self, rec: ProcRecord) -> None:
        with self.lock:
            prev = self.by_pid.get(rec.pid)
            if prev and prev.create_time and rec.create_time and abs(prev.create_time - rec.create_time) < 0.05:
                prev.seen = rec.seen
                if rec.cwd and not prev.cwd:
                    prev.cwd = rec.cwd
                if rec.login_user and not prev.login_user:
                    prev.login_user = rec.login_user
                return
            rec.args = _arg_paths(rec)
            if rec.patterns:
                self.pattern_recs.append(rec)
            self.recent.append(rec)
            self.by_pid[rec.pid] = rec
            for a in rec.args:
                self.arg_index.setdefault(a, []).append(rec)
            while len(self.recent) > self.max_recent:
                self._drop(self.recent.popleft())

    def _drop(self, r: ProcRecord) -> None:
        if self.by_pid.get(r.pid) is r:
            del self.by_pid[r.pid]
        if r.patterns:
            try:
                self.pattern_recs.remove(r)
            except ValueError:
                pass
        for a in r.args:
            lst = self.arg_index.get(a)
            if lst is not None:
                try:
                    lst.remove(r)
                except ValueError:
                    pass
                if not lst:
                    del self.arg_index[a]

    def touch_alive(self, pids: Iterable[int], now: float) -> None:
        with self.lock:
            for pid in pids:
                r = self.by_pid.get(pid)
                if r:
                    r.seen = now

    def add_handle(self, path: str, rec: ProcRecord, now: float) -> None:
        with self.lock:
            self.handles[path] = (now, rec)

    def add_kernel(self, path: str, op: str, row: Dict[str, Any], now: float) -> None:
        with self.lock:
            self.kernel[(path, op)] = (now, row)

    def add_quarantine(self, path: str, now: float) -> None:
        with self.lock:
            self.quarantined[path] = now

    def prune(self, now: float) -> None:
        with self.lock:
            if self.recent and now - min(r.seen for r in self.recent) > self.window:
                keep: Deque[ProcRecord] = deque()
                for r in self.recent:
                    if now - r.seen > self.window:
                        self._drop(r)
                    else:
                        keep.append(r)
                self.recent = keep
            for k, (t, _) in list(self.handles.items()):
                if now - t > self.window:
                    del self.handles[k]
            for k, (t, _) in list(self.kernel.items()):
                if now - t > 120:
                    del self.kernel[k]
            for k, t in list(self.quarantined.items()):
                if now - t > 120:
                    del self.quarantined[k]

    # ------------------------------------------------------------------ queries
    def kernel_seen(self, path: str, op: str, ts: float, slack: float = 10.0) -> bool:
        with self.lock:
            hit = self.kernel.get((path, op))
            return bool(hit and abs(hit[0] - ts) <= slack)

    def by_cmdline(self, path: str, ts: float, op: str = "") -> Optional[ProcRecord]:
        """The process whose command line names ``path`` or its closest parent folder.

        Walks up the path's ancestors (O(depth) lookups in the argument index).  Among processes naming the
        same folder, deletions prefer deletion tools, then the most recently started process - an editor
        holding ``~/project`` open must not take the blame for ``rm -rf ~/project``."""
        def live(r: ProcRecord) -> bool:
            return r.seen >= ts - self.window and not (r.create_time and r.create_time > ts + 2)

        def rank(r: ProcRecord):
            return (op == "deleted" and exe_name(r.name) in DELETERS, r.create_time or r.seen)
        with self.lock:
            exact: Optional[Tuple[int, ProcRecord]] = None
            cur = path
            while True:
                cands = [r for r in self.arg_index.get(cur, ()) if live(r)]
                if cands:
                    exact = (len(cur), max(cands, key=rank))
                    break
                parent = os.path.dirname(cur)
                if not parent or parent == cur:
                    break
                cur = parent
            pattern: Optional[Tuple[int, ProcRecord]] = None
            for r in self.pattern_recs:                 # sh -c "rm -rf ~/Documents/*", report{1..40}.csv ...
                if not live(r):
                    continue
                cur = path
                while True:
                    if any(rx.match(cur) for rx in r.patterns):
                        if pattern is None or (len(cur), rank(r)) > (pattern[0], rank(pattern[1])):
                            pattern = (len(cur), r)
                        break
                    parent = os.path.dirname(cur)
                    if not parent or parent == cur:
                        break
                    cur = parent
            if exact and (not pattern or exact[0] >= pattern[0]):
                return exact[1]
            return pattern[1] if pattern else None

    def attribute(self, path: str, op: str, ts: float, target: str = "") -> Dict[str, Any]:
        """{user, login_user, pid, process, exe, attribution, evidence} for one file event."""
        with self.lock:
            q = self.quarantined.get(path)
            if q is not None and op in ("deleted", "renamed") and abs(q - ts) < 120:
                return {"user": "El Doctor", "attribution": "self", "process": "eldoctor", "pid": os.getpid(),
                        "evidence": "moved to El Doctor quarantine by a response action"}
            h = self.handles.get(path) or (self.handles.get(target) if target else None)
        if h and abs(h[0] - ts) <= 60:
            return self._from_proc(h[1], "handle", "the process had the file open")
        rec = self.by_cmdline(path, ts, op) or (self.by_cmdline(target, ts, op) if target else None)
        if rec:
            return self._from_proc(rec, "cmdline", "the process command line names this file or a parent folder")
        return self.infer(path)

    def infer(self, path: str) -> Dict[str, Any]:
        owner = self.home_owner(path)
        logged = sorted({s["user"] for s in self.sessions if s.get("user")})
        if owner and owner in logged:
            return {"user": owner, "attribution": "inferred",
                    "evidence": f"{owner} owns this home folder and was logged in (no process evidence)"}
        if len(logged) == 1:
            return {"user": logged[0], "attribution": "inferred",
                    "evidence": f"{logged[0]} was the only logged-in user (no process evidence)"}
        if owner:
            return {"user": "", "attribution": "unknown", "home_owner": owner,
                    "evidence": f"no process evidence; the folder belongs to {owner}"}
        return {"user": "", "attribution": "unknown", "evidence": "no process evidence"}

    @staticmethod
    def _from_proc(rec: ProcRecord, how: str, why: str) -> Dict[str, Any]:
        return {"user": rec.user, "login_user": rec.login_user, "pid": rec.pid, "process": rec.name, "exe": rec.exe,
                "cmdline": rec.cmd[:1000], "create_time": rec.create_time, "attribution": how, "evidence": why}

    @staticmethod
    def home_owner(path: str) -> str:
        p = path.replace("\\", "/")
        m = re.match(r"^/home/([^/]+)/", p) or re.match(r"^/Users/([^/]+)/", p) or \
            re.match(r"^[A-Za-z]:/Users/([^/]+)/", p)
        if m and m.group(1).lower() not in ("public", "default", "all users", "shared"):
            return m.group(1)
        if p.startswith("/root/"):
            return "root"
        return ""


# --------------------------------------------------------------------------- open-handle sampling
def scan_handles(in_scope, under) -> List[Tuple[str, ProcRecord]]:
    """(path, process) for every regular file held open by an in-scope process below the watched roots.

    ``in_scope(username)`` limits the scan to people's processes; ``under(path)`` to the watched folders."""
    out: List[Tuple[str, ProcRecord]] = []
    me = os.getpid()
    for p in psutil.process_iter(["pid", "name", "exe", "username", "cmdline", "ppid", "create_time"]):
        try:
            info = p.info
            if info["pid"] == me or not in_scope(info.get("username") or ""):
                continue
            files = p.open_files()
        except (psutil.Error, OSError):
            continue
        rec = None
        for f in files:
            if not under(f.path):
                continue
            if rec is None:
                rec = ProcRecord(info["pid"], info.get("name") or "", info.get("exe") or "",
                                 list(info.get("cmdline") or []), info.get("username") or "", "",
                                 info.get("ppid") or 0, float(info.get("create_time") or 0), source="handles")
            out.append((f.path, rec))
    return out


def live_process(pid: int, create_time: float = 0.0) -> Optional[Dict[str, Any]]:
    """The process as a response playbook needs it (identity-checked against PID reuse), if still running."""
    try:
        p = psutil.Process(int(pid))
        with p.oneshot():
            ct = p.create_time()
            if create_time and abs(ct - float(create_time)) > 0.05:
                return None
            return {"pid": p.pid, "ppid": p.ppid(), "name": p.name(), "exe": _safe(p.exe), "cmdline":
                    " ".join(_safe(p.cmdline, [])), "username": _safe(p.username), "create_time": ct}
    except (psutil.Error, OSError, ValueError):
        return None


def _safe(fn, default: Any = "") -> Any:
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


def is_in_scope(username: str, scope: str) -> bool:
    return scope == "all" or is_human(username)
