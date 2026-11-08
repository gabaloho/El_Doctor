"""User-activity recorder for forensics and triage.

What is recorded (table ``activity``, one row per event, sealed in the signed audit chain):

  session   who logged in / out (console, terminal, remote), remote logins (sshd), privilege use (sudo),
            logins found in wtmp that happened while El Doctor was not running
  process   every application started / stopped by a person's account (and the inventory at start-up)
  file      created, edited, deleted (incl. moved to the Trash), renamed/moved, opened and downloaded
            files below the watched folders - each with the user / process responsible and *how* that is
            known (``attribution``: kernel, handle, cmdline, inferred, unknown)
  system    boots, shutdowns (clean or not), monitoring gaps (agent stopped), lost events
  incident  data-wipe incidents (mass deletion, live or found at start-up), El Doctor evidence deleted

Records survive shutdowns and reboots (SQLite + a persisted index of the watched folders).  At start-up
the agent compares the folders with their last known state, so files deleted while it was not running -
e.g. a disk wiped from another system - are still found and reported.  Data-wipe incidents are e-mailed
to the registered administrators with the complete list of affected files and folders.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import queue
import re
import stat as _st
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import psutil

from eldoctor.activity.attribution import (Attributor, ProcRecord, is_downloader, is_in_scope, live_process,
                                           origin_of, scan_handles)
from eldoctor.activity.fswatch import (InotifyUnavailable, InotifyWatcher, PathFilter, RawFileEvent, is_partial,
                                       is_temp, norm)
from eldoctor.activity.report import AdminReporter
from eldoctor.activity.rules import ACTIVITY_RULES
from eldoctor.activity.scanner import Scanner
from eldoctor.activity.sessions import SessionTracker, is_human, read_wtmp, wtmp_sessions
from eldoctor.activity.wipe import WipeDetector, WipeIncident, human_bytes
from eldoctor.config import IS_LINUX, IS_WINDOWS, home_dir, is_privileged
from eldoctor.models import Alert

_ZEROS = re.compile(r"^0+$")                    # shred -u renames a file to 000..0, 00..0, ... before unlinking it
TRASH_MARKERS = ("/.local/share/Trash/files/", "/.Trash/", "/.Trash-", "\\$Recycle.Bin\\", "/$RECYCLE.BIN/")
XBEL = "recently-used.xbel"
SEAL_NOW = {"file_deleted", "file_downloaded", "wipe_incident", "evidence_deleted", "privilege_use", "remote_login"}
EVIDENCE_NAMES = ("eldoctor.db", "keys", "audit.jsonl", "alerts.jsonl", "evidence", "quarantine")


def boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return f"boot-{int(psutil.boot_time())}"


def default_roots(privileged: bool) -> List[str]:
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        users = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
        return [users] if privileged and os.path.isdir(users) else [home]
    if sys.platform == "darwin":
        return ["/Users"] if privileged else [home]
    if privileged:
        return [r for r in ("/home", "/root") if os.path.isdir(r)]
    return [home]


def safe_open(path: str, max_bytes: int) -> Optional[int]:
    """fd of a *regular* file no larger than max_bytes, never following a symlink and never blocking.

    Files in people's folders are attacker-controlled: a FIFO named like a download would block a plain open()
    forever (the agent would stop), and a symlink would make a privileged agent read any file on the system."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not _st.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            os.close(fd)
            return None
        return fd
    except OSError:
        os.close(fd)
        return None


def _sha256(path: str, max_bytes: int) -> str:
    fd = safe_open(path, max_bytes)
    if fd is None:
        return ""
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class _Pending:
    __slots__ = ("op", "path", "target", "is_dir", "ts", "due", "details", "source")

    def __init__(self, ev: RawFileEvent, due: float) -> None:
        self.op, self.path, self.target, self.is_dir = ev.op, ev.path, ev.target, ev.is_dir
        self.ts, self.due, self.details, self.source = ev.ts, due, dict(ev.details), ev.source


class ActivityMonitor:
    def __init__(self, cfg: Dict[str, Any], store, iocs=None, errors: Optional[Any] = None,
                 session_provider: Optional[Callable[[], List[Any]]] = None) -> None:
        ac = cfg.get("activity") or {}
        self.full_cfg = cfg
        self.ac = ac
        self.store = store
        self.iocs = iocs
        self.errors = errors if errors is not None else []
        self.enabled = bool(ac.get("enabled", True))
        pc = ac.get("processes") or {}
        fc = ac.get("files") or {}
        wc = ac.get("wipe") or {}
        self.proc_enabled = bool(pc.get("enabled", True))
        self.scope = str(pc.get("scope", "users"))
        self.proc_exclude = {n.lower() for n in pc.get("exclude_names") or []}
        self.inventory = bool(pc.get("record_inventory", True))
        self.files_enabled = bool(fc.get("enabled", True))
        self.backend_cfg = str(fc.get("backend", "auto"))
        privileged = is_privileged()
        roots = fc.get("paths") or "auto"
        self.roots = [norm(r) for r in (default_roots(privileged) if roots == "auto" else roots)]
        never = [str(home_dir())] + [str(x) for x in fc.get("never_watch") or []]
        try:
            from eldoctor.config import client_dir
            never.append(str(client_dir()))
        except Exception:
            pass
        self.flt = PathFilter(self.roots, fc.get("exclude") or [], fc.get("include") or [], never)
        self.record_opens = bool(fc.get("record_opens", True))
        self.open_dedupe = float(fc.get("open_dedupe_seconds", 600))
        self.max_opens = int(fc.get("max_open_events_per_minute", 300))
        self.download_names = {d.lower() for d in fc.get("download_dirs") or ["Downloads"]}
        self.hash_max = int(float(fc.get("hash_max_mb", 50)) * 1024 * 1024)
        self.poll_interval = float(fc.get("poll_interval", 60))
        self.handles_interval = float(fc.get("open_handles_interval", 30))
        self.max_files = int(fc.get("max_files", 500_000))
        self.max_watches = int(fc.get("max_watches", 100_000))
        self.merge_delay = float(fc.get("merge_delay", 0.7))
        self.handle_scan = bool(fc.get("handle_scan", True))              # on-demand open-files scan (attribution)
        self.handle_scan_gap = float(fc.get("handle_scan_min_interval", 2.0))
        self.wipe = WipeDetector(int(wc.get("threshold", 50)), float(wc.get("window", 60)), float(wc.get("quiet", 20)))
        self.wipe_enabled = bool(wc.get("enabled", True))
        self.retention = float(ac.get("retention_days", 0) or 0)
        self.heartbeat_every = float(ac.get("heartbeat_seconds", 30))
        self.seal_interval = float(ac.get("seal_interval", 60))
        self._last_seal = time.time()
        self.disabled_rules = set((cfg.get("detection") or {}).get("disabled_rules") or [])
        self.boot_id = boot_id()
        self.sessions = SessionTracker(session_provider)
        self.attr = Attributor(float(ac.get("attribution_window", 300)))
        self.reporter = AdminReporter(cfg, store, self.errors)
        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.pending: Dict[str, _Pending] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.opened: Dict[str, float] = {}
        self.open_pairs: Dict[Tuple[int, str], float] = {}
        self.open_overflow: Counter = Counter()
        self.open_minute = (0.0, 0)
        self.saving: Dict[str, float] = {}
        self.shred_chain: Dict[str, Tuple[str, float, Dict[str, Any]]] = {}   # zero-name -> (original, ts, who)
        self.shred_sizes: Dict[str, Optional[int]] = {}
        self.self_reads: Dict[str, float] = {}
        self.xbel_seen: Dict[str, set] = {}
        self.evidence_present: Dict[str, bool] = {}
        self.incident_alert: Optional[Alert] = None
        self.kernel_files = False            # auditd / Sysmon file telemetry seen -> hold inotify events to merge
        self.started = False
        self.stopped = False
        self.backend = "off"
        self.watcher: Optional[InotifyWatcher] = None
        self.scanner: Optional[Scanner] = None
        self.last_scan: Dict[str, Any] = {}
        self.gap: Tuple[float, float] = (0.0, 0.0)
        self.state: Dict[str, Any] = {}
        self._stop = threading.Event()
        self._fs_thread: Optional[threading.Thread] = None
        self._last_hb = 0.0
        self._last_handles = 0.0
        self._last_prune = 0.0
        self._initial_apps = True
        self.counts: Counter = Counter()
        self._lock = threading.RLock()

    # ================================================================== lifecycle
    def start(self) -> None:
        with self._lock:
            if self.started or not self.enabled:
                return
            self.started = True
        try:
            self._system_start()
        except Exception as exc:
            self.errors.append(f"activity start-up: {exc!r}")
        self.reporter.start()
        if self.files_enabled and self.roots:
            self._xbel_baseline()
            self._fs_thread = threading.Thread(target=self._fs_loop, daemon=True, name="eldoctor-activity-files")
            self._fs_thread.start()

    def stop(self, clean: bool = True) -> None:
        if not self.started or self.stopped:
            return
        self.stopped = True
        self._stop.set()
        if self._fs_thread:
            self._fs_thread.join(timeout=5)
        now = time.time()
        try:
            rows, ops = self._finalize(now, force=True)
            rows.append(self._row("monitoring_stopped", "system", now, source="agent",
                                  details={"clean": clean, "boot_id": self.boot_id}))
            self._write(rows, now, ops)
            if self.wipe.current is not None:          # a shutdown in the middle of a wipe: report what we have
                self._close_incident(self.wipe.current, now, note="El Doctor was stopping")
                self.wipe.current = None
            self.store.seal_activity()
            self._save_state(now, clean=clean)
            self.store.audit("agent", "activity_monitor_stopped", {"clean": clean})
        except Exception as exc:
            self.errors.append(f"activity stop: {exc!r}")
        self.reporter.deliver()                        # best effort before shutdown; the outbox keeps the rest
        self.reporter.stop()
        if self.watcher:
            self.watcher.close()

    # ================================================================== boots, shutdowns, gaps, sessions
    def _save_state(self, now: float, clean: bool = False) -> None:
        self.state = {"boot_id": self.boot_id, "boot_time": psutil.boot_time(), "heartbeat": now,
                      "clean_stop": clean, "sessions": self.sessions.current()}
        self.store.meta_set("activity_state", self.state)
        self._last_hb = now

    def _system_start(self) -> None:
        now = time.time()
        recovered = self.store.seal_recovered_activity()
        if recovered:
            self.store.audit("agent", "activity_recovered", {"rows": recovered, "note": "written before an unclean stop"})
        prev = self.store.meta_get("activity_state") or {}
        boot = psutil.boot_time()
        rows: List[Dict[str, Any]] = []
        alerts: List[Alert] = []
        last = float(prev.get("heartbeat") or 0)
        rebooted = bool(prev) and prev.get("boot_id") != self.boot_id
        self.gap = (last or boot, now)
        if not prev:
            rows.append(self._row("system_boot", "system", boot, source="agent",
                                  details={"boot_id": self.boot_id, "note": "first start of the activity recorder"}))
        elif rebooted:
            clean = bool(prev.get("clean_stop"))
            rows.append(self._row("system_shutdown", "system", last, source="agent",
                                  details={"boot_id": prev.get("boot_id"), "clean": clean,
                                           "note": "last sign of life of El Doctor before the restart" if clean else
                                           "El Doctor did not stop cleanly: power loss, crash, or forced shutdown"}))
            rows.append(self._row("system_boot", "system", boot, source="agent", details={"boot_id": self.boot_id}))
            self.store.audit("agent", "system_restarted", {"shutdown_near": last, "clean": clean, "boot": boot})
        else:
            clean = bool(prev.get("clean_stop"))
            rows.append(self._row("monitoring_gap", "system", last, source="agent",
                                  details={"from": last, "until": now, "seconds": round(now - last),
                                           "clean_stop": clean, "boot_id": self.boot_id}))
            self.store.audit("agent", "monitoring_gap", {"from": last, "until": now, "clean_stop": clean})
            if not clean and now - last > 3 * max(self.heartbeat_every, 10):
                a = self._alert("ED-ACT-005", evidence={"from": last, "until": now, "seconds": round(now - last)},
                                dedup=f"ED-ACT-005|{int(last)}")
                if a:
                    alerts.append(a)
        rows.append(self._row("monitoring_started", "system", now, source="agent",
                              details={"boot_id": self.boot_id, "roots": self.roots, "pid": os.getpid()}))
        ended, started = self.sessions.restore(prev.get("sessions") or [], now, self.gap[0], rebooted)
        for s in ended:
            rows.append(self._session_row("session_end", s, float(self.gap[0]), source="agent",
                                          extra={"ended_between": s.get("ended_between"), "reason": s.get("reason")}))
        late = self._wtmp_rows(self.gap[0], now) if prev else []
        rows += late
        late_keys = {(r["user"], (r.get("details") or {}).get("terminal"), int(r["ts"])) for r in late
                     if r["kind"] == "session_start"}
        for s in started:
            if (s["user"], s.get("terminal"), int(s.get("started") or 0)) not in late_keys:
                rows.append(self._session_row("session_start", s, float(s.get("started") or now), source="utmp",
                                              extra={"observed_at_startup": True}))
        self.attr.sessions = self.sessions.current()
        self._recover_incident(prev)
        self._write(rows, now)
        self._save_state(now)
        self._startup_alerts = alerts
        self.store.audit("agent", "activity_monitor_started",
                         {"roots": self.roots, "boot_id": self.boot_id, "rebooted": rebooted,
                          "gap_from": self.gap[0], "sessions": [s["user"] for s in self.sessions.current()]})

    def _wtmp_rows(self, since: float, until: float) -> List[Dict[str, Any]]:
        path = str(self.ac.get("wtmp", "/var/log/wtmp"))
        if not IS_LINUX or not os.access(path, os.R_OK):
            return []
        rows = []
        for s in wtmp_sessions(read_wtmp(path, since=since, until=until)):
            if s.get("marker"):
                continue
            rows.append(self._session_row("session_start", s, s["started"], source="wtmp",
                                          extra={"recorded_late": True}))
            if s.get("ended"):
                rows.append(self._session_row("session_end", s, s["ended"], source="wtmp",
                                              extra={"recorded_late": True, "ended_by": s.get("ended_by", "logout")}))
        return rows

    def _recover_incident(self, prev: Dict[str, Any]) -> None:
        """A wipe incident that was still open when the agent died: report it now from the recorded rows."""
        inc = self.store.meta_get("activity_open_incident")
        if not inc:
            return
        try:
            w = WipeIncident(inc["id"], float(inc["started"]), float(inc["started"]), alert_id=inc.get("alert_id", ""))
            after = int(inc.get("first_id") or 1) - 1
            while True:
                chunk = self.store.query("SELECT * FROM activity WHERE id > ? AND kind = 'file_deleted' AND ts <= ?"
                                         " ORDER BY id LIMIT 5000", (after, float(prev.get("heartbeat") or time.time())))
                if not chunk:
                    break
                for r in chunk:
                    r["details"] = _json(r.get("details"))
                    w.add(r)
                after = chunk[-1]["id"]
            w.closed = True
            if w.total:
                alert = {"id": inc.get("alert_id"), "rule_id": "ED-ACT-001", "severity": "critical",
                         "title": ACTIVITY_RULES["ED-ACT-001"][0]}
                self._queue_wipe_report(w, alert, note="El Doctor stopped before the incident ended (shutdown or "
                                                       "crash); this report was completed after the restart")
        except Exception as exc:
            self.errors.append(f"incident recovery: {exc!r}")
        self.store.meta_set("activity_open_incident", None)

    # ================================================================== rows & alerts
    def _row(self, kind: str, category: str, ts: float, **kw: Any) -> Dict[str, Any]:
        r = {"ts": ts, "kind": kind, "category": category, "boot_id": self.boot_id, "user": "", "login_user": "",
             "pid": None, "process": "", "exe": "", "path": "", "target": "", "is_dir": 0, "size": None,
             "source": "", "attribution": "", "details": {}}
        r.update({k: v for k, v in kw.items() if v is not None or k in ("pid", "size")})
        return r

    def _session_row(self, kind: str, s: Dict[str, Any], ts: float, source: str, extra=None) -> Dict[str, Any]:
        det = {"terminal": s.get("terminal") or "", "host": s.get("host") or "", "type": s.get("type", ""),
               "started": s.get("started")}
        det.update({k: v for k, v in (extra or {}).items() if v is not None})
        return self._row(kind, "session", ts, user=s.get("user") or "", login_user=s.get("user") or "",
                         pid=s.get("pid"), source=source, attribution="direct", details=det)

    def _alert(self, rule_id: str, process: Optional[Dict[str, Any]] = None, evidence=None, title: str = "",
               severity: str = "", dedup: str = "", description: str = "") -> Optional[Alert]:
        if rule_id in self.disabled_rules:
            return None
        t, sev, mitre, desc = ACTIVITY_RULES[rule_id]
        return Alert(rule_id=rule_id, title=title or t, severity=severity or sev, source="activity",
                     mitre=list(mitre), description=description or desc, process=process, evidence=evidence or {},
                     dedup_key=dedup or "", tags=["activity"])

    def _write(self, rows: List[Dict[str, Any]], now: float, index_ops=None, in_tx=None, seal: bool = False) -> None:
        """Commit rows now; seal them in the signed chain now if they matter most (deletions, sessions, boots,
        incidents, downloads) or when ``seal_interval`` has passed - otherwise with the next seal."""
        if not rows and not index_ops and in_tx is None:
            return
        seal = seal or now - self._last_seal >= self.seal_interval or \
            any(r["kind"] in SEAL_NOW or r["category"] in ("session", "system", "incident") for r in rows)
        ids = self.store.add_activity(rows, index_ops, in_tx, seal=seal)
        if seal:
            self._last_seal = now
        for r, i in zip(rows, ids):
            r["id"] = i
            self.counts[r["kind"]] += 1
        self._jsonl(rows)
        for r in rows:                                  # the few events SIEMs must have even if the host is wiped
            if r["kind"] in ("session_start", "session_end", "remote_login", "privilege_use") and \
                    r.get("source") not in ("wtmp",):
                self.store.audit(r["user"] or "?", f"user_{r['kind']}",
                                 {"user": r["user"], "terminal": r["details"].get("terminal"),
                                  "host": r["details"].get("host"), "activity_id": r.get("id"),
                                  **({"command": r["details"].get("command")} if r["kind"] == "privilege_use" else {})})

    def _jsonl(self, rows: List[Dict[str, Any]]) -> None:
        name = self.ac.get("jsonl")
        if not name or not rows:
            return
        try:
            with open(home_dir() / str(name), "a", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(dict(r, host=_host(), time_iso=time.strftime(
                        "%Y-%m-%dT%H:%M:%S%z", time.localtime(r["ts"]))), default=str) + "\n")
        except OSError as exc:
            self.errors.append(f"activity jsonl: {exc}")

    # ================================================================== the agent cycle
    def tick(self, procs=None, new=None, log_events=None, now: Optional[float] = None) -> List[Alert]:
        if not self.enabled:
            return []
        if not self.started:
            self.start()
        now = now or time.time()
        alerts: List[Alert] = list(getattr(self, "_startup_alerts", []) or [])
        self._startup_alerts = []
        rows: List[Dict[str, Any]] = []
        try:
            started, ended = self.sessions.poll()
            for s in started:
                rows.append(self._session_row("session_start", s, float(s.get("started") or now), source="utmp"))
            for s in ended:
                rows.append(self._session_row("session_end", s, now, source="utmp",
                                              extra={"duration_s": round(now - float(s.get("started") or now))}))
            self.attr.sessions = self.sessions.current()
            if procs is not None and self.proc_enabled:
                rows += self._apps(procs, new or [], now)
            rows += self._logs(log_events or [], now)
            alerts += self._evidence_check(now)
            batch_alerts, batch_rows = self._drain(now)
            alerts += batch_alerts
            if self.pending:
                self._maybe_scan_handles(now)
            file_rows, ops = self._finalize(now)
            rows += file_rows
            rows += self._open_overflow_rows(now)
            self._write(rows, now, ops)
            deletions = [r for r in rows if r["kind"] == "file_deleted"] + batch_rows
            alerts += self._downloads(rows)
            if self.wipe_enabled:
                alerts += self._wipe_tick(deletions, now)
            if started or ended or now - self._last_hb >= self.heartbeat_every:
                self._save_state(now)
            if now - self._last_seal >= self.seal_interval:
                self.store.seal_activity()
                self._last_seal = now
            self.attr.prune(now)
            self._housekeeping(now)
        except Exception as exc:                 # activity recording must never stop detection & response
            import traceback
            self.errors.append(f"activity tick: {exc!r}")
            try:
                self.store.audit("agent", "activity_error", {"error": repr(exc), "trace": traceback.format_exc()[-1200:]})
            except Exception:
                pass
        return alerts

    # ------------------------------------------------------------------ applications
    def _apps(self, procs, new, now: float) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        initial = self._initial_apps
        self._initial_apps = False
        for p in new:
            cwd = ""
            try:
                cwd = psutil.Process(p.pid).cwd()
            except (psutil.Error, OSError):
                pass
            self.attr.add_process(ProcRecord(p.pid, p.name, p.exe, list(p.cmdline), p.username, cwd, p.ppid,
                                             p.create_time, seen=now))
            if not is_in_scope(p.username, self.scope) or p.name.lower() in self.proc_exclude:
                continue
            if p.ppid == 2 and not p.exe:                # kernel threads
                continue
            self.apps[p.key] = {"pid": p.pid, "name": p.name, "user": p.username, "create_time": p.create_time,
                                "exe": p.exe}
            if initial and not self.inventory:
                continue
            rows.append(self._row("app_running" if initial else "app_start", "process",
                                  now if initial else (p.create_time or now), user=p.username, pid=p.pid,
                                  process=p.name, exe=p.exe, source="psutil", attribution="direct",
                                  details={"cmdline": p.cmdline_str[:2000], "ppid": p.ppid, "parent": p.parent_name,
                                           "sha256": p.sha256, "cwd": cwd, "create_time": p.create_time,
                                           "terminal": _terminal(p.pid)}))
        alive = {p.key for p in procs}
        self.attr.touch_alive((p.pid for p in procs), now)
        for key in [k for k in self.apps if k not in alive]:
            a = self.apps.pop(key)
            rows.append(self._row("app_stop", "process", now, user=a["user"], pid=a["pid"], process=a["name"],
                                  exe=a["exe"], source="psutil", attribution="direct",
                                  details={"runtime_s": round(now - float(a["create_time"] or now), 1),
                                           "create_time": a["create_time"]}))
        return rows

    # ------------------------------------------------------------------ kernel / OS telemetry from the log sources
    def _logs(self, events: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for ev in events:
            try:
                rows += self._log_event(ev, now)
            except Exception as exc:
                self.errors.append(f"activity log event: {exc!r}")
        return rows

    def _log_event(self, ev: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        cat, et = ev.get("category"), ev.get("event_type", "")
        f = ev.get("fields") or {}
        ts = float(ev.get("ts") or now)
        if cat == "process_creation" and ev.get("process", {}).get("pid"):
            p = ev["process"]
            cmd = p.get("cmdline") or []
            self.attr.add_process(ProcRecord(int(p["pid"]), p.get("name") or "", p.get("exe") or "",
                                             cmd if isinstance(cmd, list) else str(cmd).split(" "),
                                             p.get("username") or "", p.get("cwd") or f.get("CurrentDirectory") or "",
                                             int(p.get("ppid") or 0), 0.0, login_user=f.get("auid") or "",
                                             seen=ts, source=ev.get("source") or "log"))
            return []
        if cat == "file_event" and ev.get("file"):
            return self._kernel_file(ev, ts)
        if et == "ssh_success":
            return [self._row("remote_login", "session", ts, user=f.get("user", ""), login_user=f.get("user", ""),
                              source=ev.get("source") or "authlog", attribution="direct",
                              details={"host": f.get("src_ip", ""), "method": f.get("method", ""),
                                       "port": f.get("port", ""), "terminal": "ssh"})]
        if et == "sudo_command":
            return [self._row("privilege_use", "session", ts, user=f.get("user", ""), login_user=f.get("user", ""),
                              source=ev.get("source") or "authlog", attribution="direct",
                              details={"as_user": f.get("target", ""), "command": (f.get("command") or "")[:1000],
                                       "terminal": "sudo"})]
        if et in ("logon_success", "logoff") and ev.get("product") == "windows":
            lt = str(f.get("LogonType") or "")
            if et == "logon_success" and lt not in ("2", "7", "10", "11"):
                return []                                # service / network logons are not people sitting down
            user = f.get("TargetUserName") or f.get("user") or ""
            dom = f.get("TargetDomainName") or ""
            if not is_human(f"{dom}\\{user}" if dom else user):
                return []
            kind = "session_start" if et == "logon_success" else "session_end"
            return [self._row(kind, "session", ts, user=user, login_user=user, source="winsec", attribution="direct",
                              details={"logon_type": lt, "host": f.get("IpAddress", ""), "logon_id":
                                       f.get("TargetLogonId", ""), "type": {"2": "console", "10": "remote",
                                                                            "11": "console", "7": "unlock"}.get(lt, "")})]
        return []

    def _kernel_file(self, ev: Dict[str, Any], ts: float) -> List[Dict[str, Any]]:
        fe = ev["file"]
        path = fe.get("path") or ""
        if not path or int(fe.get("pid") or 0) == os.getpid():
            return []
        for n in self.flt.never:
            if path == n or path.startswith(n.rstrip(os.sep) + os.sep):
                return []
        root = self.flt.root_of(path)
        if root is not None and not self.flt.watched(path, bool(fe.get("is_dir"))):
            return []                                   # excluded folder (cache...)
        if is_temp(os.path.basename(path)) and fe["op"] != "renamed":
            return []
        self.kernel_files = True
        op = fe["op"]
        target = fe.get("target") or ""
        kind = {"created": "file_created", "modified": "file_modified", "deleted": "file_deleted",
                "renamed": "file_renamed", "opened": "file_opened", "attributes": "file_attributes"}.get(op, "file_" + op)
        det = {"cmdline": (fe.get("cmdline") or "")[:1000], "syscall": fe.get("syscall", ""), "ppid": fe.get("ppid"),
               "evidence": f"recorded by {ev.get('source')}", "event_id": ev.get("event_id"), "url": fe.get("url"),
               "archived": fe.get("archived"), "path_relative": fe.get("relative") or None}
        if op == "renamed" and target and self._in_trash(target) and not self._in_trash(path):
            kind, det["trashed"], det["trash_path"] = "file_deleted", True, target
        prev = self.store.file_index_get(path) if op in ("deleted", "renamed") else None
        size = fe.get("size") if fe.get("size") is not None else (prev or {}).get("size")
        self.attr.add_kernel(path, op, {}, ts)
        if target:
            self.attr.add_kernel(target, op, {}, ts)
        if op == "renamed":
            self.attr.add_kernel(path, "deleted", {}, ts)
            self.attr.add_kernel(target, "created", {}, ts)
        if kind == "file_created" and (self._in_download_dir(path) or is_downloader(fe.get("process") or "")):
            kind = "file_downloaded"
        return [self._row(kind, "file", ts, user=fe.get("user") or "", login_user=fe.get("login_user") or "",
                          pid=fe.get("pid"), process=fe.get("process") or "", exe=fe.get("exe") or "", path=path,
                          target="" if det.get("trashed") else target, is_dir=int(bool(fe.get("is_dir"))),
                          size=size, source=ev.get("source") or "kernel", attribution="kernel",
                          details={k: v for k, v in det.items() if v not in (None, "")})]

    # ------------------------------------------------------------------ file events from the watcher thread
    def _drain(self, now: float) -> Tuple[List[Alert], List[Dict[str, Any]]]:
        alerts: List[Alert] = []
        deletions: List[Dict[str, Any]] = []
        while True:
            try:
                item = self.q.get_nowait()
            except queue.Empty:
                break
            kind = item[0]
            if kind == "events":
                for ev in item[1]:
                    self._ingest(ev, now)
            elif kind == "batch":
                a, d = self._record_batch(*item[1:], now=now)
                alerts += a
                deletions += d
            elif kind == "handles":
                self._handles(item[1], now)
            elif kind == "system":
                self._write([self._row(item[1], "system", now, source="agent", details=item[2])], now)
        return alerts, deletions

    def _ingest(self, ev: RawFileEvent, now: float) -> None:
        """Coalesce raw events per path (create+write = one creation, atomic saves, partial downloads...)."""
        if ev.op == "root_gone":
            ev = RawFileEvent(ev.ts, "deleted", ev.path, is_dir=True, source=ev.source,
                              details=dict(ev.details, watched_root=True))
            self.errors.append(f"watched folder {ev.path} was {ev.details.get('how', 'removed')}")
        parent = os.path.dirname(ev.path)
        if os.path.basename(ev.target or ev.path) == XBEL and ev.op in ("modified", "created", "renamed"):
            self._xbel(ev.target or ev.path, now)       # GTK saves it via a temp file renamed over it
            return
        if self.flt.route_only(parent) and ev.op != "renamed":
            return
        delay = self.merge_delay + (2.0 if self.kernel_files else 0.0)
        p = self.pending.get(ev.path)
        if ev.op == "opened":
            if p is not None or self.self_reads.get(ev.path, 0) > now - 30:
                return                                   # the creator / writer opened it - or El Doctor did
            last = self.opened.get(ev.path)
            if last and now - last < self.open_dedupe:
                return
        if ev.op == "renamed":
            src_tmp = is_temp(os.path.basename(ev.path)) or is_partial(os.path.basename(ev.path))
            dst_name = os.path.basename(ev.target)
            if is_temp(dst_name) and not ev.is_dir:       # x -> x~ (backup before an editor saves x)
                self.saving[ev.path] = now
                return
            if src_tmp and not ev.is_dir:                 # atomic save / finished download onto the target
                existed = self.store.file_index_get(ev.target) is not None or ev.target in self.pending
                partial = is_partial(os.path.basename(ev.path))
                op = "created" if (partial or not existed) else "modified"
                det = dict(ev.details, via=os.path.basename(ev.path))
                if partial:
                    det["download_completed"] = True
                self._put(RawFileEvent(ev.ts, op, ev.target, is_dir=False, source=ev.source, details=det), now + delay)
                return
        if p is not None:
            if ev.op == "modified" and p.op in ("created", "modified"):
                p.due = max(p.due, now + delay)
                return
            if ev.op == "deleted" and p.op == "created" and not ev.is_dir:
                del self.pending[ev.path]                  # short-lived scratch file: not worth a record
                return
            if ev.op == "deleted" and p.op == "modified":
                ev.details["overwritten_before_delete"] = True
                del self.pending[ev.path]
            elif ev.op == "created" and p.op == "deleted":
                del self.pending[ev.path]                  # deleted and re-created = replaced
                ev = RawFileEvent(ev.ts, "modified", ev.path, source=ev.source, details=dict(ev.details, replaced=True))
        if ev.op == "created" and self.saving.pop(ev.path, 0) > now - 10:
            ev = RawFileEvent(ev.ts, "modified", ev.path, source=ev.source, details=dict(ev.details, saved_via_backup=True))
        due = now + delay
        if ev.op == "created" and not ev.is_dir and self._in_download_dir(ev.path):
            try:
                st = os.lstat(ev.path)
                if _st.S_ISREG(st.st_mode) and st.st_size == 0:
                    due = now + 60                        # browser placeholder: wait for the download to finish
            except OSError:
                pass
        self._put(ev, due)

    def _put(self, ev: RawFileEvent, due: float) -> None:
        key = ev.path if ev.op != "renamed" else f"{ev.path}\0{ev.target}"
        old = self.pending.get(key)
        if old is not None and old.op == "created" and ev.op == "created":
            old.details.update(ev.details)
            old.due = min(old.due, due) if not ev.details.get("download_completed") else due
            return
        self.pending[key] = _Pending(ev, due)

    def _finalize(self, now: float, force: bool = False) -> Tuple[List[Dict[str, Any]], List[tuple]]:
        """Due pending events -> (rows, file-index ops).  Events dropped as duplicates of a kernel record still
        update the index, so the start-up comparison never reports them a second time."""
        rows: List[Dict[str, Any]] = []
        ops: List[tuple] = []
        def ready(p: _Pending) -> bool:
            if force:
                return True
            if p.due > now:
                return False
            # opens / writes wait (at most 3 s) for an open-files scan taken after they happened
            if self.handle_scan and p.op in ("opened", "modified", "created") and not p.is_dir:
                return self._last_handles >= p.ts or now - p.ts > 3.0
            return True
        for key in sorted([k for k, p in self.pending.items() if ready(p)], key=lambda k: self.pending[k].ts):
            p = self.pending.pop(key)
            try:
                row, row_ops = self._file_row(p, now)
            except Exception as exc:
                self.errors.append(f"activity file row: {exc!r}")
                row, row_ops = None, []
            ops += row_ops
            if row is not None:
                rows.append(row)
        return rows, ops

    def _file_row(self, p: _Pending, now: float) -> Tuple[Optional[Dict[str, Any]], List[tuple]]:
        op = p.op
        det = dict(p.details)
        duplicate = self.kernel_files and op in ("created", "modified", "deleted", "renamed") and \
            self.attr.kernel_seen(p.path, op, p.ts)
        who = self.attr.attribute(p.path, op, p.ts, p.target) if not duplicate else {}
        det["evidence"] = who.get("evidence", "")
        for k in ("cmdline", "create_time", "home_owner"):
            if who.get(k):
                det[k] = who[k]
        root = self.flt.root_of(p.target or p.path) or ""
        ops: List[tuple] = []
        size: Optional[int] = None
        target = p.target
        kind = "file_" + op
        chain = self.shred_chain.pop(p.path, None) if op in ("renamed", "deleted") else None
        weak = who.get("attribution") in ("unknown", "inferred", None)
        # the attribution of the first step of a secure-deletion sequence, carried unchanged along the chain
        chain_who = chain[2] if chain and chain[2] and chain[2].get("attribution") not in ("unknown", "inferred") \
            else (who if not weak else (chain[2] if chain else who))
        if chain and weak and chain_who is not who:
            who = dict(chain_who, evidence=f"same secure-deletion sequence as {chain[0]} "
                                           f"({chain_who.get('evidence', '')})")
        if op == "renamed" and not p.is_dir and _ZEROS.match(os.path.basename(p.target)):
            # shred -u / srm: overwrite, rename to 000..0, 00..0 ..., unlink - one record, under the original name
            orig = chain[0] if chain else p.path
            self.shred_chain[p.target] = (orig, p.ts, chain_who)
            if not chain:
                prev = self.store.file_index_get(p.path)
                self.shred_sizes[p.target] = (prev or {}).get("size")
            else:
                self.shred_sizes[p.target] = self.shred_sizes.pop(p.path, None)
            return None, [("move", p.path, p.target, root)]
        if chain and op == "deleted":
            det.update(secure_delete=True, deleted_as=p.path,
                       note="overwritten, renamed to zeros and unlinked (shred -u / srm / secure delete)")
            size = self.shred_sizes.pop(p.path, None)
            p.path = chain[0]
            ops.append(("del", det["deleted_as"]))
            row = self._row("file_deleted", "file", p.ts, user=who.get("user") or "",
                            login_user=who.get("login_user") or "", pid=who.get("pid"), process=who.get("process") or "",
                            exe=who.get("exe") or "", path=p.path, is_dir=0, size=size, source=p.source,
                            attribution=who.get("attribution", "unknown"),
                            details={k: v for k, v in {**det, "evidence": who.get("evidence", "")}.items()
                                     if v not in (None, "")})
            return (None if duplicate else row), ops
        if op == "renamed":
            if self._in_trash(p.target) and not self._in_trash(p.path):
                kind, det["trashed"], det["trash_path"], target = "file_deleted", True, p.target, ""
            elif self._in_trash(p.path) and not self._in_trash(p.target):
                det["restored_from_trash"] = True
            elif os.path.dirname(p.path) != os.path.dirname(p.target):
                det["moved"] = True
            prev = self.store.file_index_get(p.path)
            size = (prev or {}).get("size")
            ops.append(("move", p.path, p.target, root))
            ops += self._stat_op(p.target, root)
        elif op == "deleted":
            prev = self.store.file_index_get(p.path)
            if prev:
                size = prev.get("size")
                if prev.get("is_dir") and (det.get("moved_out") or det.get("watched_root")):
                    det["contained_entries"] = len(self.store.file_index_children(p.path, limit=1_000_000))
            if self._in_trash(p.path):
                det["emptied_from_trash"] = True
            ops.append(("del", p.path))
        elif op in ("created", "modified"):
            st_ops = self._stat_op(p.path, root)
            if not st_ops:
                if op == "created":
                    return None, []                        # already gone again
            else:
                size = st_ops[0][4] if not p.is_dir else None
                ops += st_ops
            if op == "created" and not p.is_dir and os.path.islink(p.path):
                try:
                    det["symlink_to"] = os.readlink(p.path)
                except OSError:
                    pass
            if op == "created" and not p.is_dir and not duplicate:
                in_dl = self._in_download_dir(p.path) or bool(det.get("download_completed"))
                by_dl = is_downloader(who.get("process") or "", who.get("cmdline", ""))
                origin = origin_of(p.path)                # browsers / wget --xattr tag downloads anywhere
                if in_dl or by_dl or origin.get("url"):
                    kind = "file_downloaded"
                    det.update(origin)
                    url = origin.get("url") or _url_in(who.get("cmdline", ""))
                    if url:
                        det["url"] = url
                    if self.hash_max and size is not None and size <= self.hash_max:
                        self.self_reads[p.path] = now
                        det["sha256"] = _sha256(p.path, self.hash_max)
        elif op == "opened":
            self.opened[p.path] = now
            if not self._open_budget(p.path, now):
                return None, []
        if duplicate:
            return None, ops                              # the kernel record (with the real user) already has it
        row = self._row(kind, "file", p.ts, user=who.get("user") or "", login_user=who.get("login_user") or "",
                        pid=who.get("pid"), process=who.get("process") or "", exe=who.get("exe") or "", path=p.path,
                        target=target, is_dir=int(p.is_dir), size=size, source=p.source,
                        attribution=who.get("attribution", "unknown"),
                        details={k: v for k, v in det.items() if v not in (None, "")})
        return row, ops

    def _stat_op(self, path: str, root: str) -> List[tuple]:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return []
        is_dir = _st.S_ISDIR(st.st_mode)
        return [("put", path, root, int(is_dir), 0 if is_dir else st.st_size, st.st_mtime_ns, st.st_ino)]

    def _open_budget(self, path: str, now: float) -> bool:
        minute, n = self.open_minute
        if now - minute >= 60:
            self.open_minute = (now, 1)
            return True
        if n < self.max_opens:
            self.open_minute = (minute, n + 1)
            return True
        self.open_overflow[os.path.dirname(path)] += 1
        return False

    def _open_overflow_rows(self, now: float) -> List[Dict[str, Any]]:
        if not self.open_overflow or now - self.open_minute[0] < 60:
            return []
        total = sum(self.open_overflow.values())
        row = self._row("bulk_access", "file", now, source="inotify", attribution="unknown",
                        details={"files_opened": total, "top_folders": self.open_overflow.most_common(15),
                                 "note": f"more than {self.max_opens} files opened in one minute - indexing, backup, "
                                         f"search, or bulk reading / exfiltration staging"})
        self.open_overflow.clear()
        return [row]

    def _maybe_scan_handles(self, now: float) -> None:
        """Files still open by a process are the best attribution after the kernel's own record.  One scan covers
        every event that happened before it; at most one scan per ``handle_scan_min_interval``."""
        if not self.handle_scan or now - self._last_handles < self.handle_scan_gap:
            return
        if not any(p.op in ("opened", "modified", "created") and p.ts > self._last_handles
                   for p in self.pending.values()):
            return
        self._last_handles = now
        try:
            pairs = scan_handles(lambda u: is_in_scope(u, self.scope), lambda path: self.flt.root_of(path) is not None)
        except Exception as exc:
            self.errors.append(f"open files: {exc!r}")
            return
        for path, rec in pairs:
            self.attr.add_handle(path, rec, now)

    def _handles(self, pairs: List[Tuple[str, ProcRecord]], now: float) -> None:
        """Periodic open-files sample from the watcher thread: attribution + 'opened' records where inotify is not
        available (Windows / macOS)."""
        rows = []
        for path, rec in pairs:
            self.attr.add_handle(path, rec, now)
            key = (rec.pid, path)
            if key in self.open_pairs or not self.record_opens:
                continue
            self.open_pairs[key] = now
            if self.backend == "inotify" and self.opened.get(path, 0) > now - self.open_dedupe:
                continue
            self.opened[path] = now
            rows.append(self._row("file_opened", "file", now, user=rec.user, pid=rec.pid, process=rec.name,
                                  exe=rec.exe, path=path, source="handles", attribution="handle",
                                  details={"cmdline": rec.cmd[:1000], "evidence": "the process had the file open"}))
        self._write(rows, now)

    def _xbel(self, path: str, now: float) -> None:
        """GTK 'recently used' list: which application opened which document (attributed to the home owner)."""
        fd = safe_open(path, 16 * 1024 * 1024)
        if fd is None:
            return
        try:
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
            if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
                return                                     # never let a DTD reach the parser
            root = ET.fromstring(data)
        except (ET.ParseError, OSError, ValueError):
            return
        owner = Attributor.home_owner(path)
        first = path not in self.xbel_seen
        seen = self.xbel_seen.setdefault(path, set())
        rows = []
        for bm in root.iter("bookmark"):
            href = bm.get("href") or ""
            stamp = bm.get("visited") or bm.get("modified") or ""
            key = f"{href}|{stamp}"
            if key in seen:
                continue
            seen.add(key)
            if first:
                continue                                   # baseline: entries that were already there
            apps = [a.get("name") for a in bm.iter() if a.tag.endswith("application") and a.get("name")]
            local = unquote(urlparse(href).path) if href.startswith("file://") else href
            rows.append(self._row("file_opened", "file", now, user=owner, path=local, process=apps[0] if apps else "",
                                  source="recently-used", attribution="inferred" if owner else "unknown",
                                  details={"applications": apps, "evidence": "GTK recently-used list of the home owner"}))
        self._write(rows, now)

    def _xbel_baseline(self) -> None:
        for r in self.roots:
            for cand in [os.path.join(r, ".local", "share", XBEL)] + glob.glob(os.path.join(r, "*", ".local", "share", XBEL)):
                if os.path.isfile(cand):
                    self._xbel(cand, time.time())

    # ------------------------------------------------------------------ batches (start-up diff, polling, rescans)
    def _record_batch(self, source: str, diff: Dict[str, Any], commit, done: threading.Event,
                      now: float) -> Tuple[List[Alert], List[Dict[str, Any]]]:
        alerts: List[Alert] = []
        rows: List[Dict[str, Any]] = []
        offline = source == "offline"
        gap = self.gap
        for op, key in (("created", "created"), ("modified", "modified"), ("deleted", "deleted"),
                        ("renamed", "renamed")):
            for r in diff.get(key) or []:
                path, target = r["path"], r.get("target", "")
                if op == "created" and self.flt.route_only(os.path.dirname(path)):
                    continue
                if offline:
                    who = {"attribution": "unknown", "evidence": "changed while El Doctor was not running",
                           "home_owner": Attributor.home_owner(path)}
                else:
                    who = self.attr.attribute(path, op, now, target)
                ts = now
                if op in ("created", "modified") and r.get("mtime_ns"):
                    ts = min(now, r["mtime_ns"] / 1e9)
                det = {"evidence": who.get("evidence", ""), "detected_by": f"folder scan ({source})"}
                if offline:
                    det["between"] = [gap[0], gap[1]]
                if who.get("home_owner"):
                    det["home_owner"] = who["home_owner"]
                if who.get("cmdline"):
                    det["cmdline"] = who["cmdline"]
                if op == "modified":
                    det["old_size"] = r.get("old_size")
                kind = "file_" + op
                if op == "renamed" and self._in_trash(target) and not self._in_trash(path):
                    kind, det["trashed"], det["trash_path"], target = "file_deleted", True, target, ""
                elif op == "created" and not r.get("is_dir") and self._in_download_dir(path):
                    kind = "file_downloaded"
                    det.update(origin_of(path))
                rows.append(self._row(kind, "file", ts, user=who.get("user") or "", login_user=who.get("login_user") or "",
                                      pid=who.get("pid"), process=who.get("process") or "", exe=who.get("exe") or "",
                                      path=path, target=target, is_dir=int(bool(r.get("is_dir"))),
                                      size=r.get("old_size") if op == "deleted" else r.get("size"),
                                      source="offline" if offline else "scan",
                                      attribution=who.get("attribution", "unknown"),
                                      details={k: v for k, v in det.items() if v not in (None, "")}))
        counts = diff.get("counts") or {}
        summary = {"source": source, "counts": counts, "truncated": diff.get("truncated"), "ts": now,
                   "scanned": self.scanner.scanned if self.scanner else 0}
        if offline and any(counts.values()):
            rows.append(self._row("offline_changes", "system", now, source="offline", attribution="unknown",
                                  details={**summary, "between": [gap[0], gap[1]],
                                           "note": "changes made while El Doctor was not running"}))
        if diff.get("truncated"):
            rows.append(self._row("scan_truncated", "system", now, source="agent",
                                  details={"limit": self.max_files, "note": "folder scan hit activity.files.max_files;"
                                           " deletions are not detected beyond the limit"}))
        try:
            for i in range(0, max(1, len(rows)), 5000):
                part = rows[i:i + 5000]
                last = i + 5000 >= len(rows)
                self._write(part, now, in_tx=commit if last else None)
        finally:
            done.set()
        self.last_scan = summary
        deletions = [r for r in rows if r["kind"] == "file_deleted"]
        if offline:
            if any(counts.values()):
                self.store.audit("agent", "offline_changes_found", {**summary, "between": [gap[0], gap[1]]})
            inc = self.wipe.offline(deletions, gap) if self.wipe_enabled else None
            if inc is not None:
                a = self._incident_alert(inc, offline=True)
                if a:
                    alerts.append(a)
                self._queue_wipe_report(inc, a.to_dict() if a else {"rule_id": "ED-ACT-002", "severity": "critical"})
            return alerts, []
        return alerts, deletions

    # ------------------------------------------------------------------ downloads, wipes, evidence store
    def _downloads(self, rows: List[Dict[str, Any]]) -> List[Alert]:
        out: List[Alert] = []
        if self.iocs is None:
            return out
        for r in rows:
            if r["kind"] != "file_downloaded":
                continue
            sha = (r.get("details") or {}).get("sha256", "")
            hit = (self.iocs.match_hash(sha) if sha else None) or self.iocs.match_filename(os.path.basename(r["path"]))
            if hit is None:
                continue
            proc = live_process(r["pid"]) if r.get("pid") else None
            a = self._alert("ED-ACT-004", process=proc, dedup=f"ED-ACT-004|{r['path']}|{sha}",
                            evidence={"path": r["path"], "sha256": sha, "url": (r.get("details") or {}).get("url"),
                                      "user": r.get("user"), "indicator": getattr(hit, "value", ""),
                                      "feed": getattr(hit, "source", ""), "description": getattr(hit, "description", ""),
                                      "activity_id": r.get("id")})
            if a:
                out.append(a)
        return out

    def _wipe_tick(self, deletions: List[Dict[str, Any]], now: float) -> List[Alert]:
        alerts: List[Alert] = []
        opened = self.wipe.feed(deletions, now)
        if opened is not None:
            a = self._incident_alert(opened)
            if a:
                alerts.append(a)
                self.incident_alert = a
                opened.alert_id = a.id
                rep = self.reporter.simple_report(
                    f"Data wipe IN PROGRESS: {opened.total:,} files/folders deleted so far",
                    [f"El Doctor is seeing a mass deletion of files on this host (started {time.ctime(opened.started)}).",
                     f"Deleted so far: {opened.total:,} ({opened.files:,} files, {opened.folders:,} folders, "
                     f"{human_bytes(opened.bytes)}).",
                     "By: " + ", ".join(f"{k} ({v})" for k, v in opened.actors.most_common(5)),
                     *[f"Process: {p['process']} pid {p['pid']} {p.get('exe') or ''} - {p.get('cmdline') or ''}"
                       for p in opened.summary()["processes"][:3]],
                     "", "A complete report with every affected file and folder follows when the deletions stop."],
                    a.to_dict())
                self.reporter.queue("wipe_started", rep["subject"], rep["body"], ref=opened.id)
        if self.wipe.current is not None:
            cur = self.wipe.current
            self.store.meta_set("activity_open_incident", {"id": cur.id, "started": cur.started,
                                                           "first_id": cur.first_id, "alert_id": cur.alert_id,
                                                           "total": cur.total})
        done = self.wipe.poll(now)
        if done is not None:
            self._close_incident(done, now)
        return alerts

    def _close_incident(self, inc: WipeIncident, now: float, note: str = "") -> None:
        a = self.incident_alert
        self.incident_alert = None
        if a is not None:
            a.evidence.update(self._incident_evidence(inc))
            a.evidence["final"] = True
            try:
                self.store.add_alert(a)                     # final numbers on the alert (re-recorded in the ledger)
            except Exception:
                pass
        self._queue_wipe_report(inc, a.to_dict() if a else {"rule_id": "ED-ACT-001", "severity": "critical"}, note)
        self.store.meta_set("activity_open_incident", None)

    def _incident_evidence(self, inc: WipeIncident) -> Dict[str, Any]:
        s = inc.summary(top=10)
        return {"incident": inc.id, "deleted_total": s["total"], "files": s["files"], "folders": s["folders"],
                "bytes": s["bytes"], "trashed": s["trashed"], "actors": s["actors"][:10],
                "processes": [{k: p.get(k) for k in ("pid", "process", "exe", "user", "login_user", "count", "cmdline")}
                              for p in s["processes"][:5]],
                "attribution": s["attribution"], "top_folders": s["top_folders"], "started": s["started"],
                "last": s["last"], "sample": [d.get("path") for d in inc.sample[:25]], "source": inc.source,
                "between": s["gap"]}

    def _incident_alert(self, inc: WipeIncident, offline: bool = False) -> Optional[Alert]:
        rule = "ED-ACT-002" if offline else "ED-ACT-001"
        proc = None
        p0 = inc.primary_process()
        if p0 and not offline:
            proc = live_process(int(p0["pid"]), float(p0.get("create_time") or 0))
        sev = "critical" if inc.total - inc.trashed >= self.wipe.threshold else "high"
        who = inc.actors.most_common(1)[0][0] if inc.actors else "unknown"
        by = "" if offline else (" (actor not identified)" if who == "unknown" else f" by {who}")
        title = ACTIVITY_RULES[rule][0] + f": {inc.total:,} items{by}"
        return self._alert(rule, process=proc, evidence=self._incident_evidence(inc), title=title, severity=sev,
                           dedup=f"{rule}|{inc.id}")

    def _queue_wipe_report(self, inc: WipeIncident, alert: Dict[str, Any], note: str = "") -> None:
        s = inc.summary()
        sessions = self.sessions.current() or list((self.state or {}).get("sessions") or [])
        if inc.source == "offline":
            sessions = list((self.store.meta_get("activity_state") or {}).get("sessions") or []) or sessions
        att = self.reporter.deletion_attachment(s)
        rep = self.reporter.wipe_report(s, alert, sessions, inc.sample, att)
        body = rep["body"] + (f"\n\nNote: {note}" if note else "")
        self.reporter.queue("wipe_report", rep["subject"], body, [att], ref=inc.id)
        self._write([self._row("wipe_incident", "incident", s["started"], user=(s["actors"][0][0] if s["actors"] else ""),
                               source=inc.source, attribution=max(s["attribution"], key=s["attribution"].get)
                               if s["attribution"] else "unknown",
                               details={**{k: v for k, v in self._incident_evidence(inc).items() if k != "sample"},
                                        "alert_id": alert.get("id"), "reported_to_admins": True, "note": note})],
                    time.time())
        self.store.audit("agent", "data_wipe_reported", {"incident": inc.id, "alert_id": alert.get("id"),
                                                         "deleted": s["total"], "actors": s["actors"][:5],
                                                         "source": inc.source})

    def _evidence_check(self, now: float) -> List[Alert]:
        out: List[Alert] = []
        base = home_dir()
        for name in EVIDENCE_NAMES:
            exists = (base / name).exists()
            was = self.evidence_present.get(name)
            self.evidence_present[name] = exists
            if was and not exists:
                path = str(base / name)
                who = self.attr.attribute(path, "deleted", now)
                row = self._row("evidence_deleted", "incident", now, user=who.get("user") or "", pid=who.get("pid"),
                                process=who.get("process") or "", exe=who.get("exe") or "", path=path,
                                source="agent", attribution=who.get("attribution", "unknown"),
                                details={"evidence": who.get("evidence", ""), "cmdline": who.get("cmdline", "")})
                self._write([row], now)
                proc = live_process(int(who["pid"]), float(who.get("create_time") or 0)) if who.get("pid") else None
                a = self._alert("ED-ACT-003", process=proc, dedup=f"ED-ACT-003|{name}|{int(now)}",
                                evidence={"path": path, "user": who.get("user"), "attribution": who.get("attribution"),
                                          "process": who.get("process"), "cmdline": who.get("cmdline")})
                if a:
                    out.append(a)
                    rep = self.reporter.simple_report(
                        f"El Doctor evidence deleted: {name}",
                        [f"{path} was deleted or moved on this host at {time.ctime(now)}.",
                         f"By: {who.get('user') or 'unknown'} ({who.get('attribution')}: {who.get('evidence')})",
                         f"Process: {who.get('process') or '?'} pid {who.get('pid') or '?'} {who.get('cmdline') or ''}",
                         "The agent keeps recording into its open database while it runs; check the SIEM copy of "
                         "the audit trail."], a.to_dict())
                    self.reporter.queue("evidence_deleted", rep["subject"], rep["body"], ref=name)
        return out

    def _housekeeping(self, now: float) -> None:
        for k in [k for k, v in self.shred_chain.items() if now - v[1] > 300]:
            self.shred_chain.pop(k, None)
            self.shred_sizes.pop(k, None)
        for d, keep in ((self.opened, self.open_dedupe), (self.self_reads, 60), (self.saving, 30),
                        (self.open_pairs, 3600)):
            if len(d) > 5000:
                for k in [k for k, t in d.items() if now - t > keep]:
                    del d[k]
        if self.retention and now - self._last_prune > 3600:
            self._last_prune = now
            try:
                n = self.store.prune_activity(now - self.retention * 86400)
                if n:
                    self.counts["pruned"] += n
            except Exception as exc:
                self.errors.append(f"activity retention: {exc!r}")

    # ------------------------------------------------------------------ watcher thread
    def _fs_loop(self) -> None:
        try:
            self.scanner = Scanner(self.store, self.flt, self.max_files)
            if self.backend_cfg in ("auto", "inotify") and IS_LINUX:
                try:
                    self.watcher = InotifyWatcher(self.flt, self.record_opens, self.max_watches)
                except InotifyUnavailable as exc:
                    self.errors.append(f"inotify unavailable ({exc}) - polling the folders instead")
            self.backend = "inotify" if self.watcher else "poll"
            self._scan("offline", self.watcher.add_watch if self.watcher else None)
            if self.watcher and self.watcher.limit_hit:
                self.q.put(("system", "watch_limit", {"watches": len(self.watcher.wds),
                                                      "unwatched_folders": self.watcher.unwatched,
                                                      "hint": "raise fs.inotify.max_user_watches / "
                                                              "activity.files.max_watches"}))
            last_poll = last_handles = time.time()
            while not self._stop.is_set():
                now = time.time()
                if self.watcher:
                    evs = self.watcher.read(0.5)
                    if evs:
                        real = [e for e in evs if e.op != "overflow"]
                        if real:
                            self.q.put(("events", real))
                        if len(real) != len(evs):
                            self.q.put(("system", "events_lost", {"reason": "inotify queue overflow",
                                                                  "recovery": "rescan of the watched folders"}))
                            self._scan("rescan", None)
                else:
                    self._stop.wait(0.5)
                    if now - last_poll >= self.poll_interval:
                        last_poll = now
                        self._scan("poll", None)
                if self.handles_interval and now - last_handles >= self.handles_interval:
                    last_handles = now
                    try:
                        pairs = scan_handles(lambda u: is_in_scope(u, self.scope),
                                             lambda path: self.flt.root_of(path) is not None)
                        if pairs:
                            self.q.put(("handles", pairs))
                    except Exception as exc:
                        self.errors.append(f"open files sample: {exc!r}")
        except Exception as exc:
            import traceback
            self.errors.append(f"activity watcher stopped: {exc!r}")
            try:
                self.store.audit("agent", "activity_error", {"error": repr(exc), "trace": traceback.format_exc()[-1200:]})
            except Exception:
                pass

    def _scan(self, source: str, on_dir) -> None:
        assert self.scanner is not None
        t0 = time.time()
        with self.scanner.lock:
            prev_roots = self.store.meta_get("file_index_roots") or []
            self.scanner.scan(self.roots, on_dir)
            compare = [r for r in self.roots if r in prev_roots]
            diff = self.scanner.diff(compare)
            diff["scan_seconds"] = round(time.time() - t0, 2)
            roots = list(self.roots)
            scanner, store = self.scanner, self.store

            def commit(c) -> None:
                scanner.commit(c, roots)
                store.meta_set("file_index_roots", sorted(set(roots) | set(prev_roots)))
            done = threading.Event()
            self.q.put(("batch", source, diff, commit, done))
            while not done.wait(0.5):               # the agent cycle records it (atomically with the new index)
                if self._stop.is_set():
                    return

    # ------------------------------------------------------------------ helpers
    def _in_download_dir(self, path: str) -> bool:
        root = self.flt.root_of(path)
        rel = os.path.relpath(os.path.dirname(path), root) if root else os.path.dirname(path)
        return any(part.lower() in self.download_names for part in rel.replace("\\", "/").split("/"))

    @staticmethod
    def _in_trash(path: str) -> bool:
        p = path.replace("\\", "/") + "/"
        return any(m.replace("\\", "/") in p for m in TRASH_MARKERS) or "/$recycle.bin/" in p.lower()

    # ------------------------------------------------------------------ views for the API
    def status(self) -> Dict[str, Any]:
        w = self.watcher
        return {"enabled": self.enabled, "started": self.started, "backend": self.backend, "roots": self.roots,
                "watches": len(w.wds) if w else 0, "watch_limit_hit": bool(w and w.limit_hit),
                "unwatched_folders": w.unwatched if w else 0, "kernel_file_telemetry": self.kernel_files,
                "index": self.store.file_index_stats(), "last_scan": self.last_scan, "boot_id": self.boot_id,
                "monitoring_since_gap": list(self.gap), "pending_events": len(self.pending),
                "recorded": dict(self.counts), "open_incident": self.wipe.current.summary(5)
                if self.wipe.current else None, "errors": list(self.errors)[-10:],
                "reports": {"smtp_configured": self.reporter.smtp() is not None,
                            "recipients": len(self.reporter.recipients())}}

    def current_sessions(self) -> List[Dict[str, Any]]:
        return self.sessions.current()


def _terminal(pid: int) -> str:
    try:
        return psutil.Process(pid).terminal() or ""
    except (psutil.Error, OSError, AttributeError):
        return ""


def _url_in(cmdline: str) -> str:
    m = re.search(r"(?:https?|ftp)://[^\s'\"<>]+", cmdline or "")
    return m.group(0) if m else ""


def _json(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v) if v else {}
    except ValueError:
        return {}


def _host() -> str:
    from eldoctor.models import HOSTNAME
    return HOSTNAME
