"""Data-wipe detection: bursts of deletions, grouped into incidents.

A deletion burst opens an incident when ``threshold`` files/folders disappear within ``window`` seconds.
The alarm is raised at that moment (while the wipe may still be running - the response playbook can
suspend the process), deletions keep being attached to the incident, and when nothing has been deleted
for ``quiet`` seconds the incident is closed and the complete report (who, what, how much) goes to the
registered administrators.
"""
from __future__ import annotations

import csv
import io
import os
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple


@dataclass
class WipeIncident:
    """Aggregates of one deletion burst.  Memory stays bounded whatever the size of the wipe: counters plus a
    sample of rows; the complete list is read back from the activity table for the report attachment."""
    id: str
    started: float
    last: float
    source: str = "live"                   # live | offline (changes found at start-up)
    alert_id: str = ""
    closed: bool = False
    gap: Optional[Tuple[float, float]] = None
    sample_size: int = 2000
    total: int = 0
    files: int = 0
    folders: int = 0
    trashed: int = 0
    bytes: int = 0
    first_id: int = 0
    last_id: int = 0
    sample: List[Dict[str, Any]] = field(default_factory=list)
    actors: Counter = field(default_factory=Counter)
    how: Counter = field(default_factory=Counter)
    parents: Counter = field(default_factory=Counter)
    deleted_dirs: List[str] = field(default_factory=list)
    procs: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def add(self, d: Dict[str, Any]) -> None:
        det = d.get("details") if isinstance(d.get("details"), dict) else {}
        self.total += 1
        ts = float(d.get("ts") or self.last)
        self.last = max(self.last, ts)
        self.started = min(self.started, ts)
        rid = int(d.get("id") or 0)
        if rid:
            self.first_id = min(self.first_id or rid, rid)
            self.last_id = max(self.last_id, rid)
        if d.get("is_dir"):
            self.folders += 1
            if len(self.deleted_dirs) < 1000:
                self.deleted_dirs.append(d.get("path") or "")
        else:
            self.files += 1
            self.bytes += int(d.get("size") or 0)
        if det.get("trashed"):
            self.trashed += 1
        who = d.get("user") or "unknown"
        login = d.get("login_user") or ""
        self.actors[who + (f" (login user {login})" if login and login != who else "")] += 1
        self.how[d.get("attribution") or "unknown"] += 1
        parent = os.path.dirname(d.get("path") or "")
        if parent in self.parents or len(self.parents) < 50000:
            self.parents[parent] += 1
        if d.get("pid"):
            k = f"{d.get('process')}[{d.get('pid')}]"
            if k not in self.procs and len(self.procs) < 200:
                self.procs[k] = {"pid": d.get("pid"), "process": d.get("process"), "exe": d.get("exe"),
                                 "user": d.get("user"), "login_user": login, "count": 0,
                                 "cmdline": det.get("cmdline", ""), "create_time": det.get("create_time", 0)}
            if k in self.procs:
                self.procs[k]["count"] += 1
        if len(self.sample) < self.sample_size:
            self.sample.append(d)

    def summary(self, top: int = 15) -> Dict[str, Any]:
        return {"id": self.id, "source": self.source, "started": self.started, "last": self.last,
                "duration_s": round(max(0.0, self.last - self.started), 1), "total": self.total,
                "files": self.files, "folders": self.folders, "trashed": self.trashed,
                "permanent": self.total - self.trashed, "bytes": self.bytes, "actors": self.actors.most_common(),
                "processes": sorted(self.procs.values(), key=lambda p: -p["count"]),
                "attribution": dict(self.how), "top_folders": self.parents.most_common(top),
                "deleted_folders": sorted(self.deleted_dirs)[:top], "gap": list(self.gap) if self.gap else None,
                "closed": self.closed, "first_id": self.first_id, "last_id": self.last_id}

    def primary_process(self) -> Optional[Dict[str, Any]]:
        """The process responsible for most of the deletions, when it is known."""
        procs = sorted(self.procs.values(), key=lambda p: -p["count"])
        if procs and procs[0]["count"] >= max(1, self.total // 2):
            return procs[0]
        return None


def _incident(rows: List[Dict[str, Any]], source: str = "live", gap=None) -> WipeIncident:
    first = min(float(r.get("ts") or time.time()) for r in rows)
    inc = WipeIncident(uuid.uuid4().hex[:10], first, first, source=source, gap=gap)
    for r in rows:
        inc.add(r)
    return inc


class WipeDetector:
    def __init__(self, threshold: int = 50, window: float = 60.0, quiet: float = 20.0) -> None:
        self.threshold = max(1, int(threshold))
        self.window = float(window)
        self.quiet = float(quiet)
        self.recent: Deque[Dict[str, Any]] = deque()
        self.current: Optional[WipeIncident] = None

    def feed(self, deletions: List[Dict[str, Any]], now: Optional[float] = None) -> Optional[WipeIncident]:
        """Add deletion rows; returns the incident when it has *just* been opened (raise the alarm)."""
        now = now or time.time()
        opened = None
        for d in deletions:
            ts = float(d.get("ts") or now)
            if self.current is not None:
                self.current.add(d)
                continue
            self.recent.append(d)
            while self.recent and ts - float(self.recent[0].get("ts") or ts) > self.window:
                self.recent.popleft()
            if len(self.recent) >= self.threshold:
                self.current = _incident(list(self.recent))
                self.recent.clear()
                opened = self.current
        return opened

    def poll(self, now: Optional[float] = None) -> Optional[WipeIncident]:
        """The incident, once deletions have stopped for ``quiet`` seconds (send the final report)."""
        now = now or time.time()
        cur = self.current
        if cur is not None and now - cur.last >= self.quiet:
            cur.closed = True
            self.current = None
            return cur
        while self.recent and now - float(self.recent[0].get("ts") or now) > self.window:
            self.recent.popleft()
        return None

    def offline(self, deletions: List[Dict[str, Any]], gap: Tuple[float, float]) -> Optional[WipeIncident]:
        """Deletions found at start-up (made while El Doctor was not running): one incident, already closed."""
        if len(deletions) < self.threshold:
            return None
        inc = _incident(deletions, source="offline", gap=gap)
        inc.closed = True
        return inc


CSV_FIELDS = ["time", "action", "type", "path", "new_path", "size_bytes", "user", "login_user", "pid", "process",
              "exe", "attribution", "source", "trashed", "moved_out", "evidence"]


def _iso(ts: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return ""


def csv_safe(v: Any) -> Any:
    """File and process names are chosen by whoever created them: a name such as =HYPERLINK(...) would run as a
    formula when an administrator opens the report in a spreadsheet (CSV injection)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def rows_csv(rows: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for r in rows:
        det = r.get("details") or {}
        if not isinstance(det, dict):
            det = {}
        w.writerow([csv_safe(x) for x in (
            _iso(r.get("ts")), r.get("kind", ""), "folder" if r.get("is_dir") else "file", r.get("path", ""),
            r.get("target", ""), "" if r.get("size") is None else r.get("size"), r.get("user", ""),
            r.get("login_user", ""), r.get("pid") or "", r.get("process", ""), r.get("exe", ""),
            r.get("attribution", ""), r.get("source", ""), "yes" if det.get("trashed") else "",
            "yes" if det.get("moved_out") else "", det.get("evidence", ""))])
    return buf.getvalue()


def human_bytes(n: Any) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
