"""Process and network telemetry via psutil (Linux, Windows, macOS)."""
from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import Dict, List, Optional, Tuple

import psutil

from eldoctor.models import ProcessInfo

ATTRS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "memory_info",
         "memory_percent", "status", "num_threads"]
IS_LINUX = sys.platform.startswith("linux")


class HashCache:
    def __init__(self, max_mb: int = 100) -> None:
        self.max_bytes = max_mb * 1024 * 1024
        self._cache: Dict[Tuple[str, float, int], str] = {}

    def sha256(self, path: str) -> str:
        if not path:
            return ""
        try:
            st = os.stat(path)
        except OSError:
            return ""
        key = (path, st.st_mtime, st.st_size)
        if key in self._cache:
            return self._cache[key]
        if st.st_size > self.max_bytes:
            return ""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
        except OSError:
            return ""
        self._cache[key] = h.hexdigest()
        if len(self._cache) > 5000:
            self._cache.clear()
        return self._cache[key]


def hash_file(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _linux_exe_info(pid: int) -> Tuple[str, bool]:
    """Return (exe path, deleted?) using /proc directly (psutil hides ' (deleted)')."""
    try:
        link = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return "", False
    if link.endswith(" (deleted)"):
        return link[: -len(" (deleted)")], True
    return link, False


class ProcessCollector:
    """Snapshots processes; reports which ones are new since the previous call."""

    def __init__(self, hash_executables: bool = True, max_hash_mb: int = 100) -> None:
        self.hash_executables = hash_executables
        self.hashes = HashCache(max_hash_mb)
        self.known: Dict[str, ProcessInfo] = {}
        self.self_pid = os.getpid()
        self.first = True

    def _build(self, p: psutil.Process, info: dict, by_pid: Dict[int, dict]) -> ProcessInfo:
        exe = info.get("exe") or ""
        deleted = False
        if IS_LINUX:
            lexe, deleted = _linux_exe_info(info["pid"])
            if lexe:
                exe = lexe
        mem = info.get("memory_info")
        try:
            cpu = p.cpu_percent(None)
        except (psutil.Error, OSError):
            cpu = 0.0
        parent = by_pid.get(info.get("ppid") or 0, {})
        proc = ProcessInfo(
            pid=info["pid"],
            ppid=info.get("ppid") or 0,
            name=info.get("name") or "",
            exe=exe,
            cmdline=list(info.get("cmdline") or []),
            username=info.get("username") or "",
            create_time=float(info.get("create_time") or 0.0),
            cpu_percent=cpu,
            memory_percent=float(info.get("memory_percent") or 0.0),
            rss=int(mem.rss) if mem else 0,
            status=info.get("status") or "",
            parent_name=parent.get("name") or "",
            parent_exe=parent.get("exe") or "",
            parent_cmdline=" ".join(parent.get("cmdline") or []),
            exe_deleted=deleted,
            num_threads=int(info.get("num_threads") or 0),
        )
        return proc

    def snapshot(self) -> Tuple[List[ProcessInfo], List[ProcessInfo]]:
        raw: List[Tuple[psutil.Process, dict]] = []
        for p in psutil.process_iter(ATTRS):
            try:
                raw.append((p, dict(p.info)))
            except (psutil.Error, OSError):
                continue
        by_pid = {info["pid"]: info for _, info in raw}
        procs: List[ProcessInfo] = []
        new: List[ProcessInfo] = []
        seen = {}
        for p, info in raw:
            try:
                proc = self._build(p, info, by_pid)
            except (psutil.Error, OSError, KeyError):
                continue
            if proc.pid == self.self_pid:
                continue
            prev = self.known.get(proc.key)
            if prev is None:
                if self.hash_executables and proc.exe and not proc.exe_deleted:
                    proc.sha256 = self.hashes.sha256(proc.exe)
                elif self.hash_executables and proc.exe_deleted and IS_LINUX:
                    # the inode is still reachable through /proc even though the file is gone
                    proc.sha256 = self.hashes.sha256(f"/proc/{proc.pid}/exe")
                new.append(proc)
            else:
                proc.sha256 = prev.sha256
            seen[proc.key] = proc
            procs.append(proc)
        self.known = seen
        self.first = False
        return procs, new


def connections() -> List[dict]:
    """All inet connections visible to us (pid may be None without privileges)."""
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return out
    for c in conns:
        out.append({
            "pid": c.pid,
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "lport": c.laddr.port if c.laddr else 0,
            "rip": c.raddr.ip if c.raddr else "",
            "rport": c.raddr.port if c.raddr else 0,
            "status": c.status,
            "type": "tcp" if c.type == 1 else "udp",
        })
    return out


def get_live_process(pid: int, create_time: Optional[float] = None) -> Optional[psutil.Process]:
    """Return psutil.Process only if it still is the *same* process (PID-reuse safe)."""
    try:
        p = psutil.Process(pid)
        if create_time and abs(p.create_time() - float(create_time)) > 0.05:
            return None
        return p
    except (psutil.Error, OSError):
        return None


def process_info_from_pid(pid: int) -> Optional[ProcessInfo]:
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {a: None for a in ATTRS}
            info.update(p.as_dict(ATTRS))
        par = {}
        try:
            pp = p.parent()
            if pp:
                par = {pp.pid: pp.as_dict(["name", "exe", "cmdline"])}
        except psutil.Error:
            pass
        col = ProcessCollector(hash_executables=True)
        proc = col._build(p, info, par)
        proc.sha256 = col.hashes.sha256(proc.exe) if proc.exe else ""
        return proc
    except (psutil.Error, OSError):
        return None


def now() -> float:
    return time.time()
