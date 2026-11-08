"""Keeping a long-running installation healthy: bounded files, evidence retention, database upkeep, log file.

* ``rotate_if_needed`` - size-based rotation of the append-only files (metrics.csv, alerts.jsonl,
  audit.jsonl, activity.jsonl): ``name`` -> ``name.1`` ... ``name.N``; the live file is re-created at once
  (the evidence-tamper check must never see it missing), rotated audit files stay verifiable on their own
  (``eldoctor audit verify-export`` accepts a chain that starts mid-way).
* ``prune_evidence`` - forensic evidence files older than ``storage.evidence_retention_days``.
* ``maintain_database`` - WAL checkpoint + ``PRAGMA optimize`` (the sealed records themselves are never
  deleted here; activity retention is ``activity.retention_days``).
* ``setup_logging`` - ``<data>/logs/eldoctor.log``, rotated, for support and post-mortems.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

SETTINGS: Dict[str, Any] = {"max_bytes": 20 * 1024 * 1024, "keep": 5, "evidence_days": 90.0}
_lock = threading.Lock()
_rotated: Dict[str, float] = {}
log = logging.getLogger("eldoctor")


def configure(cfg: Dict[str, Any]) -> None:
    sc = (cfg or {}).get("storage") or {}
    SETTINGS["max_bytes"] = int(float(sc.get("rotate_mb", 20)) * 1024 * 1024)
    SETTINGS["keep"] = max(1, int(sc.get("rotate_keep", 5)))
    SETTINGS["evidence_days"] = float(sc.get("evidence_retention_days", 90) or 0)


def rotate_if_needed(path: Path, header: str = "") -> bool:
    """Rotate ``path`` when it reached ``storage.rotate_mb``.  Safe to call before every append."""
    max_b, keep = SETTINGS["max_bytes"], SETTINGS["keep"]
    if max_b <= 0:
        return False
    try:
        if path.stat().st_size < max_b:
            return False
    except OSError:
        return False
    with _lock:
        try:
            if path.stat().st_size < max_b:             # another thread rotated it meanwhile
                return False
            oldest = path.with_name(f"{path.name}.{keep}")
            if oldest.exists():
                oldest.unlink()
            for i in range(keep - 1, 0, -1):
                src = path.with_name(f"{path.name}.{i}")
                if src.exists():
                    os.replace(src, path.with_name(f"{path.name}.{i + 1}"))
            os.replace(path, path.with_name(f"{path.name}.1"))
            _rotated[str(path)] = time.time()
            fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                if header:
                    os.write(fd, header.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as exc:                            # e.g. Windows: another process holds the file open
            log.warning("rotation of %s postponed: %s", path, exc)
            return False
    log.info("rotated %s (kept %d old copies)", path, keep)
    return True


def recently_rotated(path: Path, within: float = 30.0) -> bool:
    t = _rotated.get(str(path))
    return bool(t and time.time() - t < within)


def prune_evidence(folder: Path, days: Optional[float] = None) -> int:
    days = SETTINGS["evidence_days"] if days is None else days
    if not days or not folder.is_dir():
        return 0
    cutoff = time.time() - days * 86400
    n = 0
    for p in folder.iterdir():
        try:
            if p.is_file() and not p.is_symlink() and p.stat().st_mtime < cutoff:
                p.unlink()
                n += 1
        except OSError:
            continue
    if n:
        log.info("evidence retention: removed %d file(s) older than %g days from %s", n, days, folder)
    return n


def maintain_database(store) -> None:
    try:
        with store._lock:
            store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            store.conn.execute("PRAGMA optimize")
    except Exception as exc:                              # a busy database is retried next time
        log.warning("database maintenance skipped: %s", exc)


_log_handler: Optional[logging.Handler] = None


def setup_logging(level: str = "INFO") -> Optional[Path]:
    """Rotating log file in the data folder (idempotent).  Returns its path, or None when it cannot be written."""
    global _log_handler
    from eldoctor.config import subdir
    try:
        path = subdir("logs") / "eldoctor.log"
    except OSError:
        return None
    if _log_handler is not None:
        if os.path.abspath(getattr(_log_handler, "baseFilename", "")) == os.path.abspath(str(path)):
            return path
        log.removeHandler(_log_handler)                  # the data folder changed: follow it
        _log_handler.close()
        _log_handler = None
    try:
        h = logging.handlers.RotatingFileHandler(str(path), maxBytes=max(1024 * 1024, SETTINGS["max_bytes"] // 4),
                                                 backupCount=SETTINGS["keep"], encoding="utf-8")
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError:
        return None
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
    log.addHandler(h)
    log.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    log.propagate = False
    _log_handler = h
    return path


class LoggedErrors:
    """Drop-in for the bounded error lists (deque) the components append to: also writes them to the log file."""

    def __init__(self, maxlen: int = 50) -> None:
        from collections import deque
        self._d = deque(maxlen=maxlen)

    def append(self, msg: str) -> None:
        self._d.append(msg)
        log.warning("%s", msg)

    def __iter__(self):
        return iter(self._d)

    def __len__(self) -> int:
        return len(self._d)

    def __getitem__(self, i):
        return list(self._d)[i]

    def __bool__(self) -> bool:
        return bool(self._d)

    def __repr__(self) -> str:
        return f"LoggedErrors({list(self._d)!r})"
