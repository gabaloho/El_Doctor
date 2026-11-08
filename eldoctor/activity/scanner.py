"""Snapshot-and-compare of the watched folders against the persisted ``file_index``.

The comparison runs in SQLite (a TEMP table holds the fresh scan), so memory stays flat even for
folders with hundreds of thousands of files.  Renames are recognised by inode (+ size for files), and
the children of a renamed folder are folded into the folder's rename.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence

from eldoctor.activity.fswatch import PathFilter, walk

SCAN_SCHEMA = """
CREATE TEMP TABLE IF NOT EXISTS file_scan (
    path TEXT PRIMARY KEY, root TEXT, is_dir INTEGER, size INTEGER, mtime_ns INTEGER, ino INTEGER
);
CREATE INDEX IF NOT EXISTS temp.idx_file_scan_ino ON file_scan(ino);
"""


class Scanner:
    def __init__(self, store, flt: PathFilter, limit: int = 500_000, max_events: int = 200_000) -> None:
        self.store = store
        self.flt = flt
        self.limit = int(limit)
        self.max_events = int(max_events)
        self.truncated = False
        self.scanned = 0
        self.lock = threading.Lock()        # one scan at a time (start-up diff, periodic poll, overflow rescan)

    def _ensure(self) -> None:
        with self.store._lock:
            self.store.conn.executescript(SCAN_SCHEMA)

    def scan(self, roots: Sequence[str], on_dir: Optional[Callable[[str], None]] = None) -> int:
        """Walk the roots into temp.file_scan.  ``on_dir`` lets the inotify watcher add its watches during the
        same walk (one pass over the disk)."""
        self._ensure()
        with self.store.tx() as c:
            c.execute("DELETE FROM temp.file_scan")
        counter = [0]
        batch: List[tuple] = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            for ent in walk(root, self.flt, on_dir=on_dir, limit=self.limit, counter=counter):
                batch.append(ent)
                if len(batch) >= 2000:
                    self._flush(batch)
            if counter[0] >= self.limit:
                break
        self._flush(batch)
        self.scanned = counter[0]
        self.truncated = counter[0] >= self.limit
        return counter[0]

    def _flush(self, batch: List[tuple]) -> None:
        if not batch:
            return
        with self.store.tx() as c:
            c.executemany("INSERT OR REPLACE INTO temp.file_scan (path, root, is_dir, size, mtime_ns, ino)"
                          " VALUES (?,?,?,?,?,?)", batch)
        batch.clear()

    def diff(self, compare_roots: Sequence[str]) -> Dict[str, Any]:
        """Changes between the persisted index and the fresh scan, for roots known to both.

        Returns {created, deleted, modified, renamed: [row...], counts: {...}, truncated: bool}.  When the scan
        hit the entry limit, deletions are *not* reported (unscanned files would look deleted)."""
        roots = list(compare_roots)
        out: Dict[str, Any] = {"created": [], "deleted": [], "modified": [], "renamed": [],
                               "counts": {"created": 0, "deleted": 0, "modified": 0, "renamed": 0},
                               "truncated": self.truncated}
        if not roots:
            return out
        marks = ",".join("?" * len(roots))
        q = self.store.query
        lim = self.max_events + 1
        renamed = q(f"""SELECT d.path AS path, s.path AS target, s.is_dir AS is_dir, s.size AS size, d.size AS old_size,
                               s.root AS root
                        FROM file_index d JOIN temp.file_scan s
                             ON s.ino = d.ino AND s.is_dir = d.is_dir AND (d.is_dir = 1 OR s.size = d.size)
                        WHERE d.root IN ({marks}) AND s.root IN ({marks}) AND d.ino != 0
                          AND NOT EXISTS (SELECT 1 FROM temp.file_scan x WHERE x.path = d.path)
                          AND NOT EXISTS (SELECT 1 FROM file_index y WHERE y.path = s.path)
                        ORDER BY length(d.path) LIMIT ?""", (*roots, *roots, lim))
        # fold children of renamed folders into the folder's rename; one source may pair with one target only
        folded: List[Dict[str, Any]] = []
        used_src, used_dst, dir_moves = set(), set(), []
        for r in renamed:
            if r["path"] in used_src or r["target"] in used_dst:
                continue
            parent = next(((o, n) for o, n in dir_moves if r["path"].startswith(o.rstrip(os.sep) + os.sep)), None)
            used_src.add(r["path"])
            used_dst.add(r["target"])
            if parent and r["target"] == parent[1] + r["path"][len(parent[0]):]:
                continue
            if r["is_dir"]:
                dir_moves.append((r["path"], r["target"]))
            folded.append(r)
        moved_old = [o for o, _ in dir_moves]
        moved_new = [n for _, n in dir_moves]

        def under(p: str, bases: List[str]) -> bool:
            return any(p == b or p.startswith(b.rstrip(os.sep) + os.sep) for b in bases)

        created = [r for r in q(f"""SELECT s.* FROM temp.file_scan s WHERE s.root IN ({marks})
                                    AND NOT EXISTS (SELECT 1 FROM file_index i WHERE i.path = s.path)
                                    ORDER BY s.path LIMIT ?""", (*roots, lim))
                   if r["path"] not in used_dst and not under(r["path"], moved_new)]
        deleted: List[Dict[str, Any]] = []
        if not self.truncated:
            deleted = [r for r in q(f"""SELECT i.* FROM file_index i WHERE i.root IN ({marks})
                                        AND NOT EXISTS (SELECT 1 FROM temp.file_scan s WHERE s.path = i.path)
                                        ORDER BY i.path LIMIT ?""", (*roots, lim))
                       if r["path"] not in used_src and not under(r["path"], moved_old)]
        modified = q(f"""SELECT s.*, i.size AS old_size, i.mtime_ns AS old_mtime_ns FROM temp.file_scan s
                         JOIN file_index i ON i.path = s.path
                         WHERE s.root IN ({marks}) AND s.is_dir = 0 AND (s.size != i.size OR s.mtime_ns != i.mtime_ns)
                         ORDER BY s.path LIMIT ?""", (*roots, lim))
        for key, rows in (("created", created), ("deleted", deleted), ("modified", modified), ("renamed", folded)):
            out["counts"][key] = len(rows)
            out[key] = rows[: self.max_events]
        return out

    def commit(self, c, roots: Sequence[str]) -> None:
        """Make the fresh scan the new last-known state (called inside the transaction that records the
        changes, so a crash can never record one without the other)."""
        roots = list(roots)
        if not roots:
            return
        marks = ",".join("?" * len(roots))
        if self.truncated:              # partial scan: merge, never drop entries we did not get to
            c.execute(f"INSERT OR REPLACE INTO file_index SELECT * FROM temp.file_scan WHERE root IN ({marks})", roots)
        else:
            c.execute(f"DELETE FROM file_index WHERE root IN ({marks})", roots)
            c.execute(f"INSERT INTO file_index SELECT * FROM temp.file_scan WHERE root IN ({marks})", roots)
