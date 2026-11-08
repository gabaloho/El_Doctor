"""File-system activity sources.

* ``InotifyWatcher`` - Linux, real time, no extra dependency (ctypes).  Reports creations, edits
  (close after write), deletions, renames/moves and - optionally - opens, for every folder below the
  watched roots.  inotify does not say *who* did it; ``eldoctor.activity.attribution`` answers that.
* ``Scanner`` - portable: walks the roots and compares them with the last known state kept in the
  database (``file_index``).  Used

    - at every start, to find what changed while El Doctor was not running (shutdown, reboot, another
      OS booted from USB, the agent killed...) - the index survives reboots;
    - periodically, as the live source on Windows / macOS (where Sysmon / the Security log supply the
      attributed events), or when inotify is unavailable;
    - after an inotify queue overflow, to recover the events the kernel dropped.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fnmatch
import os
import select
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# partial downloads: never recorded on their own; renamed to the final name = download finished
PARTIAL_SUFFIXES = (".part", ".crdownload", ".download", ".partial", ".opdownload", ".!qb", ".aria2", ".filepart")
# editor swap / lock / atomic-save temp files: noise on their own, used to detect "saved" (rename over target)
TEMP_PATTERNS = ("*.swp", "*.swo", "*.swx", "*~", ".#*", ".~lock.*", "~$*", "*.tmp", ".goutputstream-*", "4913",
                 "*.crswap", ".*.kate-swp", "*.sb-*", ".nfs*")


@dataclass
class RawFileEvent:
    ts: float
    op: str                      # created | modified | deleted | renamed | opened | overflow | root_gone
    path: str
    target: str = ""             # renamed: destination
    is_dir: bool = False
    source: str = "inotify"
    details: Dict[str, Any] = field(default_factory=dict)


def norm(path: str) -> str:
    p = os.path.normpath(os.path.abspath(os.path.expanduser(str(path))))
    return p


def is_partial(name: str) -> bool:
    n = name.lower()
    return n.endswith(PARTIAL_SUFFIXES) or (n.startswith("unconfirmed ") and n.endswith(".crdownload"))


def is_temp(name: str) -> bool:
    n = name.lower() if IS_WINDOWS else name
    return any(fnmatch.fnmatchcase(n, p) for p in TEMP_PATTERNS)


class PathFilter:
    """Which folders are watched and which file names are noise.

    ``exclude`` entries without a slash are folder *names* skipped anywhere (``.cache``, ``node_modules``);
    entries with a slash are glob patterns on the path relative to the root (``.local/share/flatpak``).
    ``include`` re-allows a relative path below an excluded folder (``.local/share/Trash``)."""

    def __init__(self, roots: Sequence[str], exclude: Sequence[str] = (), include: Sequence[str] = (),
                 never: Sequence[str] = ()) -> None:
        self.roots = sorted({norm(r) for r in roots}, key=len, reverse=True)
        fold = (lambda s: s.lower()) if IS_WINDOWS else (lambda s: s)
        self._fold = fold
        self.names = {fold(e) for e in exclude if "/" not in e and "\\" not in e}
        self.globs = [fold(e.replace("\\", "/").strip("/")) for e in exclude if "/" in e or "\\" in e]
        self.include = [fold(i.replace("\\", "/").strip("/")) for i in include]
        self.never = [norm(n) for n in never if n]        # El Doctor's own folders: watching them would loop

    def root_of(self, path: str) -> Optional[str]:
        for r in self.roots:
            if path == r or path.startswith(r.rstrip(os.sep) + os.sep):
                return r
        return None

    def _rel(self, path: str, root: str) -> str:
        return self._fold(os.path.relpath(path, root).replace("\\", "/"))

    def _included(self, rel: str) -> bool:
        """rel is an included folder, inside one, or on the way to one (include entries may use globs)."""
        parts = rel.split("/")
        for inc in self.include:
            ip = inc.split("/")
            n = min(len(parts), len(ip))
            if all(fnmatch.fnmatchcase(parts[k], ip[k]) for k in range(n)):
                return True
        return False

    def route_only(self, path: str, root: Optional[str] = None) -> bool:
        """A folder watched only because an included folder lies below it (e.g. ~/.local/share on the way to
        the Trash): files directly inside it are not recorded."""
        root = root or self.root_of(path)
        if root is None or path == root:
            return False
        rel = self._rel(path, root)
        parts = rel.split("/")
        for inc in self.include:
            ip = inc.split("/")
            if len(parts) >= len(ip) and all(fnmatch.fnmatchcase(parts[k], ip[k]) for k in range(len(ip))):
                return False                    # the folder is (inside) an included folder
        if not self._included(rel):
            return False
        return any(p in self.names for p in parts) or \
            any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel, g + "/*") for g in self.globs)

    def skip_dir(self, path: str, root: Optional[str] = None) -> bool:
        for n in self.never:
            if path == n or path.startswith(n.rstrip(os.sep) + os.sep):
                return True
        root = root or self.root_of(path)
        if root is None:
            return True
        if path == root:
            return False
        rel = self._rel(path, root)
        if self._included(rel):
            return False
        parts = rel.split("/")
        if any(p in self.names for p in parts):
            return True
        return any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel, g + "/*") for g in self.globs)

    def watched(self, path: str, is_dir: bool = False) -> bool:
        """The path lies inside a root and not inside an excluded folder (events from kernel telemetry -
        auditd, Sysmon - cover the whole disk and are filtered with this)."""
        root = self.root_of(path)
        if root is None:
            return False
        if is_dir and self.skip_dir(path, root):
            return False
        parent = os.path.dirname(path)
        return path == root or not self.skip_dir(parent, root)


Entry = Tuple[str, str, int, int, int, int]        # (path, root, is_dir, size, mtime_ns, ino)


def walk(root: str, flt: PathFilter, on_dir: Optional[Callable[[str], None]] = None,
         limit: int = 500_000, counter: Optional[List[int]] = None) -> Iterator[Entry]:
    """Depth-first walk without following symlinks; excluded folders are not entered.

    ``counter[0]`` counts entries across several roots; the walk stops at ``limit`` (the caller reports it)."""
    counter = counter if counter is not None else [0]
    stack = [root]
    try:
        st = os.stat(root)
    except OSError:
        return
    if on_dir:
        on_dir(root)
    yield (root, root, 1, 0, st.st_mtime_ns, st.st_ino)
    counter[0] += 1
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                if counter[0] >= limit:
                    return
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    if flt.skip_dir(e.path, root):
                        continue
                    if on_dir:
                        on_dir(e.path)
                    stack.append(e.path)
                    yield (e.path, root, 1, 0, st.st_mtime_ns, st.st_ino)
                else:
                    if is_temp(e.name) or is_partial(e.name):
                        continue
                    yield (e.path, root, 0, st.st_size, st.st_mtime_ns, st.st_ino)
                counter[0] += 1


# --------------------------------------------------------------------------- inotify (Linux)
IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE = 0x1, 0x2, 0x4, 0x8
IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO = 0x10, 0x20, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF = 0x100, 0x200, 0x400, 0x800
IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED = 0x2000, 0x4000, 0x8000
IN_ONLYDIR, IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_ISDIR = 0x01000000, 0x02000000, 0x04000000, 0x40000000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000
_EVENT = struct.Struct("iIII")


class InotifyUnavailable(RuntimeError):
    pass


class InotifyWatcher:
    BASE_MASK = (IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE |
                 IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK)

    def __init__(self, flt: PathFilter, record_opens: bool = True, max_watches: int = 100_000) -> None:
        if not IS_LINUX:
            raise InotifyUnavailable("inotify is Linux only")
        name = ctypes.util.find_library("c") or "libc.so.6"
        try:
            self.libc = ctypes.CDLL(name, use_errno=True)
            self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self.libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        except (OSError, AttributeError) as exc:
            raise InotifyUnavailable(f"libc without inotify: {exc}") from exc
        fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            raise InotifyUnavailable(f"inotify_init1: {os.strerror(ctypes.get_errno())}")
        self.fd = fd
        self.flt = flt
        self.mask = self.BASE_MASK | (IN_OPEN if record_opens else 0)
        self.max_watches = max_watches
        self.wds: Dict[int, str] = {}
        self.by_path: Dict[str, int] = {}
        self.limit_hit = False
        self.unwatched = 0
        self.errors: List[str] = []
        self._moves: Dict[int, Tuple[float, str, bool, bool]] = {}
        self._buf = b""

    # ----------------------------------------------------------------- watches
    def add_watch(self, path: str) -> bool:
        if path in self.by_path:
            return True
        if len(self.wds) >= self.max_watches:
            self.limit_hit = True
            self.unwatched += 1
            return False
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), self.mask)
        if wd < 0:
            err = ctypes.get_errno()
            if err == errno.ENOSPC:
                self.limit_hit = True
                self.unwatched += 1
            elif err not in (errno.ENOENT, errno.ENOTDIR, errno.EACCES):
                self.errors.append(f"{path}: {os.strerror(err)}")
            return False
        old = self.wds.get(wd)
        if old is not None and old != path:      # the kernel re-used the wd of a renamed folder
            self.by_path.pop(old, None)
        self.wds[wd] = path
        self.by_path[path] = wd
        return True

    def _forget(self, wd: int) -> None:
        p = self.wds.pop(wd, None)
        if p is not None and self.by_path.get(p) == wd:
            del self.by_path[p]

    def _drop_subtree(self, path: str) -> None:
        pre = path.rstrip(os.sep) + os.sep
        for p, wd in list(self.by_path.items()):
            if p == path or p.startswith(pre):
                self.libc.inotify_rm_watch(self.fd, wd)
                self._forget(wd)

    def _rename_subtree(self, old: str, new: str) -> None:
        pre = old.rstrip(os.sep) + os.sep
        for p, wd in list(self.by_path.items()):
            if p == old or p.startswith(pre):
                np_ = new + p[len(old):]
                del self.by_path[p]
                self.by_path[np_] = wd
                self.wds[wd] = np_

    def watch_new_tree(self, path: str, ts: float) -> List[RawFileEvent]:
        """A folder appeared (created / moved in): watch it and report what is already inside - entries
        created before the watch existed would otherwise be missed (``mkdir -p a/b && cp x a/b``)."""
        out: List[RawFileEvent] = []
        root = self.flt.root_of(path)
        if root is None or self.flt.skip_dir(path, root):
            return out
        for p, _, is_dir, _, _, _ in walk(path, self.flt, on_dir=self.add_watch, limit=200_000):
            if p != path:
                out.append(RawFileEvent(ts, "created", p, is_dir=bool(is_dir), details={"found_in_new_folder": path}))
        return out

    # ----------------------------------------------------------------- events
    def read(self, timeout: float = 0.5) -> List[RawFileEvent]:
        out: List[RawFileEvent] = []
        try:
            r, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            return out
        now = time.time()
        if r:
            while True:
                try:
                    chunk = os.read(self.fd, 256 * 1024)
                except BlockingIOError:
                    break
                except OSError as exc:
                    self.errors.append(f"read: {exc}")
                    break
                if not chunk:
                    break
                self._buf += chunk
            out.extend(self._parse(now))
        # a MOVED_FROM whose MOVED_TO never came: moved out of the watched folders
        for cookie, (ts, path, is_dir, temp) in list(self._moves.items()):
            if now - ts >= 0.5:
                del self._moves[cookie]
                if is_dir:
                    self._drop_subtree(path)
                if not temp:
                    out.append(RawFileEvent(ts, "deleted", path, is_dir=is_dir, details={"moved_out": True}))
        return out

    def _parse(self, now: float) -> List[RawFileEvent]:
        out: List[RawFileEvent] = []
        buf, pos = self._buf, 0
        while pos + _EVENT.size <= len(buf):
            wd, mask, cookie, length = _EVENT.unpack_from(buf, pos)
            end = pos + _EVENT.size + length
            if end > len(buf):
                break
            name = buf[pos + _EVENT.size:end].split(b"\0", 1)[0]
            pos = end
            out.extend(self._translate(wd, mask, cookie, os.fsdecode(name) if name else "", now))
        self._buf = buf[pos:]
        return out

    def _translate(self, wd: int, mask: int, cookie: int, name: str, now: float) -> List[RawFileEvent]:
        if mask & IN_Q_OVERFLOW:
            return [RawFileEvent(now, "overflow", "", details={"reason": "kernel inotify queue overflow"})]
        base = self.wds.get(wd)
        if mask & IN_IGNORED:
            self._forget(wd)
            return []
        if base is None:
            return []
        is_dir = bool(mask & IN_ISDIR)
        path = os.path.join(base, name) if name else base
        if mask & (IN_DELETE_SELF | IN_MOVE_SELF) and not name:
            if base in self.flt.roots:
                return [RawFileEvent(now, "root_gone", base, is_dir=True,
                                     details={"how": "deleted" if mask & IN_DELETE_SELF else "moved"})]
            return []                               # reported by the parent folder's watch
        if name and is_dir and self.flt.skip_dir(path):
            return []                                # excluded folder (cache, node_modules...) - not recorded
        temp = bool(name) and not is_dir and (is_temp(name) or is_partial(name))
        if mask & IN_MOVED_FROM:
            self._moves[cookie] = (now, path, is_dir, temp)
            return []
        if mask & IN_MOVED_TO:
            src = self._moves.pop(cookie, None)
            if src is None:                          # moved in from an unwatched place
                ev = [RawFileEvent(now, "created", path, is_dir=is_dir, details={"moved_in": True})]
                if is_dir:
                    self.add_watch(path)
                    ev += self.watch_new_tree(path, now)
                return [] if temp else ev
            _, old, _, _ = src
            if is_dir:
                self._rename_subtree(old, path)
            return [RawFileEvent(now, "renamed", old, target=path, is_dir=is_dir)]
        if temp:
            return []
        if mask & IN_CREATE:
            ev = [RawFileEvent(now, "created", path, is_dir=is_dir)]
            if is_dir:
                self.add_watch(path)
                ev += self.watch_new_tree(path, now)
            return ev
        if mask & IN_DELETE:
            if is_dir:
                self._drop_subtree(path)
            return [RawFileEvent(now, "deleted", path, is_dir=is_dir)]
        if mask & IN_CLOSE_WRITE:
            return [RawFileEvent(now, "modified", path)]
        if mask & IN_OPEN and not is_dir:
            return [RawFileEvent(now, "opened", path)]
        return []

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass
