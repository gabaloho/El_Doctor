"""Lock the agent's data folder to the service account.

The database, the integrity keys, evidence, the quarantine vault and the service API key must be
readable and writable by the agent's service account only (root on Linux, LocalSystem on Windows).
Nobody else needs access any more: analysts and admins use the local API (``eldoctor.api``).

* POSIX: the folder must not be a symlink, must belong to the service account (root may take over a
  folder created by someone else; an unprivileged agent refuses to run in a folder it does not own),
  folders become 0700 and files 0600, recursively, and the process umask becomes 0077.
* Windows: ``icacls`` removes inherited permissions and grants full control to LocalSystem only
  (``api.windows_admins_access: true`` additionally keeps BUILTIN\\Administrators).

Runs at every ``eldoctor service`` start, so permissions loosened later are repaired (and reported).
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from eldoctor.config import IS_WINDOWS, system_tool


class LockdownError(RuntimeError):
    pass


def lock_data_dir(path: Path, cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    path = Path(path)
    if IS_WINDOWS:                                          # pragma: no cover - exercised on Windows only
        return _lock_windows(path, bool(((cfg or {}).get("api") or {}).get("windows_admins_access", False)))
    return _lock_posix(path)


def _lock_posix(path: Path) -> Dict[str, Any]:
    os.umask(0o077)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise LockdownError(f"data folder {path} is a symlink - refusing (point ELDOCTOR_HOME at the real folder)")
    me = os.geteuid()
    fixed: List[str] = []
    if st.st_uid != me:
        if me != 0:
            raise LockdownError(f"data folder {path} belongs to uid {st.st_uid}; the service runs as uid {me}. "
                                f"Fix ownership (chown -R) or run the service as that account")
        os.chown(path, 0, 0)
        fixed.append(f"{path}: owner -> root")
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            p = Path(root) / name
            try:
                s = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISLNK(s.st_mode):
                continue                                     # never follow links out of the folder
            if stat.S_ISSOCK(s.st_mode):
                continue                                     # the API socket's mode is managed by the server
            want = 0o700 if stat.S_ISDIR(s.st_mode) else 0o600
            if me == 0 and s.st_uid != 0:
                os.chown(p, 0, 0, follow_symlinks=False)
                fixed.append(f"{p}: owner -> root")
            if stat.S_IMODE(s.st_mode) & ~want:
                os.chmod(p, stat.S_IMODE(s.st_mode) & want)
                fixed.append(f"{p}: mode {oct(stat.S_IMODE(s.st_mode))} -> {oct(stat.S_IMODE(s.st_mode) & want)}")
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o700:
        os.chmod(path, 0o700)
        fixed.append(f"{path}: mode -> 0o700")
    return {"path": str(path), "owner_uid": me, "fixed": fixed}


def _lock_windows(path: Path, admins: bool) -> Dict[str, Any]:        # pragma: no cover
    icacls = system_tool("icacls")
    if not icacls:
        raise LockdownError("icacls.exe not found - cannot restrict the data folder")
    grants = ["/grant:r", "*S-1-5-18:(OI)(CI)F"]                    # LocalSystem
    if admins:
        grants += ["/grant:r", "*S-1-5-32-544:(OI)(CI)F"]            # BUILTIN\Administrators (break-glass)
    removed = ["*S-1-5-32-545", "*S-1-5-11", "*S-1-1-0", "*S-1-3-0", "*S-1-3-4"]   # Users, Auth. Users, Everyone,
    if not admins:                                                     # CREATOR OWNER, OWNER RIGHTS
        removed.append("*S-1-5-32-544")
    steps = [[icacls, str(path), "/inheritance:r", *grants, "/T", "/C", "/Q"]]
    steps += [[icacls, str(path), "/remove:g", sid, "/T", "/C", "/Q"] for sid in removed]
    for cmd in steps:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0 and cmd is steps[0]:
            raise LockdownError(f"icacls failed: {r.stderr.strip() or r.stdout.strip()}")
    return {"path": str(path), "acl": "SYSTEM" + (" + Administrators" if admins else "") + " only", "fixed": []}


def check_private(path: Path) -> List[str]:
    """Problems with the confidentiality of a file/folder (for warnings in non-service modes)."""
    if IS_WINDOWS:
        return []
    out = []
    try:
        s = os.stat(path)
    except OSError:
        return out
    if s.st_mode & 0o077:
        out.append(f"{path} is accessible by other users (mode {oct(stat.S_IMODE(s.st_mode))})")
    return out
