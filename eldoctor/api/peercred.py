"""OS-level peer credentials of a local API connection.

The kernel tells the agent *which OS account and process* is on the other end of the socket; this is
not something the client can claim or forge:

* Linux:          ``SO_PEERCRED``      -> pid, uid, gid
* macOS / *BSD:   ``LOCAL_PEERCRED``   -> uid, groups (+ ``LOCAL_PEERPID`` on macOS)
* Windows:        ``GetNamedPipeClientProcessId`` + the client process token (see ``winpipe``)

The agent uses them to (1) decide who may connect at all, (2) bind session tokens to the OS account
that logged in, (3) restrict bootstrap and, optionally, admin operations to OS administrators, and
(4) record the real OS identity in every audit record.  Clients use the same call on their side to
verify that the socket really belongs to the El Doctor agent (root / the service account / themselves)
before they send a password.

If peer credentials cannot be obtained the connection is refused (fail closed).
"""
from __future__ import annotations

import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Peer:
    pid: int
    uid: str                     # numeric uid on POSIX, SID string on Windows
    user: str                    # account name
    gid: Optional[int] = None
    groups: List[str] = field(default_factory=list)
    transport: str = "unix"      # unix | pipe | inproc
    elevated: bool = False       # root / LocalSystem / member of BUILTIN\\Administrators (Windows)

    def to_dict(self) -> dict:
        return {"pid": self.pid, "uid": self.uid, "user": self.user, "gid": self.gid, "groups": self.groups,
                "transport": self.transport, "elevated": self.elevated}


class PeerCredError(OSError):
    pass


def _posix_names(uid: int, gid: Optional[int]) -> tuple:
    user, groups = str(uid), []
    try:
        import grp
        import pwd
        pw = pwd.getpwuid(uid)
        user = pw.pw_name
        gids = set(os.getgrouplist(user, gid if gid is not None else pw.pw_gid))
        for g in gids:
            try:
                groups.append(grp.getgrgid(g).gr_name)
            except KeyError:
                groups.append(str(g))
    except (ImportError, KeyError, OSError):
        pass
    return user, sorted(groups)


def from_unix_socket(sock: socket.socket) -> Peer:
    """Kernel-verified credentials of the process at the other end of a connected AF_UNIX socket."""
    pid, uid, gid = 0, None, None
    if hasattr(socket, "SO_PEERCRED"):                                   # Linux
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
    elif sys.platform == "darwin" or "bsd" in sys.platform:             # pragma: no cover - not run on Linux CI
        SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID = 0, 0x001, 0x002
        fmt = "=IIh2x16I"
        raw = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize(fmt))
        vals = struct.unpack(fmt, raw[:struct.calcsize(fmt)])
        uid, ngroups = vals[1], vals[2]
        gid = vals[3] if ngroups > 0 else None
        try:
            pid = struct.unpack("i", sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
        except OSError:
            pid = 0
    else:                                                               # pragma: no cover
        raise PeerCredError(f"peer credentials are not supported on {sys.platform}")
    if uid is None or uid < 0:
        raise PeerCredError("kernel returned no peer credentials")
    user, groups = _posix_names(uid, gid)
    return Peer(pid=int(pid), uid=str(uid), user=user, gid=gid, groups=groups, transport="unix", elevated=uid == 0)


def own_identity(transport: str = "inproc") -> Peer:
    """This process as a peer (in-process API calls, and what a server compares tokens against)."""
    if sys.platform.startswith("win"):                                   # pragma: no cover
        from eldoctor.api import winpipe
        return winpipe.own_identity(transport)
    uid, gid = os.getuid(), os.getgid()
    user, groups = _posix_names(uid, gid)
    return Peer(pid=os.getpid(), uid=str(uid), user=user, gid=gid, groups=groups, transport=transport,
                elevated=uid == 0)
