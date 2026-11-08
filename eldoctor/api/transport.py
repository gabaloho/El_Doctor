"""Local transports for the agent API.

Wire format: one JSON object per line (UTF-8, ``\\n`` terminated), request -> response, several requests
per connection.  Messages are capped (``MAX_MESSAGE``) so a client cannot exhaust the agent's memory.

* ``UnixApiServer`` / ``UnixTransport`` - AF_UNIX stream socket (Linux, macOS, BSD).  The server reads
  the client's kernel-verified peer credentials on accept; the client checks the server's credentials
  before sending anything (anti-spoofing: a socket planted by another user is refused).
* ``InProcessTransport`` - the same handler called in-process (JSON round-trip included, so nothing but
  plain data crosses the boundary).  Used when the CLI/TUI/GUI itself hosts the agent on a data folder
  the current OS account owns.
* Windows named pipes live in ``eldoctor.api.winpipe`` and expose the same interface.
"""
from __future__ import annotations

import json
import os
import select
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Set

from eldoctor.api.peercred import Peer, PeerCredError, from_unix_socket

MAX_MESSAGE = 16 * 1024 * 1024
Handler = Callable[[Dict[str, Any], Peer], Dict[str, Any]]


class ApiUnavailable(ConnectionError):
    """No agent is listening (or it cannot be trusted)."""


class ServerNotTrusted(ApiUnavailable):
    pass


def encode(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), default=str).encode("utf-8") + b"\n"


def decode(line: bytes) -> Any:
    if len(line) > MAX_MESSAGE:
        raise ValueError("message too large")
    return json.loads(line.decode("utf-8"))


def read_message(rfile) -> Optional[Any]:
    line = rfile.readline(MAX_MESSAGE + 1)
    if not line:
        return None
    if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
        raise ValueError("message too large or truncated")
    return decode(line)


def serve_connection(rfile, wfile, handler: Handler, peer: Peer, stop: threading.Event) -> None:
    """Request/response loop shared by the Unix-socket and named-pipe servers."""
    while not stop.is_set():
        try:
            req = read_message(rfile)
        except (ValueError, UnicodeDecodeError):
            wfile.write(encode({"v": 1, "ok": False, "error": {"code": "bad_request", "message": "invalid message"}}))
            wfile.flush()
            return
        except OSError:
            return
        if req is None:
            return
        resp = handler(req, peer)
        try:
            wfile.write(encode(resp))
            wfile.flush()
        except OSError:
            return


# --------------------------------------------------------------------------- unix socket server
def _prepare_socket_dir(path: Path) -> None:
    """The socket's folder must belong to us (or root) and not be writable by others (no socket swapping)."""
    d = path.parent
    if not d.exists():
        d.mkdir(parents=True, mode=0o700)
    st = os.lstat(d)
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"refusing to create the API socket in a symlinked folder: {d}")
    if st.st_uid not in (os.getuid(), 0):
        raise PermissionError(f"API socket folder {d} belongs to uid {st.st_uid}, not to this agent")
    if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise PermissionError(f"API socket folder {d} is writable by other users")


class UnixApiServer:
    def __init__(self, path: str, handler: Handler, mode: int = 0o600, group: Optional[str] = None,
                 max_connections: int = 64, idle_timeout: float = 600.0,
                 admit: Optional[Callable[[Peer], Optional[str]]] = None, max_per_account: int = 16,
                 exempt_uids: Optional[Set[str]] = None) -> None:
        self.path = Path(path)
        self.handler = handler
        self.mode = mode
        self.group = group
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.admit = admit                      # peer -> None (ok) | reason for refusing the connection
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._conns: Set[socket.socket] = set()
        self._per_uid: Dict[str, int] = {}
        self.max_per_account = max_per_account    # one local account cannot exhaust the agent's connections
        self.exempt_uids = {"0", str(os.getuid())} if exempt_uids is None else set(exempt_uids)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    @property
    def endpoint(self) -> str:
        return str(self.path)

    def start(self) -> None:
        _prepare_socket_dir(self.path)
        if self.path.exists() or self.path.is_symlink():
            st = os.lstat(self.path)
            if not stat.S_ISSOCK(st.st_mode):
                raise PermissionError(f"{self.path} exists and is not a socket - refusing to replace it")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(1.0)
            try:
                probe.connect(str(self.path))
                alive = True
            except OSError:
                alive = False
            finally:
                probe.close()
            if alive:
                raise RuntimeError(f"another El Doctor agent is already serving the API on {self.path}")
            self.path.unlink()                   # stale socket of a crashed agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)                    # never even briefly world-connectable
        try:
            s.bind(str(self.path))
        finally:
            os.umask(old)
        if self.group:
            import grp
            os.chown(str(self.path), -1, grp.getgrnam(self.group).gr_gid)
        os.chmod(str(self.path), self.mode)
        s.listen(32)
        self._sock = s
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="eldoctor-api")
        self._thread.start()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self._sock], [], [], 0.5)
            except (OSError, ValueError):
                break
            if not r:
                continue
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with self._lock:
                if len(self._conns) >= self.max_connections:
                    conn.close()
                    continue
                self._conns.add(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True, name="eldoctor-api-conn").start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            try:
                peer = from_unix_socket(conn)
            except (PeerCredError, OSError):
                return                                    # fail closed: unknown peer, no service
            reason = self.admit(peer) if self.admit else None
            exempt = peer.uid in self.exempt_uids
            with self._lock:
                n = self._per_uid.get(peer.uid, 0)
                if not reason and not exempt and n >= self.max_per_account:
                    reason = f"too many open connections for OS account {peer.user} (max {self.max_per_account})"
                if not reason:
                    self._per_uid[peer.uid] = n + 1
            if reason:
                conn.sendall(encode({"v": 1, "ok": False, "error": {"code": "forbidden", "message": reason}}))
                return
            try:
                conn.settimeout(self.idle_timeout)
                with conn.makefile("rb") as rfile, conn.makefile("wb") as wfile:
                    serve_connection(rfile, wfile, self.handler, peer, self._stop)
            finally:
                with self._lock:
                    self._per_uid[peer.uid] = max(0, self._per_uid.get(peer.uid, 1) - 1)
        except (OSError, ValueError):
            pass
        finally:
            with self._lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._lock:
            conns = list(self._conns)
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        try:
            if self.path.exists() and stat.S_ISSOCK(os.lstat(self.path).st_mode):
                self.path.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- client transports
def trusted_server_uids(path: Path, extra: Iterable[Any] = ()) -> Set[int]:
    """Whom a client accepts as the agent: root, itself, the owner of a non-writable socket folder."""
    ok = {0, os.getuid()}
    try:
        st = os.stat(path.parent)
        if not st.st_mode & 0o022 or st.st_mode & stat.S_ISVTX:
            ok.add(st.st_uid)
    except OSError:
        pass
    for x in extra:
        try:
            ok.add(int(x))
        except (TypeError, ValueError):
            try:
                import pwd
                ok.add(pwd.getpwnam(str(x)).pw_uid)
            except (ImportError, KeyError):
                pass
    return ok


class UnixTransport:
    def __init__(self, path: str, timeout: float = 60.0, trusted: Iterable[Any] = ()) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.trusted = list(trusted)
        self._sock: Optional[socket.socket] = None
        self._rfile = None
        self._lock = threading.RLock()
        self.server: Optional[Peer] = None

    @property
    def endpoint(self) -> str:
        return str(self.path)

    def connect(self) -> "UnixTransport":
        with self._lock:
            self.close()
            if not self.path.exists():
                raise ApiUnavailable(f"no El Doctor agent API at {self.path}")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect(str(self.path))
            except OSError as exc:
                s.close()
                raise ApiUnavailable(f"El Doctor agent API at {self.path} is not answering ({exc.strerror or exc})") \
                    from exc
            try:
                srv = from_unix_socket(s)
            except (PeerCredError, OSError) as exc:
                s.close()
                raise ServerNotTrusted(f"cannot verify who owns {self.path}: {exc}") from exc
            if int(srv.uid) not in trusted_server_uids(self.path, self.trusted):
                s.close()
                raise ServerNotTrusted(f"refusing API socket {self.path}: it is served by OS user {srv.user} "
                                       f"(uid {srv.uid}), not by root, the El Doctor service account or you")
            self.server = srv
            self._sock = s
            self._rfile = s.makefile("rb")
            return self

    def _stale(self) -> bool:
        """The server closed an idle connection: readable + EOF before we sent anything."""
        if self._sock is None:
            return True
        try:
            r, _, _ = select.select([self._sock], [], [], 0)
        except (OSError, ValueError):
            return True
        return bool(r)

    def request(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self._stale():
                self.connect()
            assert self._sock is not None
            try:
                self._sock.sendall(encode(obj))
                resp = read_message(self._rfile)
            except socket.timeout as exc:
                self.close()
                raise ApiUnavailable(f"the El Doctor agent did not answer within {self.timeout:g}s") from exc
            except (OSError, ValueError) as exc:
                self.close()
                raise ApiUnavailable(f"connection to the El Doctor agent lost: {exc}") from exc
            if resp is None:
                self.close()
                raise ApiUnavailable("the El Doctor agent closed the connection")
            return resp

    def close(self) -> None:
        with self._lock:
            for f in (self._rfile, self._sock):
                try:
                    if f is not None:
                        f.close()
                except OSError:
                    pass
            self._sock = self._rfile = None


class InProcessTransport:
    """Calls the agent handler directly. The JSON round-trip keeps the contract identical to the socket."""

    def __init__(self, handler: Handler, peer: Peer, endpoint: str) -> None:
        self.handler = handler
        self.peer = peer
        self._endpoint = endpoint
        self.server = peer

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def connect(self) -> "InProcessTransport":
        return self

    def request(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        req = json.loads(json.dumps(obj, default=str))
        return json.loads(json.dumps(self.handler(req, self.peer), default=str))

    def close(self) -> None:
        pass


def wait_for_socket(path: str, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            UnixTransport(path, timeout=2).connect().close()
            return True
        except ApiUnavailable:
            time.sleep(0.1)
    return False
