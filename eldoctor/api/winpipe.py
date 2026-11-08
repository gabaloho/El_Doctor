"""Windows named-pipe transport for the agent API (ctypes, no pywin32 needed).

Security properties
* The pipe is created with an explicit DACL (SDDL): network logons denied, LocalSystem and
  Administrators full access, the agent's own account full access and - for the service -
  Authenticated Users read/write so non-admin analysts can *talk* to the agent (they still have to
  authenticate, and every permission is checked inside the agent).
* ``FILE_FLAG_FIRST_PIPE_INSTANCE`` stops another process from squatting the pipe name first, and
  ``PIPE_REJECT_REMOTE_CLIENTS`` refuses SMB clients.
* Peer credentials: ``GetNamedPipeClientProcessId`` -> the client's process token -> user SID,
  account name and elevation (the SYSTEM service may open any client's token).  The client checks the
  *owner SID of the pipe object* through its own handle (``GetSecurityInfo``) and only talks to a pipe
  owned by LocalSystem, the Administrators group (elevated creator) or itself - a standard user cannot
  open a SYSTEM service's token, but it can read the owner of the pipe it is connected to.

Not executed in the Linux sandbox this project was built in (see docs/PRODUCTION_READINESS.md P0-2);
the module only imports ctypes Windows APIs lazily, so importing it elsewhere is harmless.
"""
from __future__ import annotations

import getpass
import os
import threading
from typing import Any, Callable, Dict, Optional

from eldoctor.api.peercred import Peer
from eldoctor.api.transport import ApiUnavailable, MAX_MESSAGE, ServerNotTrusted, encode, read_message, \
    serve_connection

SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"              # owner of objects created by an elevated administrator
SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION = 6, 0x1
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT, PIPE_REJECT_REMOTE_CLIENTS = 0x0, 0x0, 0x0, 0x8
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS, TOKEN_ELEVATION_CLASS = 1, 20
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3


_API: Optional[tuple] = None


def _api():
    """kernel32/advapi32 with explicit prototypes (64-bit HANDLEs must never be truncated to C int)."""
    global _API
    if _API is not None:
        return _API
    import ctypes
    from ctypes import POINTER, wintypes as w
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    H, D, B, V = w.HANDLE, w.DWORD, w.BOOL, w.LPVOID
    protos = [
        (k32.CreateNamedPipeW, H, [w.LPCWSTR, D, D, D, D, D, D, V]),
        (k32.ConnectNamedPipe, B, [H, V]),
        (k32.DisconnectNamedPipe, B, [H]),
        (k32.FlushFileBuffers, B, [H]),
        (k32.CloseHandle, B, [H]),
        (k32.ReadFile, B, [H, V, D, POINTER(D), V]),
        (k32.WriteFile, B, [H, V, D, POINTER(D), V]),
        (k32.GetNamedPipeClientProcessId, B, [H, POINTER(w.ULONG)]),
        (k32.GetNamedPipeServerProcessId, B, [H, POINTER(w.ULONG)]),
        (k32.OpenProcess, H, [D, B, D]),
        (k32.GetCurrentProcess, H, []),
        (k32.LocalFree, V, [V]),
        (adv.OpenProcessToken, B, [H, D, POINTER(H)]),
        (adv.GetTokenInformation, B, [H, ctypes.c_int, V, D, POINTER(D)]),
        (adv.ConvertSidToStringSidW, B, [V, POINTER(w.LPWSTR)]),
        (adv.LookupAccountSidW, B, [w.LPCWSTR, V, w.LPWSTR, POINTER(D), w.LPWSTR, POINTER(D), POINTER(D)]),
        (adv.ConvertStringSecurityDescriptorToSecurityDescriptorW, B, [w.LPCWSTR, D, POINTER(V), POINTER(w.ULONG)]),
        (adv.GetSecurityInfo, D, [H, ctypes.c_int, D, POINTER(V), POINTER(V), POINTER(V), POINTER(V), POINTER(V)]),
    ]
    for fn, res, args in protos:
        fn.restype, fn.argtypes = res, args
    _API = (ctypes, w, k32, adv)
    return _API


class _SA:                                    # SECURITY_ATTRIBUTES built lazily (ctypes.Structure needs ctypes)
    @staticmethod
    def build(sddl: str):
        ctypes, wintypes, k32, adv = _api()

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                        ("bInheritHandle", wintypes.BOOL)]
        sd = wintypes.LPVOID()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):  # noqa
            raise OSError(ctypes.get_last_error(), "ConvertStringSecurityDescriptorToSecurityDescriptorW failed")
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd.value, False)
        return sa, sd


def _token_identity(h_process) -> Dict[str, Any]:
    ctypes, wintypes, k32, adv = _api()
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(tok)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        need = wintypes.DWORD()
        adv.GetTokenInformation(tok, TOKEN_USER_CLASS, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(need.value)
        if not adv.GetTokenInformation(tok, TOKEN_USER_CLASS, buf, need.value, ctypes.byref(need)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation(TokenUser) failed")
        psid = ctypes.cast(buf, ctypes.POINTER(wintypes.LPVOID))[0]        # TOKEN_USER.User.Sid
        sid = _sid_str(psid)
        name = ctypes.create_unicode_buffer(256)
        dom = ctypes.create_unicode_buffer(256)
        n1, n2, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
        account = sid
        if adv.LookupAccountSidW(None, psid, name, ctypes.byref(n1), dom, ctypes.byref(n2), ctypes.byref(use)):
            account = f"{dom.value}\\{name.value}" if dom.value else name.value
        elev = wintypes.DWORD()
        got = wintypes.DWORD()
        elevated = bool(adv.GetTokenInformation(tok, TOKEN_ELEVATION_CLASS, ctypes.byref(elev), 4, ctypes.byref(got))
                        and elev.value)
        return {"sid": sid, "user": account, "elevated": elevated or sid == SYSTEM_SID}
    finally:
        k32.CloseHandle(tok)


def _sid_str(psid) -> str:
    ctypes, wintypes, k32, adv = _api()
    s = wintypes.LPWSTR()
    if not adv.ConvertSidToStringSidW(psid, ctypes.byref(s)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
    try:
        return s.value
    finally:
        k32.LocalFree(s)


def pipe_owner_sid(handle) -> str:
    """Owner SID of the pipe object behind `handle` (queried through our own handle - no access to the
    server process or its token is needed, which a standard user would not have for a SYSTEM service)."""
    ctypes, wintypes, k32, adv = _api()
    owner, sd = wintypes.LPVOID(), wintypes.LPVOID()
    err = adv.GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner), None,
                              None, None, ctypes.byref(sd))
    if err != 0:
        raise OSError(err, "GetSecurityInfo(owner) failed")
    try:
        return _sid_str(owner.value)
    finally:
        k32.LocalFree(sd)


def _process_identity(pid: int) -> Dict[str, Any]:
    ctypes, wintypes, k32, adv = _api()
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        raise OSError(ctypes.get_last_error(), f"OpenProcess({pid}) failed")
    try:
        return _token_identity(h)
    finally:
        k32.CloseHandle(h)


def own_identity(transport: str = "inproc") -> Peer:
    ctypes, wintypes, k32, adv = _api()
    try:
        ident = _token_identity(k32.GetCurrentProcess())
    except OSError:
        ident = {"sid": getpass.getuser(), "user": getpass.getuser(), "elevated": False}
    return Peer(pid=os.getpid(), uid=ident["sid"], user=ident["user"], transport=transport,
                elevated=ident["elevated"])


class _HandleFile:
    """Minimal buffered file over a pipe HANDLE: readline(limit) / write / flush."""

    def __init__(self, handle) -> None:
        self.h = handle
        self.buf = b""

    def _read(self, n: int) -> bytes:
        ctypes, wintypes, k32, adv = _api()
        buf = ctypes.create_string_buffer(n)
        got = wintypes.DWORD()
        if not k32.ReadFile(self.h, buf, n, ctypes.byref(got), None):
            err = ctypes.get_last_error()
            if err == ERROR_BROKEN_PIPE:
                return b""
            raise OSError(err, "ReadFile failed")
        return buf.raw[:got.value]

    def readline(self, limit: int = MAX_MESSAGE + 1) -> bytes:
        while b"\n" not in self.buf and len(self.buf) < limit:
            chunk = self._read(65536)
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(b"\n")
        cut = i + 1 if i >= 0 else len(self.buf)
        line, self.buf = self.buf[:cut], self.buf[cut:]
        return line

    def write(self, data: bytes) -> int:
        ctypes, wintypes, k32, adv = _api()
        done = wintypes.DWORD()
        view = memoryview(data)
        while view:
            if not k32.WriteFile(self.h, bytes(view[:65536]), min(len(view), 65536), ctypes.byref(done), None):
                raise OSError(ctypes.get_last_error(), "WriteFile failed")
            view = view[done.value:]
        return len(data)

    def flush(self) -> None:
        pass


class PipeApiServer:
    def __init__(self, name: str, handler: Callable, allow_authenticated_users: bool = True,
                 admit: Optional[Callable[[Peer], Optional[str]]] = None) -> None:
        self.name = name
        self.handler = handler
        self.admit = admit
        me = own_identity()
        aces = "(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)" + f"(A;;GA;;;{me.uid})"
        if allow_authenticated_users:
            aces += "(A;;GRGW;;;AU)"
        self.sddl = "D:P" + aces
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._first = True

    @property
    def endpoint(self) -> str:
        return self.name

    def _create_instance(self):
        ctypes, wintypes, k32, adv = _api()
        sa, sd = _SA.build(self.sddl)
        flags = PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if self._first else 0)
        h = k32.CreateNamedPipeW(self.name, flags, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                 PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0,
                                 ctypes.byref(sa))
        k32.LocalFree(sd)
        if not h or h == ctypes.c_void_p(-1).value:
            raise RuntimeError(f"cannot create named pipe {self.name} (already served by another agent?) "
                               f"- error {ctypes.get_last_error()}")
        self._first = False
        return h

    def start(self) -> None:
        self._pending = self._create_instance()       # fail fast (e.g. name squatted) in the caller's thread
        self._thread = threading.Thread(target=self._loop, daemon=True, name="eldoctor-api")
        self._thread.start()

    def _loop(self) -> None:
        ctypes, wintypes, k32, adv = _api()
        while not self._stop.is_set():
            h = self._pending or self._create_instance()
            self._pending = None
            ok = k32.ConnectNamedPipe(h, None) or ctypes.get_last_error() == ERROR_PIPE_CONNECTED
            if self._stop.is_set() or not ok:
                k32.CloseHandle(h)
                continue
            threading.Thread(target=self._serve, args=(h,), daemon=True, name="eldoctor-api-conn").start()

    def _serve(self, h) -> None:
        ctypes, wintypes, k32, adv = _api()
        try:
            pid = wintypes.ULONG()
            if not k32.GetNamedPipeClientProcessId(h, ctypes.byref(pid)):
                return
            try:
                ident = _process_identity(pid.value)
            except OSError:
                return                                      # fail closed
            peer = Peer(pid=pid.value, uid=ident["sid"], user=ident["user"], transport="pipe",
                        elevated=ident["elevated"])
            f = _HandleFile(h)
            reason = self.admit(peer) if self.admit else None
            if reason:
                f.write(encode({"v": 1, "ok": False, "error": {"code": "forbidden", "message": reason}}))
                return
            serve_connection(f, f, self.handler, peer, self._stop)
        finally:
            k32.FlushFileBuffers(h)
            k32.DisconnectNamedPipe(h)
            k32.CloseHandle(h)

    def stop(self) -> None:
        self._stop.set()
        try:                                                # unblock ConnectNamedPipe
            with open(self.name, "r+b", buffering=0):
                pass
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=3)


class PipeTransport:
    def __init__(self, name: str, timeout: float = 60.0) -> None:
        self.name = name
        self.timeout = timeout
        self._f = None
        self._reader: Optional[_HandleFile] = None
        self._lock = threading.RLock()
        self.server: Optional[Peer] = None

    @property
    def endpoint(self) -> str:
        return self.name

    def connect(self) -> "PipeTransport":
        import msvcrt
        ctypes, wintypes, k32, adv = _api()
        with self._lock:
            self.close()
            try:
                f = open(self.name, "r+b", buffering=0)
            except OSError as exc:
                raise ApiUnavailable(f"no El Doctor agent API at {self.name}") from exc
            h = msvcrt.get_osfhandle(f.fileno())
            # anti-spoofing: only talk to a pipe *owned* by LocalSystem, an elevated administrator or ourselves.
            # A normal user cannot create a pipe owned by SYSTEM/Administrators.
            try:
                owner = pipe_owner_sid(h)
            except OSError as exc:
                f.close()
                raise ServerNotTrusted(f"cannot verify who owns {self.name}: {exc}") from exc
            me = own_identity()
            if owner not in (SYSTEM_SID, ADMINS_SID, me.uid):
                f.close()
                raise ServerNotTrusted(f"refusing {self.name}: the pipe is owned by {owner}, not by SYSTEM, the "
                                       f"Administrators group or you")
            pid = wintypes.ULONG()
            srv_user, srv_elev = owner, owner in (SYSTEM_SID, ADMINS_SID)
            if k32.GetNamedPipeServerProcessId(h, ctypes.byref(pid)):
                try:                                    # informational: may be denied for a SYSTEM server
                    ident = _process_identity(pid.value)
                    srv_user, srv_elev = ident["user"], ident["elevated"]
                except OSError:
                    pass
            self.server = Peer(pid=pid.value, uid=owner, user=srv_user, transport="pipe", elevated=srv_elev)
            self._f = f
            self._reader = _HandleFile(h)
            return self

    def request(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self._f is None:
                self.connect()
            try:
                self._reader.write(encode(obj))              # type: ignore[union-attr]
                resp = read_message(self._reader)
            except (OSError, ValueError) as exc:
                self.close()
                raise ApiUnavailable(f"connection to the El Doctor agent lost: {exc}") from exc
            if resp is None:
                self.close()
                raise ApiUnavailable("the El Doctor agent closed the connection")
            return resp

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                try:
                    self._f.close()
                except OSError:
                    pass
            self._f = self._reader = None
