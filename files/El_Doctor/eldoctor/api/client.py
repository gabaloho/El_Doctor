"""Client side of the agent API, used by the CLI, the TUI and the GUI.

``connect()`` finds the agent:

1. the agent's socket / named pipe (the service, or another console hosting the agent).  The server's
   OS identity is verified before anything is sent;
2. otherwise - only if this OS account can open the data folder itself (personal install) - the agent
   is hosted *in this process* (``AgentService``) and called through ``InProcessTransport``.  The
   request still goes through the same authentication and RBAC pipeline; nothing is checked in the
   front end.  In a service deployment the data folder is locked to the service account, so this
   fallback fails and the user is told to start the service.

Session tokens (JWT, issued by the agent) are stored per OS user in ``client_dir()`` (0600), one per
agent endpoint, never in the agent's data folder.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from eldoctor.api.peercred import own_identity
from eldoctor.api.transport import ApiUnavailable, InProcessTransport, ServerNotTrusted, UnixTransport
from eldoctor.config import IS_WINDOWS, api_endpoint, client_dir, home_dir, system_service_installed
from eldoctor.models import ActionResult, Alert, ProcessInfo


class ApiError(Exception):
    def __init__(self, code: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data or {}


# --------------------------------------------------------------------------- token storage (per OS user)
def token_path(endpoint: str) -> Path:
    d = client_dir() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        os.chmod(d, 0o700)
    return d / (hashlib.sha256(endpoint.encode()).hexdigest()[:20] + ".jwt")


def load_token(endpoint: str) -> Optional[str]:
    try:
        return token_path(endpoint).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def save_token(endpoint: str, token: str) -> None:
    p = token_path(endpoint)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    if not IS_WINDOWS:
        os.chmod(p, 0o600)


def clear_token(endpoint: str) -> None:
    try:
        token_path(endpoint).unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------- client
class ApiClient:
    def __init__(self, transport, client: str = "cli", api_key: Optional[str] = None) -> None:
        self.transport = transport
        self.client = client
        self.api_key = api_key or os.environ.get("ELDOCTOR_API_KEY") or None
        self.endpoint = transport.endpoint
        self.token = load_token(self.endpoint)
        self.local_service = None           # AgentService hosted in this process (personal / direct mode)
        self._ids = 0
        self._lock = threading.Lock()

    @property
    def hosted(self) -> bool:
        return self.local_service is not None

    def call(self, method: str, **params: Any) -> Any:
        with self._lock:
            self._ids += 1
            rid = self._ids
        req: Dict[str, Any] = {"v": 1, "id": rid, "method": method, "params": params, "client": self.client}
        if self.api_key:
            req["auth"] = {"api_key": self.api_key}
        elif self.token:
            req["auth"] = {"token": self.token}
        resp = self.transport.request(req)
        if resp.get("ok"):
            return resp.get("result")
        err = resp.get("error") or {}
        raise ApiError(str(err.get("code", "error")), str(err.get("message", "request failed")), err)

    def login(self, username: str, password: str) -> Dict[str, Any]:
        res = self.call("auth.login", username=username, password=password)
        self.token = res["token"]
        save_token(self.endpoint, self.token)
        return res

    def logout(self) -> None:
        try:
            if self.token:
                self.call("auth.logout")
        finally:
            self.token = None
            clear_token(self.endpoint)

    def whoami(self) -> Optional[Dict[str, Any]]:
        """The logged-in user (dict with 'permissions'), or None if not logged in / session invalid."""
        try:
            return self.call("auth.whoami")["user"]
        except ApiError as exc:
            if exc.code in ("unauthenticated", "not_registered"):
                return None
            raise

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            if self.local_service is not None:
                self.local_service.close()
                self.local_service = None


def _transport(endpoint: str, cfg: Dict[str, Any]):
    if IS_WINDOWS:                                            # pragma: no cover
        from eldoctor.api.winpipe import PipeTransport
        return PipeTransport(endpoint)
    trusted = ((cfg.get("api") or {}).get("trusted_server_users") or [])
    return UnixTransport(endpoint, trusted=trusted)


class ServiceNotRunning(ApiUnavailable):
    """The whole-computer service is installed but does not answer (yet): wait / start it, never host instead."""


def connect(cfg: Dict[str, Any], client: str = "cli", api_key: Optional[str] = None, host: bool = True,
            role: str = "direct") -> ApiClient:
    """Connect to the running agent, or (``host=True``) host it in-process on a data folder we own."""
    endpoint = api_endpoint(cfg)
    t = _transport(endpoint, cfg)
    try:
        t.connect()
        return ApiClient(t, client, api_key)
    except ServerNotTrusted:
        raise
    except ApiUnavailable as exc:
        reason = str(exc)
        if not host:
            raise
    if system_service_installed():
        # never silently fall back to a personal data folder on a host that runs the system service
        if os.name == "nt":
            raise ServiceNotRunning(
                "El Doctor's protection service is not running yet. It starts with the computer: restarting the "
                "computer usually fixes this. (Administrators: Start-ScheduledTask -TaskName 'ElDoctor Agent'; "
                f"details: {reason})")
        raise ServiceNotRunning(f"the El Doctor service is not running ({reason}). Start it: sudo systemctl start "
                                f"eldoctor   (or set ELDOCTOR_HOME to use a personal data folder)")
    from eldoctor.agent import running_agent_pid
    pid = running_agent_pid()
    if pid:
        raise ApiUnavailable(f"an El Doctor agent (pid {pid}) is running on {home_dir()} but its API is not "
                             f"reachable at {endpoint} ({reason})")
    from eldoctor.api.server import AgentService
    try:
        svc = AgentService(cfg, role=role)
    except (PermissionError, sqlite3.OperationalError, OSError) as exc:
        raise ApiUnavailable(
            f"The El Doctor agent is not running (no API at {endpoint}) and this OS account cannot open the "
            f"agent's data folder {home_dir()} ({exc}). Start the service: `systemctl start eldoctor` (Linux) or "
            f"`Start-ScheduledTask 'ElDoctor Agent'` (Windows).") from exc
    c = ApiClient(InProcessTransport(svc.handle, own_identity("inproc"), api_endpoint(cfg, server=True)),
                  client, api_key)
    c.local_service = svc
    return c


# --------------------------------------------------------------------------- remote agent view (TUI / GUI)
class RemoteAgent:
    """The agent as the TUI/GUI see it: state polled from ``agent.snapshot``, actions sent as API calls.

    Exposes the attributes the consoles used to read from the in-process Agent (latest_metrics,
    latest_procs, recent_alerts, recent_actions, lock, status(), mode) so the drawing code stays simple -
    but every value comes from the agent and every action is authorised by the agent."""

    def __init__(self, client: ApiClient, interval: float = 1.0, processes: Any = "all", alerts: int = 300,
                 actions: int = 300) -> None:
        self.client = client
        self.interval = interval
        self.want = {"processes": processes, "alerts": alerts, "actions": actions}
        self.lock = threading.RLock()
        self.latest_metrics: Dict[str, Any] = {}
        self.latest_procs: List[ProcessInfo] = []
        self.recent_alerts: Deque[Alert] = deque(maxlen=alerts or 1)
        self.recent_actions: Deque[Dict[str, Any]] = deque(maxlen=actions or 1)
        self.pending: List[Dict[str, Any]] = []
        self.user: Dict[str, Any] = {}
        self._status: Dict[str, Any] = {"mode": "?", "dry_run": False, "breaker": False, "uptime": 0.0,
                                        "own_cpu": 0.0, "own_mem_mb": 0.0, "log_sources": [], "sigma_rules": 0,
                                        "iocs": 0, "playbooks": 0, "yara": False, "tick_ms": 0.0,
                                        "notify_errors": [], "running": False, "server": {}}
        self.error = ""
        self.updated = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ polling
    def refresh(self) -> bool:
        try:
            snap = self.client.call("agent.snapshot", **self.want)
        except (ApiError, ApiUnavailable) as exc:
            self.error = f"agent API: {exc}"
            return False
        procs = [ProcessInfo.from_dict(p) for p in snap.get("processes") or []]
        alerts = [Alert.from_dict(a) for a in snap.get("alerts") or []]
        with self.lock:
            self.latest_metrics = snap.get("metrics") or {}
            self.latest_procs = procs
            self.recent_alerts.clear()
            self.recent_alerts.extend(alerts)
            self.recent_actions.clear()
            self.recent_actions.extend(snap.get("actions") or [])
            self.pending = snap.get("approvals") or []
            self._status = snap.get("status") or self._status
            self.user = snap.get("user") or self.user
        self.error = (self._status.get("error") or "") if self._status.get("running") else ""
        self.updated = time.time()
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self.interval)

    def start_background(self) -> threading.Thread:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="eldoctor-client")
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------ state
    def status(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self._status)

    @property
    def mode(self) -> str:
        return self.status().get("mode", "?")

    @property
    def running(self) -> bool:
        return bool(self.status().get("running"))

    def pending_approvals(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.pending)

    # ------------------------------------------------------------------ actions (authorised by the agent)
    def manual_action(self, action: str, proc: ProcessInfo, user: Any = None) -> ActionResult:
        try:
            res = self.client.call("respond.process", action=action, pid=proc.pid, create_time=proc.create_time)
        except ApiError as exc:
            return ActionResult(action, "blocked" if exc.code == "forbidden" else "failed", exc.message,
                                f"{proc.name}[{proc.pid}]")
        except ApiUnavailable as exc:
            return ActionResult(action, "failed", str(exc), f"{proc.name}[{proc.pid}]")
        known = set(ActionResult.__dataclass_fields__)  # type: ignore[attr-defined]
        r = ActionResult(**{k: v for k, v in res.items() if k in known})
        with self.lock:
            self.recent_actions.appendleft(dict(res, playbook="manual", mode="manual"))
        return r

    def decide(self, approval_id: str, approve: bool) -> Tuple[bool, str]:
        try:
            res = self.client.call("approvals.decide", id=approval_id, decision="approve" if approve else "deny")
            return True, f"approval {approval_id} {res['status']}"
        except ApiError as exc:
            return False, exc.message
        except ApiUnavailable as exc:
            return False, str(exc)

    def set_mode(self, mode: str) -> Tuple[bool, str]:
        try:
            res = self.client.call("agent.set_mode", mode=mode)
            with self.lock:
                self._status["mode"] = res["mode"]
            return True, f"response mode -> {res['mode']}"
        except ApiError as exc:
            return False, exc.message
        except ApiUnavailable as exc:
            return False, str(exc)
