"""The agent side of the local API: ``AgentService``.

This is the only code that opens the database, holds the integrity keys, runs response actions and
decides who may do what.  Front ends send requests; for every request the service

1. reads the caller's OS identity from the transport (kernel peer credentials),
2. admits or refuses the OS account (``api.allowed_os_users`` / ``api.allowed_os_groups``),
3. authenticates the caller (JWT bound to that OS account, or an API key),
4. re-reads the caller's *current* role from the sealed user record and checks the permission the
   method requires (table ``METHODS`` - the single source of truth for RBAC),
5. executes the method, and records who did it (El Doctor user + OS user/uid/pid + front end) in the
   hash-chained audit trail, which is forwarded to the SIEM in real time.

Refused requests are audited too (``api_denied``), so probing for permissions leaves a trace.

Roles of an ``AgentService`` process
    ``service``   unattended agent (systemd / Scheduled Task / container), API on the system socket/pipe
    ``headless``  ``eldoctor run --headless`` - same, started by a logged-in user on their own data folder
    ``embedded``  the TUI/GUI hosts the agent for a data folder the OS user owns (personal use); the
                  API is also served on the socket so ``eldoctor approvals approve`` works from another
                  terminal
    ``direct``    a one-shot CLI command on a data folder the OS user owns, when no agent is running
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

from eldoctor import __version__
from eldoctor.api.peercred import Peer, own_identity
from eldoctor.auth.tokens import TokenError, TokenService
from eldoctor.auth.users import (DEPLOY_TARGETS, PERMISSIONS, ROLES, USE_CASES, AuthError, User, UserManager,
                                 password_problems)
from eldoctor.config import IS_WINDOWS, MODES, api_endpoint, home_dir, is_privileged, user_config_path
from eldoctor.models import HOSTNAME, Alert, ProcessInfo, severity_rank
from eldoctor.siem import AuditForwarder
from eldoctor.storage import Origin, Store, acting_as

ADMIN_PERMS = {"manage_users", "enforce", "config", "deploy", "restore", "unblock", "audit"}
MANUAL_ACTIONS = {"kill", "kill_tree", "suspend", "resume", "renice", "forensics", "quarantine"}
IOC_TYPES = {"ip", "cidr", "domain", "sha256", "sha1", "md5", "filename"}
SECRET_KEY_RX = re.compile(r"(password|secret|token|api_key|apikey)$", re.I)


class ApiFault(Exception):
    """An error returned to the client: code in unauthenticated | not_registered | forbidden | bad_request |
    not_found | conflict | unavailable | integrity | internal."""

    def __init__(self, code: str, message: str, **data: Any) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


@dataclass
class Method:
    name: str
    perm: Optional[str]           # permission required (None = any authenticated user / public)
    auth: Any                     # True = required, False = public, "optional" = used when present
    fn: Callable


METHODS: Dict[str, Method] = {}


def api(name: str, perm: Optional[str] = None, auth: Any = True):
    def deco(fn: Callable) -> Callable:
        METHODS[name] = Method(name, perm, auth, fn)
        return fn
    return deco


def required_role(perm: str) -> str:
    return next((r for r in ROLES if perm in PERMISSIONS[r]), "admin")


def _int(v: Any, default: int, lo: int = 0, hi: int = 10_000) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _str(p: Dict[str, Any], key: str, required: bool = True, max_len: int = 512) -> str:
    v = p.get(key)
    if v is None or v == "":
        if required:
            raise ApiFault("bad_request", f"missing parameter '{key}'")
        return ""
    if not isinstance(v, (str, int, float)):
        raise ApiFault("bad_request", f"parameter '{key}' must be a string")
    v = str(v)
    if len(v) > max_len:
        raise ApiFault("bad_request", f"parameter '{key}' is too long")
    return v


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if SECRET_KEY_RX.search(str(k)) and not str(k).endswith("_env") and v else _redact(v))
                for k, v in obj.items() if k != "_path"}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


def _proc_row(p: ProcessInfo) -> Dict[str, Any]:
    return {"pid": p.pid, "ppid": p.ppid, "name": p.name, "exe": p.exe, "cmdline": p.cmdline_str,
            "username": p.username, "create_time": p.create_time, "cpu_percent": round(p.cpu_percent, 1),
            "memory_percent": round(p.memory_percent, 2), "rss": p.rss, "status": p.status,
            "num_threads": p.num_threads}


def _approval_row(r: Dict[str, Any]) -> Dict[str, Any]:
    return {k: r.get(k) for k in ("id", "ts", "expires", "alert_id", "playbook_id", "step_index", "summary", "status",
                                  "decided_by", "decided_ts", "decided_os_user", "executed", "integrity")}


# ----------------------------------------------------------------------------------------- light observer
class LightObserver:
    """Metrics + process table when no detection loop runs (viewer sessions)."""

    def __init__(self, interval: float = 2.0) -> None:
        from eldoctor.collectors.metrics import MetricsCollector
        from eldoctor.collectors.processes import ProcessCollector
        self.interval = interval
        self.metrics = MetricsCollector(None)
        self.procs = ProcessCollector(hash_executables=False)
        self.latest_metrics: Dict[str, Any] = {}
        self.latest_procs: List[ProcessInfo] = []
        self.lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="eldoctor-observer")
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                procs, _ = self.procs.snapshot()
                m = self.metrics.collect()
                with self.lock:
                    self.latest_metrics = m
                    self.latest_procs = sorted(procs, key=lambda p: (p.cpu_percent, p.memory_percent), reverse=True)
            except Exception:
                pass
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


# ----------------------------------------------------------------------------------------- service
class AgentService:
    def __init__(self, cfg: Dict[str, Any], role: str = "direct", store: Optional[Store] = None) -> None:
        self.cfg = cfg
        self.role = role
        self.api_cfg = cfg.get("api") or {}
        self.store = store or Store()
        if role in ("service", "headless", "embedded"):
            # long-running agents decide on an index built from a fully verified scan of the signed chain
            self.store.enable_verified_ledger()
        self.um = UserManager(self.store, cfg)
        kid = self.store.keys.kid
        self.tokens = TokenService(self.store.keys.key("jwt"), issuer=f"eldoctor:{kid}", kid=kid,
                                   lifetime_s=self.um.session_hours * 3600)
        self.forwarder = AuditForwarder(cfg, self.store)
        self.me = own_identity("inproc")
        self.agent = None
        self.observer: Optional[LightObserver] = None
        self.listener = None
        self.started = time.time()
        self.dry_run_default = bool(cfg["agent"].get("dry_run", False))
        self._responder = None
        self._engine = None
        self._dispatcher = None
        self._lock = threading.RLock()
        self._denied: Dict[tuple, float] = {}
        self._integrity_stop = threading.Event()
        self._integrity_thread: Optional[threading.Thread] = None
        self.last_verification: Dict[str, Any] = {}
        self.closed = False
        self.store.violation_listeners.append(self._on_violation)
        for problem in list(self.store.integrity_problems):
            self.store.report_violation("database", "*", problem)

    # ------------------------------------------------------------------ lifecycle
    @property
    def endpoint(self) -> str:
        return self.listener.endpoint if self.listener else api_endpoint(self.cfg, server=True)

    def start_listener(self, service: bool = False):
        """Serve the API on the local socket / named pipe (refuses if another agent already serves it)."""
        if self.listener:
            return self.listener
        endpoint = api_endpoint(self.cfg, server=True)
        if IS_WINDOWS:                                               # pragma: no cover
            from eldoctor.api.winpipe import PipeApiServer
            srv = PipeApiServer(endpoint, self.handle, allow_authenticated_users=service, admit=self.admit)
        else:
            from eldoctor.api.transport import UnixApiServer
            mode_cfg = str(self.api_cfg.get("socket_mode", "auto"))
            group = self.api_cfg.get("socket_group") or None
            if mode_cfg == "auto":
                mode = (0o660 if group else 0o666) if service else 0o600
            else:
                mode = int(mode_cfg, 8)
            parent = Path(endpoint).parent
            if service and not parent.exists():
                parent.mkdir(parents=True, mode=0o755)
            srv = UnixApiServer(endpoint, self.handle, mode=mode, group=group, admit=self.admit,
                                max_connections=_int(self.api_cfg.get("max_connections"), 64, 1, 1024))
        srv.start()
        self.listener = srv
        self.forwarder.start()                 # audit records of API clients reach the SIEM in real time
        self.store.audit("agent", "api_listening", {"endpoint": endpoint, "role": self.role})
        return srv

    def start_agent(self, user: User, mode: Optional[str] = None, dry_run: Optional[bool] = None,
                    headless: bool = True, background: bool = True):
        from eldoctor.agent import Agent
        with self._lock:
            if self.agent is not None:
                return self.agent
            mode = mode or self.cfg["agent"]["mode"]
            if mode == "enforce" and not user.can("enforce"):
                mode = "interactive"
            if dry_run is not None:
                self.dry_run_default = bool(dry_run)
            self.agent = Agent(self.cfg, self.store, user, mode=mode, dry_run=True if dry_run else None,
                               headless=headless, users=self.um)
            if self.observer:
                self.observer.stop()
                self.observer = None
        self.forwarder.start()
        self._start_integrity_monitor()
        if background:
            self.agent.start_background()
        return self.agent

    def _start_integrity_monitor(self) -> None:
        ac = self.cfg.get("audit", {}) or {}
        interval = float(ac.get("verify_interval_minutes", 15)) * 60
        if self._integrity_thread or interval <= 0:
            return

        stop = self._integrity_stop = threading.Event()

        def loop() -> None:
            if ac.get("verify_on_start", True):
                self.verify_audit()
            while not stop.wait(interval):
                self.verify_audit()
        self._integrity_thread = threading.Thread(target=loop, daemon=True, name="eldoctor-integrity")
        self._integrity_thread.start()

    def verify_audit(self) -> Dict[str, Any]:
        res = self.store.verify_audit(genesis_pin=str((self.cfg.get("audit") or {}).get("genesis_fingerprint") or ""))
        res["verified_at"] = time.time()
        self.last_verification = res
        if not res["ok"]:
            self.store.report_violation("audit", "chain", "audit trail failed hash-chain verification",
                                        {"problems": res["problems"][:20]})
        return res

    def stop_agent(self) -> None:
        """Stop detection, the API listener and background threads; the service stays usable in-process
        (e.g. for the GUI's sign-in screen after a logout)."""
        if self.listener:
            self.listener.stop()
            self.listener = None
        agent, self.agent = self.agent, None
        if agent is not None:
            agent.stop()
            agent.dispatcher.close()
        if self.observer:
            self.observer.stop()
            self.observer = None
        self._integrity_stop.set()
        if self._integrity_thread:
            self._integrity_thread.join(timeout=3)
            self._integrity_thread = None
        self.forwarder.stop()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop_agent()
        if self._dispatcher is not None:
            self._dispatcher.close()
            self._dispatcher = None
        try:
            self.store.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ integrity alerts
    def _dispatch(self):
        if self.agent is not None:
            return self.agent.dispatcher
        if self._dispatcher is None:
            from eldoctor.notify.dispatcher import Dispatcher
            self._dispatcher = Dispatcher(self.cfg, exclude_types=["console"], synchronous=self.role == "direct")
        return self._dispatcher

    def _on_violation(self, ev: Dict[str, Any]) -> None:
        """Tampering is a security incident in its own right: alert + forced notification, not just a log line."""
        from eldoctor.agent import integrity_alert
        alert = integrity_alert(ev)
        try:
            self.store.add_alert(alert)
            if self.agent is not None:
                self.agent.recent_alerts.appendleft(alert)
            self._dispatch().notify(alert.to_dict(), [], force=True)
        except Exception:
            pass

    # ------------------------------------------------------------------ request pipeline
    def _privileged_peer(self, peer: Peer) -> bool:
        return peer.elevated or peer.uid == self.me.uid

    def admit(self, peer: Peer) -> Optional[str]:
        """Connection-level policy on the OS account (None = admitted)."""
        if self._privileged_peer(peer):
            return None
        users = [str(u) for u in self.api_cfg.get("allowed_os_users") or []]
        groups = set(str(g) for g in self.api_cfg.get("allowed_os_groups") or [])
        if not users and not groups:
            return None
        if peer.user in users or peer.uid in users or groups & set(peer.groups):
            return None
        with acting_as(Origin(peer.user, peer.uid, peer.pid, "connect")):
            self._audit_denied(peer, "connect", "os_account_not_allowed")
        return (f"OS account {peer.user} is not allowed to use the El Doctor API (api.allowed_os_users / "
                f"api.allowed_os_groups)")

    def _audit_denied(self, peer: Peer, method: str, reason: str, user: Optional[User] = None, **extra: Any) -> None:
        key = (peer.uid, method, reason, user.username if user else "")
        now = time.time()
        if now - self._denied.get(key, 0) < 30:             # rate-limit identical denials in the audit trail
            return
        self._denied[key] = now
        # runs inside handle()'s acting_as(peer) context, so the record carries the caller's OS identity
        self.store.audit(user.username if user else f"os:{peer.user}", "api_denied",
                         {"method": method, "reason": reason, "role": user.role if user else None, **extra})

    def handle(self, req: Dict[str, Any], peer: Peer) -> Dict[str, Any]:
        rid = req.get("id") if isinstance(req, dict) else None
        try:
            if not isinstance(req, dict) or req.get("v") != 1:
                raise ApiFault("bad_request", "unsupported request (protocol v1 expected)")
            method = METHODS.get(str(req.get("method")))
            if method is None:
                raise ApiFault("not_found", f"unknown method {req.get('method')!r}")
            reason = self.admit(peer)
            if reason:
                raise ApiFault("forbidden", reason)
            params = req.get("params") or {}
            if not isinstance(params, dict):
                raise ApiFault("bad_request", "params must be an object")
            client = re.sub(r"[^a-z0-9_-]", "", str(req.get("client") or "api").lower())[:16] or "api"
            origin = Origin(peer.user, peer.uid, peer.pid, client)
            with acting_as(origin):
                user = None
                if method.auth is True:
                    user = self.authenticate(req.get("auth") or {}, peer, method.name)
                    if method.perm:
                        self.require(user, method.perm, peer, method.name)
                elif method.auth == "optional" and req.get("auth") and self.um.count() > 0:
                    try:                      # e.g. an admin registering someone else; stale session = anonymous
                        user = self.authenticate(req.get("auth") or {}, peer, method.name)
                    except ApiFault:
                        user = None
                result = method.fn(self, params, user, peer)
            return {"v": 1, "id": rid, "ok": True, "result": result}
        except ApiFault as f:
            return {"v": 1, "id": rid, "ok": False, "error": {"code": f.code, "message": str(f), **f.data}}
        except AuthError as exc:
            return {"v": 1, "id": rid, "ok": False, "error": {"code": "auth_failed", "message": str(exc)}}
        except Exception as exc:                       # never leak a traceback to the client, keep one locally
            try:
                self.store.audit("agent", "api_error", {"method": req.get("method") if isinstance(req, dict) else None,
                                                        "error": repr(exc), "trace": traceback.format_exc()[-1500:]})
            except Exception:
                pass
            return {"v": 1, "id": rid, "ok": False,
                    "error": {"code": "internal", "message": f"agent error ({type(exc).__name__}) - details are in "
                                                             f"the agent's audit trail (event api_error)"}}

    def authenticate(self, auth: Dict[str, Any], peer: Peer, method: str = "") -> User:
        if self.um.count() == 0:
            raise ApiFault("not_registered", "El Doctor requires registration before use")
        if not isinstance(auth, dict):
            raise ApiFault("unauthenticated", "not logged in")
        key, tok = auth.get("api_key"), auth.get("token")
        if key:
            user = self.um.user_for_api_key(str(key))
            if not user:
                self._audit_denied(peer, method, "invalid_api_key")
                raise ApiFault("unauthenticated", "invalid API key (or the user is disabled)")
            return user
        if not tok:
            raise ApiFault("unauthenticated", "not logged in")
        try:
            claims = self.tokens.verify(str(tok))
        except TokenError as exc:
            raise ApiFault("unauthenticated", f"{exc} - log in again") from exc
        if str(claims.get("ouid")) != str(peer.uid):
            # a token copied from another OS account: refuse and leave a trace
            with acting_as(Origin(peer.user, peer.uid, peer.pid, "api")):
                self.store.audit(f"os:{peer.user}", "token_peer_mismatch",
                                 {"token_user": claims.get("sub"), "token_os_user": claims.get("osu"),
                                  "method": method})
            raise ApiFault("unauthenticated", "this session belongs to another OS account - log in again")
        if self.store.token_revoked(str(claims["jti"])):
            raise ApiFault("unauthenticated", "session ended (logged out) - log in again")
        user = self.um.get_by_id(int(claims["uid"]))
        if not user or user.username != claims.get("sub"):
            raise ApiFault("unauthenticated", "account not found or its record failed the integrity check")
        if not user.active:
            raise ApiFault("unauthenticated", "account disabled")
        if int(claims.get("tv", -1)) != user.token_version:
            raise ApiFault("unauthenticated", "session revoked (role or account changed) - log in again")
        user._claims = claims                        # type: ignore[attr-defined]
        return user

    def require(self, user: User, perm: str, peer: Optional[Peer] = None, method: str = "") -> None:
        """The RBAC decision. Front ends may hide buttons; only this check counts."""
        if not user.can(perm):
            need = required_role(perm)
            if peer is not None:
                self._audit_denied(peer, method, "permission", user, perm=perm)
            raise ApiFault("forbidden", f"role '{user.role}' lacks '{perm}' (requires '{need}')", perm=perm,
                           required=need, role=user.role)
        groups = [str(g) for g in self.api_cfg.get("admin_os_groups") or []]
        if perm in ADMIN_PERMS and groups and peer is not None and not self._privileged_peer(peer) \
                and not set(groups) & set(peer.groups):
            self._audit_denied(peer, method, "admin_os_group", user, perm=perm)
            raise ApiFault("forbidden", f"'{perm}' also requires OS group membership ({', '.join(groups)}) - "
                                        f"OS account {peer.user} is not a member", perm=perm)

    # ------------------------------------------------------------------ helpers used by methods
    def responder(self):
        if self.agent is not None:
            return self.agent.responder
        if self._responder is None:
            from eldoctor.playbooks.safety import SafetyGuard
            from eldoctor.response.actions import Responder
            self._responder = Responder(self.cfg, self.store, SafetyGuard(self.cfg), dry_run=self.dry_run_default)
        return self._responder

    def engine(self):
        if self.agent is not None:
            return self.agent.engine
        if self._engine is None:
            from eldoctor.detection.engine import DetectionEngine
            self._engine = DetectionEngine(self.cfg)
        return self._engine

    def playbooks(self):
        if self.agent is not None:
            return self.agent.playbooks.playbooks, self.agent.playbooks.errors
        from eldoctor.config import package_data
        from eldoctor.playbooks.engine import load_playbooks
        pc = self.cfg.get("playbooks", {}) or {}
        dirs = [package_data("playbooks")] + [Path(d).expanduser() for d in pc.get("dirs", []) or []]
        return load_playbooks(dirs, pc.get("disabled", []))

    def source(self):
        """What produces metrics/processes: the detection loop, else a light observer."""
        if self.agent is not None:
            return self.agent
        with self._lock:
            if self.observer is None and not self.closed:
                self.observer = LightObserver(float(self.cfg["agent"].get("interval", 2.0)))
            return self.observer

    def status(self) -> Dict[str, Any]:
        if self.agent is not None:
            st = dict(self.agent.status())
            st.update(running=True, error=getattr(self.agent, "error", ""))
        else:
            try:
                me = psutil.Process(os.getpid())
                cpu, mem = me.cpu_percent(None), me.memory_info().rss / 1048576
            except psutil.Error:
                cpu, mem = 0.0, 0.0
            st = {"mode": self.cfg["agent"]["mode"], "dry_run": self.dry_run_default, "ticks": 0,
                  "uptime": time.time() - self.started, "tick_ms": 0.0, "own_cpu": cpu, "own_mem_mb": mem,
                  "breaker": False, "log_sources": [], "sigma_rules": 0, "playbooks": 0, "iocs": 0, "yara": False,
                  "notify_errors": [], "running": False, "error": ""}
        st["server"] = {"pid": os.getpid(), "role": self.role, "host": HOSTNAME, "version": __version__,
                        "endpoint": self.endpoint, "os_user": self.me.user, "privileged": is_privileged()}
        return st


# ======================================================================================== API methods
# ---------------------------------------------------------------------------------------- public
@api("sys.hello", auth=False)
def _hello(svc: AgentService, p, user, peer: Peer):
    return {"product": "El Doctor", "version": __version__, "host": HOSTNAME, "role": svc.role,
            "server_pid": os.getpid(), "registered": svc.um.count() > 0, "agent_running": svc.agent is not None,
            "peer": {"user": peer.user, "uid": peer.uid, "pid": peer.pid, "transport": peer.transport},
            "self_registration": bool((svc.cfg.get("registration") or {}).get("self_service", True)),
            "webhook_consent": bool((svc.cfg.get("registration") or {}).get("webhook_url"))}


@api("auth.register", auth="optional")
def _register(svc: AgentService, p, user, peer: Peer):
    creator = user                    # an authenticated admin may create accounts with a role
    first = svc.um.count() == 0
    if first and not svc._privileged_peer(peer):
        # the first account is the administrator: only the OS account that runs the agent (or root/SYSTEM)
        # may create it - otherwise any local user could race to own a freshly installed service
        raise ApiFault("forbidden", f"the first (administrator) account must be registered by the OS account that "
                                    f"runs the agent ({svc.me.user}) or by an OS administrator")
    if not first and creator is None and not (svc.cfg.get("registration") or {}).get("self_service", True):
        raise ApiFault("forbidden", "self-registration is disabled (registration.self_service: false); ask an admin")
    role = p.get("role")
    if role is not None and role not in ROLES:
        raise ApiFault("bad_request", f"role must be one of {ROLES}")
    new, key = svc.um.register(_str(p, "username", max_len=64), _str(p, "password", max_len=1024),
                               _str(p, "email", max_len=254), _str(p, "full_name", False, 128),
                               _str(p, "organization", False, 128), _str(p, "use_case", False, 32) or "other",
                               _str(p, "deployment_target", False, 32) or "linux", role=role, created_by=creator,
                               consent_share=bool(p.get("consent_share")))
    return {"user": new.public(), "api_key": key}


@api("auth.login", auth=False)
def _login(svc: AgentService, p, user, peer: Peer):
    if svc.um.count() == 0:
        raise ApiFault("not_registered", "El Doctor requires registration before use")
    u = svc.um.authenticate(_str(p, "username", max_len=64), _str(p, "password", max_len=1024))
    tok = svc.tokens.issue(u, peer.uid, peer.user)
    svc.store.audit(u.username, "session_issued", {"jti": tok["claims"]["jti"], "exp": tok["claims"]["exp"],
                                                   "bound_os_user": peer.user})
    return {"token": tok["token"], "expires": tok["claims"]["exp"], "user": u.public()}


# ---------------------------------------------------------------------------------------- session
@api("auth.whoami")
def _whoami(svc: AgentService, p, user: User, peer: Peer):
    claims = getattr(user, "_claims", {}) or {}
    return {"user": user.public(), "peer": peer.to_dict(), "session_expires": claims.get("exp"),
            "auth": "token" if claims else "api_key", "server": svc.status()["server"]}


@api("auth.logout")
def _logout(svc: AgentService, p, user: User, peer: Peer):
    claims = getattr(user, "_claims", None)
    if claims:
        svc.store.revoke_token(str(claims["jti"]), float(claims["exp"]))
    svc.store.audit(user.username, "logout", {"jti": claims.get("jti") if claims else None})
    return {"ok": True}


@api("auth.logout_all")
def _logout_all(svc: AgentService, p, user: User, peer: Peer):
    svc.um.logout_everywhere(user)
    return {"ok": True}


@api("auth.rotate_api_key")
def _rotate_key(svc: AgentService, p, user: User, peer: Peer):
    return {"api_key": svc.um.rotate_api_key(user)}


@api("auth.change_password")
def _change_password(svc: AgentService, p, user: User, peer: Peer):
    svc.um.change_password(user, _str(p, "old", max_len=1024), _str(p, "new", max_len=1024))
    return {"ok": True, "note": "password changed - every session was ended, log in again"}


@api("auth.recover", auth=False)
def _recover(svc: AgentService, p, user, peer: Peer):
    """Forgotten admin password: reset by the OS account that runs the agent, or root / an elevated administrator,
    without logging in (they can read the data folder anyway).  Anyone else is refused and audited."""
    if not svc._privileged_peer(peer):
        svc._audit_denied(peer, "auth.recover", "not_agent_os_account")
        raise ApiFault("forbidden", f"account recovery must be run as root/Administrator or as the OS account that "
                                    f"runs the El Doctor agent (you are {peer.user})")
    if svc.um.count() == 0:
        raise ApiFault("not_registered", "nobody is registered yet - register instead")
    username = _str(p, "username", False, 64) or svc.um.first_admin() or ""
    u = svc.um.recover(username, _str(p, "password", max_len=1024), f"{peer.user} (uid {peer.uid})")
    return {"username": u.username, "role": u.role}


@api("auth.check_password", auth=False)
def _check_password(svc: AgentService, p, user, peer: Peer):
    return {"problems": password_problems(_str(p, "password", False, 1024), _str(p, "username", False, 64))}


# ---------------------------------------------------------------------------------------- users (admin)
@api("users.list", "view")
def _users_list(svc: AgentService, p, user: User, peer: Peer):
    rows = svc.um.list()
    if not user.can("manage_users"):                 # least privilege: others' e-mail addresses are PII
        rows = [r for r in rows if r["username"] == user.username]
    return rows


@api("users.add", "manage_users")
def _users_add(svc: AgentService, p, user: User, peer: Peer):
    role = p.get("role") or "analyst"
    if role not in ROLES:
        raise ApiFault("bad_request", f"role must be one of {ROLES}")
    new, key = svc.um.register(_str(p, "username", max_len=64), _str(p, "password", max_len=1024),
                               _str(p, "email", max_len=254), _str(p, "full_name", False, 128),
                               _str(p, "organization", False, 128), _str(p, "use_case", False, 32) or "soc",
                               _str(p, "deployment_target", False, 32) or "linux", role=role, created_by=user)
    return {"user": new.public(), "api_key": key}


@api("users.reset_password", "manage_users")
def _users_reset_password(svc: AgentService, p, user: User, peer: Peer):
    svc.um.reset_password(user, _str(p, "username", max_len=64), _str(p, "password", max_len=1024))
    return {"ok": True}


@api("users.set_role", "manage_users")
def _users_set_role(svc: AgentService, p, user: User, peer: Peer):
    svc.um.set_role(user, _str(p, "username", max_len=64), _str(p, "role", max_len=16))
    return {"ok": True}


@api("users.set_active", "manage_users")
def _users_set_active(svc: AgentService, p, user: User, peer: Peer):
    svc.um.set_active(user, _str(p, "username", max_len=64), bool(p.get("active")))
    return {"ok": True}


@api("service.rotate_key", "manage_users")
def _service_key(svc: AgentService, p, user: User, peer: Peer):
    svc_user, path = create_service_key(svc.um, user)
    return {"service_user": svc_user.username, "key_file": str(path)}


def create_service_key(um: UserManager, admin: User):
    """Service identity (admin role) whose API key lives in the locked data folder, for the unattended agent."""
    import secrets
    name = "svc-" + "".join(ch for ch in socket.gethostname().lower() if ch.isalnum() or ch in "-_")[:24]
    name = name if len(name) > 4 else "svc-eldoctor"
    svc_user = um.get(name)
    if not svc_user:
        svc_user, _ = um.register(name, secrets.token_urlsafe(24) + "aA1!", admin.email, "El Doctor service account",
                                  admin.organization, admin.use_case or "other", admin.deployment_target or "linux",
                                  role="admin", created_by=admin)
    key = um.rotate_api_key(svc_user)
    kf = home_dir() / "service.key"
    fd = os.open(str(kf), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key)
    if not IS_WINDOWS:
        os.chmod(kf, 0o600)
    um.store.audit(admin.username, "service_key_rotated", {"service_user": svc_user.username})
    return svc_user, kf


# ---------------------------------------------------------------------------------------- agent state
@api("agent.status", "view")
def _agent_status(svc: AgentService, p, user: User, peer: Peer):
    return svc.status()


@api("agent.info", "view")
def _agent_info(svc: AgentService, p, user: User, peer: Peer):
    chans = (svc.cfg.get("notifications", {}) or {}).get("channels", []) or []
    return {"data_dir": str(home_dir()), "config_path": svc.cfg.get("_path") or str(user_config_path()),
            "privileged": is_privileged(), "role": svc.role, "endpoint": svc.endpoint, "version": __version__,
            "channels": [c.get("name") or c["type"] for c in chans if c.get("enabled", True)],
            "audit_forwarding": svc.forwarder.status(), "host": HOSTNAME,
            "audit_genesis": _genesis(svc)}


def _genesis(svc: AgentService) -> str:
    from eldoctor.integrity import fingerprint
    g = svc.store.meta_get("audit_genesis") or {}
    return fingerprint(g.get("pub", "")) if g else ""


@api("agent.snapshot", "view")
def _agent_snapshot(svc: AgentService, p, user: User, peer: Peer):
    src = svc.source()
    n_alerts = _int(p.get("alerts"), 50, 0, 500)
    n_actions = _int(p.get("actions"), 50, 0, 500)
    with src.lock:
        procs = list(src.latest_procs)
        metrics = dict(src.latest_metrics or {})
    if p.get("processes") != "all":
        procs = procs[:_int(p.get("processes"), 30, 0, 5000)]
    if svc.agent is not None:
        alerts = [a.to_dict() for a in list(svc.agent.recent_alerts)[:n_alerts]]
        actions = list(svc.agent.recent_actions)[:n_actions]
    else:
        alerts = [json.loads(r["data"]) for r in svc.store.list_alerts(n_alerts)]
        actions = [{"action": a["action"], "status": a["status"], "message": a["message"], "target": a["target"],
                    "timestamp": a["ts"], "playbook": a["playbook_id"], "mode": a["mode"]}
                   for a in svc.store.list_actions(n_actions)]
    return {"status": svc.status(), "metrics": metrics, "processes": [_proc_row(x) for x in procs],
            "alerts": alerts, "actions": actions,
            "approvals": [_approval_row(a) for a in svc.store.list_approvals("pending", limit=50)],
            "user": user.public()}


@api("agent.start", "run")
def _agent_start(svc: AgentService, p, user: User, peer: Peer):
    if svc.role != "embedded":
        if svc.agent is not None:
            return {"started": False, "mode": svc.agent.mode, "message": "the agent is already running"}
        raise ApiFault("unavailable", "detection can only be started by the process hosting the agent")
    mode = p.get("mode") or svc.cfg["agent"]["mode"]
    if mode not in MODES:
        raise ApiFault("bad_request", f"mode must be one of {MODES}")
    note = ""
    if mode == "enforce" and not user.can("enforce"):
        mode, note = "interactive", "enforce mode requires the admin role - using interactive"
    already = svc.agent is not None
    agent = svc.start_agent(user, mode, bool(p.get("dry_run")) or None, headless=bool(p.get("headless", False)))
    if not already:
        svc.store.audit(user.username, "detection_started", {"mode": agent.mode, "dry_run": agent.responder.dry_run})
    return {"started": not already, "mode": agent.mode, "message": note}


@api("agent.shutdown", auth=False)
def _agent_shutdown(svc: AgentService, p, user, peer: Peer):
    """Clean stop for installers and upgrades (the agent records a clean shutdown).  Only the agent's own OS account
    or root / an elevated administrator - the same people who can stop the service from the OS anyway."""
    if not svc._privileged_peer(peer):
        svc._audit_denied(peer, "agent.shutdown", "not_agent_os_account")
        raise ApiFault("forbidden", "only root/Administrator or the agent's OS account can stop the agent")
    if svc.agent is None:
        raise ApiFault("unavailable", "no detection loop is running in this process")
    svc.store.audit(f"os:{peer.user}", "agent_shutdown_requested", {"by_os_account": peer.user, "uid": peer.uid})
    svc.agent._stop.set()
    return {"stopping": True}


@api("agent.set_mode", "run")
def _agent_set_mode(svc: AgentService, p, user: User, peer: Peer):
    mode = _str(p, "mode", max_len=16)
    if mode not in MODES:
        raise ApiFault("bad_request", f"mode must be one of {MODES}")
    if mode == "enforce":
        svc.require(user, "enforce", peer, "agent.set_mode")
    if svc.agent is None:
        raise ApiFault("unavailable", "detection & response is not running")
    prev = svc.agent.mode
    svc.agent.playbooks.set_mode(mode)
    svc.store.audit(user.username, "mode_changed", {"mode": mode, "previous": prev})
    return {"mode": mode, "previous": prev}


# ---------------------------------------------------------------------------------------- records
@api("alerts.list", "view")
def _alerts_list(svc: AgentService, p, user: User, peer: Peer):
    limit = _int(p.get("limit"), 50, 1, 5000)
    after = p.get("after")
    if after is not None:
        rows = svc.store.query("SELECT * FROM alerts WHERE ts > ? ORDER BY ts LIMIT ?", (float(after), limit))
    else:
        rows = svc.store.list_alerts(limit, float(p.get("since") or 0))
    out = []
    for r in rows:                    # every alert is checked against the digest the agent signed into the chain
        a = json.loads(r["data"])
        a["_integrity"] = svc.store.ledger_state("alert", r)
        out.append(a)
    minsev = p.get("min_severity")
    if minsev:
        out = [a for a in out if severity_rank(a.get("severity", "")) >= severity_rank(minsev)]
    if p.get("include_actions"):                 # one round-trip for the dashboard / banner
        for a in out:
            a["_actions"] = [{"action": x["action"], "status": x["status"]}
                             for x in svc.store.list_actions(alert_id=a["id"])]
    return out


@api("alerts.get", "view")
def _alerts_get(svc: AgentService, p, user: User, peer: Peer):
    r = svc.store.get_alert(_str(p, "id", max_len=64))
    if not r:
        raise ApiFault("not_found", "no such alert")
    return {"alert": json.loads(r["data"]), "integrity": svc.store.ledger_state("alert", r),
            "actions": _with_integrity(svc, svc.store.list_actions(alert_id=r["id"]))}


def _with_integrity(svc: AgentService, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for r in rows:
        r["integrity"] = svc.store.ledger_state("action", r)
    return rows


@api("actions.list", "view")
def _actions_list(svc: AgentService, p, user: User, peer: Peer):
    if p.get("alert_id"):
        return _with_integrity(svc, svc.store.list_actions(alert_id=_str(p, "alert_id", max_len=64)))
    return _with_integrity(svc, svc.store.list_actions(_int(p.get("limit"), 50, 1, 5000)))


@api("stats.dashboard", "view")
def _dashboard(svc: AgentService, p, user: User, peer: Peer):
    since = time.time() - 86400
    st = svc.store
    counts = {r["severity"]: r["n"] for r in st.query(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE ts >= ? GROUP BY severity", (since,))}
    n_actions = st.query("SELECT COUNT(*) AS n FROM actions WHERE ts >= ? AND status='success' AND action IN "
                         "('kill','suspend','quarantine','block_ip','renice')", (since,))[0]["n"]
    return {"severity_24h": counts, "containment_24h": n_actions, "pending_approvals": len(st.list_approvals("pending")),
            "blocked_ips": len(st.active_blocks()),
            "quarantined": sum(1 for x in st.list_quarantine() if not x["restored"])}


# ---------------------------------------------------------------------------------------- approvals
@api("approvals.list", "view")
def _approvals_list(svc: AgentService, p, user: User, peer: Peer):
    status = p.get("status")
    if status not in (None, "pending", "approved", "denied", "expired", "rejected"):
        raise ApiFault("bad_request", "invalid status filter")
    return [_approval_row(a) for a in svc.store.list_approvals(status, _int(p.get("limit"), 100, 1, 2000))]


@api("approvals.decide", "approve")
def _approvals_decide(svc: AgentService, p, user: User, peer: Peer):
    aid = _str(p, "id", max_len=32)
    decision = _str(p, "decision", max_len=8)
    if decision not in ("approve", "deny"):
        raise ApiFault("bad_request", "decision must be 'approve' or 'deny'")
    if not svc.store.decide_approval(aid, decision == "approve", user.username):
        raise ApiFault("conflict", f"approval {aid} not found, already decided, expired or not created by the agent")
    return {"id": aid, "status": "approved" if decision == "approve" else "denied", "decided_by": user.username}


# ---------------------------------------------------------------------------------------- response
@api("respond.process", "respond")
def _respond_process(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.agent import manual_response
    from eldoctor.collectors.processes import process_info_from_pid
    action = _str(p, "action", max_len=16)
    if action not in MANUAL_ACTIONS:
        raise ApiFault("bad_request", f"action must be one of {sorted(MANUAL_ACTIONS)}")
    pid = _int(p.get("pid"), -1, -1, 2 ** 31)
    if pid <= 0:
        raise ApiFault("bad_request", "invalid pid")
    # the agent resolves the process itself: executable path, owner etc. are never taken from the client
    proc = process_info_from_pid(pid)
    if proc is None:
        raise ApiFault("not_found", f"process {pid} does not exist (any more)")
    ct = p.get("create_time")
    if ct and abs(proc.create_time - float(ct)) > 0.05:
        raise ApiFault("conflict", f"pid {pid} now belongs to a different process (PID reuse) - refresh and retry")
    res = manual_response(svc.responder(), svc.store, action, proc, user)
    if svc.agent is not None:
        svc.agent.recent_actions.appendleft(dict(res.to_dict(), playbook="manual", mode="manual"))
    return res.to_dict()


@api("respond.block_ip", "respond")
def _respond_block(svc: AgentService, p, user: User, peer: Peer):
    ip = _str(p, "ip", max_len=64)
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ApiFault("bad_request", f"invalid IP address {ip!r}") from exc
    alert_id = _str(p, "alert_id", False, 64)
    res = svc.responder().block_ip(ip, alert_id, reason=_str(p, "reason", False, 256) or "manual block",
                                   automated=False)
    svc.store.add_action(res, alert_id, "manual", "manual", user.username)
    svc.store.audit(user.username, "manual_block_ip", res.to_dict())
    return res.to_dict()


@api("blocks.list", "view")
def _blocks_list(svc: AgentService, p, user: User, peer: Peer):
    return svc.store.active_blocks()


@api("blocks.unblock", "unblock")
def _blocks_unblock(svc: AgentService, p, user: User, peer: Peer):
    res = svc.responder().unblock_ip(_str(p, "ip", max_len=64))
    svc.store.audit(user.username, "unblock_ip", res.to_dict())
    return res.to_dict()


@api("quarantine.list", "view")
def _quarantine_list(svc: AgentService, p, user: User, peer: Peer):
    return svc.store.list_quarantine()


@api("quarantine.restore", "restore")
def _quarantine_restore(svc: AgentService, p, user: User, peer: Peer):
    res = svc.responder().restore(_str(p, "id", max_len=64))
    svc.store.audit(user.username, "quarantine_restore", res.to_dict())
    return res.to_dict()


# ---------------------------------------------------------------------------------------- intel, rules, playbooks
@api("intel.status", "view")
def _intel_status(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.detection.ioc import feed_status
    eng = svc.engine()
    return {"summary": eng.iocs.summary(), "feeds": feed_status(), "yara": eng.yara.enabled,
            "rules": len(eng.catalogue())}


@api("intel.update", "intel")
def _intel_update(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.detection.ioc import IOCStore, update_feeds
    only = p.get("feeds") or None
    if only is not None and not (isinstance(only, list) and all(isinstance(x, str) for x in only)):
        raise ApiFault("bad_request", "feeds must be a list of feed names")
    res = update_feeds(svc.cfg, only=only)
    if any(r["ok"] for r in res):
        svc.engine().iocs = IOCStore.from_config(svc.cfg)
    svc.store.audit(user.username, "intel_update", res)
    return res


@api("intel.add", "intel")
def _intel_add(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.detection.ioc import Indicator, add_local_ioc
    t, v = _str(p, "type", max_len=16), _str(p, "value", max_len=512).strip()
    sev = _str(p, "severity", False, 16) or "high"
    if t not in IOC_TYPES:
        raise ApiFault("bad_request", f"type must be one of {sorted(IOC_TYPES)}")
    if sev not in ("low", "medium", "high", "critical"):
        raise ApiFault("bad_request", "severity must be low|medium|high|critical")
    desc, mitre = _str(p, "description", False, 256), _str(p, "mitre", False, 128)
    try:
        path = add_local_ioc(t, v, sev, desc, mitre)
    except ValueError as exc:
        raise ApiFault("bad_request", str(exc)) from exc
    live = False
    if svc.agent is not None:
        svc.agent.engine.iocs.add(Indicator(t, v, sev, desc, source="local"))
        live = True
    svc.store.audit(user.username, "ioc_added", {"type": t, "value": v, "severity": sev})
    return {"path": str(path), "live": live}


@api("rules.list", "view")
def _rules_list(svc: AgentService, p, user: User, peer: Peer):
    eng = svc.engine()
    return {"rules": eng.catalogue(), "sigma": len(eng.sigma_rules),
            "sigma_errors": [list(e) for e in eng.sigma_errors[:50]],
            "yara": f"{eng.yara.rule_count} rule files" if eng.yara.enabled else eng.yara.error}


@api("playbooks.list", "view")
def _playbooks_list(svc: AgentService, p, user: User, peer: Peer):
    pbs, errors = svc.playbooks()
    return {"playbooks": [{"prio": pb.priority, "id": pb.id, "enabled": pb.enabled, "max_mode": pb.max_mode,
                           "steps": [s.action + ("(auto)" if s.auto else "") for s in pb.steps], "name": pb.name}
                          for pb in pbs], "errors": errors}


@api("playbooks.show", "view")
def _playbooks_show(svc: AgentService, p, user: User, peer: Peer):
    pid = _str(p, "id", max_len=128)
    for pb in svc.playbooks()[0]:
        if pb.id == pid:
            return {"id": pb.id, "path": pb.path, "text": Path(pb.path).read_text(encoding="utf-8")}
    raise ApiFault("not_found", "no such playbook")


# ---------------------------------------------------------------------------------------- scan, notify, deploy, config
@api("scan.run", "view")
def _scan(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.agent import Agent
    from eldoctor.collectors.processes import ProcessCollector, connections
    from eldoctor.detection.engine import DetectionEngine
    respond = bool(p.get("respond"))
    mode = p.get("mode") or svc.cfg["agent"]["mode"]
    if mode not in MODES:
        raise ApiFault("bad_request", f"mode must be one of {MODES}")
    if respond:
        svc.require(user, "run", peer, "scan.run")
        if mode == "enforce":
            svc.require(user, "enforce", peer, "scan.run")
    eng = DetectionEngine(svc.cfg)
    col = ProcessCollector()
    procs, new = col.snapshot()
    time.sleep(1.0)
    procs, _ = col.snapshot()
    alerts: List[Alert] = []
    for pr in new:
        alerts += eng.on_process_start(pr, initial=True)
    alerts += eng.on_connections(connections(), {x.pid: x for x in procs})
    out = {"processes": len(new), "sigma_rules": len(eng.sigma_rules), "iocs": len(eng.iocs), "yara": eng.yara.enabled,
           "findings": [{"short": a.short(), "alert": a.to_dict()} for a in alerts], "runs": []}
    if respond and alerts:
        agent = Agent(svc.cfg, svc.store, user, mode=mode, dry_run=True if p.get("dry_run") else None, headless=True,
                      users=svc.um)
        try:
            for a in alerts:
                svc.store.add_alert(a)
                for run in agent.playbooks.handle(a):
                    out["runs"].append({"playbook": run["playbook"], "results": run["results"]})
        finally:
            agent.dispatcher.close()
    svc.store.audit(user.username, "scan", {"findings": len(alerts), "respond": respond, "mode": mode})
    return out


@api("notify.test", "notify_test")
def _notify_test(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.notify.dispatcher import Dispatcher
    d = Dispatcher(svc.cfg, synchronous=True, exclude_types=None if p.get("console") else ["console"])
    alert = Alert(rule_id="ED-TEST-000", title="El Doctor notification test", severity="high", source="test",
                  mitre=["T1496"], description=f"Test message sent by {user.username}")
    ch = p.get("channel")
    d.notify(alert.to_dict(), [], channels=[str(ch)] if ch else None, force=True)
    svc.store.audit(user.username, "notify_test", {"channel": ch, "sent": d.sent, "errors": list(d.errors)})
    return {"channels": [{"name": c.name, "sent": d.sent.get(c.name, 0)} for c in d.channels], "errors": list(d.errors)}


@api("deploy.record", "deploy")
def _deploy_record(svc: AgentService, p, user: User, peer: Peer):
    """Authorise + audit a deployment bundle; the front end writes the files into *its own* folder (the agent
    never writes to client-chosen paths as the service account)."""
    target = _str(p, "target", max_len=32)
    if target not in DEPLOY_TARGETS:
        raise ApiFault("bad_request", f"target must be one of {list(DEPLOY_TARGETS)}")
    mode = p.get("mode")
    if mode is not None and mode not in MODES:
        raise ApiFault("bad_request", f"mode must be one of {MODES}")
    svc.store.audit(user.username, "deploy_generated", {"target": target, "mode": mode,
                                                        "out": _str(p, "out", False, 1024)})
    return {"profile": {"username": user.username, "email": user.email, "full_name": user.full_name,
                        "organization": user.organization, "use_case": user.use_case}}


@api("config.get", "config")
def _config_get(svc: AgentService, p, user: User, peer: Peer):
    return _redact(svc.cfg)


# ---------------------------------------------------------------------------------------- user activity (forensics)
ACTIVITY_CATEGORIES = {"session", "process", "file", "system", "incident"}


def _activity_filters(p: Dict[str, Any]) -> Dict[str, Any]:
    def num(key: str) -> float:
        v = p.get(key)
        if v in (None, ""):
            return 0.0
        try:
            return float(v)
        except (TypeError, ValueError):
            raise ApiFault("bad_request", f"{key} must be a number (epoch seconds)") from None
    cat = _str(p, "category", False, 64)
    if cat and not set(cat.split(",")) <= ACTIVITY_CATEGORIES:
        raise ApiFault("bad_request", f"category must be in {sorted(ACTIVITY_CATEGORIES)}")
    return {"since": num("since"), "until": num("until"), "user": _str(p, "user", False, 128),
            "kind": _str(p, "kind", False, 256), "category": cat, "path": _str(p, "path", False, 4096),
            "text": _str(p, "q", False, 512), "pid": _int(p.get("pid"), 0, 0, 2 ** 31),
            "before_id": _int(p.get("before_id"), 0, 0, 2 ** 62), "after_id": _int(p.get("after_id"), 0, 0, 2 ** 62)}


@api("activity.list", "forensics")
def _activity_list(svc: AgentService, p, user: User, peer: Peer):
    """Timeline of sessions, applications, file activity, boots and incidents (newest first, or oldest first with
    order=asc - used for paging exports with after_id)."""
    f = _activity_filters(p)
    rows = svc.store.list_activity(limit=_int(p.get("limit"), 200, 1, 5000), ascending=p.get("order") == "asc", **f)
    if p.get("export") and not f["after_id"]:
        svc.store.audit(user.username, "activity_exported", {"filters": {k: v for k, v in f.items() if v},
                                                             "format": _str(p, "format", False, 16)})
    return rows


def _running_apps(all_accounts: bool = False) -> List[Dict[str, Any]]:
    from eldoctor.activity.sessions import is_human
    from eldoctor.collectors.processes import ProcessCollector
    procs, _ = ProcessCollector(hash_executables=False).snapshot()
    out = []
    for x in procs:
        if not (all_accounts or is_human(x.username)) or (x.ppid == 2 and not x.exe):
            continue
        try:
            term = psutil.Process(x.pid).terminal() or ""
        except (psutil.Error, OSError, AttributeError):
            term = ""
        out.append({"pid": x.pid, "ppid": x.ppid, "name": x.name, "exe": x.exe, "cmdline": x.cmdline_str[:500],
                    "user": x.username, "started": x.create_time, "terminal": term, "parent": x.parent_name,
                    "memory_percent": round(x.memory_percent, 2)})
    return sorted(out, key=lambda r: r["started"])


@api("activity.now", "forensics")
def _activity_now(svc: AgentService, p, user: User, peer: Peer):
    """Who is logged in right now and which applications each person is running."""
    from eldoctor.activity.sessions import read_sessions
    mon = getattr(svc.agent, "activity", None)
    sessions = mon.current_sessions() if mon is not None and mon.started else read_sessions()
    apps = _running_apps(bool(p.get("all")))
    users: Dict[str, Dict[str, Any]] = {}
    for s in sessions:
        users.setdefault(s["user"], {"user": s["user"], "sessions": [], "apps": []})["sessions"].append(s)
    for a in apps:
        users.setdefault(a["user"], {"user": a["user"], "sessions": [], "apps": []})["apps"].append(a)
    return {"host": HOSTNAME, "time": time.time(), "boot_time": psutil.boot_time(), "sessions": sessions,
            "logged_in": sorted({s["user"] for s in sessions}),
            "users": sorted(users.values(), key=lambda u: (not u["sessions"], u["user"]))}


@api("activity.sessions", "forensics")
def _activity_sessions(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.activity.sessions import read_sessions
    mon = getattr(svc.agent, "activity", None)
    current = mon.current_sessions() if mon is not None and mon.started else read_sessions()
    hist = svc.store.list_activity(limit=_int(p.get("limit"), 100, 1, 5000), category="session",
                                   user=_str(p, "user", False, 128))
    return {"current": current, "history": hist}


@api("activity.status", "forensics")
def _activity_status(svc: AgentService, p, user: User, peer: Peer):
    mon = getattr(svc.agent, "activity", None)
    if mon is not None and mon.started:
        st = mon.status()
    else:
        st = {"enabled": bool((svc.cfg.get("activity") or {}).get("enabled", True)), "started": False,
              "note": "the detection loop (which records activity) is not running in this process",
              "index": svc.store.file_index_stats()}
    st["state"] = svc.store.meta_get("activity_state") or {}
    st["state"].pop("sessions", None)
    counts = {r["status"]: r["n"] for r in svc.store.query("SELECT status, COUNT(*) AS n FROM outbox GROUP BY status")}
    st["outbox"] = counts
    st["total_records"] = svc.store.query("SELECT COUNT(*) AS n FROM activity")[0]["n"]
    return st


@api("activity.reports", "forensics")
def _activity_reports(svc: AgentService, p, user: User, peer: Peer):
    return svc.store.outbox_list(_int(p.get("limit"), 50, 1, 1000))


@api("activity.reports_retry", "notify_test")
def _activity_reports_retry(svc: AgentService, p, user: User, peer: Peer):
    from eldoctor.activity.report import AdminReporter
    mon = getattr(svc.agent, "activity", None)
    rep = mon.reporter if mon is not None else AdminReporter(svc.cfg, svc.store)
    res = rep.deliver(force=True)
    svc.store.audit(user.username, "admin_reports_retried", {"results": res})
    return {"results": res, "smtp_configured": rep.smtp() is not None, "recipients": len(rep.recipients())}


# ---------------------------------------------------------------------------------------- audit (admin)
@api("audit.list", "audit")
def _audit_list(svc: AgentService, p, user: User, peer: Peer):
    return svc.store.list_audit(_int(p.get("limit"), 100, 1, 10000), include_bookkeeping=bool(p.get("all")))


@api("audit.verify", "audit")
def _audit_verify(svc: AgentService, p, user: User, peer: Peer):
    res = svc.verify_audit()
    res["forwarding"] = svc.forwarder.status()
    svc.store.audit(user.username, "audit_verified", {"ok": res["ok"], "checked": res["checked"],
                                                      "problems": len(res["problems"])})
    return res


# metadata for front ends: which permission each method needs (they may grey out controls with it)
@api("sys.methods", auth=False)
def _methods(svc: AgentService, p, user, peer: Peer):
    return {m.name: {"perm": m.perm, "auth": m.auth} for m in METHODS.values()}


__all__ = ["AgentService", "ApiFault", "METHODS", "create_service_key", "USE_CASES"]
