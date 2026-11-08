"""The agent's link to an El Doctor Hub: enrollment, check-ins, remote response, fleet threat intel.

`eldoctor enroll <TOKEN>` (administrator / root) once per computer:
  1. the token names the hub and the SHA-256 fingerprint of its CA; the CA certificate is downloaded and must match
     (no trust on first use: a different CA = interception, refused);
  2. the agent creates its own key (never leaves the machine) and sends a certificate request with the one-time
     secret; the hub answers with a client certificate (CN = the agent id it chose);
  3. <data>/hub/: ca.crt, agent.crt, agent.key (0600), link.json.

The running agent then checks in every `checkin_interval` seconds (mutual TLS, the pinned CA only):
  * sends health, logged-in users, the head of its tamper-evident audit trail, new alerts (at-least-once: a cursor
    advances only after the hub confirms), results of earlier commands (kept until delivered, across restarts);
  * receives response commands - each runs once (executed ids are remembered), only if allowed here
    (`hub.allow_commands`), through the same safety guards as a local analyst, and is recorded in the local audit
    trail with the hub analyst's name - and threat-intel updates (written to <data>/intel/hub_iocs.csv, loaded live).
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import platform
import random
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from eldoctor import __version__
from eldoctor.config import subdir
from eldoctor.fleet import pki
from eldoctor.models import HOSTNAME

log = logging.getLogger("eldoctor")
DEFAULT_ALLOWED = ["ping", "forensics", "suspend", "resume", "kill", "kill_tree", "quarantine", "block_ip",
                   "unblock_ip", "set_mode"]
PROC_ACTIONS = {"forensics", "suspend", "resume", "kill", "kill_tree", "quarantine"}


class LinkError(Exception):
    pass


def hub_dir() -> Path:
    return subdir("hub")


def link_info() -> Optional[Dict[str, Any]]:
    p = hub_dir() / "link.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)


def _conn(url: str, ctx: ssl.SSLContext, timeout: float = 20) -> http.client.HTTPSConnection:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise LinkError(f"the hub URL must be https://...: {url}")
    return http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)


def _request(conn: http.client.HTTPSConnection, method: str, path: str, body: Optional[Dict[str, Any]] = None
             ) -> Any:
    data = json.dumps(body, default=str).encode() if body is not None else None
    try:
        conn.request(method, path, body=data, headers={"Content-Type": "application/json",
                                                       "User-Agent": f"ElDoctor/{__version__}"})
        r = conn.getresponse()
        raw = r.read()
    except ssl.SSLCertVerificationError as exc:
        raise LinkError(f"the hub's certificate is not trusted: {exc.verify_message}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise LinkError(f"cannot reach the hub: {exc}") from exc
    finally:
        conn.close()
    if r.status != 200:
        try:
            msg = json.loads(raw).get("error", "")
        except ValueError:
            msg = raw[:200].decode("utf-8", "replace")
        raise LinkError(f"hub answered {r.status}: {msg}")
    return raw if path == "/v1/ca" else json.loads(raw)


# --------------------------------------------------------------------------- enrollment
def enroll(token: str) -> Dict[str, Any]:
    t = pki.parse_token(token)
    # 1. the CA, checked against the fingerprint the token carries (the only unverified connection, and only for
    #    a public certificate that must match that fingerprint)
    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    ca_pem = _request(_conn(t["url"], loose), "GET", "/v1/ca")
    try:
        ca = pki.load_cert(ca_pem)
    except ValueError as exc:
        raise LinkError("the hub did not send a certificate authority") from exc
    if pki.fingerprint(ca) != t["ca_fingerprint"]:
        raise LinkError("the hub's certificate authority does not match the token - possible interception; enrollment "
                        "refused")
    hd = hub_dir()
    (hd / "ca.crt").write_bytes(ca_pem)
    # 2. our own key, a certificate request, the one-time secret - over TLS verified with the pinned CA
    key = pki.new_key()
    ctx = ssl.create_default_context(cafile=str(hd / "ca.crt"))
    res = _request(_conn(t["url"], ctx), "POST", "/v1/enroll",
                   {"secret": t["secret"], "csr": pki.make_csr(key, HOSTNAME).decode(), "hostname": HOSTNAME,
                    "os": f"{platform.system()} {platform.release()}", "version": __version__})
    cert = pki.load_cert(res["cert_pem"].encode())
    if pki.agent_id_of(cert) != res["agent_id"]:
        raise LinkError("the hub returned a certificate for another identity")
    _write_private(hd / "agent.key", pki.key_pem(key))
    (hd / "agent.crt").write_bytes(res["cert_pem"].encode())
    info = {"url": t["url"], "agent_id": res["agent_id"], "ca_fingerprint": t["ca_fingerprint"],
            "enrolled": time.time(), "checkin_interval": res.get("checkin_interval", 15)}
    _write_private(hd / "link.json", json.dumps(info, indent=2).encode())
    return info


def unenroll() -> bool:
    hd = hub_dir()
    found = False
    for n in ("link.json", "agent.key", "agent.crt", "ca.crt"):
        p = hd / n
        if p.exists():
            p.unlink()
            found = True
    return found


class HubPrincipal:
    """The identity a remote command runs under locally: 'hub:<analyst>' - may respond, nothing else."""

    def __init__(self, analyst: str) -> None:
        self.username = f"hub:{analyst}"[:64]
        self.role = "analyst"
        self.active = True

    def can(self, perm: str) -> bool:
        return perm == "respond"


# --------------------------------------------------------------------------- the link inside the running agent
class HubLink:
    def __init__(self, agent) -> None:
        self.agent = agent
        hc = (agent.cfg.get("hub") or {})
        self.enabled = bool(hc.get("enabled", True))
        self.allowed = set(hc.get("allow_commands") or DEFAULT_ALLOWED)
        self.allow_enforce = bool(hc.get("allow_remote_enforce", False))
        self.state: Dict[str, Any] = {"enrolled": False, "last_ok": 0.0, "last_error": "", "url": ""}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.interval = 15.0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if not self.enabled or self._thread:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="eldoctor-hub-link")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        backoff = 0.0
        while not self._stop.is_set():
            info = link_info()
            self.state["enrolled"] = bool(info)
            if not info:
                self._stop.wait(30)                  # `eldoctor enroll` takes effect without a restart
                continue
            try:
                res = self.checkin_once(info)
                backoff = 0.0
                # commands just ran: report their results right away (analysts are waiting), then the usual pace
                wait = 1.0 if res.get("commands") else self.interval
            except Exception as exc:                 # the hub being away must never disturb detection
                self.state["last_error"] = f"{time.strftime('%H:%M:%S')} {exc}"
                backoff = min(300.0, max(self.interval, backoff * 2 or self.interval))
                wait = backoff
                log.warning("hub check-in failed: %s", exc)
            self._stop.wait(wait if wait <= 1.0 else wait * random.uniform(0.85, 1.15))

    # ------------------------------------------------------------------ one check-in
    def _ctx(self) -> ssl.SSLContext:
        hd = hub_dir()
        ctx = ssl.create_default_context(cafile=str(hd / "ca.crt"))   # only the hub's own CA, nothing else
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(hd / "agent.crt"), str(hd / "agent.key"))
        return ctx

    def checkin_once(self, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        info = info or link_info()
        if not info:
            raise LinkError("not enrolled")
        store = self.agent.store
        self.state["url"] = info["url"]
        cursor = store.meta_get("hub_alert_cursor") or {"ts": 0.0, "id": ""}
        alerts = store.query("SELECT * FROM alerts WHERE ts > ? OR (ts = ? AND id > ?) ORDER BY ts, id LIMIT 200",
                             (cursor["ts"], cursor["ts"], cursor["id"]))
        results = list(store.meta_get("hub_results") or [])
        payload = {"status": self.status(), "audit_head": self.audit_head(),
                   "events": [{"type": "alert", "alert": json.loads(a["data"])} for a in alerts],
                   "results": results, "intel_version": int(store.meta_get("hub_intel_version") or 0)}
        res = _request(_conn(info["url"], self._ctx()), "POST", "/v1/checkin", payload)
        # the hub has what we sent: advance the cursor, forget delivered results
        if alerts:
            store.meta_set("hub_alert_cursor", {"ts": alerts[-1]["ts"], "id": alerts[-1]["id"]})
        if results:
            sent = {r["id"] for r in results}
            store.meta_set("hub_results", [r for r in (store.meta_get("hub_results") or []) if r["id"] not in sent])
        self.interval = float(res.get("checkin_interval") or self.interval)
        for cmd in res.get("commands") or []:
            self._run_command(cmd)
        if isinstance(res.get("intel"), dict):
            self._apply_intel(res["intel"])
        self.state.update(last_ok=time.time(), last_error="", agent_id=info["agent_id"])
        return res

    def status(self) -> Dict[str, Any]:
        a = self.agent
        st: Dict[str, Any] = {"hostname": HOSTNAME, "os": f"{platform.system()} {platform.release()}",
                              "version": __version__, "mode": a.mode, "uptime": round(time.time() - a.started),
                              "dry_run": a.responder.dry_run, "breaker_open": a.guard.breaker_open,
                              "log_sources": a.logs.sources, "sigma_rules": len(a.engine.sigma_rules),
                              "iocs": len(a.engine.iocs)}
        try:
            from eldoctor.config import is_privileged
            st["privileged"] = is_privileged()
            act = getattr(a, "activity", None)
            if act is not None:
                st["logged_in"] = act.sessions.users()
                st["activity_backend"] = act.backend
            since = time.time() - 86400
            st["alerts_24h"] = {r["severity"]: r["n"] for r in a.store.query(
                "SELECT severity, COUNT(*) AS n FROM alerts WHERE ts >= ? GROUP BY severity", (since,))}
        except Exception:
            pass
        return st

    def audit_head(self) -> Dict[str, Any]:
        from eldoctor.integrity import fingerprint
        head = self.agent.store.audit_head()
        g = self.agent.store.meta_get("audit_genesis") or {}
        return {"seq": head.get("seq"), "hash": head.get("hash"), "genesis": fingerprint(g["pub"]) if g.get("pub") else ""}

    # ------------------------------------------------------------------ remote response
    def _run_command(self, cmd: Dict[str, Any]) -> None:
        store = self.agent.store
        cid = str(cmd.get("id") or "")
        done = list(store.meta_get("hub_done_commands") or [])
        if not cid or cid in done:
            return                                          # replay / re-delivery: runs once
        store.meta_set("hub_done_commands", (done + [cid])[-1000:])   # at most once, even if we crash while running it
        try:
            result = self.execute(cmd)
        except Exception as exc:
            result = {"status": "failed", "message": f"{type(exc).__name__}: {exc}"}
        result["id"] = cid
        result["ts"] = time.time()
        store.meta_set("hub_results", list(store.meta_get("hub_results") or []) + [result])
        store.audit(f"hub:{cmd.get('created_by', '?')}", "remote_command",
                    {"id": cid, "action": cmd.get("action"), "params": cmd.get("params"), "status": result["status"],
                     "message": str(result.get("message", ""))[:300], "hub": (link_info() or {}).get("url")})

    def execute(self, cmd: Dict[str, Any]) -> Dict[str, Any]:
        from eldoctor.agent import manual_response
        from eldoctor.collectors.processes import process_info_from_pid
        a = self.agent
        action = str(cmd.get("action") or "")
        p = cmd.get("params") or {}
        who = HubPrincipal(str(cmd.get("created_by") or "?"))
        if action not in self.allowed:
            return {"status": "refused", "message": f"'{action}' is not allowed on this host (hub.allow_commands)"}
        if float(cmd.get("expires") or 0) and float(cmd["expires"]) < time.time():
            return {"status": "refused", "message": "the command expired before it arrived"}
        if action == "ping":
            return {"status": "success", "message": f"pong from {HOSTNAME}"}
        if action in PROC_ACTIONS:
            proc = process_info_from_pid(int(p.get("pid") or 0))
            if proc is None:
                return {"status": "failed", "message": f"process {p.get('pid')} does not exist (any more)"}
            if p.get("create_time") and abs(proc.create_time - float(p["create_time"])) > 0.05:
                return {"status": "failed", "message": f"pid {p.get('pid')} now belongs to another process (PID reuse)"}
            res = manual_response(a.responder, a.store, action, proc, who)
            a.recent_actions.appendleft(dict(res.to_dict(), playbook="hub", mode="manual"))
            return res.to_dict()
        if action == "block_ip":
            res = a.responder.block_ip(str(p.get("ip")), "", reason=f"hub: {who.username} {p.get('reason', '')}".strip(),
                                       automated=False)
            a.store.add_action(res, "", "hub", "manual", who.username)
            return res.to_dict()
        if action == "unblock_ip":
            res = a.responder.unblock_ip(str(p.get("ip")))
            return res.to_dict()
        if action == "set_mode":
            mode = str(p.get("mode"))
            if mode == "enforce" and not self.allow_enforce:
                return {"status": "refused", "message": "enforce mode cannot be set remotely on this host "
                                                        "(hub.allow_remote_enforce: false)"}
            prev = a.mode
            a.playbooks.set_mode(mode)
            return {"status": "success", "message": f"mode {prev} -> {mode}"}
        return {"status": "refused", "message": f"unknown action {action!r}"}

    # ------------------------------------------------------------------ fleet threat intel
    def _apply_intel(self, intel: Dict[str, Any]) -> None:
        import csv
        import io
        from eldoctor.detection.ioc import IOCStore
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "severity", "description", "mitre", "source"])
        for i in intel.get("indicators") or []:
            w.writerow([i.get("type", ""), i.get("value", ""), i.get("severity", "high"), i.get("description", ""),
                        "", "hub"])
        path = subdir("intel") / "hub_iocs.csv"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(buf.getvalue(), encoding="utf-8")
        os.replace(tmp, path)
        self.agent.engine.iocs = IOCStore.from_config(self.agent.cfg)
        if getattr(self.agent, "activity", None) is not None:
            self.agent.activity.iocs = self.agent.engine.iocs
        self.agent.store.meta_set("hub_intel_version", int(intel.get("version") or 0))
        self.agent.store.audit("hub", "hub_intel_applied", {"version": intel.get("version"),
                                                             "indicators": len(intel.get("indicators") or [])})
