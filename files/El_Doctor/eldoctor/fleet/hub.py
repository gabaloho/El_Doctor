"""El Doctor Hub: one place for a security team to see, triage and act on every El Doctor in the fleet.

Agents enroll once with a token, then check in every few seconds over mutual TLS (client certificates issued by the
hub's own CA).  One check-in = heartbeat + health + new alerts + results of earlier commands + the head of the
agent's tamper-evident audit trail; the answer carries pending response commands and threat-intel updates.  The
hub never connects to agents (works through NAT / firewalls, nothing listens on endpoints).

The hub raises its own alerts:
  HUB-001  agent stopped reporting (killed, host down, network cut, wiped ...)
  HUB-002  agent reporting again (with the length of the gap)
  HUB-003  agent audit trail went backwards or was rewritten (tampering on the endpoint)
  HUB-004  revoked agent tried to connect

Analyst accounts, roles and the signed audit trail of every analyst action are El Doctor's own (UserManager, Store).
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from eldoctor.fleet import pki

log = logging.getLogger("eldoctor.hub")

HUB_SCHEMA = """
CREATE TABLE IF NOT EXISTS hub_agents (
    id TEXT PRIMARY KEY, hostname TEXT, os TEXT, version TEXT, cert_fp TEXT, enrolled_ts REAL, enrolled_via TEXT,
    last_seen REAL, last_ip TEXT, status TEXT DEFAULT 'active', mode TEXT DEFAULT '', info TEXT DEFAULT '{}',
    audit_seq INTEGER DEFAULT 0, audit_hash TEXT DEFAULT '', audit_genesis TEXT DEFAULT '', silent INTEGER DEFAULT 0,
    intel_version INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hub_tokens (
    hash TEXT PRIMARY KEY, created REAL, expires REAL, uses_left INTEGER, created_by TEXT, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hub_alerts (
    id TEXT PRIMARY KEY, agent_id TEXT, alert_id TEXT, ts REAL, received REAL, rule_id TEXT, title TEXT,
    severity TEXT, host TEXT, source TEXT, data TEXT, status TEXT DEFAULT 'new', assignee TEXT DEFAULT '',
    verdict TEXT DEFAULT '', notes TEXT DEFAULT '[]', updated REAL
);
CREATE INDEX IF NOT EXISTS idx_hub_alerts_ts ON hub_alerts(ts);
CREATE INDEX IF NOT EXISTS idx_hub_alerts_status ON hub_alerts(status, ts);
CREATE TABLE IF NOT EXISTS hub_commands (
    id TEXT PRIMARY KEY, agent_id TEXT, created REAL, created_by TEXT, action TEXT, params TEXT, status TEXT,
    sent_ts REAL DEFAULT 0, done_ts REAL DEFAULT 0, expires REAL, result TEXT DEFAULT '', alert_ref TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hub_commands_agent ON hub_commands(agent_id, status);
CREATE TABLE IF NOT EXISTS hub_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, type TEXT, value TEXT, severity TEXT, description TEXT,
    added_by TEXT, active INTEGER DEFAULT 1
);
"""

HUB_RULES = {
    "HUB-001": ("El Doctor agent stopped reporting", "high",
                "The agent has not checked in for longer than hub.silent_after. It was stopped or killed, the host "
                "is down or cut off, or it was wiped. Check the host; the last known state is kept."),
    "HUB-002": ("El Doctor agent reporting again", "medium",
                "An agent that had stopped reporting checked in again. Review what happened during the gap."),
    "HUB-003": ("Agent audit trail went backwards or was rewritten", "critical",
                "The head of the agent's tamper-evident audit trail is older than, or different from, one it "
                "reported before: its database was restored, replaced or rewritten. Treat the host as compromised."),
    "HUB-004": ("Revoked agent tried to connect", "high",
                "A certificate that was revoked at the hub was used to check in."),
}
ALERT_STATUSES = ("new", "acknowledged", "investigating", "closed")
VERDICTS = ("", "true_positive", "false_positive", "benign", "duplicate")
# remote response: action -> (required params, hub permission)
ACTIONS: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "ping": ((), "respond"), "forensics": (("pid",), "respond"), "suspend": (("pid",), "respond"),
    "resume": (("pid",), "respond"), "kill": (("pid",), "respond"), "kill_tree": (("pid",), "respond"),
    "quarantine": (("pid",), "respond"), "block_ip": (("ip",), "respond"), "unblock_ip": (("ip",), "unblock"),
    "set_mode": (("mode",), "run"),
}
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_HUB_CONFIG: Dict[str, Any] = {
    "hub": {"agent_listen": "0.0.0.0:8443", "console_listen": "127.0.0.1:8444", "public_url": "",
            "names": [], "checkin_interval": 15, "silent_after": 180, "token_hours": 24, "command_ttl_minutes": 60,
            "max_body_mb": 8, "session_hours": 8},
    "notifications": {"min_severity": "high", "rate_limit_per_minute": 30,
                      "channels": [{"type": "jsonl", "path": "hub-alerts.jsonl"}]},
}


class HubError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def parse_listen(spec: str) -> Tuple[str, int]:
    host, _, port = str(spec).rpartition(":")
    return (host.strip("[]") or "0.0.0.0"), int(port)


class Hub:
    """Hub state and logic (no networking): used by the HTTPS servers, the web console and the CLI."""

    def __init__(self, home: Path) -> None:
        from eldoctor.auth.users import UserManager
        from eldoctor.config import deep_merge
        from eldoctor.storage import Store
        self.home = Path(home)
        if not (self.home / "pki" / "ca.crt").exists():
            raise HubError(f"no hub in {self.home} - create one with: eldoctor hub init --name <hub address>")
        raw = yaml.safe_load((self.home / "hub.yaml").read_text(encoding="utf-8")) if (self.home / "hub.yaml").exists() \
            else {}
        self.cfg = deep_merge(DEFAULT_HUB_CONFIG, raw or {})
        for ch in self.cfg["notifications"].get("channels") or []:        # relative paths: the hub's folder
            if ch.get("type") == "jsonl" and not os.path.isabs(str(ch.get("path", ""))):
                ch["path"] = str(self.home / str(ch.get("path") or "hub-alerts.jsonl"))
        self.hc = self.cfg["hub"]
        self.store = Store(self.home / "eldoctor.db")
        with self.store._lock:
            self.store.conn.executescript(HUB_SCHEMA)
        self.users = UserManager(self.store, {"registration": {"session_hours": self.hc.get("session_hours", 8)}})
        self.ca_pem = (self.home / "pki" / "ca.crt").read_bytes()
        self.ca_cert = pki.load_cert(self.ca_pem)
        self.ca_fp = pki.fingerprint(self.ca_cert)
        self.lock = threading.RLock()
        self._dispatcher = None
        self._revoked_seen: Dict[str, float] = {}
        self._refused_seen: Dict[str, float] = {}        # enrollment refusals are recorded once a minute per address

    # ------------------------------------------------------------------ creation
    @staticmethod
    def init(home: Path, names: List[str], port: int = 8443, console_port: int = 8444) -> Dict[str, Any]:
        home = Path(home)
        home.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(home, 0o700)
        pk = home / "pki"
        if (pk / "ca.crt").exists():
            raise HubError(f"a hub already exists in {home}")
        pk.mkdir(exist_ok=True)
        if os.name != "nt":
            os.chmod(pk, 0o700)
        ca_key, ca = pki.create_ca()
        srv_key, srv = pki.issue_server_cert(ca_key, ca, names)
        for name, data in (("ca.key", pki.key_pem(ca_key)), ("server.key", pki.key_pem(srv_key)),
                           ("ca.crt", pki.cert_pem(ca)), ("server.crt", pki.cert_pem(srv))):
            fd = os.open(str(pk / name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        host = names[0] if ":" not in names[0] else f"[{names[0]}]"
        cfg = {"hub": {"agent_listen": f"0.0.0.0:{port}", "console_listen": f"127.0.0.1:{console_port}",
                       "public_url": f"https://{host}:{port}", "names": list(names)}}
        (home / "hub.yaml").write_text("# El Doctor Hub configuration. Edit, then restart `eldoctor hub serve`.\n" +
                                       yaml.safe_dump(cfg, sort_keys=False) +
                                       "# notifications: same format as an agent's config (e-mail, Slack, syslog...)\n",
                                       encoding="utf-8")
        return {"home": str(home), "ca_fingerprint": pki.fingerprint(ca), "public_url": cfg["hub"]["public_url"]}

    def close(self) -> None:
        if self._dispatcher is not None:
            self._dispatcher.close()
        self.store.close()

    # ------------------------------------------------------------------ helpers
    def audit(self, actor: str, event: str, details: Any) -> None:
        self.store.audit(actor, event, details)

    def q(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        return self.store.query(sql, params)

    def x(self, sql: str, params: tuple = ()) -> None:
        with self.store.tx() as c:
            c.execute(sql, params)

    def dispatcher(self):
        if self._dispatcher is None:
            from eldoctor.notify.dispatcher import Dispatcher
            self._dispatcher = Dispatcher(self.cfg, exclude_types=["console"])
        return self._dispatcher

    # ------------------------------------------------------------------ enrollment
    def create_token(self, by: str, hours: Optional[float] = None, uses: int = 1, note: str = "") -> str:
        secret = pki.new_secret()
        hours = float(hours if hours is not None else self.hc.get("token_hours", 24))
        url = self.hc.get("public_url") or ""
        if not url:
            raise HubError("hub.public_url is not set in hub.yaml")
        self.x("INSERT INTO hub_tokens (hash, created, expires, uses_left, created_by, note) VALUES (?,?,?,?,?,?)",
               (pki.secret_hash(secret), time.time(), time.time() + hours * 3600, int(uses), by, note))
        self.audit(by, "hub_token_created", {"uses": uses, "hours": hours, "note": note})
        return pki.make_token(url, secret, self.ca_fp)

    def enroll(self, secret: str, csr_pem: str, hostname: str, os_name: str, version: str, ip: str) -> Dict[str, Any]:
        h = pki.secret_hash(str(secret or ""))
        with self.lock:
            ok = self.q("SELECT 1 FROM hub_tokens WHERE hash = ? AND expires >= ? AND uses_left >= 1", (h, time.time()))
            if not ok:                         # recorded outside any transaction: a refusal must never be rolled back
                now = time.time()
                if now - self._refused_seen.get(ip, 0) >= 60:          # no audit-trail flooding from the network
                    self._refused_seen[ip] = now
                    if len(self._refused_seen) > 10000:
                        self._refused_seen.clear()
                    self.audit(f"ip:{ip}", "hub_enroll_refused", {"hostname": str(hostname)[:100],
                                                                  "reason": "invalid, used or expired token"})
                raise HubError("the enrollment token is invalid, already used or expired: ask for a new one", 403)
            return self._enroll(h, csr_pem, hostname, os_name, version, ip)

    def _enroll(self, h: str, csr_pem: str, hostname: str, os_name: str, version: str, ip: str) -> Dict[str, Any]:
        with self.store.tx() as c:
            row = c.execute("SELECT * FROM hub_tokens WHERE hash = ?", (h,)).fetchone()
            c.execute("UPDATE hub_tokens SET uses_left = uses_left - 1 WHERE hash = ?", (h,))
            safe_host = "".join(ch for ch in str(hostname).lower() if ch.isalnum() or ch in "-_.")[:40] or "agent"
            agent_id = f"{safe_host}-{uuid.uuid4().hex[:8]}"
            ca_key = pki.load_key((self.home / "pki" / "ca.key").read_bytes())
            try:
                cert = pki.sign_agent_csr(ca_key, self.ca_cert, str(csr_pem).encode(), agent_id)
            except pki.PkiError as exc:
                raise HubError(str(exc)) from exc
            now = time.time()
            c.execute("INSERT INTO hub_agents (id, hostname, os, version, cert_fp, enrolled_ts, enrolled_via, last_seen,"
                      " last_ip, status) VALUES (?,?,?,?,?,?,?,?,?, 'active')",
                      (agent_id, str(hostname)[:255], str(os_name)[:64], str(version)[:32], pki.fingerprint(cert), now,
                       row["created_by"], now, ip))
            self.audit(f"agent:{agent_id}", "hub_agent_enrolled", {"hostname": hostname, "ip": ip, "os": os_name,
                                                                   "version": version, "token_by": row["created_by"]})
        return {"agent_id": agent_id, "cert_pem": pki.cert_pem(cert).decode(), "ca_pem": self.ca_pem.decode(),
                "checkin_interval": int(self.hc.get("checkin_interval", 15))}

    def revoke(self, agent_id: str, by: str) -> None:
        if not self.q("SELECT 1 FROM hub_agents WHERE id = ?", (agent_id,)):
            raise HubError("no such agent", 404)
        self.x("UPDATE hub_agents SET status = 'revoked' WHERE id = ?", (agent_id,))
        self.x("UPDATE hub_commands SET status = 'cancelled' WHERE agent_id = ? AND status IN ('pending', 'sent')",
               (agent_id,))
        self.audit(by, "hub_agent_revoked", {"agent_id": agent_id})

    # ------------------------------------------------------------------ check-in
    def authenticate_agent(self, agent_id: str, cert_fp: str, ip: str) -> Dict[str, Any]:
        rows = self.q("SELECT * FROM hub_agents WHERE id = ?", (agent_id,))
        if not rows or rows[0]["cert_fp"] != cert_fp:
            raise HubError("unknown agent certificate", 403)
        a = rows[0]
        if a["status"] == "revoked":
            if time.time() - self._revoked_seen.get(agent_id, 0) > 3600:
                self._revoked_seen[agent_id] = time.time()
                self._hub_alert("HUB-004", a, {"ip": ip})
            raise HubError("this agent was revoked at the hub", 403)
        return a

    def checkin(self, agent_id: str, cert_fp: str, payload: Dict[str, Any], ip: str) -> Dict[str, Any]:
        a = self.authenticate_agent(agent_id, cert_fp, ip)
        now = time.time()
        status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
        if a["silent"]:                                    # it was reported silent: it is back
            self._hub_alert("HUB-002", a, {"silent_since": a["last_seen"], "gap_seconds": round(now - a["last_seen"]),
                                           "ip": ip})
        self._check_audit_head(a, payload.get("audit_head") or {})
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
        new_alerts = 0
        for ev in events[:1000]:
            if isinstance(ev, dict) and ev.get("type") == "alert" and isinstance(ev.get("alert"), dict):
                new_alerts += self._store_agent_alert(a, ev["alert"])
        for r in (payload.get("results") if isinstance(payload.get("results"), list) else [])[:500]:
            self._command_result(agent_id, r)
        self.x("UPDATE hub_agents SET last_seen = ?, last_ip = ?, silent = 0, hostname = ?, os = ?, version = ?, "
               "mode = ?, info = ?, intel_version = ? WHERE id = ?",
               (now, ip, str(status.get("hostname") or a["hostname"])[:255], str(status.get("os") or a["os"])[:64],
                str(status.get("version") or a["version"])[:32], str(status.get("mode") or "")[:16],
                json.dumps(status, default=str)[:20000], int(payload.get("intel_version") or 0), agent_id))
        resp: Dict[str, Any] = {"ok": True, "server_time": now, "agent_id": agent_id,
                                "checkin_interval": int(self.hc.get("checkin_interval", 15)),
                                "commands": self._deliver_commands(agent_id, now), "accepted_alerts": new_alerts}
        version, indicators = self.intel_snapshot()
        if int(payload.get("intel_version") or 0) != version:
            resp["intel"] = {"version": version, "indicators": indicators}
        return resp

    def _check_audit_head(self, a: Dict[str, Any], head: Dict[str, Any]) -> None:
        try:
            seq, h = int(head.get("seq") or 0), str(head.get("hash") or "")
        except (TypeError, ValueError):
            return
        genesis = str(head.get("genesis") or "")
        if not seq:
            return
        problem = ""
        if a["audit_seq"] and seq < a["audit_seq"]:
            problem = f"the audit trail went back from record {a['audit_seq']} to {seq}"
        elif a["audit_seq"] and seq == a["audit_seq"] and h != a["audit_hash"]:
            problem = f"audit record {seq} changed"
        elif a["audit_genesis"] and genesis and genesis != a["audit_genesis"]:
            problem = f"the audit trail was rebuilt from another first key ({a['audit_genesis']} -> {genesis})"
        if problem:
            self._hub_alert("HUB-003", a, {"problem": problem, "reported_seq": seq, "known_seq": a["audit_seq"],
                                           "reported_hash": h, "known_hash": a["audit_hash"]}, dedup=f"{seq}:{h}")
        # the reported head becomes the reference (after an alert too: one alert per event, not per check-in)
        self.x("UPDATE hub_agents SET audit_seq = ?, audit_hash = ?, audit_genesis = ? WHERE id = ?",
               (seq, h, genesis or a["audit_genesis"] or "", a["id"]))

    def _store_agent_alert(self, a: Dict[str, Any], al: Dict[str, Any]) -> int:
        aid = str(al.get("id") or "")[:64]
        if not aid:
            return 0
        hid = f"{a['id']}:{aid}"
        if self.q("SELECT 1 FROM hub_alerts WHERE id = ?", (hid,)):
            return 0
        sev = str(al.get("severity") or "medium").lower()
        sev = sev if sev in SEV_ORDER else "medium"
        self.x("INSERT INTO hub_alerts (id, agent_id, alert_id, ts, received, rule_id, title, severity, host, source,"
               " data, status, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'new', ?)",
               (hid, a["id"], aid, float(al.get("timestamp") or time.time()), time.time(), str(al.get("rule_id"))[:80],
                str(al.get("title") or "")[:300], sev, str(al.get("host") or a["hostname"])[:255],
                str(al.get("source") or "")[:32], json.dumps(al, default=str)[:200000], time.time()))
        self._notify(dict(al, host=al.get("host") or a["hostname"]), sev)
        return 1

    def _hub_alert(self, rule: str, a: Dict[str, Any], evidence: Dict[str, Any], dedup: str = "") -> str:
        title, sev, desc = HUB_RULES[rule]
        aid = f"{rule}-{uuid.uuid4().hex[:10]}" if not dedup else f"{rule}-{dedup}"[:64]
        hid = f"{a['id']}:{aid}"
        if self.q("SELECT 1 FROM hub_alerts WHERE id = ?", (hid,)):
            return hid
        now = time.time()
        al = {"id": aid, "rule_id": rule, "title": f"{title}: {a['hostname']}", "severity": sev, "source": "hub",
              "description": desc, "host": a["hostname"], "timestamp": now, "mitre": [],
              "evidence": dict(evidence, agent_id=a["id"], last_seen=a.get("last_seen"), last_ip=a.get("last_ip")),
              "time_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now))}
        self.x("INSERT INTO hub_alerts (id, agent_id, alert_id, ts, received, rule_id, title, severity, host, source,"
               " data, status, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'new', ?)",
               (hid, a["id"], aid, now, now, rule, al["title"], sev, a["hostname"], "hub", json.dumps(al, default=str),
                now))
        self.audit("hub", "hub_alert", {"rule": rule, "agent_id": a["id"], "host": a["hostname"], **evidence})
        self._notify(al, sev)
        return hid

    def _notify(self, alert: Dict[str, Any], sev: str) -> None:
        try:
            self.dispatcher().notify(alert, [])
        except Exception as exc:
            log.warning("hub notification failed: %r", exc)

    # ------------------------------------------------------------------ silent agents
    def sweep(self, now: Optional[float] = None) -> List[str]:
        now = now or time.time()
        limit = float(self.hc.get("silent_after", 180))
        raised = []
        for a in self.q("SELECT * FROM hub_agents WHERE status = 'active' AND silent = 0 AND last_seen < ?",
                        (now - limit,)):
            self.x("UPDATE hub_agents SET silent = 1 WHERE id = ?", (a["id"],))
            raised.append(self._hub_alert("HUB-001", a, {"silent_for_seconds": round(now - a["last_seen"])}))
        self.x("UPDATE hub_commands SET status = 'expired' WHERE status = 'pending' AND expires < ?", (now,))
        return raised

    def agent_state(self, a: Dict[str, Any], now: Optional[float] = None) -> str:
        now = now or time.time()
        if a["status"] == "revoked":
            return "revoked"
        age = now - float(a["last_seen"] or 0)
        interval = float(self.hc.get("checkin_interval", 15))
        if age <= 2 * interval + 15:
            return "online"
        return "late" if age <= float(self.hc.get("silent_after", 180)) else "silent"

    def agents(self) -> List[Dict[str, Any]]:
        out = []
        for a in self.q("SELECT * FROM hub_agents ORDER BY hostname"):
            a["state"] = self.agent_state(a)
            a["info"] = json.loads(a.get("info") or "{}")
            a["open_alerts"] = self.q("SELECT COUNT(*) AS n FROM hub_alerts WHERE agent_id = ? AND status != 'closed'",
                                      (a["id"],))[0]["n"]
            out.append(a)
        return out

    # ------------------------------------------------------------------ alert queue and triage
    def alerts(self, status: str = "", severity: str = "", agent_id: str = "", text: str = "",
               limit: int = 200) -> List[Dict[str, Any]]:
        where, params = ["1=1"], []
        if status == "open":
            where.append("status != 'closed'")
        elif status:
            where.append("status = ?"); params.append(status)
        if severity:
            where.append("severity IN (%s)" % ",".join("?" * len([s for s in SEV_ORDER if SEV_ORDER[s] >= SEV_ORDER.get(severity, 0)])))
            params += [s for s in SEV_ORDER if SEV_ORDER[s] >= SEV_ORDER.get(severity, 0)]
        if agent_id:
            where.append("agent_id = ?"); params.append(agent_id)
        if text:
            where.append("(title LIKE ? OR host LIKE ? OR rule_id LIKE ?)")
            params += [f"%{text}%"] * 3
        rows = self.q(f"SELECT * FROM hub_alerts WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ?",
                      (*params, int(limit)))
        for r in rows:
            r["notes"] = json.loads(r.get("notes") or "[]")
        return rows

    def alert(self, hid: str) -> Optional[Dict[str, Any]]:
        rows = self.q("SELECT * FROM hub_alerts WHERE id = ?", (hid,))
        if not rows:
            return None
        r = rows[0]
        r["notes"] = json.loads(r.get("notes") or "[]")
        r["data"] = json.loads(r.get("data") or "{}")
        return r

    def triage(self, hid: str, by: str, status: str = "", verdict: Optional[str] = None, note: str = "",
               assignee: Optional[str] = None) -> Dict[str, Any]:
        r = self.alert(hid)
        if r is None:
            raise HubError("no such alert", 404)
        if status and status not in ALERT_STATUSES:
            raise HubError(f"status must be one of {ALERT_STATUSES}")
        if verdict is not None and verdict not in VERDICTS:
            raise HubError(f"verdict must be one of {VERDICTS[1:]}")
        if status == "closed" and not (verdict or r["verdict"]):
            raise HubError("closing an alert needs a verdict (true_positive, false_positive, benign, duplicate)")
        notes = r["notes"]
        if note:
            notes.append({"ts": time.time(), "by": by, "text": str(note)[:4000]})
        new = {"status": status or r["status"], "verdict": r["verdict"] if verdict is None else verdict,
               "assignee": r["assignee"] if assignee is None else str(assignee)[:64]}
        self.x("UPDATE hub_alerts SET status = ?, verdict = ?, assignee = ?, notes = ?, updated = ? WHERE id = ?",
               (new["status"], new["verdict"], new["assignee"], json.dumps(notes), time.time(), hid))
        self.audit(by, "hub_alert_triaged", {"alert": hid, **new, "note": bool(note)})
        return self.alert(hid) or {}

    # ------------------------------------------------------------------ remote response
    def create_command(self, user, agent_id: str, action: str, params: Dict[str, Any], alert_ref: str = "") -> str:
        if action not in ACTIONS:
            raise HubError(f"action must be one of {sorted(ACTIONS)}")
        needed, perm = ACTIONS[action]
        if not user.can(perm):
            raise HubError(f"role '{user.role}' may not '{action}' (needs {perm})", 403)
        a = self.q("SELECT * FROM hub_agents WHERE id = ?", (agent_id,))
        if not a or a[0]["status"] != "active":
            raise HubError("no such active agent", 404)
        clean: Dict[str, Any] = {}
        for p in needed:
            if p not in params or params[p] in (None, ""):
                raise HubError(f"'{action}' needs {p}")
        if "pid" in needed:
            try:
                clean["pid"] = int(params["pid"])
            except (TypeError, ValueError):
                raise HubError("pid must be a number") from None
            if clean["pid"] <= 0:
                raise HubError("pid must be positive")
            if params.get("create_time"):
                clean["create_time"] = float(params["create_time"])
        if "ip" in needed:
            try:
                clean["ip"] = str(ipaddress.ip_address(str(params["ip"]).strip()))
            except ValueError:
                raise HubError("invalid IP address") from None
        if action == "set_mode":
            from eldoctor.config import MODES
            if params["mode"] not in MODES:
                raise HubError(f"mode must be one of {MODES}")
            if params["mode"] == "enforce" and not user.can("enforce"):
                raise HubError("enforce mode needs the admin role", 403)
            clean["mode"] = params["mode"]
        if params.get("reason"):
            clean["reason"] = str(params["reason"])[:300]
        cid = uuid.uuid4().hex[:16]
        now = time.time()
        self.x("INSERT INTO hub_commands (id, agent_id, created, created_by, action, params, status, expires, alert_ref)"
               " VALUES (?,?,?,?,?,?, 'pending', ?, ?)",
               (cid, agent_id, now, user.username, action, json.dumps(clean), now + 60 * float(
                   self.hc.get("command_ttl_minutes", 60)), alert_ref))
        self.audit(user.username, "hub_command_created", {"id": cid, "agent_id": agent_id, "action": action,
                                                          "params": clean, "alert": alert_ref})
        return cid

    def _deliver_commands(self, agent_id: str, now: float) -> List[Dict[str, Any]]:
        """Pending commands, and sent ones without a result for a while (the answer may have been lost - the agent
        executes each command id once)."""
        rows = self.q("SELECT * FROM hub_commands WHERE agent_id = ? AND expires >= ? AND (status = 'pending' OR "
                      "(status = 'sent' AND sent_ts < ?)) ORDER BY created", (agent_id, now, now - 60))
        out = []
        for r in rows:
            self.x("UPDATE hub_commands SET status = 'sent', sent_ts = ? WHERE id = ?", (now, r["id"]))
            out.append({"id": r["id"], "action": r["action"], "params": json.loads(r["params"] or "{}"),
                        "created_by": r["created_by"], "expires": r["expires"]})
        return out

    def _command_result(self, agent_id: str, r: Dict[str, Any]) -> None:
        cid = str(r.get("id") or "")
        rows = self.q("SELECT * FROM hub_commands WHERE id = ? AND agent_id = ?", (cid, agent_id))
        if not rows or rows[0]["status"] in ("done", "failed"):
            return
        ok = str(r.get("status")) in ("success", "dry_run", "would_run", "skipped")
        self.x("UPDATE hub_commands SET status = ?, done_ts = ?, result = ? WHERE id = ?",
               ("done" if ok else "failed", time.time(), json.dumps(r, default=str)[:20000], cid))
        self.audit(f"agent:{agent_id}", "hub_command_result", {"id": cid, "status": r.get("status"),
                                                               "message": str(r.get("message", ""))[:300]})

    def commands(self, agent_id: str = "", limit: int = 200) -> List[Dict[str, Any]]:
        if agent_id:
            rows = self.q("SELECT * FROM hub_commands WHERE agent_id = ? ORDER BY created DESC LIMIT ?",
                          (agent_id, limit))
        else:
            rows = self.q("SELECT * FROM hub_commands ORDER BY created DESC LIMIT ?", (limit,))
        for r in rows:
            r["params"] = json.loads(r["params"] or "{}")
            r["result"] = json.loads(r["result"]) if r.get("result") else {}
        return rows

    # ------------------------------------------------------------------ fleet threat intel
    def add_intel(self, by: str, ioc_type: str, value: str, severity: str = "high", description: str = "") -> int:
        from eldoctor.detection.ioc import normalize
        if normalize(ioc_type, value) is None:
            raise HubError(f"invalid {ioc_type}: {value}")
        if severity not in ("low", "medium", "high", "critical"):
            raise HubError("severity must be low, medium, high or critical")
        with self.store.tx() as c:
            cur = c.execute("INSERT INTO hub_intel (ts, type, value, severity, description, added_by) VALUES "
                            "(?,?,?,?,?,?)", (time.time(), ioc_type, value.strip(), severity, description[:300], by))
            iid = int(cur.lastrowid)
            self._bump_intel()
        self.audit(by, "hub_intel_added", {"id": iid, "type": ioc_type, "value": value, "severity": severity})
        return iid

    def remove_intel(self, by: str, iid: int) -> None:
        with self.store.tx() as c:
            if c.execute("UPDATE hub_intel SET active = 0 WHERE id = ? AND active = 1", (int(iid),)).rowcount != 1:
                raise HubError("no such active indicator", 404)
            self._bump_intel()
        self.audit(by, "hub_intel_removed", {"id": iid})

    def _bump_intel(self) -> None:
        v = int(self.store.meta_get("hub_intel_version") or 0) + 1
        self.store.meta_set("hub_intel_version", v)

    def intel_snapshot(self) -> Tuple[int, List[Dict[str, Any]]]:
        v = int(self.store.meta_get("hub_intel_version") or 0)
        rows = self.q("SELECT id, type, value, severity, description FROM hub_intel WHERE active = 1 ORDER BY id")
        return v, rows

    # ------------------------------------------------------------------ overview
    def overview(self) -> Dict[str, Any]:
        agents = self.agents()
        states: Dict[str, int] = {}
        for a in agents:
            states[a["state"]] = states.get(a["state"], 0) + 1
        sev = {r["severity"]: r["n"] for r in self.q("SELECT severity, COUNT(*) AS n FROM hub_alerts WHERE status != "
                                                      "'closed' GROUP BY severity")}
        return {"agents": len(agents), "states": states, "open_alerts": sev,
                "pending_commands": self.q("SELECT COUNT(*) AS n FROM hub_commands WHERE status IN ('pending','sent')")[0]["n"]}


# --------------------------------------------------------------------------- agent-facing HTTPS (mutual TLS)
def server_context(home: Path, require_client: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(home / "pki" / "server.crt"), str(home / "pki" / "server.key"))
    if require_client:
        ctx.load_verify_locations(cafile=str(home / "pki" / "ca.crt"))
        ctx.verify_mode = ssl.CERT_OPTIONAL        # enrollment has no certificate yet; check-ins must present one
    return ctx


class TLSServer(http.server.ThreadingHTTPServer):
    """TLS handshake in the request thread (a client that never finishes its handshake blocks nobody)."""
    daemon_threads = True
    allow_reuse_address = True

    max_connections = 256
    request_queue_size = 512          # listen backlog (default 5): a fleet reconnecting at once must not be dropped

    def __init__(self, addr, handler, ctx: ssl.SSLContext, hub: Hub) -> None:
        self.ctx = ctx
        self.hub = hub
        self._slots = threading.BoundedSemaphore(self.max_connections)
        if ":" in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)

    def process_request(self, request, client_address) -> None:
        """A bounded number of connections at once: a flood of idle connections cannot exhaust the hub."""
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address) -> None:
        request.settimeout(20)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log.debug("TLS handshake with %s failed: %s", client_address[0], exc)
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


class AgentAPIHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ElDoctorHub"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("agent-api %s " + fmt, self.client_address[0], *args)

    def _send(self, status: int, obj: Dict[str, Any], ctype: str = "application/json") -> None:
        body = obj if isinstance(obj, bytes) else json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        hub: Hub = self.server.hub                         # type: ignore[attr-defined]
        if self.path == "/v1/ca":
            self._send(200, hub.ca_pem, "application/x-pem-file")
        elif self.path == "/v1/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        hub: Hub = self.server.hub                         # type: ignore[attr-defined]
        ip = self.client_address[0]
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > float(hub.hc.get("max_body_mb", 8)) * 1048576:
                raise HubError("request body missing or too large", 413)
            payload = json.loads(self.rfile.read(n))
            if not isinstance(payload, dict):
                raise HubError("JSON object expected")
            if self.path == "/v1/enroll":
                res = hub.enroll(payload.get("secret", ""), payload.get("csr", ""), str(payload.get("hostname", "")),
                                 str(payload.get("os", "")), str(payload.get("version", "")), ip)
            elif self.path == "/v1/checkin":
                der = self.connection.getpeercert(binary_form=True)
                if not der:
                    raise HubError("a client certificate is required (enroll first)", 401)
                from cryptography import x509
                cert = x509.load_der_x509_certificate(der)
                res = hub.checkin(pki.agent_id_of(cert), pki.fingerprint_der(der), payload, ip)
            else:
                raise HubError("not found", 404)
            self._send(200, res)
        except HubError as exc:
            self._send(exc.status, {"ok": False, "error": str(exc)})
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"ok": False, "error": "invalid JSON"})
        except Exception as exc:                            # never leak a traceback to the network
            log.exception("agent API error")
            self._send(500, {"ok": False, "error": f"hub error ({type(exc).__name__})"})


class HubServer:
    """Runs the agent API (mutual TLS), the analyst web console and the silent-agent sweeper."""

    def __init__(self, hub: Hub) -> None:
        self.hub = hub
        self.threads: List[threading.Thread] = []
        self.servers: List[http.server.HTTPServer] = []
        self._stop = threading.Event()

    def start(self, console: bool = True) -> Dict[str, Any]:
        from eldoctor.fleet.console import ConsoleHandler
        h = self.hub
        agent_addr = parse_listen(h.hc.get("agent_listen", "0.0.0.0:8443"))
        s = TLSServer(agent_addr, AgentAPIHandler, server_context(h.home, True), h)
        self.servers.append(s)
        out = {"agent_api": f"{s.server_address[0]}:{s.server_address[1]}"}
        if console and h.hc.get("console_listen"):
            caddr = parse_listen(h.hc["console_listen"])
            c = TLSServer(caddr, ConsoleHandler, server_context(h.home, False), h)
            self.servers.append(c)
            out["console"] = f"{c.server_address[0]}:{c.server_address[1]}"
        for srv in self.servers:
            t = threading.Thread(target=srv.serve_forever, daemon=True, name="hub-http")
            t.start()
            self.threads.append(t)
        sw = threading.Thread(target=self._sweeper, daemon=True, name="hub-sweeper")
        sw.start()
        self.threads.append(sw)
        h.audit("hub", "hub_started", out)
        return out

    def _sweeper(self) -> None:
        while not self._stop.wait(15):
            try:
                self.hub.sweep()
            except Exception:
                log.exception("sweep failed")

    def stop(self) -> None:
        self._stop.set()
        for s in self.servers:
            s.shutdown()
            s.server_close()
