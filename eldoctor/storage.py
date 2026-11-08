"""SQLite persistence: alerts, response actions, approvals, blocks, quarantine, users and the audit trail.

Only the agent process opens this database (the data folder is locked to the service account; the CLI,
TUI and GUI talk to the agent through ``eldoctor.api``).  Even so, nothing security-relevant is trusted
just because it is in a row:

* approvals, users, quarantine records and IP blocks carry HMAC seals (``eldoctor.integrity``) made with
  a key only the agent can read - a row edited or inserted behind the agent's back fails verification;
* the audit trail is an append-only hash chain (seq, prev_hash, hash, mac) with a sealed head pointer,
  so modified, inserted, deleted or truncated records are detected, and every record is handed to the
  SIEM forwarder the moment it is committed;
* every record is also signed with a one-time Ed25519 key (forward-secure: a stolen key cannot change
  history), and every write to alerts, actions, users, blocks, quarantine and approval requests appends
  the row's digest to that signed chain (the *ledger*).  Rows are checked against the ledger before
  the agent acts on them, and ``verify_audit`` checks every row of those tables.

Safe for several threads (one connection, re-entrant lock) and several processes (WAL + BEGIN IMMEDIATE
transactions serialise writers, so two writers can never fork the audit chain).
"""
from __future__ import annotations

import contextvars
import getpass
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from eldoctor.config import IS_WINDOWS, home_dir
from eldoctor.integrity import (GENESIS, Keyring, SigningChain, audit_hash, fingerprint, row_digest,
                                verify_records, verify_signature)
from eldoctor.models import HOSTNAME

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, ts REAL, rule_id TEXT, title TEXT, severity TEXT, source TEXT,
    mitre TEXT, pid INTEGER, process_name TEXT, remote_ip TEXT, data TEXT, status TEXT DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, alert_id TEXT, playbook_id TEXT, action TEXT,
    target TEXT, status TEXT, message TEXT, mode TEXT, actor TEXT, details TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, ts REAL, expires REAL, alert_id TEXT, playbook_id TEXT, step_index INTEGER,
    summary TEXT, alert TEXT, status TEXT, decided_by TEXT, decided_ts REAL, executed INTEGER DEFAULT 0,
    entity TEXT DEFAULT '', req_mac TEXT, dec_mac TEXT, decided_os_user TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY, ts REAL, expires REAL, reason TEXT, alert_id TEXT, backend TEXT, active INTEGER,
    seal TEXT
);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY, ts REAL, original_path TEXT, stored_path TEXT, sha256 TEXT, size INTEGER,
    mode INTEGER, alert_id TEXT, restored INTEGER DEFAULT 0, seal TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT, full_name TEXT,
    organization TEXT, role TEXT NOT NULL, use_case TEXT, deployment_target TEXT, password_hash TEXT,
    api_key_hash TEXT, created_at REAL, last_login REAL, active INTEGER DEFAULT 1,
    failed_logins INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, consent_share INTEGER DEFAULT 0,
    token_version INTEGER DEFAULT 0, seal TEXT
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY, exp REAL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, ts REAL, actor TEXT, event TEXT, details TEXT,
    os_user TEXT DEFAULT '', os_uid TEXT DEFAULT '', os_pid INTEGER DEFAULT 0, client TEXT DEFAULT '',
    host TEXT DEFAULT '', prev_hash TEXT, hash TEXT, mac TEXT,
    v INTEGER DEFAULT 1, pub TEXT, next_pub TEXT, sig TEXT, ref_kind TEXT, ref_id TEXT, ref_digest TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit(event);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT, mac TEXT
);
"""

# columns added after the first release: (table, column, declaration) - applied to older databases
MIGRATIONS = [
    ("approvals", "entity", "TEXT DEFAULT ''"),
    ("approvals", "req_mac", "TEXT"),
    ("approvals", "dec_mac", "TEXT"),
    ("approvals", "decided_os_user", "TEXT DEFAULT ''"),
    ("blocked_ips", "seal", "TEXT"),
    ("quarantine", "seal", "TEXT"),
    ("users", "token_version", "INTEGER DEFAULT 0"),
    ("users", "seal", "TEXT"),
    ("audit", "os_user", "TEXT DEFAULT ''"),
    ("audit", "os_uid", "TEXT DEFAULT ''"),
    ("audit", "os_pid", "INTEGER DEFAULT 0"),
    ("audit", "client", "TEXT DEFAULT ''"),
    ("audit", "host", "TEXT DEFAULT ''"),
    ("audit", "prev_hash", "TEXT"),
    ("audit", "hash", "TEXT"),
    ("audit", "mac", "TEXT"),
    ("audit", "v", "INTEGER DEFAULT 1"),
    ("audit", "pub", "TEXT"),
    ("audit", "next_pub", "TEXT"),
    ("audit", "sig", "TEXT"),
    ("audit", "ref_kind", "TEXT"),
    ("audit", "ref_id", "TEXT"),
    ("audit", "ref_digest", "TEXT"),
]

# ledger: row kinds whose every write is recorded (digest) in the signed chain
LEDGER_TABLES = {"alert": ("alerts", "id"), "action": ("actions", "id"), "user": ("users", "id"),
                 "block": ("blocked_ips", "ip"), "quarantine": ("quarantine", "id"), "approval": ("approvals", "id")}
LEDGER_EVENTS = {"alert": "alert_recorded", "action": "action_recorded", "user": "user_state",
                 "block": "block_state", "quarantine": "quarantine_state", "approval": "approval_requested"}
# chain bookkeeping, hidden from the default audit listing (still chained, verified and forwarded)
BOOKKEEPING_EVENTS = ("alert_recorded", "action_recorded", "user_state", "block_state", "quarantine_state",
                      "ledger_batch")

DECISION_EVENTS = ("approval_decided", "approval_expired")
# response actions that change the system: each one executed also goes into the hash-chained audit trail
AUDITED_ACTIONS = {"kill", "suspend", "resume", "renice", "quarantine", "block_ip", "unblock_ip", "restore"}
AUDITED_STATUSES = {"success", "failed"}


def entity_key(alert) -> str:
    """Identity of what an alert is about: a process instance, else a remote IP, else the alert itself."""
    p = alert.process or {}
    if p.get("pid"):
        return f"proc:{p.get('pid')}:{float(p.get('create_time') or 0):.2f}"
    if alert.remote_ip:
        return f"ip:{alert.remote_ip}"
    return f"alert:{alert.id}"


# --------------------------------------------------------------------------- who is acting (OS identity)
@dataclass
class Origin:
    """The OS-level identity behind an operation, recorded in every audit record.

    The API server sets it per request from the socket's *peer credentials* (kernel-verified uid/pid),
    so the audit trail says "analyst admin_user, OS user admin_user (uid 1001, pid 4242) via the GUI" and not just
    a username typed into a form."""
    os_user: str
    os_uid: str
    os_pid: int
    client: str = "agent"


def _own_origin() -> Origin:
    try:
        who = getpass.getuser()
    except Exception:
        who = "?"
    uid = str(os.getuid()) if hasattr(os, "getuid") else ""
    return Origin(who, uid, os.getpid(), "agent")


_ORIGIN: "contextvars.ContextVar[Optional[Origin]]" = contextvars.ContextVar("eldoctor_origin", default=None)


def current_origin() -> Origin:
    return _ORIGIN.get() or _own_origin()


@contextmanager
def acting_as(origin: Optional[Origin]) -> Iterator[None]:
    tok = _ORIGIN.set(origin)
    try:
        yield
    finally:
        _ORIGIN.reset(tok)


# --------------------------------------------------------------------------- store
class Store:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else home_dir() / "eldoctor.db"
        new = not self.path.exists()
        self._lock = threading.RLock()
        self._depth = 0
        self._after_commit: List[Callable[[], None]] = []
        self.audit_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.violation_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.integrity_problems: List[str] = []
        self._reported: set = set()
        self.keys = Keyring(self.path.parent)
        self.signer = SigningChain(self.keys.dir)
        self._ledger: Optional[Dict[Tuple[str, str], Tuple[int, str]]] = None     # verified index (agent)
        self._lv: Dict[str, Any] = {}
        # autocommit mode: transactions are explicit (BEGIN IMMEDIATE) so multi-statement updates and
        # audit appends are atomic across processes
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.executescript(SCHEMA)
        self._migrate()
        if new and not IS_WINDOWS:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.chmod(str(self.path) + suffix, 0o600)
                except OSError:
                    pass
        self._ensure_integrity()
        self._ensure_ledger()

    # ------------------------------------------------------------------ helpers
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Re-entrant write transaction (BEGIN IMMEDIATE takes the database write lock up front)."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self.conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self.conn
            except BaseException:
                self._depth -= 1
                if outer:
                    self.conn.execute("ROLLBACK")
                    self._after_commit.clear()
                raise
            self._depth -= 1
            if outer:
                self.conn.execute("COMMIT")
                pending, self._after_commit = self._after_commit, []
                for cb in pending:
                    try:
                        cb()
                    except Exception:
                        pass

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def _migrate(self) -> None:
        for table, col, decl in MIGRATIONS:
            cols = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if col not in cols:
                try:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except sqlite3.OperationalError:      # another process migrated concurrently
                    pass
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ref ON audit(ref_kind, ref_id)")

    # ------------------------------------------------------------------ sealed metadata
    def meta_get(self, key: str) -> Optional[Any]:
        rows = self.query("SELECT value, mac FROM meta WHERE key = ?", (key,))
        if not rows:
            return None
        if not self.keys.check_seal("meta", [key, rows[0]["value"]], rows[0]["mac"]):
            self.report_violation("meta", key, "sealed metadata was modified outside the agent")
            return None
        return json.loads(rows[0]["value"])

    def _meta_checked(self, key: str) -> Tuple[Optional[Any], bool]:
        """(value, seal_ok) without reporting - for use inside the audit append itself."""
        row = self.conn.execute("SELECT value, mac FROM meta WHERE key = ?", (key,)).fetchone()
        if not row:
            return None, True
        return json.loads(row["value"]), self.keys.check_seal("meta", [key, row["value"]], row["mac"])

    def meta_set(self, key: str, value: Any) -> None:
        raw = json.dumps(value, default=str)
        self.execute("INSERT OR REPLACE INTO meta (key, value, mac) VALUES (?,?,?)",
                     (key, raw, self.keys.seal("meta", [key, raw])))

    # ------------------------------------------------------------------ integrity bootstrap
    def _ensure_integrity(self) -> None:
        """Seal a brand-new or pre-integrity database once; refuse to silently re-seal a tampered one."""
        rows = self.query("SELECT value, mac FROM meta WHERE key = 'integrity_epoch'")
        if rows:
            if not self.keys.check_seal("meta", ["integrity_epoch", rows[0]["value"]], rows[0]["mac"]):
                self.integrity_problems.append("integrity metadata was modified outside the agent")
            return
        has_data = any(self.query(f"SELECT 1 FROM {t} LIMIT 1") for t in ("users", "audit", "approvals"))
        if has_data and not self.keys.created:
            # the key predates this database state: someone removed the integrity metadata
            self.integrity_problems.append(
                "the database has data but no integrity metadata although the agent key exists - it was "
                "replaced or tampered with; records are NOT trusted (restore a backup, or remove "
                f"{self.keys.dir} as the service account to re-seal the current content knowingly)")
            return
        self._adopt()

    def _adopt(self) -> None:
        legacy: Dict[str, int] = {}
        with self.tx() as c:
            if c.execute("SELECT 1 FROM meta WHERE key = 'integrity_epoch'").fetchone():
                return                                   # another process adopted concurrently
            # 1. chain pre-existing audit records (renumbered 1..N; their pre-adoption content is unverified)
            old = [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id").fetchall()]
            if old:
                c.execute("DELETE FROM audit")
                prev = GENESIS
                for seq, r in enumerate(old, start=1):
                    rec = {"seq": seq, "ts": float(r["ts"] or 0), "actor": r["actor"] or "", "event": r["event"] or "",
                           "details": r["details"] or "", "os_user": r.get("os_user") or "",
                           "os_uid": r.get("os_uid") or "", "os_pid": int(r.get("os_pid") or 0),
                           "client": r.get("client") or "legacy", "host": r.get("host") or HOSTNAME}
                    h = audit_hash(rec, prev)
                    c.execute("INSERT INTO audit (id, ts, actor, event, details, os_user, os_uid, os_pid, client, host,"
                              " prev_hash, hash, mac) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (seq, rec["ts"], rec["actor"], rec["event"], rec["details"], rec["os_user"],
                               rec["os_uid"], rec["os_pid"], rec["client"], rec["host"], prev, h,
                               self.keys.audit_mac(h)))
                    prev = h
                self.meta_set("audit_head", {"seq": len(old), "hash": prev})
            legacy["audit"] = len(old)
            self.meta_set("audit_legacy_upto", len(old))
            # 2. seal pre-existing rows
            legacy["users"] = 0
            for r in c.execute("SELECT * FROM users").fetchall():
                self._reseal_user(dict(r), ledger=False)
                legacy["users"] += 1
            legacy["approvals"] = 0
            for r in c.execute("SELECT * FROM approvals").fetchall():
                r = dict(r)
                req = self.keys.seal("approval_request", self._approval_req_fields(r))
                dec = self.keys.seal("approval_decision", self._approval_dec_fields(dict(r, req_mac=req))) \
                    if r["status"] != "pending" else None
                c.execute("UPDATE approvals SET req_mac = ?, dec_mac = ?, executed = CASE WHEN status = 'pending'"
                          " THEN executed ELSE 1 END WHERE id = ?", (req, dec, r["id"]))
                legacy["approvals"] += 1
            for r in c.execute("SELECT * FROM quarantine").fetchall():
                c.execute("UPDATE quarantine SET seal = ? WHERE id = ?", (self._quarantine_seal(dict(r)), r["id"]))
            for r in c.execute("SELECT * FROM blocked_ips").fetchall():
                c.execute("UPDATE blocked_ips SET seal = ? WHERE ip = ?", (self._block_seal(dict(r)), r["ip"]))
            if legacy["users"]:
                self.meta_set("first_admin_created", True)
            self.meta_set("integrity_epoch", {"ts": time.time(), "kid": self.keys.kid, "legacy": legacy})
            self._ledger_existing_rows(sealed_only=False)
            self.meta_set("ledger_epoch", {"ts": time.time()})
            self.audit("system", "integrity_initialized",
                       {"kid": self.keys.kid, "legacy_records_adopted": legacy,
                        "note": "records older than this event were sealed on adoption; their earlier history is "
                                "unverified" if any(legacy.values()) else "new database"})

    def _ensure_ledger(self) -> None:
        """Upgrade a database sealed by the first chain version: record every existing row in the signed
        chain once (rows whose HMAC seal is invalid are *not* adopted - they stay untrusted)."""
        if self.integrity_problems:
            return
        if self.query("SELECT 1 FROM meta WHERE key = 'ledger_epoch'"):
            return
        with self.tx() as c:
            if c.execute("SELECT 1 FROM meta WHERE key = 'ledger_epoch'").fetchone():
                return
            counts = self._ledger_existing_rows(sealed_only=True)
            self.meta_set("ledger_epoch", {"ts": time.time()})
            self.audit("system", "ledger_initialized",
                       {"rows_recorded": counts, "note": "existing rows recorded in the signed chain on upgrade"})

    # ------------------------------------------------------------------ ledger (row digests in the signed chain)
    def _row_fields(self, kind: str, r: Dict[str, Any]) -> list:
        if kind == "alert":
            return [r["id"], float(r["ts"] or 0), r["rule_id"], r["title"], r["severity"], r["source"], r["mitre"],
                    r["pid"], r["process_name"], r["remote_ip"], r["data"], r.get("status") or "open"]
        if kind == "action":
            return [int(r["id"]), float(r["ts"] or 0), r["alert_id"], r["playbook_id"], r["action"], r["target"],
                    r["status"], r["message"], r["mode"], r["actor"], r["details"]]
        if kind == "user":
            return self._user_fields(r)
        if kind == "block":
            return self._block_fields(r)
        if kind == "quarantine":
            return self._quarantine_fields(r) + [int(r.get("restored") or 0)]
        if kind == "approval":
            return self._approval_req_fields(r)
        raise ValueError(kind)

    def row_digest(self, kind: str, r: Dict[str, Any]) -> str:
        return row_digest(kind, self._row_fields(kind, r))

    def _ledger_write(self, kind: str, key: Any, actor: str = "agent", summary: Optional[Dict[str, Any]] = None) -> None:
        """Record the row as it is *now in the database* (read back inside the caller's transaction, so the
        digest is computed from exactly the values later readers will see)."""
        table, col = LEDGER_TABLES[kind]
        row = self.conn.execute(f"SELECT * FROM {table} WHERE {col} = ?", (key,)).fetchone()
        if row is None:
            return
        row = dict(row)
        self.audit(actor, LEDGER_EVENTS[kind], summary if summary is not None else {},
                   ref=(kind, str(key), self.row_digest(kind, row)))

    def _ledger_existing_rows(self, sealed_only: bool) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        checks = {"user": lambda r: self.keys.check_seal("user", self._user_fields(r), r.get("seal")),
                  "block": lambda r: self.keys.check_seal("block", self._block_fields(r), r.get("seal")),
                  "quarantine": lambda r: self.keys.check_seal("quarantine", self._quarantine_fields(r), r.get("seal")),
                  "approval": lambda r: self.keys.check_seal("approval_request", self._approval_req_fields(r),
                                                             r.get("req_mac"))}
        for kind, (table, col) in LEDGER_TABLES.items():
            rows = [dict(r) for r in self.conn.execute(f"SELECT * FROM {table} ORDER BY {col}").fetchall()]
            if sealed_only and kind in checks:
                rows = [r for r in rows if checks[kind](r)]
            batch = [[str(r[col]), self.row_digest(kind, r)] for r in rows]
            for i in range(0, len(batch), 500):
                part = batch[i:i + 500]
                self.audit("system", "ledger_batch", {"kind": kind, "batch": part},
                           ref=(kind, "*", row_digest(kind + "_batch", part)))
            counts[kind] = len(batch)
        return counts

    def _record_trusted(self, rec: Dict[str, Any]) -> bool:
        """Single-record check (fast path): hash, MAC, signature, key continuity and chain linkage."""
        if not self.audit_record_ok(rec):
            return False
        if int(rec.get("v") or 1) >= 2:
            if not verify_signature(rec.get("pub") or "", rec["hash"], rec.get("sig") or ""):
                return False
            prev = self.query("SELECT v, next_pub FROM audit WHERE id = ?", (int(rec["seq"]) - 1,))
            if prev and int(prev[0]["v"] or 1) >= 2 and prev[0]["next_pub"] != rec.get("pub"):
                return False
        return True

    def enable_verified_ledger(self) -> None:
        """Long-running agents: trust decisions use an index built from a *fully verified* scan of the chain,
        kept up to date incrementally - a record inserted or edited in the DB later cannot influence them."""
        with self._lock:
            self._ledger = {}
            self._lv = {"seq": 0, "hash": GENESIS, "next_pub": None}
            self._ledger_refresh()

    def _ledger_refresh(self) -> None:
        lv = self._lv
        while True:
            rows = self.query("SELECT *, id AS seq FROM audit WHERE id > ? ORDER BY id LIMIT 2000", (lv["seq"],))
            if not rows:
                return
            for r in rows:
                ok = (audit_hash(r, r.get("prev_hash") or "") == r.get("hash")
                      and self.keys.audit_mac(r.get("hash") or "") == r.get("mac")
                      and r.get("prev_hash") == lv["hash"])
                if ok and int(r.get("v") or 1) >= 2:
                    ok = verify_signature(r.get("pub") or "", r["hash"], r.get("sig") or "")
                    if ok and lv["next_pub"] and r.get("pub") != lv["next_pub"]:
                        # not signed by the key its predecessor committed to: a re-signed (rewritten) record,
                        # or the first record after a lost key - never trusted for decisions (fail closed)
                        ok = False
                if not ok:
                    self._after_or_now(lambda s=r["seq"]: self.report_violation(
                        "audit", f"record:{s}", "audit record fails verification - ignored for trust decisions"))
                elif r.get("ref_kind"):
                    self._index_ref(r)
                lv.update(seq=int(r["seq"]), hash=r.get("hash") or "",
                          next_pub=r.get("next_pub") if int(r.get("v") or 1) >= 2 else lv["next_pub"])

    def _after_or_now(self, fn: Callable[[], None]) -> None:
        if self._depth:
            self._after_commit.append(fn)
        else:
            fn()

    def _index_ref(self, r: Dict[str, Any]) -> None:
        assert self._ledger is not None
        seq = int(r["seq"])
        if r["ref_id"] == "*":
            try:
                part = json.loads(r["details"] or "{}").get("batch") or []
            except ValueError:
                return
            for ident, digest in part:
                self._ledger[(r["ref_kind"], str(ident))] = (seq, digest)
        else:
            self._ledger[(r["ref_kind"], r["ref_id"])] = (seq, r["ref_digest"])

    def ledger_digest(self, kind: str, ident: Any) -> Optional[str]:
        """Digest of the row as last recorded in the signed chain (None = never recorded)."""
        ident = str(ident)
        with self._lock:
            if self._ledger is not None:
                self._ledger_refresh()
                hit = self._ledger.get((kind, ident))
                return hit[1] if hit else None
            for rec in self.query("SELECT *, id AS seq FROM audit WHERE ref_kind = ? AND ref_id IN (?, '*') "
                                  "ORDER BY id DESC", (kind, ident)):
                if not self._record_trusted(rec):
                    continue
                if rec["ref_id"] != "*":
                    return rec["ref_digest"]
                try:
                    part = dict((str(a), b) for a, b in json.loads(rec["details"] or "{}").get("batch") or [])
                except ValueError:
                    continue
                if ident in part:
                    return part[ident]
            return None

    def ledger_state(self, kind: str, row: Dict[str, Any]) -> str:
        """'ok' | 'tampered' (row differs from what the agent recorded) | 'unrecorded' (row inserted behind
        the agent's back)."""
        table, col = LEDGER_TABLES[kind]
        d = self.ledger_digest(kind, row[col])
        if d is None:
            return "unrecorded"
        return "ok" if d == self.row_digest(kind, row) else "tampered"

    def ledger_states(self, kind: str, rows: List[Dict[str, Any]]) -> Dict[str, str]:
        return {str(r[LEDGER_TABLES[kind][1]]): self.ledger_state(kind, r) for r in rows}

    def verify_ledger(self) -> List[Dict[str, Any]]:
        """Every row of every ledgered table against a fresh, fully verified index: edited, inserted and
        deleted rows."""
        saved = (self._ledger, dict(self._lv))
        try:
            self.enable_verified_ledger()
            index = dict(self._ledger or {})
        finally:
            if saved[0] is None:
                self._ledger, self._lv = None, {}
        problems: List[Dict[str, Any]] = []
        for kind, (table, col) in LEDGER_TABLES.items():
            seen = set()
            for r in self.query(f"SELECT * FROM {table}"):
                ident = str(r[col])
                seen.add(ident)
                hit = index.get((kind, ident))
                if hit is None:
                    problems.append({"seq": None, "problem": f"{kind} {ident}: row not recorded by the agent "
                                                             f"(inserted outside El Doctor)"})
                elif hit[1] != self.row_digest(kind, r):
                    problems.append({"seq": hit[0], "problem": f"{kind} {ident}: row was modified after the agent "
                                                               f"recorded it"})
            for (k, ident), (seq, _) in index.items():
                if k == kind and ident not in seen:
                    problems.append({"seq": seq, "problem": f"{kind} {ident}: row recorded by the agent was deleted"})
        return problems

    # ------------------------------------------------------------------ violations
    def report_violation(self, kind: str, ident: str, reason: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Record an integrity failure once (audit + listeners, e.g. critical notification to the SOC)."""
        key = (kind, str(ident), reason)
        if key in self._reported:
            return
        self._reported.add(key)
        ev = {"kind": kind, "id": str(ident), "reason": reason, **(details or {})}
        try:
            self.audit("agent", "integrity_violation", ev)
        except Exception:
            pass

        def fire() -> None:
            for cb in list(self.violation_listeners):
                try:
                    cb(ev)
                except Exception:
                    pass
        if self._depth:             # never notify (network I/O) while holding the database write lock
            self._after_commit.append(fire)
        else:
            fire()

    # ------------------------------------------------------------------ alerts
    def add_alert(self, alert) -> None:
        d = alert.to_dict()
        p = alert.process or {}
        with self.tx():
            self.execute(
                "INSERT OR REPLACE INTO alerts (id, ts, rule_id, title, severity, source, mitre, pid, process_name,"
                " remote_ip, data) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (alert.id, alert.timestamp, alert.rule_id, alert.title, alert.severity, alert.source,
                 ",".join(alert.mitre), p.get("pid"), p.get("name"), alert.remote_ip, json.dumps(d, default=str)),
            )
            self._ledger_write("alert", alert.id, summary={"rule_id": alert.rule_id, "severity": alert.severity})

    def list_alerts(self, limit: int = 50, since: float = 0) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?", (since, limit))

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        rows = self.query("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return rows[0] if rows else None

    # ------------------------------------------------------------------ actions
    def add_action(self, result, alert_id: str = "", playbook_id: str = "", mode: str = "", actor: str = "agent") -> None:
        with self.tx():
            cur = self.execute(
                "INSERT INTO actions (ts, alert_id, playbook_id, action, target, status, message, mode, actor, details)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (result.timestamp, alert_id, playbook_id, result.action, result.target, result.status,
                 result.message, mode, actor, json.dumps(result.details, default=str)),
            )
            row = dict(self.conn.execute("SELECT * FROM actions WHERE id = ?", (cur.lastrowid,)).fetchone())
            ref = ("action", str(row["id"]), self.row_digest("action", row))
            # accountability for automated / approved containment (manual actions are audited as manual_*);
            # the same chained record is the ledger entry of the action row
            if result.action in AUDITED_ACTIONS and result.status in AUDITED_STATUSES and playbook_id != "manual":
                self.audit(actor, "response_action", {"action": result.action, "status": result.status,
                                                      "target": result.target, "message": result.message,
                                                      "alert_id": alert_id, "playbook": playbook_id, "mode": mode},
                           ref=ref)
            else:
                self.audit(actor, "action_recorded", {"action": result.action, "status": result.status}, ref=ref)

    def list_actions(self, limit: int = 50, alert_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if alert_id:
            return self.query("SELECT * FROM actions WHERE alert_id = ? ORDER BY id", (alert_id,))
        return self.query("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------ approvals
    @staticmethod
    def _approval_req_fields(r: Dict[str, Any]) -> list:
        return [r["id"], float(r["ts"] or 0), float(r["expires"] or 0), r["alert_id"], r["playbook_id"],
                int(r["step_index"] or 0), r["summary"], r["alert"], r.get("entity") or ""]

    @staticmethod
    def _approval_dec_fields(r: Dict[str, Any]) -> list:
        return [r["id"], r.get("req_mac") or "", r["status"], r.get("decided_by") or "",
                float(r.get("decided_ts") or 0), r.get("decided_os_user") or ""]

    def create_approval(self, alert, playbook_id: str, step_index: int, summary: str, timeout: float) -> str:
        aid = uuid.uuid4().hex[:8]
        now = time.time()
        row = {"id": aid, "ts": now, "expires": now + timeout, "alert_id": alert.id, "playbook_id": playbook_id,
               "step_index": int(step_index), "summary": summary,
               "alert": json.dumps(alert.to_dict(), default=str), "entity": entity_key(alert)}
        req = self.keys.seal("approval_request", self._approval_req_fields(row))
        with self.tx() as c:
            c.execute("INSERT INTO approvals (id, ts, expires, alert_id, playbook_id, step_index, summary, alert, status,"
                      " entity, req_mac) VALUES (?,?,?,?,?,?,?,?, 'pending', ?, ?)",
                      (aid, now, row["expires"], alert.id, playbook_id, int(step_index), summary, row["alert"],
                       row["entity"], req))
            self._ledger_write("approval", aid, summary={"id": aid, "playbook": playbook_id, "step": int(step_index),
                                                         "summary": summary, "alert_id": alert.id})
        return aid

    def pending_for_entity(self, entity: str, playbook_id: str) -> Optional[str]:
        rows = self.query("SELECT * FROM approvals WHERE status = 'pending' AND entity = ? AND playbook_id = ?"
                          " AND expires >= ?", (entity, playbook_id, time.time()))
        for r in rows:
            if self.keys.check_seal("approval_request", self._approval_req_fields(r), r.get("req_mac")):
                return r["id"]
        return None

    def approval_integrity(self, r: Dict[str, Any]) -> str:
        """'ok' | 'invalid' - cheap seal check for listings (full verification: verify_approval)."""
        if not self.keys.check_seal("approval_request", self._approval_req_fields(r), r.get("req_mac")):
            return "invalid"
        if self.ledger_state("approval", r) != "ok":
            return "invalid"
        if r["status"] != "pending" and not self.keys.check_seal("approval_decision", self._approval_dec_fields(r),
                                                                 r.get("dec_mac")):
            return "invalid"
        return "ok"

    def list_approvals(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if status:
            rows = self.query("SELECT * FROM approvals WHERE status = ? ORDER BY ts DESC LIMIT ?", (status, limit))
        else:
            rows = self.query("SELECT * FROM approvals ORDER BY ts DESC LIMIT ?", (limit,))
        for r in rows:
            r["integrity"] = self.approval_integrity(r)
        if status == "pending":            # never offer a forged request to an approver
            rows = [r for r in rows if r["integrity"] == "ok"]
        return rows

    def get_approval(self, aid: str) -> Optional[Dict[str, Any]]:
        rows = self.query("SELECT * FROM approvals WHERE id = ?", (aid,))
        return rows[0] if rows else None

    def decide_approval(self, aid: str, approved: bool, actor: str) -> bool:
        """Record an analyst decision: status + decision seal + chained audit record, atomically.

        Only the agent calls this (API method approvals.decide, after the role check); a decision that
        lacks any of the three is rejected when the agent processes approvals."""
        now = time.time()
        status = "approved" if approved else "denied"
        origin = current_origin()
        with self.tx() as c:
            r = c.execute("SELECT * FROM approvals WHERE id = ?", (aid,)).fetchone()
            if not r or r["status"] != "pending" or r["expires"] < now:
                return False
            r = dict(r)
            if not self.keys.check_seal("approval_request", self._approval_req_fields(r), r.get("req_mac")) or \
                    self.ledger_state("approval", r) != "ok":
                self.report_violation("approval", aid, "approval request was not created by the agent or was modified")
                return False
            r.update(status=status, decided_by=actor, decided_ts=now, decided_os_user=origin.os_user)
            dec = self.keys.seal("approval_decision", self._approval_dec_fields(r))
            c.execute("UPDATE approvals SET status = ?, decided_by = ?, decided_ts = ?, decided_os_user = ?, dec_mac = ?"
                      " WHERE id = ? AND status = 'pending'", (status, actor, now, origin.os_user, dec, aid))
            self.audit(actor, "approval_decided", {"id": aid, "decision": status, "summary": r["summary"],
                                                   "dec_mac": dec})
        return True

    def expire_approvals(self) -> List[Dict[str, Any]]:
        now = time.time()
        out = []
        with self.tx() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM approvals WHERE status = 'pending' AND expires < ?", (now,)).fetchall()]
            for r in rows:
                r.update(status="expired", decided_by="", decided_ts=now, decided_os_user="")
                dec = self.keys.seal("approval_decision", self._approval_dec_fields(r))
                c.execute("UPDATE approvals SET status = 'expired', decided_by = '', decided_ts = ?, decided_os_user = '',"
                          " dec_mac = ? WHERE id = ? AND status = 'pending'", (now, dec, r["id"]))
                self.audit("agent", "approval_expired", {"id": r["id"], "decision": "expired", "dec_mac": dec})
                out.append(r)
        return out

    def undecided_outcomes(self) -> List[Dict[str, Any]]:
        """Approved / denied / expired approvals the agent has not acted on yet (status column is NOT trusted)."""
        return self.query("SELECT * FROM approvals WHERE status IN ('approved','denied','expired') AND executed = 0"
                          " ORDER BY decided_ts")

    def _decision_record(self, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for a in self.query("SELECT *, id AS seq FROM audit WHERE event IN (?, ?) AND details LIKE ? ORDER BY id",
                            (*DECISION_EVENTS, f'%"{r["id"]}"%')):
            try:
                d = json.loads(a["details"] or "{}")
            except ValueError:
                continue
            if d.get("id") == r["id"] and d.get("decision") == r["status"] and d.get("dec_mac") == r.get("dec_mac"):
                return a
        return None

    def audit_record_ok(self, rec: Dict[str, Any]) -> bool:
        """One record: content matches its hash, the agent's MAC, and it is linked into the chain."""
        h = audit_hash(rec, rec.get("prev_hash") or "")
        if h != rec.get("hash") or self.keys.audit_mac(h) != rec.get("mac"):
            return False
        nxt = self.query("SELECT prev_hash FROM audit WHERE id = ?", (int(rec["seq"]) + 1,))
        if nxt:
            return nxt[0]["prev_hash"] == h
        head = self.meta_get("audit_head") or {}
        return head.get("seq") == int(rec["seq"]) and head.get("hash") == h

    def verify_approval(self, r: Dict[str, Any],
                        approver_ok: Optional[Callable[[str], Tuple[bool, str]]] = None) -> Tuple[bool, List[str]]:
        """Full check before the agent acts on an approval outcome. Returns (ok, reasons)."""
        why: List[str] = []
        if not self.keys.check_seal("approval_request", self._approval_req_fields(r), r.get("req_mac")):
            why.append("request seal invalid: the approval was not created by the agent or its alert/step was edited")
        elif self.ledger_state("approval", r) != "ok":
            why.append("request does not match the one recorded in the signed audit chain")
        if not self.keys.check_seal("approval_decision", self._approval_dec_fields(r), r.get("dec_mac")):
            why.append("decision seal invalid: the decision was not recorded by the agent")
        dts = float(r.get("decided_ts") or 0)
        if not (float(r["ts"] or 0) <= dts <= float(r["expires"] or 0) + 1) and r["status"] != "expired":
            why.append("decision time outside the approval window")
        if r["status"] == "approved":
            if approver_ok:
                ok, reason = approver_ok(r.get("decided_by") or "")
                if not ok:
                    why.append(f"approver not authorised: {reason}")
            if self.query("SELECT 1 FROM audit WHERE event = 'approval_executed' AND details LIKE ?",
                          (f'%"id": "{r["id"]}"%',)):
                why.append("replay: this approval was already executed")
        rec = self._decision_record(r)
        if rec is None:
            why.append("no matching decision record in the audit trail")
        elif not self.audit_record_ok(rec):
            why.append("the decision's audit record fails hash-chain verification")
        return not why, why

    def mark_executed(self, r: Dict[str, Any]) -> bool:
        with self.tx() as c:
            cur = c.execute("UPDATE approvals SET executed = 1 WHERE id = ? AND executed = 0", (r["id"],))
            if cur.rowcount != 1:
                return False
            if r["status"] == "approved":
                self.audit("agent", "approval_executed", {"id": r["id"], "approved_by": r.get("decided_by"),
                                                          "playbook": r["playbook_id"], "step": r["step_index"]})
        return True

    def reject_approval(self, r: Dict[str, Any], reasons: List[str]) -> None:
        with self.tx() as c:
            c.execute("UPDATE approvals SET status = 'rejected', executed = 1 WHERE id = ?", (r["id"],))
        self.report_violation("approval", r["id"], "forged or tampered approval refused",
                              {"claimed_status": r["status"], "claimed_by": r.get("decided_by"), "reasons": reasons,
                               "summary": r.get("summary")})

    # ------------------------------------------------------------------ users (sealed role / status / credentials)
    @staticmethod
    def _user_fields(r: Dict[str, Any]) -> list:
        return [int(r["id"]), r["username"], r["role"], int(r["active"] or 0), r.get("password_hash") or "",
                r.get("api_key_hash") or "", int(r.get("token_version") or 0)]

    def _reseal_user(self, r: Dict[str, Any], ledger: bool = True) -> None:
        with self.tx():
            self.execute("UPDATE users SET seal = ? WHERE id = ?", (self.keys.seal("user", self._user_fields(r)), r["id"]))
            if ledger:
                self._ledger_write("user", r["id"], summary={"username": r["username"], "role": r["role"],
                                                             "active": bool(r["active"])})

    def reseal_user(self, user_id: int) -> None:
        with self.tx() as c:
            r = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if r:
                self._reseal_user(dict(r))

    def user_row_ok(self, r: Dict[str, Any]) -> bool:
        """HMAC seal (fast) *and* the row as last recorded in the signed chain: a key holder who recomputes
        the seal still cannot rewrite the chain's history."""
        ok = self.keys.check_seal("user", self._user_fields(r), r.get("seal")) and \
            self.ledger_state("user", r) == "ok"
        if not ok:
            self.report_violation("user", r.get("username"), "user record (role / status / credentials) was modified "
                                                             "outside the agent", {"role_in_db": r.get("role")})
        return ok

    # ------------------------------------------------------------------ tokens
    def revoke_token(self, jti: str, exp: float) -> None:
        now = time.time()
        with self.tx() as c:
            c.execute("DELETE FROM revoked_tokens WHERE exp < ?", (now,))
            c.execute("INSERT OR REPLACE INTO revoked_tokens (jti, exp) VALUES (?,?)", (jti, exp))

    def token_revoked(self, jti: str) -> bool:
        return bool(self.query("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)))

    # ------------------------------------------------------------------ blocks
    @staticmethod
    def _block_fields(r: Dict[str, Any]) -> list:
        return [r["ip"], float(r["ts"] or 0), float(r["expires"] or 0), r.get("reason") or "", r.get("alert_id") or "",
                r.get("backend") or "", int(r.get("active") or 0)]

    def _block_seal(self, r: Dict[str, Any]) -> str:
        return self.keys.seal("block", self._block_fields(r))

    def add_block(self, ip: str, ttl_s: float, reason: str, alert_id: str, backend: str) -> None:
        now = time.time()
        r = {"ip": ip, "ts": now, "expires": now + ttl_s if ttl_s else 0, "reason": reason, "alert_id": alert_id,
             "backend": backend, "active": 1}
        with self.tx():
            self.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, ts, expires, reason, alert_id, backend, active, seal)"
                " VALUES (?,?,?,?,?,?,1,?)", (ip, now, r["expires"], reason, alert_id, backend, self._block_seal(r)))
            self._ledger_write("block", ip, summary={"ip": ip, "active": True, "backend": backend})

    def active_blocks(self) -> List[Dict[str, Any]]:
        """Only blocks the agent itself created: a forged row would make the agent kill every process that
        talks to an arbitrary IP."""
        out = []
        for r in self.query("SELECT * FROM blocked_ips WHERE active = 1 ORDER BY ts DESC"):
            if self.keys.check_seal("block", self._block_fields(r), r.get("seal")) and \
                    self.ledger_state("block", r) == "ok":
                out.append(r)
            else:
                self.report_violation("block", r["ip"], "IP block not created by the agent - ignored")
        return out

    def deactivate_block(self, ip: str) -> None:
        with self.tx() as c:
            r = c.execute("SELECT * FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
            if r:
                r = dict(r, active=0)
                c.execute("UPDATE blocked_ips SET active = 0, seal = ? WHERE ip = ?", (self._block_seal(r), ip))
                self._ledger_write("block", ip, summary={"ip": ip, "active": False})

    # ------------------------------------------------------------------ quarantine
    @staticmethod
    def _quarantine_fields(r: Dict[str, Any]) -> list:
        return [r["id"], float(r["ts"] or 0), r["original_path"], r["stored_path"], r["sha256"], int(r["size"] or 0),
                int(r["mode"] or 0), r.get("alert_id") or ""]

    def _quarantine_seal(self, r: Dict[str, Any]) -> str:
        return self.keys.seal("quarantine", self._quarantine_fields(r))

    def add_quarantine(self, rec: Dict[str, Any]) -> None:
        r = {"id": rec["id"], "ts": time.time(), "original_path": rec["original_path"],
             "stored_path": rec["stored_path"], "sha256": rec["sha256"], "size": rec["size"], "mode": rec["mode"],
             "alert_id": rec.get("alert_id", "")}
        with self.tx():
            self.execute(
                "INSERT INTO quarantine (id, ts, original_path, stored_path, sha256, size, mode, alert_id, seal)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (r["id"], r["ts"], r["original_path"], r["stored_path"], r["sha256"], r["size"], r["mode"],
                 r["alert_id"], self._quarantine_seal(r)))
            self._ledger_write("quarantine", r["id"], summary={"id": r["id"], "sha256": r["sha256"]})

    def list_quarantine(self) -> List[Dict[str, Any]]:
        rows = self.query("SELECT * FROM quarantine ORDER BY ts DESC")
        for r in rows:
            r["integrity"] = "ok" if self.keys.check_seal("quarantine", self._quarantine_fields(r), r.get("seal")) \
                and self.ledger_state("quarantine", r) == "ok" else "invalid"
        return rows

    def quarantine_record(self, qid: str) -> Optional[Dict[str, Any]]:
        """A quarantine record the agent may act on (restore writes files as the service account)."""
        rows = self.query("SELECT * FROM quarantine WHERE id = ?", (qid,))
        if not rows:
            return None
        r = rows[0]
        if not self.keys.check_seal("quarantine", self._quarantine_fields(r), r.get("seal")) or \
                self.ledger_state("quarantine", r) != "ok":
            self.report_violation("quarantine", qid, "quarantine record was modified outside the agent")
            r["integrity"] = "invalid"
        else:
            r["integrity"] = "ok"
        return r

    def mark_restored(self, qid: str) -> None:
        with self.tx():
            self.execute("UPDATE quarantine SET restored = 1 WHERE id = ?", (qid,))
            self._ledger_write("quarantine", qid, summary={"id": qid, "restored": True})

    # ------------------------------------------------------------------ audit (hash chain)
    def audit(self, actor: str, event: str, details: Any = None,
              ref: Optional[Tuple[str, str, str]] = None) -> Dict[str, Any]:
        """Append one record to the hash chain (atomic with the caller's transaction, if any).

        The record is signed with the one-time key whose public half the previous record committed to
        (``next_pub``); it commits to a fresh key for the next record, and the used key is destroyed
        after the commit.  ``ref`` = (kind, id, digest) makes the record a ledger entry for a table row."""
        o = current_origin()
        rec = {"ts": time.time(), "actor": str(actor), "event": str(event),
               "details": json.dumps(details, default=str) if details is not None else "",
               "os_user": o.os_user, "os_uid": o.os_uid, "os_pid": int(o.os_pid or 0), "client": o.client,
               "host": HOSTNAME, "v": 2, "ref_kind": ref[0] if ref else "", "ref_id": ref[1] if ref else "",
               "ref_digest": ref[2] if ref else ""}
        outermost = self._depth == 0
        with self.tx() as c:
            tail = c.execute("SELECT id, hash, v, next_pub FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            seq, prev = ((tail["id"] + 1), (tail["hash"] or "")) if tail else (1, GENESIS)
            expected = (tail["next_pub"] or None) if tail else None
            # The sealed head pointer is updated in the same transaction as every append, so a mismatch here
            # means records were removed or rewritten behind the agent's back. Keep numbering after the head so
            # the hole stays visible forever, instead of silently re-chaining onto a truncated tail.
            head, head_ok = self._meta_checked("audit_head")
            problems: List[str] = []
            if head is not None and not head_ok:
                problems.append("audit head pointer was modified outside the agent")
            elif head is not None and int(head.get("seq") or 0) > (tail["id"] if tail else 0):
                problems.append(f"audit records {(tail['id'] + 1) if tail else 1}..{head['seq']} were deleted from "
                                f"the end of the trail")
                seq, prev = int(head["seq"]) + 1, str(head.get("hash") or "")
                expected = head.get("next_pub") or expected
            elif head is not None and tail is not None and (head.get("seq") != tail["id"] or
                                                           head.get("hash") != tail["hash"]):
                problems.append("the last audit record does not match the sealed head pointer")
            elif head is None and tail is not None and self._meta_checked("integrity_epoch")[0] is not None:
                problems.append("audit head pointer is missing")
            # forward-secure signing key: only the key committed by the previous record may sign this one
            if outermost:        # inside a larger transaction a rollback may still need the committed tail's key
                self.signer.cleanup(keep=expected or "")
            sk = self.signer.load(expected) if expected else None
            if sk is None:
                if expected:
                    problems.append(f"the signing key committed for record {seq} ({fingerprint(expected)}) is "
                                    f"missing - the signing-key chain restarts here")
                sk, expected = self.signer.new_key()
                if not tail or not tail["next_pub"]:
                    self.meta_set("audit_genesis", {"seq": seq, "pub": expected})
            _, next_pub = self.signer.new_key()
            rec.update(seq=seq, prev_hash=prev, pub=expected, next_pub=next_pub)
            rec["hash"] = audit_hash(rec, prev)
            rec["sig"] = self.signer.sign(sk, rec["hash"])
            rec["mac"] = self.keys.audit_mac(rec["hash"])
            c.execute("INSERT INTO audit (id, ts, actor, event, details, os_user, os_uid, os_pid, client, host, prev_hash,"
                      " hash, mac, v, pub, next_pub, sig, ref_kind, ref_id, ref_digest)"
                      " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (seq, rec["ts"], rec["actor"], rec["event"], rec["details"], rec["os_user"], rec["os_uid"],
                       rec["os_pid"], rec["client"], rec["host"], prev, rec["hash"], rec["mac"], 2, expected,
                       next_pub, rec["sig"], rec["ref_kind"], rec["ref_id"], rec["ref_digest"]))
            self.meta_set("audit_head", {"seq": seq, "hash": rec["hash"], "next_pub": next_pub})
            used = expected
            self._after_commit.append(lambda: self.signer.destroy(used))     # forward security
            if event != "integrity_violation":
                for pr in problems:
                    self._after_commit.append(lambda p=pr: self.report_violation("audit", "chain", p))
            for cb in self.audit_listeners:
                self._after_commit.append(lambda cb=cb, rec=dict(rec): cb(rec))
        return rec

    def list_audit(self, limit: int = 100, include_bookkeeping: bool = False) -> List[Dict[str, Any]]:
        if include_bookkeeping:
            return self.query("SELECT *, id AS seq FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        marks = ",".join("?" * len(BOOKKEEPING_EVENTS))
        return self.query(f"SELECT *, id AS seq FROM audit WHERE event NOT IN ({marks}) ORDER BY id DESC LIMIT ?",
                          (*BOOKKEEPING_EVENTS, limit))

    def audit_after(self, seq: int, limit: int = 500) -> List[Dict[str, Any]]:
        return self.query("SELECT *, id AS seq FROM audit WHERE id > ? ORDER BY id LIMIT ?", (seq, limit))

    def audit_head(self) -> Dict[str, Any]:
        return self.meta_get("audit_head") or {"seq": 0, "hash": GENESIS}

    def verify_audit(self, chunk: int = 5000, genesis_pin: str = "") -> Dict[str, Any]:
        """Walk the whole chain and the ledgered tables.

        Chain: modified / inserted / deleted / truncated records, MACs, Ed25519 signatures, signing-key
        continuity (a rewrite must break a destroyed key's signature somewhere) and, if ``genesis_pin`` is
        given, that the chain still starts from the key fingerprint recorded off-host.
        Ledger: every alert, action, user, block, quarantine and approval-request row against the digest
        the agent recorded in the signed chain (edited, inserted, deleted rows)."""
        problems: List[Dict[str, Any]] = []
        prev, seq, checked, last = GENESIS, 1, 0, 0
        next_pub, genesis, signed = None, None, 0
        while True:
            rows = self.query("SELECT *, id AS seq FROM audit WHERE id >= ? ORDER BY id LIMIT ?", (last + 1, chunk))
            if not rows:
                break
            res = verify_records(rows, self.keys, prev_hash=prev, first_seq=seq, prev_next_pub=next_pub,
                                 genesis_seen=genesis is not None)
            problems += res["problems"]
            checked += res["checked"]
            signed += sum(1 for r in rows if int(r.get("v") or 1) >= 2)
            genesis = genesis or res["genesis"]
            prev, seq, last, next_pub = res["last_hash"], res["last_seq"] + 1, int(rows[-1]["seq"]), res["last_next_pub"]
        head = self.meta_get("audit_head")
        if head is None and checked:
            problems.append({"seq": None, "problem": "chain head pointer missing or modified"})
        elif head and (head.get("seq") != seq - 1 or head.get("hash") != prev):
            if int(head.get("seq") or 0) > seq - 1:
                problems.append({"seq": seq, "problem": f"records {seq}..{head.get('seq')} were deleted from the end "
                                                        f"of the trail (truncation)"})
            else:
                problems.append({"seq": head.get("seq"), "problem": "chain head does not match the last record"})
        gfp = fingerprint(genesis) if genesis else ""
        if genesis_pin and gfp != genesis_pin:
            problems.append({"seq": None, "problem": f"the chain starts from signing key {gfp or 'none'}, not from the "
                                                     f"pinned {genesis_pin} - the whole chain was rebuilt"})
        if next_pub and not self.signer.load(next_pub) and checked:
            problems.append({"seq": None, "problem": "the key committed for the next record is missing (the next "
                                                     "append will restart the signing-key chain)"})
        problems += self.verify_ledger()
        problems += [{"seq": None, "problem": p} for p in self.integrity_problems]
        return {"ok": not problems, "checked": checked, "signed": signed, "head": {"seq": seq - 1, "hash": prev},
                "genesis": gfp, "legacy_upto": self.meta_get("audit_legacy_upto") or 0, "kid": self.keys.kid,
                "problems": problems}
