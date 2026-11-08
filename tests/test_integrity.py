"""Tamper resistance of the data the agent acts on (docs/PRODUCTION_READINESS.md P0-1).

The attacker in these tests edits eldoctor.db with a *separate* sqlite3 connection, exactly like a
user with write access to the file would - the agent must not trust anything it did not write itself.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

import pytest

from eldoctor.agent import Agent
from eldoctor.auth.users import AuthError, UserManager
from eldoctor.collectors.processes import process_info_from_pid
from eldoctor.models import Alert
from eldoctor.storage import Store

PW = "Str0ng!Passw0rd"


def raw(store):
    """The attacker's own connection to the database file."""
    c = sqlite3.connect(str(store.path), isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


@pytest.fixture
def victim():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    yield p
    if p.poll() is None:
        p.kill()
    p.wait()


@pytest.fixture
def people(store, cfg):
    um = UserManager(store, cfg)
    admin, _ = um.register("admin1", PW, "a@x.io")
    analyst, _ = um.register("ana", "An4lyst!Passw0rd", "b@x.io", role="analyst", created_by=admin)
    mallory, _ = um.register("mallory", "M4llory!Passw0rd", "m@x.io")          # self-registered: viewer
    return um, admin, analyst, mallory


def pending_for(agent, victim):
    alert = Alert(rule_id="ED-RES-001", title="hog", severity="high", mitre=["T1496"],
                  process=process_info_from_pid(victim.pid).to_dict())
    run = agent.playbooks.handle(alert)[0]
    assert run["status"] == "awaiting_approval"
    return run["approval_id"]


def violations(store, kind=None):
    out = []
    for r in store.query("SELECT details FROM audit WHERE event = 'integrity_violation'"):
        d = json.loads(r["details"])
        if kind is None or d["kind"] == kind:
            out.append(d)
    return out


# ------------------------------------------------------------------ approvals
def test_p0_1_forged_approval_is_refused_and_raised(cfg, store, people, victim):
    """The exact audit finding: a viewer writes status='approved', decided_by='admin1' into the DB."""
    um, admin, _, mallory = people
    assert not mallory.can("approve")
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        db = raw(store)
        db.execute("UPDATE approvals SET status='approved', decided_by='admin1', decided_ts=? WHERE id=?",
                   (time.time(), aid))
        agent.playbooks.process_approvals()
        time.sleep(0.5)
        assert victim.poll() is None, "the agent executed a forged approval"
        row = store.get_approval(aid)
        assert row["status"] == "rejected" and row["executed"] == 1
        v = violations(store, "approval")
        assert v and v[0]["claimed_by"] == "admin1" and any("decision seal" in r for r in v[0]["reasons"])
        alert = store.query("SELECT * FROM alerts WHERE rule_id = 'ED-INT-001'")
        assert alert and alert[0]["severity"] == "critical"
        # the forged decision is not in the audit trail as an admin decision
        assert not store.query("SELECT 1 FROM audit WHERE event='approval_decided'")
    finally:
        agent.dispatcher.close()


def test_forged_row_with_copied_mac_or_inserted_row_is_refused(cfg, store, people, victim, tmp_path):
    um, admin, _, _ = people
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        # a genuine decision on *another* approval gives the attacker a valid MAC to copy
        other = Alert(rule_id="ED-LOG-001", title="bf", severity="high", remote_ip="203.0.113.9")
        other_id = store.create_approval(other, "pb-brute-force", 0, "block", 300)
        assert store.decide_approval(other_id, False, "admin1")
        donor = store.get_approval(other_id)
        db = raw(store)
        db.execute("UPDATE approvals SET status='approved', decided_by='admin1', decided_ts=?, dec_mac=? WHERE id=?",
                   (donor["decided_ts"], donor["dec_mac"], aid))
        # ... and a completely new row, crafted to kill the victim's tree with the cryptominer playbook
        alert = json.dumps(Alert(rule_id="ED-IOC-003", title="x", severity="critical",
                                 process=process_info_from_pid(victim.pid).to_dict()).to_dict())
        db.execute("INSERT INTO approvals (id, ts, expires, alert_id, playbook_id, step_index, summary, alert, status,"
                   " decided_by, decided_ts, executed, entity) VALUES ('deadbeef', ?, ?, 'a1', 'pb-cryptominer', 0,"
                   " 'kill', ?, 'approved', 'admin1', ?, 0, 'x')", (time.time(), time.time() + 300, alert, time.time()))
        agent.playbooks.process_approvals()
        time.sleep(0.5)
        assert victim.poll() is None
        assert {store.get_approval(aid)["status"], store.get_approval("deadbeef")["status"]} == {"rejected"}
        assert "deadbeef" not in [a["id"] for a in store.list_approvals("pending")]
    finally:
        agent.dispatcher.close()


def test_edited_alert_in_pending_request_is_refused(cfg, store, people, victim):
    """Retargeting a genuine request (swap the process) breaks the request seal, even if an admin approves."""
    um, admin, _, _ = people
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        row = store.get_approval(aid)
        d = json.loads(row["alert"])
        d["process"]["pid"] = os.getppid()
        raw(store).execute("UPDATE approvals SET alert = ? WHERE id = ?", (json.dumps(d), aid))
        assert aid not in [a["id"] for a in store.list_approvals("pending")]     # never offered to an approver
        assert not store.decide_approval(aid, True, "admin1")                     # and the agent won't record it
        assert violations(store, "approval")
    finally:
        agent.dispatcher.close()


def test_approver_demoted_before_execution_is_refused(cfg, store, people, victim):
    """Authorisation is checked by the agent when it *acts*, not only when the button is pressed."""
    um, admin, analyst, _ = people
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        assert store.decide_approval(aid, True, "ana")
        um.set_role(admin, "ana", "viewer")
        agent.playbooks.process_approvals()
        time.sleep(0.5)
        assert victim.poll() is None and store.get_approval(aid)["status"] == "rejected"
        assert any("lacks the approve permission" in r for r in violations(store, "approval")[0]["reasons"])
    finally:
        agent.dispatcher.close()


def test_approved_containment_is_in_the_audit_chain(cfg, store, people, victim):
    """Who did what: the decision, its execution and the kill itself are chained audit records."""
    um, admin, analyst, _ = people
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        assert store.decide_approval(aid, True, "ana")
        agent.playbooks.process_approvals()
        victim.wait(timeout=10)
        events = [(r["event"], r["actor"]) for r in reversed(store.list_audit(50))]
        i = events.index(("approval_decided", "ana"))
        assert ("approval_executed", "agent") in events[i:]
        kill = next(json.loads(r["details"]) for r in store.list_audit(50) if r["event"] == "response_action"
                    and json.loads(r["details"])["action"] == "kill")
        assert kill["status"] == "success" and str(victim.pid) in kill["target"]
        assert store.verify_audit()["ok"]
    finally:
        agent.dispatcher.close()


def test_genuine_approval_executes_once_and_replay_is_refused(cfg, store, people, victim):
    um, admin, analyst, _ = people
    agent = Agent(cfg, store, admin, mode="interactive")
    try:
        aid = pending_for(agent, victim)
        assert store.decide_approval(aid, True, "ana")
        runs = agent.playbooks.process_approvals()
        assert runs and runs[0]["approved_by"] == "ana"
        victim.wait(timeout=10)
        ok, why = store.verify_approval(store.get_approval(aid))
        assert not ok and any("replay" in w for w in why)
        raw(store).execute("UPDATE approvals SET executed = 0 WHERE id = ?", (aid,))
        assert agent.playbooks.process_approvals() == []
        assert store.get_approval(aid)["status"] == "rejected"
    finally:
        agent.dispatcher.close()


# ------------------------------------------------------------------ users / roles
def test_role_edited_in_db_is_never_trusted(cfg, store, people):
    um, admin, _, mallory = people
    raw(store).execute("UPDATE users SET role='admin' WHERE username='mallory'")
    with pytest.raises(AuthError, match="integrity"):
        um.authenticate("mallory", "M4llory!Passw0rd")
    assert um.get("mallory") is None
    ok, why = um.can_approve("mallory")
    assert not ok
    assert violations(store, "user")[0]["id"] == "mallory"
    assert next(u for u in um.list() if u["username"] == "mallory")["integrity"] == "invalid"


def test_emptied_user_table_does_not_hand_out_admin(cfg, store, people):
    um = people[0]
    raw(store).execute("DELETE FROM users")
    with pytest.raises(AuthError, match="tampering"):
        um.register("eve", "Ev3!Passw0rd!!", "e@x.io")


# ------------------------------------------------------------------ blocks / quarantine
def test_forged_block_is_ignored(store):
    store.add_block("198.51.100.7", 3600, "real", "a1", "app-level")
    raw(store).execute("INSERT INTO blocked_ips (ip, ts, expires, reason, alert_id, backend, active) "
                       "VALUES ('8.8.8.8', 0, 0, 'forged', '', 'app-level', 1)")
    assert [b["ip"] for b in store.active_blocks()] == ["198.51.100.7"]
    assert violations(store, "block")[0]["id"] == "8.8.8.8"


def test_tampered_quarantine_record_is_not_restored(cfg, store, tmp_path):
    from eldoctor.playbooks.safety import SafetyGuard
    from eldoctor.response.actions import Responder
    vault = tmp_path / "stored"
    vault.write_bytes(b"payload")
    from eldoctor.collectors.processes import hash_file
    store.add_quarantine({"id": "q1", "original_path": str(tmp_path / "orig"), "stored_path": str(vault),
                          "sha256": hash_file(str(vault)), "size": 7, "mode": 0o644})
    raw(store).execute("UPDATE quarantine SET original_path = ? WHERE id = 'q1'", (str(tmp_path / "elsewhere"),))
    r = Responder(cfg, store, SafetyGuard(cfg)).restore("q1")
    assert r.status == "blocked" and "integrity" in r.message and not (tmp_path / "elsewhere").exists()


# ------------------------------------------------------------------ audit trail
def _fill(store, n=6):
    for i in range(n):
        store.audit("alice", "event_%d" % i, {"i": i})


def test_audit_chain_verifies_and_records_os_identity(store):
    _fill(store)
    res = store.verify_audit()
    assert res["ok"] and res["checked"] >= 7 and res["head"]["seq"] == res["checked"]
    r = store.list_audit(1)[0]
    assert r["os_uid"] == str(os.getuid()) and r["os_pid"] == os.getpid() and r["prev_hash"] and r["mac"]


@pytest.mark.parametrize("attack, expect", [
    ("UPDATE audit SET details = '{\"i\": 99}' WHERE id = 3", "modified"),
    ("UPDATE audit SET actor = 'admin1' WHERE id = 4", "modified"),
    ("DELETE FROM audit WHERE id = 3", "sequence gap"),
    ("DELETE FROM audit WHERE id >= 6", "truncation"),
    ("UPDATE meta SET value = '{}' WHERE key = 'audit_head'", "head"),
])
def test_audit_tampering_is_detected(store, attack, expect):
    _fill(store)
    raw(store).execute(attack)
    res = Store(store.path).verify_audit()
    assert not res["ok"] and any(expect in p["problem"] for p in res["problems"]), res["problems"]


def test_truncation_stays_visible_after_the_agent_writes_again(store):
    """Deleting the newest records must not be 'healed' by the next append re-chaining onto the shorter tail."""
    _fill(store)
    head = store.audit_head()["seq"]
    raw(store).execute("DELETE FROM audit WHERE id > ?", (head - 3,))
    store.audit("agent", "after_truncation", {})                 # the agent keeps working ...
    res = store.verify_audit()
    assert not res["ok"] and any("sequence gap" in p["problem"] for p in res["problems"]), res["problems"]
    assert store.list_audit(1)[0]["seq"] > head                    # ... numbering continues after the sealed head
    assert any("deleted from the end" in v["reason"] for v in violations(store, "audit"))


def test_rewritten_chain_without_the_key_is_detected(store):
    """An attacker who edits a record and recomputes every (public) hash still cannot produce the agent's MAC."""
    from eldoctor.integrity import audit_hash
    _fill(store)
    db = raw(store)
    rows = [dict(r) for r in db.execute("SELECT *, id AS seq FROM audit ORDER BY id")]
    rows[2]["details"] = '{"i": "forged"}'
    prev = rows[0]["prev_hash"]
    for r in rows:
        r["prev_hash"] = prev
        r["hash"] = audit_hash(r, prev)
        db.execute("UPDATE audit SET details=?, prev_hash=?, hash=? WHERE id=?", (r["details"], prev, r["hash"], r["seq"]))
        prev = r["hash"]
    res = Store(store.path).verify_audit()
    assert not res["ok"] and any("MAC" in p["problem"] for p in res["problems"])


def test_agent_raises_chain_break_as_incident(cfg, store):
    from eldoctor.api.server import AgentService
    _fill(store)
    raw(store).execute("UPDATE audit SET event = 'nothing_to_see' WHERE id = 2")
    svc = AgentService(cfg, store=store)
    res = svc.verify_audit()
    assert not res["ok"]
    assert store.query("SELECT 1 FROM alerts WHERE rule_id = 'ED-INT-001'")
    assert violations(store, "audit")
    svc.close()


# ------------------------------------------------------------------ upgrade / metadata
OLD_SCHEMA = """
CREATE TABLE approvals (id TEXT PRIMARY KEY, ts REAL, expires REAL, alert_id TEXT, playbook_id TEXT, step_index INTEGER,
    summary TEXT, alert TEXT, status TEXT, decided_by TEXT, decided_ts REAL, executed INTEGER DEFAULT 0, entity TEXT DEFAULT '');
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT, full_name TEXT,
    organization TEXT, role TEXT NOT NULL, use_case TEXT, deployment_target TEXT, password_hash TEXT,
    api_key_hash TEXT, created_at REAL, last_login REAL, active INTEGER DEFAULT 1,
    failed_logins INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, consent_share INTEGER DEFAULT 0);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER, created REAL, expires REAL);
CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, event TEXT, details TEXT);
"""


def test_pre_integrity_database_is_adopted_once(tmp_path, cfg):
    from eldoctor.auth.users import hash_password
    home = tmp_path / "legacy"
    home.mkdir()
    db = sqlite3.connect(str(home / "eldoctor.db"))
    db.executescript(OLD_SCHEMA)
    db.execute("INSERT INTO users (username, email, role, password_hash, active) VALUES ('old', 'o@x.io', 'admin', ?, 1)",
               (hash_password(PW),))
    for i in (1, 2, 5):                                                 # ids with a gap: renumbered on adoption
        db.execute("INSERT INTO audit (id, ts, actor, event, details) VALUES (?, ?, 'old', 'legacy', '')", (i, i))
    db.commit()
    db.close()
    store = Store(home / "eldoctor.db")
    res = store.verify_audit()
    # 3 legacy records + the ledger batch recording the existing user row + integrity_initialized
    assert res["ok"] and res["legacy_upto"] == 3 and res["checked"] == 5, res
    assert store.query("SELECT 1 FROM audit WHERE event='ledger_batch' AND ref_kind='user'")
    assert UserManager(store, cfg).authenticate("old", PW).role == "admin"
    store.close()
    again = Store(home / "eldoctor.db")                                      # no second adoption
    assert len(again.query("SELECT 1 FROM audit WHERE event='integrity_initialized'")) == 1
    again.close()


def test_removed_integrity_metadata_is_not_silently_resealed(store, cfg):
    UserManager(store, cfg).register("alice", PW, "a@x.io")
    raw(store).execute("DELETE FROM meta")
    s2 = Store(store.path)
    assert s2.integrity_problems and not s2.verify_audit()["ok"]
    assert s2.query("SELECT seal FROM users")[0]["seal"]                    # existing seals untouched
    s2.close()
