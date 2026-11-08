"""Turn 2 of the trust-boundary work: key theft must not allow rewriting history, and alerts / actions
are tamper-evident too.

The attacker here has read *every file of the data folder* - the HMAC master key and the current
one-time signing key included - i.e. what root or the service account could take.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


from eldoctor.auth.users import UserManager
from eldoctor.integrity import audit_hash, fingerprint, verify_signature
from eldoctor.models import ActionResult, Alert
from eldoctor.siem import as_json, verify_export
from eldoctor.storage import Store

PW = "Str0ng!Passw0rd"


def raw(store):
    c = sqlite3.connect(str(store.path), isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


def fill(store, n=8):
    for i in range(n):
        store.audit("alice", f"event_{i}", {"i": i})


def problems(res):
    return " | ".join(p["problem"] for p in res["problems"])


def attacker_rewrite(store, seq, **changes):
    """Edit a record and make it look perfect with everything the attacker has: recompute the hash and the
    HMAC (master key stolen) and re-sign it - with the only signing key left on disk, or a fresh one."""
    from eldoctor.integrity import SigningChain
    db = raw(store)
    r = dict(db.execute("SELECT *, id AS seq FROM audit WHERE id = ?", (seq,)).fetchone())
    r.update(changes)
    stolen = [p.stem for p in store.signer.dir.glob("*.key")]
    chain = SigningChain(store.keys.dir)
    sk = chain.load(stolen[0]) if stolen else None
    if sk is None:
        sk, pub = chain.new_key()
    else:
        pub = stolen[0]
    r["pub"] = pub
    r["hash"] = audit_hash(r, r["prev_hash"])
    r["mac"] = store.keys.audit_mac(r["hash"])
    r["sig"] = chain.sign(sk, r["hash"])
    db.execute("UPDATE audit SET details=?, actor=?, pub=?, hash=?, mac=?, sig=?, ref_digest=? WHERE id=?",
               (r["details"], r["actor"], r["pub"], r["hash"], r["mac"], r["sig"], r["ref_digest"], seq))
    nxt = db.execute("SELECT id FROM audit WHERE id = ?", (seq + 1,)).fetchone()
    if nxt:                                                     # re-link the successor too
        db.execute("UPDATE audit SET prev_hash = ? WHERE id = ?", (r["hash"], seq + 1))
    return r


# ------------------------------------------------------------------ forward-secure signatures
def test_every_record_is_signed_and_used_keys_are_destroyed(store):
    fill(store)
    rows = store.query("SELECT *, id AS seq FROM audit ORDER BY id")
    assert all(r["v"] == 2 and verify_signature(r["pub"], r["hash"], r["sig"]) for r in rows)
    for a, b in zip(rows, rows[1:]):
        assert b["pub"] == a["next_pub"]                        # each record signed by the key its predecessor named
    on_disk = {p.stem for p in store.signer.dir.glob("*.key")}
    assert on_disk == {rows[-1]["next_pub"]}                    # only the key for the *next* record exists
    assert not on_disk & {r["pub"] for r in rows}               # every used key is gone
    assert store.verify_audit()["ok"]


def test_stolen_keys_cannot_rewrite_history(store):
    """Master key + current signing key in hand, the attacker still cannot change a past record."""
    fill(store)
    attacker_rewrite(store, 3, details='{"i": "forged"}', actor="admin1")
    res = Store(store.path).verify_audit()
    assert not res["ok"] and "signing key does not continue" in problems(res), problems(res)


def test_keeping_the_committed_key_without_its_private_half_fails_the_signature(store):
    """Edit + recompute hash and HMAC, keep the expected public key: only the destroyed private key could sign."""
    fill(store)
    db = raw(store)
    r = dict(db.execute("SELECT *, id AS seq FROM audit WHERE id = 4").fetchone(), details='{"i": "forged"}')
    r["hash"] = audit_hash(r, r["prev_hash"])
    db.execute("UPDATE audit SET details=?, hash=?, mac=? WHERE id=4", (r["details"], r["hash"],
                                                                      store.keys.audit_mac(r["hash"])))
    db.execute("UPDATE audit SET prev_hash=? WHERE id=5", (r["hash"],))
    res = Store(store.path).verify_audit()
    assert not res["ok"] and "signature invalid" in problems(res), problems(res)
    assert "signature invalid" in problems(verify_export(
        [as_json(x) for x in store.query("SELECT *, id AS seq FROM audit ORDER BY id")]))


def test_rebuilding_the_whole_chain_changes_the_genesis(store):
    """Re-creating every record with new keys verifies locally - but not against the pinned genesis (and the
    SIEM copy has the original chain)."""
    from eldoctor.integrity import SigningChain
    fill(store, 4)
    pin = store.verify_audit()["genesis"]
    assert pin.startswith("ed25519:")
    db = raw(store)
    chain = SigningChain(store.keys.dir)
    prev, nxt_sk, nxt_pub = "0" * 64, None, None
    for r in [dict(x) for x in db.execute("SELECT *, id AS seq FROM audit ORDER BY id")]:
        sk, pub = (nxt_sk, nxt_pub) if nxt_sk else chain.new_key()
        nxt_sk, nxt_pub = chain.new_key()
        r.update(prev_hash=prev, pub=pub, next_pub=nxt_pub, actor="admin1")
        r["hash"] = audit_hash(r, prev)
        db.execute("UPDATE audit SET actor=?, prev_hash=?, pub=?, next_pub=?, hash=?, mac=?, sig=? WHERE id=?",
                   (r["actor"], prev, pub, nxt_pub, r["hash"], store.keys.audit_mac(r["hash"]),
                    chain.sign(sk, r["hash"]), r["seq"]))
        prev = r["hash"]
    store.meta_set("audit_head", {"seq": r["seq"], "hash": prev, "next_pub": nxt_pub})
    fresh = Store(store.path)
    assert fresh.verify_audit()["genesis"] != pin
    res = fresh.verify_audit(genesis_pin=pin)
    assert not res["ok"] and "pinned" in problems(res)


def test_a_lost_signing_key_is_an_incident(store):
    fill(store, 3)
    for f in store.signer.dir.glob("*.key"):
        f.unlink()
    store.audit("agent", "after_key_loss", {})
    res = store.verify_audit()
    assert not res["ok"] and "signing key does not continue" in problems(res)
    reasons = [json.loads(r["details"])["reason"] for r in store.query(
        "SELECT details FROM audit WHERE event = 'integrity_violation'")]
    assert any("is missing" in x for x in reasons)


def test_siem_copy_is_verifiable_without_any_secret(store):
    fill(store, 5)
    recs = [as_json(r) for r in store.query("SELECT *, id AS seq FROM audit ORDER BY id")]
    res = verify_export(recs)
    assert res["ok"] and res["genesis"] == store.verify_audit()["genesis"]
    assert verify_export(recs, genesis_pin=res["genesis"])["ok"]
    bad = [dict(r) for r in recs]
    bad[2]["sig"] = bad[1]["sig"]
    assert "signature invalid" in problems(verify_export(bad))
    assert "pinned" in problems(verify_export(recs, genesis_pin="ed25519:0000"))


def test_crash_between_commit_and_key_destruction_is_harmless(store):
    """A used key left behind (crash after commit) is destroyed by the next append; the chain stays valid."""
    fill(store, 2)
    used = store.query("SELECT pub FROM audit ORDER BY id DESC LIMIT 1")[0]["pub"]
    (store.signer.dir / f"{used}.key").write_text("00" * 32)            # pretend it survived
    store.audit("agent", "next", {})
    assert not (store.signer.dir / f"{used}.key").exists()
    assert store.verify_audit()["ok"]


# ------------------------------------------------------------------ ledger: alerts, actions, state rows
def test_alerts_and_actions_are_tamper_evident(store):
    a1 = Alert(rule_id="ED-RES-001", title="hog", severity="high")
    a2 = Alert(rule_id="ED-IOC-003", title="miner", severity="critical")
    store.add_alert(a1)
    store.add_alert(a2)
    store.add_action(ActionResult("kill", "success", "killed", "x[1]"), a1.id, "pb-resource-hog", "enforce", "agent")
    store.add_action(ActionResult("renice", "success", "reniced", "x[1]"), a1.id, "pb-resource-hog", "enforce", "agent")
    assert store.verify_audit()["ok"]
    db = raw(store)
    db.execute("UPDATE alerts SET severity = 'low' WHERE id = ?", (a1.id,))                  # downplay
    db.execute("UPDATE actions SET status = 'failed' WHERE action = 'kill'")                  # rewrite history
    db.execute("DELETE FROM alerts WHERE id = ?", (a2.id,))                                  # make it disappear
    db.execute("INSERT INTO actions (ts, action, status, message, actor) VALUES (1, 'kill', 'success', 'x', 'admin1')")
    res = Store(store.path).verify_audit()
    txt = problems(res)
    assert f"alert {a1.id}: row was modified" in txt
    assert f"alert {a2.id}: row recorded by the agent was deleted" in txt
    assert "row was modified" in txt and "action" in txt
    assert "not recorded by the agent (inserted" in txt
    fresh = Store(store.path)
    assert fresh.ledger_state("alert", fresh.get_alert(a1.id)) == "tampered"


def test_hmac_key_holder_cannot_promote_a_user(store, cfg):
    """With the master key the seal can be recomputed - the signed chain still says 'viewer'."""
    um = UserManager(store, cfg)
    um.register("owner", PW, "o@x.io")
    um.register("mallory", "M4llory!Passw0rd", "m@x.io")
    r = dict(store.query("SELECT * FROM users WHERE username = 'mallory'")[0], role="admin")
    raw(store).execute("UPDATE users SET role = 'admin', seal = ? WHERE id = ?",
                       (store.keys.seal("user", store._user_fields(r)), r["id"]))
    assert store.keys.check_seal("user", store._user_fields(r), store.keys.seal("user", store._user_fields(r)))
    for s in (Store(store.path), store):                       # fast path and a fresh verified index
        if s is not store:
            s.enable_verified_ledger()
        assert UserManager(s, cfg).get("mallory") is None


def test_key_holder_cannot_rewrite_the_ledger_record_either(store, cfg):
    """... and rewriting the user's ledger record in the chain to match is caught (destroyed key)."""
    um = UserManager(store, cfg)
    um.register("owner", PW, "o@x.io")
    um.register("mallory", "M4llory!Passw0rd", "m@x.io")
    r = dict(store.query("SELECT * FROM users WHERE username = 'mallory'")[0], role="admin")
    raw(store).execute("UPDATE users SET role = 'admin', seal = ? WHERE id = ?",
                       (store.keys.seal("user", store._user_fields(r)), r["id"]))
    led = store.query("SELECT id FROM audit WHERE ref_kind = 'user' AND ref_id = ? ORDER BY id DESC LIMIT 1",
                      (str(r["id"]),))[0]["id"]
    attacker_rewrite(store, led, ref_digest=store.row_digest("user", r))
    agent_view = Store(store.path)
    agent_view.enable_verified_ledger()
    assert UserManager(agent_view, cfg).get("mallory") is None
    assert UserManager(Store(store.path), cfg).get("mallory") is None
    assert not Store(store.path).verify_audit()["ok"]


def test_blocks_quarantine_and_approval_requests_need_the_ledger(store, cfg, tmp_path):
    from eldoctor.collectors.processes import hash_file
    store.add_block("198.51.100.7", 3600, "real", "a1", "app-level")
    fake = {"ip": "8.8.8.8", "ts": 0.0, "expires": 0.0, "reason": "forged", "alert_id": "", "backend": "app-level",
            "active": 1}
    raw(store).execute("INSERT INTO blocked_ips (ip, ts, expires, reason, alert_id, backend, active, seal) "
                       "VALUES ('8.8.8.8', 0, 0, 'forged', '', 'app-level', 1, ?)", (store._block_seal(fake),))
    assert [b["ip"] for b in store.active_blocks()] == ["198.51.100.7"]          # valid HMAC, not in the chain
    vault = tmp_path / "v"
    vault.write_bytes(b"x")
    store.add_quarantine({"id": "q1", "original_path": str(tmp_path / "o"), "stored_path": str(vault),
                          "sha256": hash_file(str(vault)), "size": 1, "mode": 0o644})
    q = dict(store.query("SELECT * FROM quarantine WHERE id='q1'")[0], original_path="/etc/cron.d/evil")
    raw(store).execute("UPDATE quarantine SET original_path = ?, seal = ? WHERE id = 'q1'",
                       (q["original_path"], store._quarantine_seal(q)))
    assert store.quarantine_record("q1")["integrity"] == "invalid"
    al = Alert(rule_id="ED-LOG-001", title="bf", severity="high", remote_ip="203.0.113.9")
    aid = store.create_approval(al, "pb-brute-force", 0, "block", 300)
    ap = dict(store.get_approval(aid), step_index=5)
    raw(store).execute("UPDATE approvals SET step_index = 5, req_mac = ? WHERE id = ?",
                       (store.keys.seal("approval_request", store._approval_req_fields(ap)), aid))
    assert not store.decide_approval(aid, True, "owner")


def test_api_and_cli_show_row_integrity(cfg, tmp_path):
    from eldoctor.api.client import ApiClient
    from eldoctor.api.peercred import own_identity
    from eldoctor.api.server import AgentService
    from eldoctor.api.transport import InProcessTransport
    svc = AgentService(cfg, role="service")
    try:
        c = ApiClient(InProcessTransport(svc.handle, own_identity(), "x"))
        c.token = None
        c.call("auth.register", username="owner", password=PW, email="o@x.io")
        c.login("owner", PW)
        ok, bad = Alert(rule_id="A", title="kept", severity="high"), Alert(rule_id="B", title="edited", severity="high")
        svc.store.add_alert(ok)
        svc.store.add_alert(bad)
        raw(svc.store).execute("UPDATE alerts SET title = 'nothing here' WHERE id = ?", (bad.id,))
        states = {a["id"]: a["_integrity"] for a in c.call("alerts.list", limit=10)}
        assert states[ok.id] == "ok" and states[bad.id] == "tampered"
        assert c.call("alerts.get", id=bad.id)["integrity"] == "tampered"
        names = {r["event"] for r in c.call("audit.list", limit=100)}
        assert "alert_recorded" not in names                                     # bookkeeping hidden ...
        assert "alert_recorded" in {r["event"] for r in c.call("audit.list", limit=100, all=True)}   # ... on demand
        assert c.call("agent.info")["audit_genesis"].startswith("ed25519:")
    finally:
        svc.close()


def test_cli_verify_prints_the_genesis_and_checks_exports(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, P=PW)

    def cli(*a):
        return subprocess.run([sys.executable, "-m", "eldoctor", *a], cwd=str(root), env=env, capture_output=True,
                              text=True, timeout=120)
    cli("register", "--non-interactive", "--username", "owner", "--email", "o@x.io", "--password-env", "P")
    cli("login", "--username", "owner", "--password-env", "P")
    r = cli("audit", "verify")
    assert r.returncode == 0 and "Ed25519" in r.stdout and "genesis signing key: ed25519:" in r.stdout, r.stdout
    genesis = r.stdout.split("genesis signing key: ")[1].split()[0]
    export = Path(os.environ["ELDOCTOR_HOME"]) / "audit.jsonl"
    time.sleep(0.2)
    r = cli("audit", "verify-export", str(export), "--genesis", genesis)
    assert r.returncode == 0 and r.stdout.startswith("OK"), r.stdout + r.stderr
    lines = export.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["actor"] = "someone-else"
    lines[1] = json.dumps(rec)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("\n".join(lines))
    r = cli("audit", "verify-export", str(bad))
    assert r.returncode == 4 and "TAMPERED" in r.stdout
    assert "integrity" in cli("alerts").stdout.lower() or cli("alerts").returncode == 0
    assert fingerprint("00" * 32).startswith("ed25519:")


def test_database_from_the_first_chain_version_is_upgraded(store, cfg):
    """v1 records (hash chain + HMAC, no signatures, no ledger) continue under a signed v2 chain."""
    from eldoctor.integrity import GENESIS
    um = UserManager(store, cfg)
    um.register("owner", PW, "o@x.io")
    store.add_alert(Alert(rule_id="A", title="old alert", severity="high"))
    db = raw(store)
    old = [dict(r) for r in db.execute("SELECT *, id AS seq FROM audit WHERE ref_kind IS NULL OR ref_kind = '' "
                                       "ORDER BY id")]
    db.execute("DELETE FROM audit")
    prev = GENESIS
    for i, r in enumerate(old, 1):                       # rewrite as the first release stored them
        r.update(seq=i, v=1)
        h = audit_hash(r, prev)
        db.execute("INSERT INTO audit (id, ts, actor, event, details, os_user, os_uid, os_pid, client, host, prev_hash,"
                   " hash, mac, v) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                   (i, r["ts"], r["actor"], r["event"], r["details"], r["os_user"], r["os_uid"], r["os_pid"],
                    r["client"], r["host"], prev, h, store.keys.audit_mac(h)))
        prev = h
    db.execute("DELETE FROM meta WHERE key IN ('ledger_epoch', 'audit_genesis')")
    store.meta_set("audit_head", {"seq": len(old), "hash": prev})
    for f in store.signer.dir.glob("*.key"):
        f.unlink()
    up = Store(store.path)
    res = up.verify_audit()
    assert res["ok"], problems(res)
    assert up.query("SELECT 1 FROM audit WHERE event = 'ledger_initialized'")
    assert res["signed"] >= 1 and res["genesis"]
    assert UserManager(up, cfg).authenticate("owner", PW).role == "admin"
    assert up.ledger_state("alert", up.list_alerts(1)[0]) == "ok"
