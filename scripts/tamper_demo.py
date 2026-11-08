#!/usr/bin/env python3
"""P0-1 acceptance demo: forging approvals and the audit trail no longer works.

Replays the production-readiness finding against a *running* agent:

  "a self-registered viewer wrote status='approved', decided_by='admin1' straight into eldoctor.db;
   the agent killed the process, and the audit trail shows the approval as coming from admin1."

Requires an agent in interactive mode on the same ELDOCTOR_HOME:

    LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && python3 scripts/tamper_demo.py

Steps
  1. a viewer ("attacker_user") cannot approve through the API            -> refused by the agent (exit 3)
  2. attacker_user edits the database directly to forge the approval      -> the agent refuses to act, marks it
                                                                       'rejected', raises ED-INT-001 (critical)
  3. attacker_user promotes herself to admin in the users table           -> her account is refused (seal broken)
  4. attacker_user rewrites an audit record to blame someone else         -> `eldoctor audit verify` -> TAMPERED
  5. the SIEM copy (mock receiver) holds the original records and the integrity incidents
  --- the attacker now also reads every key file (what root / the service account could take) ---
  6. with the HMAC master key she recomputes the seal of "role=admin"   -> still refused: the signed
                                                                       chain records her as viewer
  7. with the current one-time signing key she re-signs a past record -> TAMPERED: a destroyed key's
                                                                       signature / key continuity breaks
  8. she downplays an alert and rewrites a kill as "failed"            -> `eldoctor alerts` marks the
                                                                       row tampered, verify reports both

(In a real deployment attacker_user could not even open the database: `eldoctor service` locks the data folder
to the service account.  This demo runs as the folder's owner precisely to show what happens *if* the file
is edited anyway.)
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
LAB_CFG = Path("/tmp/ed_lab_config.yaml")
ED = [sys.executable, "-m", "eldoctor", "--config",
      str(LAB_CFG if LAB_CFG.exists() else Path(__file__).with_name("lab_config.yaml"))]
DB = Path(os.environ.get("ELDOCTOR_HOME", "/tmp/ed_lab")) / "eldoctor.db"
SIEM = Path("/tmp/ed_received.jsonl")
MALLORY_PW = "M4llory!Passw0rd"


def ed(*args, client_dir=None, **kw):
    env = dict(os.environ, P=MALLORY_PW)
    if client_dir:
        env["ELDOCTOR_CLIENT_DIR"] = str(client_dir)
    return subprocess.run(ED + list(args), capture_output=True, text=True, cwd=ROOT, env=env, timeout=60, **kw)


def db():
    c = sqlite3.connect(str(DB), isolation_level=None, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def check(ok, what):
    print(f"   [{'PASS' if ok else 'FAIL'}] {what}")
    return bool(ok)


def main() -> int:
    ok = True
    attacker_user = Path("/tmp/ed_mallory_client")                     # attacker_user's own client folder (session token)
    print("== 0. attacker_user self-registers (viewer) and logs in")
    ed("register", "--non-interactive", "--username", "attacker_user", "--email", "m@example.invalid", "--password-env", "P",
       client_dir=attacker_user)
    r = ed("login", "--username", "attacker_user", "--password-env", "P", client_dir=attacker_user)
    print("   " + (r.stdout or r.stderr).strip())

    print("== 1. a process triggers an approval request")
    hog = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    aid = None
    end = time.time() + 40
    while time.time() < end and not aid:
        row = db().execute("SELECT id FROM approvals WHERE status='pending' AND summary LIKE ?",
                           (f"%[{hog.pid}]%",)).fetchone()
        aid = row["id"] if row else None
        time.sleep(0.5)
    if not aid:
        print("   no approval requested - is the agent running in interactive mode?")
        hog.kill()
        return 1
    print(f"   approval {aid} pending for python3[{hog.pid}]")
    r = ed("approvals", "approve", aid, client_dir=attacker_user)
    ok &= check(r.returncode == 3 and "checked by the agent" in r.stderr,
                f"attacker_user> eldoctor approvals approve {aid}  ->  {r.stderr.strip()}")

    print("== 2. attacker_user forges the approval directly in eldoctor.db")
    db().execute("UPDATE approvals SET status='approved', decided_by='admin1', decided_ts=? WHERE id=?",
                 (time.time(), aid))
    time.sleep(4)
    st = db().execute("SELECT status FROM approvals WHERE id=?", (aid,)).fetchone()["status"]
    ok &= check(hog.poll() is None, "the process is still alive (the agent did not act on the forged row)")
    ok &= check(st == "rejected", f"approval status is now '{st}'")
    inc = db().execute("SELECT title FROM alerts WHERE rule_id='ED-INT-001' ORDER BY ts DESC").fetchone()
    ok &= check(inc is not None, f"incident raised: {inc['title'] if inc else '-'}")
    hog.kill()

    print("== 3. attacker_user makes herself admin in the users table")
    db().execute("UPDATE users SET role='admin' WHERE username='attacker_user'")
    r = ed("login", "--username", "attacker_user", "--password-env", "P", client_dir=attacker_user)
    ok &= check(r.returncode == 2 and "integrity" in r.stderr, f"login refused: {r.stderr.strip()}")
    r = ed("users", "list", client_dir=attacker_user)
    ok &= check(r.returncode == 2, "her existing session is refused as well")

    print("== 4. attacker_user rewrites the audit trail to blame someone else")
    rec = db().execute("SELECT id, actor FROM audit WHERE event='api_denied' AND actor='attacker_user' "
                       "ORDER BY id LIMIT 1").fetchone()
    if rec:
        db().execute("UPDATE audit SET actor='admin_user' WHERE id=?", (rec["id"],))
    r = ed("audit", "verify")
    first = r.stdout.strip().splitlines()[:3]
    ok &= check(r.returncode == 4 and "TAMPERED" in r.stdout, "eldoctor audit verify -> " + " | ".join(first))

    print("== 5. the SIEM copy")
    time.sleep(1)
    if SIEM.exists():
        lines = [json.loads(x) for x in SIEM.read_text().splitlines() if '"syslog"' in x]
        audit = [x["message"] for x in lines if "eldoctor-audit" in x.get("message", "")]
        viol = [m for m in audit if "audit:integrity_violation" in m]
        denied = [m for m in audit if "audit:api_denied" in m and "suser=attacker_user" in m]
        ok &= check(audit, f"{len(audit)} audit records forwarded to the SIEM (CEF over syslog)")
        ok &= check(viol, f"{len(viol)} integrity incidents in the SIEM")
        ok &= check(denied, "the original record 'attacker_user was denied' is in the SIEM, whatever the local DB says")
    else:
        print("   (no mock SIEM output at /tmp/ed_received.jsonl - run via scripts/lab.sh)")
    print("== 6. attacker_user (now holding the master key) recomputes the seal for role=admin")
    sys.path.insert(0, str(ROOT))
    from eldoctor.integrity import Keyring, SigningChain, audit_hash
    from eldoctor.storage import Store
    keys = Keyring(DB.parent)
    row = dict(db().execute("SELECT * FROM users WHERE username='attacker_user'").fetchone())
    row["role"] = "admin"
    db().execute("UPDATE users SET role='admin', seal=? WHERE username='attacker_user'",
                 (keys.seal("user", Store._user_fields(row)),))
    r = ed("login", "--username", "attacker_user", "--password-env", "P", client_dir=attacker_user)
    ok &= check(r.returncode == 2, "HMAC seal recomputed with the stolen key - login still refused: "
                + r.stderr.strip()[:110])

    print("== 7. attacker_user re-signs a past audit record with the stolen current signing key")
    chain = SigningChain(keys.dir)
    stolen = [f.stem for f in chain.dir.glob("*.key")]
    c = db()
    victim_rec = dict(c.execute("SELECT *, id AS seq FROM audit WHERE event='session_issued' AND actor='attacker_user' "
                                "ORDER BY id LIMIT 1").fetchone() or {})
    if victim_rec and stolen:
        sk = chain.load(stolen[0])
        victim_rec.update(actor="nobody", pub=stolen[0])
        victim_rec["hash"] = audit_hash(victim_rec, victim_rec["prev_hash"])
        c.execute("UPDATE audit SET actor=?, pub=?, hash=?, mac=?, sig=? WHERE id=?",
                  ("nobody", stolen[0], victim_rec["hash"], keys.audit_mac(victim_rec["hash"]),
                   chain.sign(sk, victim_rec["hash"]), victim_rec["seq"]))
        c.execute("UPDATE audit SET prev_hash=? WHERE id=?", (victim_rec["hash"], victim_rec["seq"] + 1))
    r = ed("audit", "verify")
    ok &= check(r.returncode == 4 and "signing key does not continue" in r.stdout,
                "eldoctor audit verify -> TAMPERED: signing key does not continue the chain")

    print("== 8. attacker_user downplays an alert and rewrites a kill as 'failed'")
    a = db().execute("SELECT id FROM alerts ORDER BY ts DESC LIMIT 1").fetchone()
    db().execute("UPDATE alerts SET severity='low' WHERE id=?", (a["id"],))
    db().execute("UPDATE actions SET status='failed' WHERE id=(SELECT MAX(id) FROM actions WHERE action='kill' "
                 "OR action='renice')")
    r = ed("alerts", "--limit", "200")
    ok &= check("tampered" in r.stdout, f"eldoctor alerts marks alert {a['id']} as tampered")
    r = ed("audit", "verify")
    ok &= check("row was modified after the agent recorded it" in r.stdout and f"alert {a['id']}" in r.stdout
                and "action " in r.stdout, "eldoctor audit verify reports the edited alert and action rows")
    print("== result:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
