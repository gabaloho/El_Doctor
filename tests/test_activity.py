"""User-activity recording for forensics: sessions, applications, files (created / edited / deleted / renamed /
opened / downloaded), attribution (who did it), persistence across restarts and reboots, data-wipe incidents
e-mailed to the registered administrators, kernel telemetry parsers (auditd, Sysmon, Security log) and the API.

File-system events are real (inotify on this Linux host); processes that delete files are real child processes.
"""
import copy
import io
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import zipfile

import pytest

from eldoctor.activity.attribution import Attributor, ProcRecord
from eldoctor.activity.fswatch import PathFilter
from eldoctor.activity.monitor import ActivityMonitor
from eldoctor.activity.sessions import UTMP, read_wtmp, wtmp_sessions
from eldoctor.activity.wipe import WipeDetector
from eldoctor.auth.users import UserManager
from eldoctor.collectors.logs import AuditParser, parse_windows_events_xml
from eldoctor.collectors.processes import ProcessCollector
from eldoctor.storage import Store

PW = "Str0ng!Passw0rd"
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify / auditd are Linux only")


# ------------------------------------------------------------------ fixtures & helpers
@pytest.fixture
def root(tmp_path):
    r = tmp_path / "users" / "alice"
    for d in ("Documents", "Downloads", "Pictures", ".cache", "proj/node_modules", ".local/share/Trash/files"):
        (r / d).mkdir(parents=True)
    for i in range(5):
        (r / "Documents" / f"old{i}.txt").write_text("x" * (i + 1))
    (r / ".cache" / "c.bin").write_text("cache")
    return r


@pytest.fixture
def acfg(cfg, root):
    c = copy.deepcopy(cfg)
    c["activity"]["files"].update(enabled=True, paths=[str(root)], open_handles_interval=0, merge_delay=0.2)
    c["activity"]["wipe"].update(threshold=10, window=30, quiet=1.0)
    return c


@pytest.fixture
def smtp_sink():
    """Minimal SMTP server: records envelope recipients and the message."""
    got = []

    class S(socketserver.StreamRequestHandler):
        def handle(self):
            w = lambda line: self.wfile.write((line + "\r\n").encode())
            w("220 hi")
            rcpt = []
            while True:
                line = self.rfile.readline().decode(errors="replace").strip()
                if not line:
                    return
                u = line.upper()
                if u.startswith("EHLO") or u.startswith("HELO"):
                    w("250-x"); w("250 OK")
                elif u.startswith("RCPT TO"):
                    rcpt.append(line.split(":", 1)[1].strip().strip("<>")); w("250 ok")
                elif u == "DATA":
                    w("354 go")
                    data = []
                    while True:
                        ln = self.rfile.readline().decode(errors="replace")
                        if ln.strip() == ".":
                            break
                        data.append(ln)
                    got.append({"rcpt": list(rcpt), "data": "".join(data)}); w("250 ok")
                elif u == "QUIT":
                    w("221 bye"); return
                else:
                    w("250 ok")

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), S)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], got
    srv.shutdown()
    srv.server_close()


def admin(store, cfg, email="admin@example.invalid"):
    return UserManager(store, cfg).register("admin_user", PW, email)[0]


class Pump:
    """Drives a monitor like the agent loop: real process snapshots + optional log events."""

    def __init__(self, mon):
        self.mon = mon
        self.col = ProcessCollector(hash_executables=False)
        self.alerts = []

    def tick(self, log_events=None):
        procs, new = self.col.snapshot()
        self.alerts += self.mon.tick(procs, new, log_events or [])

    def until(self, pred, timeout=15.0, step=0.25):
        end = time.time() + timeout
        while time.time() < end:
            self.tick()
            if pred():
                return True
            time.sleep(step)
        return False


def started(mon, timeout=15):
    """Monitor started and its start-up folder comparison recorded (the watcher is live after that)."""
    p = Pump(mon)
    assert p.until(lambda: mon.last_scan.get("source") == "offline", timeout), mon.errors
    return p


def spawn(script):
    """bash -c SCRIPT in its own process group (killed as a whole - no orphaned children)."""
    return subprocess.Popen(["bash", "-c", script], start_new_session=True)


def kill(proc):
    import signal
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    proc.wait()


def rows(store, **kw):
    return store.list_activity(limit=5000, **kw)


def kinds(store, **kw):
    return [(r["kind"], os.path.basename(r["path"])) for r in rows(store, **kw)]


# ------------------------------------------------------------------ storage: sealed, tamper-evident, persistent
def test_activity_rows_are_sealed_in_the_signed_chain(store):
    ids = store.add_activity([{"kind": "file_deleted", "category": "file", "path": f"/h/a{i}", "user": "alice",
                               "details": {"x": i}} for i in range(5)])
    assert ids == list(range(ids[0], ids[0] + 5))
    seal = [r for r in store.list_audit(50, include_bookkeeping=True) if r["event"] == "activity_sealed"][0]
    assert json.loads(seal["details"])["count"] == 5
    assert store.verify_audit()["ok"]

    store.execute("UPDATE activity SET user = 'mallory' WHERE id = ?", (ids[1],))           # hide who did it
    probs = [p["problem"] for p in store.verify_audit()["problems"]]
    assert any("were modified" in p for p in probs)
    store.execute("UPDATE activity SET user = 'alice' WHERE id = ?", (ids[1],))
    store.execute("DELETE FROM activity WHERE id = ?", (ids[2],))                           # erase a record
    assert any("deleted" in p["problem"] for p in store.verify_audit()["problems"])
    store.execute("INSERT INTO activity (ts, kind, category) VALUES (1, 'file_created', 'file')")  # forge one
    assert any("not recorded by the agent" in p["problem"] for p in store.verify_audit()["problems"])


def test_retention_prunes_whole_sealed_batches_and_stays_verifiable(store):
    store.add_activity([{"kind": "app_start", "category": "process", "ts": 1000.0}] * 3)
    store.add_activity([{"kind": "app_start", "category": "process", "ts": time.time()}] * 2)
    assert store.prune_activity(time.time() - 3600) == 3
    assert store.query("SELECT COUNT(*) AS n FROM activity")[0]["n"] == 2
    assert store.verify_audit()["ok"]


def test_file_index_operations(store):
    put = lambda p, d=0, s=1: ("put", p, "/h", d, s, 1, 1)
    store.add_activity([], [put("/h/a", 1, 0), put("/h/a/x"), put("/h/a/y/z"), put("/h/ab")])
    store.add_activity([], [("move", "/h/a", "/h/b", "/h")])
    assert {r["path"] for r in store.query("SELECT path FROM file_index")} == {"/h/b", "/h/b/x", "/h/b/y/z", "/h/ab"}
    store.add_activity([], [("del", "/h/b")])
    assert {r["path"] for r in store.query("SELECT path FROM file_index")} == {"/h/ab"}        # /h/ab is not a child


# ------------------------------------------------------------------ live file activity (inotify)
@linux_only
def test_file_activity_is_recorded_and_classified(store, acfg, root):
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    assert mon.backend == "inotify"
    d, dl = root / "Documents", root / "Downloads"
    (d / "new.txt").write_text("hello")                                  # created (+ written = one record)
    with open(d / "old1.txt", "a") as fh:                                # edited
        fh.write("more")
    (d / "old2.txt").rename(d / "renamed.txt")                           # renamed
    (d / "old3.txt").read_text()                                         # opened
    (d / "old4.txt").unlink()                                            # deleted
    (d / "old0.txt").rename(root / ".local/share/Trash/files/old0.txt")  # moved to the Trash = deleted by the user
    (d / ".report.docx.swp").write_text("x")                             # editor noise: not recorded
    (d / "report.docx").write_text("v1")
    p.until(lambda: ("file_created", "report.docx") in kinds(store, category="file"))
    (d / "report.docx.tmp").write_text("v2")                             # atomic save: temp renamed over the file
    os.replace(d / "report.docx.tmp", d / "report.docx")
    (dl / "tool.zip.part").write_bytes(b"PK\x03\x04")                    # browser download: partial -> final name
    os.setxattr(dl / "tool.zip.part", "user.xdg.origin.url", b"https://files.example.net/tool.zip")
    os.rename(dl / "tool.zip.part", dl / "tool.zip")
    (root / ".cache" / "c.bin").write_text("changed")                    # excluded folder
    (root / "proj/node_modules/m.js").write_text("x")
    assert p.until(lambda: ("file_downloaded", "tool.zip") in kinds(store, category="file"))
    p.until(lambda: ("file_modified", "report.docx") in kinds(store, category="file"), timeout=5)
    got = kinds(store, category="file")
    for expected in [("file_created", "new.txt"), ("file_modified", "old1.txt"), ("file_renamed", "old2.txt"),
                     ("file_opened", "old3.txt"), ("file_deleted", "old4.txt"), ("file_deleted", "old0.txt"),
                     ("file_modified", "report.docx"), ("file_downloaded", "tool.zip")]:
        assert expected in got, (expected, got)
    names = [n for _, n in got]
    assert not any(n.endswith((".swp", ".tmp", ".part")) or n in ("c.bin", "m.js") for n in names), got
    assert ("file_modified", "new.txt") not in got                       # create + write coalesced
    by = {(r["kind"], os.path.basename(r["path"])): r for r in rows(store, category="file")}
    assert by[("file_renamed", "old2.txt")]["target"].endswith("renamed.txt")
    trash = by[("file_deleted", "old0.txt")]
    assert trash["details"]["trashed"] and "Trash" in trash["details"]["trash_path"]
    dlr = by[("file_downloaded", "tool.zip")]
    assert dlr["details"]["url"] == "https://files.example.net/tool.zip" and len(dlr["details"]["sha256"]) == 64
    assert by[("file_deleted", "old4.txt")]["size"] == 5                 # last known size from the index
    assert not any(str(store.path.parent) in r["path"] for r in rows(store))   # El Doctor never watches itself
    assert store.verify_audit()["ok"]
    mon.stop()


@linux_only
def test_who_deleted_it_command_line_and_open_handle_attribution(store, acfg, root):
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    target = root / "Pictures" / "holiday"
    target.mkdir()
    for i in range(3):
        (target / f"p{i}.jpg").write_bytes(b"\xff\xd8" * 10)
    p.until(lambda: len([r for r in rows(store, kind="file_created") if "holiday" in r["path"]]) >= 4)
    # a short-lived rm inside a shell: the shell (seen by the process poller) names the folder on its command line
    sh = subprocess.Popen(["bash", "-c", f"sleep 0.8; rm -rf '{target}'; sleep 1.5"])
    assert p.until(lambda: any(r["path"].endswith("p2.jpg") for r in rows(store, kind="file_deleted")))
    sh.wait()
    dels = [r for r in rows(store, kind="file_deleted") if "holiday" in r["path"]]
    assert len(dels) == 4 and all(r["attribution"] == "cmdline" and r["pid"] == sh.pid for r in dels)
    assert all(r["process"] == "bash" and r["user"] for r in dels)
    assert "rm -rf" in dels[0]["details"]["cmdline"]
    # a process holding a document open is named as the one who opened it
    doc = root / "Documents" / "contract.pdf"
    doc.write_bytes(b"%PDF")
    p.until(lambda: any(r["path"] == str(doc) for r in rows(store, kind="file_created")))
    holder = subprocess.Popen([sys.executable, "-c", "import os, time; f = open(os.environ['DOC']); time.sleep(20)"],
                              env=dict(os.environ, DOC=str(doc)))       # the path is not on its command line
    try:
        assert p.until(lambda: any(r["path"] == str(doc) for r in rows(store, kind="file_opened")))
        o = [r for r in rows(store, kind="file_opened") if r["path"] == str(doc)][0]
        assert o["attribution"] == "handle" and o["pid"] == holder.pid
    finally:
        holder.kill()
    mon.stop()


def test_inference_is_labelled_as_a_lead_not_proof():
    a = Attributor()
    a.sessions = [{"user": "alice", "terminal": "tty2"}, {"user": "bob", "terminal": "pts/0", "host": "10.0.0.5"}]
    r = a.attribute("/home/alice/Documents/x.docx", "deleted", time.time())
    assert r["user"] == "alice" and r["attribution"] == "inferred" and "no process evidence" in r["evidence"]
    r = a.attribute("/srv/share/x", "deleted", time.time())
    assert r["attribution"] == "unknown" and not r["user"]
    a.sessions = [{"user": "bob"}]
    assert a.attribute("/srv/share/x", "deleted", time.time())["user"] == "bob"
    # an editor that has had ~/project open for hours does not take the blame for rm -rf ~/project
    now = time.time()
    a.add_process(ProcRecord(10, "code", "/usr/bin/code", ["code", "/home/alice/project"], "alice", "/home/alice",
                             create_time=now - 3600, seen=now))
    a.add_process(ProcRecord(11, "rm", "/usr/bin/rm", ["rm", "-rf", "project"], "alice", "/home/alice",
                             create_time=now - 1, seen=now))
    assert a.attribute("/home/alice/project/src/main.c", "deleted", now)["pid"] == 11


# ------------------------------------------------------------------ data wipe -> admins by e-mail
@linux_only
def test_mass_deletion_alerts_and_emails_the_registered_admins(store, acfg, root, smtp_sink):
    port, got = smtp_sink
    boss = admin(store, acfg, "boss@corp.example")
    UserManager(store, acfg).register("analyst_a", "An4lyst!Passw0rd", "analyst@corp.example", role="analyst",
                                      created_by=boss)
    acfg["activity"]["report"].update(smtp={"smtp_host": "127.0.0.1", "smtp_port": port, "starttls": False},
                                      extra_recipients=["soc@corp.example"])
    data = root / "Documents" / "finance"
    data.mkdir()
    for i in range(25):
        (data / f"q{i}.xlsx").write_bytes(b"1" * 1000)
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    wiper = spawn(f"sleep 0.8; rm -rf '{data}'; sleep 30")
    try:
        assert p.until(lambda: any(a.rule_id == "ED-ACT-001" for a in p.alerts)), mon.errors
        alert = [a for a in p.alerts if a.rule_id == "ED-ACT-001"][0]
        assert alert.severity == "critical" and "T1485" in alert.mitre
        assert alert.process and alert.process["pid"] == wiper.pid      # live process: playbooks can suspend it
        assert p.until(lambda: len(got) >= 2, timeout=20), (mon.errors, store.outbox_list())
    finally:
        kill(wiper)
    final = [m for m in got if "Data wipe on" in m["data"]][0]
    assert sorted(final["rcpt"]) == ["boss@corp.example", "soc@corp.example"]      # admins only (+ extra)
    assert "analyst@corp.example" not in json.dumps(got)
    assert "26 files/folders deleted" in final["data"] and "bash" in final["data"]
    import email
    msg = email.message_from_string(final["data"])
    att = [part for part in msg.walk() if part.get_filename()][0]
    z = zipfile.ZipFile(io.BytesIO(att.get_payload(decode=True)))
    csv_text = z.read(z.namelist()[0]).decode()
    assert csv_text.count("finance/q") == 25 and ",cmdline," in csv_text and str(wiper.pid) in csv_text
    inc = rows(store, kind="wipe_incident")[0]
    assert inc["details"]["deleted_total"] == 26 and inc["details"]["reported_to_admins"]
    assert {o["status"] for o in store.outbox_list()} == {"sent"}
    sent = [r for r in store.list_audit(200) if r["event"] == "admin_report_sent"]
    assert sent and "boss@corp.example" in sent[0]["details"]
    assert [r for r in store.list_audit(200) if r["event"] == "data_wipe_reported"]
    mon.stop()


@linux_only
def test_agent_runs_the_data_destruction_playbook_on_the_wiper(store, acfg, root):
    from eldoctor.agent import Agent
    data = root / "Documents" / "hr"
    data.mkdir()
    for i in range(15):
        (data / f"e{i}.doc").write_text("x")
    acfg["agent"]["interval"] = 0.3
    agent = Agent(acfg, store, admin(store, acfg), mode="monitor")
    wiper = None
    try:
        end = time.time() + 15
        while agent.activity.last_scan.get("source") != "offline" and time.time() < end:
            agent.tick(); time.sleep(0.2)
        wiper = spawn(f"sleep 0.8; rm -rf '{data}'; sleep 30")
        end = time.time() + 15
        acts = []
        while time.time() < end:
            agent.tick(); time.sleep(0.25)
            acts = [a for a in store.list_actions(50) if a["playbook_id"] == "pb-data-destruction"]
            if any(a["action"] == "suspend" for a in acts):
                break
        assert ("suspend", "would_run") in [(a["action"], a["status"]) for a in acts]     # monitor mode: untouched
        assert wiper.poll() is None
    finally:
        agent.activity.stop()
        agent.dispatcher.close()
        if wiper:
            kill(wiper)


def test_wipe_detector_bursts():
    w = WipeDetector(threshold=5, window=10, quiet=3)
    t = 1000.0
    assert w.feed([{"ts": t + i, "path": f"/a/{i}"} for i in range(4)], t + 4) is None      # below threshold
    assert w.feed([{"ts": t + 20, "path": "/a/x"}], t + 20) is None      # the first four left the 10 s window
    inc = w.feed([{"ts": t + 21 + i, "path": f"/b/{i}", "user": "eve", "pid": 7, "process": "shred"}
                  for i in range(5)], t + 26)
    assert inc is not None and inc.total == 6 and inc.started == t + 20   # /a/x is inside the burst's window
    w.feed([{"ts": t + 27, "path": "/b/z", "is_dir": 1, "user": "eve", "pid": 7, "process": "shred"}], t + 27)
    assert w.poll(t + 28) is None and w.poll(t + 31).total == 7 and w.current is None
    assert inc.primary_process()["process"] == "shred"


# ------------------------------------------------------------------ across restarts and reboots
@linux_only
def test_deletions_while_el_doctor_was_not_running_are_found_and_reported(acfg, root, monkeypatch):
    store = Store()
    admin(store, acfg)
    mon = ActivityMonitor(acfg, store, session_provider=lambda: [{"name": "alice", "terminal": "tty2",
                                                                  "host": "", "started": 1.0}])
    started(mon)
    mon.stop(clean=True)
    store.close()
    # --- El Doctor is off: someone wipes the documents (e.g. booted from a USB stick) ---
    shutil.rmtree(root / "Documents")
    (root / "Pictures" / "new.png").write_bytes(b"\x89PNG")
    monkeypatch.setattr("eldoctor.activity.monitor.boot_id", lambda: "another-boot")
    store = Store()                                   # the agent comes back: same database, new process
    mon = ActivityMonitor(acfg, store, session_provider=lambda: [])
    p = started(mon)
    offline = [r for r in rows(store, kind="file_deleted") if r["source"] == "offline"]
    assert {os.path.basename(r["path"]) for r in offline} == {"Documents", "old0.txt", "old1.txt", "old2.txt",
                                                              "old3.txt", "old4.txt"}
    assert all(r["attribution"] == "unknown" and len(r["details"]["between"]) == 2 for r in offline)
    assert [r["source"] for r in rows(store, kind="file_created") if r["path"].endswith("new.png")] == ["offline"]
    # the previous boot's shutdown and this boot, the session that ended with it
    ks = [r["kind"] for r in rows(store, category="system")]
    assert "system_shutdown" in ks and "system_boot" in ks
    shut = rows(store, kind="system_shutdown")[0]
    assert shut["details"]["clean"] is True
    assert any(r["user"] == "alice" and r["details"].get("reason") == "system restarted"
               for r in rows(store, kind="session_end"))
    assert not any(a.rule_id == "ED-ACT-002" for a in p.alerts)      # 6 deletions < wipe threshold (10)
    mon.stop()
    store.close()


@linux_only
def test_offline_wipe_raises_alert_and_report_persists_until_smtp_exists(acfg, root, smtp_sink):
    port, got = smtp_sink
    acfg["activity"]["wipe"]["threshold"] = 3
    store = Store()
    admin(store, acfg, "owner@corp.example")
    mon = ActivityMonitor(acfg, store)
    started(mon)
    mon.stop()
    store.close()
    shutil.rmtree(root / "Documents")                                  # wiped while off
    store = Store()
    mon = ActivityMonitor(acfg, store)                                 # no SMTP configured yet
    p = started(mon)
    alert = [a for a in p.alerts if a.rule_id == "ED-ACT-002"]
    assert alert and alert[0].evidence["deleted_total"] == 6 and alert[0].evidence["source"] == "offline"
    mon.reporter.deliver(force=True)
    pending = store.outbox_list()
    assert pending and pending[0]["status"] == "pending" and "SMTP" in pending[0]["last_error"]
    mon.stop()
    store.close()
    # next start (e.g. after a reboot), now with a mail server: the queued report is delivered
    acfg["activity"]["report"]["smtp"] = {"smtp_host": "127.0.0.1", "smtp_port": port, "starttls": False}
    store = Store()
    mon = ActivityMonitor(acfg, store)
    mon.start()
    mon.reporter.deliver(force=True)
    assert got and got[0]["rcpt"] == ["owner@corp.example"]
    assert "deleted while El Doctor was not running" in got[0]["data"].replace("=\n", "")
    mon.stop()
    store.close()


def test_unclean_stop_is_a_monitoring_gap_alert(store, cfg):
    mon = ActivityMonitor(cfg, store)
    mon.start()
    st = dict(store.meta_get("activity_state"), heartbeat=time.time() - 900, clean_stop=False)
    store.meta_set("activity_state", st)                  # the agent was killed 15 minutes ago
    mon2 = ActivityMonitor(cfg, store)
    alerts = mon2.tick()
    assert [a.rule_id for a in alerts] == ["ED-ACT-005"]
    gap = rows(store, kind="monitoring_gap")[0]
    assert gap["details"]["seconds"] >= 890 and gap["details"]["clean_stop"] is False
    assert [r for r in store.list_audit(100) if r["event"] == "monitoring_gap"]


def test_wipe_incident_interrupted_by_a_crash_is_reported_after_restart(store, cfg):
    admin(store, cfg)
    ids = store.add_activity([{"kind": "file_deleted", "category": "file", "path": f"/home/a/d/{i}", "ts": time.time(),
                               "user": "eve", "attribution": "cmdline"} for i in range(12)])
    store.meta_set("activity_state", {"boot_id": "x", "heartbeat": time.time(), "clean_stop": False})
    store.meta_set("activity_open_incident", {"id": "inc1", "started": time.time() - 5, "first_id": ids[0],
                                              "alert_id": "al1", "total": 12})
    mon = ActivityMonitor(cfg, store)
    mon.start()
    rep = [o for o in store.outbox_list() if o["kind"] == "wipe_report"]
    assert rep and "12 files/folders deleted by eve" in rep[0]["subject"]
    assert store.meta_get("activity_open_incident") is None
    mon.stop()


# ------------------------------------------------------------------ sessions and applications
def test_logins_logouts_and_applications(store, cfg):
    sessions = [{"name": "alice", "terminal": "tty2", "host": "", "started": time.time() - 60, "pid": 1}]
    mon = ActivityMonitor(cfg, store, session_provider=lambda: list(sessions))
    p = Pump(mon)
    p.tick()
    sessions.append({"name": "bob", "terminal": "pts/1", "host": "203.0.113.7", "started": time.time(), "pid": 2})
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1.2)"])
    p.until(lambda: any(r["pid"] == child.pid for r in rows(store, kind="app_start")), timeout=5)
    del sessions[0]
    child.wait()
    p.until(lambda: any(r["pid"] == child.pid for r in rows(store, kind="app_stop")), timeout=5)
    start = [(r["user"], r["details"]["type"]) for r in rows(store, kind="session_start")]
    assert ("alice", "console") in start and ("bob", "remote") in start
    assert [r["user"] for r in rows(store, kind="session_end")] == ["alice"]
    app = [r for r in rows(store, kind="app_start") if r["pid"] == child.pid][0]
    assert "time.sleep" in app["details"]["cmdline"] and app["user"]
    stop = [r for r in rows(store, kind="app_stop") if r["pid"] == child.pid][0]
    assert stop["details"]["runtime_s"] >= 1
    assert rows(store, kind="app_running")                              # inventory at start-up
    audit = [r["event"] for r in store.list_audit(200)]
    assert "user_session_start" in audit and "user_session_end" in audit     # -> SIEM in real time
    assert mon.sessions.users() == ["bob"]


def test_wtmp_logins_while_el_doctor_was_off(tmp_path):
    def rec(t, pid, line, user, host, ts):
        return UTMP.pack(t, pid, line.encode(), b"ts/0", user.encode(), host.encode(), 0, 0, 0, int(ts), 0,
                         0, 0, 0, 0, b"\0" * 20)
    w = tmp_path / "wtmp"
    w.write_bytes(rec(2, 0, "~", "reboot", "6.1", 1000) + rec(7, 50, "pts/0", "mallory", "198.51.100.4", 1100) +
                  rec(8, 50, "pts/0", "", "", 1400) + rec(7, 60, "tty1", "alice", "", 1500) + rec(1, 0, "~", "shutdown", "", 1600))
    sess = [s for s in wtmp_sessions(read_wtmp(str(w), since=1050)) if not s.get("marker")]
    assert [(s["user"], s["type"], s["started"], s["ended"]) for s in sess] == \
        [("mallory", "remote", 1100, 1400), ("alice", "console", 1500, 1600)]


# ------------------------------------------------------------------ kernel telemetry: auditd, Sysmon, Security log
AUDIT_UNLINK = """type=SYSCALL msg=audit(1700000000.100:500): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=55d a2=0 a3=0 items=2 ppid=900 pid=901 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" key="eldoctor_file"\x1dARCH=x86_64 SYSCALL=unlinkat AUID="alice" UID="root" GID="root"
type=CWD msg=audit(1700000000.100:500): cwd="/home/alice"
type=PATH msg=audit(1700000000.100:500): item=0 name="/home/alice/Documents/" inode=11 dev=fd:01 mode=040755 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT
type=PATH msg=audit(1700000000.100:500): item=1 name="/home/alice/Documents/salaries.xlsx" inode=12 dev=fd:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=DELETE
type=PROCTITLE msg=audit(1700000000.100:500): proctitle=726D002D66002F686F6D652F616C6963652F446F63756D656E74732F73616C61726965732E786C7378
type=EOE msg=audit(1700000000.100:500):
type=SYSCALL msg=audit(1700000001.200:501): arch=c000003e syscall=316 success=yes exit=0 items=4 ppid=900 pid=902 auid=1000 uid=1000 comm="mv" exe="/usr/bin/mv" key="eldoctor_file"
type=CWD msg=audit(1700000001.200:501): cwd="/home/alice/Documents"
type=PATH msg=audit(1700000001.200:501): item=0 name="/home/alice/Documents/" nametype=PARENT mode=040755
type=PATH msg=audit(1700000001.200:501): item=1 name="/home/alice/Archive/" nametype=PARENT mode=040755
type=PATH msg=audit(1700000001.200:501): item=2 name="plan.txt" nametype=DELETE mode=0100644
type=PATH msg=audit(1700000001.200:501): item=3 name="plan-2024.txt" nametype=CREATE mode=0100644
type=EOE msg=audit(1700000001.200:501):
type=SYSCALL msg=audit(1700000002.300:502): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ff a2=241 a3=1b6 items=2 ppid=900 pid=903 auid=1000 uid=1000 comm="vim" exe="/usr/bin/vim" key="eldoctor_file"
type=PATH msg=audit(1700000002.300:502): item=0 name="/home/alice/notes.md" nametype=NORMAL mode=0100644
type=EOE msg=audit(1700000002.300:502):
type=SYSCALL msg=audit(1700000003.000:503): arch=c000003e syscall=263 success=no exit=-13 items=2 pid=904 auid=1000 uid=1000 comm="rm" exe="/usr/bin/rm" key="eldoctor_file"
type=PATH msg=audit(1700000003.000:503): item=1 name="/etc/shadow" nametype=DELETE mode=0100640
type=EOE msg=audit(1700000003.000:503):
"""


def test_auditd_file_records_name_the_login_user_behind_sudo(store, cfg):
    parser = AuditParser()
    evs = [e for line in AUDIT_UNLINK.split("\n") for e in parser.feed(line)]   # not splitlines(): \x1d is a line break there
    files = [e["file"] for e in evs if e.get("category") == "file_event"]
    assert [(f["op"], f["path"]) for f in files] == [
        ("deleted", "/home/alice/Documents/salaries.xlsx"), ("renamed", "/home/alice/Documents/plan.txt"),
        ("modified", "/home/alice/notes.md")]                           # the failed unlink of /etc/shadow is dropped
    rm = files[0]
    assert rm["user"] == "root" and rm["login_user"] == "alice" and rm["pid"] == 901 and rm["syscall"] == "unlinkat"
    assert rm["cmdline"] == "rm -f /home/alice/Documents/salaries.xlsx"
    assert files[1]["target"] == "/home/alice/Archive/plan-2024.txt"
    mon = ActivityMonitor(cfg, store)
    mon.tick(None, None, evs)
    r = rows(store, kind="file_deleted")[0]
    assert (r["user"], r["login_user"], r["attribution"], r["source"], r["process"]) == \
        ("root", "alice", "kernel", "auditd", "rm")
    assert mon.kernel_files


SYSMON = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>23</EventID><EventRecordID>77</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS1</Computer></System><EventData><Data Name="User">CORP\\bob</Data><Data Name="ProcessId">4242</Data><Data Name="Image">C:\\Tools\\sdelete64.exe</Data><Data Name="TargetFilename">C:\\Users\\bob\\Documents\\budget.xlsx</Data><Data Name="Archived">false</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>15</EventID><EventRecordID>78</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS1</Computer></System><EventData><Data Name="User">CORP\\bob</Data><Data Name="ProcessId">100</Data><Data Name="Image">C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe</Data><Data Name="TargetFilename">C:\\Users\\bob\\Downloads\\setup.exe:Zone.Identifier</Data><Data Name="Contents">[ZoneTransfer]  ZoneId=3  HostUrl=https://dl.example.org/setup.exe</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4663</EventID><EventRecordID>79</EventRecordID><Channel>Security</Channel><Computer>WS1</Computer></System><EventData><Data Name="SubjectUserName">carol</Data><Data Name="SubjectDomainName">CORP</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">C:\\Share\\hr\\list.csv</Data><Data Name="AccessMask">0x10000</Data><Data Name="ProcessId">0x1a4</Data><Data Name="ProcessName">C:\\Windows\\explorer.exe</Data></EventData></Event>"""


def test_windows_sysmon_and_security_file_events():
    evs = parse_windows_events_xml(SYSMON)
    f = [e["file"] for e in evs]
    assert [(x["op"], x["path"], x["user"]) for x in f] == [
        ("deleted", "C:\\Users\\bob\\Documents\\budget.xlsx", "CORP\\bob"),
        ("downloaded", "C:\\Users\\bob\\Downloads\\setup.exe", "CORP\\bob"),
        ("deleted", "C:\\Share\\hr\\list.csv", "CORP\\carol")]
    assert f[0]["process"] == "sdelete64.exe" and f[0]["pid"] == 4242 and f[2]["pid"] == 0x1a4
    assert f[1]["url"] == "https://dl.example.org/setup.exe"


def test_filter_never_watches_el_doctor_and_reaches_the_trash(tmp_path):
    f = PathFilter(["/home"], exclude=[".local", ".cache"], include=["*/.local/share/Trash/files"],
                   never=[str(tmp_path)])
    assert not f.skip_dir("/home/al/.local/share/Trash/files/x") and f.route_only("/home/al/.local/share")
    assert f.skip_dir("/home/al/.local/share/keyrings") and f.skip_dir("/home/al/.cache")
    f2 = PathFilter([str(tmp_path)], never=[str(tmp_path / "ed")])
    assert f2.skip_dir(str(tmp_path / "ed" / "keys")) and not f2.skip_dir(str(tmp_path / "docs"))


# ------------------------------------------------------------------ evidence store and malicious downloads
def test_deleting_el_doctors_evidence_is_an_incident(store, cfg, tmp_path):
    from eldoctor.config import home_dir
    (home_dir() / "audit.jsonl").write_text("{}\n")
    mon = ActivityMonitor(cfg, store)
    assert mon.tick() == []
    (home_dir() / "audit.jsonl").unlink()
    alerts = mon.tick()
    assert [a.rule_id for a in alerts] == ["ED-ACT-003"] and alerts[0].severity == "critical"
    assert rows(store, kind="evidence_deleted")
    assert any(o["kind"] == "evidence_deleted" for o in store.outbox_list())


@linux_only
def test_downloaded_file_matching_threat_intel(store, acfg, root):
    import hashlib
    from eldoctor.detection.ioc import Indicator, IOCStore
    payload = b"MZ-evil-payload"
    iocs = IOCStore()
    iocs.add(Indicator("sha256", hashlib.sha256(payload).hexdigest(), "critical", "test sample", source="test"))
    mon = ActivityMonitor(acfg, store, iocs=iocs)
    p = started(mon)
    (root / "Downloads" / "invoice.exe").write_bytes(payload)
    assert p.until(lambda: any(a.rule_id == "ED-ACT-004" for a in p.alerts))
    mon.stop()


# ------------------------------------------------------------------ detection rules for wipe tools
@pytest.mark.parametrize("platform,exe,cmd,hit", [
    ("linux", "/usr/bin/shred", "shred -u -z secret.pdf", True),
    ("linux", "/usr/bin/dd", "dd if=/dev/urandom of=/dev/nvme0n1 bs=1M", True),
    ("linux", "/usr/bin/rm", "rm -rf /home/alice", True),
    ("linux", "/usr/bin/rm", "rm -rf build/", False),
    ("linux", "/usr/bin/dd", "dd if=/dev/sda of=backup.img", False),
    ("windows", r"C:\Tools\sdelete64.exe", r"sdelete64.exe -s C:\Users\bob", True),
    ("windows", r"C:\Windows\System32\cipher.exe", r"cipher.exe /w:C:\ ", True),
    ("windows", r"C:\Windows\System32\cmd.exe", r"cmd.exe /c rd /s /q C:\Users\bob", True),
    ("windows", r"C:\Windows\System32\cipher.exe", r"cipher.exe /e C:\data", False),
])
def test_wipe_tool_sigma_rules(cfg, platform, exe, cmd, hit):
    from eldoctor.detection.engine import DetectionEngine
    from eldoctor.models import ProcessInfo
    eng = DetectionEngine(cfg)
    eng.platform = platform
    p = ProcessInfo(pid=4321, name=exe.replace("\\", "/").rsplit("/", 1)[-1], exe=exe, cmdline=cmd.split(" "),
                    username="u", create_time=1.0)
    ids = [a.rule_id for a in eng.on_process_start(p)]
    assert any(i.startswith("SIGMA:7c1e9a52") for i in ids) == hit, ids
    assert "ED-ACT-001" in {r["id"] for r in eng.catalogue()}


# ------------------------------------------------------------------ API: forensics permission, export audit
def test_activity_api_rbac_and_export_audit(cfg, store):
    from eldoctor.api.client import ApiClient, ApiError
    from eldoctor.api.peercred import own_identity
    from eldoctor.api.server import AgentService
    from eldoctor.api.transport import InProcessTransport
    svc = AgentService(cfg, store=store)
    try:
        def client():
            c = ApiClient(InProcessTransport(svc.handle, own_identity(), f"t-{id(svc)}"), "cli")
            c.token = None
            return c
        adm = client()
        adm.call("auth.register", username="admin1", password=PW, email="a@example.invalid")
        adm.login("admin1", PW)
        adm.call("users.add", username="analyst1", password="An4lyst!Passw0rd", email="b@example.invalid",
                 role="analyst")
        client().call("auth.register", username="viewer1", password="V1ewer!Passw0rd", email="v@example.invalid")
        an, vw = client(), client()
        an.login("analyst1", "An4lyst!Passw0rd")
        vw.login("viewer1", "V1ewer!Passw0rd")
        store.add_activity([{"kind": "file_deleted", "category": "file", "path": "/home/alice/x.docx",
                             "user": "alice", "ts": 1000.0},
                            {"kind": "session_start", "category": "session", "user": "bob", "ts": 2000.0}])
        for m in ("activity.list", "activity.now", "activity.sessions", "activity.status", "activity.reports"):
            with pytest.raises(ApiError) as e:
                vw.call(m)
            assert e.value.code == "forbidden"                      # viewers do not see people's file activity
        assert [r["path"] for r in an.call("activity.list", kind="file_deleted")] == ["/home/alice/x.docx"]
        assert [r["user"] for r in an.call("activity.list", since=1500)] == ["bob"]
        assert an.call("activity.list", path="/home/alice/")[0]["user"] == "alice"
        assert an.call("activity.list", q="x.doc")[0]["kind"] == "file_deleted"
        with pytest.raises(ApiError):
            an.call("activity.list", category="nope")
        an.call("activity.list", export=True, format="csv", order="asc")
        ex = [r for r in store.list_audit(100) if r["event"] == "activity_exported"]
        assert ex and ex[0]["actor"] == "analyst1"
        now = an.call("activity.now")
        assert "users" in now and "logged_in" in now
        st = an.call("activity.status")
        assert st["total_records"] == 2 and "outbox" in st
    finally:
        svc.close()


def test_cli_activity_export(tmp_path):
    env = dict(os.environ, P=PW)
    run = lambda *a: subprocess.run([sys.executable, "-m", "eldoctor", *a], capture_output=True, text=True, env=env,
                                    cwd=str(os.path.dirname(os.path.dirname(__file__))), timeout=120)
    assert run("register", "--non-interactive", "--username", "admin_user", "--email", "a@example.invalid",
               "--password-env", "P", "--json").returncode == 0
    assert run("login", "--username", "admin_user", "--password-env", "P").returncode == 0
    s = Store()
    s.add_activity([{"kind": "file_downloaded", "category": "file", "path": "/home/a/Downloads/x.zip", "user": "a",
                     "details": {"url": "https://example.org/x.zip"}}])
    s.close()
    out = tmp_path / "triage.csv"
    r = run("activity", "export", "--out", str(out))
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert "file_downloaded" in text and "https://example.org/x.zip" in text
    r = run("activity", "list", "--kind", "file_downloaded")
    assert r.returncode == 0 and "x.zip" in r.stdout and "example.org" in r.stdout
    assert run("activity", "status").returncode == 0


# ------------------------------------------------------------------ hostile input from people's folders
@linux_only
def test_a_fifo_or_symlink_posing_as_a_download_cannot_stall_or_leak(store, acfg, root):
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    os.mkfifo(root / "Downloads" / "movie.mkv")                       # open() would block the agent forever
    os.symlink("/etc/hostname", root / "Downloads" / "secret.txt")   # a privileged agent must not read through it
    t0 = time.time()
    assert p.until(lambda: {"movie.mkv", "secret.txt"} <= {os.path.basename(r["path"]) for r in rows(store, category="file")})
    assert time.time() - t0 < 10
    for r in rows(store, category="file"):
        assert "sha256" not in r["details"]
    link = [r for r in rows(store, category="file") if r["path"].endswith("secret.txt")][0]
    assert link["details"]["symlink_to"] == "/etc/hostname"
    mon.stop()


def test_report_attachment_and_subject_are_neutralised(store, cfg, smtp_sink):
    from eldoctor.activity.report import AdminReporter
    from eldoctor.activity.wipe import rows_csv
    assert rows_csv([{"path": "=cmd|' /C calc'!A0", "user": "+x"}]).splitlines()[1].split(",")[3].startswith("'=")
    port, got = smtp_sink
    admin(store, cfg)
    cfg["activity"]["report"]["smtp"] = {"smtp_host": "127.0.0.1", "smtp_port": port, "starttls": False}
    rep = AdminReporter(cfg, store)
    rep.queue("test", "wipe by evil\r\nBcc: attacker@example.net", "body")
    assert rep.deliver()[0]["status"] == "sent"
    assert "Bcc:" not in got[0]["data"].split("\n\n", 1)[0].replace("Subject: wipe by evil Bcc: attacker", "")
    assert got[0]["rcpt"] == ["admin@example.invalid"]


def test_polling_backend_used_on_windows_and_macos(store, acfg, root):
    """The folder-scan backend (Windows / macOS, or backend: poll): same records, renames found by inode."""
    acfg["activity"]["files"].update(backend="poll", poll_interval=0.5)
    acfg["activity"]["wipe"]["threshold"] = 1000
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    assert mon.backend == "poll"
    d = root / "Documents"
    (d / "a.txt").write_text("new")
    (d / "old1.txt").write_text("edited, longer")
    (d / "old2.txt").rename(d / "moved.txt")
    (root / "Pictures").rename(root / "Photos")                         # a folder rename = one record
    (d / "old3.txt").unlink()
    assert p.until(lambda: ("file_deleted", "old3.txt") in kinds(store, category="file"), timeout=20)
    got = kinds(store, category="file")
    for expected in [("file_created", "a.txt"), ("file_modified", "old1.txt"), ("file_renamed", "old2.txt"),
                     ("file_renamed", "Pictures"), ("file_deleted", "old3.txt")]:
        assert expected in got, (expected, got)
    assert not any(n in ("moved.txt", "Photos") for k, n in got if k in ("file_created", "file_deleted"))
    ren = [r for r in rows(store, kind="file_renamed") if r["path"].endswith("old2.txt")][0]
    assert ren["target"].endswith("moved.txt") and ren["source"] == "scan"
    assert store.verify_audit()["ok"]
    mon.stop()


@linux_only
def test_secure_deletion_is_one_record_under_the_original_name(store, acfg, root):
    """shred -u overwrites, renames the file to 000..0 a dozen times, then unlinks it: one deletion record of the
    original file (not of '0'), marked secure_delete, attributed to whoever ran it."""
    if not shutil.which("shred"):
        pytest.skip("shred not installed")
    mon = ActivityMonitor(acfg, store)
    p = started(mon)
    victim = root / "Documents" / "old3.txt"
    sh = spawn(f"sleep 0.8; shred -u '{victim}'; sleep 1.5")
    try:
        assert p.until(lambda: any(r["details"].get("secure_delete") for r in rows(store, kind="file_deleted")))
    finally:
        kill(sh)
    d = [r for r in rows(store, kind="file_deleted") if r["details"].get("secure_delete")]
    assert len(d) == 1 and d[0]["path"] == str(victim) and d[0]["details"]["deleted_as"].endswith("/0")
    assert d[0]["attribution"] == "cmdline" and d[0]["pid"] == sh.pid and d[0]["size"] == 4   # last known size
    assert d[0]["details"]["evidence"].count("secure-deletion sequence") == 1
    assert not [r for r in rows(store, kind="file_renamed") if "0000" in r["target"]]
    mon.stop()


def test_unexpanded_globs_and_braces_attribute_wrapped_wipes(monkeypatch):
    """sh -c "rm -rf ~/Documents/*" or report{1..40}.csv: the shell holds the pattern, not the paths."""
    import eldoctor.activity.attribution as at
    monkeypatch.setattr(at, "home_of", lambda u: "/home/alice")
    a = at.Attributor()
    now = time.time()
    a.add_process(ProcRecord(5, "bash", "/bin/bash", ["bash", "-c", "rm -rf ~/Documents/*"], "alice", "/",
                             create_time=now - 1, seen=now))
    a.add_process(ProcRecord(6, "sh", "/bin/sh", ["sh", "-c", "cd /srv && rm -f data/report{1..40}.csv"], "bob",
                             "/srv", create_time=now - 1, seen=now))
    assert a.attribute("/home/alice/Documents/proj/deep/main.c", "deleted", now)["pid"] == 5
    assert a.attribute("/srv/data/report32.csv", "deleted", now)["pid"] == 6
    assert a.attribute("/home/alice/Pictures/x.png", "deleted", now)["attribution"] == "unknown"
    # an exact path on a command line wins over a broader pattern
    a.add_process(ProcRecord(7, "rm", "/bin/rm", ["rm", "/home/alice/Documents/proj/deep/main.c"], "alice", "/",
                             create_time=now - 0.5, seen=now))
    assert a.attribute("/home/alice/Documents/proj/deep/main.c", "deleted", now)["pid"] == 7


# ------------------------------------------------------------------ sealing cadence: small chain, no loss, no blind spot
def _seals(store):
    return [json.loads(r["details"]) for r in store.list_audit(100000, include_bookkeeping=True)
            if r["event"] == "activity_sealed"]


def test_deferred_seal_still_catches_edits_made_before_the_seal(store):
    ids = store.add_activity([{"kind": "app_start", "category": "process", "user": "alice"}] * 3, seal=False)
    assert store.query("SELECT COUNT(*) AS n FROM activity")[0]["n"] == 3          # committed at once
    assert not _seals(store) and store.verify_audit()["ok"]                        # our own pending rows: fine
    store.execute("UPDATE activity SET user = 'mallory' WHERE id = ?", (ids[0],))  # edited before the seal
    store.seal_activity()
    assert any("were modified" in p["problem"] for p in store.verify_audit()["problems"])


def test_rows_left_unsealed_by_a_crash_are_flagged_then_sealed_as_recovered(cfg):
    s1 = Store()
    s1.add_activity([{"kind": "file_opened", "category": "file", "path": "/h/a"}] * 2, seal=False)
    s1.close()                                                  # the agent dies before sealing
    s2 = Store()
    assert any("stopped before sealing" in p["problem"] for p in s2.verify_audit()["problems"])
    mon = ActivityMonitor(cfg, s2)
    mon.start()                                                 # next start: sealed, explicitly marked 'recovered'
    assert s2.verify_audit()["ok"]
    assert any(x.get("recovered") and x["count"] == 2 for x in _seals(s2))
    assert [r for r in s2.list_audit(100) if r["event"] == "activity_recovered"]
    mon.stop()
    s2.close()


def test_routine_activity_does_not_grow_the_signed_chain_every_cycle(store, cfg):
    cfg["activity"]["seal_interval"] = 3600
    mon = ActivityMonitor(cfg, store)
    p = Pump(mon)
    p.tick()
    before = len(_seals(store))
    for _ in range(6):                                           # app starts / stops every cycle
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.4)"])
        p.tick()
        child.wait()
        p.tick()
    assert rows(store, kind="app_stop")
    assert len(_seals(store)) == before                          # committed, sealed later (or at once if important)
    store.add_activity([{"kind": "file_deleted", "category": "file", "path": "/h/x"}], seal=False)
    mon._write([mon._row("file_deleted", "file", time.time(), path="/h/y")], time.time())
    assert len(_seals(store)) == before + 1                      # a deletion is sealed immediately (with the rest)
    assert store.verify_audit()["ok"]
    mon.stop()
