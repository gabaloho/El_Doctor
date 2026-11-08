import os
import shutil
import subprocess
import sys
import time

import psutil
import pytest

from eldoctor.collectors.processes import process_info_from_pid
from eldoctor.models import Alert
from eldoctor.notify.dispatcher import Dispatcher
from eldoctor.playbooks.engine import PlaybookEngine, evaluate, parse_playbook, render, validate_doc
from eldoctor.playbooks.safety import SafetyGuard
from eldoctor.response.actions import Responder


def spawn(*args):
    p = subprocess.Popen(list(args) or [sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    return p


@pytest.fixture
def victim():
    p = spawn()
    yield p
    if p.poll() is None:
        p.kill()
    p.wait()


@pytest.fixture
def responder(cfg, store):
    return Responder(cfg, store, SafetyGuard(cfg))


def pinfo(p):
    return process_info_from_pid(p.pid).to_dict()


# ------------------------------------------------------------------ safety guard
def test_guard_protects_self_parents_init_and_names(cfg):
    cfg["safety"]["only_descendants_of"] = []                 # whole-host scope: test the name/PID rules themselves
    g = SafetyGuard(cfg)
    assert not g.check_process({"pid": 1, "name": "systemd", "exe": "/sbin/init"}, "kill")[0]
    assert not g.check_process({"pid": os.getpid(), "name": "python", "exe": sys.executable}, "kill")[0]
    assert not g.check_process({"pid": os.getppid(), "name": "x", "exe": "/x"}, "kill")[0]
    ok, why = g.check_process({"pid": 99999, "name": "lsass.exe", "exe": "C:\\Windows\\System32\\lsass.exe"}, "kill")
    assert not ok and "protected" in why
    assert not g.check_process({"pid": 99998, "name": "sshd", "exe": "/usr/sbin/sshd"}, "kill")[0]
    assert g.check_process({"pid": 99997, "name": "xmrig", "exe": "/tmp/xmrig", "cmdline": ["xmrig"]}, "kill")[0]


def test_guard_allowlists_and_quarantine_paths(cfg):
    cfg["safety"]["allowlist"] = {"names": ["backup-agent"], "paths": ["/opt/trusted/"], "hashes": ["ab" * 32],
                                  "ips": ["203.0.113.10"]}
    cfg["safety"]["protected_users"] = ["postgres"]
    g = SafetyGuard(cfg)
    assert not g.check_process({"pid": 5000, "name": "backup-agent", "exe": "/x"}, "kill")[0]
    assert not g.check_process({"pid": 5000, "name": "a", "exe": "/opt/trusted/a"}, "kill")[0]
    assert not g.check_process({"pid": 5000, "name": "a", "exe": "/x", "sha256": "AB" * 32}, "kill")[0]
    assert not g.check_process({"pid": 5000, "name": "a", "exe": "/x", "username": "postgres"}, "kill")[0]
    assert not g.check_process({"pid": 5000, "name": "ls", "exe": "/usr/bin/ls"}, "quarantine")[0]
    assert not g.check_quarantine_path("/usr/bin/python3.12")[0]      # interpreter file itself: never
    assert not g.check_ip("203.0.113.10")[0]


@pytest.mark.parametrize("ip,ok", [("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.1", False),
                                   ("169.254.169.254", False), ("168.63.129.16", False), ("::1", False),
                                   ("224.0.0.1", False), ("not-an-ip", False), ("203.0.113.50", True),
                                   ("8.8.4.4", True), ("2001:db8::1", True)])
def test_guard_ip_rules(cfg, ip, ok):
    assert SafetyGuard(cfg).check_ip(ip)[0] is ok


def test_guard_detects_pid_reuse(cfg, victim):
    g = SafetyGuard(cfg)
    d = pinfo(victim)
    assert g.live_process(d)[0] is not None
    d["create_time"] -= 100          # alert was about an older process with the same pid
    p, why = g.live_process(d)
    assert p is None and "reused" in why


def test_circuit_breaker(cfg):
    cfg["safety"]["max_actions_per_window"] = 3
    g = SafetyGuard(cfg)
    assert all(g.consume_action_budget()[0] for _ in range(3))
    ok, why = g.consume_action_budget()
    assert not ok and "tripped" in why and g.breaker_open


# ------------------------------------------------------------------ actions on real processes
def test_kill_and_tree_kill(responder):
    parent = spawn(sys.executable, "-c",
                   "import subprocess,time; [subprocess.Popen(['sleep','60']) for _ in range(3)]; time.sleep(60)")
    time.sleep(0.5)
    kids = [c.pid for c in psutil.Process(parent.pid).children()]
    assert len(kids) == 3
    res = responder.kill(pinfo(parent), tree=True, force=True)
    assert res.status == "success" and res.details["killed"] == 4
    parent.wait(timeout=5)
    time.sleep(0.2)
    assert not any(psutil.pid_exists(k) and psutil.Process(k).status() != psutil.STATUS_ZOMBIE for k in kids)


def test_kill_graceful_then_forced(responder):
    p = spawn(sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)")
    res = responder.kill(pinfo(p), grace=0.5)
    assert res.status == "success" and res.details["forced"] == 1 and "SIGKILL" in res.message


def test_suspend_resume(responder, victim):
    d = pinfo(victim)
    assert responder.suspend(d).status == "success"
    assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED
    assert responder.resume(d).status == "success"
    assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED


def test_renice(responder, victim):
    assert responder.renice(pinfo(victim)).status == "success"
    assert psutil.Process(victim.pid).nice() == 19


def test_dry_run_never_touches(cfg, store, victim):
    r = Responder(cfg, store, SafetyGuard(cfg), dry_run=True)
    assert r.kill(pinfo(victim)).status == "dry_run"
    assert victim.poll() is None


def test_quarantine_and_restore(responder, store, tmp_path):
    exe = tmp_path / "dropper"
    shutil.copy("/bin/sleep", exe)
    os.chmod(exe, 0o755)
    p = spawn(str(exe), "60")
    try:
        res = responder.quarantine(pinfo(p), alert_id="a1")
        assert res.status == "success" and not exe.exists()
        rec = store.list_quarantine()[0]
        assert oct(os.stat(rec["stored_path"]).st_mode & 0o777) == "0o400"       # vault copy is not executable
        assert responder.restore(rec["id"]).status == "success" and exe.exists()
    finally:
        p.kill()


def test_quarantine_recovers_deleted_binary(responder, store, tmp_path):
    exe = tmp_path / "fileless"
    shutil.copy("/bin/sleep", exe)
    p = spawn(str(exe), "60")
    exe.unlink()
    try:
        d = pinfo(p)
        assert d["exe_deleted"]
        res = responder.quarantine(d)
        assert res.status == "success" and "recovered" in res.message
        assert store.list_quarantine()[0]["size"] == os.path.getsize("/bin/sleep")
    finally:
        p.kill()


def test_block_ip_app_level_and_unblock(responder, store):
    r = responder.block_ip("203.0.113.77", "a1", "test")
    assert r.status == "success" and r.details["backend"] in ("app-level", "iptables", "nftables")
    assert responder.block_ip("203.0.113.77").status == "skipped"
    assert responder.block_ip("127.0.0.1").status == "blocked"
    assert responder.unblock_ip("203.0.113.77").status == "success"
    assert store.active_blocks() == []


def test_forensics(responder, victim):
    res = responder.collect_forensics({"id": "x1", "process": pinfo(victim)})
    import json
    data = json.load(open(res.details["path"]))
    assert data["live_process"]["pid"] == victim.pid and "parents" in data["live_process"]


# ------------------------------------------------------------------ playbooks
def make_engine(cfg, store, mode):
    d = Dispatcher(cfg, synchronous=True)
    r = Responder(cfg, store, SafetyGuard(cfg))
    return PlaybookEngine(cfg, store, r, d, mode=mode)


def hog_alert(p, rule="ED-RES-001", sev="high"):
    return Alert(rule_id=rule, title="t", severity=sev, mitre=["T1496"], process=pinfo(p))


def test_bundled_playbooks_valid(cfg, store):
    eng = make_engine(cfg, store, "enforce")
    assert eng.errors == [] and len(eng.playbooks) >= 9


def test_templating_and_conditions():
    ctx = {"alert": {"remote_ip": "1.2.3.4", "process": {"cpu_percent": 95, "name": "xmrig"}, "mitre": ["T1496"]}}
    assert render("{{ alert.remote_ip }}", ctx) == "1.2.3.4"
    assert render("ip={{alert.remote_ip}}!", ctx) == "ip=1.2.3.4!"
    assert evaluate({"field": "alert.process.cpu_percent", "op": "gte", "value": 90}, ctx)
    assert evaluate({"field": "alert.process.name", "op": "in", "value": ["XMRIG", "minerd"]}, ctx)
    assert evaluate({"field": "alert.mitre", "op": "contains", "value": "T1496"}, ctx)
    assert evaluate({"field": "alert.nope", "op": "not_exists"}, ctx)
    assert evaluate({"field": "alert.process.name", "op": "regex", "value": "^xm"}, ctx)


def test_playbook_validation_errors():
    errs = validate_doc({"id": "x", "name": "x", "trigger": {}, "steps": [{"action": "format_disk"}],
                         "max_mode": "yolo"})
    assert any("max_mode" in e for e in errs) and any("format_disk" in e for e in errs) and any("trigger" in e for e in errs)


def test_monitor_mode_only_records(cfg, store, victim):
    run = make_engine(cfg, store, "monitor").handle(hog_alert(victim))[0]
    statuses = {r["action"]: r["status"] for r in run["results"]}
    assert statuses["kill"] == "would_run" and statuses["renice"] == "would_run"
    assert victim.poll() is None and psutil.Process(victim.pid).nice() == 0


def test_enforce_mode_kills(cfg, store, victim):
    run = make_engine(cfg, store, "enforce").handle(hog_alert(victim))[0]
    assert {r["action"]: r["status"] for r in run["results"]}["kill"] == "success"
    victim.wait(timeout=5)


def test_interactive_mode_approval_flow(cfg, store, victim):
    eng = make_engine(cfg, store, "interactive")
    run = eng.handle(hog_alert(victim))[0]
    assert run["status"] == "awaiting_approval" and victim.poll() is None
    assert psutil.Process(victim.pid).nice() == 19              # renice is automatic in interactive mode
    aid = run["approval_id"]
    # a second alert for the same process must not create a second approval
    assert eng.handle(hog_alert(victim))[0]["approval_id"] == aid
    assert len(store.list_approvals("pending")) == 1
    assert store.decide_approval(aid, True, "alice")
    runs = eng.process_approvals()
    assert runs and runs[0]["approved_by"] == "alice"
    victim.wait(timeout=5)


def test_interactive_deny_resumes_suspended_process(cfg, store, tmp_path):
    miner = tmp_path / "xmrig"
    shutil.copy("/bin/sleep", miner)
    p = spawn(str(miner), "60")
    try:
        eng = make_engine(cfg, store, "interactive")
        a = Alert(rule_id="ED-IOC-003", title="miner", severity="critical", source="ioc", mitre=["T1496"],
                  process=pinfo(p))
        run = eng.handle(a)[0]
        assert run["playbook"] == "pb-cryptominer" and run["status"] == "awaiting_approval"
        assert psutil.Process(p.pid).status() == psutil.STATUS_STOPPED
        store.decide_approval(run["approval_id"], False, "alice")
        eng.process_approvals()
        assert psutil.Process(p.pid).status() != psutil.STATUS_STOPPED and miner.exists()
    finally:
        p.kill()


def test_no_approval_for_protected_targets(cfg, store):
    eng = make_engine(cfg, store, "interactive")
    a = Alert(rule_id="ED-PROC-005", title="memfd", severity="high",
              process={"pid": os.getppid(), "name": "bash", "exe": "/usr/bin/bash", "create_time": 0})
    run = eng.handle(a)[0]
    assert store.list_approvals("pending") == []
    assert any(r["status"] == "blocked" for r in run["results"])


def test_breaker_falls_back_to_approval(cfg, store):
    cfg["safety"]["max_actions_per_window"] = 1
    eng = make_engine(cfg, store, "enforce")
    procs = [spawn() for _ in range(2)]
    try:
        eng.handle(hog_alert(procs[0]))
        run = eng.handle(hog_alert(procs[1]))[0]
        assert run["status"] == "awaiting_approval" and procs[1].poll() is None
        assert eng.effective_mode(eng.playbooks[0]) == "interactive"
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()


def test_custom_playbook_dir_and_max_mode(cfg, store, tmp_path, victim):
    d = tmp_path / "pb"
    d.mkdir()
    (d / "x.yml").write_text("""
id: pb-custom
name: custom
priority: 1
exclusive: true
max_mode: monitor
trigger: {rule_ids: [CUSTOM-*]}
steps:
  - {action: kill}
""")
    cfg["playbooks"]["dirs"] = [str(d)]
    eng = make_engine(cfg, store, "enforce")
    run = eng.handle(Alert(rule_id="CUSTOM-1", title="c", severity="high", process=pinfo(victim)))[0]
    assert run["playbook"] == "pb-custom" and run["mode"] == "monitor"
    assert run["results"][0]["status"] == "would_run" and victim.poll() is None


# ------------------------------------------------------------------ regression: never quarantine interpreters
@pytest.mark.parametrize("path", ["/opt/uv-python/cpython-3.14.7/bin/python3.14", "/home/u/.venv/bin/python",
                                  "C:\\Users\\bob\\AppData\\Local\\Programs\\Python\\Python314\\python.exe",
                                  "C:\\Users\\bob\\AppData\\Local\\Programs\\Python\\Python314\\pythonw.exe",
                                  "/usr/local/bin/node", "/opt/homebrew/bin/bash", "C:\\Windows\\System32\\cmd.exe",
                                  "C:\\Program Files\\PowerShell\\7\\pwsh.exe"])
def test_interpreters_are_never_quarantined(cfg, path):
    ok, why = SafetyGuard(cfg).check_quarantine_path(path)
    assert not ok and ("interpreter" in why or "system path" in why)


def test_interpreter_quarantine_takes_the_script_not_the_interpreter(responder, store, tmp_path):
    script = tmp_path / "evil_beacon.py"
    script.write_text("import time\nwhile True: time.sleep(1)\n")
    p = subprocess.Popen([sys.executable, "evil_beacon.py"], cwd=str(tmp_path))     # relative path
    time.sleep(0.5)
    try:
        res = responder.quarantine(pinfo(p))
        assert res.status == "success", res.message
        assert "evil_beacon.py" in res.message and not script.exists()
        assert os.path.exists(sys.executable), "the interpreter must never be touched"
    finally:
        p.kill()


def test_inline_code_interpreter_is_skipped(responder, store):
    p = spawn(sys.executable, "-c", "import time; time.sleep(60)")
    try:
        res = responder.quarantine(pinfo(p))
        assert res.status == "skipped" and "inline code" in res.message
        assert store.list_quarantine() == [] and os.path.exists(sys.executable)
    finally:
        p.kill()



def test_response_scope_limits_actions_to_own_process_tree(cfg, victim):
    """safety.only_descendants_of: tests/CI/labs can never act on unrelated processes of the machine."""
    g = SafetyGuard(cfg)                                       # conftest scopes to this test run's PID
    assert g.check_process(pinfo(victim), "kill")[0]           # our own child: allowed
    outsider = subprocess.Popen(["sleep", "30"], start_new_session=True)
    try:
        ok, why = SafetyGuard(dict(cfg, safety=dict(cfg["safety"], only_descendants_of=[victim.pid]))).check_process(
            {"pid": outsider.pid, "name": "sleep", "exe": "/usr/bin/sleep", "cmdline": ["sleep"]}, "kill")
        assert not ok and "outside the configured response scope" in why
    finally:
        outsider.kill()
