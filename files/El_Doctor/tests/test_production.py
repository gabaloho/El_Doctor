"""Production readiness: self-check, bounded files, evidence retention, log file, account recovery, standalone
(frozen) behaviour, first-run without a terminal, installers that upgrade in place, release tooling."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from eldoctor import housekeeping
from eldoctor.auth.users import AuthError, UserManager

ROOT = Path(__file__).resolve().parents[1]
PW = "Str0ng!Passw0rd"


def cli(*args, env_extra=None, stdin=None, timeout=120):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run([sys.executable, "-m", "eldoctor", *args], capture_output=True, text=True, env=env,
                          cwd=str(ROOT), timeout=timeout, stdin=stdin)


@pytest.fixture(autouse=True)
def default_rotation():
    saved = dict(housekeeping.SETTINGS)
    yield
    housekeeping.SETTINGS.update(saved)


# ------------------------------------------------------------------ eldoctor doctor
def test_doctor_is_read_only_and_explains_fixes(tmp_path, monkeypatch):
    home = tmp_path / "fresh"
    monkeypatch.setenv("ELDOCTOR_HOME", str(home))
    r = cli("doctor", "--json", env_extra={"ELDOCTOR_HOME": str(home)})
    assert r.returncode == 0, r.stderr
    checks = {c["area"]: c for c in json.loads(r.stdout)}
    assert not home.exists()                                   # nothing created, not even the data folder
    assert checks["dependencies"]["status"] == "ok"
    assert checks["admin e-mail"]["status"] == "warn" and "activity.report.smtp" in checks["admin e-mail"]["fix"]
    assert "created at the first start" in checks["data folder"]["summary"]
    human = cli("doctor", env_extra={"ELDOCTOR_HOME": str(home)}).stdout
    assert "[WARN] admin e-mail" in human and "->" in human


def test_doctor_fails_on_a_broken_config_and_accepts_smtp(tmp_path):
    home = tmp_path / "h"
    home.mkdir(mode=0o700)
    (home / "config.yaml").write_text("agent: [this is: not valid\n")
    r = cli("doctor", "--json", env_extra={"ELDOCTOR_HOME": str(home)})
    assert r.returncode == 1 and any(c["area"] == "config" and c["status"] == "fail" for c in json.loads(r.stdout))
    (home / "config.yaml").write_text("activity: {report: {smtp: {smtp_host: mail.example.net}}}\n")
    r = cli("doctor", "--json", env_extra={"ELDOCTOR_HOME": str(home)})
    mail = [c for c in json.loads(r.stdout) if c["area"] == "admin e-mail"][0]
    assert r.returncode == 0 and mail["status"] == "ok" and "mail.example.net" in mail["summary"]


# ------------------------------------------------------------------ bounded files
def test_rotation_keeps_n_copies_and_recreates_the_live_file(tmp_path):
    housekeeping.SETTINGS.update(max_bytes=100, keep=2)
    f = tmp_path / "alerts.jsonl"
    for i in range(5):
        f.write_text("x" * 150)
        assert housekeeping.rotate_if_needed(f, header="h\n")
        assert f.read_text() == "h\n"                         # re-created at once, with its header
    assert sorted(p.name for p in tmp_path.iterdir()) == ["alerts.jsonl", "alerts.jsonl.1", "alerts.jsonl.2"]
    assert housekeeping.recently_rotated(f) and not housekeeping.rotate_if_needed(f)


def test_rotated_audit_copies_still_verify_offline(store, cfg, tmp_path):
    from eldoctor.siem import JsonlSink, verify_export
    housekeeping.SETTINGS.update(max_bytes=4000, keep=10)
    sink = JsonlSink({"type": "jsonl", "path": str(tmp_path / "audit.jsonl")})
    for i in range(40):
        store.audit("tester", "event", {"i": i, "pad": "p" * 40})
    recs = store.audit_after(0, 1000)
    for i in range(0, len(recs), 5):                          # the sink rotates before each delivery
        sink.send(recs[i:i + 5])
    parts = sorted(tmp_path.glob("audit.jsonl*"))
    assert len(parts) > 2
    every = []
    for part in parts:
        recs = [json.loads(line) for line in part.read_text().splitlines() if line.strip()]
        every += recs
        if recs:
            assert verify_export(recs)["ok"], part                # each rotated part verifies on its own
    assert verify_export(every)["ok"] and len(every) == len(store.audit_after(0, 1000))


def test_metrics_csv_is_bounded_and_keeps_its_header(tmp_path):
    from eldoctor.collectors.metrics import CSV_HEADER, MetricsCollector
    housekeeping.SETTINGS.update(max_bytes=500, keep=3)
    mc = MetricsCollector(tmp_path / "metrics.csv")
    for _ in range(30):
        mc.log_csv(mc.collect())
    files = sorted(tmp_path.glob("metrics.csv*"))
    assert 1 < len(files) <= 4
    for f in files:
        assert f.read_text().splitlines()[0] == ",".join(CSV_HEADER)


def test_rotation_is_not_mistaken_for_evidence_destruction(store, cfg):
    from eldoctor.activity.monitor import ActivityMonitor
    from eldoctor.config import home_dir
    housekeeping.SETTINGS.update(max_bytes=10, keep=2)
    f = home_dir() / "alerts.jsonl"
    f.write_text("x" * 50)
    mon = ActivityMonitor(cfg, store)
    mon.tick()
    assert housekeeping.rotate_if_needed(f)                      # replaced by an empty file at once
    assert mon.tick() == []
    os.replace(f, f.with_name("alerts.jsonl.2"))                 # sampled in the microseconds of a rotation ...
    assert mon.tick() == []
    f.write_text("")                                             # ... the file is back at the next check
    assert mon.tick() == []
    f.unlink()                                                   # a real deletion is an incident, right after a
    assert mon.tick() == []                                      # rotation too (confirmed on the next check)
    assert [a.rule_id for a in mon.tick()] == ["ED-ACT-003"]
    f.write_text("x" * 40)
    mon.tick()
    time.sleep(0.01)
    housekeeping._rotated.clear()
    f.write_text("")                                             # emptied behind El Doctor's back
    alerts = mon.tick()
    assert [a.rule_id for a in alerts] == ["ED-ACT-003"] and "truncated" in json.dumps(rows_of(store, "evidence_deleted"))


def rows_of(store, kind):
    return store.list_activity(limit=100, kind=kind)


def test_evidence_retention(tmp_path):
    old, new = tmp_path / "a.json", tmp_path / "b.json"
    old.write_text("{}")
    new.write_text("{}")
    os.utime(old, (time.time() - 100 * 86400,) * 2)
    assert housekeeping.prune_evidence(tmp_path, days=90) == 1 and not old.exists() and new.exists()
    assert housekeeping.prune_evidence(tmp_path, days=0) == 0


def test_agent_writes_a_rotating_log_file(store, cfg):
    from eldoctor.agent import Agent
    from eldoctor.config import home_dir
    user = UserManager(store, cfg).register("admin_user", PW, "a@example.invalid")[0]
    agent = Agent(cfg, store, user, mode="monitor")
    import threading
    t = threading.Thread(target=agent.run, kwargs={"duration": 2.0})
    t.start()
    time.sleep(0.7)
    agent.dispatcher.errors.append("smtp.example.net: connection refused")
    t.join(30)
    text = (home_dir() / "logs" / "eldoctor.log").read_text()
    assert "agent starting" in text and "agent stopped" in text and "connection refused" in text


# ------------------------------------------------------------------ passwords and recovery
def test_password_change_reset_and_local_recovery(cfg):
    from eldoctor.api.client import ApiClient, ApiError
    from eldoctor.api.peercred import Peer, own_identity
    from eldoctor.api.server import AgentService
    from eldoctor.api.transport import InProcessTransport
    svc = AgentService(cfg)
    try:
        def client(peer=None):
            c = ApiClient(InProcessTransport(svc.handle, peer or own_identity(), f"t-{id(svc)}"), "cli")
            c.token = None
            return c
        adm = client()
        adm.call("auth.register", username="admin1", password=PW, email="a@example.invalid")
        adm.login("admin1", PW)
        adm.call("users.add", username="analyst1", password="An4lyst!Passw0rd", email="b@example.invalid",
                 role="analyst")
        other = client()
        other.login("admin1", PW)
        with pytest.raises(ApiError) as e:
            adm.call("auth.change_password", old="wrong-Passw0rd!", new="N3w!Passw0rd-x")
        assert "wrong" in e.value.message
        with pytest.raises(ApiError):
            adm.call("auth.change_password", old=PW, new="weak")
        adm.call("auth.change_password", old=PW, new="N3w!Passw0rd-x")
        with pytest.raises(ApiError) as e:                      # every session ended, the other one too
            other.call("auth.whoami")
        assert e.value.code == "unauthenticated"
        adm.login("admin1", "N3w!Passw0rd-x")
        adm.call("users.reset_password", username="analyst1", password="R3set!Passw0rd")
        client().login("analyst1", "R3set!Passw0rd")
        # forgotten + locked out: another OS account may not recover, the agent's own account may
        for _ in range(5):
            with pytest.raises(ApiError):
                client().login("admin1", "nope-Wr0ng!pass")
        stranger = Peer(pid=1, uid="4242", user="mallory", groups=[], transport="unix")
        with pytest.raises(ApiError) as e:
            client(stranger).call("auth.recover", password="Hack3d!Passw0rd")
        assert e.value.code == "forbidden"
        assert any(r["event"] == "api_denied" and "auth.recover" in r["details"] for r in svc.store.list_audit(100))
        res = client().call("auth.recover", password="Rec0vered!Passw0rd")
        assert res == {"username": "admin1", "role": "admin"}            # the first admin by default
        client().login("admin1", "Rec0vered!Passw0rd")                   # unlocked
        rec = [r for r in svc.store.list_audit(200) if r["event"] == "account_recovered"][0]
        assert "by_os_account" in rec["details"]
        assert svc.verify_audit()["ok"]
    finally:
        svc.close()


def test_recover_reenables_a_disabled_admin(store, cfg):
    um = UserManager(store, cfg)
    a = um.register("admin1", PW, "a@example.invalid")[0]
    um.register("admin2", PW, "b@example.invalid", role="admin", created_by=a)
    um.set_active(um.get("admin2"), "admin1", False)
    with pytest.raises(AuthError):
        um.authenticate("admin1", PW)
    um.recover("admin1", "Back!Passw0rd-1", "root (uid 0)")
    assert um.authenticate("admin1", "Back!Passw0rd-1").active


def test_cli_recover_admin(tmp_path):
    env = {"P": PW, "N": "Cl1!Recovered-pw"}
    assert cli("register", "--non-interactive", "--username", "owner", "--email", "o@example.invalid",
               "--password-env", "P", "--json", env_extra=env).returncode == 0
    r = cli("recover-admin", "--password-env", "N", env_extra=env)
    assert r.returncode == 0 and "Recovered 'owner'" in r.stdout, r.stderr
    assert cli("login", "--username", "owner", "--password-env", "N", env_extra=env).returncode == 0


# ------------------------------------------------------------------ standalone (frozen) behaviour
def test_frozen_build_behaviour(monkeypatch, tmp_path):
    from eldoctor import _bootstrap
    from eldoctor.cli import prog
    from eldoctor.deploy.generator import bundled_binaries, generate
    exe = tmp_path / "eldoctor"
    exe.write_bytes(b"\x7fELF standalone")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert prog() == "eldoctor" and _bootstrap.missing_dependencies() == []
    monkeypatch.setattr(_bootstrap, "tk_missing", lambda: True)
    assert "without the desktop GUI" in _bootstrap.tk_problem()
    if sys.platform.startswith("linux"):
        assert bundled_binaries("linux") == [exe] and bundled_binaries("windows") == []
        files = generate("linux", tmp_path / "bundle")
        assert (tmp_path / "bundle" / "eldoctor").read_bytes() == exe.read_bytes()
        assert any(f.name.endswith("-src.zip") for f in files)


def test_started_without_a_terminal_does_not_hang(tmp_path):
    r = cli(stdin=subprocess.DEVNULL, env_extra={"DISPLAY": "", "WAYLAND_DISPLAY": ""})
    assert r.returncode == 2 and "doctor" in r.stderr


def test_installers_upgrade_in_place_and_prefer_the_standalone_binary(tmp_path):
    from eldoctor.deploy.generator import generate
    generate("linux", tmp_path / "l")
    generate("windows", tmp_path / "w")
    sh = (tmp_path / "l" / "install.sh").read_text()
    assert 'if [[ -x "$HERE/eldoctor"' in sh and "UPGRADE=1" in sh and "systemctl restart" in sh
    assert subprocess.run(["bash", "-n", str(tmp_path / "l" / "install.sh")]).returncode == 0
    assert "ExecStart=/opt/eldoctor/bin/eldoctor" in (tmp_path / "l" / "eldoctor.service").read_text()
    ps = (tmp_path / "w" / "install.ps1").read_text()
    assert "Stop-ScheduledTask" in ps and "$Upgrade" in ps and 'Test-Path "$PSScriptRoot\\eldoctor.exe"' in ps
    assert ps.count("{") == ps.count("}")                     # template braces balanced after .format()


# ------------------------------------------------------------------ release tooling
def test_single_source_version_and_release_notes():
    import eldoctor
    sys.path.insert(0, str(ROOT / "packaging"))
    from release_notes import section
    assert 'dynamic = ["version"]' in (ROOT / "pyproject.toml").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"## [{eldoctor.__version__}]" in changelog
    text = section(eldoctor.__version__, changelog)
    assert text and not text.startswith("## [") and "## [2.0.0]" not in text    # this version only
    assert section("0.0.0", changelog) == "See CHANGELOG.md."


def test_lock_file_pins_every_dependency_with_hashes():
    lock = (ROOT / "requirements.lock").read_text()
    for dep in ("psutil==", "pyyaml==", "cryptography==", "windows-curses=="):
        assert dep in lock.lower()
    import re
    blocks = re.split(r"\n(?=[A-Za-z])", lock.split("\n\n", 1)[1].strip())   # one block per pinned package
    for b in blocks:
        assert re.match(r"^[A-Za-z0-9_.-]+==\S+", b) and "--hash=sha256:" in b, b[:60]
    assert len(blocks) >= 6 and lock.count("--hash=sha256:") > 50


@pytest.mark.skipif(not os.environ.get("ELDOCTOR_TEST_BINARY"), reason="set ELDOCTOR_TEST_BINARY to a built executable")
def test_built_standalone_executable():
    sys.path.insert(0, str(ROOT / "packaging"))
    from build_release import smoke_test
    results = smoke_test(Path(os.environ["ELDOCTOR_TEST_BINARY"]))
    assert "running agent records file activity" in results
