import os
import shutil
import subprocess
import sys
import time

import pytest

from eldoctor.agent import Agent
from eldoctor.auth.users import UserManager
from eldoctor.models import Alert


@pytest.fixture
def admin(store, cfg):
    user, _ = UserManager(store, cfg).register("admin_user", "Str0ng!Passw0rd", "a@example.invalid")
    return user


def fast(cfg):
    cfg["agent"].update(interval=0.5, metrics_csv="metrics.csv")
    cfg["thresholds"].update(process_cpu=70, process_cpu_duration=1.5)
    cfg["safety"]["max_actions_per_window"] = 50
    return cfg


def run_until(agent, pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        agent.tick()
        if pred():
            return True
        time.sleep(0.5)
    return False


def test_agent_kills_cpu_hog_in_enforce_mode(cfg, store, admin):
    agent = Agent(fast(cfg), store, admin, mode="enforce")
    hog = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        assert run_until(agent, lambda: hog.poll() is not None), "CPU hog was not killed"
        rules = {a["rule_id"] for a in store.list_alerts(100) if a["pid"] == hog.pid}
        assert "ED-RES-001" in rules
        acts = [(a["action"], a["status"]) for a in store.list_actions(100)]
        assert ("renice", "success") in acts and ("kill", "success") in acts
        assert (agent.store.path.parent / "metrics.csv").read_text().startswith("timestamp,cpu_usage")
    finally:
        agent.dispatcher.close()
        if hog.poll() is None:
            hog.kill()


def test_agent_detects_miner_correlates_and_quarantines(cfg, store, admin, tmp_path):
    miner = tmp_path / "xmrig"
    shutil.copy("/bin/sleep", miner)
    p = subprocess.Popen([str(miner), "60"])
    agent = Agent(fast(cfg), store, admin, mode="enforce")
    try:
        assert run_until(agent, lambda: p.poll() is not None)
        alerts = [a for a in store.list_alerts(100) if a["pid"] == p.pid]
        assert {"ED-IOC-003", "ED-PROC-001"} <= {a["rule_id"] for a in alerts}
        runs = [a for a in store.list_actions(100) if a["playbook_id"] == "pb-cryptominer" and a["action"] == "kill"]
        assert len(runs) == 1, "correlation must run the containment playbook once per process"
        assert store.list_quarantine() and not miner.exists()
    finally:
        agent.dispatcher.close()
        if p.poll() is None:
            p.kill()


def test_correlation_merges_entity_alerts(cfg, store, admin):
    agent = Agent(fast(cfg), store, admin, mode="monitor")
    proc = {"pid": 123, "create_time": 5.0, "name": "xmrig", "exe": "/tmp/xmrig"}
    a1 = Alert(rule_id="ED-PROC-001", title="tmp", severity="medium", mitre=["T1204.002"], process=proc)
    a2 = Alert(rule_id="ED-IOC-003", title="miner", severity="critical", source="ioc", mitre=["T1496"], process=proc)
    a3 = Alert(rule_id="ED-LOG-001", title="bf", severity="high", remote_ip="203.0.113.9")
    inc = agent.correlate([a1, a2, a3])
    assert len(inc) == 2 and inc[0].rule_id == "ED-IOC-003"
    assert set(inc[0].mitre) == {"T1496", "T1204.002"}
    assert inc[0].evidence["correlated_detections"][0]["rule_id"] == "ED-PROC-001"
    agent.dispatcher.close()


def test_single_instance_lock(cfg, store, admin):
    a1 = Agent(fast(cfg), store, admin, mode="monitor")
    a1._acquire_lock()
    try:
        (a1.store.path.parent / "agent.lock").write_text(str(os.getppid()))   # pretend a live agent owns it
        with pytest.raises(RuntimeError, match="already running"):
            Agent(fast(cfg), store, admin, mode="monitor")._acquire_lock()
    finally:
        (a1.store.path.parent / "agent.lock").unlink()


def test_tui_renders_in_a_pty(tmp_path):
    pyte = pytest.importorskip("pyte")
    env = dict(os.environ, TERM="xterm", PW="Str0ng!Passw0rd", COLUMNS="160", LINES="45")
    base = [sys.executable, "-m", "eldoctor"]
    subprocess.run(base + ["register", "--non-interactive", "--username", "admin_user", "--email", "a@example.invalid",
                           "--password-env", "PW"], env=env, check=True, capture_output=True)
    subprocess.run(base + ["login", "--username", "admin_user", "--password-env", "PW"], env=env, check=True,
                   capture_output=True)
    import pty
    import select
    import struct
    import fcntl
    import termios
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(sys.executable, base + ["tui", "--mode", "monitor", "--interval", "0.5"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 160, 0, 0))
    screen, stream = pyte.Screen(160, 45), pyte.ByteStream()
    stream.attach(screen)
    end = time.time() + 8
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                stream.feed(os.read(fd, 65536))
            except OSError:
                break
    text = "\n".join(screen.display)
    os.write(fd, b"q")
    os.waitpid(pid, 0)
    assert "El Doctor" in text and "MONITOR" in text and "Top processes" in text and "Pending approvals" in text
