#!/usr/bin/env python3
"""Interactive-mode demo: approvals from a second process (the analyst's terminal).

Requires an agent already running in interactive mode on the same ELDOCTOR_HOME
(LAB_SCOPE_PID=$$ scripts/lab.sh interactive none).  The analyst's commands below are
clients of the agent's local API: the agent checks the approve permission, seals the
decision and writes the hash-chained audit record.  Scenario:
  1. CPU hog  -> renice (automatic) + forensics -> approval requested -> analyst APPROVES -> killed
  2. miner    -> suspended (automatic, reversible) -> approval requested -> analyst DENIES -> resumed
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eldoctor.storage import Store  # noqa: E402

SIM = Path("/tmp/eldoctor-sim")
ROOT = Path(__file__).resolve().parents[1]
LAB_CFG = Path("/tmp/ed_lab_config.yaml")          # written by scripts/lab.sh (response scope included)
ED = [sys.executable, "-m", "eldoctor", "--config",
      str(LAB_CFG if LAB_CFG.exists() else Path(__file__).with_name("lab_config.yaml"))]


def wait_approval(store, pid, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        for a in store.list_approvals("pending"):
            if f"[{pid}]" in a["summary"]:
                return a
        time.sleep(0.5)
    return None


def state(pid):
    try:
        return psutil.Process(pid).status()
    except psutil.NoSuchProcess:
        return "terminated"


def main() -> int:
    store = Store()
    ok = True
    print("== 1. CPU hog in interactive mode")
    hog = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    t0 = time.time()
    ap = wait_approval(store, hog.pid)
    if not ap:
        print("   no approval requested!"); return 1
    print(f"   t+{time.time() - t0:.1f}s approval {ap['id']} pending: {ap['summary']}")
    print(f"   nice value now: {psutil.Process(hog.pid).nice()} (renice ran automatically), state: {state(hog.pid)}")
    time.sleep(2)
    print(f"   still alive while waiting for the analyst: {state(hog.pid)}")
    r = subprocess.run(ED + ["approvals", "approve", ap["id"]], capture_output=True, text=True, cwd=ROOT)
    print("   analyst> eldoctor approvals approve", ap["id"], "->", r.stdout.strip() or r.stderr.strip())
    try:
        hog.wait(timeout=15)
        print(f"   result: process {hog.pid} terminated (rc {hog.returncode}) {time.time() - t0:.1f}s after start")
    except subprocess.TimeoutExpired:
        print("   result: STILL ALIVE"); ok = False; hog.kill()

    print("== 2. Miner in interactive mode, analyst denies (false positive)")
    miner = SIM / "xmrig"
    shutil.copy(SIM / "sleeper", miner); os.chmod(miner, 0o755)
    m = subprocess.Popen([str(miner), "--donate-level", "1", "-o", "stratum+tcp://pool.example.org:3333"])
    ap = wait_approval(store, m.pid)
    if not ap:
        print("   no approval requested!"); return 1
    print(f"   approval {ap['id']} pending: {ap['summary']}")
    print(f"   process state while waiting: {state(m.pid)}  (suspended automatically - reversible)")
    r = subprocess.run(ED + ["approvals", "deny", ap["id"]], capture_output=True, text=True, cwd=ROOT)
    print("   analyst> eldoctor approvals deny", ap["id"], "->", r.stdout.strip() or r.stderr.strip())
    time.sleep(3)
    st = state(m.pid)
    print(f"   result: process state {st} (expected: resumed / sleeping), binary still on disk: {miner.exists()}")
    ok &= st in ("sleeping", "running")
    m.kill()
    print("== approvals history")
    print(subprocess.run(ED + ["approvals", "list", "--all"], capture_output=True, text=True, cwd=ROOT).stdout)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
