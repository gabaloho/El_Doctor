"""El Doctor Hub: enrollment, mutual TLS, fleet alerts, remote response, threat-intel distribution, silent /
tampered agents, the analyst web console, the CLI.  Everything runs for real on localhost: TLS servers, certificates,
the agent's detection store, child processes killed on the hub's order."""
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

from eldoctor.fleet import pki
from eldoctor.fleet.hub import Hub, HubError, HubServer
from eldoctor.fleet.link import HubLink, LinkError, enroll, link_info
from eldoctor.models import Alert

ROOT = Path(__file__).resolve().parents[1]
PW = "Str0ng!Passw0rd"


class Op:
    def __init__(self, name="op", role="admin"):
        self.username, self.role, self.active = name, role, True

    def can(self, perm):
        from eldoctor.auth.users import PERMISSIONS
        return perm in PERMISSIONS[self.role]


@pytest.fixture
def hub(tmp_path):
    home = tmp_path / "hub"
    Hub.init(home, ["127.0.0.1", "localhost"])
    cfg = yaml.safe_load((home / "hub.yaml").read_text())
    cfg["hub"].update(agent_listen="127.0.0.1:0", console_listen="127.0.0.1:0", checkin_interval=2, silent_after=60)
    (home / "hub.yaml").write_text(yaml.safe_dump(cfg))
    h = Hub(home)
    h.users.register("socadmin", PW, "soc@corp.example", "", "", "soc", "linux")
    srv = HubServer(h)
    where = srv.start()
    h.agent_port = int(where["agent_api"].rsplit(":", 1)[1])
    h.console_port = int(where["console"].rsplit(":", 1)[1])
    h.hc["public_url"] = f"https://127.0.0.1:{h.agent_port}"
    yield h
    srv.stop()
    h.close()


@pytest.fixture
def agent(cfg, store):
    from eldoctor.agent import Agent
    from eldoctor.auth.users import UserManager
    user, _ = UserManager(store, cfg).register("localadmin", PW, "l@example.invalid")
    a = Agent(cfg, store, user, mode="monitor")
    yield a
    a.dispatcher.close()


def enrolled(hub, agent):
    enroll(hub.create_token("socadmin"))
    return HubLink(agent)


# ------------------------------------------------------------------ PKI and tokens
def test_certificates_and_tokens(tmp_path):
    from cryptography.x509.oid import ExtendedKeyUsageOID
    ca_key, ca = pki.create_ca()
    _, srv = pki.issue_server_cert(ca_key, ca, ["hub.corp.example", "10.0.0.5"])
    key = pki.new_key()
    cert = pki.sign_agent_csr(ca_key, ca, pki.make_csr(key, "attacker-chosen-CN"), "laptop-1234")
    assert pki.agent_id_of(cert) == "laptop-1234"                    # the hub chooses the identity, not the CSR
    from cryptography import x509
    eku = lambda c: list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)  # noqa: E731
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku(cert) and ExtendedKeyUsageOID.SERVER_AUTH not in eku(cert)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku(srv)
    tok = pki.make_token("https://hub.corp.example:8443", pki.new_secret(), pki.fingerprint(ca))
    t = pki.parse_token(tok)
    assert t["url"] == "https://hub.corp.example:8443" and t["ca_fingerprint"] == pki.fingerprint(ca)
    for bad in ("", "hello", tok[:-10] + "!!!!", pki.make_token("http://insecure", pki.new_secret(), "sha256:x")):
        with pytest.raises(pki.PkiError):
            pki.parse_token(bad)


# ------------------------------------------------------------------ enrollment + the whole check-in flow
def test_enroll_report_respond_and_distribute_intel(hub, agent, tmp_path):
    tok = hub.create_token("socadmin", uses=1)
    info = enroll(tok)
    assert link_info()["agent_id"] == info["agent_id"] and link_info()["url"] == info["url"]
    from eldoctor.config import home_dir
    assert oct((home_dir() / "hub" / "agent.key").stat().st_mode)[-3:] == "600"
    with pytest.raises(LinkError) as e:                                 # single use
        enroll(tok)
    assert "403" in str(e.value)
    assert [r for r in hub.store.list_audit(50) if r["event"] == "hub_enroll_refused"]
    link = HubLink(agent)
    # --- alerts reach the hub once (at-least-once delivery, no duplicates)
    agent.store.add_alert(Alert(rule_id="ED-IOC-003", title="Process name matches known malicious tool",
                                severity="critical", process={"pid": 1, "name": "xmrig"}))
    link.checkin_once()
    link.checkin_once()
    fleet = hub.alerts(status="open")
    assert len(fleet) == 1 and fleet[0]["severity"] == "critical" and fleet[0]["agent_id"] == info["agent_id"]
    a = hub.agents()[0]
    assert a["state"] == "online" and a["mode"] == "monitor" and a["audit_seq"] > 0
    # --- remote response: kill a real process on the endpoint
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        cid = hub.create_command(Op("analyst1", "analyst"), info["agent_id"], "kill", {"pid": victim.pid})
        link.checkin_once()                                              # delivered + executed
        assert victim.wait(15) is not None
        link.checkin_once()                                              # result reported
        c = [x for x in hub.commands() if x["id"] == cid][0]
        assert c["status"] == "done" and c["result"]["status"] == "success"
        local = [r for r in agent.store.list_audit(200) if r["event"] == "remote_command"]
        assert local and local[0]["actor"] == "hub:analyst1"             # the endpoint knows who asked
        # re-delivery of the same command (answer lost): executed once only
        hub.x("UPDATE hub_commands SET status = 'pending' WHERE id = ?", (cid,))
        link.checkin_once()
        assert len([r for r in agent.store.list_audit(300) if r["event"] == "remote_command"]) == 1
    finally:
        if victim.poll() is None:
            victim.kill()
    # --- the endpoint's own policy wins: not allowed here / enforce not allowed remotely
    link.allowed.discard("block_ip")
    cb = hub.create_command(Op("analyst1", "analyst"), info["agent_id"], "block_ip", {"ip": "203.0.113.9"})
    ce = hub.create_command(Op("socadmin", "admin"), info["agent_id"], "set_mode", {"mode": "enforce"})
    link.checkin_once()
    link.checkin_once()
    res = {x["id"]: x for x in hub.commands()}
    assert res[cb]["status"] == "failed" and "not allowed" in res[cb]["result"]["message"]
    assert res[ce]["status"] == "failed" and "enforce" in res[ce]["result"]["message"] and agent.mode == "monitor"
    with pytest.raises(HubError):                                        # analysts cannot even ask for enforce
        hub.create_command(Op("analyst1", "analyst"), info["agent_id"], "set_mode", {"mode": "enforce"})
    # --- fleet threat intel: one indicator at the hub, detected by the agent
    iid = hub.add_intel("socadmin", "ip", "203.0.113.77", "critical", "C2 of incident 42")
    link.checkin_once()
    assert agent.engine.iocs.match_ip("203.0.113.77") is not None
    from eldoctor.detection.ioc import IOCStore
    assert IOCStore.from_config(agent.cfg).match_ip("203.0.113.77") is not None     # survives a restart
    hub.remove_intel("socadmin", iid)
    link.checkin_once()
    assert agent.engine.iocs.match_ip("203.0.113.77") is None


def test_a_forged_hub_is_refused_before_the_secret_is_sent(hub, agent):
    tok = hub.create_token("socadmin")
    t = pki.parse_token(tok)
    forged = pki.make_token(t["url"], t["secret"], "sha256:" + "0" * 64)      # someone else's CA
    with pytest.raises(LinkError) as e:
        enroll(forged)
    assert "interception" in str(e.value)
    assert hub.q("SELECT uses_left FROM hub_tokens")[0]["uses_left"] == 1    # the secret never reached the hub


def test_mutual_tls_and_revocation(hub, agent, tmp_path):
    link = enrolled(hub, agent)
    link.checkin_once()
    ctx = ssl.create_default_context(cafile=str(hub.home / "pki" / "ca.crt"))
    req = urllib.request.Request(f"https://127.0.0.1:{hub.agent_port}/v1/checkin", data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as e:                       # no client certificate
        urllib.request.urlopen(req, context=ctx, timeout=10)
    assert e.value.code == 401
    # a certificate from another CA is rejected during the TLS handshake
    other_key, other_ca = pki.create_ca("Evil CA")                     # same agent id, another CA
    k = pki.new_key()
    fake = pki.sign_agent_csr(other_key, other_ca, pki.make_csr(k), link_info()["agent_id"])
    (tmp_path / "fake.crt").write_bytes(pki.cert_pem(fake))
    (tmp_path / "fake.key").write_bytes(pki.key_pem(k))
    evil = ssl.create_default_context(cafile=str(hub.home / "pki" / "ca.crt"))
    evil.load_cert_chain(str(tmp_path / "fake.crt"), str(tmp_path / "fake.key"))
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError)):
        urllib.request.urlopen(req, context=evil, timeout=10)
    # revoked: refused, and the attempt is an alert
    hub.revoke(link_info()["agent_id"], "socadmin")
    with pytest.raises(LinkError) as e:
        link.checkin_once()
    assert "403" in str(e.value) and "revoked" in str(e.value)
    assert any(r["rule_id"] == "HUB-004" for r in hub.alerts(status="open"))


# ------------------------------------------------------------------ the hub's own detections
def test_silent_agent_is_an_alert_and_its_return_too(hub, agent, tmp_path):
    link = enrolled(hub, agent)
    link.checkin_once()
    aid = link_info()["agent_id"]
    hub.x("UPDATE hub_agents SET last_seen = ? WHERE id = ?", (time.time() - 3600, aid))
    assert hub.agents()[0]["state"] == "silent"
    raised = hub.sweep()
    assert len(raised) == 1 and hub.sweep() == []                          # once, not every sweep
    hub.dispatcher().flush()
    notes = (hub.home / "hub-alerts.jsonl").read_text()
    assert "stopped reporting" in notes                                    # the SOC is notified
    link.checkin_once()
    rules = [r["rule_id"] for r in hub.alerts(status="open")]
    assert "HUB-001" in rules and "HUB-002" in rules
    back = [r for r in hub.alerts(status="open") if r["rule_id"] == "HUB-002"][0]
    assert hub.alert(back["id"])["data"]["evidence"]["gap_seconds"] >= 3500


def test_audit_trail_rollback_on_an_endpoint_is_detected(hub, agent):
    link = enrolled(hub, agent)
    link.checkin_once()
    a = hub.q("SELECT * FROM hub_agents")[0]
    fp = a["cert_fp"]
    head = link.audit_head()
    hub.checkin(a["id"], fp, {"audit_head": {"seq": head["seq"] + 40, "hash": "a" * 64, "genesis": head["genesis"]}},
                "127.0.0.1")
    hub.checkin(a["id"], fp, {"audit_head": {"seq": head["seq"] + 3, "hash": "b" * 64, "genesis": head["genesis"]}},
                "127.0.0.1")                                               # database restored from an old copy
    crit = [r for r in hub.alerts(status="open") if r["rule_id"] == "HUB-003"]
    assert len(crit) == 1 and crit[0]["severity"] == "critical"
    hub.checkin(a["id"], fp, {"audit_head": {"seq": head["seq"] + 3, "hash": "b" * 64, "genesis": head["genesis"]}},
                "127.0.0.1")
    assert len([r for r in hub.alerts(status="open") if r["rule_id"] == "HUB-003"]) == 1   # one alert per event
    hub.checkin(a["id"], fp, {"audit_head": {"seq": head["seq"] + 3, "hash": "c" * 64, "genesis": head["genesis"]}},
                "127.0.0.1")                                               # same record, different content
    assert len([r for r in hub.alerts(status="open") if r["rule_id"] == "HUB-003"]) == 2


def test_triage_rules_and_audit(hub, agent):
    link = enrolled(hub, agent)
    agent.store.add_alert(Alert(rule_id="ED-RES-001", title="CPU hog", severity="high"))
    link.checkin_once()
    hid = hub.alerts()[0]["id"]
    with pytest.raises(HubError):
        hub.triage(hid, "alice", status="closed")                           # a verdict is required to close
    with pytest.raises(HubError):
        hub.triage(hid, "alice", status="done")
    hub.triage(hid, "alice", status="investigating", assignee="alice", note="looking at the build server")
    r = hub.triage(hid, "alice", status="closed", verdict="false_positive", note="nightly build")
    assert r["status"] == "closed" and r["verdict"] == "false_positive" and len(r["notes"]) == 2
    assert hub.alerts(status="open") == []
    assert len([x for x in hub.store.list_audit(100) if x["event"] == "hub_alert_triaged"]) == 2
    assert hub.store.verify_audit()["ok"]


# ------------------------------------------------------------------ web console
class Browser:
    def __init__(self, port, cafile):
        self.base = f"https://127.0.0.1:{port}"
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context(cafile=cafile)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        self.op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                              urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def go(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try:
            r = self.op.open(self.base + path, data=body, timeout=15)
            return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), dict(exc.headers)

    def csrf(self, path):
        return re.search(r'name=csrf value="([^"]+)"', self.go(path)[1]).group(1)


def test_web_console_security(hub, agent):
    link = enrolled(hub, agent)
    agent.store.add_alert(Alert(rule_id="ED-X", title="<script>alert('xss')</script>", severity="critical",
                                process={"pid": 99999, "name": "<img src=x onerror=alert(1)>", "create_time": 1.0}))
    link.checkin_once()
    hid = hub.alerts()[0]["id"]
    hub.users.register("viewer1", "V1ewer!Passw0rd", "v@corp.example", "", "", "soc", "linux")
    ca = str(hub.home / "pki" / "ca.crt")
    anon = Browser(hub.console_port, ca)
    st, _, hdr = anon.go("/")
    assert st == 303 and hdr["Location"] == "/login"                      # nothing without signing in
    assert anon.go("/login", {"username": "socadmin", "password": "wrong"})[0] == 401
    admin = Browser(hub.console_port, ca)
    st, _, hdr = admin.go("/login", {"username": "socadmin", "password": PW})
    assert st == 303 and "HttpOnly" in hdr["Set-Cookie"] and "Secure" in hdr["Set-Cookie"] and \
        "SameSite=Strict" in hdr["Set-Cookie"]
    st, page, hdr = admin.go(f"/alert?id={urllib.parse.quote(hid)}")
    assert st == 200 and "frame-ancestors 'none'" in hdr["Content-Security-Policy"]
    assert "<script>alert" not in page and "&lt;script&gt;" in page          # attacker-controlled text escaped
    assert "<img src=x" not in page
    for path in ("/", "/agents", "/alerts?status=open", "/commands", "/intel", "/tokens", "/audit"):
        assert admin.go(path)[0] == 200, path
    # CSRF: a form post without the session's token is refused
    st, _, _ = admin.go("/alert/triage", {"id": hid, "status": "acknowledged"})
    assert st == 403 and hub.alert(hid)["status"] == "new"
    tok = admin.csrf(f"/alert?id={urllib.parse.quote(hid)}")
    assert admin.go("/alert/triage", {"id": hid, "status": "acknowledged", "verdict": "", "note": "on it",
                                      "assignee": "socadmin", "csrf": tok})[0] == 303
    assert hub.alert(hid)["status"] == "acknowledged"
    # roles: a viewer sees, but cannot respond, triage or enroll
    viewer = Browser(hub.console_port, ca)
    viewer.go("/login", {"username": "viewer1", "password": "V1ewer!Passw0rd"})
    vt = viewer.csrf("/alerts")
    assert viewer.go("/agent/command", {"agent": link_info()["agent_id"], "action": "ping", "csrf": vt})[0] == 403
    assert viewer.go("/alert/triage", {"id": hid, "status": "closed", "verdict": "benign", "csrf": vt})[0] == 403
    assert viewer.go("/tokens")[0] == 403 and hub.commands() == []
    # an analyst sends a response command from the console (the agent runs it at its next check-in)
    hub.users.register("analyst1", "An4lyst!Passw0rd", "an@corp.example", "", "", "soc", "linux", role="analyst",
                       created_by=Op())
    analyst = Browser(hub.console_port, ca)
    analyst.go("/login", {"username": "analyst1", "password": "An4lyst!Passw0rd"})
    at = analyst.csrf("/alerts")
    st, _, hdr = analyst.go("/agent/command", {"agent": link_info()["agent_id"], "action": "ping", "csrf": at})
    assert st == 303 and [c["created_by"] for c in hub.commands()] == ["analyst1"]
    link.checkin_once()
    link.checkin_once()
    assert hub.commands()[0]["status"] == "done" and "pong" in hub.commands()[0]["result"]["message"]
    # an admin creates an enrollment token from the console (shown once)
    st, page, _ = admin.go("/tokens", {"uses": "3", "hours": "2", "note": "finance", "csrf": tok})
    assert st == 200 and "EDH1-" in page
    # sign out ends the session
    admin.go("/logout", {"csrf": tok})
    assert admin.go("/")[0] == 303


# ------------------------------------------------------------------ command line, real processes
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_cli_hub_and_agent_processes(tmp_path):
    env = dict(os.environ, P=PW, ELDOCTOR_HUB_HOME=str(tmp_path / "hubhome"))
    run = lambda *a, e=None: subprocess.run([sys.executable, "-m", "eldoctor", *a], capture_output=True, text=True,
                                            env=e or env, cwd=str(ROOT), timeout=120)
    ap, cp = _free_port(), _free_port()
    r = run("hub", "init", "--name", "127.0.0.1", "--port", str(ap), "--console-port", str(cp), "--admin-username",
            "socadmin", "--admin-email", "soc@corp.example", "--password-env", "P")
    assert r.returncode == 0 and "CA fingerprint: sha256:" in r.stdout, r.stderr
    hy = tmp_path / "hubhome" / "hub.yaml"
    conf = yaml.safe_load(hy.read_text())
    conf["hub"]["checkin_interval"] = 2                                 # test pace (production: 15 s)
    hy.write_text(yaml.safe_dump(conf))
    hub = subprocess.Popen([sys.executable, "-m", "eldoctor", "hub", "serve"], env=env, cwd=str(ROOT),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    agent = None
    try:
        time.sleep(3)
        tok = run("hub", "token").stdout.split()[4]
        aenv = dict(env, ELDOCTOR_HOME=str(tmp_path / "agenthome"), ELDOCTOR_CLIENT_DIR=str(tmp_path / "ac"))
        key = json.loads(run("register", "--non-interactive", "--username", "owner", "--email", "o@example.invalid",
                             "--password-env", "P", "--json", e=aenv).stdout)["api_key"]
        r = run("enroll", tok, e=aenv)
        assert r.returncode == 0 and "Enrolled as" in r.stdout, r.stderr
        agent = subprocess.Popen([sys.executable, "-m", "eldoctor", "--api-key", key, "run", "--headless",
                                  "--duration", "40"], env=aenv, cwd=str(ROOT), stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
        state = ""
        for _ in range(40):
            rows = json.loads(run("hub", "agents", "--json").stdout or "[]")
            state = rows[0]["state"] if rows else ""
            if state == "online" and rows[0]["mode"]:
                break
            time.sleep(1)
        assert state == "online"
        aid = rows[0]["id"]
        assert run("hub", "respond", aid, "ping").returncode == 0
        for _ in range(30):
            cmds = run("hub", "commands").stdout
            if "done" in cmds:
                break
            time.sleep(1)
        assert "done" in cmds and "ping" in cmds
    finally:
        for p in (agent, hub):
            if p and p.poll() is None:
                p.terminate()
                p.wait(30)


def test_analyst_added_indicators_survive_a_restart(cfg):
    from eldoctor.detection.ioc import IOCStore, add_local_ioc
    add_local_ioc("ip", "198.51.100.77", "critical", "analyst-added C2")
    assert IOCStore.from_config(cfg).match_ip("198.51.100.77") is not None


def test_hub_service_install_is_hardened_and_unprivileged(tmp_path, monkeypatch):
    import argparse
    import eldoctor.fleet.cli as fcli
    calls = []

    def fake(cmd):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if cmd[:2] == ["id", "-u"] else 0, "", "")
    monkeypatch.setattr(fcli, "HUB_UNIT_PATH", tmp_path / "eldoctor-hub.service")
    monkeypatch.setattr("eldoctor.config.is_privileged", lambda: True)
    args = argparse.Namespace(hub_home=str(tmp_path / "hubhome"), name=["hub.corp.example"], port=8443,
                              console_port=8444, admin_username="socadmin", admin_email="soc@corp.example",
                              password_env="P")
    monkeypatch.setenv("P", PW)
    assert fcli.install_hub_service(args, run_cmd=fake) == 0
    assert ["useradd", "--system", "--home-dir", str(tmp_path / "hubhome"), "--no-create-home", "--shell",
            "/usr/sbin/nologin", "eldoctor-hub"] in calls
    assert ["chown", "-R", "eldoctor-hub:eldoctor-hub", str(tmp_path / "hubhome")] in calls
    unit = (tmp_path / "eldoctor-hub.service").read_text()
    for must in ("User=eldoctor-hub", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n",
                 f"ReadWritePaths={tmp_path / 'hubhome'}", "hub serve"):
        assert must in unit, must
    assert calls[-1] == ["systemctl", "restart", "eldoctor-hub.service"]
    h = Hub(tmp_path / "hubhome")
    assert h.users.get("socadmin").role == "admin"
    h.close()


def test_the_hub_resists_floods(hub):
    import threading
    # refused enrollments: always refused, recorded once a minute per address (no audit-trail flooding)
    ctx = ssl.create_default_context(cafile=str(hub.home / "pki" / "ca.crt"))
    body = json.dumps({"secret": "x" * 43, "csr": "", "hostname": "probe"}).encode()
    for _ in range(20):
        req = urllib.request.Request(f"https://127.0.0.1:{hub.agent_port}/v1/enroll", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, context=ctx, timeout=10)
        assert e.value.code == 403
    assert len([r for r in hub.store.list_audit(200) if r["event"] == "hub_enroll_refused"]) == 1
    # a flood of idle connections: at most TLSServer.max_connections threads, the rest closed at once
    from eldoctor.fleet.hub import TLSServer
    before = threading.active_count()
    idle = []
    try:
        for _ in range(TLSServer.max_connections + 80):
            idle.append(socket.create_connection(("127.0.0.1", hub.agent_port), timeout=5))
        time.sleep(1.0)
        assert threading.active_count() - before <= TLSServer.max_connections + 5
    finally:
        for c in idle:
            c.close()
    time.sleep(1.0)
    ok = urllib.request.urlopen(f"https://127.0.0.1:{hub.agent_port}/v1/health", context=ctx, timeout=30).read()
    assert json.loads(ok)["ok"] is True                                # still serving once the flood is gone
