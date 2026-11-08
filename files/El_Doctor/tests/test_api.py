"""The local authenticated API: every permission is decided by the agent, not by a front end.

Cross-account cases (a token replayed from another OS account, unknown peers, groups) use Peer
identities handed to the same handler the socket server calls; the real AF_UNIX path, with kernel
peer credentials, is exercised with this test account (the sandbox has no second account / root).
"""
import base64
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from eldoctor.api.client import ApiClient, ApiError, RemoteAgent, connect
from eldoctor.api.peercred import Peer, own_identity
from eldoctor.api.server import METHODS, AgentService
from eldoctor.api.transport import InProcessTransport, UnixTransport, trusted_server_uids
from eldoctor.auth.users import PERMISSIONS
from eldoctor.models import Alert

PW = "Str0ng!Passw0rd"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def svc(cfg):
    s = AgentService(cfg)
    yield s
    s.close()


def client(svc, peer=None, name="cli"):
    """A fresh API client (own session: tokens persisted by other test clients are not picked up)."""
    c = ApiClient(InProcessTransport(svc.handle, peer or own_identity(), f"test-{id(svc)}"), name)
    c.token = None
    return c


def other_peer(uid="4242", user="attacker_user", groups=()):
    return Peer(pid=31337, uid=uid, user=user, groups=list(groups), transport="unix")


@pytest.fixture
def team(svc):
    """admin1 (admin), analyst_user (analyst), viewer_user (viewer), each logged in through the API from this OS account."""
    admin = client(svc)
    admin.call("auth.register", username="admin1", password=PW, email="a@example.invalid")
    admin.login("admin1", PW)
    admin.call("users.add", username="analyst_user", password="An4lyst!Passw0rd", email="b@example.invalid", role="analyst")
    client(svc).call("auth.register", username="viewer_user", password="V1ewer!Passw0rd", email="v@example.invalid")  # self-service
    analyst_user, viewer_user = client(svc), client(svc)
    analyst_user.login("analyst_user", "An4lyst!Passw0rd")
    viewer_user.login("viewer_user", "V1ewer!Passw0rd")
    return {"admin": admin, "analyst": analyst_user, "viewer": viewer_user}


# ------------------------------------------------------------------ RBAC is enforced in the agent
def test_every_method_declares_its_permission():
    public = {m for m, spec in METHODS.items() if spec.auth is not True}
    assert public == {"sys.hello", "sys.methods", "auth.register", "auth.login", "auth.check_password",
                      "auth.recover", "agent.shutdown"}   # refused unless the caller is the agent's OS account / root
    for name, spec in METHODS.items():
        assert spec.perm is None or any(spec.perm in p for p in PERMISSIONS.values()), name


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_agent_refuses_every_call_the_role_does_not_allow(svc, team, role):
    c = team[role]
    granted = PERMISSIONS[role]
    for name, spec in METHODS.items():
        if not spec.perm or spec.perm in granted:
            continue
        with pytest.raises(ApiError) as e:
            c.call(name)                    # no params needed: the role check happens before the method runs
        assert e.value.code == "forbidden", name
        assert e.value.data["perm"] == spec.perm
    denied = svc.store.query("SELECT actor, details FROM audit WHERE event = 'api_denied'")
    if role != "admin":
        assert any(r["actor"] == ("viewer_user" if role == "viewer" else "analyst_user") for r in denied)


def test_viewer_cannot_approve_enforce_or_kill_even_calling_the_agent_directly(svc, team, cfg):
    viewer_user, analyst_user = team["viewer"], team["analyst"]
    alert = Alert(rule_id="ED-LOG-001", title="bf", severity="high", remote_ip="203.0.113.9")
    aid = svc.store.create_approval(alert, "pb-brute-force", 0, "block 203.0.113.9", 300)
    for call in (lambda: viewer_user.call("approvals.decide", id=aid, decision="approve"),
                 lambda: viewer_user.call("respond.process", action="kill", pid=os.getpid()),
                 lambda: viewer_user.call("users.set_role", username="viewer_user", role="admin"),
                 lambda: analyst_user.call("users.set_role", username="analyst_user", role="admin"),
                 lambda: analyst_user.call("audit.list"),
                 lambda: analyst_user.call("scan.run", respond=True, mode="enforce")):
        with pytest.raises(ApiError) as e:
            call()
        assert e.value.code == "forbidden"
    assert svc.store.get_approval(aid)["status"] == "pending"
    res = analyst_user.call("approvals.decide", id=aid, decision="deny")
    assert res["decided_by"] == "analyst_user"
    rec = [r for r in svc.store.list_audit(50) if r["event"] == "approval_decided"][0]
    assert rec["actor"] == "analyst_user" and rec["os_uid"] == str(os.getuid()) and rec["client"] == "cli"


def test_admin_os_group_policy(svc, team, cfg):
    svc.api_cfg["admin_os_groups"] = ["eldoctor-admins"]
    admin_elsewhere = client(svc, other_peer(groups=["users"]))
    admin_elsewhere.login("admin1", PW)
    with pytest.raises(ApiError) as e:
        admin_elsewhere.call("users.list") and admin_elsewhere.call("audit.list")
    assert e.value.code == "forbidden" and "OS group" in e.value.message
    ok = client(svc, other_peer(groups=["eldoctor-admins"]))
    ok.login("admin1", PW)
    assert ok.call("audit.list", limit=1)


def test_allowed_os_accounts_policy(svc, team):
    svc.api_cfg["allowed_os_groups"] = ["soc"]
    with pytest.raises(ApiError) as e:
        client(svc, other_peer(groups=["users"])).call("sys.hello")
    assert e.value.code == "forbidden" and "not allowed" in e.value.message
    assert client(svc, other_peer(groups=["soc"])).call("sys.hello")["registered"]
    assert client(svc).call("sys.hello")                       # the agent's own account is always admitted


def test_first_admin_only_from_the_agents_os_account(svc):
    with pytest.raises(ApiError) as e:
        client(svc, other_peer()).call("auth.register", username="user_four", password=PW, email="e@example.invalid")
    assert e.value.code == "forbidden" and svc.um.count() == 0
    client(svc).call("auth.register", username="owner", password=PW, email="o@example.invalid")
    res = client(svc, other_peer()).call("auth.register", username="user_four", password="Ev3!Passw0rd!", email="e@example.invalid")
    assert res["user"]["role"] == "viewer"
    svc.cfg["registration"]["self_service"] = False
    with pytest.raises(ApiError):
        client(svc, other_peer()).call("auth.register", username="eve2", password="Ev3!Passw0rd!", email="e@example.invalid")


# ------------------------------------------------------------------ stateless tokens
def test_token_is_a_signed_jwt_bound_to_the_os_account(svc, team):
    admin = team["admin"]
    h, c, _ = admin.token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=="))
    claims = json.loads(base64.urlsafe_b64decode(c + "=="))
    assert header["alg"] == "HS256" and claims["sub"] == "admin1" and claims["ouid"] == str(os.getuid())
    assert not svc.store.query("SELECT name FROM sqlite_master WHERE name = 'sessions'")   # no session table
    thief = client(svc, other_peer())
    thief.token = admin.token                                  # token file copied by another OS account
    with pytest.raises(ApiError) as e:
        thief.call("audit.list")
    assert e.value.code == "unauthenticated" and "another OS account" in e.value.message
    assert svc.store.query("SELECT 1 FROM audit WHERE event = 'token_peer_mismatch'")


def _forge(token, **changes):
    h, c, s = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(c + "=="))
    claims.update(changes)
    c2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{h}.{c2}.{s}"


def test_forged_expired_and_alg_none_tokens_are_refused(svc, team):
    viewer_user = team["viewer"]
    bad = [_forge(viewer_user.token, role="admin", uid=1, sub="admin1"),
           base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." +
           viewer_user.token.split(".")[1] + ".",
           "garbage", viewer_user.token[:-3] + "AAA"]
    for t in bad:
        c = client(svc)
        c.token = t
        with pytest.raises(ApiError) as e:
            c.call("auth.whoami")
        assert e.value.code == "unauthenticated", t
    expired = svc.tokens.issue(svc.um.get("viewer_user"), str(os.getuid()), lifetime_s=-3600)["token"]
    c = client(svc)
    c.token = expired
    with pytest.raises(ApiError, match="expired"):
        c.call("auth.whoami")


def test_role_change_disable_and_logout_revoke_tokens(svc, team):
    admin, analyst_user = team["admin"], team["analyst"]
    assert analyst_user.whoami()["role"] == "analyst"
    admin.call("users.set_role", username="analyst_user", role="viewer")
    with pytest.raises(ApiError, match="revoked"):
        analyst_user.call("alerts.list")
    analyst_user.login("analyst_user", "An4lyst!Passw0rd")
    assert analyst_user.whoami()["role"] == "viewer" and "approve" not in analyst_user.whoami()["permissions"]
    admin.call("users.set_active", username="analyst_user", active=False)
    assert analyst_user.whoami() is None
    old = admin.token
    admin.logout()
    c = client(svc)
    c.token = old
    assert c.whoami() is None


def test_api_key_authentication(svc, team):
    key = team["admin"].call("auth.rotate_api_key")["api_key"]
    c = ApiClient(InProcessTransport(svc.handle, other_peer(), "x"), api_key=key)
    assert c.call("auth.whoami")["auth"] == "api_key"


# ------------------------------------------------------------------ response requests are resolved by the agent
def test_manual_response_resolves_the_process_itself(svc, team):
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        time.sleep(0.3)
        analyst_user = team["analyst"]
        with pytest.raises(ApiError) as e:
            analyst_user.call("respond.process", action="kill", pid=p.pid, create_time=1.0)    # PID reuse guard
        assert e.value.code == "conflict"
        with pytest.raises(ApiError):
            analyst_user.call("respond.process", action="rm -rf", pid=p.pid)
        res = analyst_user.call("respond.process", action="kill", pid=p.pid, exe="/etc/passwd")  # extra fields are ignored
        assert res["status"] == "success"
        p.wait(timeout=5)
    finally:
        if p.poll() is None:
            p.kill()


# ------------------------------------------------------------------ real socket + peer credentials
def test_unix_socket_with_kernel_peer_credentials(svc, team):
    srv = svc.start_listener()
    mode = stat.S_IMODE(os.stat(srv.endpoint).st_mode)
    assert mode == 0o600                                   # personal agent: owner only
    t = UnixTransport(srv.endpoint).connect()
    assert t.server.pid == os.getpid() and t.server.uid == str(os.getuid())
    c = ApiClient(t, "cli")
    c.login("analyst_user", "An4lyst!Passw0rd")
    who = c.call("auth.whoami")
    assert who["peer"]["transport"] == "unix" and who["peer"]["pid"] == os.getpid()
    # many requests over one connection, from two threads
    errs = []

    def spam():
        try:
            for _ in range(20):
                c.call("agent.status")
        except Exception as exc:          # pragma: no cover
            errs.append(exc)
    ts = [threading.Thread(target=spam) for _ in range(2)]
    [x.start() for x in ts]
    [x.join() for x in ts]
    assert not errs
    c.close()
    # garbage on the wire is answered, not fatal
    s = socket.socket(socket.AF_UNIX)
    s.connect(srv.endpoint)
    s.sendall(b"{not json\n")
    assert b"bad_request" in s.recv(4096)
    s.close()


def test_one_account_cannot_exhaust_the_api_connections(tmp_path):
    from eldoctor.api.transport import UnixApiServer
    srv = UnixApiServer(str(tmp_path / "s.sock"), lambda req, peer: {"v": 1, "ok": True, "result": peer.uid},
                        max_per_account=2, exempt_uids=set())
    srv.start()
    try:
        held = [UnixTransport(srv.endpoint).connect() for _ in range(2)]
        for t in held:
            assert t.request({"v": 1})["ok"]
        third = UnixTransport(srv.endpoint).connect()
        resp = third.request({"v": 1})
        assert not resp["ok"] and "too many open connections" in resp["error"]["message"]
        held[0].close()
        time.sleep(0.3)
        assert UnixTransport(srv.endpoint).connect().request({"v": 1})["ok"]    # slot released
    finally:
        srv.stop()


def test_client_refuses_a_socket_served_by_another_account(tmp_path):
    d = tmp_path / "sock"
    d.mkdir(mode=0o700)
    assert trusted_server_uids(d / "api.sock") == {0, os.getuid()}
    d.chmod(0o777)                                   # writable by others: its owner is no longer trusted implicitly
    assert trusted_server_uids(d / "api.sock", extra=[1234]) == {0, os.getuid(), 1234}


def test_second_agent_cannot_take_over_the_socket(svc, cfg, team):
    svc.start_listener()
    other = AgentService(cfg)
    try:
        with pytest.raises(RuntimeError, match="already serving"):
            other.start_listener()
    finally:
        other.close()


def test_connect_prefers_the_running_agent(svc, cfg, team):
    svc.start_listener()
    c = connect(cfg)
    assert not c.hosted and isinstance(c.transport, UnixTransport)
    c.close()
    svc.stop_agent()
    c = connect(cfg)
    assert c.hosted
    c.close()


def test_remote_agent_view(svc, team, cfg):
    admin = team["admin"]
    svc.role = "embedded"
    admin.call("agent.start", mode="monitor")
    ra = RemoteAgent(admin, processes=5)
    assert ra.refresh() and ra.running and ra.mode == "monitor"
    ok, msg = ra.set_mode("interactive")
    assert ok and svc.agent.mode == "interactive"
    vic_view = RemoteAgent(team["viewer"])
    ok, msg = vic_view.set_mode("enforce")
    assert not ok and "lacks" in msg and svc.agent.mode == "interactive"


# ------------------------------------------------------------------ SIEM forwarding
class _Collector:
    def __init__(self, proto):
        self.proto, self.lines, self.ready = proto, [], threading.Event()
        kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
        self.s = socket.socket(socket.AF_INET, kind)
        self.s.bind(("127.0.0.1", 0))
        self.port = self.s.getsockname()[1]
        if proto == "tcp":
            self.s.listen(5)
        self.s.settimeout(0.2)
        self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        buf = b""
        conn = None
        while not self.stop:
            try:
                if self.proto == "udp":
                    self.lines.append(self.s.recv(65535).decode())
                    continue
                if conn is None:
                    conn, _ = self.s.accept()
                    conn.settimeout(0.2)
                data = conn.recv(65535)
                if not data:
                    conn = None
                    continue
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self.lines.append(line.decode())
            except (socket.timeout, OSError):
                continue

    def close(self):
        self.stop = True
        self.t.join(2)
        self.s.close()


def test_audit_forwarded_to_siem_in_real_time_and_verifiable(cfg, tmp_path):
    from eldoctor.siem import verify_export
    udp, tcp = _Collector("udp"), _Collector("tcp")
    cfg["audit"]["forward"] = [{"type": "syslog", "host": "127.0.0.1", "port": udp.port, "protocol": "udp", "format": "cef"},
                               {"type": "syslog", "host": "127.0.0.1", "port": tcp.port, "protocol": "tcp", "format": "json"}]
    svc = AgentService(cfg)
    svc.forwarder.start()
    try:
        c = client(svc)
        c.call("auth.register", username="admin1", password=PW, email="a@example.invalid")
        t0 = time.time()
        c.login("admin1", PW)
        head = svc.store.audit_head()["seq"]
        end = time.time() + 5
        while time.time() < end and len(tcp.lines) < head:
            time.sleep(0.05)
        assert len(tcp.lines) >= head, "audit records did not reach the SIEM"
        assert time.time() - t0 < 3
        recs = [json.loads(x) for x in tcp.lines]
        assert [r["seq"] for r in recs] == list(range(1, len(recs) + 1))          # in order, nothing missing
        assert {"user_registered", "login", "session_issued"} <= {r["event"] for r in recs}
        assert verify_export(recs)["ok"]
        recs[1]["actor"] = "somebody-else"                                        # the SIEM copy exposes edits
        assert not verify_export(recs)["ok"]
        assert any("CEF:0|ElDoctor|ElDoctor|" in x and "cs1Label=hash" in x for x in udp.lines)
        local = [json.loads(x) for x in (Path(os.environ["ELDOCTOR_HOME"]) / "audit.jsonl").read_text().splitlines()]
        assert verify_export(local)["ok"]
    finally:
        svc.close()
        udp.close()
        tcp.close()


def test_forwarding_survives_an_outage_without_losing_records(cfg):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                                                  # SIEM down
    cfg["audit"]["forward"] = [{"type": "syslog", "host": "127.0.0.1", "port": port, "protocol": "tcp", "format": "json"}]
    cfg["audit"]["jsonl"] = ""
    svc = AgentService(cfg)
    for i in range(5):
        svc.store.audit("agent", f"during_outage_{i}", {})
    assert not svc.forwarder.pump()
    st = svc.forwarder.status()[0]
    assert st["lag"] >= 5 and st["last_error"]
    svc.close()
    col = _Collector.__new__(_Collector)                                       # SIEM back on the same port
    col.proto, col.lines, col.stop = "tcp", [], False
    col.s = socket.socket()
    col.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    col.s.bind(("127.0.0.1", port))
    col.s.listen(5)
    col.s.settimeout(0.2)
    col.t = threading.Thread(target=col.run, daemon=True)
    col.t.start()
    try:
        svc2 = AgentService(cfg)                                               # agent restarted: cursor persisted
        assert svc2.forwarder.flush(5)
        end = time.time() + 3
        while time.time() < end and not any("during_outage_4" in x for x in col.lines):
            time.sleep(0.05)
        seqs = [json.loads(x)["seq"] for x in col.lines]
        assert seqs == sorted(seqs) and seqs[0] == 1 and any("during_outage_4" in x for x in col.lines)
        svc2.close()
    finally:
        col.close()


def test_webhook_sink_is_signed(cfg, monkeypatch):
    import hashlib
    import hmac
    from eldoctor.siem import WebhookSink
    sent = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: sent.append(req) or Resp())
    monkeypatch.setenv("HOOK", "https://siem.example/hec")
    monkeypatch.setenv("SECRET", "k3y")
    WebhookSink({"type": "webhook", "url_env": "HOOK", "secret_env": "SECRET"}).send(
        [{"seq": 1, "ts": 1.0, "actor": "a", "event": "e", "details": "", "prev_hash": "0" * 64, "hash": "h", "mac": "m"}])
    body = sent[0].data
    assert sent[0].headers["X-eldoctor-signature"] == "sha256=" + hmac.new(b"k3y", body, hashlib.sha256).hexdigest()
    assert json.loads(body)["records"][0]["seq"] == 1


# ------------------------------------------------------------------ data folder lockdown
def test_lockdown_restricts_the_data_folder(tmp_path):
    from eldoctor.lockdown import LockdownError, lock_data_dir
    d = tmp_path / "data"
    (d / "evidence").mkdir(parents=True)
    (d / "eldoctor.db").write_text("x")
    (d / "evidence" / "e.json").write_text("{}")
    os.chmod(d, 0o755)
    os.chmod(d / "eldoctor.db", 0o666)
    os.chmod(d / "evidence", 0o777)
    info = lock_data_dir(d)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(d / "eldoctor.db").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(d / "evidence").st_mode) == 0o700
    assert len(info["fixed"]) >= 3
    link = tmp_path / "link"
    link.symlink_to(d)
    with pytest.raises(LockdownError, match="symlink"):
        lock_data_dir(link)


# ------------------------------------------------------------------ CLI clients against a running service
def run_cli(*args, env=None, timeout=60):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([sys.executable, "-m", "eldoctor", *args], capture_output=True, text=True, env=e,
                          cwd=str(ROOT), timeout=timeout)


def test_cli_is_a_client_of_the_running_service(tmp_path):
    home = Path(os.environ["ELDOCTOR_HOME"])
    cfgf = tmp_path / "cfg.yaml"
    cfgf.write_text("notifications: {channels: []}\nlogs: {files: [], journald: false, auditd: false}\n"
                    f"safety: {{only_descendants_of: [{os.getpid()}]}}\nagent: {{initial_scan: false}}\n")
    env = {"ELDOCTOR_ADMIN_USER": "owner", "ELDOCTOR_ADMIN_EMAIL": "o@example.invalid", "ELDOCTOR_ADMIN_PASSWORD": PW}
    svc = subprocess.Popen([sys.executable, "-m", "eldoctor", "--config", str(cfgf), "service", "--bootstrap",
                            "--mode", "interactive", "--duration", "60"], cwd=str(ROOT), env=dict(os.environ, **env),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        sock = None
        end = time.time() + 20
        while time.time() < end and not sock:
            sock = next(iter(Path(os.path.dirname(run_endpoint())).glob("*.sock")), None) if os.path.exists(
                os.path.dirname(run_endpoint())) else None
            time.sleep(0.2)
        assert sock, "service API socket never appeared"
        # service lockdown: data folder and files are private to the service account
        assert stat.S_IMODE(os.stat(home).st_mode) == 0o700
        for f in ("eldoctor.db", "service.key", "keys/master.key"):
            assert stat.S_IMODE(os.stat(home / f).st_mode) == 0o600, f
        c = lambda *a, **k: run_cli("--config", str(cfgf), *a, **k)                # noqa: E731
        assert c("login", "--username", "owner", "--password-env", "P", env={"P": PW}).returncode == 0
        who = c("whoami").stdout
        assert "agent: service" in who and "via unix" in who, who
        vic_client = tmp_path / "viewer_user-client"                                     # viewer_user's own client folder
        v = lambda *a, **k: run_cli("--config", str(cfgf), *a, env=dict(k.pop("env", {}),          # noqa: E731
                                                                       ELDOCTOR_CLIENT_DIR=str(vic_client)), **k)
        r = v("register", "--non-interactive", "--username", "viewer_user", "--email", "v@example.invalid", "--password-env", "P",
              "--json", env={"P": "V1ewer!Passw0rd"})
        assert json.loads(r.stdout)["role"] == "viewer", r.stderr
        assert v("login", "--username", "viewer_user", "--password-env", "P", env={"P": "V1ewer!Passw0rd"}).returncode == 0
        r = v("approvals", "approve", "deadbeef")
        assert r.returncode == 3 and "checked by the agent" in r.stderr
        assert v("audit").returncode == 3
        r = c("audit", "verify")
        assert r.returncode == 0 and r.stdout.startswith("OK:"), r.stdout + r.stderr
        assert "api_denied" in c("audit", "--limit", "30").stdout
    finally:
        svc.terminate()
        out = svc.communicate(timeout=20)[0]
    assert "local API:" in out, out


def run_endpoint():
    from eldoctor.config import api_endpoint
    return api_endpoint({}, server=True)
