"""`eldoctor hub ...` - run and operate an El Doctor Hub (on the hub server, as the account that owns its folder).

    eldoctor hub init --name hub.example.com          # CA, certificates, first hub administrator
    eldoctor hub serve                                # agent API (mutual TLS) + web console + silent-agent watch
    eldoctor hub token --uses 50                      # enrollment token -> on each computer: eldoctor enroll <TOKEN>
    eldoctor hub agents | alerts | commands | status
    eldoctor hub respond <AGENT> kill --pid 4242      # remote response (runs at the agent's next check-in)
    eldoctor hub triage <ALERT> --status closed --verdict false_positive --note "backup job"
    eldoctor hub intel add ip 203.0.113.66            # every agent detects / blocks it
    eldoctor hub user-add alice --email a@corp.example --role analyst
"""
from __future__ import annotations

import getpass
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List


class Operator:
    """The hub's OS operator on the command line (owner of the hub folder): full rights, recorded as os:<user>."""

    def __init__(self) -> None:
        try:
            self.username = f"os:{getpass.getuser()}"
        except Exception:
            self.username = "os:operator"
        self.role = "admin"
        self.active = True

    def can(self, perm: str) -> bool:
        return True


def default_home() -> Path:
    env = os.environ.get("ELDOCTOR_HUB_HOME")
    if env:
        return Path(env).expanduser()
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/eldoctor-hub")
    return Path.home() / ".eldoctor-hub"


def add_parser(sub) -> None:
    from eldoctor.auth.users import ROLES
    h = sub.add_parser("hub", help="El Doctor Hub: one console for every El Doctor in the fleet (server side)")
    h.add_argument("--hub-home", help=f"hub folder (default {default_home()}, or $ELDOCTOR_HUB_HOME)")
    hs = h.add_subparsers(dest="hub_cmd", required=True)
    i = hs.add_parser("init", help="create the hub: CA, certificates, first administrator")
    i.add_argument("--name", action="append", required=True,
                   help="DNS name or IP address agents use to reach the hub (repeatable; the first one goes in tokens)")
    i.add_argument("--port", type=int, default=8443, help="agent API port (mutual TLS)")
    i.add_argument("--console-port", type=int, default=8444, help="web console port (listens on 127.0.0.1)")
    i.add_argument("--admin-username"); i.add_argument("--admin-email"); i.add_argument("--password-env")
    hs.add_parser("serve", help="run the hub (agent API, web console, silent-agent detection)")
    t = hs.add_parser("token", help="create an enrollment token")
    t.add_argument("--uses", type=int, default=1, help="how many computers may enroll with it")
    t.add_argument("--hours", type=float, help="validity (default hub.token_hours)")
    t.add_argument("--note", default="")
    hs.add_parser("status", help="fleet overview")
    ag = hs.add_parser("agents", help="enrolled agents and their state"); ag.add_argument("--json", action="store_true")
    al = hs.add_parser("alerts", help="fleet alert queue")
    al.add_argument("--status", default="open"); al.add_argument("--severity", default="")
    al.add_argument("--agent", default=""); al.add_argument("--limit", type=int, default=50)
    al.add_argument("--json", action="store_true")
    tr = hs.add_parser("triage", help="update an alert: status, verdict, assignee, note")
    tr.add_argument("alert"); tr.add_argument("--status", default=""); tr.add_argument("--verdict")
    tr.add_argument("--assignee"); tr.add_argument("--note", default="")
    r = hs.add_parser("respond", help="send a response command to an agent")
    r.add_argument("agent"); r.add_argument("action")
    r.add_argument("--pid", type=int); r.add_argument("--ip"); r.add_argument("--mode"); r.add_argument("--reason")
    r.add_argument("--alert", default="")
    c = hs.add_parser("commands", help="response commands and their results"); c.add_argument("--agent", default="")
    rv = hs.add_parser("revoke", help="revoke an agent's certificate"); rv.add_argument("agent")
    it = hs.add_parser("intel", help="fleet threat intel")
    its = it.add_subparsers(dest="intel_cmd", required=True)
    ia = its.add_parser("add"); ia.add_argument("type"); ia.add_argument("value")
    ia.add_argument("--severity", default="high"); ia.add_argument("--description", default="")
    its.add_parser("list")
    ir = its.add_parser("remove"); ir.add_argument("id", type=int)
    u = hs.add_parser("user-add", help="create a hub console account")
    u.add_argument("username"); u.add_argument("--email", required=True)
    u.add_argument("--role", choices=ROLES, default="analyst"); u.add_argument("--password-env")
    u.add_argument("--full-name", default="")
    svc = hs.add_parser("install-service", help="Linux: run the hub as a hardened systemd service under its own "
                                                "unprivileged account (creates the hub if needed; root)")
    svc.add_argument("--name", action="append", help="hub DNS name / IP (needed when the hub does not exist yet)")
    svc.add_argument("--port", type=int, default=8443); svc.add_argument("--console-port", type=int, default=8444)
    svc.add_argument("--admin-username"); svc.add_argument("--admin-email"); svc.add_argument("--password-env")
    h.set_defaults(func=run)


HUB_USER = "eldoctor-hub"
HUB_UNIT_PATH = Path("/etc/systemd/system/eldoctor-hub.service")


def hub_unit(command: List[str], home: Path) -> str:
    exec_start = " ".join(f'"{c}"' if " " in c else c for c in command + ["hub", "serve"])
    return f"""[Unit]
Description=El Doctor Hub - fleet console for El Doctor agents
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={HUB_USER}
Group={HUB_USER}
Environment=ELDOCTOR_HUB_HOME={home}
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
# the hub needs no privilege at all: read-only system, its own folder writable, nothing else
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths={home}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def install_hub_service(args, run_cmd=None) -> int:
    """Dedicated account, hub folder owned by it, hardened unit, enabled and started."""
    import shutil
    from eldoctor.config import is_privileged
    from eldoctor.fleet.hub import Hub
    from eldoctor.installer import agent_command
    run_cmd = run_cmd or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, timeout=120))
    if not sys.platform.startswith("linux") or not is_privileged():
        print("error: hub install-service is for Linux, as root (other systems: run `eldoctor hub serve` under your "
              "service manager)", file=sys.stderr)
        return 1
    home = Path(args.hub_home).expanduser() if args.hub_home else Path("/var/lib/eldoctor-hub")
    if run_cmd(["id", "-u", HUB_USER]).returncode != 0:
        r = run_cmd(["useradd", "--system", "--home-dir", str(home), "--no-create-home", "--shell",
                     "/usr/sbin/nologin", HUB_USER])
        if r.returncode != 0:
            print(f"error: cannot create the {HUB_USER} account: {r.stderr.strip()}", file=sys.stderr)
            return 1
    if not (home / "pki" / "ca.crt").exists():
        if not args.name:
            print("error: the hub does not exist yet: give its address with --name hub.example.com", file=sys.stderr)
            return 1
        info = Hub.init(home, args.name, args.port, args.console_port)
        hub = Hub(home)
        try:
            username = args.admin_username or input("Hub administrator user name: ").strip()
            email = args.admin_email or input("E-mail: ").strip()
            hub.users.register(username, _password(args.password_env, username), email, "", "", "soc", "linux")
        finally:
            hub.close()
        print(f"hub created: {info['public_url']}, CA fingerprint {info['ca_fingerprint']}")
    r = run_cmd(["chown", "-R", f"{HUB_USER}:{HUB_USER}", str(home)])
    if r.returncode != 0:
        print(f"error: chown failed: {r.stderr.strip()}", file=sys.stderr)
        return 1
    HUB_UNIT_PATH.write_text(hub_unit(agent_command(), home), encoding="utf-8")
    os.chmod(HUB_UNIT_PATH, 0o644)
    for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "eldoctor-hub.service"],
                ["systemctl", "restart", "eldoctor-hub.service"]):
        r = run_cmd(cmd)
        if r.returncode != 0:
            print(f"error: {' '.join(cmd)}: {r.stderr.strip()}", file=sys.stderr)
            return 1
    print(f"El Doctor Hub service running as '{HUB_USER}' (data {home}). Logs: journalctl -u eldoctor-hub -f\n"
          f"Enrollment tokens: sudo -u {HUB_USER} ELDOCTOR_HUB_HOME={home} {shutil.which('eldoctor') or 'eldoctor'} "
          f"hub token --uses 10   (or in the web console)")
    return 0


def _ts(t: Any) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t))) if t else ""


def _table(rows: List[Dict[str, Any]], cols: List[str]) -> None:
    from eldoctor.cli import _print_table
    _print_table(rows, cols, {"title": 60, "result": 50, "params": 30})


def _password(env_name: str, username: str) -> str:
    from eldoctor.cli import _new_password
    return _new_password(env_name, username)


def run(args) -> int:
    from eldoctor.fleet.hub import Hub, HubError, HubServer
    if args.hub_cmd == "install-service":
        return install_hub_service(args)
    home = Path(args.hub_home).expanduser() if args.hub_home else default_home()
    os.environ["ELDOCTOR_HOME"] = str(home)               # the hub's folder is its data folder (logs, keys)
    op = Operator()
    try:
        if args.hub_cmd == "init":
            info = Hub.init(home, args.name, args.port, args.console_port)
            hub = Hub(home)
            try:
                username = args.admin_username or input("Hub administrator user name: ").strip()
                email = args.admin_email or input("E-mail: ").strip()
                hub.users.register(username, _password(args.password_env, username), email, "", "", "soc", "linux")
            finally:
                hub.close()
            print(f"Hub created in {info['home']}\n  agent API: {info['public_url']}  (mutual TLS)\n"
                  f"  console:   https://127.0.0.1:{args.console_port}/  (sign in as {username})\n"
                  f"  CA fingerprint: {info['ca_fingerprint']}\n"
                  f"Next: {_me()} hub serve   then   {_me()} hub token --uses 10")
            return 0
        hub = Hub(home)
        try:
            return _dispatch(args, hub, op, HubServer)
        finally:
            hub.close()
    except HubError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _me() -> str:
    from eldoctor.cli import prog
    return prog()


def _dispatch(args, hub, op, HubServer) -> int:
    cmd = args.hub_cmd
    if cmd == "serve":
        from eldoctor.housekeeping import setup_logging
        setup_logging()
        srv = HubServer(hub)
        where = srv.start()
        print(f"El Doctor Hub serving - agents: {where['agent_api']} (mutual TLS)"
              + (f" - console: https://{where['console']}/" if "console" in where else ""), flush=True)
        stop = threading.Event()
        for sig in ("SIGTERM", "SIGINT", "SIGHUP"):
            if hasattr(signal, sig):
                try:
                    signal.signal(getattr(signal, sig), lambda *a: stop.set())
                except (ValueError, OSError):
                    pass
        try:
            while not stop.wait(1):
                pass
        except KeyboardInterrupt:
            pass
        srv.stop()
        print("hub stopped")
        return 0
    if cmd == "token":
        tok = hub.create_token(op.username, args.hours, args.uses, args.note)
        print(f"Enrollment token ({args.uses} computer(s)):\n\n  {tok}\n\nOn each computer, as administrator / root:\n"
              f"  eldoctor enroll {tok}")
        return 0
    if cmd == "status":
        print(json.dumps(hub.overview(), indent=2))
        return 0
    if cmd == "agents":
        rows = hub.agents()
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        for a in rows:
            a["last_seen"] = _ts(a["last_seen"])
            a["logged_in"] = ",".join(a["info"].get("logged_in") or [])
        _table(rows, ["id", "hostname", "state", "last_seen", "last_ip", "version", "mode", "open_alerts", "logged_in"])
        return 0
    if cmd == "alerts":
        rows = hub.alerts(args.status, args.severity, args.agent, limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        for r in rows:
            r["time"] = _ts(r["ts"])
        _table(rows, ["id", "time", "severity", "host", "rule_id", "title", "status", "assignee", "verdict"])
        return 0
    if cmd == "triage":
        r = hub.triage(args.alert, op.username, args.status, args.verdict, args.note, args.assignee)
        print(f"{r['id']}: {r['status']} {r['verdict']}")
        return 0
    if cmd == "respond":
        params = {k: v for k, v in {"pid": args.pid, "ip": args.ip, "mode": args.mode, "reason": args.reason}.items()
                  if v not in (None, "")}
        cid = hub.create_command(op, args.agent, args.action, params, args.alert)
        print(f"command {cid} queued: delivered at the agent's next check-in ({_me()} hub commands)")
        return 0
    if cmd == "commands":
        rows = hub.commands(args.agent)
        for r in rows:
            r["created"] = _ts(r["created"])
            r["result"] = (r["result"] or {}).get("message", "")
            r["params"] = json.dumps(r["params"])
        _table(rows, ["id", "created", "created_by", "agent_id", "action", "params", "status", "result"])
        return 0
    if cmd == "revoke":
        hub.revoke(args.agent, op.username)
        print(f"{args.agent} revoked: its certificate is refused from now on")
        return 0
    if cmd == "intel":
        if args.intel_cmd == "add":
            iid = hub.add_intel(op.username, args.type, args.value, args.severity, args.description)
            print(f"indicator {iid} added: every agent receives it at its next check-in")
        elif args.intel_cmd == "remove":
            hub.remove_intel(op.username, args.id)
            print(f"indicator {args.id} removed")
        else:
            version, rows = hub.intel_snapshot()
            print(f"fleet intel version {version}")
            _table(rows, ["id", "type", "value", "severity", "description"])
        return 0
    if cmd == "user-add":
        user, _ = hub.users.register(args.username, _password(args.password_env, args.username), args.email,
                                     args.full_name, "", "soc", "linux", role=args.role, created_by=op)
        hub.audit(op.username, "hub_user_added", {"username": user.username, "role": user.role})
        print(f"hub account {user.username} ({user.role}) created")
        return 0
    return 1
