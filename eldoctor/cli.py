"""El Doctor command line - a client of the agent's local API.

First run:  `eldoctor`  -> registration wizard (mandatory) -> login -> console.
Run `eldoctor -h` or `eldoctor <command> -h` for details.

Every command is a request to the agent (``eldoctor.api``).  The CLI checks no roles or permissions
itself: the agent authenticates the caller (session token bound to the OS account, or API key),
checks the permission, acts and writes the audit record.  When no agent is running and this OS account
owns the data folder (personal install), the agent is hosted inside the CLI process for the duration
of the command - through the very same API code path.
"""
from __future__ import annotations

import os as _os
import sys as _sys

if __name__ == "__main__" and not __package__:      # `python eldoctor/cli.py`
    _pkg = _os.path.dirname(_os.path.abspath(__file__))
    _sys.path[:] = [p for p in _sys.path if _os.path.abspath(p or _os.curdir) != _pkg]
    _sys.path.insert(0, _os.path.dirname(_pkg))
    from eldoctor._bootstrap import ensure_dependencies
    ensure_dependencies()

import argparse
import getpass
import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from eldoctor import __version__
from eldoctor.config import MODES, api_endpoint, home_dir, load_config, user_config_path, write_default_config

def prog() -> str:
    """How the user started El Doctor, so hints show a command that works for them."""
    a0 = sys.argv[0] if sys.argv else ""
    base = os.path.basename(a0.rstrip("/\\")).lower()
    py = os.path.basename(sys.executable or "python") or "python"
    if os.path.isdir(a0):                                     # python eldoctor
        return f"{py} {a0}"
    if base == "el_doctor.py":
        return f"{py} {a0}"
    if base in ("__main__.py", "cli.py"):                     # python -m eldoctor / python eldoctor/__main__.py
        return f"{py} -m eldoctor"
    return "eldoctor"                                         # console script installed by pip


EXIT_AUTH = 2
EXIT_PERM = 3


# --------------------------------------------------------------------------- helpers
def _cfg(args):
    cfg = load_config(getattr(args, "config", None))
    if getattr(args, "config", None):
        cfg["_path"] = args.config
    return cfg


def _client(args, client: str = "cli", role: str = "direct", cfg=None):
    """Connected ApiClient, or exit with a clear message."""
    from eldoctor.api.client import connect
    from eldoctor.api.transport import ApiUnavailable
    try:
        return connect(cfg or _cfg(args), client=client, api_key=getattr(args, "api_key", None), role=role)
    except ApiUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def _fail(exc) -> int:
    """Map an agent error to the CLI's exit codes (2 = authentication, 3 = permission)."""
    code, msg = exc.code, exc.message
    if code == "not_registered":
        print(f"El Doctor requires registration before use. Run:  {prog()} register", file=sys.stderr)
        return EXIT_AUTH
    if code == "unauthenticated":
        print(f"Not logged in (or session expired): {msg}. Run:  {prog()} login", file=sys.stderr)
        return EXIT_AUTH
    if code == "auth_failed":
        print(f"error: {msg}", file=sys.stderr)
        return EXIT_AUTH
    if code == "forbidden":
        need = exc.data.get("required")
        hint = f" Ask an admin: {prog()} users set-role <you> {need}" if need else ""
        print(f"Permission denied (checked by the agent): {msg}.{hint}", file=sys.stderr)
        return EXIT_PERM
    print(f"error: {msg}", file=sys.stderr)
    return 1


def api_command(client: str = "cli", role: str = "direct"):
    """Decorator: open a client, run the command, map agent errors to exit codes, always close."""
    def deco(fn):
        def wrapper(args) -> int:
            from eldoctor.api.client import ApiError
            from eldoctor.api.transport import ApiUnavailable
            c = _client(args, client, role)
            try:
                return int(fn(args, c) or 0)
            except ApiError as exc:
                return _fail(exc)
            except ApiUnavailable as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            finally:
                c.close()
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper
    return deco


def _print_table(rows: List[Dict[str, Any]], cols: List[str], widths: Optional[Dict[str, int]] = None) -> None:
    if not rows:
        print("(none)")
        return
    widths = widths or {}
    w = {c: min(widths.get(c, 40), max(len(c), *(len(str(r.get(c, ""))) for r in rows))) for c in cols}
    print("  ".join(c.upper().ljust(w[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "") if r.get(c) is not None else "")[: w[c]].ljust(w[c]) for c in cols))


def _ts(t: Optional[float]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""


def _ask(prompt: str, default: str = "", validator=None) -> str:
    while True:
        val = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip() or default
        if not validator or validator(val):
            return val
        print("  invalid value, try again")


def _choose(prompt: str, options: Dict[str, str], default: str) -> str:
    keys = list(options)
    print(prompt)
    for i, k in enumerate(keys, 1):
        print(f"  {i}) {k:<11} {options[k]}")
    while True:
        val = input(f"Choose 1-{len(keys)} [{keys.index(default) + 1}]: ").strip()
        if not val:
            return default
        if val.isdigit() and 1 <= int(val) <= len(keys):
            return keys[int(val) - 1]
        if val in options:
            return val


# --------------------------------------------------------------------------- registration / auth
@api_command()
def cmd_register(args, c) -> int:
    from eldoctor.api.client import ApiError
    from eldoctor.auth.users import DEPLOY_TARGETS, USE_CASES, password_problems

    hello = c.call("sys.hello")
    first = not hello["registered"]
    interactive = not args.non_interactive
    if interactive:
        print(f"\n=== El Doctor {__version__} - user registration ===")
        if first:
            print("You are the first user: you will be the administrator of this installation.")
        else:
            print("Self-registered accounts start as 'viewer' until an admin promotes them.")
        username = args.username or _ask("Username")
        full_name = args.full_name or _ask("Full name")
        email = args.email or _ask("Email")
        org = args.org if args.org is not None else _ask("Organization / team (optional)", "")
        use_case = args.use_case or _choose("\nHow will you use El Doctor?", USE_CASES, "personal")
        target = args.deploy_target or _choose("\nWhere will you deploy El Doctor?", DEPLOY_TARGETS,
                                               "windows" if os.name == "nt" else "linux")
        while True:
            pw = getpass.getpass("Password (min 10 chars, 3 character classes): ")
            probs = password_problems(pw, username)          # UX only - the agent enforces the policy
            if probs:
                print("  weak password: " + ", ".join(probs))
                continue
            if getpass.getpass("Repeat password: ") != pw:
                print("  passwords do not match")
                continue
            break
        consent = False
        if hello.get("webhook_consent"):
            consent = input("Share your registration profile (name, email, org, use case, deployment target - "
                            "never your password) with the El Doctor operator? [y/N]: ").strip().lower() == "y"
    else:
        username, full_name, email = args.username, args.full_name or "", args.email
        org, use_case, target = args.org or "", args.use_case or "other", args.deploy_target or "linux"
        pw = os.environ.get(args.password_env or "", "") if args.password_env else ""
        if not pw:
            print("--non-interactive requires --password-env VAR", file=sys.stderr)
            return 1
        consent = bool(args.consent_share)
    try:
        res = c.call("auth.register", username=username, password=pw, email=email, full_name=full_name,
                     organization=org, use_case=use_case, deployment_target=target, role=args.role,
                     consent_share=consent)
    except ApiError as exc:
        if exc.code == "forbidden":
            return _fail(exc)
        print(f"Registration failed: {exc.message}", file=sys.stderr)
        return 1
    user, api_key = res["user"], res["api_key"]
    if args.json:
        print(json.dumps({"username": user["username"], "role": user["role"], "api_key": api_key}))
        return 0
    print(f"\nRegistered '{user['username']}' with role '{user['role']}' (use case: {use_case}, deploy target: {target}).")
    print(f"API key (shown once - for services/automation, env ELDOCTOR_API_KEY):\n  {api_key}")
    if interactive and sys.stdin.isatty():
        if input(f"\nGenerate the '{target}' deployment bundle now? [Y/n]: ").strip().lower() in ("", "y", "yes"):
            from eldoctor.deploy.generator import generate
            out = Path(f"eldoctor-deploy-{target}").resolve()
            files = generate(target, out, {"username": user["username"], "email": user["email"],
                                           "full_name": user["full_name"], "organization": user["organization"],
                                           "use_case": user["use_case"]})
            print(f"  {len(files)} files written to {out} - see README-DEPLOY.md")
    print(f"Next: {prog()} login   (then {prog()} to open the console)")
    return 0


@api_command()
def cmd_login(args, c) -> int:
    from eldoctor.api.client import ApiError
    if not c.call("sys.hello")["registered"]:
        print(f"No users yet - run: {prog()} register", file=sys.stderr)
        return EXIT_AUTH
    username = args.username or input("Username: ").strip()
    pw = os.environ.get(args.password_env, "") if args.password_env else getpass.getpass("Password: ")
    try:
        res = c.login(username, pw)
    except ApiError as exc:
        print(f"Login failed: {exc.message}", file=sys.stderr)
        return EXIT_AUTH
    u = res["user"]
    hours = max(0.0, (res["expires"] - time.time()) / 3600)
    print(f"Logged in as {u['username']} ({u['role']}); session valid {hours:.0f}h.")
    return 0


@api_command()
def cmd_logout(args, c) -> int:
    c.logout()
    print("Logged out.")
    return 0


@api_command()
def cmd_whoami(args, c) -> int:
    res = c.call("auth.whoami")
    u, peer, srv = res["user"], res["peer"], res["server"]
    print(f"{u['username']} <{u['email']}>  role={u['role']}  org={u['organization'] or '-'}  "
          f"use_case={u['use_case']}  deploy_target={u['deployment_target']}")
    print("permissions (granted by the agent): " + ", ".join(u["permissions"]))
    print(f"OS identity seen by the agent: {peer['user']} (uid {peer['uid']}, pid {peer['pid']}) via {peer['transport']}"
          f"  |  auth: {res['auth']}" + (f", session until {_ts(res['session_expires'])}" if res["session_expires"] else ""))
    print(f"agent: {srv['role']} (pid {srv['pid']}, OS user {srv['os_user']}, privileged {srv['privileged']}) "
          f"at {srv['endpoint']}")
    return 0


@api_command()
def cmd_users(args, c) -> int:
    if args.users_cmd == "list":
        rows = c.call("users.list")
        for r in rows:
            r["created"] = _ts(r["created_at"])
            r["last_login"] = _ts(r["last_login"])
        _print_table(rows, ["username", "role", "email", "organization", "use_case", "deployment_target",
                            "created", "last_login", "active", "integrity"])
    elif args.users_cmd == "add":
        pw = os.environ.get(args.password_env, "") if args.password_env else getpass.getpass("Password for new user: ")
        res = c.call("users.add", username=args.username, password=pw, email=args.email, full_name=args.full_name or "",
                     organization=args.org or "", use_case=args.use_case, deployment_target=args.deploy_target,
                     role=args.role)
        print(f"created {res['user']['username']} ({res['user']['role']}); API key: {res['api_key']}")
    elif args.users_cmd == "set-role":
        c.call("users.set_role", username=args.username, role=args.role)
        print(f"{args.username} -> {args.role} (their existing sessions were revoked)")
    elif args.users_cmd in ("disable", "enable"):
        c.call("users.set_active", username=args.username, active=args.users_cmd == "enable")
        print(f"{args.username} {args.users_cmd}d")
    return 0


# --------------------------------------------------------------------------- agent hosting
def _graceful(agent) -> None:
    """systemd / docker / Task Scheduler stop the agent with SIGTERM: finish the cycle, flush, release the lock."""
    import signal

    def handler(signum, frame):
        agent._stop.set()
    for sig in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), handler)
            except (ValueError, OSError):
                pass


def _banner(agent, svc=None) -> None:
    from eldoctor.config import is_privileged
    st = agent.status()
    print(f"El Doctor {__version__} agent | mode={st['mode']}{' (dry-run)' if st['dry_run'] else ''} | "
          f"privileged={is_privileged()} | sigma={st['sigma_rules']} iocs={st['iocs']} yara={'on' if st['yara'] else 'off'}"
          f" playbooks={st['playbooks']}")
    print(f"log sources: {', '.join(st['log_sources']) or 'none readable - process/network telemetry only'}")
    print(f"notification channels: {', '.join(c.name for c in agent.dispatcher.channels) or 'none'}")
    if svc is not None:
        print(f"local API: {svc.endpoint}  |  audit forwarding: "
              f"{', '.join(s['destination'] for s in svc.forwarder.status()) or 'none'}")
    if agent.engine.sigma_errors:
        print(f"warning: {len(agent.engine.sigma_errors)} Sigma rules skipped (unsupported features)")
    if agent.playbooks.errors:
        print("playbook errors: " + "; ".join(agent.playbooks.errors))
    sys.stdout.flush()


def _apply_overrides(cfg, args) -> None:
    if getattr(args, "interval", None):
        cfg["agent"]["interval"] = args.interval
    if getattr(args, "syslog_port", None):
        cfg["logs"]["syslog_listener"].update(enabled=True, port=args.syslog_port)
    for f in getattr(args, "log_file", None) or []:
        cfg["logs"]["files"].append(f)


def _agent_already_running(cfg) -> Optional[str]:
    from eldoctor.api.client import _transport
    from eldoctor.api.transport import ApiUnavailable
    endpoint = api_endpoint(cfg, server=True)
    try:
        _transport(endpoint, cfg).connect().close()
        return endpoint
    except ApiUnavailable:
        return None


def _run_hosted(svc, user, args, service: bool) -> int:
    """Run the detection loop in the foreground with the API served on the local socket / pipe."""
    try:
        svc.start_listener(service=service)
    except (RuntimeError, PermissionError, OSError) as exc:
        print(f"error: cannot serve the local API: {exc}", file=sys.stderr)
        svc.close()
        return 1
    mode = args.mode or svc.cfg["agent"]["mode"]
    if mode == "enforce" and not user.can("enforce"):
        print(f"enforce mode requires the admin role (you are '{user.role}'); using interactive", file=sys.stderr)
        mode = "interactive"
    agent = svc.start_agent(user, mode, True if args.dry_run else None, headless=True, background=False)
    _banner(agent, svc)
    _graceful(agent)
    try:
        agent.run(duration=args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        svc.close()
    return 0


def cmd_run(args) -> int:
    if not args.headless:
        return cmd_tui(args)
    from eldoctor.api.client import ApiClient, ApiError
    from eldoctor.api.peercred import own_identity
    from eldoctor.api.server import AgentService, ApiFault
    from eldoctor.api.transport import InProcessTransport
    cfg = _cfg(args)
    _apply_overrides(cfg, args)
    running = _agent_already_running(cfg)
    if running:
        print(f"error: an El Doctor agent is already serving {running} - use `{prog()} tui` to attach to it",
              file=sys.stderr)
        return 1
    try:
        svc = AgentService(cfg, role="headless")
    except (PermissionError, OSError) as exc:
        print(f"error: cannot open the data folder {home_dir()}: {exc}", file=sys.stderr)
        return 1
    c = ApiClient(InProcessTransport(svc.handle, own_identity("inproc"), api_endpoint(cfg, server=True)), "cli",
                  args.api_key)
    try:
        who = c.call("auth.whoami")["user"]
        user = svc.um.get(who["username"])
        svc.require(user, "run")
    except ApiError as exc:
        svc.close()
        return _fail(exc)
    except ApiFault as exc:
        svc.close()
        print(f"Permission denied (checked by the agent): {exc}", file=sys.stderr)
        return EXIT_PERM
    return _run_hosted(svc, user, args, service=False)


def cmd_tui(args) -> int:
    from eldoctor._bootstrap import curses_available, curses_hint
    from eldoctor.api.client import ApiError, RemoteAgent
    if not curses_available():
        print(f"The full-screen console needs curses - {curses_hint()}.\n"
              "Starting the text console instead (alerts and actions are printed below; approve with "
              f"`{prog()} approvals approve ID` in another window). Press Ctrl+C to stop.\n", flush=True)
        args.headless = True
        return cmd_run(args)
    cfg = _cfg(args)
    _apply_overrides(cfg, args)
    c = _client(args, "tui", role="embedded", cfg=cfg)
    remote = None
    try:
        who = c.call("auth.whoami")["user"]
        note = ""
        if c.hosted:
            # personal install: this console hosts the agent; serve the API so other terminals can approve
            try:
                c.local_service.start_listener()
            except (RuntimeError, PermissionError, OSError) as exc:
                note = f"local API not served: {exc}"
            try:
                res = c.call("agent.start", mode=args.mode, dry_run=bool(args.dry_run))
                note = res.get("message") or note
            except ApiError as exc:
                if exc.code != "forbidden":
                    raise
                note = f"view only: {exc.message}"
        else:
            note = "attached to the running El Doctor agent"
        from eldoctor.ui.tui import run_tui
        remote = RemoteAgent(c, interval=min(1.0, float(cfg["agent"].get("interval", 2.0))), processes=200)
        run_tui(remote, who, note)
        return 0
    except ApiError as exc:
        return _fail(exc)
    finally:
        if remote:
            remote.stop()
        c.close()


def cmd_gui(args) -> int:
    """Desktop GUI. Registration/login happen inside the window."""
    from eldoctor._bootstrap import tk_missing, tk_problem
    if tk_missing() and not args.no_auto_runtime:
        # no tkinter in this Python (e.g. system Python without python3-tk and no sudo):
        # run the GUI with a Tk-capable Python found on this machine instead
        from eldoctor.ui.runtime import relaunch_gui
        rc = relaunch_gui(getattr(args, "_argv", sys.argv[1:]))
        if rc is not None:
            return rc
        return 1
    problem = tk_problem()
    if problem:
        print(f"The desktop GUI cannot start: {problem}", file=sys.stderr)
        return 1
    cfg = _cfg(args)
    from eldoctor.ui.gui import run_gui
    run_gui(cfg, args.mode, args.dry_run, args.interval, theme=args.theme)
    return 0


def _service_identity(svc, bootstrap: bool):
    """The unattended agent's own identity (it *is* the agent: direct access, no API round-trip)."""
    from eldoctor.api.server import create_service_key
    from eldoctor.auth.users import AuthError
    um = svc.um
    key = os.environ.get("ELDOCTOR_API_KEY", "")
    key_file = home_dir() / "service.key"
    if not key and key_file.exists():
        key = key_file.read_text(encoding="utf-8").strip()
    if key:
        user = um.user_for_api_key(key)
        if user:
            return user
        print("service: API key is invalid, the user is disabled or its record failed the integrity check",
              file=sys.stderr)
    if not bootstrap:
        return None
    if um.count() == 0:
        e = os.environ
        pw = e.get("ELDOCTOR_ADMIN_PASSWORD") or (secrets.token_urlsafe(18) + "aA1!")
        try:
            admin, _ = um.register(e.get("ELDOCTOR_ADMIN_USER", "admin"), pw,
                                   e.get("ELDOCTOR_ADMIN_EMAIL", f"admin@{socket.gethostname()}.local"),
                                   e.get("ELDOCTOR_ADMIN_NAME", ""), e.get("ELDOCTOR_ADMIN_ORG", ""),
                                   e.get("ELDOCTOR_ADMIN_USE_CASE", "cloud"),
                                   e.get("ELDOCTOR_ADMIN_DEPLOY_TARGET", "linux"))
        except AuthError as exc:
            print(f"service bootstrap registration failed: {exc}", file=sys.stderr)
            return None
        if not e.get("ELDOCTOR_ADMIN_PASSWORD"):
            pfile = home_dir() / "admin-password"
            fd = os.open(str(pfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(pw + "\n")
            if os.name != "nt":
                os.chmod(pfile, 0o600)
            print(f"service: registered admin '{admin.username}'; generated password stored in {pfile}")
        svc_user, kf = create_service_key(um, admin)
        print(f"service identity '{svc_user.username}' ready; key stored in {kf}")
        return svc_user
    print(f"service: no service identity. Log in as admin and run: {prog()} service-key", file=sys.stderr)
    return None


@api_command()
def cmd_service_key(args, c) -> int:
    res = c.call("service.rotate_key")
    print(f"service identity '{res['service_user']}' ready; key stored in {res['key_file']}")
    return 0


def cmd_service(args) -> int:
    from eldoctor.api.server import AgentService
    from eldoctor.lockdown import LockdownError, lock_data_dir
    cfg = _cfg(args)
    _apply_overrides(cfg, args)
    running = _agent_already_running(cfg)
    if running:
        print(f"error: an El Doctor agent is already serving {running}", file=sys.stderr)
        return 1
    try:
        info = lock_data_dir(home_dir(), cfg)          # DB, keys, evidence, vault: service account only
    except (LockdownError, OSError) as exc:
        print(f"service: refusing to start - {exc}", file=sys.stderr)
        return 1
    for f in info.get("fixed", []):
        print(f"service: lockdown fixed {f}")
    svc = AgentService(cfg, role="service")
    user = _service_identity(svc, args.bootstrap)
    if not user:
        svc.close()
        return EXIT_AUTH
    if not user.can("run"):
        print(f"service identity '{user.username}' lacks the run permission", file=sys.stderr)
        svc.close()
        return EXIT_PERM
    return _run_hosted(svc, user, args, service=True)


@api_command()
def cmd_scan(args, c) -> int:
    res = c.call("scan.run", respond=bool(args.respond), mode=args.mode, dry_run=bool(args.dry_run))
    print(f"scanned {res['processes']} processes with {res['sigma_rules']} Sigma rules, {res['iocs']} IOCs, "
          f"YARA {'on' if res['yara'] else 'off'}: {len(res['findings'])} finding(s)")
    for f in res["findings"]:
        print("  " + f["short"])
    for run in res["runs"]:
        for r in run["results"]:
            print(f"    -> [{run['playbook']}] {r['action']}: {r['status']} - {r['message']}")
    return 1 if res["findings"] and args.fail_on_findings else 0


# --------------------------------------------------------------------------- records
@api_command()
def cmd_alerts(args, c) -> int:
    alerts = c.call("alerts.list", limit=args.limit)
    if args.json:
        print(json.dumps(alerts, indent=2))
        return 0
    rows = [{"time": _ts(a.get("timestamp")), "severity": a.get("severity"), "rule_id": a.get("rule_id"),
             "title": a.get("title"), "process_name": (a.get("process") or {}).get("name"),
             "pid": (a.get("process") or {}).get("pid"), "remote_ip": a.get("remote_ip"),
             "mitre": ",".join(a.get("mitre") or []), "integrity": a.get("_integrity", "")} for a in alerts]
    _print_table(list(reversed(rows)), ["time", "severity", "rule_id", "title", "process_name", "pid", "remote_ip",
                                        "mitre", "integrity"], {"title": 50, "rule_id": 22})
    return 0


@api_command()
def cmd_actions(args, c) -> int:
    rows = c.call("actions.list", limit=args.limit)
    for r in rows:
        r["time"] = _ts(r["ts"])
    _print_table(list(reversed(rows)), ["time", "playbook_id", "action", "status", "target", "mode", "actor",
                                        "message", "integrity"], {"message": 80})
    return 0


@api_command()
def cmd_approvals(args, c) -> int:
    if args.ap_cmd == "list":
        rows = c.call("approvals.list", status=None if args.all else "pending")
        for r in rows:
            r["requested"] = _ts(r["ts"])
            r["expires_in"] = f"{int(r['expires'] - time.time())}s" if r["status"] == "pending" else ""
        _print_table(rows, ["id", "status", "requested", "expires_in", "summary", "decided_by", "integrity"],
                     {"summary": 90})
        return 0
    from eldoctor.api.client import ApiError
    try:
        res = c.call("approvals.decide", id=args.id, decision=args.ap_cmd)
    except ApiError as exc:
        if exc.code == "conflict":
            print(f"approval {args.id} not found, already decided or expired", file=sys.stderr)
            return 1
        raise
    print(f"approval {args.id} {res['status']} by {res['decided_by']}; the agent applies the decision on its next cycle.")
    return 0


def cmd_playbooks(args) -> int:
    if args.pb_cmd == "validate":                       # pure file check, no agent state involved
        import yaml
        from eldoctor.playbooks.engine import validate_doc
        rc = 0
        for f in args.files:
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
            errs = validate_doc(doc)
            print(f"{f}: {'OK' if not errs else 'INVALID - ' + '; '.join(errs)}")
            rc |= bool(errs)
        return rc
    return _playbooks_api(args)


@api_command()
def _playbooks_api(args, c) -> int:
    from eldoctor.api.client import ApiError
    if args.pb_cmd == "show":
        try:
            print(c.call("playbooks.show", id=args.id)["text"])
        except ApiError as exc:
            if exc.code != "not_found":
                raise
            print("no such playbook", file=sys.stderr)
            return 1
        return 0
    res = c.call("playbooks.list")
    rows = [dict(p, steps=" > ".join(p["steps"])) for p in res["playbooks"]]
    _print_table(rows, ["prio", "id", "enabled", "max_mode", "steps", "name"], {"steps": 80})
    for e in res["errors"]:
        print("error:", e)
    return 0


@api_command()
def cmd_rules(args, c) -> int:
    res = c.call("rules.list")
    rows = res["rules"]
    for r in rows:
        r["mitre"] = ",".join(r["mitre"])
    _print_table(rows, ["id", "severity", "mitre", "source", "title"], {"id": 46, "title": 70, "mitre": 40})
    print(f"\n{len(rows)} rules ({res['sigma']} Sigma); YARA: {res['yara']}")
    for f, e in res["sigma_errors"][:20]:
        print(f"skipped {f}: {e}")
    return 0


@api_command()
def cmd_intel(args, c) -> int:
    if args.intel_cmd == "update":
        for r in c.call("intel.update", feeds=args.feed or None):
            print(f"{r['name']:<30} {'OK ' + str(r.get('count')) + ' indicators' if r['ok'] else 'FAILED ' + r.get('error', '')}")
    elif args.intel_cmd == "add":
        res = c.call("intel.add", type=args.type, value=args.value, severity=args.severity,
                     description=args.description or "", mitre=args.mitre or "")
        print(f"added {args.type} {args.value} to {res['path']}" + (" (active now)" if res["live"] else ""))
    else:
        res = c.call("intel.status")
        print(json.dumps(res["summary"], indent=2))
        for f in res["feeds"]:
            print(f"feed {f['name']}: {f['count']} indicators, updated {_ts(f['updated'])}")
    return 0


@api_command()
def cmd_quarantine(args, c) -> int:
    if args.q_cmd == "list":
        rows = c.call("quarantine.list")
        for r in rows:
            r["time"] = _ts(r["ts"])
        _print_table(rows, ["id", "time", "original_path", "sha256", "size", "restored", "integrity"], {"sha256": 20})
        return 0
    res = c.call("quarantine.restore", id=args.id)
    print(f"{res['status']}: {res['message']}")
    return 0 if res["status"] == "success" else 1


@api_command()
def cmd_blocks(args, c) -> int:
    if args.b_cmd == "list":
        rows = c.call("blocks.list")
        for r in rows:
            r["since"] = _ts(r["ts"])
            r["until"] = _ts(r["expires"])
        _print_table(rows, ["ip", "backend", "since", "until", "reason"], {"reason": 60})
        return 0
    res = c.call("blocks.unblock", ip=args.ip)
    print(f"{res['status']}: {res['message']}")
    return 0


@api_command()
def cmd_deploy(args, c) -> int:
    from eldoctor.auth.users import DEPLOY_TARGETS
    from eldoctor.deploy.generator import default_mode, generate
    me = c.call("auth.whoami")["user"]
    target = args.target
    if not target:
        target = _choose("Deployment target:", DEPLOY_TARGETS, me.get("deployment_target") or "linux")
    mode = args.mode or (default_mode(target) if args.target else
                         _choose("Response mode:", {"monitor": "alerts only",
                                                    "interactive": "kill/quarantine/block after approval",
                                                    "enforce": "automatic response (guards + breaker apply)"},
                                 default_mode(target)))
    out = Path(args.out or f"eldoctor-deploy-{target}").resolve()
    # the agent authorises (admin) and audits; the files are written here, as *this* OS user, into *their* folder
    res = c.call("deploy.record", target=target, mode=mode, out=str(out))
    files = generate(target, out, res["profile"], mode=mode, image=args.image, package_url=args.package_url or "")
    print(f"Generated {len(files)} files for '{target}' (mode {mode}) in {out}:")
    for f in files:
        print(f"  {f.relative_to(out)}")
    print(f"Next: read {out / 'README-DEPLOY.md'}")
    return 0


@api_command()
def cmd_notify_test(args, c) -> int:
    res = c.call("notify.test", channel=args.channel, console=True)
    for ch in res["channels"]:
        print(f"{ch['name']:<12} sent={ch['sent']}")
    for e in res["errors"]:
        print("error:", e)
    return 1 if res["errors"] else 0


def cmd_config(args) -> int:
    if args.cfg_cmd == "init":
        p = write_default_config(force=args.force)
        print(f"config at {p}")
        return 0
    import yaml
    if getattr(args, "local", False):
        print(yaml.safe_dump(load_config(args.config), sort_keys=False))
        return 0
    return _config_show(args)


@api_command()
def _config_show(args, c) -> int:
    import yaml
    print(yaml.safe_dump(c.call("config.get"), sort_keys=False))
    return 0


def cmd_audit(args) -> int:
    sub = getattr(args, "audit_cmd", None) or "list"
    if sub == "verify-export":
        from eldoctor.siem import verify_export
        recs = []
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    recs.append(r.get("record", r))
        res = verify_export(recs, genesis_pin=args.genesis or "")
        print(f"{'OK' if res['ok'] else 'TAMPERED'}: {res['checked']} records (seq {res['first_seq']}..{res['last_seq']}), "
              f"hash chain + Ed25519 signatures + signing-key continuity, no secret needed")
        if res["genesis"]:
            print(f"first signing key: {res['genesis']}" + ("" if args.genesis else
                  "   (compare with the genesis recorded at installation, or pass --genesis)"))
        for p in res["problems"][:50]:
            print(f"  seq {p['seq']}: {p['problem']}")
        return 0 if res["ok"] else 4
    return _audit_api(args)


@api_command()
def _audit_api(args, c) -> int:
    sub = getattr(args, "audit_cmd", None) or "list"
    if sub == "verify":
        res = c.call("audit.verify")
        print(f"{'OK' if res['ok'] else 'TAMPERED'}: {res['checked']} records verified (hash chain, agent MAC, "
              f"{res.get('signed', 0)} forward-secure Ed25519 signatures) + every alert/action/user/block/quarantine/"
              f"approval row against the signed ledger; head seq {res['head']['seq']} {res['head']['hash'][:16]}...")
        if res.get("genesis"):
            print(f"genesis signing key: {res['genesis']}   (record it off-host, or pin it in "
                  f"audit.genesis_fingerprint)")
        if res.get("legacy_upto"):
            print(f"note: records 1..{res['legacy_upto']} were written before the chain existed (sealed on upgrade)")
        for p in res["problems"][:50]:
            print(f"  seq {p['seq']}: {p['problem']}")
        for f in res.get("forwarding", []):
            print(f"forwarding -> {f['destination']}: forwarded up to seq {f['forwarded_seq']} (lag {f['lag']})"
                  + (f", last error: {f['last_error']}" if f["last_error"] else ""))
        return 0 if res["ok"] else 4
    rows = c.call("audit.list", limit=args.limit, all=bool(getattr(args, "all", False)))
    for r in rows:
        r["time"] = _ts(r["ts"])
        r["os"] = f"{r.get('os_user') or ''}:{r.get('os_uid') or ''}"
        r["hash"] = (r.get("hash") or "")[:12]
    _print_table(list(reversed(rows)), ["seq", "time", "actor", "os", "client", "event", "details", "hash"],
                 {"details": 90})
    return 0


def cmd_default(args) -> int:
    """`eldoctor` with no command: register if needed, log in, open the console."""
    from eldoctor.api.client import ApiError
    c = _client(args)
    try:
        registered = c.call("sys.hello")["registered"]
        logged_in = c.whoami() is not None if registered else False
    except ApiError as exc:
        return _fail(exc)
    finally:
        c.close()
    if not registered:
        print("Welcome to El Doctor. Registration is required before first use.")
        ns = argparse.Namespace(**vars(args), username=None, full_name=None, email=None, org=None, use_case=None,
                                deploy_target=None, role=None, non_interactive=False, password_env=None,
                                consent_share=False, json=False)
        if cmd_register(ns) != 0:
            return 1
    if not logged_in:
        if cmd_login(argparse.Namespace(config=args.config, api_key=args.api_key, username=None,
                                        password_env=None)) != 0:
            return EXIT_AUTH
    ns = argparse.Namespace(**vars(args), mode=None, dry_run=False, headless=False, duration=None, interval=None,
                            syslog_port=None, log_file=None)
    return cmd_tui(ns)


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    from eldoctor.auth.users import DEPLOY_TARGETS, ROLES, USE_CASES
    p = argparse.ArgumentParser(prog="eldoctor", description="El Doctor - monitoring, detection & automated response")
    p.add_argument("--version", action="version", version=f"El Doctor {__version__}")
    p.add_argument("--config", help=f"config file (default {user_config_path()})")
    p.add_argument("--api-key", help="API key instead of an interactive session (or env ELDOCTOR_API_KEY)")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("register", help="register a user (mandatory before first use)")
    r.add_argument("--username"); r.add_argument("--email"); r.add_argument("--full-name"); r.add_argument("--org")
    r.add_argument("--use-case", choices=list(USE_CASES)); r.add_argument("--deploy-target", choices=list(DEPLOY_TARGETS))
    r.add_argument("--role", choices=ROLES, help="only honoured when an admin is logged in")
    r.add_argument("--non-interactive", action="store_true"); r.add_argument("--password-env")
    r.add_argument("--consent-share", action="store_true"); r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_register)

    lg = sub.add_parser("login", help="log in and create a session")
    lg.add_argument("--username"); lg.add_argument("--password-env")
    lg.set_defaults(func=cmd_login)
    sub.add_parser("logout", help="end this session (the token is revoked by the agent)").set_defaults(func=cmd_logout)
    sub.add_parser("whoami").set_defaults(func=cmd_whoami)

    u = sub.add_parser("users", help="user management (admin)")
    usub = u.add_subparsers(dest="users_cmd", required=True)
    usub.add_parser("list")
    ua = usub.add_parser("add")
    ua.add_argument("username"); ua.add_argument("--email", required=True); ua.add_argument("--role", choices=ROLES, default="analyst")
    ua.add_argument("--full-name"); ua.add_argument("--org"); ua.add_argument("--password-env")
    ua.add_argument("--use-case", choices=list(USE_CASES), default="soc")
    ua.add_argument("--deploy-target", choices=list(DEPLOY_TARGETS), default="linux")
    us = usub.add_parser("set-role"); us.add_argument("username"); us.add_argument("role", choices=ROLES)
    usub.add_parser("disable").add_argument("username")
    usub.add_parser("enable").add_argument("username")
    u.set_defaults(func=cmd_users)

    def agent_opts(sp):
        sp.add_argument("--mode", choices=MODES, help="response mode (overrides config)")
        sp.add_argument("--dry-run", action="store_true", help="never execute destructive actions")
        sp.add_argument("--duration", type=float, help="stop after N seconds")
        sp.add_argument("--interval", type=float, help="collection interval in seconds")
        sp.add_argument("--syslog-port", type=int, help="enable the built-in syslog receiver on this UDP port")
        sp.add_argument("--log-file", action="append", help="extra log file to tail (repeatable)")

    rn = sub.add_parser("run", help="run the agent (TUI by default, --headless for console output)")
    agent_opts(rn); rn.add_argument("--headless", action="store_true")
    rn.set_defaults(func=cmd_run)
    tu = sub.add_parser("tui", help="interactive console")
    agent_opts(tu); tu.set_defaults(func=cmd_tui)
    gu = sub.add_parser("gui", help="desktop GUI (Tkinter): dashboard, alerts, approvals, response, deploy")
    gu.add_argument("--mode", choices=MODES, help="response mode (overrides config)")
    gu.add_argument("--dry-run", action="store_true", help="never execute destructive actions")
    gu.add_argument("--interval", type=float, help="collection interval in seconds")
    gu.add_argument("--theme", choices=["system", "light", "dark"],
                    help="appearance (default: your saved choice, else follow the operating system)")
    gu.add_argument("--no-auto-runtime", action="store_true",
                    help="do not look for another Python with Tk when this one has no tkinter")
    gu.set_defaults(func=cmd_gui)
    sv = sub.add_parser("service", help="unattended agent (systemd / Scheduled Task / container)")
    agent_opts(sv); sv.add_argument("--bootstrap", action="store_true",
                                    help="register owner from ELDOCTOR_ADMIN_* env and create a service key if needed")
    sv.set_defaults(func=cmd_service)
    sub.add_parser("service-key", help="create/rotate the service identity key (admin)").set_defaults(func=cmd_service_key)

    sc = sub.add_parser("scan", help="one-shot scan of running processes and connections")
    sc.add_argument("--respond", action="store_true", help="run playbooks on findings")
    sc.add_argument("--mode", choices=MODES); sc.add_argument("--dry-run", action="store_true")
    sc.add_argument("--fail-on-findings", action="store_true")
    sc.set_defaults(func=cmd_scan)

    al = sub.add_parser("alerts"); al.add_argument("--limit", type=int, default=30); al.add_argument("--json", action="store_true")
    al.set_defaults(func=cmd_alerts)
    ac = sub.add_parser("actions"); ac.add_argument("--limit", type=int, default=30); ac.set_defaults(func=cmd_actions)

    ap = sub.add_parser("approvals", help="interactive-mode approvals")
    apsub = ap.add_subparsers(dest="ap_cmd", required=True)
    apl = apsub.add_parser("list"); apl.add_argument("--all", action="store_true")
    apsub.add_parser("approve").add_argument("id")
    apsub.add_parser("deny").add_argument("id")
    ap.set_defaults(func=cmd_approvals)

    pb = sub.add_parser("playbooks")
    pbsub = pb.add_subparsers(dest="pb_cmd", required=True)
    pbsub.add_parser("list")
    pbsub.add_parser("show").add_argument("id")
    pbsub.add_parser("validate").add_argument("files", nargs="+")
    pb.set_defaults(func=cmd_playbooks)

    sub.add_parser("rules", help="list detection rules (heuristic, IOC, Sigma)").set_defaults(func=cmd_rules)

    it = sub.add_parser("intel", help="threat intelligence")
    itsub = it.add_subparsers(dest="intel_cmd", required=True)
    itsub.add_parser("status")
    iu = itsub.add_parser("update"); iu.add_argument("--feed", action="append")
    ia = itsub.add_parser("add")
    ia.add_argument("type", choices=["ip", "cidr", "domain", "sha256", "sha1", "md5", "filename"]); ia.add_argument("value")
    ia.add_argument("--severity", default="high"); ia.add_argument("--description"); ia.add_argument("--mitre")
    it.set_defaults(func=cmd_intel)

    q = sub.add_parser("quarantine")
    qsub = q.add_subparsers(dest="q_cmd", required=True)
    qsub.add_parser("list"); qsub.add_parser("restore").add_argument("id")
    q.set_defaults(func=cmd_quarantine)

    b = sub.add_parser("blocks", help="blocked IP addresses")
    bsub = b.add_subparsers(dest="b_cmd", required=True)
    bsub.add_parser("list"); bsub.add_parser("unblock").add_argument("ip")
    b.set_defaults(func=cmd_blocks)

    d = sub.add_parser("deploy", help="generate deployment bundles (windows, linux, docker, kubernetes, aws, azure, gcp)")
    d.add_argument("--target", choices=list(DEPLOY_TARGETS)); d.add_argument("--out"); d.add_argument("--mode", choices=MODES)
    d.add_argument("--image", default="eldoctor:latest"); d.add_argument("--package-url")
    d.set_defaults(func=cmd_deploy)

    nt = sub.add_parser("notify-test", help="send a test alert to notification channels")
    nt.add_argument("--channel"); nt.set_defaults(func=cmd_notify_test)

    cf = sub.add_parser("config")
    cfsub = cf.add_subparsers(dest="cfg_cmd", required=True)
    cs = cfsub.add_parser("show", help="the agent's effective configuration (admin; secrets redacted)")
    cs.add_argument("--local", action="store_true", help="show the config file as loaded by this process instead")
    cfsub.add_parser("init").add_argument("--force", action="store_true")
    cf.set_defaults(func=cmd_config)

    au = sub.add_parser("audit", help="tamper-evident audit trail (admin): list | verify | verify-export FILE")
    au.add_argument("--limit", type=int, default=50)
    au.add_argument("--all", action="store_true", help="include ledger bookkeeping records (alert/action/... digests)")
    ausub = au.add_subparsers(dest="audit_cmd")
    al2 = ausub.add_parser("list", help="latest records (default)")
    al2.add_argument("--limit", type=int, default=50)
    al2.add_argument("--all", action="store_true", help="include ledger bookkeeping records")
    ausub.add_parser("verify", help="verify chain, signatures, head pointer and every ledgered row (agent side)")
    ve = ausub.add_parser("verify-export", help="verify an exported / SIEM copy (JSON lines) offline, no key needed")
    ve.add_argument("file")
    ve.add_argument("--genesis", help="expected genesis key fingerprint (ed25519:...)")
    au.set_defaults(func=cmd_audit)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):          # Windows consoles (cp1252) vs. unicode command lines
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    args._argv = argv                      # exact arguments, e.g. for relaunching the GUI in another runtime
    try:
        if not getattr(args, "func", None):
            return cmd_default(args)
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:            # e.g. `eldoctor alerts | head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
