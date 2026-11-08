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
from eldoctor.config import MODES, api_endpoint, home_dir, load_config, write_default_config

def prog() -> str:
    """How the user started El Doctor, so hints show a command that works for them."""
    from eldoctor._bootstrap import executable_name, is_frozen
    if is_frozen():
        return executable_name()
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


def _new_password(env_name: Optional[str], username: str = "") -> str:
    """New password from an environment variable (automation) or typed twice (checked against the policy)."""
    from eldoctor.auth.users import password_problems
    if env_name:
        pw = os.environ.get(env_name, "")
        if not pw:
            raise SystemExit(f"error: environment variable {env_name} is empty")
        return pw
    while True:
        pw = getpass.getpass("New password (min 10 chars, 3 character classes): ")
        probs = password_problems(pw, username)          # UX only - the agent enforces the policy
        if probs:
            print("  weak password: " + ", ".join(probs))
            continue
        if getpass.getpass("Repeat new password: ") != pw:
            print("  passwords do not match")
            continue
        return pw


@api_command()
def cmd_passwd(args, c) -> int:
    """Change your own password (every session ends)."""
    from eldoctor.api.client import ApiError
    me = c.call("auth.whoami")["user"]["username"]
    old = os.environ.get(args.old_password_env, "") if args.old_password_env else getpass.getpass("Current password: ")
    try:
        c.call("auth.change_password", old=old, new=_new_password(args.password_env, me))
    except ApiError as exc:
        print(f"Password not changed: {exc.message}", file=sys.stderr)
        return 1
    print(f"Password changed; every session was ended. Log in again:  {prog()} login --username {me}")
    return 0


@api_command()
def cmd_recover(args, c) -> int:
    """Forgotten admin password: reset it locally (root / the agent's OS account only, no login needed)."""
    from eldoctor.api.client import ApiError
    print("Account recovery: resets the password, unlocks and re-enables the account, ends its sessions.\n"
          "Allowed only for root/Administrator or the OS account that runs the El Doctor agent; recorded in the "
          "audit trail as a critical event.")
    pw = _new_password(args.password_env, args.username or "")
    try:
        res = c.call("auth.recover", username=args.username or "", password=pw)
    except ApiError as exc:
        return _fail(exc)
    print(f"Recovered '{res['username']}' (role {res['role']}). Log in:  {prog()} login --username {res['username']}")
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
    elif args.users_cmd == "reset-password":
        c.call("users.reset_password", username=args.username, password=_new_password(args.password_env, args.username))
        print(f"{args.username}: password reset, account unlocked, sessions ended")
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
    from eldoctor._bootstrap import is_frozen, tk_missing, tk_problem
    if tk_missing() and not args.no_auto_runtime and not is_frozen():
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


# --------------------------------------------------------------------------- whole-computer protection (service)
def _installer_log(path: Optional[str]):
    lines: List[str] = []

    def log(msg: str) -> None:
        lines.append(msg)
        print(msg, flush=True)
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    return log


def cmd_install_service(args) -> int:
    """Protect the whole computer: background service at boot (Windows: Scheduled Task as SYSTEM; Linux: systemd).
    Used by the Windows setup wizard and the Linux packages; also usable on its own (as administrator / root)."""
    from eldoctor.installer import InstallError, install_service
    log = _installer_log(args.log)
    e = os.environ
    admin = {"username": args.admin_username or e.get("ELDOCTOR_ADMIN_USER", ""),
             "email": args.admin_email or e.get("ELDOCTOR_ADMIN_EMAIL", ""),
             "full_name": args.admin_name or e.get("ELDOCTOR_ADMIN_NAME", ""),
             "organization": e.get("ELDOCTOR_ADMIN_ORG", ""),
             "password": (e.get(args.password_env, "") if args.password_env else "") or e.get("ELDOCTOR_ADMIN_PASSWORD", "")}
    try:
        res = install_service(admin, mode=args.mode, start=not args.no_start, log=log)
    except InstallError as exc:
        if "administrator account" in str(exc) and sys.stdin.isatty() and not args.quiet:
            print("El Doctor needs an administrator: the person who manages it on this computer.")
            admin["username"] = admin["username"] or _ask("User name", getpass.getuser().lower())
            admin["full_name"] = admin["full_name"] or _ask("Full name", "")
            admin["email"] = admin["email"] or _ask("E-mail (data-wipe reports go here)")
            admin["password"] = admin["password"] or _new_password(None, admin["username"])
            try:
                res = install_service(admin, mode=args.mode, start=not args.no_start, log=log)
            except InstallError as exc2:
                log(f"error: {exc2}")
                return 1
        else:
            log(f"error: {exc}")
            return 1
    except Exception as exc:                      # the wizard shows the log: never end without a reason
        log(f"error: {type(exc).__name__}: {exc}")
        return 1
    log(("Upgraded" if res.get("upgraded") else "Installed") + f" the El Doctor service (data: {res['data_dir']}).")
    if not args.quiet:
        print(f"Every user can now open El Doctor (\"{prog()} gui\" or the El Doctor shortcut) and log in.")
    return 0


def cmd_uninstall_service(args) -> int:
    from eldoctor.installer import InstallError, stop_service, uninstall_service
    log = _installer_log(args.log)
    if args.stop_only:
        res = stop_service(log=log)
        log("El Doctor service stopped" if res.get("stopped") else res.get("note", "nothing to stop"))
        return 0
    try:
        res = uninstall_service(purge=args.purge, log=log)
    except InstallError as exc:
        log(f"error: {exc}")
        return 1
    if not res.get("removed"):
        log(res.get("note", "nothing to remove"))
        return 0
    log("El Doctor service removed" + (" with all its records." if res.get("purged") else
                                      f"; records kept in {res.get('data_dir')}."))
    return 0


# --------------------------------------------------------------------------- El Doctor Hub (agent side)
def cmd_enroll(args) -> int:
    """Join an El Doctor Hub (fleet console) with the token the hub administrator gave you."""
    from eldoctor.fleet.link import LinkError, enroll
    from eldoctor.fleet.pki import PkiError
    try:
        info = enroll(args.token)
    except (LinkError, PkiError) as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Enrollment failed: cannot write to the El Doctor data folder ({exc}). Run as administrator / root "
              f"(the account of the El Doctor service).", file=sys.stderr)
        return 1
    print(f"Enrolled as '{info['agent_id']}' with the hub {info['url']}.\n"
          f"The running agent connects within a minute (no restart needed); check with: {prog()} doctor")
    return 0


def cmd_unenroll(args) -> int:
    from eldoctor.fleet.link import unenroll
    print("Left the hub (its certificate was deleted here; revoke it at the hub too)." if unenroll()
          else "This computer is not enrolled with a hub.")
    return 0


# --------------------------------------------------------------------------- self-check
def cmd_doctor(args) -> int:
    """Is this installation ready? Read-only, no login needed."""
    from eldoctor import doctor
    checks = doctor.run_checks(getattr(args, "config", None), network=args.network)
    if args.json:
        print(json.dumps(doctor.as_json(checks), indent=2))
    else:
        print(doctor.render(checks, color=sys.stdout.isatty() and os.name != "nt"))
    return doctor.exit_code(checks)


# --------------------------------------------------------------------------- user activity (forensics)
def parse_when(v: Optional[str]) -> float:
    """'2h', '30m', '3d', '45s', epoch seconds, or a local date/time ('2025-01-31', '2025-01-31 14:00')."""
    if not v:
        return 0.0
    v = str(v).strip()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if v[-1:].lower() in units and v[:-1].replace(".", "", 1).isdigit():
        return time.time() - float(v[:-1]) * units[v[-1].lower()]
    try:
        return float(v)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(v, fmt))
        except ValueError:
            continue
    raise SystemExit(f"error: cannot understand time {v!r} (use 2h, 30m, 3d, epoch seconds or 'YYYY-MM-DD HH:MM')")


def _activity_params(args) -> Dict[str, Any]:
    return {k: v for k, v in {"since": parse_when(args.since), "until": parse_when(args.until), "user": args.user,
                              "kind": args.kind, "category": args.category, "path": args.path, "q": args.search,
                              "pid": args.pid}.items() if v}


@api_command()
def cmd_activity(args, c) -> int:
    from eldoctor.activity.export import describe as _activity_line
    sub = args.act_cmd or "list"
    if sub == "list":
        rows = c.call("activity.list", limit=args.limit, **_activity_params(args))
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        _print_table([_activity_line(r) for r in reversed(rows)],
                     ["id", "time", "kind", "user", "process", "what", "how", "source"],
                     {"what": 90, "user": 24, "process": 22})
        return 0
    if sub == "now":
        res = c.call("activity.now", all=args.all)
        print(f"{res['host']}  {_ts(res['time'])}  (booted {_ts(res['boot_time'])})")
        print("Logged in now: " + (", ".join(res["logged_in"]) or "nobody (no interactive session)"))
        for u in res["users"]:
            # people with a session: everything they run; others: only what runs on a terminal (unless --all)
            apps = u["apps"] if (args.all or u["sessions"]) else [a for a in u["apps"] if a.get("terminal")]
            shown = apps[: args.limit]
            hidden = len(u["apps"]) - len(shown)
            print(f"\n== {u['user']}" + ("" if u["sessions"] else "  (no login session)"))
            for s in u["sessions"]:
                print(f"   session  {s.get('type', ''):<9} {s.get('terminal') or '-':<8} "
                      f"{('from ' + s['host']) if s.get('host') else '':<22} since {_ts(s.get('started'))}")
            for a in shown:
                print(f"   app      {a['pid']:>7}  {a['name'][:22]:<22} since {_ts(a['started'])}  "
                      f"{a.get('terminal') or '':<6} {a['cmdline'][:90]}")
            if hidden:
                print(f"   ({hidden} more process(es) not shown - use --all / --limit N)")
        return 0
    if sub == "sessions":
        res = c.call("activity.sessions", limit=args.limit, user=args.user)
        print("Current sessions:")
        _print_table([{"user": s["user"], "type": s.get("type"), "terminal": s.get("terminal"), "host": s.get("host"),
                       "since": _ts(s.get("started"))} for s in res["current"]],
                     ["user", "type", "terminal", "host", "since"])
        print("\nHistory:")
        _print_table([_activity_line(r) for r in reversed(res["history"])], ["time", "kind", "user", "what", "source"],
                     {"what": 70})
        return 0
    if sub == "status":
        st = c.call("activity.status")
        if args.json:
            print(json.dumps(st, indent=2, default=str))
            return 0
        print(f"activity recorder: {'running' if st.get('started') else 'not running in the agent'}"
              + (f", backend {st.get('backend')}, {st.get('watches', 0)} folders watched" if st.get("started") else ""))
        if st.get("roots"):
            print("watched: " + ", ".join(st["roots"]))
        idx = st.get("index") or {}
        print(f"last known state: {idx.get('entries', 0):,} entries ({idx.get('folders', 0):,} folders)  |  "
              f"records: {st.get('total_records', 0):,}")
        if st.get("kernel_file_telemetry"):
            print("kernel file telemetry (auditd / Sysmon): yes - deletions carry the real user and login user")
        if st.get("watch_limit_hit"):
            print(f"warning: inotify watch limit reached, {st.get('unwatched_folders')} folders not watched")
        state = st.get("state") or {}
        if state:
            print(f"last heartbeat: {_ts(state.get('heartbeat'))}  clean stop last time: {state.get('clean_stop')}")
        if st.get("last_scan"):
            ls = st["last_scan"]
            print(f"last folder comparison ({ls.get('source')}): {ls.get('counts')}")
        rep = st.get("reports") or {}
        print(f"admin reports: outbox {st.get('outbox') or {}}; SMTP configured: {rep.get('smtp_configured', '?')}; "
              f"admin recipients: {rep.get('recipients', '?')}")
        if st.get("open_incident"):
            print(f"OPEN DATA-WIPE INCIDENT: {st['open_incident']}")
        for e in st.get("errors") or []:
            print(f"  note: {e}")
        return 0
    if sub == "reports":
        if args.retry:
            res = c.call("activity.reports_retry")
            for r in res["results"]:
                print(f"{r['id']}: {r['status']} {r['error']}")
            if not res["smtp_configured"]:
                print("No SMTP server configured: set activity.report.smtp or add an 'email' channel under "
                      "notifications.channels, then retry.")
            return 0
        rows = c.call("activity.reports", limit=args.limit)
        for r in rows:
            r["time"] = _ts(r["ts"])
            r["sent"] = _ts(r["sent_ts"])
        _print_table(rows, ["id", "time", "kind", "status", "attempts", "sent", "recipients", "subject", "last_error"],
                     {"subject": 70, "last_error": 60})
        return 0
    if sub == "export":
        from eldoctor.activity.export import export
        out = Path(args.out).resolve()
        n = export(c.call, str(out), _activity_params(args), args.format)
        print(f"exported {n:,} records to {out}")
        return 0
    return 1


def cmd_default(args) -> int:
    """`eldoctor` with no command: register if needed, log in, open the console.

    Started without a terminal (double-clicked in a file manager, a desktop launcher): the desktop GUI
    instead, which has its own registration and sign-in screens."""
    from eldoctor.api.client import ApiError
    if not (sys.stdin and sys.stdin.isatty()):
        from eldoctor._bootstrap import tk_problem
        problem = tk_problem()
        if not problem:
            return cmd_gui(argparse.Namespace(config=args.config, api_key=args.api_key, mode=None, dry_run=False,
                                              interval=None, theme=None, no_auto_runtime=False, _argv=["gui"]))
        print(f"El Doctor needs a terminal (run `{prog()}` in one) or a desktop: {problem}\n"
              f"Run `{prog()} doctor` to check this installation, `{prog()} -h` for every command.", file=sys.stderr)
        return 2
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
    from eldoctor.config import home_path
    p.add_argument("--config", help=f"config file (default {home_path() / 'config.yaml'})")
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
    pw = sub.add_parser("passwd", help="change your password")
    pw.add_argument("--old-password-env"); pw.add_argument("--password-env", help="new password from this variable")
    pw.set_defaults(func=cmd_passwd)
    rc = sub.add_parser("recover-admin", help="forgotten admin password: reset it locally (root / service account)")
    rc.add_argument("--username", help="account to recover (default: the first admin)")
    rc.add_argument("--password-env", help="new password from this variable")
    rc.set_defaults(func=cmd_recover)
    isv = sub.add_parser("install-service", help="protect the whole computer: background service at boot "
                                                 "(administrator / root)")
    isv.add_argument("--admin-username"); isv.add_argument("--admin-email"); isv.add_argument("--admin-name")
    isv.add_argument("--password-env", help="administrator password from this variable (default ELDOCTOR_ADMIN_PASSWORD)")
    isv.add_argument("--mode", choices=MODES, default="interactive")
    isv.add_argument("--no-start", action="store_true"); isv.add_argument("--quiet", action="store_true")
    isv.add_argument("--log", help="also append the steps to this file (used by the installers)")
    isv.set_defaults(func=cmd_install_service)
    usv = sub.add_parser("uninstall-service", help="remove the background service (records are kept unless --purge)")
    usv.add_argument("--purge", action="store_true", help="also delete every El Doctor record on this computer")
    usv.add_argument("--stop-only", action="store_true", help="only stop the running service (before an upgrade)")
    usv.add_argument("--quiet", action="store_true"); usv.add_argument("--log")
    usv.set_defaults(func=cmd_uninstall_service)
    en = sub.add_parser("enroll", help="join an El Doctor Hub (fleet console) with an enrollment token")
    en.add_argument("token")
    en.set_defaults(func=cmd_enroll)
    sub.add_parser("unenroll", help="leave the El Doctor Hub").set_defaults(func=cmd_unenroll)
    from eldoctor.fleet.cli import add_parser as add_hub_parser
    add_hub_parser(sub)
    dr = sub.add_parser("doctor", help="check this installation and say how to fix problems (no login needed)")
    dr.add_argument("--json", action="store_true")
    dr.add_argument("--network", action="store_true", help="also try to reach the configured SMTP server")
    dr.set_defaults(func=cmd_doctor)

    u = sub.add_parser("users", help="user management (admin)")
    usub = u.add_subparsers(dest="users_cmd", required=True)
    usub.add_parser("list")
    ua = usub.add_parser("add")
    ua.add_argument("username"); ua.add_argument("--email", required=True); ua.add_argument("--role", choices=ROLES, default="analyst")
    ua.add_argument("--full-name"); ua.add_argument("--org"); ua.add_argument("--password-env")
    ua.add_argument("--use-case", choices=list(USE_CASES), default="soc")
    ua.add_argument("--deploy-target", choices=list(DEPLOY_TARGETS), default="linux")
    us = usub.add_parser("set-role"); us.add_argument("username"); us.add_argument("role", choices=ROLES)
    urp = usub.add_parser("reset-password", help="set a new password for another user (admin)")
    urp.add_argument("username"); urp.add_argument("--password-env", help="read the new password from this variable")
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

    ac2 = sub.add_parser("activity", help="forensics: who logged in, which apps ran, which files were created / "
                                          "edited / deleted / opened / downloaded (analyst, admin)")
    ac2sub = ac2.add_subparsers(dest="act_cmd")

    def act_filters(sp):
        sp.add_argument("--since", help="2h, 30m, 3d, epoch or 'YYYY-MM-DD HH:MM'")
        sp.add_argument("--until")
        sp.add_argument("--user", help="OS user name")
        sp.add_argument("--kind", help="e.g. file_deleted,file_downloaded,session_start,app_start (comma-separated)")
        sp.add_argument("--category", help="session, process, file, system, incident (comma-separated)")
        sp.add_argument("--path", help="path prefix (also matches rename targets)")
        sp.add_argument("--search", help="substring in path, process, user or details")
        sp.add_argument("--pid", type=int)
    for sp in (ac2, ac2sub.add_parser("list", help="timeline (default)")):
        act_filters(sp)
        sp.add_argument("--limit", type=int, default=100)
        sp.add_argument("--json", action="store_true")
    an = ac2sub.add_parser("now", help="who is logged in and what they are running")
    an.add_argument("--all", action="store_true", help="service accounts too")
    an.add_argument("--limit", type=int, default=40)
    asn = ac2sub.add_parser("sessions", help="current sessions + login/logout history")
    asn.add_argument("--limit", type=int, default=50); asn.add_argument("--user")
    ast = ac2sub.add_parser("status", help="recorder status: watched folders, backend, reports")
    ast.add_argument("--json", action="store_true")
    arp = ac2sub.add_parser("reports", help="reports e-mailed to the registered admins (outbox)")
    arp.add_argument("--limit", type=int, default=30)
    arp.add_argument("--retry", action="store_true", help="try to deliver pending reports now")
    aex = ac2sub.add_parser("export", help="export the record for triage (CSV or JSON lines)")
    act_filters(aex)
    aex.add_argument("--out", required=True)
    aex.add_argument("--format", choices=["csv", "jsonl"], default="csv")
    ac2.set_defaults(func=cmd_activity, act_cmd=None)

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
