"""The hub's web console for analysts: fleet, alert queue and triage, remote response, threat intel, tokens, audit.

Server-rendered HTML, no JavaScript.  Security: every value is HTML-escaped (agent-reported names and alert titles
are attacker-controlled), CSRF token on every form, session cookie HttpOnly + Secure + SameSite=Strict, strict CSP,
no framing, the user's role and status re-read from the sealed user record on every request.  Listens on
127.0.0.1 by default (hub.console_listen): put it behind your reverse proxy / VPN to expose it.
"""
from __future__ import annotations

import hmac
import html
import http.server
import json
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

from eldoctor import __version__
from eldoctor.fleet.hub import ACTIONS, ALERT_STATUSES, VERDICTS, Hub, HubError

SESSIONS: Dict[str, Dict[str, Any]] = {}
_SLOCK = threading.Lock()
COOKIE = "edh_session"


def e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def ts(t: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t))) if t else ""
    except (TypeError, ValueError):
        return ""


def ago(t: Any) -> str:
    try:
        s = int(time.time() - float(t))
    except (TypeError, ValueError):
        return ""
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60}m ago"
    if s < 172800:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f6fa;color:#1d2433}
header{background:#173f78;color:#fff;padding:10px 22px;display:flex;align-items:center;gap:22px}
header a{color:#dbe7ff;text-decoration:none;font-weight:500} header a:hover{color:#fff}
header .brand{font-weight:700;font-size:18px;color:#fff} header form{margin-left:auto}
main{padding:20px 24px;max-width:1400px}
table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 2px #0001}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #e6e9f0;font-size:14px;vertical-align:top}
th{background:#eef2f8;font-weight:600} tr:hover td{background:#f8faff}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.card{background:#fff;padding:14px 18px;min-width:150px;box-shadow:0 1px 2px #0001;border-radius:6px}
.card b{display:block;font-size:26px}
.sev-critical{color:#c62828;font-weight:700}.sev-high{color:#d35400;font-weight:600}.sev-medium{color:#9a7d0a}
.sev-low,.sev-info{color:#2c6e8f}
.st-online{color:#17702f;font-weight:600}.st-late{color:#9a7d0a;font-weight:600}.st-silent{color:#c62828;font-weight:700}
.st-revoked{color:#777}
input,select,textarea{font:inherit;padding:5px 7px;border:1px solid #c3cad8;border-radius:4px}
button{font:inherit;padding:6px 12px;border:0;border-radius:4px;background:#1a66d6;color:#fff;cursor:pointer}
button.danger{background:#c62828} .muted{color:#6b7385} .box{background:#fff;padding:16px;margin:14px 0;
box-shadow:0 1px 2px #0001;border-radius:6px} pre{white-space:pre-wrap;word-break:break-word;background:#f1f3f7;
padding:10px;border-radius:4px;font-size:13px} .flash{background:#e7f4e9;border:1px solid #b7dfbf;padding:10px;
border-radius:4px} .err{background:#fdecea;border:1px solid #f5c2c0;padding:10px;border-radius:4px}
form.inline{display:inline} .row{display:flex;gap:10px;flex-wrap:wrap;align-items:end} label{display:block;
font-size:13px;color:#4a5263}
"""


class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ElDoctorHub"
    sys_version = ""

    # ------------------------------------------------------------------ plumbing
    @property
    def hub(self) -> Hub:
        return self.server.hub                                   # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        import logging
        logging.getLogger("eldoctor.hub").info("console %s " + fmt, self.client_address[0], *args)

    def _headers(self, status: int, ctype: str = "text/html; charset=utf-8", extra: Optional[List[Tuple[str, str]]] = None,
                 length: int = 0) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
                                                    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in extra or []:
            self.send_header(k, v)
        self.end_headers()

    def page(self, title: str, body: str, status: int = 200, refresh: int = 0, user=None, sess=None,
             extra: Optional[List[Tuple[str, str]]] = None) -> None:
        nav = ""
        if user is not None:
            links = [("/", "Dashboard"), ("/agents", "Agents"), ("/alerts?status=open", "Alerts"),
                     ("/commands", "Commands"), ("/intel", "Threat intel")]
            if user.can("manage_users"):
                links += [("/tokens", "Enroll agents")]
            if user.can("audit"):
                links += [("/audit", "Audit")]
            nav = "".join(f'<a href="{e(h)}">{e(t)}</a>' for h, t in links) + \
                f'<form method="post" action="/logout">{self.csrf_field(sess)}<span class="muted" style="color:#dbe7ff">' \
                f'{e(user.username)} ({e(user.role)})</span> <button>Sign out</button></form>'
        meta = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
        doc = (f"<!doctype html><html><head><meta charset=utf-8><title>{e(title)} - El Doctor Hub</title>{meta}"
               f"<meta name=viewport content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body>"
               f"<header><span class=brand>El Doctor Hub</span>{nav}</header><main><h2>{e(title)}</h2>{body}"
               f"<p class=muted style='margin-top:30px'>El Doctor {e(__version__)}</p></main></body></html>").encode()
        self._headers(status, length=len(doc), extra=extra)
        self.wfile.write(doc)

    def redirect(self, where: str, extra: Optional[List[Tuple[str, str]]] = None) -> None:
        self._headers(303, extra=[("Location", where)] + (extra or []))

    def form(self) -> Dict[str, str]:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise HubError("form too large", 413)
        data = parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] for k, v in data.items()}

    def query(self) -> Dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    # ------------------------------------------------------------------ sessions
    def session(self):
        raw = self.headers.get("Cookie") or ""
        sid = ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                sid = v
        with _SLOCK:
            s = SESSIONS.get(sid)
            if not s or s["expires"] < time.time():
                SESSIONS.pop(sid, None)
                return None, None
        user = self.hub.users.get(s["username"])          # current role / status, seal checked
        if user is None or not user.active or user.token_version != s["tv"]:
            with _SLOCK:
                SESSIONS.pop(sid, None)
            return None, None
        s["sid"] = sid
        return user, s

    def csrf_field(self, sess) -> str:
        return f'<input type=hidden name=csrf value="{e(sess["csrf"])}">' if sess else ""

    def check_csrf(self, sess, f: Dict[str, str]) -> None:
        if not sess or not hmac.compare_digest(f.get("csrf", ""), sess["csrf"]):
            raise HubError("the form expired or did not come from this console - reload the page", 403)

    # ------------------------------------------------------------------ routing
    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def _route(self, method: str) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/login":
                return self.login(method)
            user, sess = self.session()
            if user is None:
                return self.redirect("/login")
            f: Dict[str, str] = {}
            if method == "POST":
                f = self.form()
                self.check_csrf(sess, f)
            routes = {("GET", "/"): self.dashboard, ("GET", "/agents"): self.agents, ("GET", "/agent"): self.agent,
                      ("GET", "/alerts"): self.alerts, ("GET", "/alert"): self.alert, ("GET", "/commands"): self.commands,
                      ("GET", "/intel"): self.intel, ("GET", "/tokens"): self.tokens, ("GET", "/audit"): self.audit,
                      ("POST", "/logout"): self.logout, ("POST", "/alert/triage"): self.triage,
                      ("POST", "/agent/command"): self.send_command, ("POST", "/agent/revoke"): self.revoke,
                      ("POST", "/intel/add"): self.intel_add, ("POST", "/intel/remove"): self.intel_remove,
                      ("POST", "/tokens"): self.token_create}
            fn = routes.get((method, path))
            if fn is None:
                return self.page("Not found", "<p>No such page.</p>", 404, user=user, sess=sess)
            fn(user, sess, f)
        except HubError as exc:
            user, sess = (None, None)
            try:
                user, sess = self.session()
            except Exception:
                pass
            self.page("Error", f'<p class=err>{e(exc)}</p><p><a href="/">Back</a></p>', exc.status, user=user, sess=sess)
        except Exception:
            import logging
            logging.getLogger("eldoctor.hub").exception("console error")
            self.page("Error", "<p class=err>Internal error - details are in the hub log.</p>", 500)

    # ------------------------------------------------------------------ pages
    def login(self, method: str) -> None:
        from eldoctor.auth.users import AuthError
        msg = ""
        if method == "POST":
            f = self.form()
            try:
                u = self.hub.users.authenticate(f.get("username", ""), f.get("password", ""))
            except AuthError as exc:
                msg = f"<p class=err>{e(exc)}</p>"
            else:
                sid = secrets.token_urlsafe(32)
                hours = float(self.hub.hc.get("session_hours", 8))
                with _SLOCK:
                    SESSIONS[sid] = {"username": u.username, "tv": u.token_version, "csrf": secrets.token_urlsafe(24),
                                     "expires": time.time() + hours * 3600}
                self.hub.audit(u.username, "hub_console_login", {"ip": self.client_address[0]})
                return self.redirect("/", [("Set-Cookie", f"{COOKIE}={sid}; HttpOnly; Secure; SameSite=Strict; "
                                                          f"Path=/; Max-Age={int(hours * 3600)}")])
        body = (f'{msg}<form method=post action="/login" class=box style="max-width:380px">'
                '<label>User name<br><input name=username autofocus required></label><br>'
                '<label>Password<br><input name=password type=password required></label><br><button>Sign in</button>'
                '<p class=muted>Hub accounts: <code>eldoctor hub user-add</code> on the hub.</p></form>')
        self.page("Sign in", body, 200 if not msg else 401)

    def logout(self, user, sess, f) -> None:
        with _SLOCK:
            SESSIONS.pop(sess["sid"], None)
        self.redirect("/login", [("Set-Cookie", f"{COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")])

    def dashboard(self, user, sess, f) -> None:
        ov = self.hub.overview()
        st = ov["states"]
        sev = ov["open_alerts"]
        cards = "".join(f'<div class=card><span class=muted>{e(k)}</span><b class="{c}">{e(v)}</b></div>' for k, v, c in [
            ("Agents", ov["agents"], ""), ("Online", st.get("online", 0), "st-online"),
            ("Silent", st.get("silent", 0), "st-silent"), ("Late", st.get("late", 0), "st-late"),
            ("Critical open", sev.get("critical", 0), "sev-critical"), ("High open", sev.get("high", 0), "sev-high"),
            ("Pending commands", ov["pending_commands"], "")])
        silent = [a for a in self.hub.agents() if a["state"] == "silent"]
        warn = ""
        if silent:
            warn = "<p class=err><b>Not reporting:</b> " + ", ".join(
                f'<a href="/agent?id={quote(a["id"])}">{e(a["hostname"])}</a> (last seen {e(ago(a["last_seen"]))})'
                for a in silent) + "</p>"
        body = f"<div class=cards>{cards}</div>{warn}<h3>Latest open alerts</h3>" + \
            self._alert_table(self.hub.alerts(status="open", limit=25))
        self.page("Fleet overview", body, refresh=20, user=user, sess=sess)

    def _alert_table(self, rows: List[Dict[str, Any]]) -> str:
        if not rows:
            return "<p class=muted>No alerts.</p>"
        tr = "".join(
            f'<tr><td>{e(ts(r["ts"]))}</td><td class="sev-{e(r["severity"])}">{e(r["severity"])}</td>'
            f'<td><a href="/alert?id={quote(r["id"])}">{e(r["title"])}</a><br><span class=muted>{e(r["rule_id"])}</span></td>'
            f'<td><a href="/agent?id={quote(r["agent_id"])}">{e(r["host"])}</a></td><td>{e(r["status"])}</td>'
            f'<td>{e(r["assignee"])}</td><td>{e(r["verdict"])}</td></tr>' for r in rows)
        return ("<table><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Host</th><th>Status</th><th>Assignee</th>"
                f"<th>Verdict</th></tr>{tr}</table>")

    def agents(self, user, sess, f) -> None:
        rows = self.hub.agents()
        tr = "".join(
            f'<tr><td><a href="/agent?id={quote(a["id"])}">{e(a["hostname"])}</a><br><span class=muted>{e(a["id"])}</span></td>'
            f'<td class="st-{e(a["state"])}">{e(a["state"])}</td><td>{e(ago(a["last_seen"]))}</td><td>{e(a["os"])}</td>'
            f'<td>{e(a["version"])}</td><td>{e(a["mode"])}</td><td>{e(a["last_ip"])}</td><td>{e(a["open_alerts"])}</td>'
            f'<td>{e(", ".join((a["info"].get("logged_in") or [])[:5]))}</td></tr>' for a in rows)
        body = ("<table><tr><th>Host</th><th>State</th><th>Last check-in</th><th>OS</th><th>Version</th><th>Mode</th>"
                f"<th>Address</th><th>Open alerts</th><th>Logged in</th></tr>{tr}</table>") if rows else \
            '<p class=muted>No agent enrolled yet. <a href="/tokens">Create an enrollment token</a>.</p>'
        self.page("Agents", body, refresh=20, user=user, sess=sess)

    def agent(self, user, sess, f) -> None:
        aid = self.query().get("id", "")
        rows = [a for a in self.hub.agents() if a["id"] == aid]
        if not rows:
            raise HubError("no such agent", 404)
        a = rows[0]
        info = {k: v for k, v in a["info"].items() if k not in ("alerts",)}
        opts = "".join(f"<option>{e(x)}</option>" for x in sorted(ACTIONS))
        cmd_form = ""
        if a["status"] == "active" and user.can("respond"):
            cmd_form = (f'<div class=box><h3>Respond on this host</h3><form method=post action="/agent/command" class=row>'
                        f'{self.csrf_field(sess)}<input type=hidden name=agent value="{e(a["id"])}">'
                        f'<label>Action<br><select name=action>{opts}</select></label>'
                        '<label>PID<br><input name=pid size=8></label><label>IP<br><input name=ip size=16></label>'
                        '<label>Mode<br><select name=mode><option></option><option>monitor</option><option>interactive'
                        '</option><option>enforce</option></select></label><label>Reason<br><input name=reason size=30>'
                        '</label><button>Send</button></form><p class=muted>Delivered at the next check-in. The agent '
                        'applies its own safety guards and allow-list (hub.allow_commands) and records who asked.</p></div>')
        revoke = ""
        if a["status"] == "active" and user.can("manage_users"):
            revoke = (f'<form method=post action="/agent/revoke" class=inline>{self.csrf_field(sess)}'
                      f'<input type=hidden name=agent value="{e(a["id"])}"><button class=danger>Revoke this agent'
                      '</button></form>')
        body = (f'<div class=box><b>{e(a["hostname"])}</b> <span class="st-{e(a["state"])}">{e(a["state"])}</span> - '
                f'last check-in {e(ts(a["last_seen"]))} from {e(a["last_ip"])}, El Doctor {e(a["version"])} '
                f'({e(a["os"])}), mode {e(a["mode"])}, enrolled {e(ts(a["enrolled_ts"]))}. '
                f'Audit trail head: record {e(a["audit_seq"])}. {revoke}<pre>{e(json.dumps(info, indent=2, default=str))}'
                f'</pre></div>{cmd_form}<h3>Alerts</h3>{self._alert_table(self.hub.alerts(agent_id=aid, limit=50))}'
                f'<h3>Commands</h3>{self._command_table(self.hub.commands(agent_id=aid, limit=50))}')
        self.page(a["hostname"], body, user=user, sess=sess)

    def alerts(self, user, sess, f) -> None:
        qd = self.query()
        st, sev, text = qd.get("status", "open"), qd.get("severity", ""), qd.get("q", "")
        sel = lambda name, opts, cur: f"<select name={name}>" + "".join(  # noqa: E731
            f'<option value="{e(o)}"{" selected" if o == cur else ""}>{e(o or "any")}</option>' for o in opts) + "</select>"
        filt = (f'<form method=get action="/alerts" class="row box"><label>Status<br>'
                f'{sel("status", ["open", ""] + list(ALERT_STATUSES), st)}</label><label>Minimum severity<br>'
                f'{sel("severity", ["", "low", "medium", "high", "critical"], sev)}</label><label>Search<br>'
                f'<input name=q value="{e(text)}"></label><button>Filter</button></form>')
        self.page("Alert queue", filt + self._alert_table(self.hub.alerts(st, sev, text=text, limit=300)),
                  refresh=30, user=user, sess=sess)

    def alert(self, user, sess, f) -> None:
        r = self.hub.alert(self.query().get("id", ""))
        if r is None:
            raise HubError("no such alert", 404)
        d = r["data"]
        notes = "".join(f'<p><b>{e(n["by"])}</b> <span class=muted>{e(ts(n["ts"]))}</span><br>{e(n["text"])}</p>'
                        for n in r["notes"]) or "<p class=muted>No notes yet.</p>"
        stat = "".join(f'<option{" selected" if s == r["status"] else ""}>{e(s)}</option>' for s in ALERT_STATUSES)
        verd = "".join(f'<option value="{e(v)}"{" selected" if v == r["verdict"] else ""}>{e(v or "-")}</option>'
                       for v in VERDICTS)
        proc = d.get("process") or {}
        kill = ""
        if proc.get("pid") and user.can("respond"):
            kill = (f'<form method=post action="/agent/command" class=inline>{self.csrf_field(sess)}'
                    f'<input type=hidden name=agent value="{e(r["agent_id"])}"><input type=hidden name=alert '
                    f'value="{e(r["id"])}"><input type=hidden name=pid value="{e(proc.get("pid"))}">'
                    f'<input type=hidden name=create_time value="{e(proc.get("create_time") or "")}">'
                    '<select name=action><option>suspend</option><option>kill</option><option>kill_tree</option>'
                    '<option>forensics</option><option>quarantine</option></select> '
                    f'<button class=danger>Act on {e(proc.get("name"))} (pid {e(proc.get("pid"))})</button></form>')
        if d.get("remote_ip") and user.can("respond"):
            kill += (f' <form method=post action="/agent/command" class=inline>{self.csrf_field(sess)}'
                     f'<input type=hidden name=agent value="{e(r["agent_id"])}"><input type=hidden name=alert '
                     f'value="{e(r["id"])}"><input type=hidden name=action value=block_ip><input type=hidden name=ip '
                     f'value="{e(d["remote_ip"])}"><button class=danger>Block {e(d["remote_ip"])}</button></form>')
        triage = ""
        if user.can("approve"):
            triage = (f'<form method=post action="/alert/triage" class="row box">{self.csrf_field(sess)}'
                      f'<input type=hidden name=id value="{e(r["id"])}"><label>Status<br><select name=status>{stat}'
                      f'</select></label><label>Verdict<br><select name=verdict>{verd}</select></label>'
                      f'<label>Assignee<br><input name=assignee value="{e(r["assignee"])}" size=14></label>'
                      '<label>Note<br><textarea name=note rows=2 cols=50></textarea></label><button>Save</button></form>')
        mitre = ", ".join(f'{m.get("id")} {m.get("name")}' for m in d.get("mitre_details") or [])
        body = (f'<div class=box><span class="sev-{e(r["severity"])}">{e(r["severity"].upper())}</span> '
                f'<b>{e(r["title"])}</b><br>Host <a href="/agent?id={quote(r["agent_id"])}">{e(r["host"])}</a> - '
                f'{e(ts(r["ts"]))} - rule {e(r["rule_id"])} ({e(r["source"])})'
                f'<p>{e(d.get("description"))}</p>{"<p>MITRE ATT&amp;CK: " + e(mitre) + "</p>" if mitre else ""}'
                f'{("<p>Process: " + e(proc.get("name")) + " pid " + e(proc.get("pid")) + " user " + e(proc.get("username")) + "<br><code>" + e(proc.get("cmdline")) + "</code></p>") if proc else ""}'
                f'<p>{kill}</p></div>{triage}<div class=box><h3>Notes</h3>{notes}</div>'
                f'<div class=box><h3>Evidence</h3><pre>{e(json.dumps(d.get("evidence") or {}, indent=2, default=str))}'
                f'</pre></div>')
        self.page("Alert", body, user=user, sess=sess)

    def triage(self, user, sess, f) -> None:
        if not user.can("approve"):
            raise HubError("your role may not triage alerts", 403)
        self.hub.triage(f.get("id", ""), user.username, f.get("status", ""), f.get("verdict"), f.get("note", ""),
                        f.get("assignee"))
        self.redirect(f"/alert?id={quote(f.get('id', ''))}")

    def send_command(self, user, sess, f) -> None:
        params = {k: f[k] for k in ("pid", "ip", "mode", "reason", "create_time") if f.get(k)}
        self.hub.create_command(user, f.get("agent", ""), f.get("action", ""), params, f.get("alert", ""))
        self.redirect(f"/agent?id={quote(f.get('agent', ''))}")

    def revoke(self, user, sess, f) -> None:
        if not user.can("manage_users"):
            raise HubError("only admins can revoke agents", 403)
        self.hub.revoke(f.get("agent", ""), user.username)
        self.redirect(f"/agent?id={quote(f.get('agent', ''))}")

    def _command_table(self, rows: List[Dict[str, Any]]) -> str:
        if not rows:
            return "<p class=muted>No commands.</p>"
        tr = "".join(f'<tr><td>{e(ts(c["created"]))}</td><td>{e(c["created_by"])}</td><td>{e(c["action"])}</td>'
                     f'<td>{e(json.dumps(c["params"]))}</td><td>{e(c["status"])}</td>'
                     f'<td>{e((c["result"] or {}).get("message", ""))}</td></tr>' for c in rows)
        return ("<table><tr><th>Created</th><th>By</th><th>Action</th><th>Parameters</th><th>Status</th><th>Result</th>"
                f"</tr>{tr}</table>")

    def commands(self, user, sess, f) -> None:
        rows = self.hub.commands(limit=300)
        hosts = {a["id"]: a["hostname"] for a in self.hub.agents()}
        for r in rows:
            r["created_by"] = f'{r["created_by"]} -> {hosts.get(r["agent_id"], r["agent_id"])}'
        self.page("Response commands", self._command_table(rows), refresh=20, user=user, sess=sess)

    def intel(self, user, sess, f) -> None:
        version, rows = self.hub.intel_snapshot()
        tr = "".join(f'<tr><td>{e(r["type"])}</td><td><code>{e(r["value"])}</code></td>'
                     f'<td class="sev-{e(r["severity"])}">{e(r["severity"])}</td><td>{e(r["description"])}</td><td>'
                     + (f'<form method=post action="/intel/remove" class=inline>{self.csrf_field(sess)}<input type=hidden '
                        f'name=id value="{e(r["id"])}"><button class=danger>Remove</button></form>'
                        if user.can("intel") else "") + "</td></tr>" for r in rows)
        add = ""
        if user.can("intel"):
            add = (f'<form method=post action="/intel/add" class="row box">{self.csrf_field(sess)}'
                   '<label>Type<br><select name=type><option>ip</option><option>cidr</option><option>domain</option>'
                   '<option>sha256</option><option>md5</option><option>sha1</option><option>filename</option></select>'
                   '</label><label>Value<br><input name=value size=40 required></label><label>Severity<br><select '
                   'name=severity><option>critical</option><option selected>high</option><option>medium</option>'
                   '<option>low</option></select></label><label>Description<br><input name=description size=30></label>'
                   '<button>Add for the whole fleet</button></form>')
        body = (f"<p class=muted>Every agent receives these indicators at its next check-in (version {e(version)}) and "
                f"detects / blocks them like its own threat intel.</p>{add}<table><tr><th>Type</th><th>Value</th>"
                f"<th>Severity</th><th>Description</th><th></th></tr>{tr}</table>")
        self.page("Fleet threat intel", body, user=user, sess=sess)

    def intel_add(self, user, sess, f) -> None:
        if not user.can("intel"):
            raise HubError("your role may not change threat intel", 403)
        self.hub.add_intel(user.username, f.get("type", ""), f.get("value", ""), f.get("severity", "high"),
                           f.get("description", ""))
        self.redirect("/intel")

    def intel_remove(self, user, sess, f) -> None:
        if not user.can("intel"):
            raise HubError("your role may not change threat intel", 403)
        self.hub.remove_intel(user.username, int(f.get("id") or 0))
        self.redirect("/intel")

    def tokens(self, user, sess, f, token: str = "") -> None:
        if not user.can("manage_users"):
            raise HubError("only admins can enroll agents", 403)
        shown = ""
        if token:
            shown = (f'<div class=flash><p><b>Enrollment token</b> (shown once - copy it now):</p><pre>{e(token)}</pre>'
                     '<p>On each computer, as administrator / root:</p><pre>eldoctor enroll ' + e(token) + '</pre>'
                     '<p>Windows: run it in an administrator command prompt (El Doctor (command line) shortcut).</p></div>')
        body = (f'{shown}<form method=post action="/tokens" class="row box">{self.csrf_field(sess)}'
                '<label>Computers that may use it<br><input name=uses value=1 size=5></label>'
                '<label>Valid for (hours)<br><input name=hours value=24 size=5></label>'
                '<label>Note<br><input name=note size=30 placeholder="e.g. finance laptops"></label>'
                '<button>Create token</button></form>')
        self.page("Enroll agents", body, user=user, sess=sess)

    def token_create(self, user, sess, f) -> None:
        if not user.can("manage_users"):
            raise HubError("only admins can enroll agents", 403)
        try:
            uses, hours = max(1, min(10000, int(f.get("uses") or 1))), max(0.1, min(720.0, float(f.get("hours") or 24)))
        except ValueError:
            raise HubError("uses and hours must be numbers") from None
        tok = self.hub.create_token(user.username, hours, uses, f.get("note", "")[:100])
        self.tokens(user, sess, f, token=tok)

    def audit(self, user, sess, f) -> None:
        if not user.can("audit"):
            raise HubError("only admins can read the audit trail", 403)
        rows = self.hub.store.list_audit(300)
        tr = "".join(f'<tr><td>{e(r["seq"])}</td><td>{e(ts(r["ts"]))}</td><td>{e(r["actor"])}</td><td>{e(r["event"])}</td>'
                     f'<td><code>{e((r["details"] or "")[:300])}</code></td></tr>' for r in rows)
        v = self.hub.store.verify_audit()
        head = "<p class=flash>Audit trail verified: intact.</p>" if v["ok"] else \
            f"<p class=err>Audit trail verification FAILED: {e(v['problems'][:3])}</p>"
        self.page("Hub audit trail", head + f"<table><tr><th>#</th><th>Time</th><th>Actor</th><th>Event</th>"
                                            f"<th>Details</th></tr>{tr}</table>", user=user, sess=sess)
