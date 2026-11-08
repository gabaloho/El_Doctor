"""Desktop GUI tests - drive the real Tk widgets (needs tkinter and a display; skipped otherwise)."""
import os
import subprocess
import sys
import time

import pytest

tk = pytest.importorskip("tkinter")
if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    pytest.skip("no display", allow_module_level=True)

from eldoctor.ui import gui  # noqa: E402

PW = "Str0ng!Passw0rd"


@pytest.fixture
def app(cfg, monkeypatch):
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(gui.messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(gui.messagebox, "showwarning", lambda *a, **k: None)
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(gui.ApiKeyDialog, "__init__", lambda self, app, user, key: setattr(app, "_key", key))
    cfg["agent"]["interval"] = 0.5
    cfg["thresholds"].update(process_cpu=70, process_cpu_duration=1.5)
    created = []
    import threading
    before = {t.ident for t in threading.enumerate()}

    def make(mode="interactive"):
        a = gui.App(cfg, mode=mode)
        created.append(a)
        return a
    yield make
    import gc
    for a in created:
        try:
            a._stop_agent()
            if a.api is not None:
                a.api.close()
            a.root.destroy()
        except Exception:
            pass
    created.clear()
    gc.collect()          # finalize Tk objects on the main thread, not in the next test's agent thread
    # regression guard: closing the GUI must stop the agent, API, notification and polling threads it started
    leaked = [t.name for t in threading.enumerate() if t.ident not in before
              and t.name in ("eldoctor-agent", "notify", "eldoctor-observer", "eldoctor-api", "eldoctor-api-conn",
                             "eldoctor-client", "eldoctor-siem", "eldoctor-integrity")]
    assert not leaked, f"threads still running after the GUI closed: {leaked}"


def pump(app, seconds=1.0, until=None):
    end = time.time() + seconds
    while time.time() < end:
        app.root.update()
        if until and until():
            return True
        time.sleep(0.05)
    return bool(until and until())


def diag(a):
    ag, m = a.agent, a.main
    return (f"ticks={ag.status().get('ticks', '?')} err={getattr(ag, 'error', '')!r} procs={len(ag.latest_procs)} "
            f"rows={len(m.ptree.get_children(''))} tab={m.TABS[m.nb.index(m.nb.select())]!r} "
            f"status={m.status_msg.get()!r} refreshes={getattr(m, '_refreshes', '?')}")


def register_and_login(a, username="admin_user", password=PW):
    assert a.auth and a.auth.mode == "register"
    v = a.auth.vars
    v["username"].set(username)
    v["full_name"].set("Security Operator")
    v["email"].set("admin_user@example.invalid")
    v["pw"].set(password)
    v["pw2"].set(password)
    a.auth.submit()
    assert a.auth.mode == "login" and a.auth.vars["username"].get() == username
    a.auth.vars["pw"].set(password)
    a.auth.submit()
    assert a.main is not None
    return a.main


def test_registration_validation_and_login(app):
    a = app()
    v = a.auth.vars
    v["username"].set("admin_user")
    v["email"].set("admin_user@example.invalid")
    v["pw"].set(PW)
    v["pw2"].set("different!A1x")
    a.auth.submit()
    assert "do not match" in a.auth.err.get()
    v["pw2"].set(PW)
    v["pw"].set("weak")
    v["pw2"].set("weak")
    a.auth.submit()
    assert "weak password" in a.auth.err.get()
    main = register_and_login(a)
    assert a.user.role == "admin" and a._key.startswith("edk_")
    assert pump(a, 6, until=lambda: bool(a.agent.latest_metrics))
    main.refresh(force=True)
    assert main.c_cpu[1].get().endswith("%") and len(main.hist_cpu) >= 1
    assert [main.nb.tab(i, "text").strip() for i in range(3)] == ["Dashboard", "Processes", "Alerts"]


def test_wrong_password_and_lockout_message(app, cfg):
    a = app()
    register_and_login(a)
    a._stop_agent()
    a.api.logout()
    a.show_auth("login")
    for _ in range(5):
        a.auth.vars["username"].set("admin_user")
        a.auth.vars["pw"].set("Wrong!Passw0rd")
        a.auth.submit()
    assert "locked" in a.auth.err.get()
    assert a.main is None


def test_manual_kill_from_process_tab(app):
    a = app("monitor")
    main = register_and_login(a)
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        main.nb.select(1)
        assert pump(a, 8, until=lambda: str(victim.pid) in main.ptree.get_children("")), diag(a)
        main.ptree.selection_set(str(victim.pid))
        main.proc_action("kill")
        victim.wait(timeout=10)
        acts = a.api.call("actions.list", limit=10)
        assert acts[0]["action"] == "kill" and acts[0]["status"] == "success" and acts[0]["actor"] == "admin_user"
        # the agent recorded who did it, including the OS identity and the front end
        rec = next(r for r in a.api.call("audit.list", limit=20) if r["event"] == "manual_kill")
        assert rec["actor"] == "admin_user" and rec["client"] == "gui" and rec["os_uid"] == str(os.getuid())
    finally:
        if victim.poll() is None:
            victim.kill()


def test_manual_kill_of_protected_process_is_refused(app):
    a = app("monitor")
    main = register_and_login(a)
    main.nb.select(1)
    assert pump(a, 8, until=lambda: str(os.getppid()) in main.ptree.get_children("")), diag(a)
    main.ptree.selection_set(str(os.getppid()))           # the test runner's parent shell
    main.proc_action("kill")
    assert a.api.call("actions.list", limit=1)[0]["status"] == "blocked"


def test_interactive_approval_from_gui(app):
    a = app("interactive")
    main = register_and_login(a)
    hog = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        main.nb.select(4)
        assert pump(a, 25, until=lambda: len(main.aptree.get_children("")) > 0), "no approval appeared " + diag(a)
        assert "Approvals (" in main.nb.tab(4, "text")
        # regression: once the tab title shows the counter, the table must keep refreshing
        main.aptree.delete(*main.aptree.get_children(""))
        assert pump(a, 3, until=lambda: len(main.aptree.get_children("")) > 0), "approvals table stopped refreshing"
        main.aptree.selection_set(main.aptree.get_children("")[0])
        main.decide(True)
        assert pump(a, 10, until=lambda: hog.poll() is not None), "hog not killed after approval"
        main.refresh(force=True)
        hist = [main.aphist.item(i, "values") for i in main.aphist.get_children("")]
        assert hist and hist[0][2] == "approved" and hist[0][3] == "admin_user"
    finally:
        if hog.poll() is None:
            hog.kill()


def test_alerts_tab_details_and_banner(app):
    a = app("enforce")
    main = register_and_login(a)
    hog = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        assert pump(a, 25, until=lambda: hog.poll() is not None)
        pump(a, 2)
        assert main.banner.winfo_manager() == "pack" and main.banner_text.get().startswith(("HIGH:", "CRITICAL:"))
        main.nb.select(2)
        main.refresh(force=True)
        iid = next(i for i in main.atree.get_children("") if main._alerts_cache[i]["rule_id"] == "ED-RES-001")
        main.atree.selection_set(iid)
        main.show_alert()
        text = main.adetail.get("1.0", "end")
        assert "T1496" in text and "Resource Hijacking" in text and "kill" in text and "success" in text
    finally:
        if hog.poll() is None:
            hog.kill()


def test_deploy_tab_generates_bundle(app, tmp_path):
    a = app("monitor")
    main = register_and_login(a)
    main.dep_target.set("kubernetes")
    main.dep_out.set(str(tmp_path / "k8s"))
    main.generate()
    assert pump(a, 10, until=lambda: (tmp_path / "k8s" / "30-daemonset.yaml").exists())
    pump(a, 0.5)
    assert "Generated" in main.dep_text.get("1.0", "end")


def test_viewer_is_read_only(app, store):
    from eldoctor.auth.users import UserManager
    UserManager(store).register("admin1", PW, "a@example.invalid")
    a = app()
    assert a.auth.mode == "login"
    a.show_auth("register")
    v = a.auth.vars
    for k, val in (("username", "user_two"), ("email", "b@example.invalid"), ("pw", "B0b!Passw0rd"), ("pw2", "B0b!Passw0rd")):
        v[k].set(val)
    a.auth.submit()
    a.auth.vars["pw"].set("B0b!Passw0rd")
    a.auth.submit()
    assert a.user.role == "viewer" and not a.agent.running           # the agent refused to start detection
    assert "view-only" in a.agent.reason
    assert all(b.instate(["disabled"]) for b in a.main.proc_buttons)
    assert a.main.b_approve.instate(["disabled"])
    # greyed-out buttons are only UX: calling the agent directly is refused by the agent itself
    from eldoctor.api.client import ApiError
    with pytest.raises(ApiError) as e:
        a.api.call("respond.process", action="kill", pid=os.getpid())
    assert e.value.code == "forbidden"
    res = a.agent.manual_action("kill", gui.ProcessInfo(pid=os.getpid(), name="x"))
    assert res.status == "blocked" and "lacks 'respond'" in res.message


def test_gui_attaches_to_running_service(app, cfg):
    """A real agent serves the API on its socket: the GUI becomes a pure client of it."""
    from eldoctor.api.server import AgentService
    svc = AgentService(cfg, role="service")
    try:
        admin, _ = svc.um.register("admin_user", PW, "a@example.invalid")
        svc.start_listener()
        svc.start_agent(admin, "monitor")
        a = app("enforce")
        assert a.auth.mode == "login" and not a.api.hosted            # talking to the service over the socket
        a.auth.vars["username"].set("admin_user")
        a.auth.vars["pw"].set(PW)
        a.auth.submit()
        assert a.main is not None and a.attached_pid == os.getpid()
        assert "attached" in a.agent.reason and a.agent.running and a.agent.mode == "monitor"
        assert pump(a, 6, until=lambda: bool(a.agent.latest_metrics))
        a.main.set_mode("interactive")                              # authorised + executed by the service
        assert svc.agent.mode == "interactive"
        assert any(r["event"] == "mode_changed" and r["client"] == "gui" for r in svc.store.list_audit(20))
        a._stop_agent()                                             # closing the client must not stop the service
        assert svc.agent is not None and svc.agent._thread.is_alive()
    finally:
        svc.close()


# ------------------------------------------------------------------ appearance (light / dark / system)
@pytest.mark.parametrize("name", ["light", "dark"])
def test_theme_palettes_meet_wcag_aa(name):
    t = gui.THEMES[name]
    texts = [t[k] for k in ("fg", "muted", "accent", "ok", "warn", "high", "crit")]
    texts += list(t["sev"].values()) + list(t["status"].values())
    for bg in (t["panel"], t["card"], t["bg"]):
        worst = min(gui.contrast(c, bg) for c in texts)
        assert worst >= 4.5, f"{name}: text contrast {worst:.2f} < 4.5 on {bg}"
    assert gui.contrast(t["accent_fg"], t["accent"]) >= 4.5
    assert gui.contrast(t["danger_fg"], t["danger"]) >= 4.5
    for c in t["mode"].values():                               # header mode badge
        assert gui.contrast(gui.text_on(c), c) >= 4.5


def test_theme_preference_precedence(app, monkeypatch):
    monkeypatch.setattr(gui, "detect_system_theme", lambda: "dark")
    a = app()
    assert a.theme_pref == "system" and a.theme == "dark"      # default follows the OS
    a.set_theme("light")
    assert gui.load_prefs()["theme"] == "light"
    a._stop_agent()
    a.root.destroy()
    b = gui.App(a.cfg)                                         # saved choice wins over the OS
    assert b.theme == "light"
    b.root.destroy()
    c = gui.App(a.cfg, theme="dark")                           # --theme wins over the saved choice
    assert c.theme == "dark"
    c.root.destroy()


def test_live_theme_switch_keeps_agent_tab_and_selection(app, monkeypatch):
    monkeypatch.setattr(gui, "detect_system_theme", lambda: "light")
    a = app("monitor")
    main = register_and_login(a)
    agent = a.agent
    from eldoctor.models import Alert
    al = Alert(rule_id="ED-TEST-1", title="theme test alert", severity="critical", mitre=["T1496"])
    a.api.local_service.store.add_alert(al)
    main.nb.select(2)
    main.refresh(force=True)
    main.atree.selection_set(al.id)
    main.show_alert()
    assert a.theme == "light"
    style = gui.ttk.Style(a.root)
    assert style.lookup("Treeview", "background") == gui.THEMES["light"]["panel"]
    a.toggle_theme()
    pump(a, 0.5)
    assert a.theme == "dark" and a.agent is agent and agent._thread.is_alive()
    assert a.api.local_service.agent._thread.is_alive()               # detection kept running too
    new = a.main
    assert new is not main and new.nb.index(new.nb.select()) == 2
    assert new.atree.selection() == (al.id,) and "theme test alert" in new.adetail.get("1.0", "end")
    assert style.lookup("Treeview", "background") == gui.THEMES["dark"]["panel"]
    assert str(new.adetail.cget("background")) == gui.THEMES["dark"]["panel"]
    a.set_theme("system")
    assert a.theme == "light" and gui.load_prefs()["theme"] == "system"


def test_auth_screen_toggle_keeps_username(app):
    a = app()
    a.auth.vars["username"].set("analyst_user")
    before = a.theme
    a.toggle_theme()
    assert a.theme != before and a.auth.mode == "register" and a.auth.vars["username"].get() == "analyst_user"
