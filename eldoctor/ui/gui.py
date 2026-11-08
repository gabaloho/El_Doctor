"""El Doctor desktop GUI (Tkinter - ships with Python on Windows and macOS).

    python eldoctor gui        python -m eldoctor gui        eldoctor-gui (no console window on Windows)

Flow: registration (mandatory, first user = admin) -> login -> main window.

The GUI is a client of the agent's local API (``eldoctor.api``).  If the El Doctor
service (or another console) is running, the GUI *attaches* to it over the socket /
named pipe.  Otherwise - personal install, data folder owned by this OS account - it
hosts the agent in-process and serves the API for other terminals.  Either way every
action and every permission check happens inside the agent; the GUI only greys out
controls using the permission list the agent reports.

Keyboard: Ctrl+1..9 switch tabs, F5 refresh, Delete = kill selected process,
Alt+A / Alt+D approve / deny the selected request, Ctrl+Q quit.
"""
from __future__ import annotations

import gc
import json
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from eldoctor import __version__
from eldoctor.config import MODES, client_dir, load_config
from eldoctor.models import HOSTNAME, ProcessInfo, severity_rank

THEMES: Dict[str, Dict[str, Any]] = {
    "dark": {
        "bg": "#14161d", "panel": "#1b1e29", "card": "#232838", "fg": "#e6e8ef", "muted": "#8b93a7",
        "accent": "#3fa9f5", "accent_fg": "#0b1020", "accent_active": "#6cc0ff", "ok": "#2ecc71", "warn": "#f1c40f",
        "high": "#ff8c1a", "crit": "#ff5c5e", "border": "#2f3548", "select": "#2f4a73", "entry": "#10121a",
        "trough": "#10121a", "heading": "#232838", "tab": "#1b1e29", "tab_selected": "#232838",
        "danger": "#8e2a2c", "danger_fg": "#ffffff", "banner_high": "#c8650d", "banner_btn": "#7a1c1e",
        "banner_btn_active": "#a52a2d", "bar_ok": "#2ecc71", "bar_warn": "#f1c40f", "bar_crit": "#ff5c5e",
        "bar_blue": "#3fa9f5", "chart_cpu": "#3fa9f5", "chart_mem": "#ff8c1a",
        "sev": {"info": "#8b93a7", "low": "#4fc3f7", "medium": "#f1c40f", "high": "#ff8c1a", "critical": "#ff5c5e"},
        "status": {"success": "#2ecc71", "failed": "#ff5c5e", "blocked": "#ff8c1a", "pending_approval": "#f1c40f",
                   "would_run": "#4fc3f7", "dry_run": "#4fc3f7", "skipped": "#8b93a7", "approved": "#2ecc71",
                   "denied": "#ff5c5e", "expired": "#8b93a7"},
        "mode": {"monitor": "#4fc3f7", "interactive": "#f1c40f", "enforce": "#ff5c5e"},
    },
    "light": {
        "bg": "#eceff4", "panel": "#ffffff", "card": "#ffffff", "fg": "#1c2230", "muted": "#566070",
        "accent": "#1a66d6", "accent_fg": "#ffffff", "accent_active": "#3b7fe3", "ok": "#17702f", "warn": "#8a6100",
        "high": "#b34700", "crit": "#c62828", "border": "#cfd6e1", "select": "#d2e3fc", "entry": "#ffffff",
        "trough": "#e4e8ef", "heading": "#e9edf3", "tab": "#dde2ea", "tab_selected": "#ffffff",
        "danger": "#c62828", "danger_fg": "#ffffff", "banner_high": "#b34700", "banner_btn": "#7f1d1d",
        "banner_btn_active": "#991b1b", "bar_ok": "#2ea44f", "bar_warn": "#e3a008", "bar_crit": "#d93025",
        "bar_blue": "#1a73e8", "chart_cpu": "#1a66d6", "chart_mem": "#d35400",
        "sev": {"info": "#566070", "low": "#01579b", "medium": "#8a6100", "high": "#b34700", "critical": "#c62828"},
        "status": {"success": "#17702f", "failed": "#c62828", "blocked": "#b34700", "pending_approval": "#8a6100",
                   "would_run": "#01579b", "dry_run": "#01579b", "skipped": "#566070", "approved": "#17702f",
                   "denied": "#c62828", "expired": "#566070"},
        "mode": {"monitor": "#0277bd", "interactive": "#f9ab00", "enforce": "#d93025"},
    },
}
THEME_CHOICES = ["system", "light", "dark"]
# live palette - mutated in place by apply_palette() so every module-level reference stays valid
C: Dict[str, str] = {}
SEV: Dict[str, str] = {}
STATUS: Dict[str, str] = {}
MODE_COLOR: Dict[str, str] = {}


def apply_palette(name: str) -> None:
    t = THEMES[name]
    C.clear()
    C.update({k: v for k, v in t.items() if isinstance(v, str)})
    C["name"] = name
    for target, key in ((SEV, "sev"), (STATUS, "status"), (MODE_COLOR, "mode")):
        target.clear()
        target.update(t[key])


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    rgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    """WCAG 2.x contrast ratio between two colours (4.5 = AA for normal text)."""
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def text_on(bg: str) -> str:
    """Black or white, whichever reads better on `bg`."""
    return "#000000" if contrast(bg, "#000000") >= contrast(bg, "#ffffff") else "#ffffff"


def detect_system_theme() -> str:
    """'dark' or 'light' from the operating system preference (falls back to light)."""
    try:
        if sys.platform.startswith("win"):
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
                return "light" if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] else "dark"
        if sys.platform == "darwin":
            r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True, text=True,
                               timeout=3)
            return "dark" if "dark" in r.stdout.lower() else "light"
        gtk = os.environ.get("GTK_THEME", "")
        if gtk:
            return "dark" if "dark" in gtk.lower() else "light"
        for key in ("color-scheme", "gtk-theme"):
            r = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", key], capture_output=True,
                               text=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip() not in ("", "'default'"):
                return "dark" if "dark" in r.stdout.lower() else "light"
    except Exception:
        pass
    return "light"


def prefs_path() -> Path:
    import getpass
    try:
        who = "".join(ch for ch in getpass.getuser() if ch.isalnum() or ch in "-_.") or "user"
    except Exception:
        who = "user"
    return client_dir() / f"gui-prefs-{who}.json"


def load_prefs() -> Dict[str, Any]:
    try:
        return json.loads(prefs_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_prefs(**kw: Any) -> None:
    prefs = load_prefs()
    prefs.update(kw)
    try:
        prefs_path().write_text(json.dumps(prefs), encoding="utf-8")
    except OSError:
        pass


apply_palette("dark")


def ts(t: Optional[float], fmt: str = "%H:%M:%S") -> str:
    return time.strftime(fmt, time.localtime(t)) if t else ""


def rate(b: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB/s"


def open_path(path: str) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def sync_tree(tree: ttk.Treeview, rows: List[tuple]) -> None:
    """Update a Treeview in place (keeps selection and scroll position). rows: (iid, values, tags)."""
    existing = set(tree.get_children(""))
    wanted = set()
    for idx, (iid, values, tags) in enumerate(rows):
        iid = str(iid)
        if iid in wanted:
            continue
        wanted.add(iid)
        if iid in existing:
            tree.item(iid, values=values, tags=tags)
        else:
            tree.insert("", "end", iid=iid, values=values, tags=tags)
        if tree.index(iid) != idx:
            tree.move(iid, "", idx)
    gone = existing - wanted
    if gone:
        tree.delete(*gone)


# ----------------------------------------------------------------------------------------- user view
class GuiUser:
    """The signed-in user as reported by the agent.  ``can()`` only greys out controls - the agent
    re-checks every request against the user's current role."""

    def __init__(self, d: Dict[str, Any]) -> None:
        self.data = dict(d)
        self.id = d.get("id")
        self.username = d.get("username", "")
        self.email = d.get("email", "")
        self.full_name = d.get("full_name", "")
        self.organization = d.get("organization", "")
        self.role = d.get("role", "viewer")
        self.use_case = d.get("use_case", "")
        self.deployment_target = d.get("deployment_target", "")
        self.permissions = set(d.get("permissions") or [])

    def can(self, perm: str) -> bool:
        return perm in self.permissions


# ----------------------------------------------------------------------------------------- app
class App:
    def __init__(self, cfg: Optional[Dict[str, Any]] = None, mode: Optional[str] = None, dry_run: bool = False,
                 interval: Optional[float] = None, root: Optional[tk.Tk] = None, theme: Optional[str] = None) -> None:
        self.cfg = cfg or load_config()
        if interval:
            self.cfg["agent"]["interval"] = interval
        self.req_mode, self.dry_run = mode, dry_run
        self.api = None                                # eldoctor.api.client.ApiClient
        self.hello: Dict[str, Any] = {}
        self.root = root or tk.Tk()
        self.root.title(f"El Doctor {__version__} - Security Console")
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        w, h = min(1360, sw - 40), min(860, sh - 80)
        self.root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")
        self.root.minsize(min(1000, w), min(640, h))
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        # appearance: --theme > saved preference > config gui.theme > follow the operating system
        self.theme_pref = (theme or load_prefs().get("theme") or (self.cfg.get("gui") or {}).get("theme")
                           or "system")
        if self.theme_pref not in THEME_CHOICES:
            self.theme_pref = "system"
        self.theme = detect_system_theme() if self.theme_pref == "system" else self.theme_pref
        apply_palette(self.theme)
        self.hist_cpu: deque = deque(maxlen=180)       # survive view rebuilds (theme switch)
        self.hist_mem: deque = deque(maxlen=180)
        self._setup_fonts()
        self._apply_styles()
        self.root.bind_all("<Control-t>", lambda e: self.toggle_theme())
        self.agent = None
        self.attached_pid: Optional[int] = None
        self.user = None
        self.main: Optional[MainView] = None
        self.auth: Optional[AuthView] = None
        self.tasks: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self.root.after(100, self._drain_tasks)
        self.root.bind_all("<Control-q>", lambda e: self.on_close())
        self.error_view: Optional[ttk.Frame] = None
        self.open()

    # -------------------------------------------------------------- connection to the agent
    def connect(self) -> bool:
        """Attach to the running agent, or host it in-process on a data folder this OS account owns."""
        from eldoctor.api.client import connect
        from eldoctor.api.transport import ApiUnavailable
        if self.api is not None:
            return True
        try:
            self.api = connect(self.cfg, client="gui", role="embedded")
            self.hello = self.api.call("sys.hello")
            return True
        except ApiUnavailable as exc:
            self.api = None
            self.show_error(str(exc))
            return False

    def open(self) -> None:
        from eldoctor.api.transport import ApiUnavailable
        if not self.connect():
            return
        try:
            who = self.api.whoami()
        except ApiUnavailable as exc:              # the service went away between connect and sign-in
            self.api = None
            self.show_error(str(exc))
            return
        if who:
            self.start_main(GuiUser(who))
        else:
            self.show_auth("register" if not self.hello.get("registered") else "login")

    def show_error(self, msg: str) -> None:
        for v in (self.main, self.auth, self.error_view):
            if v is not None:
                v.destroy()
        self.main = self.auth = None
        f = ttk.Frame(self.root, padding=40)
        ttk.Label(f, text="El Doctor", style="Title.TLabel").pack(anchor="w")
        ttk.Label(f, text=msg, wraplength=760, justify="left").pack(anchor="w", pady=12)
        row = ttk.Frame(f)
        row.pack(anchor="w")

        def retry() -> None:
            f.destroy()
            self.error_view = None
            self.open()
        ttk.Button(row, text="Retry", style="Accent.TButton", command=retry).pack(side="left")
        ttk.Button(row, text="Quit", command=self.root.destroy).pack(side="left", padx=8)
        f.pack(fill="both", expand=True)
        self.error_view = f

    # -------------------------------------------------------------- theme
    def set_theme(self, pref: str) -> None:
        """Switch appearance live: restyle ttk widgets and rebuild the current screen (the agent keeps running)."""
        if pref not in THEME_CHOICES:
            return
        self.theme_pref = pref
        save_prefs(theme=pref)
        self.theme = detect_system_theme() if pref == "system" else pref
        apply_palette(self.theme)
        self._apply_styles()
        if self.main:
            state = self.main.view_state()
            self.main.destroy()
            self.main = None
            self._release_tk_objects()
            self.main = MainView(self, last_alert_ts=state["last_alert_ts"])
            self.main.pack(fill="both", expand=True)
            self.main.restore_view_state(state)
            self.main.flash(f"appearance: {pref}" + (f" ({self.theme})" if pref == "system" else ""))
        elif self.auth:
            mode = self.auth.mode
            typed = {k: v.get() for k, v in self.auth.vars.items() if k not in ("pw", "pw2")}   # never keep passwords
            self.show_auth(mode, typed.get("username", ""), typed)

    def toggle_theme(self) -> None:
        self.set_theme("light" if self.theme == "dark" else "dark")

    def _setup_fonts(self) -> None:
        r = self.root
        families = set(tkfont.families(r))
        ui = next((f for f in ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Noto Sans", "DejaVu Sans",
                               "Liberation Sans", "Ubuntu") if f in families), None)
        mono = next((f for f in ("Cascadia Mono", "Consolas", "Menlo", "DejaVu Sans Mono", "Noto Sans Mono",
                                 "Liberation Mono") if f in families), None)
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            f = tkfont.nametofont(name)
            if ui:
                f.configure(family=ui)
            f.configure(size=10)
        if mono:
            tkfont.nametofont("TkFixedFont").configure(family=mono)
        base = tkfont.nametofont("TkDefaultFont")
        self.f_small = base.copy()
        self.f_small.configure(size=9)
        self.f_bold = base.copy()
        self.f_bold.configure(weight="bold")
        self.f_title = base.copy()
        self.f_title.configure(size=16, weight="bold")
        self.f_big = base.copy()
        self.f_big.configure(size=22, weight="bold")
        self.f_mono = tkfont.nametofont("TkFixedFont").copy()
        self.f_mono.configure(size=9)
        for cls in ("TEntry", "Entry"):
            r.bind_class(cls, "<Control-a>", lambda e: (e.widget.select_range(0, "end"), e.widget.icursor("end"), "break")[-1])

    def _apply_styles(self) -> None:
        r = self.root
        r.configure(bg=C["bg"])
        st = ttk.Style(r)
        st.theme_use("clam")
        st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["entry"], bordercolor=C["border"],
                     lightcolor=C["panel"], darkcolor=C["panel"], troughcolor=C["panel"], focuscolor=C["accent"],
                     selectbackground=C["select"], selectforeground=C["fg"], insertcolor=C["fg"])
        st.configure("TFrame", background=C["bg"])
        st.configure("Card.TFrame", background=C["card"], relief="flat")
        st.configure("Panel.TFrame", background=C["panel"])
        st.configure("TLabel", background=C["bg"], foreground=C["fg"])
        st.configure("Card.TLabel", background=C["card"])
        st.configure("Panel.TLabel", background=C["panel"])
        st.configure("Muted.TLabel", foreground=C["muted"])
        st.configure("CardMuted.TLabel", background=C["card"], foreground=C["muted"])
        st.configure("Title.TLabel", font=self.f_title, foreground=C["fg"])
        st.configure("Big.TLabel", background=C["card"], font=self.f_big)
        st.configure("Error.TLabel", foreground=C["crit"])
        st.configure("TButton", background=C["heading"] if C["name"] == "light" else C["card"], foreground=C["fg"],
                     padding=(10, 5), borderwidth=1)
        st.map("TButton", background=[("disabled", C["tab"]), ("active", C["select"])],
               foreground=[("disabled", C["muted"])])
        st.configure("Accent.TButton", background=C["accent"], foreground=C["accent_fg"], font=self.f_bold)
        st.map("Accent.TButton", background=[("active", C["accent_active"]), ("disabled", C["tab"])],
               foreground=[("disabled", C["muted"])])
        st.configure("Danger.TButton", background=C["danger"], foreground=C["danger_fg"])
        st.map("Danger.TButton", background=[("active", C["crit"]), ("disabled", C["tab"])],
               foreground=[("disabled", C["muted"])])
        st.configure("TEntry", fieldbackground=C["entry"], foreground=C["fg"], padding=4)
        st.configure("TCombobox", fieldbackground=C["entry"], background=C["card"], foreground=C["fg"],
                     arrowcolor=C["fg"], padding=3)
        st.map("TCombobox", fieldbackground=[("readonly", C["entry"])], foreground=[("readonly", C["fg"])])
        r.option_add("*TCombobox*Listbox.background", C["card"])
        r.option_add("*TCombobox*Listbox.foreground", C["fg"])
        r.option_add("*TCombobox*Listbox.selectBackground", C["select"])
        st.configure("TCheckbutton", background=C["bg"], foreground=C["fg"])
        st.configure("TRadiobutton", background=C["card"], foreground=C["fg"], indicatorbackground=C["entry"])
        st.map("TRadiobutton", background=[("active", C["card"])])
        st.map("TCheckbutton", background=[("active", C["bg"])])
        st.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(6, 6, 6, 0))
        st.configure("TNotebook.Tab", background=C["tab"], foreground=C["muted"], padding=(14, 6))
        st.map("TNotebook.Tab", background=[("selected", C["tab_selected"])], foreground=[("selected", C["fg"])])
        st.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["fg"],
                     rowheight=22, borderwidth=0)
        st.map("Treeview", background=[("selected", C["select"])])
        st.configure("Treeview.Heading", background=C["heading"], foreground=C["muted"], font=self.f_bold, relief="flat")
        st.map("Treeview.Heading", background=[("active", C["select"])])
        for name, color in (("Green", C["bar_ok"]), ("Yellow", C["bar_warn"]), ("Red", C["bar_crit"]),
                            ("Blue", C["bar_blue"])):
            st.configure(f"{name}.Horizontal.TProgressbar", background=color, troughcolor=C["trough"],
                         bordercolor=C["card"], lightcolor=color, darkcolor=color, thickness=10)
        st.configure("TLabelframe", background=C["bg"], bordercolor=C["border"])
        st.configure("TLabelframe.Label", background=C["bg"], foreground=C["muted"], font=self.f_bold)

    # -------------------------------------------------------------- task plumbing
    def run_bg(self, work: Callable[[], Any], done: Callable[[Any], None]) -> None:
        """Run `work` in a thread, then `done(result)` on the Tk thread (Tk is not thread-safe)."""
        def wrapper() -> None:
            try:
                result = work()
            except Exception as exc:
                result = exc
            self.tasks.put(lambda: done(result))
        threading.Thread(target=wrapper, daemon=True).start()

    def _drain_tasks(self) -> None:
        while True:
            try:
                self.tasks.get_nowait()()
            except queue.Empty:
                break
            except Exception as exc:  # never kill the UI loop
                print(f"gui task error: {exc}", file=sys.stderr)
        self.root.after(100, self._drain_tasks)

    # -------------------------------------------------------------- navigation
    @staticmethod
    def _release_tk_objects() -> None:
        """Collect destroyed screens *now*, on the Tk thread. Otherwise the garbage collector may finalize their
        Tk variables on the agent thread, which then blocks ~1 s per variable waiting for the Tk main loop."""
        gc.collect()

    def show_auth(self, mode: str, username: str = "", values: Optional[Dict[str, Any]] = None) -> None:
        if not self.connect():
            return
        try:
            self.hello = self.api.call("sys.hello")
        except Exception:
            pass
        if self.main:
            self.main.destroy()
            self.main = None
        if self.auth:
            self.auth.destroy()
        self.auth = None
        self._release_tk_objects()
        self.auth = AuthView(self, mode, username)
        for k, v in (values or {}).items():
            if k in self.auth.vars:
                self.auth.vars[k].set(v)
        self.auth.pack(fill="both", expand=True)

    def start_main(self, user: "GuiUser") -> None:
        from eldoctor.api.client import ApiError, RemoteAgent
        self.user = user
        if self.auth:
            self.auth.destroy()
            self.auth = None
        self._release_tk_objects()
        if self.api.hosted:
            # personal install: this window hosts the agent. Serve the API so a terminal can run
            # `eldoctor approvals approve ID` while the GUI is open.
            self.attached_pid = None
            reason = ""
            try:
                self.api.local_service.start_listener()
            except (RuntimeError, PermissionError, OSError) as exc:
                reason = f"local API not served: {exc}"
            try:
                res = self.api.call("agent.start", mode=self.req_mode, dry_run=bool(self.dry_run), headless=False)
                reason = res.get("message") or reason
            except ApiError as exc:                     # e.g. viewer: the agent refuses to start detection
                reason = f"view-only: {exc.message}"
        else:
            st = self.api.call("agent.status")
            self.attached_pid = (st.get("server") or {}).get("pid")
            reason = f"attached to the running El Doctor agent (pid {self.attached_pid})"
        self.agent = RemoteAgent(self.api, interval=1.0, processes="all", alerts=0, actions=0)
        self.agent.reason = reason
        self.agent.refresh()
        self.agent.start_background()
        try:
            self.info = self.api.call("agent.info")
        except ApiError:
            self.info = {}
        self.main = MainView(self)
        self.main.pack(fill="both", expand=True)

    def logout(self) -> None:
        hosted_running = self.api is not None and self.api.hosted and self.agent is not None and self.agent.running
        if hosted_running and not messagebox.askyesno("Log out", "Stop monitoring and log out?", parent=self.root):
            return
        self._stop_agent()
        try:
            self.api.logout()                            # the agent revokes the token (jti denylist)
        except Exception:
            pass
        self.user = None
        self.show_auth("login")

    def _stop_agent(self) -> None:
        """Stop polling; if this window hosts the agent, stop detection and the API listener too."""
        # finalize dead Tk objects here, on the Tk thread: if the GC ran them inside a worker thread, that thread
        # would block ~1 s per Tk variable waiting for the main loop - which is busy joining that very thread
        self._release_tk_objects()
        if self.agent:
            self.agent.stop()
            self.agent = None
        if self.api is not None and self.api.hosted and self.api.local_service is not None:
            self.api.local_service.stop_agent()

    def on_close(self) -> None:
        if self.api is not None and self.api.hosted and self.agent is not None and self.agent.running:
            if not messagebox.askyesno("Exit El Doctor",
                                       "Stop monitoring and close El Doctor?\n\nDetection and automated response "
                                       "stop while the console is closed (install the service for 24/7 protection).",
                                       parent=self.root):
                return
        self._stop_agent()
        if self.api is not None:
            self.api.close()
            self.api = None
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


# ----------------------------------------------------------------------------------------- auth
class AuthView(ttk.Frame):
    def __init__(self, app: App, mode: str, username: str = "") -> None:
        super().__init__(app.root)
        self.app, self.mode = app, mode
        from eldoctor.auth.users import DEPLOY_TARGETS, USE_CASES
        self.use_cases, self.targets = USE_CASES, DEPLOY_TARGETS
        outer = ttk.Frame(self)
        outer.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Button(self, text="Dark mode" if app.theme == "light" else "Light mode",
                   command=app.toggle_theme).place(relx=1.0, x=-16, y=16, anchor="ne")
        ttk.Label(outer, text="El Doctor", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text=f"Host security monitoring & automated response  -  v{__version__}",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))
        card = ttk.Frame(outer, style="Card.TFrame", padding=24)
        card.pack(fill="both")
        self.vars: Dict[str, tk.Variable] = {}
        self.err = tk.StringVar()
        if mode == "register":
            self._build_register(card)
        else:
            self._build_login(card, username)
        ttk.Label(card, textvariable=self.err, style="Error.TLabel", background=C["card"],
                  wraplength=460).grid(row=99, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _entry(self, parent, row: int, label: str, key: str, show: str = "", value: str = "") -> ttk.Entry:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        var = tk.StringVar(value=value)
        self.vars[key] = var
        e = ttk.Entry(parent, textvariable=var, show=show, width=42)
        e.grid(row=row, column=1, sticky="ew", pady=4)
        e.bind("<Return>", lambda ev: self.submit())
        return e

    def _combo(self, parent, row: int, label: str, key: str, options: Dict[str, str], default: str) -> None:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 12))
        labels = [f"{k} - {v}" for k, v in options.items()]
        var = tk.StringVar(value=next(l for l in labels if l.startswith(default + " ")))
        self.vars[key] = var
        ttk.Combobox(parent, textvariable=var, values=labels, state="readonly", width=52).grid(
            row=row, column=1, sticky="ew", pady=4)

    def _build_register(self, card) -> None:
        first = not self.app.hello.get("registered")
        ttk.Label(card, text="Create your account", style="Card.TLabel", font=self.app.f_title).grid(
            row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(card, text=("You are the first user: you become the administrator." if first else
                              "Self-registered accounts start as 'viewer' until an admin promotes them."),
                  style="CardMuted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))
        first_entry = self._entry(card, 2, "Username", "username")
        self._entry(card, 3, "Full name", "full_name")
        self._entry(card, 4, "E-mail", "email")
        self._entry(card, 5, "Organization (optional)", "org")
        self._combo(card, 6, "Use case", "use_case", self.use_cases, "personal")
        self._combo(card, 7, "Deploy on", "target", self.targets, "windows" if os.name == "nt" else "linux")
        self._entry(card, 8, "Password", "pw", show="\u2022")
        self._entry(card, 9, "Repeat password", "pw2", show="\u2022")
        ttk.Label(card, text="min. 10 characters, 3 of: lowercase, uppercase, digit, symbol",
                  style="CardMuted.TLabel", font=self.app.f_small).grid(row=10, column=1, sticky="w")
        self.vars["consent"] = tk.BooleanVar(value=False)
        if self.app.hello.get("webhook_consent"):
            ttk.Checkbutton(card, variable=self.vars["consent"], style="TCheckbutton",
                            text="Share my profile (never the password) with the El Doctor operator").grid(
                row=11, column=0, columnspan=2, sticky="w", pady=(8, 0))
        btns = ttk.Frame(card, style="Card.TFrame")
        btns.grid(row=12, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        ttk.Button(btns, text="Create account", style="Accent.TButton", command=self.submit).pack(side="left")
        if not first:
            ttk.Button(btns, text="I already have an account", command=lambda: self.app.show_auth("login")).pack(
                side="left", padx=8)
        first_entry.focus_set()

    def _build_login(self, card, username: str) -> None:
        ttk.Label(card, text="Sign in", style="Card.TLabel", font=self.app.f_title).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        u = self._entry(card, 2, "Username", "username", value=username)
        p = self._entry(card, 3, "Password", "pw", show="\u2022")
        btns = ttk.Frame(card, style="Card.TFrame")
        btns.grid(row=12, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        ttk.Button(btns, text="Sign in", style="Accent.TButton", command=self.submit).pack(side="left")
        ttk.Button(btns, text="Create a new account", command=lambda: self.app.show_auth("register")).pack(
            side="left", padx=8)
        (p if username else u).focus_set()

    def submit(self) -> None:
        """Both forms are requests to the agent: it verifies the password, applies the lockout and the
        password policy, picks the role, and issues the session token."""
        from eldoctor.api.client import ApiError
        from eldoctor.api.transport import ApiUnavailable
        v = {k: var.get() for k, var in self.vars.items()}
        self.err.set("")
        api = self.app.api
        try:
            if self.mode == "login":
                res = api.login(v["username"].strip(), v["pw"])
                self.app.start_main(GuiUser(res["user"]))
                return
            if v["pw"] != v["pw2"]:
                self.err.set("passwords do not match")
                return
            res = api.call("auth.register", username=v["username"].strip(), password=v["pw"],
                           email=v["email"].strip(), full_name=v["full_name"].strip(), organization=v["org"].strip(),
                           use_case=v["use_case"].split(" - ")[0], deployment_target=v["target"].split(" - ")[0],
                           consent_share=bool(v.get("consent")))
        except ApiError as exc:
            self.err.set(exc.message)
            return
        except ApiUnavailable as exc:
            self.err.set(str(exc))
            return
        self.app.hello["registered"] = True
        user = GuiUser(res["user"])
        ApiKeyDialog(self.app, user, res["api_key"])
        self.app.show_auth("login", user.username)


class ApiKeyDialog(tk.Toplevel):
    def __init__(self, app: App, user, key: str) -> None:
        super().__init__(app.root)
        self.app, self.user = app, user
        self.title("Account created")
        self.configure(bg=C["card"], padx=20, pady=16)
        self.transient(app.root)
        ttk.Label(self, text=f"Welcome {user.full_name or user.username}!", style="Card.TLabel",
                  font=app.f_title).pack(anchor="w")
        ttk.Label(self, text=f"Role: {user.role}   Use case: {user.use_case}   Deploy on: {user.deployment_target}",
                  style="Card.TLabel").pack(anchor="w", pady=(4, 10))
        ttk.Label(self, text="API key for services/automation (shown once - store it safely):",
                  style="CardMuted.TLabel").pack(anchor="w")
        e = ttk.Entry(self, width=60)
        e.insert(0, key)
        e.configure(state="readonly")
        e.pack(fill="x", pady=4)
        row = ttk.Frame(self, style="Card.TFrame")
        row.pack(fill="x", pady=(10, 0))
        ttk.Button(row, text="Copy key", command=lambda: (self.clipboard_clear(), self.clipboard_append(key))).pack(
            side="left")
        if user.role == "admin":
            ttk.Button(row, text=f"Generate {user.deployment_target} deployment bundle...",
                       command=self.deploy).pack(side="left", padx=8)
        ok = ttk.Button(row, text="Continue to sign in", style="Accent.TButton", command=self.destroy)
        ok.pack(side="right")
        self.bind("<Return>", lambda e: self.destroy())
        self.bind("<Escape>", lambda e: self.destroy())
        ok.focus_set()
        self.wait_visibility()
        self.grab_set()
        app.root.wait_window(self)

    def deploy(self) -> None:
        from eldoctor.deploy.generator import generate
        d = filedialog.askdirectory(parent=self, title="Output folder for the deployment bundle")
        if not d:
            return
        out = Path(d) / f"eldoctor-deploy-{self.user.deployment_target}"
        files = generate(self.user.deployment_target, out, {"username": self.user.username, "email": self.user.email,
                                                           "full_name": self.user.full_name,
                                                           "organization": self.user.organization,
                                                           "use_case": self.user.use_case})
        messagebox.showinfo("Deployment bundle", f"{len(files)} files written to\n{out}\n\nSee README-DEPLOY.md",
                            parent=self)


# ----------------------------------------------------------------------------------------- main view
class MainView(ttk.Frame):
    TABS = ["Dashboard", "Processes", "Alerts", "Response log", "Approvals", "Threat intel & rules",
            "Blocks & quarantine", "Deploy", "Users & settings"]

    def __init__(self, app: App, last_alert_ts: Optional[float] = None) -> None:
        super().__init__(app.root)
        self.app, self.user = app, app.user
        self.hist_cpu, self.hist_mem = app.hist_cpu, app.hist_mem
        self._last_metrics_ts = None
        self.last_alert_ts = last_alert_ts or time.time()
        self.proc_sort = ("cpu", True)
        self.alert_filter = tk.StringVar(value="all")
        self.search = tk.StringVar()
        self.proc_filter = tk.StringVar()
        self.status_msg = tk.StringVar(value="Ready")
        self._banner_hide = None
        self._alive = True
        self._build_header()
        self._build_banner()
        bar = ttk.Frame(self, style="Panel.TFrame", padding=(10, 3))
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, textvariable=self.status_msg, style="Panel.TLabel").pack(side="left")
        self.status_right = tk.StringVar()
        ttk.Label(bar, textvariable=self.status_right, style="Panel.TLabel", foreground=C["muted"]).pack(side="right")
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.tabs: Dict[str, ttk.Frame] = {}
        for name in self.TABS:
            f = ttk.Frame(self.nb, padding=10)
            self.nb.add(f, text=f"  {name}  ")
            self.tabs[name] = f
        self._tab_dashboard(self.tabs["Dashboard"])
        self._tab_processes(self.tabs["Processes"])
        self._tab_alerts(self.tabs["Alerts"])
        self._tab_actions(self.tabs["Response log"])
        self._tab_approvals(self.tabs["Approvals"])
        self._tab_intel(self.tabs["Threat intel & rules"])
        self._tab_blocks(self.tabs["Blocks & quarantine"])
        self._tab_deploy(self.tabs["Deploy"])
        self._tab_users(self.tabs["Users & settings"])
        root = app.root
        for i in range(1, 10):
            root.bind(f"<Control-Key-{i}>", lambda e, i=i: self.nb.select(i - 1))
        root.bind("<F5>", lambda e: self.refresh(force=True))
        root.bind("<Alt-a>", lambda e: self.decide(True))
        root.bind("<Alt-d>", lambda e: self.decide(False))
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh(force=True))
        if getattr(app.agent, "reason", ""):
            self.flash(app.agent.reason, C["warn"])
        self.after(300, self.refresh)

    def destroy(self) -> None:
        self._alive = False
        super().destroy()

    # -------------------------------------------------------------- state kept across a theme switch
    def view_state(self) -> Dict[str, Any]:
        return {"tab": self.nb.index(self.nb.select()), "last_alert_ts": self.last_alert_ts,
                "alert": (self.atree.selection() or [None])[0], "alert_filter": self.alert_filter.get(),
                "search": self.search.get(), "proc_filter": self.proc_filter.get(), "proc_sort": self.proc_sort,
                "proc": (self.ptree.selection() or [None])[0], "dep_target": self.dep_target.get(),
                "dep_mode": self.dep_mode.get(), "dep_out": self.dep_out.get()}

    def restore_view_state(self, st: Dict[str, Any]) -> None:
        self.alert_filter.set(st["alert_filter"])
        self.search.set(st["search"])
        self.proc_filter.set(st["proc_filter"])
        self.proc_sort = st["proc_sort"]
        self.dep_target.set(st["dep_target"])
        self.dep_mode.set(st["dep_mode"])
        self.dep_out.set(st["dep_out"])
        self.nb.select(st["tab"])
        self.refresh(force=True)
        self._refresh_alerts()                         # populate so the previous selection can be restored
        if st["alert"] and self.atree.exists(st["alert"]):
            self.atree.selection_set(st["alert"])
            self.atree.see(st["alert"])
            self.show_alert()
        self._refresh_processes()
        if st["proc"] and self.ptree.exists(st["proc"]):
            self.ptree.selection_set(st["proc"])
            self.ptree.see(st["proc"])

    # -------------------------------------------------------------- header & banner
    def _build_header(self) -> None:
        h = ttk.Frame(self, style="Panel.TFrame", padding=(12, 8))
        h.pack(fill="x")
        ttk.Label(h, text="El Doctor", style="Panel.TLabel", font=self.app.f_title).pack(side="left")
        ttk.Label(h, text=f"  {HOSTNAME}  |  {self.user.username} ({self.user.role})",
                  style="Panel.TLabel", foreground=C["muted"]).pack(side="left")
        ttk.Button(h, text="Log out", command=self.app.logout).pack(side="right")
        ttk.Button(h, text="Dark mode" if self.app.theme == "light" else "Light mode",
                   command=self.app.toggle_theme).pack(side="right", padx=(0, 6))
        self.mode_var = tk.StringVar()
        # greyed-out options are a hint only: the agent decides (agent.set_mode: run; enforce needs admin)
        allowed = [m for m in MODES if m != "enforce" or self.user.can("enforce")]
        self.mode_box = ttk.Combobox(h, textvariable=self.mode_var, values=allowed, state="readonly", width=12)
        self.mode_box.pack(side="right", padx=(4, 12))
        self.mode_box.bind("<<ComboboxSelected>>", lambda e: self.set_mode(self.mode_var.get()))
        if not (self.app.agent.running and self.user.can("run")):
            self.mode_box.configure(state="disabled")
        ttk.Label(h, text="Response mode:", style="Panel.TLabel").pack(side="right")
        self.mode_badge = tk.Label(h, text="", bg=C["panel"], fg=C["fg"], font=self.app.f_bold, padx=8)
        self.mode_badge.pack(side="right", padx=8)
        self.hdr_info = tk.StringVar()
        ttk.Label(h, textvariable=self.hdr_info, style="Panel.TLabel", foreground=C["muted"]).pack(side="right",
                                                                                               padx=12)

    def _build_banner(self) -> None:
        self.banner = tk.Frame(self, bg=C["crit"])
        self.banner_text = tk.StringVar()
        # buttons first: pack() gives earlier widgets priority, so long alert text can never hide them
        tk.Button(self.banner, text="Dismiss", command=self.hide_banner, bg=C["banner_btn"], fg="white", relief="flat",
                  activebackground=C["banner_btn_active"], activeforeground="white").pack(side="right", padx=6, pady=4)
        tk.Button(self.banner, text="View alerts", command=lambda: self.nb.select(2), bg=C["banner_btn"], fg="white",
                  relief="flat", activebackground=C["banner_btn_active"], activeforeground="white").pack(side="right",
                                                                                                         pady=4)
        tk.Label(self.banner, textvariable=self.banner_text, bg=C["crit"], fg="white", font=self.app.f_bold,
                 anchor="w", padx=12, pady=6).pack(side="left", fill="x", expand=True)

    def show_banner(self, text: str, color: str) -> None:
        self.banner.configure(bg=color)
        for w in self.banner.winfo_children():
            if isinstance(w, tk.Label):
                w.configure(bg=color)
        self.banner_text.set(text)
        if not self.banner.winfo_ismapped():
            self.banner.pack(fill="x", after=self.winfo_children()[0], padx=8, pady=(6, 0))
        if self._banner_hide:
            self.after_cancel(self._banner_hide)
        self._banner_hide = self.after(20000, self.hide_banner)
        try:
            self.app.root.bell()
        except tk.TclError:
            pass

    def hide_banner(self) -> None:
        self.banner.pack_forget()

    def flash(self, msg: str, color: str = "") -> None:
        self.status_msg.set(f"{time.strftime('%H:%M:%S')}  {msg}")

    def set_mode(self, mode: str) -> None:
        ok, msg = self.app.agent.set_mode(mode)          # authorised and audited by the agent
        if not ok:
            messagebox.showwarning("Mode", msg, parent=self)
        self.flash(msg)
        self.app.agent.refresh()
        self.refresh(force=True)

    # -------------------------------------------------------------- helpers
    def tree(self, parent, columns: List[tuple], height: int = 12) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        t = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height,
                         selectmode="browse")
        for cid, title, width, anchor in columns:
            t.heading(cid, text=title)
            t.column(cid, width=width, anchor=anchor, stretch=cid in ("cmd", "title", "message", "summary", "reason"))
        sb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for sev, color in SEV.items():
            t.tag_configure(f"sev_{sev}", foreground=color)
        for st, color in STATUS.items():
            t.tag_configure(f"st_{st}", foreground=color)
        t.tag_configure("hot", foreground=C["crit"])
        t.tag_configure("warm", foreground=C["warn"])
        return t

    def card(self, parent, title: str) -> tuple:
        f = ttk.Frame(parent, style="Card.TFrame", padding=12)
        ttk.Label(f, text=title, style="CardMuted.TLabel").pack(anchor="w")
        v = tk.StringVar(value="-")
        ttk.Label(f, textvariable=v, style="Big.TLabel").pack(anchor="w")
        sub = tk.StringVar()
        ttk.Label(f, textvariable=sub, style="CardMuted.TLabel").pack(anchor="w")
        bar = ttk.Progressbar(f, maximum=100, style="Green.Horizontal.TProgressbar", length=220)
        bar.pack(fill="x", pady=(6, 0))
        return f, v, sub, bar

    def can(self, perm: str) -> bool:
        """UX only (greys out controls). The agent re-checks every request."""
        return self.user.can(perm)

    def call(self, method: str, **params: Any) -> Any:
        return self.app.api.call(method, **params)

    # -------------------------------------------------------------- dashboard
    def _tab_dashboard(self, tab) -> None:
        cards = ttk.Frame(tab)
        cards.pack(fill="x")
        self.c_cpu = self.card(cards, "CPU")
        self.c_mem = self.card(cards, "MEMORY")
        self.c_disk = self.card(cards, "DISK")
        self.c_net = self.card(cards, "NETWORK")
        for i, c in enumerate((self.c_cpu, self.c_mem, self.c_disk, self.c_net)):
            c[0].grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            cards.columnconfigure(i, weight=1)
        mid = ttk.Frame(tab)
        mid.pack(fill="both", expand=True, pady=10)
        left = ttk.Frame(mid, style="Card.TFrame", padding=10)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="CPU (blue) and memory (orange) - last 3 minutes", style="CardMuted.TLabel").pack(anchor="w")
        self.chart = tk.Canvas(left, bg=C["panel"], highlightthickness=1 if C["name"] == "light" else 0,
                               highlightbackground=C["border"], height=210)
        self.chart.pack(fill="both", expand=True, pady=(6, 0))
        right = ttk.Frame(mid, style="Card.TFrame", padding=12)
        right.pack(side="left", fill="y", padx=(10, 0))
        ttk.Label(right, text="SECURITY POSTURE (24 h)", style="CardMuted.TLabel").pack(anchor="w")
        self.sev_labels: Dict[str, tk.StringVar] = {}
        grid = ttk.Frame(right, style="Card.TFrame")
        grid.pack(anchor="w", pady=6)
        for i, sev in enumerate(["critical", "high", "medium", "low"]):
            v = tk.StringVar(value="0")
            self.sev_labels[sev] = v
            box = tk.Frame(grid, bg=C["panel"], padx=10, pady=6)
            box.grid(row=i // 2, column=i % 2, padx=4, pady=4, sticky="nsew")
            tk.Label(box, textvariable=v, bg=C["panel"], fg=SEV[sev], font=self.app.f_big, width=4).pack()
            tk.Label(box, text=sev.upper(), bg=C["panel"], fg=C["muted"], font=self.app.f_small).pack()
        self.posture = tk.StringVar()
        ttk.Label(right, textvariable=self.posture, style="Card.TLabel", justify="left", wraplength=300).pack(
            anchor="w", pady=(8, 0))
        bottom = ttk.Frame(tab)
        bottom.pack(fill="both", expand=True)
        ttk.Label(bottom, text="Latest detections", style="Muted.TLabel").pack(anchor="w")
        self.dash_alerts = self.tree(bottom, [("time", "Time", 80, "w"), ("sev", "Severity", 80, "w"),
                                              ("title", "Detection", 420, "w"), ("who", "Process / IP", 200, "w"),
                                              ("mitre", "MITRE ATT&CK", 180, "w"), ("resp", "Response", 300, "w")],
                                     height=7)
        self.dash_alerts.bind("<Double-1>", lambda e: self.nb.select(2))

    def draw_chart(self) -> None:
        c = self.chart
        c.delete("all")
        w, h = max(c.winfo_width(), 100), max(c.winfo_height(), 60)
        for pct in (25, 50, 75, 100):
            y = h - (h - 10) * pct / 100
            c.create_line(30, y, w, y, fill=C["border"], dash=(2, 4))
            c.create_text(4, y, text=f"{pct}%", anchor="w", fill=C["muted"], font=self.app.f_small)
        for data, color in ((self.hist_mem, C["chart_mem"]), (self.hist_cpu, C["chart_cpu"])):
            if len(data) < 2:
                continue
            step = (w - 32) / (data.maxlen - 1)
            offset = data.maxlen - len(data)
            pts = []
            for i, v in enumerate(data):
                pts += [32 + (i + offset) * step, h - (h - 10) * min(v, 100) / 100]
            c.create_line(*pts, fill=color, width=2, smooth=True)

    # -------------------------------------------------------------- processes
    def _tab_processes(self, tab) -> None:
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Filter:").pack(side="left")
        ttk.Entry(top, textvariable=self.proc_filter, width=30).pack(side="left", padx=6)
        self.proc_count = tk.StringVar()
        ttk.Label(top, textvariable=self.proc_count, style="Muted.TLabel").pack(side="left", padx=10)
        respond = self.can("respond")
        self.proc_buttons = []
        for text, action, style in [("Kill", "kill", "Danger.TButton"), ("Kill tree", "kill_tree", "Danger.TButton"),
                                    ("Suspend", "suspend", "TButton"), ("Resume", "resume", "TButton"),
                                    ("Lower priority", "renice", "TButton"), ("Quarantine exe", "quarantine", "TButton"),
                                    ("Forensics", "forensics", "TButton")]:
            b = ttk.Button(top, text=text, style=style, command=lambda a=action: self.proc_action(a))
            b.pack(side="right", padx=2)
            if not respond:
                b.state(["disabled"])
            self.proc_buttons.append(b)
        cols = [("pid", "PID", 70, "e"), ("user", "User", 110, "w"), ("cpu", "CPU %", 70, "e"),
                ("mem", "Mem %", 70, "e"), ("rss", "RSS MB", 80, "e"), ("thr", "Threads", 70, "e"),
                ("name", "Name", 160, "w"), ("cmd", "Command line", 600, "w")]
        self.ptree = self.tree(tab, cols, height=24)
        for cid, *_ in cols:
            self.ptree.heading(cid, command=lambda c=cid: self.sort_procs(c))
        self.ptree.bind("<Delete>", lambda e: self.proc_action("kill"))
        menu = tk.Menu(self, tearoff=0, bg=C["card"], fg=C["fg"], activebackground=C["select"],
                       activeforeground=C["fg"])
        for label, action in [("Kill", "kill"), ("Kill process tree", "kill_tree"), ("Suspend", "suspend"),
                              ("Resume", "resume"), ("Lower priority", "renice"), ("Quarantine executable", "quarantine"),
                              ("Collect forensics", "forensics")]:
            menu.add_command(label=label, command=lambda a=action: self.proc_action(a),
                             state="normal" if respond else "disabled")

        def popup(e):
            iid = self.ptree.identify_row(e.y)
            if iid:
                self.ptree.selection_set(iid)
                menu.tk_popup(e.x_root, e.y_root)
        self.ptree.bind("<Button-3>", popup)
        ttk.Label(tab, text="Actions pass through El Doctor's safety guards (system processes, El Doctor itself and "
                            "its parents are protected). Double-click a row to copy its command line.",
                  style="Muted.TLabel").pack(anchor="w", pady=(6, 0))
        self.ptree.bind("<Double-1>", self._copy_cmd)

    def _copy_cmd(self, e) -> None:
        p = self.selected_proc()
        if p:
            self.clipboard_clear()
            self.clipboard_append(p.cmdline_str)
            self.flash(f"copied command line of {p.name}[{p.pid}]")

    def sort_procs(self, col: str) -> None:
        cur, desc = self.proc_sort
        self.proc_sort = (col, not desc if cur == col else col in ("cpu", "mem", "rss", "thr"))
        self.refresh(force=True)

    def selected_proc(self) -> Optional[ProcessInfo]:
        sel = self.ptree.selection()
        if not sel:
            return None
        with self.app.agent.lock:
            procs = {str(p.pid): p for p in self.app.agent.latest_procs}
        return procs.get(sel[0])

    def proc_action(self, action: str) -> None:
        p = self.selected_proc()
        if not p:
            self.flash("select a process first")
            return
        verb = {"kill": "KILL", "kill_tree": "KILL (with all children)", "suspend": "SUSPEND",
                "quarantine": "QUARANTINE the executable of"}.get(action)
        if verb and not messagebox.askyesno("Confirm response action",
                                            f"{verb} {p.name} (pid {p.pid}, user {p.username})?\n\n{p.cmdline_str[:300]}",
                                            icon="warning", parent=self):
            return
        res = self.app.agent.manual_action(action, p)    # the agent checks 'respond' and resolves the pid itself
        self.flash(f"{action}: {res.status} - {res.message}")
        if res.status in ("failed", "blocked"):
            messagebox.showwarning(f"{action}: {res.status}", res.message, parent=self)
        self.refresh(force=True)

    # -------------------------------------------------------------- alerts
    def _tab_alerts(self, tab) -> None:
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Minimum severity:").pack(side="left")
        ttk.Combobox(top, textvariable=self.alert_filter, values=["all", "low", "medium", "high", "critical"],
                     state="readonly", width=10).pack(side="left", padx=6)
        ttk.Label(top, text="Search:").pack(side="left", padx=(12, 0))
        ttk.Entry(top, textvariable=self.search, width=30).pack(side="left", padx=6)
        self.b_alert_kill = ttk.Button(top, text="Kill this process", style="Danger.TButton",
                                       command=lambda: self.alert_action("kill"))
        self.b_alert_kill.pack(side="right", padx=2)
        self.b_alert_block = ttk.Button(top, text="Block remote IP", command=lambda: self.alert_action("block"))
        self.b_alert_block.pack(side="right", padx=2)
        ttk.Button(top, text="Open MITRE ATT&CK", command=self.open_mitre).pack(side="right", padx=2)
        if not self.can("respond"):
            self.b_alert_kill.state(["disabled"])
            self.b_alert_block.state(["disabled"])
        pw = ttk.PanedWindow(tab, orient="vertical")
        pw.pack(fill="both", expand=True)
        upper = ttk.Frame(pw)
        lower = ttk.Frame(pw)
        pw.add(upper, weight=3)
        pw.add(lower, weight=2)
        self.atree = self.tree(upper, [("time", "Time", 140, "w"), ("sev", "Severity", 80, "w"),
                                       ("rule", "Rule", 150, "w"), ("title", "Detection", 380, "w"),
                                       ("proc", "Process", 150, "w"), ("ip", "Remote IP", 120, "w"),
                                       ("mitre", "MITRE", 200, "w"), ("src", "Source", 80, "w")], height=14)
        self.atree.bind("<<TreeviewSelect>>", lambda e: self.show_alert())
        self.adetail = tk.Text(lower, bg=C["panel"], fg=C["fg"], insertbackground=C["fg"], relief="flat",
                               font=self.app.f_mono, wrap="word", height=12, padx=10, pady=8)
        self.adetail.pack(fill="both", expand=True, pady=(8, 0))
        self.adetail.tag_configure("h", foreground=C["accent"], font=self.app.f_bold)
        for sev, color in SEV.items():
            self.adetail.tag_configure(sev, foreground=color, font=self.app.f_bold)
        for st, color in STATUS.items():
            self.adetail.tag_configure(st, foreground=color)
        self._alerts_cache: Dict[str, Dict[str, Any]] = {}

    def selected_alert(self) -> Optional[Dict[str, Any]]:
        sel = self.atree.selection()
        return self._alerts_cache.get(sel[0]) if sel else None

    def show_alert(self) -> None:
        a = self.selected_alert()
        t = self.adetail
        t.configure(state="normal")
        t.delete("1.0", "end")
        if not a:
            return
        t.insert("end", f"{a['title']}\n", "h")
        integ = a.get("_integrity", "")
        if integ:
            t.insert("end", {"ok": "record verified against the agent's signed audit chain\n",
                             "tampered": "WARNING: this alert was modified after the agent recorded it\n",
                             "unrecorded": "WARNING: this alert was not recorded by the agent (inserted)\n"}.get(
                                 integ, f"integrity: {integ}\n"), "success" if integ == "ok" else "failed")
        t.insert("end", f"{a['severity'].upper()}", a["severity"])
        t.insert("end", f"   {a['rule_id']}   source: {a['source']}   {a.get('time_iso', '')}   host: {a.get('host')}\n\n")
        if a.get("description"):
            t.insert("end", "Why it matters\n", "h")
            t.insert("end", a["description"] + "\n\n")
        if a.get("mitre_details"):
            t.insert("end", "MITRE ATT&CK\n", "h")
            for m in a["mitre_details"]:
                t.insert("end", f"  {m['id']:<11} {m['name']}  [{m['tactic']}]  {m['url']}\n")
            t.insert("end", "\n")
        p = a.get("process") or {}
        if p:
            t.insert("end", "Process\n", "h")
            t.insert("end", f"  {p.get('name')} pid {p.get('pid')} ppid {p.get('ppid')} user {p.get('username')}\n"
                            f"  exe: {p.get('exe')}\n  cmd: {p.get('cmdline')}\n  parent: {p.get('parent_name')} "
                            f"{p.get('parent_exe')}\n  sha256: {p.get('sha256') or '-'}\n\n")
        if a.get("remote_ip"):
            t.insert("end", "Remote address\n", "h")
            t.insert("end", f"  {a['remote_ip']}\n\n")
        acts = self.call("actions.list", alert_id=a["id"])
        t.insert("end", "Automated response\n", "h")
        if not acts:
            t.insert("end", "  (none - see correlated incident or notify-only playbook)\n")
        for x in acts:
            t.insert("end", f"  {ts(x['ts'])}  {x['playbook_id']:<24} {x['action']:<18} ")
            t.insert("end", f"{x['status']:<17}", x["status"])
            t.insert("end", f" {x['message']}\n")
        t.insert("end", "\nEvidence\n", "h")
        t.insert("end", json.dumps(a.get("evidence", {}), indent=2, default=str) + "\n")
        t.configure(state="disabled")

    def open_mitre(self) -> None:
        a = self.selected_alert()
        if a and a.get("mitre_details"):
            webbrowser.open(a["mitre_details"][0]["url"])
        else:
            webbrowser.open("https://attack.mitre.org/")

    def alert_action(self, kind: str) -> None:
        a = self.selected_alert()
        if not a:
            self.flash("select an alert first")
            return
        if kind == "kill":
            p = a.get("process")
            if not p:
                self.flash("this alert has no process")
                return
            proc = ProcessInfo.from_dict(p)
            if not messagebox.askyesno("Confirm", f"Kill {proc.name} (pid {proc.pid})?", icon="warning", parent=self):
                return
            res = self.app.agent.manual_action("kill_tree", proc)
        else:
            from eldoctor.api.client import ApiError
            from eldoctor.models import ActionResult
            ip = a.get("remote_ip")
            if not ip:
                self.flash("this alert has no remote IP")
                return
            if not messagebox.askyesno("Confirm", f"Block {ip} for 24 hours?", parent=self):
                return
            try:
                d = self.call("respond.block_ip", ip=ip, alert_id=a["id"], reason=a["title"])
                res = ActionResult(d["action"], d["status"], d["message"], d.get("target", ip))
            except ApiError as exc:
                res = ActionResult("block_ip", "blocked" if exc.code == "forbidden" else "failed", exc.message, ip)
        self.flash(f"{res.action}: {res.status} - {res.message}")
        if res.status in ("failed", "blocked"):
            messagebox.showwarning(res.status, res.message, parent=self)
        self.show_alert()

    # -------------------------------------------------------------- actions log
    def _tab_actions(self, tab) -> None:
        self.xtree = self.tree(tab, [("time", "Time", 140, "w"), ("pb", "Playbook", 170, "w"),
                                     ("action", "Action", 130, "w"), ("status", "Status", 120, "w"),
                                     ("target", "Target", 200, "w"), ("mode", "Mode", 90, "w"),
                                     ("actor", "Actor", 110, "w"), ("message", "Result", 500, "w")], height=28)

    # -------------------------------------------------------------- approvals
    def _tab_approvals(self, tab) -> None:
        ttk.Label(tab, text="Interactive mode: El Doctor paused these playbooks and waits for an analyst decision. "
                            "Approve runs the remaining steps; deny resumes any process El Doctor suspended.",
                  style="Muted.TLabel", wraplength=1100).pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 6))
        self.b_approve = ttk.Button(row, text="Approve  (Alt+A)", style="Accent.TButton", command=lambda: self.decide(True))
        self.b_deny = ttk.Button(row, text="Deny  (Alt+D)", command=lambda: self.decide(False))
        self.b_approve.pack(side="left")
        self.b_deny.pack(side="left", padx=6)
        if not self.can("approve"):
            self.b_approve.state(["disabled"])
            self.b_deny.state(["disabled"])
        self.pending_lbl = tk.StringVar()
        ttk.Label(row, textvariable=self.pending_lbl, style="Muted.TLabel").pack(side="left", padx=12)
        self.aptree = self.tree(tab, [("id", "ID", 90, "w"), ("req", "Requested", 90, "w"),
                                      ("exp", "Expires in", 90, "e"), ("summary", "Requested action", 800, "w")],
                                height=8)
        ttk.Label(tab, text="History", style="Muted.TLabel").pack(anchor="w", pady=(12, 4))
        self.aphist = self.tree(tab, [("id", "ID", 90, "w"), ("req", "Requested", 140, "w"),
                                      ("status", "Decision", 100, "w"), ("by", "By", 110, "w"),
                                      ("summary", "Action", 800, "w")], height=10)


    def decide(self, approve: bool) -> None:
        sel = self.aptree.selection()
        if not sel:
            kids = self.aptree.get_children("")
            if not kids:
                self.flash("no pending approvals")
                return
            sel = (kids[0],)
        aid = sel[0]
        # the agent checks the approve permission, seals the decision and writes the chained audit record
        ok, msg = self.app.agent.decide(aid, approve)
        self.flash(msg if ok else f"approval {aid} not applied: {msg}")
        self.app.agent.refresh()
        self.refresh(force=True)

    # -------------------------------------------------------------- intel & rules
    def _tab_intel(self, tab) -> None:
        top = ttk.Frame(tab)
        top.pack(fill="x")
        self.ioc_summary = tk.StringVar()
        box = ttk.Frame(top, style="Card.TFrame", padding=12)
        box.pack(side="left", fill="both", expand=True)
        ttk.Label(box, text="THREAT INTELLIGENCE", style="CardMuted.TLabel").pack(anchor="w")
        ttk.Label(box, textvariable=self.ioc_summary, style="Card.TLabel", justify="left").pack(anchor="w", pady=4)
        b = ttk.Button(box, text="Update open feeds now (abuse.ch, Emerging Threats)", command=self.update_feeds)
        b.pack(anchor="w", pady=(6, 0))
        if not self.can("intel"):
            b.state(["disabled"])
        add = ttk.Frame(top, style="Card.TFrame", padding=12)
        add.pack(side="left", fill="both", padx=(10, 0))
        ttk.Label(add, text="ADD YOUR OWN INDICATOR", style="CardMuted.TLabel").grid(row=0, column=0, columnspan=4,
                                                                                    sticky="w")
        self.ioc_type = tk.StringVar(value="ip")
        self.ioc_value = tk.StringVar()
        self.ioc_sev = tk.StringVar(value="high")
        ttk.Combobox(add, textvariable=self.ioc_type, values=["ip", "cidr", "domain", "sha256", "sha1", "md5", "filename"],
                     state="readonly", width=9).grid(row=1, column=0, pady=6)
        ttk.Entry(add, textvariable=self.ioc_value, width=40).grid(row=1, column=1, padx=4)
        ttk.Combobox(add, textvariable=self.ioc_sev, values=["low", "medium", "high", "critical"], state="readonly",
                     width=8).grid(row=1, column=2)
        b2 = ttk.Button(add, text="Add", command=self.add_ioc)
        b2.grid(row=1, column=3, padx=4)
        if not self.can("intel"):
            b2.state(["disabled"])
        ttk.Label(add, text="Takes effect when the agent restarts or after the next feed update.",
                  style="CardMuted.TLabel").grid(row=2, column=0, columnspan=4, sticky="w")
        nb = ttk.Notebook(tab)
        nb.pack(fill="both", expand=True, pady=(10, 0))
        f1, f2, f3 = ttk.Frame(nb, padding=6), ttk.Frame(nb, padding=6), ttk.Frame(nb, padding=6)
        nb.add(f1, text="  Detection rules  ")
        nb.add(f2, text="  Playbooks  ")
        nb.add(f3, text="  Feeds  ")
        self.rtree = self.tree(f1, [("id", "Rule", 330, "w"), ("sev", "Severity", 80, "w"), ("mitre", "MITRE", 220, "w"),
                                    ("src", "Source", 220, "w"), ("title", "Title", 450, "w")], height=16)
        self.pbtree = self.tree(f2, [("prio", "Prio", 50, "e"), ("id", "Playbook", 190, "w"),
                                     ("max", "Max mode", 90, "w"), ("steps", "Steps", 520, "w"),
                                     ("title", "Name", 330, "w")], height=16)
        self.ftree = self.tree(f3, [("name", "Feed", 260, "w"), ("type", "Type", 80, "w"), ("count", "Indicators", 90, "e"),
                                    ("updated", "Updated", 160, "w"), ("url", "URL", 560, "w")], height=16)
        self.after(500, self.load_static)

    def load_static(self) -> None:
        api = self.app.api

        def work():
            return api.call("rules.list"), api.call("playbooks.list"), api.call("intel.status")
        self.app.run_bg(work, self._static_done)

    def _static_done(self, res) -> None:
        if isinstance(res, Exception) or not self._alive:
            return
        rules_res, pbs_res, intel = res
        rules, summary = rules_res["rules"], intel["summary"]
        sync_tree(self.rtree, [(r["id"], (r["id"], r["severity"], ",".join(r["mitre"]), r["source"], r["title"]),
                                (f"sev_{r['severity']}",)) for r in rules])
        sync_tree(self.pbtree, [(p["id"], (p["prio"], p["id"], p["max_mode"], " > ".join(p["steps"]), p["name"]), ())
                                for p in pbs_res["playbooks"]])
        bt = summary["by_type"]
        self.ioc_summary.set(f"{summary['total']} indicators loaded  -  IPs {bt['ip']}, CIDRs {bt['cidr']}, domains "
                             f"{bt['domain']}, hashes {bt['sha256'] + bt['sha1'] + bt['md5']}, tool names "
                             f"{bt['filename']}\nSources: " + ", ".join(f"{k} ({v})" for k, v in summary["sources"].items())
                             + f"\n{len(rules)} detection rules  -  YARA {'enabled' if intel['yara'] else 'not available'}")
        sync_tree(self.ftree, [(f["name"], (f["name"], f["type"], f["count"], ts(f["updated"], "%Y-%m-%d %H:%M"),
                                            f["url"]), ()) for f in intel["feeds"]])

    def _api_error(self, title: str, exc: Exception) -> None:
        msg = getattr(exc, "message", None) or str(exc)
        messagebox.showerror(title, msg, parent=self)
        self.flash(f"{title}: {msg}")

    def update_feeds(self) -> None:
        self.flash("updating threat-intel feeds ...")
        api = self.app.api

        def work():
            return api.call("intel.update")

        def done(res):
            if isinstance(res, Exception):
                self._api_error("Feed update", res)
                return
            msg = "\n".join(f"{r['name']}: " + (f"OK, {r['count']} indicators" if r["ok"] else f"FAILED - {r.get('error')}")
                            for r in res)
            messagebox.showinfo("Feed update", msg or "no feeds configured", parent=self)
            self.load_static()
        self.app.run_bg(work, done)

    def add_ioc(self) -> None:
        from eldoctor.api.client import ApiError
        value = self.ioc_value.get().strip()
        try:
            res = self.call("intel.add", type=self.ioc_type.get(), value=value, severity=self.ioc_sev.get(),
                            description="added in GUI")
        except ApiError as exc:
            self._api_error("Invalid indicator" if exc.code == "bad_request" else "Indicator", exc)
            return
        self.flash(f"indicator {value} added" + (" (active now)" if res["live"] else ""))
        self.ioc_value.set("")
        self.load_static()

    # -------------------------------------------------------------- blocks & quarantine
    def _tab_blocks(self, tab) -> None:
        row = ttk.Frame(tab)
        row.pack(fill="x")
        ttk.Label(row, text="Blocked IP addresses", style="Muted.TLabel").pack(side="left")
        b = ttk.Button(row, text="Unblock selected", command=self.unblock)
        b.pack(side="right")
        if not self.can("unblock"):
            b.state(["disabled"])
        self.btree = self.tree(tab, [("ip", "IP", 160, "w"), ("backend", "Enforced by", 120, "w"),
                                     ("since", "Since", 140, "w"), ("until", "Until", 140, "w"),
                                     ("reason", "Reason", 600, "w")], height=10)
        row2 = ttk.Frame(tab)
        row2.pack(fill="x", pady=(14, 0))
        ttk.Label(row2, text="Quarantine vault (files are stored read-only, not executable)",
                  style="Muted.TLabel").pack(side="left")
        b2 = ttk.Button(row2, text="Restore selected", command=self.restore)
        b2.pack(side="right")
        ttk.Button(row2, text="Open vault folder",
                   command=lambda: open_path(str(Path(self.app.info.get("data_dir", ".")) / "quarantine"))).pack(
            side="right", padx=6)
        if not self.can("restore"):
            b2.state(["disabled"])
        self.qtree = self.tree(tab, [("id", "ID", 100, "w"), ("time", "Time", 140, "w"), ("path", "Original path", 380, "w"),
                                     ("sha", "SHA-256", 480, "w"), ("size", "Size", 80, "e"), ("rest", "Restored", 70, "w")],
                               height=10)

    def unblock(self) -> None:
        sel = self.btree.selection()
        if not sel:
            return
        from eldoctor.api.client import ApiError
        try:
            res = self.call("blocks.unblock", ip=sel[0])
        except ApiError as exc:
            self._api_error("Unblock", exc)
            return
        self.flash(f"unblock {sel[0]}: {res['status']} - {res['message']}")
        self.refresh(force=True)

    def restore(self) -> None:
        sel = self.qtree.selection()
        if not sel or not messagebox.askyesno("Restore", "Put this file back at its original location?\n"
                                                         "Only do this for confirmed false positives.", parent=self):
            return
        from eldoctor.api.client import ApiError
        try:
            res = self.call("quarantine.restore", id=sel[0])
        except ApiError as exc:
            self._api_error("Restore", exc)
            return
        (messagebox.showinfo if res["status"] == "success" else messagebox.showwarning)("Restore", res["message"],
                                                                                       parent=self)
        self.refresh(force=True)

    # -------------------------------------------------------------- deploy
    def _tab_deploy(self, tab) -> None:
        from eldoctor.auth.users import DEPLOY_TARGETS
        from eldoctor.deploy.generator import default_mode
        allowed = self.can("deploy")
        left = ttk.Frame(tab, style="Card.TFrame", padding=14)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="WHERE DO YOU WANT TO RUN EL DOCTOR?", style="CardMuted.TLabel").pack(anchor="w")
        self.dep_target = tk.StringVar(value=self.user.deployment_target or "linux")
        for key, desc in DEPLOY_TARGETS.items():
            ttk.Radiobutton(left, text=f"{key:<11} {desc}", value=key, variable=self.dep_target,
                            command=lambda: (self.dep_mode.set(default_mode(self.dep_target.get())),
                                             self.dep_out.set(str(Path.home() / f"eldoctor-deploy-{self.dep_target.get()}")))
                            ).pack(anchor="w", pady=2)
        ttk.Label(left, text="Response mode", style="CardMuted.TLabel").pack(anchor="w", pady=(12, 0))
        self.dep_mode = tk.StringVar(value=default_mode(self.dep_target.get()))
        ttk.Combobox(left, textvariable=self.dep_mode, values=MODES, state="readonly", width=14).pack(anchor="w")
        ttk.Label(left, text="Output folder", style="CardMuted.TLabel").pack(anchor="w", pady=(12, 0))
        self.dep_out = tk.StringVar(value=str(Path.home() / f"eldoctor-deploy-{self.dep_target.get()}"))
        r = ttk.Frame(left, style="Card.TFrame")
        r.pack(anchor="w", fill="x")
        ttk.Entry(r, textvariable=self.dep_out, width=42).pack(side="left")
        ttk.Button(r, text="...", width=3, command=lambda: self.dep_out.set(
            filedialog.askdirectory(parent=self) or self.dep_out.get())).pack(side="left", padx=4)
        ttk.Label(left, text="Container image (Docker / Kubernetes)", style="CardMuted.TLabel").pack(anchor="w",
                                                                                                   pady=(12, 0))
        self.dep_image = tk.StringVar(value="eldoctor:latest")
        ttk.Entry(left, textvariable=self.dep_image, width=42).pack(anchor="w")
        ttk.Label(left, text="Package URL (cloud VMs download El Doctor from here)", style="CardMuted.TLabel").pack(
            anchor="w", pady=(12, 0))
        self.dep_url = tk.StringVar()
        ttk.Entry(left, textvariable=self.dep_url, width=42).pack(anchor="w")
        b = ttk.Button(left, text="Generate deployment bundle", style="Accent.TButton", command=self.generate)
        b.pack(anchor="w", pady=(16, 0))
        ob = ttk.Button(left, text="Open output folder", command=lambda: open_path(self.dep_out.get()))
        ob.pack(anchor="w", pady=(6, 0))
        if not allowed:
            b.state(["disabled"])
            ttk.Label(left, text="Generating deployments requires the admin role.", style="CardMuted.TLabel").pack(
                anchor="w", pady=6)
        right = ttk.Frame(tab)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.dep_text = tk.Text(right, bg=C["panel"], fg=C["fg"], insertbackground=C["fg"], relief="flat", font=self.app.f_mono, wrap="word",
                                padx=10, pady=8)
        self.dep_text.pack(fill="both", expand=True)
        self.dep_text.insert("end", "Choose a target and press 'Generate deployment bundle'.\n\n"
                                    "Every bundle contains a tuned config.yaml, the El Doctor package and a README with "
                                    "step-by-step instructions (Windows installer, systemd service, Docker compose, "
                                    "Kubernetes DaemonSet, cloud-init / startup scripts).")

    def generate(self) -> None:
        from eldoctor.deploy.generator import generate
        # read every widget value here, on the Tk thread - Tk must never be touched from the worker thread
        target, mode, out = self.dep_target.get(), self.dep_mode.get(), Path(self.dep_out.get()).expanduser()
        image, url = self.dep_image.get() or "eldoctor:latest", self.dep_url.get()
        api = self.app.api

        def work():
            # the agent authorises (deploy = admin) and audits; the files are written by this GUI, as this OS
            # user, into this user's folder - the service account never writes to client-chosen paths
            profile = api.call("deploy.record", target=target, mode=mode, out=str(out))["profile"]
            return generate(target, out, profile, mode=mode, image=image, package_url=url)

        def done(files):
            if isinstance(files, Exception):
                self._api_error("Deploy", files)
                return
            t = self.dep_text
            t.delete("1.0", "end")
            t.insert("end", f"Generated {len(files)} files in {out}:\n")
            for f in files:
                t.insert("end", f"  {f.relative_to(out)}\n")
            t.insert("end", "\n" + (out / "README-DEPLOY.md").read_text(encoding="utf-8"))
            self.flash(f"{target} bundle written to {out}")
        self.app.run_bg(work, done)

    # -------------------------------------------------------------- users & settings
    def _tab_users(self, tab) -> None:
        from eldoctor.auth.users import ROLES
        admin = self.can("manage_users")
        row = ttk.Frame(tab)
        row.pack(fill="x")
        ttk.Label(row, text="Registered users", style="Muted.TLabel").pack(side="left")
        self.role_var = tk.StringVar(value="analyst")
        if admin:
            ttk.Button(row, text="Disable", command=lambda: self.user_active(False)).pack(side="right", padx=2)
            ttk.Button(row, text="Enable", command=lambda: self.user_active(True)).pack(side="right", padx=2)
            ttk.Button(row, text="Set role", command=self.set_role).pack(side="right", padx=2)
            ttk.Combobox(row, textvariable=self.role_var, values=ROLES, state="readonly", width=10).pack(side="right",
                                                                                                       padx=4)
        self.utree = self.tree(tab, [("user", "Username", 120, "w"), ("role", "Role", 80, "w"), ("email", "E-mail", 200, "w"),
                                     ("org", "Organization", 150, "w"), ("use", "Use case", 90, "w"),
                                     ("target", "Deploy target", 100, "w"), ("created", "Registered", 140, "w"),
                                     ("last", "Last login", 140, "w"), ("active", "Active", 60, "w")], height=6)
        lower = ttk.Frame(tab)
        lower.pack(fill="both", expand=True, pady=(12, 0))
        s = ttk.Frame(lower, style="Card.TFrame", padding=12)
        s.pack(side="left", fill="y")
        ttk.Label(s, text="SETTINGS", style="CardMuted.TLabel").pack(anchor="w")
        info = self.app.info or {}                      # reported by the agent (agent.info)
        ttk.Label(s, text="Notification channels: " + (", ".join(info.get("channels") or []) or "none"),
                  style="Card.TLabel", wraplength=380).pack(anchor="w", pady=4)
        ttk.Label(s, text=f"Agent: {info.get('role', '?')} at {info.get('endpoint', '?')}", style="Card.TLabel",
                  wraplength=380).pack(anchor="w")
        ttk.Label(s, text=f"Data folder (agent only): {info.get('data_dir', '?')}", style="Card.TLabel",
                  wraplength=380).pack(anchor="w")
        ttk.Label(s, text=f"Config file: {info.get('config_path', '?')}", style="Card.TLabel", wraplength=380).pack(
            anchor="w", pady=(0, 4))
        ttk.Label(s, text="Privileged agent (admin/root): " + ("yes" if info.get("privileged") else
                                                               "no - some actions may be denied"),
                  style="Card.TLabel").pack(anchor="w")
        fwd = info.get("audit_forwarding") or []
        ttk.Label(s, text="Audit trail forwarded to: " + (", ".join(f["destination"] for f in fwd) or "nothing"),
                  style="Card.TLabel", wraplength=380).pack(anchor="w", pady=(4, 0))
        b = ttk.Button(s, text="Send test notification", command=self.test_notify)
        b.pack(anchor="w", pady=(10, 2))
        if not self.can("notify_test"):
            b.state(["disabled"])
        ttk.Button(s, text="Open data folder", command=lambda: open_path(str(info.get("data_dir", ".")))).pack(
            anchor="w", pady=2)
        ttk.Label(s, text="APPEARANCE", style="CardMuted.TLabel").pack(anchor="w", pady=(14, 2))
        self.theme_var = tk.StringVar(value=self.app.theme_pref)
        for value, label in (("system", f"Follow the system (now {detect_system_theme()})"),
                             ("light", "Light"), ("dark", "Dark")):
            ttk.Radiobutton(s, text=label, value=value, variable=self.theme_var,
                            command=lambda: self.app.set_theme(self.theme_var.get())).pack(anchor="w")
        ttk.Label(s, text="Shortcut: Ctrl+T toggles light / dark", style="CardMuted.TLabel").pack(anchor="w",
                                                                                                pady=(2, 0))
        ttk.Button(s, text="Create config file", command=self.init_config).pack(anchor="w", pady=2)
        a = ttk.Frame(lower)
        a.pack(side="left", fill="both", expand=True, padx=(10, 0))
        ttk.Label(a, text="Audit trail - hash-chained, verified by the agent" if self.can("audit")
                  else "Audit trail (admins only)", style="Muted.TLabel").pack(anchor="w")
        self.audtree = self.tree(a, [("time", "Time", 140, "w"), ("actor", "Actor", 110, "w"),
                                     ("os", "OS user / via", 130, "w"), ("event", "Event", 160, "w"),
                                     ("details", "Details", 600, "w")], height=12)

    def set_role(self) -> None:
        from eldoctor.api.client import ApiError
        sel = self.utree.selection()
        if not sel:
            return
        try:
            self.call("users.set_role", username=sel[0], role=self.role_var.get())
            self.flash(f"{sel[0]} is now {self.role_var.get()} (their sessions were revoked)")
        except ApiError as exc:
            messagebox.showerror("Role", exc.message, parent=self)
        self.refresh(force=True)

    def user_active(self, active: bool) -> None:
        from eldoctor.api.client import ApiError
        sel = self.utree.selection()
        if not sel:
            return
        try:
            self.call("users.set_active", username=sel[0], active=active)
        except ApiError as exc:
            messagebox.showerror("User", exc.message, parent=self)
        self.refresh(force=True)

    def test_notify(self) -> None:
        api = self.app.api

        def work():
            return api.call("notify.test")

        def done(res):
            if isinstance(res, Exception):
                self._api_error("Notifications", res)
                return
            lines = [f"{c['name']}: {'sent' if c['sent'] else 'FAILED'}" for c in res["channels"]]
            messagebox.showinfo("Notifications", "\n".join(lines + list(res["errors"])) or "no channels configured",
                                parent=self)
        self.app.run_bg(work, done)

    def init_config(self) -> None:
        from eldoctor.config import write_default_config
        try:
            p = write_default_config()
        except OSError as exc:
            messagebox.showerror("Config", f"Cannot write the configuration file ({exc}).\nIn a service "
                                           "installation the configuration belongs to the service account - edit it "
                                           "as an administrator.", parent=self)
            return
        messagebox.showinfo("Config", f"Configuration file:\n{p}\n\nEdit it (notifications, thresholds, allow-lists) "
                                      "and restart El Doctor.", parent=self)
        open_path(str(p))

    # -------------------------------------------------------------- refresh loop
    def refresh(self, force: bool = False) -> None:
        if not self._alive:
            return
        self._refreshes = getattr(self, "_refreshes", 0) + 1
        try:
            self._refresh_header()
            self._refresh_metrics()
            self._check_new_alerts()
            current = self.TABS[self.nb.index(self.nb.select())]     # by position: titles carry live counters
            fn = {"Dashboard": self._refresh_dashboard, "Processes": self._refresh_processes,
                  "Alerts": self._refresh_alerts, "Response log": self._refresh_actions,
                  "Approvals": self._refresh_approvals, "Blocks & quarantine": self._refresh_blocks,
                  "Users & settings": self._refresh_users}.get(current)
            if fn:
                fn()
            self._refresh_approval_badge()
        except tk.TclError:
            return
        except Exception as exc:
            self.flash(f"refresh error: {exc}")
        if not force:
            self.after(1000, self.refresh)

    def _refresh_header(self) -> None:
        agent = self.app.agent
        st = agent.status()
        mode = st["mode"]
        if self.mode_var.get() != mode and mode in MODES:
            self.mode_var.set(mode)
        running = bool(st.get("running"))
        if not running:
            badge = "VIEW ONLY"
        elif self.app.attached_pid:
            badge = f"SERVICE: {mode.upper()}"
        else:
            badge = mode.upper()
        self.mode_badge.configure(text=f" {badge}{' DRY-RUN' if st['dry_run'] else ''} ",
                                  bg=MODE_COLOR.get(mode, C["muted"]), fg=text_on(MODE_COLOR.get(mode, C["muted"])))
        self.mode_box.configure(state="readonly" if running and self.can("run") else "disabled")
        err = getattr(agent, "error", "")
        if err:
            self.hdr_info.set(f"agent error: {err}")
        elif not running or self.app.attached_pid:
            self.hdr_info.set(getattr(agent, "reason", ""))
        else:
            self.hdr_info.set(f"{'CIRCUIT BREAKER OPEN  |  ' if st['breaker'] else ''}agent {st['own_cpu']:.0f}% CPU "
                              f"{st['own_mem_mb']:.0f} MB  |  up {int(st['uptime'] // 60)}m{int(st['uptime'] % 60):02d}s")
        who = "service" if self.app.attached_pid else "agent"
        self.status_right.set(f"{who} log sources: {', '.join(st['log_sources']) or 'process & network telemetry'}  |  "
                              f"{st['sigma_rules']} Sigma rules, {st['iocs']} IOCs, {st['playbooks']} playbooks"
                              + (f"  |  cycle {st['tick_ms']:.0f} ms" if running else ""))

    def _refresh_metrics(self) -> None:
        m = self.app.agent.latest_metrics or {}
        if not m:
            return
        if m.get("timestamp") != self._last_metrics_ts:
            self._last_metrics_ts = m.get("timestamp")
            self.hist_cpu.append(m["cpu_usage"])
            self.hist_mem.append(m["memory_percent"])

        def setc(card, value, text, sub):
            _, v, s, bar = card
            v.set(text)
            s.set(sub)
            bar["value"] = value
            bar.configure(style=("Red" if value >= 90 else "Yellow" if value >= 70 else "Green")
                          + ".Horizontal.TProgressbar")
        setc(self.c_cpu, m["cpu_usage"], f"{m['cpu_usage']:.1f}%", f"load {m['load'][0]:.2f}  |  {m['process_count']} processes")
        setc(self.c_mem, m["memory_percent"], f"{m['memory_percent']:.1f}%",
             f"{m['used_memory'] / 1024:.1f} of {m['total_memory'] / 1024:.1f} GB")
        setc(self.c_disk, m["disk_percent"], f"{m['disk_percent']:.1f}%",
             f"{m['used_disk']:.0f} of {m['total_disk']:.0f} GB")
        _, v, s, bar = self.c_net
        v.set(rate(m["rx_rate"] + m["tx_rate"]))
        s.set(f"in {rate(m['rx_rate'])}  |  out {rate(m['tx_rate'])}")
        bar.configure(style="Blue.Horizontal.TProgressbar")
        bar["value"] = min(100, (m["rx_rate"] + m["tx_rate"]) / 1048576 * 10)

    def _check_new_alerts(self) -> None:
        rows = self.call("alerts.list", after=self.last_alert_ts, limit=200, include_actions=True)
        if not rows:
            return
        self.last_alert_ts = max(r["timestamp"] for r in rows)
        top = max(rows, key=lambda r: severity_rank(r["severity"]))
        if severity_rank(top["severity"]) >= severity_rank("high"):
            p = top.get("process") or {}
            who = f"{p.get('name')}[{p.get('pid')}]" if p.get("pid") else (top.get("remote_ip") or "")
            done = ", ".join(f"{a['action']} {a['status']}" for a in top.get("_actions", [])
                             if a["action"] != "collect_forensics")
            more = f"  (+{len(rows) - 1} more)" if len(rows) > 1 else ""
            self.show_banner(f"{top['severity'].upper()}: {top['title']}  -  {who}  [{','.join(top.get('mitre', []))}]"
                             + (f"  ->  {done}" if done else "") + more,
                             C["crit"] if top["severity"] == "critical" else C["banner_high"])

    def _alert_rows(self, limit: int = 500, include_actions: bool = False) -> List[Dict[str, Any]]:
        return self.call("alerts.list", limit=limit, include_actions=include_actions)

    def _refresh_dashboard(self) -> None:
        self.draw_chart()
        st = self.call("stats.dashboard")
        counts = st["severity_24h"]
        for sev, v in self.sev_labels.items():
            v.set(str(counts.get(sev, 0)))
        self.posture.set(f"Containment actions: {st['containment_24h']}\nPending approvals: {st['pending_approvals']}\n"
                         f"Blocked IPs: {st['blocked_ips']}\nQuarantined files: {st['quarantined']}")
        rows = []
        for a in self._alert_rows(8, include_actions=True):
            p = a.get("process") or {}
            resp = ", ".join(f"{x['action']}:{x['status']}" for x in a.get("_actions", [])
                             if x["action"] != "collect_forensics")
            rows.append((a["id"], (ts(a["timestamp"]), a["severity"], a["title"],
                                   f"{p.get('name')}[{p.get('pid')}]" if p else a.get("remote_ip", ""),
                                   ",".join(a.get("mitre", [])), resp or "-"), (f"sev_{a['severity']}",)))
        sync_tree(self.dash_alerts, rows)

    def _refresh_processes(self) -> None:
        with self.app.agent.lock:
            procs = list(self.app.agent.latest_procs)
        f = self.proc_filter.get().strip().lower()
        if f:
            procs = [p for p in procs if f in p.name.lower() or f in p.cmdline_str.lower() or f == str(p.pid)
                     or f in p.username.lower()]
        key = {"pid": lambda p: p.pid, "user": lambda p: p.username, "cpu": lambda p: p.cpu_percent,
               "mem": lambda p: p.memory_percent, "rss": lambda p: p.rss, "thr": lambda p: p.num_threads,
               "name": lambda p: p.name.lower(), "cmd": lambda p: p.cmdline_str}[self.proc_sort[0]]
        procs.sort(key=key, reverse=self.proc_sort[1])
        self.proc_count.set(f"{len(procs)} processes  |  sorted by {self.proc_sort[0]}")
        sync_tree(self.ptree, [(p.pid, (p.pid, p.username[:18], f"{p.cpu_percent:.1f}", f"{p.memory_percent:.1f}",
                                        f"{p.rss / 1048576:.0f}", p.num_threads, p.name,
                                        " ".join(p.cmdline_str.split())[:400]),
                                ("hot",) if p.cpu_percent >= 80 else ("warm",) if p.cpu_percent >= 40 else ())
                               for p in procs])

    def _refresh_alerts(self) -> None:
        minsev = self.alert_filter.get()
        s = self.search.get().strip().lower()
        rows = []
        self._alerts_cache = {}
        for a in self._alert_rows(500):
            if minsev != "all" and severity_rank(a["severity"]) < severity_rank(minsev):
                continue
            p = a.get("process") or {}
            text = json.dumps(a, default=str).lower() if s else ""
            if s and s not in text:
                continue
            self._alerts_cache[a["id"]] = a
            rows.append((a["id"], (ts(a["timestamp"], "%m-%d %H:%M:%S"), a["severity"], a["rule_id"][:22], a["title"],
                                   f"{p.get('name')}[{p.get('pid')}]" if p else "", a.get("remote_ip", ""),
                                   ",".join(a.get("mitre", [])), a["source"]), (f"sev_{a['severity']}",)))
        sync_tree(self.atree, rows)

    def _refresh_actions(self) -> None:
        rows = [(x["id"], (ts(x["ts"], "%m-%d %H:%M:%S"), x["playbook_id"], x["action"], x["status"], x["target"],
                           x["mode"], x["actor"], x["message"]), (f"st_{x['status']}",))
                for x in self.call("actions.list", limit=400)]
        sync_tree(self.xtree, rows)

    def _refresh_approvals(self) -> None:
        now = time.time()
        pend = self.call("approvals.list", status="pending")
        self._fresh_pending = len(pend)                  # keep the tab badge consistent with this table
        sync_tree(self.aptree, [(a["id"], (a["id"], ts(a["ts"]), f"{max(0, int(a['expires'] - now))} s", a["summary"]),
                                 ("st_pending_approval",)) for a in reversed(pend)])
        if pend and not self.aptree.selection():
            self.aptree.selection_set(self.aptree.get_children("")[0])
        hist = [a for a in self.call("approvals.list", limit=200) if a["status"] != "pending"]
        sync_tree(self.aphist, [(a["id"], (a["id"], ts(a["ts"], "%m-%d %H:%M:%S"), a["status"], a["decided_by"] or "",
                                           a["summary"]), (f"st_{a['status']}",)) for a in hist])

    def _refresh_approval_badge(self) -> None:
        fresh = getattr(self, "_fresh_pending", None)
        self._fresh_pending = None
        n = fresh if fresh is not None else len(self.app.agent.pending_approvals())
        idx = self.TABS.index("Approvals")
        self.nb.tab(idx, text=f"  Approvals ({n})  " if n else "  Approvals  ")
        self.pending_lbl.set(f"{n} pending" if n else "nothing waiting for you")
        self.app.root.title(f"El Doctor {__version__} - Security Console" + (f"  -  {n} approval(s) waiting" if n else ""))

    def _refresh_blocks(self) -> None:
        sync_tree(self.btree, [(b["ip"], (b["ip"], b["backend"], ts(b["ts"], "%m-%d %H:%M"), ts(b["expires"], "%m-%d %H:%M"),
                                          b["reason"]), ()) for b in self.call("blocks.list")])
        sync_tree(self.qtree, [(q["id"], (q["id"], ts(q["ts"], "%m-%d %H:%M"), q["original_path"], q["sha256"],
                                          q["size"], "yes" if q["restored"] else "no"), ())
                               for q in self.call("quarantine.list")])

    def _refresh_users(self) -> None:
        users = self.call("users.list")                # the agent returns only your own record unless you are admin
        sync_tree(self.utree, [(u["username"], (u["username"], u["role"], u["email"], u["organization"], u["use_case"],
                                                u["deployment_target"], ts(u["created_at"], "%Y-%m-%d %H:%M"),
                                                ts(u["last_login"], "%Y-%m-%d %H:%M"), "yes" if u["active"] else "no"), ())
                               for u in users])
        if self.can("audit"):
            sync_tree(self.audtree, [(a["id"], (ts(a["ts"], "%m-%d %H:%M:%S"), a["actor"],
                                                f"{a.get('os_user') or ''} {a.get('client') or ''}".strip(), a["event"],
                                                (a["details"] or "")[:300]), ())
                                     for a in self.call("audit.list", limit=200)])


# ----------------------------------------------------------------------------------------- entry points
def run_gui(cfg: Dict[str, Any], mode: Optional[str] = None, dry_run: bool = False,
            interval: Optional[float] = None, theme: Optional[str] = None) -> None:
    App(cfg, mode=mode, dry_run=dry_run, interval=interval, theme=theme).run()


def main(argv: Optional[List[str]] = None) -> int:
    from eldoctor.ui.launch import main as launch_main
    return launch_main(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
