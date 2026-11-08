"""Interactive curses console (successor of the original El Doctor screen).

Keys
  Up/Down  select process        k  kill selected        K  kill tree
  s        suspend selected      r  resume selected      n  renice (lowest priority)
  f        collect forensics     a  approve oldest pending request   d  deny it
  m        cycle response mode (monitor -> interactive -> enforce; enforce needs admin)
  p        pause/resume screen   h  help               q  quit

The console is a client of the agent API (``eldoctor.api.client.RemoteAgent``): what it shows comes
from the agent, and every key that acts (kill, approve, mode) is a request the *agent* authorises -
the console checks no permissions itself.
"""
from __future__ import annotations

import curses
import time
from typing import Optional

from eldoctor import __version__
from eldoctor.config import MODES
from eldoctor.models import HOSTNAME

SEV_PAIR = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
STATUS_PAIR = {"success": 6, "failed": 5, "blocked": 4, "pending_approval": 3, "would_run": 2, "dry_run": 2,
               "skipped": 1}
HELP = ("Up/Down select | k kill | K kill tree | s suspend | r resume | n renice | f forensics | "
        "a approve | d deny | m mode | p pause | q quit")


def _bar(pct: float, width: int = 20) -> str:
    filled = int(round(min(max(pct, 0), 100) / 100 * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _rate(b: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if b < 1024:
            return f"{b:6.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB/s"


class TUI:
    def __init__(self, agent, user, note: str = "") -> None:
        self.agent = agent
        self.user = user                      # dict from the agent (auth.whoami): display only
        self.sel = 0
        self.msg = note or "Welcome to El Doctor - press h for help"
        self.msg_ts = time.time()
        self.paused = False
        self.confirm: Optional[tuple] = None

    # ------------------------------------------------------------------ drawing helpers
    def put(self, scr, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = scr.getmaxyx()
        if y >= h - 1 or x >= w:
            return
        try:
            scr.addnstr(y, x, text, max(0, w - x - 1), attr)
        except curses.error:
            pass

    def section(self, scr, y: int, title: str) -> int:
        _, w = scr.getmaxyx()
        self.put(scr, y, 0, ("-- " + title + " ").ljust(w - 1, "-"), curses.A_BOLD | curses.color_pair(7))
        return y + 1

    def flash(self, text: str) -> None:
        self.msg, self.msg_ts = text, time.time()

    # ------------------------------------------------------------------ main loop
    def run(self, scr) -> None:
        curses.curs_set(0)
        scr.nodelay(True)
        scr.timeout(500)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for i, c in enumerate([curses.COLOR_WHITE, curses.COLOR_CYAN, curses.COLOR_YELLOW, curses.COLOR_MAGENTA,
                                   curses.COLOR_RED, curses.COLOR_GREEN, curses.COLOR_BLUE], start=1):
                curses.init_pair(i, c, -1)
        while True:
            if not self.paused:
                self.draw(scr)
            ch = scr.getch()
            if ch == -1:
                continue
            if not self.handle_key(ch):
                break

    def draw(self, scr) -> None:
        a = self.agent
        scr.erase()
        h, w = scr.getmaxyx()
        st = a.status()
        m = a.latest_metrics or {}
        with a.lock:
            procs = list(a.latest_procs)
        mode_attr = curses.color_pair({"monitor": 2, "interactive": 3, "enforce": 5}.get(st["mode"], 1)) | curses.A_BOLD
        who = f"{self.user.get('username')} ({self.user.get('role')})"
        self.put(scr, 0, 0, f" El Doctor {__version__} | {HOSTNAME} | {who} | mode: ", curses.A_REVERSE)
        x = len(f" El Doctor {__version__} | {HOSTNAME} | {who} | mode: ")
        mode_txt = (st["mode"].upper() if st.get("running", True) else "VIEW ONLY") + (" DRY-RUN" if st["dry_run"] else "")
        self.put(scr, 0, x, mode_txt, mode_attr | curses.A_REVERSE)
        x += len(mode_txt)
        breaker = "BREAKER OPEN" if st["breaker"] else "guards ok"
        self.put(scr, 0, x, f" | {breaker} | up {int(st['uptime'])}s | agent {st['own_cpu']:.0f}% cpu "
                            f"{st['own_mem_mb']:.0f}MB | h help ".ljust(w), curses.A_REVERSE)
        if m:
            mem_pct = m.get("memory_percent", 0)
            self.put(scr, 1, 0, f" CPU {_bar(m['cpu_usage'], 15)} {m['cpu_usage']:5.1f}%   "
                                f"MEM {_bar(mem_pct, 15)} {mem_pct:5.1f}% {m['used_memory'] / 1024:.1f}/"
                                f"{m['total_memory'] / 1024:.1f} GB   DISK {_bar(m['disk_percent'], 10)} "
                                f"{m['disk_percent']:5.1f}%")
            self.put(scr, 2, 0, f" NET in {_rate(m['rx_rate'])}  out {_rate(m['tx_rate'])}   processes "
                                f"{m['process_count']}   load {m['load'][0]:.2f}   rules: {st['sigma_rules']} sigma, "
                                f"{st['iocs']} IOCs, yara {'on' if st['yara'] else 'off'}, {st['playbooks']} playbooks")
        srcs = ", ".join(st["log_sources"]) or "none readable (process/network telemetry only)"
        srv = st.get("server") or {}
        where = f"agent pid {srv.get('pid')} ({srv.get('role')})" if srv else "agent"
        err = getattr(a, "error", "")
        self.put(scr, 3, 0, (f" {err}" if err else f" {where} | log sources: {srcs}")[: w - 1],
                 curses.color_pair(5 if err else 1))

        # --- processes
        avail = h - 5
        n_proc = max(5, min(12, avail // 3))
        n_alert = max(4, (avail - n_proc - 8) // 2)
        n_act = max(3, avail - n_proc - n_alert - 8)
        y = self.section(scr, 4, "Top processes (Up/Down select, k kill, s suspend, n renice, f forensics)")
        self.put(scr, y, 0, f" {'PID':>7} {'USER':<10} {'CPU%':>6} {'MEM%':>5}  {'NAME':<16} COMMAND", curses.A_BOLD)
        y += 1
        self.sel = max(0, min(self.sel, max(0, len(procs) - 1)))
        start = max(0, self.sel - n_proc + 1)
        for i, p in enumerate(procs[start:start + n_proc], start=start):
            attr = curses.A_REVERSE if i == self.sel else 0
            if p.cpu_percent >= 90:
                attr |= curses.color_pair(5)
            self.put(scr, y, 0, f" {p.pid:>7} {p.username[:10]:<10} {p.cpu_percent:6.1f} {p.memory_percent:5.1f}  "
                                f"{p.name[:16]:<16} {p.cmdline_str[:w]}", attr)
            y += 1
        # --- alerts
        y = self.section(scr, y, f"Live alerts ({len(a.recent_alerts)})")
        for al in list(a.recent_alerts)[:n_alert]:
            t = time.strftime("%H:%M:%S", time.localtime(al.timestamp))
            self.put(scr, y, 0, f" {t} {al.severity.upper():<8} {al.short()[len(al.severity) + 3:]}",
                     curses.color_pair(SEV_PAIR.get(al.severity, 1)))
            y += 1
        # --- actions
        y = self.section(scr, y, "Response actions")
        for act in list(a.recent_actions)[:n_act]:
            t = time.strftime("%H:%M:%S", time.localtime(act.get("timestamp", time.time())))
            self.put(scr, y, 0, f" {t} {act['action']:<17} {act['status']:<16} {act.get('message', '')} "
                                f"[{act.get('playbook', '')}]", curses.color_pair(STATUS_PAIR.get(act["status"], 1)))
            y += 1
        # --- approvals
        pend = a.pending_approvals()[:5]
        y = self.section(scr, y, f"Pending approvals ({len(pend)})  a = approve oldest, d = deny oldest")
        for ap in reversed(pend):
            left = int(ap["expires"] - time.time())
            self.put(scr, y, 0, f" [{ap['id']}] {ap['summary']}  (expires in {left}s)", curses.color_pair(3) | curses.A_BOLD)
            y += 1
        # --- status line
        if self.confirm:
            line = f" CONFIRM {self.confirm[0]} on {self.confirm[1].name}[{self.confirm[1].pid}]? (y/n) "
            self.put(scr, h - 1, 0, line.ljust(w - 1), curses.A_REVERSE | curses.color_pair(5))
        else:
            msg = self.msg if time.time() - self.msg_ts < 8 else HELP
            self.put(scr, h - 1, 0, (" " + msg).ljust(w - 1), curses.A_REVERSE)
        scr.refresh()

    # ------------------------------------------------------------------ keys
    def selected(self):
        with self.agent.lock:
            procs = list(self.agent.latest_procs)
        return procs[self.sel] if 0 <= self.sel < len(procs) else None

    def handle_key(self, ch: int) -> bool:
        if self.confirm:
            action, proc = self.confirm
            self.confirm = None
            if ch in (ord("y"), ord("Y")):
                res = self.agent.manual_action(action, proc, self.user)
                self.flash(f"{action}: {res.status} - {res.message}")
            else:
                self.flash("cancelled")
            return True
        if ch in (ord("q"), ord("Q")):
            return False
        if ch == curses.KEY_UP:
            self.sel = max(0, self.sel - 1)
        elif ch == curses.KEY_DOWN:
            self.sel += 1
        elif ch == ord("p"):
            self.paused = not self.paused
        elif ch == ord("h"):
            self.flash(HELP)
        elif ch in (ord("k"), ord("K"), ord("s"), ord("r"), ord("n"), ord("f")):
            proc = self.selected()
            if not proc:
                return True
            action = {ord("k"): "kill", ord("K"): "kill_tree", ord("s"): "suspend", ord("r"): "resume",
                      ord("n"): "renice", ord("f"): "forensics"}[ch]
            if action in ("kill", "kill_tree", "suspend"):
                self.confirm = (action, proc)
            else:
                res = self.agent.manual_action(action, proc, self.user)
                self.flash(f"{action}: {res.status} - {res.message}")
        elif ch in (ord("a"), ord("d")):
            pend = self.agent.pending_approvals()
            if not pend:
                self.flash("no pending approvals")
                return True
            oldest = pend[-1]
            ok, msg = self.agent.decide(oldest["id"], ch == ord("a"))      # the agent checks the approve role
            self.flash(msg if ok else f"not applied: {msg}")
            self.agent.refresh()
        elif ch == ord("m"):
            cur = self.agent.mode
            nxt = MODES[(MODES.index(cur) + 1) % len(MODES)] if cur in MODES else MODES[0]
            ok, msg = self.agent.set_mode(nxt)
            if not ok and nxt == "enforce":                # not allowed to enforce: wrap around to monitor
                ok, msg2 = self.agent.set_mode("monitor")
                msg = f"{msg} -> {msg2}" if ok else msg
            self.flash(msg)
        return True


def run_tui(agent, user, note: str = "") -> None:
    agent.refresh()
    agent.start_background()
    try:
        curses.wrapper(TUI(agent, user, note).run)
    finally:
        agent.stop()
