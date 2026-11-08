"""Safety guards for automated response.

Every destructive action (kill / suspend / quarantine / block_ip) passes
through SafetyGuard first.  Guards, in order:

 1. PID 0/1, kernel threads, El Doctor itself and its whole ancestor chain
    (so it never kills the terminal/service manager it runs under)
 2. protected process names (system daemons, Windows critical processes)
 3. protected users
 4. allow-lists (name / path / sha256 / ip)
 5. process identity check: pid + start time must still match the alert
    (defeats PID reuse races)
 6. quarantine path restrictions (never move files out of /usr, C:\\Windows ...)
 7. block-ip: never block loopback, private, link-local, cloud metadata, allow-listed
 8. circuit breaker: more than N destructive actions in a window trips the
    breaker and the agent drops to interactive mode (protects against a
    detection storm / bad rule wiping out the host)
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Set, Tuple

import psutil

import re

# Script interpreters / shells / LOLBins: the malicious artefact is the script they run, never the binary.
INTERPRETER_RX = re.compile(
    r"^(python|pythonw|python\d[\d.]*|pypy\d*|perl[\d.]*|ruby[\d.]*|node|nodejs|deno|bun|php[\d.-]*|java|javaw|"
    r"bash|sh|dash|zsh|ksh|csh|tcsh|fish|busybox|lua[\d.]*|tclsh[\d.]*|wish[\d.]*|osascript|"
    r"powershell|powershell_ise|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin)"
    r"(\.exe)?$", re.IGNORECASE)


def is_interpreter(path_or_name: str) -> bool:
    base = str(path_or_name or "").replace("\\", "/").rsplit("/", 1)[-1]
    return bool(INTERPRETER_RX.match(base))


DESTRUCTIVE = {"kill", "suspend", "quarantine", "block_ip"}      # need approval in interactive mode
MODIFYING = DESTRUCTIVE | {"renice", "resume"}                     # never executed in monitor mode


class SafetyGuard:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        sc = cfg.get("safety", {})
        self.protected_names: Set[str] = {n.lower() for n in sc.get("protected_names", [])}
        self.protected_users: Set[str] = {u.lower() for u in sc.get("protected_users", [])}
        al = sc.get("allowlist", {}) or {}
        self.allow_names = {n.lower() for n in al.get("names", []) or []}
        self.allow_paths = [p.lower() for p in al.get("paths", []) or []]
        self.allow_hashes = {h.lower() for h in al.get("hashes", []) or []}
        self.allow_ips = {i for i in al.get("ips", []) or []}
        self.never_nets = []
        for n in sc.get("never_block_networks", []) or []:
            try:
                self.never_nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        self.never_ips = set(sc.get("never_block_ips", []) or [])
        self.q_forbidden = [p.lower() for p in sc.get("quarantine_forbidden_paths", []) or []]
        self.max_actions = int(sc.get("max_actions_per_window", 10))
        self.window = float(sc.get("action_window", 60))
        self.breaker_cooldown = float(sc.get("breaker_cooldown", 600))
        self._recent: Deque[float] = deque()
        self.breaker_tripped_at: float = 0.0
        self._lock = threading.Lock()
        self.protected_pids = self._ancestors(os.getpid())
        # optional response scope: only act on processes started (directly or indirectly) by these PIDs.
        # Empty = whole host (production). Tests, CI and labs use it so they can never touch unrelated work.
        self.scope = {int(x) for x in sc.get("only_descendants_of", []) or []}

    @staticmethod
    def _ancestors(pid: int) -> Set[int]:
        pids = {0, 1, pid}
        try:
            p = psutil.Process(pid)
            for a in p.parents():
                pids.add(a.pid)
        except (psutil.Error, OSError):
            pass
        return pids

    def _in_scope(self, pid: int) -> bool:
        try:
            chain = {pid} | {p.pid for p in psutil.Process(pid).parents()}
        except (psutil.Error, OSError):
            return False
        return bool(chain & self.scope)

    # ------------------------------------------------------------------ breaker
    @property
    def breaker_open(self) -> bool:
        if self.breaker_tripped_at and time.time() - self.breaker_tripped_at > self.breaker_cooldown:
            self.breaker_tripped_at = 0.0
        return bool(self.breaker_tripped_at)

    def consume_action_budget(self) -> Tuple[bool, str]:
        with self._lock:
            now = time.time()
            while self._recent and now - self._recent[0] > self.window:
                self._recent.popleft()
            if self.breaker_open:
                return False, "circuit breaker open (too many automated actions) - approval required"
            if len(self._recent) >= self.max_actions:
                self.breaker_tripped_at = now
                return False, (f"circuit breaker tripped: {len(self._recent)} destructive actions in "
                               f"{int(self.window)}s - switching to approval mode")
            self._recent.append(now)
            return True, ""

    # ------------------------------------------------------------------ processes
    def check_process(self, proc: Dict[str, Any], action: str) -> Tuple[bool, str]:
        """Static checks on the alert's process record (no live lookup)."""
        if not proc:
            return False, "alert has no process entity"
        pid = int(proc.get("pid") or 0)
        name = str(proc.get("name") or "").lower()
        exe = str(proc.get("exe") or "").lower()
        user = str(proc.get("username") or "").lower()
        if pid in self.protected_pids:
            return False, f"pid {pid} is protected (init / El Doctor / its parent chain)"
        if self.scope and not self._in_scope(pid):
            return False, f"pid {pid} is outside the configured response scope (safety.only_descendants_of)"
        if pid == 2 or (not exe and not proc.get("cmdline") and proc.get("ppid") in (0, 2)):
            return False, f"pid {pid} looks like a kernel thread"
        if name in self.protected_names or (name.endswith(".exe") and name[:-4] in self.protected_names):
            # a protected *name* launched from a suspicious location is masquerading - still protected,
            # but say so explicitly so an analyst can decide manually.
            return False, f"'{name}' is a protected system process name"
        if user and (user in self.protected_users or user.split("\\")[-1] in self.protected_users):
            return False, f"processes of user '{user}' are protected"
        if name in self.allow_names:
            return False, f"'{name}' is allow-listed"
        if exe and any(exe.startswith(p) for p in self.allow_paths):
            return False, f"'{exe}' is in an allow-listed path"
        sha = str(proc.get("sha256") or "").lower()
        if sha and sha in self.allow_hashes:
            return False, "executable hash is allow-listed"
        if action == "quarantine":
            if not proc.get("exe"):
                return False, "no executable path to quarantine"
            ok, why = self.check_quarantine_path(str(proc.get("exe")))
            if not ok and not is_interpreter(str(proc.get("exe"))):
                return False, why
        return True, ""

    def check_quarantine_path(self, path: str) -> Tuple[bool, str]:
        """May this file be moved into the vault?  Never system paths, never interpreters/shells."""
        low = path.lower()
        norm = low.replace("/", "\\") if "\\" in low or ":" in low[:3] else low
        if any(norm.startswith(p) for p in self.q_forbidden):
            return False, f"refusing to quarantine system path {path}"
        if is_interpreter(path):
            return False, f"refusing to quarantine interpreter/shell {path} (the script is the threat, not the interpreter)"
        return True, ""

    def live_process(self, proc: Dict[str, Any]) -> Tuple[Optional[psutil.Process], str]:
        """Resolve the live process and make sure it is still the one from the alert."""
        pid = int(proc.get("pid") or 0)
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None, f"process {pid} no longer exists"
        except (psutil.Error, OSError) as exc:
            return None, f"cannot access process {pid}: {exc}"
        ct = float(proc.get("create_time") or 0)
        try:
            live_ct = p.create_time()
        except (psutil.Error, OSError):
            live_ct = 0.0
        if ct and abs(live_ct - ct) > 0.05:
            return None, f"pid {pid} was reused by another process (start time changed) - refusing"
        if not ct:
            try:
                if proc.get("name") and p.name().lower() != str(proc["name"]).lower():
                    return None, f"pid {pid} now belongs to '{p.name()}' - refusing"
            except (psutil.Error, OSError):
                pass
        return p, ""

    # ------------------------------------------------------------------ ips
    def check_ip(self, ip: str) -> Tuple[bool, str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"'{ip}' is not a valid IP address"
        if ip in self.never_ips or ip in self.allow_ips:
            return False, f"{ip} is allow-listed / protected (e.g. cloud metadata service)"
        for net in self.never_nets:
            if addr.version == net.version and addr in net:
                return False, f"{ip} is in protected network {net} (loopback/private/link-local)"
        if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return False, f"{ip} is not a routable unicast address"
        return True, ""

    def status(self) -> Dict[str, Any]:
        return {"breaker_open": self.breaker_open, "recent_actions": len(self._recent),
                "max_actions": self.max_actions, "window": self.window,
                "protected_pids": sorted(self.protected_pids)}
