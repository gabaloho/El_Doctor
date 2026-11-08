"""Detection engine.

Behavioural analytics that Sigma cannot express (sustained resource abuse,
fork storms, deleted binaries, shells holding sockets, masquerading ...) live
here as Python heuristics; command-line *content* detections live in Sigma
rules; threat-intel matching uses the IOC store; YARA scans suspicious
binaries.  Every alert carries MITRE ATT&CK technique IDs.
"""
from __future__ import annotations

import ipaddress
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from eldoctor.config import PLATFORM, package_data
from eldoctor.detection import sigma as sg
from eldoctor.detection.ioc import IOCStore
from eldoctor.detection.yara_scan import YaraScanner
from eldoctor.models import Alert, ProcessInfo

# Catalogue of built-in rules: id -> (title, severity, mitre, description)
RULES: Dict[str, Tuple[str, str, List[str], str]] = {
    "ED-RES-001": ("Sustained high CPU usage by process", "high", ["T1496"],
                   "A single process kept CPU above the threshold for the configured duration "
                   "(resource hijacking / cryptojacking / runaway process)."),
    "ED-RES-002": ("Sustained high memory usage by process", "high", ["T1499"],
                   "A single process held more RAM than allowed for the configured duration."),
    "ED-RES-003": ("Process spawn storm (fork bomb)", "critical", ["T1499"],
                   "One parent created an abnormal number of child processes in a short window."),
    "ED-SYS-001": ("System CPU above critical threshold", "medium", ["T1499"], "Whole-host CPU usage is critical."),
    "ED-SYS-002": ("System memory above critical threshold", "medium", ["T1499"], "Whole-host memory usage is critical."),
    "ED-SYS-003": ("Disk usage above critical threshold", "medium", [], "Root filesystem is almost full."),
    "ED-PROC-001": ("Executable running from temporary / world-writable directory", "medium",
                    ["T1204.002", "T1036.005"], "Binaries executed from /tmp, /dev/shm, %TEMP% ... are typical of droppers."),
    "ED-PROC-002": ("Process running from a deleted executable", "high", ["T1070.004"],
                    "The binary was removed from disk after launch - common anti-forensics for malware."),
    "ED-PROC-003": ("Process masquerading as kernel thread or system daemon", "high", ["T1036.004", "T1036.005"],
                    "Userland process disguised with a kernel-thread style name or a system daemon name "
                    "from an unexpected location."),
    "ED-PROC-005": ("Fileless execution from memory (memfd)", "high", ["T1620", "T1027"],
                    "The process image is an anonymous memfd_create() file - code executed without touching disk."),
    "ED-PROC-004": ("Web server spawned a shell", "high", ["T1505.003", "T1059.004"],
                    "A web server / application server process started a command shell (web shell / RCE)."),
    "ED-NET-001": ("Shell process holding a network connection (reverse shell)", "critical", ["T1059.004", "T1095"],
                   "A command interpreter owns an established TCP connection."),
    "ED-NET-002": ("Connection to port associated with miners / C2", "medium", ["T1571"],
                   "Outbound connection to a non-standard port frequently used by mining pools and C2 frameworks."),
    "ED-NET-003": ("Connection to an IP blocked by El Doctor", "high", ["T1071"],
                   "A process talks to an address previously blocked by a response playbook."),
    "ED-IOC-001": ("Executable hash matches threat intelligence", "critical", ["T1588.001", "T1204.002"],
                   "SHA-256 of the running binary is a known-malicious sample."),
    "ED-IOC-002": ("Connection to malicious IP (threat intelligence)", "critical", ["T1071"],
                   "Remote address is listed in a threat-intel feed."),
    "ED-IOC-003": ("Process name matches known malicious tool", "high", ["T1588.001"],
                   "Process name matches a known miner / attack tool."),
    "ED-IOC-004": ("Command line references malicious domain", "high", ["T1105", "T1071"],
                   "A URL/host on the command line is in a threat-intel feed."),
    "ED-YARA-001": ("YARA rule matched running executable", "high", ["T1204.002"],
                    "The on-disk executable of a running process matched a YARA signature."),
    "ED-LOG-001": ("SSH / login brute force", "high", ["T1110.001"],
                   "Many failed authentications from one source in a short time window."),
    "ED-LOG-002": ("Successful login after brute force", "critical", ["T1110", "T1078"],
                   "A source that was brute forcing then logged in successfully."),
    "ED-LOG-003": ("Repeated sudo / su authentication failures", "medium", ["T1548.003"],
                   "Local privilege escalation attempts with wrong passwords."),
    "ED-LOG-004": ("Local user account created", "medium", ["T1136.001"], "A new local account appeared."),
    "ED-LOG-005": ("Windows logon brute force (4625)", "high", ["T1110.001"],
                   "Many failed Windows logons from one source."),
}


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


class DetectionEngine:
    def __init__(self, cfg: Dict[str, Any], iocs: Optional[IOCStore] = None, load_sigma: bool = True,
                 yara_scanner: Optional[YaraScanner] = None) -> None:
        self.cfg = cfg
        self.th = cfg.get("thresholds", {})
        self.dc = cfg.get("detection", {})
        self.platform = PLATFORM
        self.iocs = iocs if iocs is not None else IOCStore.from_config(cfg)
        self.yara = yara_scanner if yara_scanner is not None else YaraScanner(cfg)
        self.sigma_rules: List[sg.SigmaRule] = []
        self.sigma_errors: List[Tuple[str, str]] = []
        if load_sigma:
            dirs = [package_data("rules", "sigma")] + [Path(d).expanduser() for d in self.dc.get("sigma_dirs", []) or []]
            self.sigma_rules, self.sigma_errors = sg.load_rules(dirs)
        self.disabled: Set[str] = set(self.dc.get("disabled_rules", []) or [])
        self.cooldown = float(self.dc.get("alert_cooldown", 300))
        self.blocked_ips: Set[str] = set()
        self._last_fired: Dict[str, float] = {}
        self._cpu_since: Dict[str, float] = {}
        self._mem_since: Dict[str, float] = {}
        self._spawns: Dict[int, Deque[float]] = defaultdict(deque)
        self._seen_conns: Set[Tuple[Any, ...]] = set()
        self._auth_fail: Dict[str, Deque[float]] = defaultdict(deque)
        self._bruteforcers: Dict[str, float] = {}
        self._sudo_fail: Dict[str, Deque[float]] = defaultdict(deque)
        self._win_fail: Dict[str, Deque[float]] = defaultdict(deque)
        self.stats: Dict[str, int] = defaultdict(int)
        self.miner_names = {n.lower() for n in self.dc.get("miner_names", [])}
        self.shells = {s.lower() for s in self.dc.get("shells", [])}
        self.web_servers = {s.lower() for s in self.dc.get("web_servers", [])}
        key = "suspicious_paths_windows" if self.platform == "windows" else "suspicious_paths_linux"
        self.suspicious_paths = [p.lower() for p in self.dc.get(key, [])]

    # ------------------------------------------------------------------ helpers
    def _fire(self, out: List[Alert], rule_id: str, proc: Optional[ProcessInfo] = None, *, title: str = "",
              severity: str = "", mitre: Optional[List[str]] = None, source: str = "heuristic",
              remote_ip: str = "", evidence: Optional[Dict[str, Any]] = None, description: str = "",
              dedup_key: str = "", tags: Optional[List[str]] = None, now: Optional[float] = None) -> Optional[Alert]:
        if rule_id in self.disabled:
            return None
        base = RULES.get(rule_id, ("", "medium", [], ""))
        alert = Alert(rule_id=rule_id, title=title or base[0], severity=severity or base[1],
                      mitre=list(mitre if mitre is not None else base[2]), source=source,
                      description=description or base[3], process=proc.to_dict() if proc else None,
                      remote_ip=remote_ip, evidence=evidence or {}, tags=tags or [], dedup_key=dedup_key)
        now = now or time.time()
        last = self._last_fired.get(alert.dedup_key)
        if last is not None and now - last < self.cooldown:
            self.stats["suppressed"] += 1
            return None
        self._last_fired[alert.dedup_key] = now
        self.stats[rule_id] += 1
        out.append(alert)
        return alert

    def catalogue(self) -> List[Dict[str, Any]]:
        rows = [{"id": rid, "title": t, "severity": s, "mitre": m, "source": "heuristic/ioc"}
                for rid, (t, s, m, _) in RULES.items()]
        rows += [{"id": f"SIGMA:{r.id}", "title": r.title, "severity": r.severity, "mitre": r.mitre,
                  "source": f"sigma ({'/'.join(v for v in r.logsource.values())})"} for r in self.sigma_rules]
        return rows

    # ------------------------------------------------------------------ process start
    def on_process_start(self, proc: ProcessInfo, initial: bool = False) -> List[Alert]:
        out: List[Alert] = []
        name = proc.name.lower()
        exe_l = proc.exe.lower().replace("/", "\\") if self.platform == "windows" else proc.exe.lower()
        cmd = proc.cmdline_str

        # --- threat intel
        hit = self.iocs.match_hash(proc.sha256)
        if hit:
            self._fire(out, "ED-IOC-001", proc, severity=hit.severity, mitre=hit.mitre or None, source="ioc",
                       evidence={"sha256": proc.sha256, "indicator": hit.value, "feed": hit.source,
                                 "description": hit.description})
        fhit = self.iocs.match_filename(proc.name) or (self.iocs.match_filename(_basename(proc.exe)) if proc.exe else None)
        if not fhit and name in self.miner_names:
            self._fire(out, "ED-IOC-003", proc, severity="critical", mitre=["T1496"], source="ioc",
                       evidence={"matched": name, "list": "detection.miner_names"})
        elif fhit:
            self._fire(out, "ED-IOC-003", proc, severity=fhit.severity, mitre=fhit.mitre or None, source="ioc",
                       evidence={"matched": fhit.value, "feed": fhit.source, "description": fhit.description})
        dhit = self.iocs.match_domains_in(cmd)
        if dhit:
            self._fire(out, "ED-IOC-004", proc, severity=dhit.severity, mitre=dhit.mitre or None, source="ioc",
                       evidence={"domain": dhit.value, "feed": dhit.source, "description": dhit.description})

        # --- behavioural heuristics
        suspicious_location = bool(proc.exe) and any(p in exe_l for p in self.suspicious_paths)
        if suspicious_location:
            self._fire(out, "ED-PROC-001", proc, evidence={"exe": proc.exe})
        if proc.exe.startswith("/memfd:"):
            self._fire(out, "ED-PROC-005", proc, evidence={"exe": proc.exe, "technique": "memfd_create + execve"})
        elif proc.exe_deleted:
            self._fire(out, "ED-PROC-002", proc, evidence={"exe": proc.exe + " (deleted)"})
        if self.platform == "linux" and proc.exe:
            looks_kthread = cmd.startswith("[") and cmd.endswith("]")
            sys_names = {"sshd", "systemd", "cron", "crond", "init", "kthreadd", "rsyslogd", "dbus-daemon"}
            bad_loc = name in sys_names and not proc.exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib"))
            if looks_kthread or bad_loc:
                self._fire(out, "ED-PROC-003", proc, evidence={"cmdline": cmd, "exe": proc.exe,
                                                               "reason": "kernel-thread name" if looks_kthread
                                                               else "system daemon name from unusual path"})
        if name in self.shells and proc.parent_name.lower() in self.web_servers:
            self._fire(out, "ED-PROC-004", proc, evidence={"parent": proc.parent_name, "parent_exe": proc.parent_exe})

        # --- Sigma process_creation
        ev = sg.process_event(proc, self.platform)
        for rule in self.sigma_rules:
            if rule.applies_to(ev, self.platform) and rule.match(ev):
                self._fire(out, f"SIGMA:{rule.id}", proc, title=rule.title, severity=rule.severity,
                           mitre=rule.mitre, source="sigma", description=rule.description,
                           evidence={"rule_file": os.path.basename(rule.path), "cmdline": cmd,
                                     "falsepositives": rule.falsepositives})

        # --- YARA on suspicious binaries only (cheap)
        if self.yara.enabled and proc.exe and (self.yara.scan_all or suspicious_location or proc.exe_deleted or out):
            target = f"/proc/{proc.pid}/exe" if proc.exe_deleted else proc.exe
            for m in self.yara.scan_file(target):
                meta = m.get("meta", {})
                self._fire(out, "ED-YARA-001", proc, title=f"YARA match: {m['rule']}",
                           severity=str(meta.get("severity", "high")).lower(),
                           mitre=[x.strip() for x in str(meta.get("mitre", "T1204.002")).split(",") if x.strip()],
                           source="yara", evidence={"rule": m["rule"], "description": meta.get("description", ""),
                                                    "file": proc.exe}, dedup_key=f"ED-YARA-001|{proc.key}|{m['rule']}")
        return out

    # ------------------------------------------------------------------ resource sampling
    def on_process_sample(self, procs: List[ProcessInfo], new: Iterable[ProcessInfo] = (), now: Optional[float] = None,
                          initial: bool = False) -> List[Alert]:
        now = now or time.time()
        out: List[Alert] = []
        cpu_th = float(self.th.get("process_cpu", 90))
        cpu_dur = float(self.th.get("process_cpu_duration", 20))
        mem_th = float(self.th.get("process_memory", 25))
        mem_dur = float(self.th.get("process_memory_duration", 10))
        alive = set()
        for p in procs:
            alive.add(p.key)
            if p.cpu_percent >= cpu_th:
                since = self._cpu_since.setdefault(p.key, now)
                if now - since >= cpu_dur:
                    self._fire(out, "ED-RES-001", p, now=now, evidence={
                        "cpu_percent": round(p.cpu_percent, 1), "threshold": cpu_th,
                        "sustained_seconds": round(now - since, 1), "cores": os.cpu_count()})
            else:
                self._cpu_since.pop(p.key, None)
            if p.memory_percent >= mem_th:
                since = self._mem_since.setdefault(p.key, now)
                if now - since >= mem_dur:
                    self._fire(out, "ED-RES-002", p, now=now, evidence={
                        "memory_percent": round(p.memory_percent, 1), "rss_mb": round(p.rss / 1048576, 1),
                        "threshold": mem_th, "sustained_seconds": round(now - since, 1)})
            else:
                self._mem_since.pop(p.key, None)
        for d in (self._cpu_since, self._mem_since):
            for k in [k for k in d if k not in alive]:
                d.pop(k, None)

        # spawn storms (ignore the initial inventory)
        if not initial:
            window = float(self.th.get("spawn_storm_window", 30))
            limit = int(self.th.get("spawn_storm_children", 50))
            by_pid = {p.pid: p for p in procs}
            for p in new:
                dq = self._spawns[p.ppid]
                dq.append(now)
            for ppid, dq in list(self._spawns.items()):
                while dq and now - dq[0] > window:
                    dq.popleft()
                if not dq:
                    self._spawns.pop(ppid, None)
                    continue
                if len(dq) >= limit and ppid in by_pid and ppid > 1:
                    parent = by_pid[ppid]
                    live_children = sum(1 for p in procs if p.ppid == ppid)
                    self._fire(out, "ED-RES-003", parent, now=now, evidence={
                        "children_spawned": len(dq), "window_seconds": window, "live_children": live_children})
        return out

    # ------------------------------------------------------------------ system metrics
    def on_metrics(self, m: Dict[str, Any], procs: List[ProcessInfo]) -> List[Alert]:
        out: List[Alert] = []
        top_cpu = sorted(procs, key=lambda p: p.cpu_percent, reverse=True)[:3]
        top_mem = sorted(procs, key=lambda p: p.memory_percent, reverse=True)[:3]
        fmt = lambda ps, attr: [{"pid": p.pid, "name": p.name, attr: round(getattr(p, attr), 1)} for p in ps]
        if m["cpu_usage"] > float(self.th.get("system_cpu", 90)):
            self._fire(out, "ED-SYS-001", source="system", dedup_key="ED-SYS-001|host",
                       evidence={"cpu_usage": m["cpu_usage"], "top_processes": fmt(top_cpu, "cpu_percent")})
        if m["memory_percent"] > float(self.th.get("system_memory", 90)):
            self._fire(out, "ED-SYS-002", source="system", dedup_key="ED-SYS-002|host",
                       evidence={"memory_percent": m["memory_percent"], "top_processes": fmt(top_mem, "memory_percent")})
        if m["disk_percent"] > float(self.th.get("system_disk", 90)):
            self._fire(out, "ED-SYS-003", source="system", dedup_key="ED-SYS-003|host",
                       evidence={"disk_percent": m["disk_percent"], "used_gb": round(m["used_disk"], 1),
                                 "total_gb": round(m["total_disk"], 1)})
        return out

    # ------------------------------------------------------------------ network
    def on_connections(self, conns: List[Dict[str, Any]], procs_by_pid: Dict[int, ProcessInfo]) -> List[Alert]:
        out: List[Alert] = []
        ports = {int(p) for p in self.dc.get("suspicious_ports", [])}
        current = set()
        for c in conns:
            rip = c.get("rip")
            if not rip or c.get("status") == "LISTEN":
                continue
            pid = c.get("pid")
            proc = procs_by_pid.get(pid) if pid else None
            ident = (pid, proc.create_time if proc else 0, rip, c.get("rport"))
            current.add(ident)
            first_seen = ident not in self._seen_conns
            ev_common = {"remote": f"{rip}:{c.get('rport')}", "local": c.get("laddr"), "status": c.get("status"),
                         "pid": pid}
            hit = self.iocs.match_ip(rip)
            if hit:
                self._fire(out, "ED-IOC-002", proc, severity=hit.severity, mitre=hit.mitre or None, source="ioc",
                           remote_ip=rip, evidence={**ev_common, "feed": hit.source, "description": hit.description},
                           dedup_key=f"ED-IOC-002|{rip}|{pid}")
            if rip in self.blocked_ips:
                self._fire(out, "ED-NET-003", proc, remote_ip=rip, evidence=ev_common,
                           dedup_key=f"ED-NET-003|{rip}|{pid}")
            if proc and c.get("status") == "ESTABLISHED" and c.get("type") == "tcp":
                if proc.name.lower() in self.shells:
                    self._fire(out, "ED-NET-001", proc, remote_ip=rip, evidence=ev_common)
                if int(c.get("rport") or 0) in ports and not _is_loopback(rip):
                    self._fire(out, "ED-NET-002", proc, remote_ip=rip, evidence=ev_common,
                               dedup_key=f"ED-NET-002|{proc.key}|{rip}")
            if first_seen and proc:
                ev = sg.network_event(proc, c, self.platform)
                for rule in self.sigma_rules:
                    if rule.logsource.get("category") == "network_connection" and rule.applies_to(ev, self.platform) \
                            and rule.match(ev):
                        self._fire(out, f"SIGMA:{rule.id}", proc, title=rule.title, severity=rule.severity,
                                   mitre=rule.mitre, source="sigma", remote_ip=rip, description=rule.description,
                                   evidence=ev_common)
        self._seen_conns = current
        return out

    # ------------------------------------------------------------------ logs
    def _proc_from_event(self, ev: Dict[str, Any]) -> ProcessInfo:
        """ProcessInfo from an auditd / Sysmon / 4688 event, enriched from the live process when it still runs."""
        proc = ProcessInfo.from_dict(ev["process"])
        try:
            import psutil
            live = psutil.Process(proc.pid)
            if not proc.exe or live.exe() == proc.exe:
                proc.create_time = live.create_time()
                parent = live.parent()
                if parent:
                    proc.parent_name, proc.parent_exe = parent.name(), parent.exe()
                    proc.parent_cmdline = " ".join(parent.cmdline())
        except Exception:
            pass
        if proc.exe and self.dc.get("hash_executables", True):
            from eldoctor.collectors.processes import HashCache
            if not hasattr(self, "_hashes"):
                self._hashes = HashCache(int(self.dc.get("max_hash_mb", 100)))
            proc.sha256 = self._hashes.sha256(proc.exe)
        return proc

    def on_log(self, ev: Dict[str, Any], now: Optional[float] = None) -> List[Alert]:
        now = now or time.time()
        if ev.get("category") == "process_creation" and ev.get("process", {}).get("pid"):
            # kernel/OS exec telemetry (auditd, Sysmon EID 1, Security 4688): full process pipeline
            alerts = self.on_process_start(self._proc_from_event(ev))
            for a in alerts:
                a.evidence.setdefault("telemetry", ev.get("source"))
            return alerts
        out: List[Alert] = []
        et = ev.get("event_type", "")
        f = ev.get("fields") or {}
        bf = self.cfg.get("logs", {}).get("brute_force", {})
        threshold, window = int(bf.get("threshold", 5)), float(bf.get("window", 120))
        src = f.get("src_ip", "")
        log_ev = {"source": ev.get("source"), "program": ev.get("program"), "host": ev.get("host"),
                  "message": (ev.get("message") or "")[:500]}

        def bump(store: Dict[str, Deque[float]], key: str) -> int:
            dq = store[key]
            dq.append(now)
            while dq and now - dq[0] > window:
                dq.popleft()
            return len(dq)

        if et == "ssh_failed" and src:
            n = bump(self._auth_fail, src)
            if n >= threshold:
                self._bruteforcers[src] = now
                self._fire(out, "ED-LOG-001", source="log", remote_ip=src, now=now,
                           evidence={**log_ev, "failures": n, "window_seconds": window, "user": f.get("user")})
        elif et == "ssh_success" and src:
            if src in self._bruteforcers and now - self._bruteforcers[src] < 3600:
                self._fire(out, "ED-LOG-002", source="log", remote_ip=src, now=now,
                           evidence={**log_ev, "user": f.get("user"), "method": f.get("method")})
        elif et in ("sudo_failed", "su_failed"):
            user = f.get("user", "?")
            n = bump(self._sudo_fail, user)
            if n >= 3:
                self._fire(out, "ED-LOG-003", source="log", now=now, dedup_key=f"ED-LOG-003|{user}",
                           evidence={**log_ev, "user": user, "failures": n})
        elif et == "user_created":
            self._fire(out, "ED-LOG-004", source="log", now=now, dedup_key=f"ED-LOG-004|{f.get('user')}|{now}",
                       evidence={**log_ev, "new_user": f.get("user") or f.get("TargetUserName")})
        elif et == "logon_failed":
            key = src or f.get("WorkstationName") or f.get("user", "?")
            n = bump(self._win_fail, key)
            if n >= threshold:
                self._fire(out, "ED-LOG-005", source="log", remote_ip=src, now=now,
                           dedup_key=f"ED-LOG-005|{key}",
                           evidence={**log_ev, "failures": n, "target_user": f.get("TargetUserName")})
        elif et == "logon_success" and src and src in self._bruteforcers:
            self._fire(out, "ED-LOG-002", source="log", remote_ip=src, now=now, evidence={**log_ev, "user": f.get("user")})

        # Sigma on the log event (keyword/service rules or Windows structured events)
        sev = sg.log_event(ev)
        for rule in self.sigma_rules:
            if rule.applies_to(sev, self.platform) and rule.match(sev):
                self._fire(out, f"SIGMA:{rule.id}", title=rule.title, severity=rule.severity, mitre=rule.mitre,
                           source="sigma", remote_ip=src, now=now, description=rule.description,
                           evidence=log_ev, dedup_key=f"SIGMA:{rule.id}|{src or ev.get('message', '')[:80]}")
        return out
