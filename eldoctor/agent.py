"""El Doctor agent: collection -> detection -> playbooks -> notification loop.

The agent runs inside ``eldoctor.api.server.AgentService``, which owns the database and serves the
local API; front ends never touch the agent's objects or its database directly."""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

import psutil

from eldoctor.collectors.logs import LogManager
from eldoctor.collectors.metrics import MetricsCollector
from eldoctor.collectors.processes import ProcessCollector, connections
from eldoctor.config import home_dir
from eldoctor.detection.engine import DetectionEngine
from eldoctor.detection.ioc import IOCStore, update_feeds
from eldoctor.models import ActionResult, Alert, ProcessInfo, max_severity, severity_rank
from eldoctor.notify.dispatcher import Dispatcher
from eldoctor.playbooks.engine import PlaybookEngine
from eldoctor.playbooks.safety import SafetyGuard
from eldoctor.response.actions import Responder
from eldoctor.storage import Store


def running_agent_pid() -> Optional[int]:
    """PID of an El Doctor agent already running on this data directory (e.g. the Windows/Linux service)."""
    lock = home_dir() / "agent.lock"
    try:
        pid = int(lock.read_text().strip() or 0)
    except (OSError, ValueError):
        return None
    if pid and pid != os.getpid() and psutil.pid_exists(pid):
        return pid
    return None


def integrity_alert(ev: Dict[str, Any]) -> Alert:
    return Alert(rule_id="ED-INT-001", title=f"El Doctor integrity violation: {ev.get('reason')}",
                 severity="critical", source="integrity", mitre=["T1565.001", "T1070"],
                 description="Security-relevant El Doctor data (approvals, user roles, the audit trail, blocks or "
                             "quarantine records) was modified outside the agent. The agent refused to trust it. "
                             "Find out who could write to the data folder and compare the SIEM copy of the "
                             "audit trail.", evidence=ev)


def manual_response(responder, store, action: str, proc: ProcessInfo, user) -> ActionResult:
    """Analyst-initiated action (API respond.process). Same safety guards as playbooks, no breaker budget.

    The API server has already checked the permission; the check is repeated here (defence in depth),
    and ``proc`` is always resolved by the agent from the live process table, never sent by a client."""
    if not user or not user.can("respond"):
        return ActionResult(action, "blocked", f"role '{getattr(user, 'role', '?')}' may not run response actions")
    pd = proc.to_dict()
    r = responder
    if action == "kill":
        res = r.kill(pd, automated=False)
    elif action == "kill_tree":
        res = r.kill(pd, tree=True, automated=False)
    elif action == "suspend":
        res = r.suspend(pd, automated=False)
    elif action == "resume":
        res = r.resume(pd)
    elif action == "renice":
        res = r.renice(pd, automated=False)
    elif action == "forensics":
        res = r.collect_forensics({"id": f"manual-{int(time.time())}", "process": pd})
    elif action == "quarantine":
        res = r.quarantine(pd, automated=False)
    else:
        res = ActionResult(action, "failed", "unknown action")
    store.add_action(res, "", "manual", "manual", user.username)
    store.audit(user.username, f"manual_{action}", res.to_dict())
    return res


class Agent:
    def __init__(self, cfg: Dict[str, Any], store: Store, user, mode: Optional[str] = None,
                 dry_run: Optional[bool] = None, headless: bool = True, users=None,
                 integrity_alerts: Optional[bool] = None) -> None:
        from eldoctor.auth.users import UserManager
        self.cfg = cfg
        self.store = store
        self.user = user
        self.users = users or UserManager(store, cfg)
        ac = cfg["agent"]
        self.interval = float(ac.get("interval", 2.0))
        self.dispatcher = Dispatcher(cfg, exclude_types=None if headless else ["console"])
        self.guard = SafetyGuard(cfg)
        self.responder = Responder(cfg, store, self.guard, dry_run=ac.get("dry_run", False) if dry_run is None else dry_run)
        self.engine = DetectionEngine(cfg)
        self.playbooks = PlaybookEngine(cfg, store, self.responder, self.dispatcher, mode or ac["mode"],
                                        actor=f"agent:{user.username}" if user else "agent",
                                        approver_check=self.users.can_approve)
        # stand-alone agents raise integrity incidents themselves; inside AgentService the service does it
        own_alerts = (users is None) if integrity_alerts is None else integrity_alerts
        if own_alerts:
            store.violation_listeners.append(self._on_violation)
        csv_name = ac.get("metrics_csv")
        self.metrics = MetricsCollector(home_dir() / csv_name if csv_name else None)
        dc = cfg.get("detection", {})
        self.procs = ProcessCollector(dc.get("hash_executables", True), int(dc.get("max_hash_mb", 100)))
        self.logs = LogManager(cfg)
        self.initial_scan = bool(ac.get("initial_scan", True))
        # state for the UI
        self.latest_metrics: Dict[str, Any] = {}
        self.latest_procs: List[ProcessInfo] = []
        self.recent_alerts: Deque[Alert] = deque(maxlen=300)
        self.recent_actions: Deque[Dict[str, Any]] = deque(maxlen=300)
        self.ticks = 0
        self.started = time.time()
        self.last_tick_ms = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._intel_thread: Optional[threading.Thread] = None
        self.lock = threading.RLock()
        self.playbooks.listeners.append(self._on_run)
        self.self_proc = psutil.Process(os.getpid())
        self.self_proc.cpu_percent(None)

    @property
    def mode(self) -> str:
        return self.playbooks.mode

    def _on_violation(self, ev: Dict[str, Any]) -> None:
        alert = integrity_alert(ev)
        try:
            self.store.add_alert(alert)
            self.recent_alerts.appendleft(alert)
            self.dispatcher.notify(alert.to_dict(), [], force=True)
        except Exception:
            pass

    def _on_run(self, run: Dict[str, Any]) -> None:
        for r in run["results"]:
            self.recent_actions.appendleft(dict(r, playbook=run["playbook"], mode=run["mode"]))

    # ------------------------------------------------------------------ loop
    def tick(self) -> List[Alert]:
        t0 = time.time()
        alerts: List[Alert] = []
        blocked = {b["ip"] for b in self.store.active_blocks()}
        self.engine.blocked_ips = blocked

        procs, new = self.procs.snapshot()
        initial = self.ticks == 0
        m = self.metrics.collect()
        self.metrics.log_csv(m)
        if initial and not self.initial_scan:
            new = []
        for p in new:
            alerts += self.engine.on_process_start(p, initial=initial)
        alerts += self.engine.on_process_sample(procs, new, initial=initial)
        alerts += self.engine.on_metrics(m, procs)
        by_pid = {p.pid: p for p in procs}
        alerts += self.engine.on_connections(connections(), by_pid)
        for ev in self.logs.poll():
            alerts += self.engine.on_log(ev)

        with self.lock:
            self.latest_metrics = m
            self.latest_procs = sorted(procs, key=lambda p: (p.cpu_percent, p.memory_percent), reverse=True)

        incidents = self.correlate(alerts)
        for a in alerts:
            self.store.add_alert(a)
            self.recent_alerts.appendleft(a)
        for a in incidents:
            try:
                self.playbooks.handle(a)
            except Exception as exc:  # a broken playbook must never stop monitoring
                self.store.audit("agent", "playbook_error", {"alert": a.id, "error": repr(exc)})
        self.playbooks.process_approvals()
        for res in self.responder.expire_blocks():
            self.store.add_action(res, actor="agent:ttl")
        self.ticks += 1
        self.last_tick_ms = (time.time() - t0) * 1000
        return alerts

    def correlate(self, alerts: List[Alert]) -> List[Alert]:
        """Group alerts about the same entity (process instance / remote IP) into one incident.

        The primary alert is the one whose best playbook is the most specific (lowest priority
        number), then the most severe.  Other detections are attached as evidence, their MITRE
        techniques merged, so one process triggers one response - not one per rule.
        """
        from eldoctor.storage import entity_key
        groups: Dict[str, List[Alert]] = {}
        for a in alerts:
            groups.setdefault(entity_key(a), []).append(a)
        incidents: List[Alert] = []
        for grp in groups.values():
            if len(grp) > 1:
                def rank(al: Alert):
                    prios = [p.priority for p in self.playbooks.matching(al) if p.id != "pb-notify-only"]
                    return (min(prios) if prios else 1000, -severity_rank(al.severity))
                grp.sort(key=rank)
                primary = grp[0]
                for other in grp[1:]:
                    primary.evidence.setdefault("correlated_detections", []).append(
                        {"id": other.id, "rule_id": other.rule_id, "title": other.title,
                         "severity": other.severity, "source": other.source})
                    primary.mitre += [m for m in other.mitre if m not in primary.mitre]
                    primary.severity = max_severity(primary.severity, other.severity)
                    other.tags.append(f"correlated:{primary.id}")
            incidents.append(grp[0])
        # highest severity first so containment of critical threats is not delayed by noise
        incidents.sort(key=lambda a: severity_rank(a.severity), reverse=True)
        return incidents

    def _acquire_lock(self) -> None:
        """One agent per data directory - two agents would double-respond to every incident."""
        lock = home_dir() / "agent.lock"
        for _ in range(2):
            try:
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                self._lock_path = lock
                return
            except FileExistsError:
                try:
                    other = int(lock.read_text().strip() or 0)
                except (OSError, ValueError):
                    other = 0
                if other and other != os.getpid() and psutil.pid_exists(other):
                    raise RuntimeError(f"another El Doctor agent (pid {other}) is already running on {home_dir()}")
                lock.unlink(missing_ok=True)   # stale lock from a crashed agent
        raise RuntimeError("could not acquire agent lock")

    def _release_lock(self) -> None:
        p = getattr(self, "_lock_path", None)
        if p:
            try:
                if p.read_text().strip() == str(os.getpid()):
                    p.unlink()
            except OSError:
                pass

    def run(self, duration: Optional[float] = None) -> None:
        self._acquire_lock()
        for problem in self.logs.start():
            self.store.audit("agent", "log_source_error", problem)
            self.dispatcher.errors.append(problem)
            print(f"warning: {problem}", flush=True)
        self.store.audit(self.user.username if self.user else "agent", "agent_started",
                         {"mode": self.mode, "dry_run": self.responder.dry_run, "log_sources": self.logs.sources,
                          "sigma_rules": len(self.engine.sigma_rules), "playbooks": len(self.playbooks.playbooks),
                          "iocs": len(self.engine.iocs)})
        self._maybe_start_intel_updates()
        end = time.time() + duration if duration else None
        try:
            while not self._stop.is_set():
                start = time.time()
                try:
                    self.tick()
                except Exception as exc:
                    self.store.audit("agent", "tick_error", repr(exc))
                if end and time.time() >= end:
                    break
                self._stop.wait(max(0.0, self.interval - (time.time() - start)))
        finally:
            self.logs.stop()
            self.dispatcher.close()            # flush pending notifications and stop the worker thread
            self._release_lock()
            self.store.audit(self.user.username if self.user else "agent", "agent_stopped", {"ticks": self.ticks})

    def _run_safe(self) -> None:
        try:
            self.run()
        except Exception as exc:          # surfaced to the UI instead of dying silently
            self.error = f"{type(exc).__name__}: {exc}"

    def start_background(self) -> threading.Thread:
        self.error = ""
        self._thread = threading.Thread(target=self._run_safe, daemon=True, name="eldoctor-agent")
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _maybe_start_intel_updates(self) -> None:
        ic = self.cfg.get("intel", {})
        if not ic.get("auto_update"):
            return

        def loop() -> None:
            while not self._stop.is_set():
                res = update_feeds(self.cfg)
                if any(r["ok"] for r in res):
                    self.engine.iocs = IOCStore.from_config(self.cfg)
                self.store.audit("agent", "intel_update", res)
                self._stop.wait(float(ic.get("update_interval_hours", 12)) * 3600)
        self._intel_thread = threading.Thread(target=loop, daemon=True, name="intel")
        self._intel_thread.start()

    # ------------------------------------------------------------------ manual response (TUI)
    def manual_action(self, action: str, proc: ProcessInfo, user) -> ActionResult:
        res = manual_response(self.responder, self.store, action, proc, user)
        self.recent_actions.appendleft(dict(res.to_dict(), playbook="manual", mode="manual"))
        return res

    def status(self) -> Dict[str, Any]:
        try:
            own_cpu = self.self_proc.cpu_percent(None)
            own_mem = self.self_proc.memory_info().rss / 1048576
        except psutil.Error:
            own_cpu, own_mem = 0.0, 0.0
        return {"mode": self.mode, "dry_run": self.responder.dry_run, "ticks": self.ticks,
                "uptime": time.time() - self.started, "tick_ms": self.last_tick_ms, "own_cpu": own_cpu,
                "own_mem_mb": own_mem, "breaker": self.guard.breaker_open, "log_sources": self.logs.sources,
                "sigma_rules": len(self.engine.sigma_rules), "playbooks": len(self.playbooks.playbooks),
                "iocs": len(self.engine.iocs), "yara": self.engine.yara.enabled,
                "notify_errors": list(self.dispatcher.errors)[-3:]}
