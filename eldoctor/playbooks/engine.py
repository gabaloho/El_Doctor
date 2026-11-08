"""SOAR-style YAML playbook engine.

Playbook schema (see data/playbooks/*.yml)::

    id: pb-cryptominer
    name: Cryptominer containment
    enabled: true
    priority: 10                 # lower runs first
    exclusive: true              # stop evaluating other playbooks after this one
    max_mode: enforce            # cap: monitor | interactive | enforce
    approval_timeout_action: resume   # resume | keep   (interactive mode, nobody answered)
    trigger:                     # any selector may match (OR) ...
      rule_ids: [ED-IOC-003, "SIGMA:8e7d6c5b-*"]
      sources: [sigma, ioc, yara]
      mitre: [T1496]
      min_severity: high         # ... AND severity >= min_severity
    conditions:                  # AND, evaluated on {alert, process, host, mode}
      - {field: alert.process.pid, op: exists}
    steps:
      - {action: collect_forensics}
      - {action: suspend, auto: true}          # reversible: allowed without approval in interactive mode
      - {action: kill, tree: true}
      - {action: block_ip, ip: "{{ alert.remote_ip }}", when: [{field: alert.remote_ip, op: exists}]}
      - {action: notify, channels: [all], message: "Miner contained"}

Response modes
  monitor     : destructive steps are *not* executed, recorded as "would_run"
  interactive : first destructive step pauses the run and creates an approval
                request (TUI key 'a' / `eldoctor approvals approve ID`); on
                approval the run resumes from that step; on denial any
                auto-suspended process is resumed.  The agent never trusts the
                approvals table: before acting it verifies the request seal,
                the decision seal, the matching hash-chained audit record and
                that the approver *currently* holds the approve permission
                (see Store.verify_approval).  Anything else is refused and
                raised as an integrity incident.
  enforce     : everything runs automatically (still subject to safety guards
                and the circuit breaker, which falls back to approvals).
"""
from __future__ import annotations

import fnmatch
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from eldoctor.config import MODE_RANK, MODES, check_trusted_file, package_data
from eldoctor.models import ActionResult, Alert, HOSTNAME, severity_rank
from eldoctor.playbooks.safety import DESTRUCTIVE, MODIFYING

ACTIONS = {"notify", "collect_forensics", "renice", "suspend", "resume", "kill", "quarantine", "block_ip", "log"}
OPS = {"eq", "ne", "gt", "gte", "lt", "lte", "contains", "not_contains", "in", "not_in", "regex", "exists",
       "not_exists", "startswith", "endswith"}
TEMPLATE_RX = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


# --------------------------------------------------------------------------- helpers
def resolve(ctx: Dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def render(value: Any, ctx: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        m = TEMPLATE_RX.fullmatch(value.strip())
        if m:
            return resolve(ctx, m.group(1))
        return TEMPLATE_RX.sub(lambda mm: str(resolve(ctx, mm.group(1)) or ""), value)
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    return value


def _num(x: Any) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def evaluate(cond: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    op = cond.get("op", "eq")
    actual = resolve(ctx, str(cond.get("field", "")))
    expected = render(cond.get("value"), ctx)
    if op == "exists":
        return actual not in (None, "", [], {})
    if op == "not_exists":
        return actual in (None, "", [], {})
    if op in ("gt", "gte", "lt", "lte"):
        a, b = _num(actual), _num(expected)
        if a is None or b is None:
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "eq":
        return str(actual).lower() == str(expected).lower()
    if op == "ne":
        return str(actual).lower() != str(expected).lower()
    if op in ("in", "not_in"):
        vals = [str(v).lower() for v in (expected or [])]
        res = str(actual).lower() in vals
        return res if op == "in" else not res
    s = str(actual or "").lower()
    if op == "contains":
        return str(expected).lower() in s
    if op == "not_contains":
        return str(expected).lower() not in s
    if op == "startswith":
        return s.startswith(str(expected).lower())
    if op == "endswith":
        return s.endswith(str(expected).lower())
    if op == "regex":
        return re.search(str(expected), str(actual or ""), re.I) is not None
    return False


# --------------------------------------------------------------------------- model
@dataclass
class Step:
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    when: List[Dict[str, Any]] = field(default_factory=list)
    auto: bool = False
    on_failure: str = "continue"

    @property
    def destructive(self) -> bool:
        return self.action in DESTRUCTIVE

    @property
    def modifying(self) -> bool:
        return self.action in MODIFYING


@dataclass
class Playbook:
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100
    exclusive: bool = False
    max_mode: str = "enforce"
    approval_timeout_action: str = "resume"
    trigger: Dict[str, Any] = field(default_factory=dict)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    steps: List[Step] = field(default_factory=list)
    path: str = ""

    def matches(self, alert: Alert, ctx: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        t = self.trigger or {}
        if severity_rank(alert.severity) < severity_rank(t.get("min_severity", "info")):
            return False
        selectors = []
        if t.get("rule_ids"):
            selectors.append(any(fnmatch.fnmatchcase(alert.rule_id, pat) for pat in t["rule_ids"]))
        if t.get("sources"):
            selectors.append(alert.source in t["sources"])
        if t.get("mitre"):
            from eldoctor.mitre import matches as mitre_matches
            selectors.append(mitre_matches(alert.mitre, t["mitre"]))
        if t.get("tags"):
            selectors.append(bool(set(alert.tags) & set(t["tags"])))
        if selectors and not (all(selectors) if t.get("match") == "all" else any(selectors)):
            return False
        return all(evaluate(c, ctx) for c in self.conditions)


def validate_doc(doc: Any) -> List[str]:
    errs: List[str] = []
    if not isinstance(doc, dict):
        return ["playbook must be a mapping"]
    for k in ("id", "name", "steps"):
        if k not in doc:
            errs.append(f"missing '{k}'")
    if doc.get("max_mode", "enforce") not in MODES:
        errs.append(f"max_mode must be one of {MODES}")
    if doc.get("approval_timeout_action", "resume") not in ("resume", "keep"):
        errs.append("approval_timeout_action must be resume|keep")
    trig = doc.get("trigger") or {}
    if not isinstance(trig, dict):
        errs.append("trigger must be a mapping")
    elif not any(trig.get(k) for k in ("rule_ids", "sources", "mitre", "tags", "min_severity")):
        errs.append("trigger needs at least one of rule_ids/sources/mitre/tags/min_severity")
    for i, c in enumerate(doc.get("conditions") or []):
        if c.get("op", "eq") not in OPS:
            errs.append(f"conditions[{i}]: unknown op {c.get('op')!r}")
    for i, s in enumerate(doc.get("steps") or []):
        if not isinstance(s, dict) or s.get("action") not in ACTIONS:
            errs.append(f"steps[{i}]: unknown action {s.get('action') if isinstance(s, dict) else s!r} "
                        f"(valid: {sorted(ACTIONS)})")
            continue
        for c in s.get("when") or []:
            if c.get("op", "eq") not in OPS:
                errs.append(f"steps[{i}].when: unknown op {c.get('op')!r}")
        if s.get("on_failure", "continue") not in ("continue", "stop"):
            errs.append(f"steps[{i}]: on_failure must be continue|stop")
    return errs


def parse_playbook(doc: Dict[str, Any], path: str = "") -> Playbook:
    errs = validate_doc(doc)
    if errs:
        raise ValueError(f"{path or doc.get('id', '?')}: " + "; ".join(errs))
    steps = []
    for s in doc["steps"]:
        s = dict(s)
        action = s.pop("action")
        when = s.pop("when", []) or []
        auto = bool(s.pop("auto", False))
        on_failure = s.pop("on_failure", "continue")
        steps.append(Step(action, s, when, auto, on_failure))
    return Playbook(id=str(doc["id"]), name=str(doc["name"]), description=str(doc.get("description", "")).strip(),
                    enabled=bool(doc.get("enabled", True)), priority=int(doc.get("priority", 100)),
                    exclusive=bool(doc.get("exclusive", False)), max_mode=doc.get("max_mode", "enforce"),
                    approval_timeout_action=doc.get("approval_timeout_action", "resume"),
                    trigger=doc.get("trigger") or {}, conditions=doc.get("conditions") or [], steps=steps, path=path)


def load_playbooks(dirs: List[Path], disabled: Optional[List[str]] = None) -> Tuple[List[Playbook], List[str]]:
    pbs: Dict[str, Playbook] = {}
    errors: List[str] = []
    for d in dirs:
        d = Path(d)
        files = [d] if d.is_file() else sorted(list(d.glob("*.yml")) + list(d.glob("*.yaml")))
        for f in files:
            try:
                check_trusted_file(f)
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
                pb = parse_playbook(doc, str(f))
                if pb.id in (disabled or []):
                    pb.enabled = False
                pbs[pb.id] = pb          # later dirs override bundled playbooks with the same id
            except Exception as exc:
                errors.append(f"{f}: {exc}")
    return sorted(pbs.values(), key=lambda p: (p.priority, p.id)), errors


# --------------------------------------------------------------------------- engine
class PlaybookEngine:
    def __init__(self, cfg: Dict[str, Any], store, responder, dispatcher, mode: Optional[str] = None,
                 actor: str = "agent",
                 approver_check: Optional[Callable[[str], Tuple[bool, str]]] = None) -> None:
        self.cfg = cfg
        self.approver_check = approver_check
        self.store = store
        self.responder = responder
        self.dispatcher = dispatcher
        self.mode = mode or cfg["agent"]["mode"]
        self.actor = actor
        self.approval_timeout = float(cfg["agent"].get("approval_timeout", 300))
        dirs = [package_data("playbooks")] + [Path(d).expanduser() for d in cfg.get("playbooks", {}).get("dirs", []) or []]
        self.playbooks, self.errors = load_playbooks(dirs, cfg.get("playbooks", {}).get("disabled", []))
        self.recent_runs: List[Dict[str, Any]] = []
        self.listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.RLock()

    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(mode)
        self.mode = mode

    def effective_mode(self, pb: Playbook) -> str:
        mode = min(self.mode, pb.max_mode, key=lambda m: MODE_RANK[m])
        if self.responder.guard.breaker_open and MODE_RANK[mode] > MODE_RANK["interactive"]:
            mode = "interactive"
        return mode

    def context(self, alert: Alert) -> Dict[str, Any]:
        d = alert.to_dict()
        return {"alert": d, "process": d.get("process") or {}, "host": HOSTNAME, "mode": self.mode}

    def matching(self, alert: Alert) -> List[Playbook]:
        ctx = self.context(alert)
        out = []
        for pb in self.playbooks:
            if pb.matches(alert, ctx):
                out.append(pb)
                if pb.exclusive:
                    break
        return out

    # ------------------------------------------------------------------ public
    def handle(self, alert: Alert) -> List[Dict[str, Any]]:
        runs = [self.run(pb, alert) for pb in self.matching(alert)]
        if not any(r.get("notified") for r in runs):
            # default route: every alert is notified even if no playbook sends anything
            self.dispatcher.notify(alert.to_dict(), [a for r in runs for a in r["results"]])
        return runs

    def run(self, pb: Playbook, alert: Alert, start: int = 0, approved_by: str = "") -> Dict[str, Any]:
        with self._lock:
            mode = "enforce" if approved_by else self.effective_mode(pb)
            ctx = self.context(alert)
            run = {"playbook": pb.id, "alert_id": alert.id, "mode": mode, "status": "completed", "results": [],
                   "notified": False, "ts": time.time(), "approved_by": approved_by}
            for idx in range(start, len(pb.steps)):
                step = pb.steps[idx]
                if step.when and not all(evaluate(c, ctx) for c in step.when):
                    continue
                if step.destructive and not step.auto and mode == "interactive":
                    blocked = self._statically_blocked(pb, alert, idx, ctx)
                    if blocked:
                        # never ask a human to approve something the safety guards will refuse anyway
                        run["results"].append(blocked.to_dict())
                        self.store.add_action(blocked, alert.id, pb.id, mode, self.actor)
                        continue
                    self._request_approval(pb, alert, idx, run)
                    break
                if step.modifying and mode == "monitor":
                    target = self._target(step, ctx)
                    if step.action == "block_ip":
                        ok, why = self.responder.guard.check_ip(target) if target else (False, "no ip")
                    else:
                        ok, why = self.responder.guard.check_process(alert.process or {}, step.action)
                    res = (ActionResult(step.action, "would_run", f"monitor mode: would {step.action} {target}", target)
                           if ok else ActionResult(step.action, "blocked",
                                                   f"monitor mode: {step.action} would be refused - {why}", target))
                else:
                    res = self._execute(step, alert, ctx, run, automated=not approved_by)
                if res is None:
                    continue
                run["results"].append(res.to_dict())
                self.store.add_action(res, alert.id, pb.id, mode, approved_by or self.actor)
                if res.details.get("breaker"):
                    self._request_approval(pb, alert, idx, run)
                    break
                if not res.ok and step.on_failure == "stop":
                    run["status"] = "failed"
                    break
            self.recent_runs.append(run)
            self.recent_runs[:] = self.recent_runs[-200:]
            for cb in self.listeners:
                try:
                    cb(run)
                except Exception:
                    pass
            return run

    def _statically_blocked(self, pb: Playbook, alert: Alert, idx: int, ctx: Dict[str, Any]) -> Optional[ActionResult]:
        """If every remaining destructive step targets something the guards protect, return a 'blocked' result."""
        guard = self.responder.guard
        reasons = []
        for step in pb.steps[idx:]:
            if not step.destructive or (step.when and not all(evaluate(c, ctx) for c in step.when)):
                continue
            if step.action == "block_ip":
                ip = str(render(step.params.get("ip", "{{ alert.remote_ip }}"), ctx) or "")
                ok, why = guard.check_ip(ip) if ip else (False, "no ip")
            else:
                ok, why = guard.check_process(alert.process or {}, step.action)
            if ok:
                return None
            reasons.append(why)
        if not reasons:
            return None
        step = pb.steps[idx]
        return ActionResult(step.action, "blocked", f"no approval requested - {reasons[0]}", self._target(step, ctx))

    def _target(self, step: Step, ctx: Dict[str, Any]) -> str:
        if step.action == "block_ip":
            return str(render(step.params.get("ip", "{{ alert.remote_ip }}"), ctx) or "")
        p = ctx.get("process") or {}
        return f"{p.get('name')}[{p.get('pid')}]" if p else ""

    def _execute(self, step: Step, alert: Alert, ctx: Dict[str, Any], run: Dict[str, Any],
                 automated: bool) -> Optional[ActionResult]:
        a = step.action
        params = render(step.params, ctx)
        proc = alert.process or {}
        r = self.responder
        if a == "notify":
            self.dispatcher.notify(alert.to_dict(), run["results"], note=params.get("message", ""),
                                   channels=params.get("channels"), force=bool(params.get("force")))
            run["notified"] = True
            return None
        if a == "log":
            return ActionResult("log", "success", str(params.get("message", "")))
        if a == "collect_forensics":
            return r.collect_forensics(alert.to_dict())
        if a in ("kill", "suspend", "resume", "quarantine", "renice") and not proc:
            return ActionResult(a, "skipped", "alert has no process entity")
        if a == "kill":
            return r.kill(proc, tree=bool(params.get("tree")), automated=automated, force=bool(params.get("force")),
                          grace=float(params.get("grace", 3.0)))
        if a == "suspend":
            return r.suspend(proc, automated=automated)
        if a == "resume":
            return r.resume(proc)
        if a == "renice":
            return r.renice(proc, automated=automated)
        if a == "quarantine":
            return r.quarantine(proc, alert.id, automated=automated)
        if a == "block_ip":
            ip = params.get("ip") or alert.remote_ip
            if not ip:
                return ActionResult("block_ip", "skipped", "no IP to block")
            return r.block_ip(str(ip), alert.id, reason=alert.title, automated=automated,
                              ttl_hours=params.get("ttl_hours"))
        return ActionResult(a, "failed", f"unknown action {a}")

    # ------------------------------------------------------------------ approvals
    def _request_approval(self, pb: Playbook, alert: Alert, idx: int, run: Dict[str, Any]) -> None:
        from eldoctor.storage import entity_key
        existing = self.store.pending_for_entity(entity_key(alert), pb.id)
        if existing:   # one decision per entity & playbook - don't flood the approver
            run["status"] = "awaiting_approval"
            run["approval_id"] = existing
            run["notified"] = True
            return
        remaining = [s.action for s in pb.steps[idx:] if s.destructive]
        proc = alert.process or {}
        target = f"{proc.get('name')}[{proc.get('pid')}]" if proc else alert.remote_ip
        summary = f"{pb.name}: {', '.join(dict.fromkeys(remaining))} on {target} ({alert.rule_id})"
        aid = self.store.create_approval(alert, pb.id, idx, summary, self.approval_timeout)
        run["status"] = "awaiting_approval"
        run["approval_id"] = aid
        res = ActionResult("approval", "pending_approval", f"approval {aid} requested: {summary}", target,
                           {"approval_id": aid})
        run["results"].append(res.to_dict())
        self.store.add_action(res, alert.id, pb.id, "interactive", self.actor)
        self.dispatcher.notify(alert.to_dict(), run["results"], kind="approval", force=True,
                               note=f"Approve: eldoctor approvals approve {aid}   |   Deny: eldoctor approvals deny {aid}"
                                    f"   (expires in {int(self.approval_timeout)}s)")
        run["notified"] = True

    def _resume_suspended(self, alert_id: str, proc: Dict[str, Any], reason: str) -> Optional[ActionResult]:
        acts = self.store.list_actions(alert_id=alert_id)
        if any(a["action"] == "suspend" and a["status"] == "success" for a in acts) and proc:
            res = self.responder.resume(proc)
            res.message += f" ({reason})"
            return res
        return None

    def process_approvals(self) -> List[Dict[str, Any]]:
        """Act on decided approvals - only after verifying that the agent itself recorded the decision."""
        runs = []
        pbs = {p.id: p for p in self.playbooks}
        for row in self.store.undecided_outcomes():
            ok, why = self.store.verify_approval(row, self.approver_check)
            if not ok:
                # forged / edited row: never execute, never resume - raise it as an integrity incident
                self.store.reject_approval(row, why)
                continue
            if not self.store.mark_executed(row):          # already handled (another agent instance)
                continue
            alert = Alert.from_dict(json.loads(row["alert"]))
            pb = pbs.get(row["playbook_id"])
            if row["status"] == "approved":
                if pb:
                    runs.append(self.run(pb, alert, start=int(row["step_index"]),
                                         approved_by=row["decided_by"] or "approver"))
                continue
            if row["status"] == "expired" and pb and pb.approval_timeout_action == "keep":
                continue
            res = self._resume_suspended(alert.id, alert.process or {}, f"approval {row['status']}")
            results = [res.to_dict()] if res else []
            if res:
                self.store.add_action(res, alert.id, row["playbook_id"], "interactive", row["decided_by"] or "system")
            self.dispatcher.notify(alert.to_dict(), results, note=f"Approval {row['id']} {row['status']}"
                                   + (f" by {row['decided_by']}" if row["decided_by"] else ""))
        self.store.expire_approvals()
        return runs
