"""Response actions: kill, suspend, resume, quarantine, block/unblock IP, forensics.

All destructive actions pass through SafetyGuard.  Automated (playbook)
actions additionally consume the circuit-breaker budget; manual actions by a
logged-in analyst skip the budget but never the static guards.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import time
import uuid
from typing import Any, Dict, List, Optional

import psutil

from eldoctor.collectors.processes import hash_file
from eldoctor.config import IS_LINUX, subdir
from eldoctor.models import ActionResult
from eldoctor.playbooks.safety import SafetyGuard, is_interpreter
from eldoctor.response import firewall
from eldoctor.storage import Store


class Responder:
    def __init__(self, cfg: Dict[str, Any], store: Store, guard: SafetyGuard, dry_run: bool = False) -> None:
        self.cfg = cfg
        self.store = store
        self.guard = guard
        self.dry_run = dry_run
        self.block_ttl = float(cfg.get("safety", {}).get("block_ttl_hours", 24)) * 3600
        self.max_blocks = int(cfg.get("safety", {}).get("max_blocked_ips", 500))
        self._pending_removal: Dict[int, str] = {}

    # ------------------------------------------------------------------ common
    def _gate(self, action: str, proc: Dict[str, Any], automated: bool) -> Optional[ActionResult]:
        """Static guards + dry-run.  The circuit-breaker budget is charged later, in _charge(),
        only when the action is really about to touch a live process."""
        target = f"{proc.get('name')}[{proc.get('pid')}]" if proc else "?"
        ok, why = self.guard.check_process(proc, action)
        if not ok:
            return ActionResult(action, "blocked", why, target)
        if self.dry_run:
            return ActionResult(action, "dry_run", f"dry-run: would {action} {target}", target)
        return None

    def _charge(self, action: str, target: str, automated: bool) -> Optional[ActionResult]:
        if not automated:
            return None
        ok, why = self.guard.consume_action_budget()
        return None if ok else ActionResult(action, "blocked", why, target, {"breaker": True})

    # ------------------------------------------------------------------ kill
    def kill(self, proc: Dict[str, Any], tree: bool = False, automated: bool = True,
             grace: float = 3.0, force: bool = False) -> ActionResult:
        """Terminate a process (optionally its whole tree).

        The tree is frozen first (SIGSTOP) so children cannot respawn / fork while we work.
        force=True sends SIGKILL immediately (reverse shells ignore SIGTERM, fork bombs
        don't deserve a grace period); otherwise SIGTERM + SIGCONT, wait `grace`, then SIGKILL."""
        gate = self._gate("kill", proc, automated)
        if gate:
            return gate
        target = f"{proc.get('name')}[{proc.get('pid')}]"
        p, why = self.guard.live_process(proc)
        if p is None:
            return ActionResult("kill", "skipped" if "no longer exists" in why else "blocked", why, target)
        charge = self._charge("kill", target, automated)
        if charge:
            return charge
        victims: List[psutil.Process] = []
        skipped: List[str] = []
        if tree:
            try:
                for c in p.children(recursive=True):
                    try:
                        cinfo = c.as_dict(["pid", "ppid", "name", "exe", "username", "cmdline"], ad_value="")
                    except (psutil.Error, OSError):
                        continue
                    ok, reason = self.guard.check_process(cinfo, "kill")
                    (victims.append(c) if ok else skipped.append(f"{cinfo['name']}[{c.pid}]: {reason}"))
            except (psutil.Error, OSError):
                pass
        victims.append(p)
        errors = []
        if len(victims) > 1:
            for v in [p] + victims[:-1]:          # freeze parent first, then children
                try:
                    v.suspend()
                except (psutil.Error, OSError):
                    pass
        for v in victims:
            try:
                if force:
                    v.kill()
                else:
                    v.terminate()
                    if v.status() == psutil.STATUS_STOPPED:
                        v.resume()                 # a stopped process only handles SIGTERM once continued
            except psutil.NoSuchProcess:
                pass
            except (psutil.AccessDenied, OSError) as exc:
                errors.append(f"{v.pid}: access denied ({exc.__class__.__name__})")
        gone, alive = psutil.wait_procs(victims, timeout=0.5 if force else grace)
        for v in alive:
            try:
                v.kill()
            except (psutil.Error, OSError):
                pass
        gone2, alive2 = psutil.wait_procs(alive, timeout=2)
        killed = len(gone) + len(gone2)
        details = {"killed": killed, "requested": len(victims), "forced": len(gone2),
                   "still_alive": [x.pid for x in alive2], "skipped_children": skipped}
        pid = int(proc.get("pid"))
        if pid in self._pending_removal and not alive2:
            path = self._pending_removal.pop(pid)
            try:
                os.remove(path)
                details["quarantine_original_removed"] = path
            except OSError as exc:
                details["quarantine_original_removal_error"] = str(exc)
        if alive2 or (errors and killed < len(victims)):
            return ActionResult("kill", "failed", "; ".join(errors) or "process survived SIGKILL", target, details)
        how = "SIGKILL" if gone2 else "terminated"
        return ActionResult("kill", "success", f"{how} {target}" + (f" + {killed - 1} child(ren)" if killed > 1 else ""),
                            target, details)

    # ------------------------------------------------------------------ suspend / resume
    def suspend(self, proc: Dict[str, Any], automated: bool = True) -> ActionResult:
        gate = self._gate("suspend", proc, automated)
        if gate:
            return gate
        target = f"{proc.get('name')}[{proc.get('pid')}]"
        p, why = self.guard.live_process(proc)
        if p is None:
            return ActionResult("suspend", "skipped", why, target)
        charge = self._charge("suspend", target, automated)
        if charge:
            return charge
        try:
            p.suspend()
        except (psutil.Error, OSError) as exc:
            return ActionResult("suspend", "failed", f"{exc.__class__.__name__}: {exc}", target)
        if os.name == "nt":
            return ActionResult("suspend", "success", f"suspended {target} (NtSuspendProcess)", target)
        # SIGSTOP is asynchronous - verify the effect instead of assuming it
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                if p.status() == psutil.STATUS_STOPPED:
                    return ActionResult("suspend", "success", f"suspended {target} (SIGSTOP, verified)", target)
            except psutil.NoSuchProcess:
                return ActionResult("suspend", "skipped", f"{target} exited", target)
            time.sleep(0.02)
        return ActionResult("suspend", "failed", f"SIGSTOP sent but {target} is not stopped (traced/uninterruptible?)",
                            target)

    def resume(self, proc: Dict[str, Any]) -> ActionResult:
        target = f"{proc.get('name')}[{proc.get('pid')}]"
        p, why = self.guard.live_process(proc)
        if p is None:
            return ActionResult("resume", "skipped", why, target)
        try:
            p.resume()
            if os.name != "nt":
                deadline = time.time() + 1.0
                while time.time() < deadline and p.status() == psutil.STATUS_STOPPED:
                    time.sleep(0.02)
            return ActionResult("resume", "success", f"resumed {target}", target)
        except (psutil.Error, OSError) as exc:
            return ActionResult("resume", "failed", str(exc), target)

    def renice(self, proc: Dict[str, Any], automated: bool = True) -> ActionResult:
        """Graduated response: drop the process to the lowest CPU priority (reversible, no approval)."""
        target = f"{proc.get('name')}[{proc.get('pid')}]"
        ok, why = self.guard.check_process(proc, "renice")
        if not ok:
            return ActionResult("renice", "blocked", why, target)
        if self.dry_run:
            return ActionResult("renice", "dry_run", f"dry-run: would lower priority of {target}", target)
        p, why = self.guard.live_process(proc)
        if p is None:
            return ActionResult("renice", "skipped", why, target)
        try:
            low = psutil.IDLE_PRIORITY_CLASS if os.name == "nt" else 19  # type: ignore[attr-defined]
            before = p.nice()
            p.nice(low)
            return ActionResult("renice", "success", f"priority of {target} lowered ({before} -> {low})", target)
        except (psutil.Error, OSError) as exc:
            return ActionResult("renice", "failed", f"{exc.__class__.__name__}: {exc}", target)

    # ------------------------------------------------------------------ quarantine
    def quarantine(self, proc: Dict[str, Any], alert_id: str = "", automated: bool = True) -> ActionResult:
        gate = self._gate("quarantine", proc, automated)
        if gate:
            return gate
        exe = proc.get("exe") or ""
        script_note = ""
        if is_interpreter(exe):
            script = self._script_of(proc)
            if not script:
                return ActionResult("quarantine", "skipped",
                                    f"{os.path.basename(exe)} runs inline code - nothing on disk to quarantine "
                                    "(interpreters are never quarantined; the process is handled by kill)", exe)
            script_note = f" (script run by {os.path.basename(exe)})"
            exe = script
            proc = dict(proc, exe=script, exe_deleted=False)
        ok, why = self.guard.check_quarantine_path(exe)
        if not ok:
            return ActionResult("quarantine", "blocked", why, exe)
        target = exe
        deleted = bool(proc.get("exe_deleted"))
        src = exe
        if deleted or not os.path.exists(exe):
            if IS_LINUX and proc.get("pid") and os.path.exists(f"/proc/{proc['pid']}/exe"):
                src = f"/proc/{proc['pid']}/exe"     # recover the deleted binary from the running process
            else:
                return ActionResult("quarantine", "skipped", f"{exe} not found on disk", target)
        charge = self._charge("quarantine", target, automated)
        if charge:
            return charge
        qid = uuid.uuid4().hex[:10]
        vault = subdir("quarantine")
        dest = vault / f"{qid}.bin"
        try:
            st = os.stat(src)
            shutil.copyfile(src, dest)
            os.chmod(dest, stat.S_IRUSR)               # 0400: not executable
            digest = hash_file(str(dest))
        except OSError as exc:
            return ActionResult("quarantine", "failed", f"copy failed: {exc}", target)
        removed, note = False, ""
        if src == exe:
            try:
                os.remove(exe)
                removed = True
            except OSError as exc:
                note = f"original not removed yet ({exc.__class__.__name__}); will retry after kill"
                self._pending_removal[int(proc.get("pid") or 0)] = exe
        else:
            removed, note = True, "binary was already deleted - recovered copy from /proc"
        meta = {"id": qid, "original_path": exe, "stored_path": str(dest), "sha256": digest, "size": st.st_size,
                "mode": stat.S_IMODE(st.st_mode), "alert_id": alert_id, "ts": time.time(),
                "process": {k: proc.get(k) for k in ("pid", "name", "cmdline", "username")}}
        (vault / f"{qid}.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        self.store.add_quarantine(meta)
        msg = f"{exe}{script_note} -> vault {qid} (sha256 {digest[:16]}...)" + ("" if removed else f"; {note}")
        if note and removed:
            msg += f"; {note}"
        return ActionResult("quarantine", "success", msg, target, {"quarantine_id": qid, "sha256": digest,
                                                                   "original_removed": removed})

    @staticmethod
    def _script_of(proc: Dict[str, Any]) -> str:
        """Script file an interpreter is running (`python /tmp/x.py`, `bash -x ./a.sh`, `node app.js`)."""
        args = proc.get("cmdline") or []
        if isinstance(args, str):
            args = args.split(" ")
        cwd = proc.get("cwd") or ""
        if not cwd and proc.get("pid"):
            try:
                cwd = psutil.Process(int(proc["pid"])).cwd()      # relative script paths are relative to the process
            except (psutil.Error, OSError):
                cwd = ""
        skip_next = {"-c", "-e", "-m", "-E", "-Command", "-command", "-EncodedCommand", "-enc", "/c", "/k"}
        for i, a in enumerate(args[1:], start=1):
            if args[i - 1] in skip_next:
                return ""            # inline code / module: no script file
            if not a or a.startswith("-") or a.startswith("/") and len(a) <= 3 and not os.path.exists(a):
                continue
            cand = a if os.path.isabs(a) or not cwd else os.path.join(cwd, a)
            if os.path.isfile(cand) and not is_interpreter(cand):
                return cand
        return ""

    def restore(self, qid: str) -> ActionResult:
        r = self.store.quarantine_record(qid)
        if not r:
            return ActionResult("restore", "failed", f"unknown quarantine id {qid}", qid)
        # restore writes a file as the (privileged) agent: only for records the agent itself sealed, and only
        # if the vault copy is still the exact file that was quarantined
        if r.get("integrity") != "ok":
            return ActionResult("restore", "blocked", "quarantine record failed its integrity check - refusing to "
                                                      "restore (possible tampering)", r["original_path"])
        if r["restored"]:
            return ActionResult("restore", "skipped", "already restored", r["original_path"])
        if os.path.exists(r["original_path"]):
            return ActionResult("restore", "failed", "a file already exists at the original path", r["original_path"])
        try:
            vault_digest = hash_file(r["stored_path"])
        except OSError as exc:
            return ActionResult("restore", "failed", f"vault copy unreadable: {exc}", r["original_path"])
        if vault_digest != r["sha256"]:
            return ActionResult("restore", "blocked", "the vault copy no longer matches the quarantined file's "
                                                      "SHA-256 - refusing to restore", r["original_path"])
        try:
            shutil.copyfile(r["stored_path"], r["original_path"])
            os.chmod(r["original_path"], int(r["mode"] or 0o644))
        except OSError as exc:
            return ActionResult("restore", "failed", str(exc), r["original_path"])
        self.store.mark_restored(qid)
        return ActionResult("restore", "success", f"restored {r['original_path']}", r["original_path"])

    # ------------------------------------------------------------------ network
    def block_ip(self, ip: str, alert_id: str = "", reason: str = "", automated: bool = True,
                 ttl_hours: Optional[float] = None) -> ActionResult:
        ok, why = self.guard.check_ip(ip)
        if not ok:
            return ActionResult("block_ip", "blocked", why, ip)
        if any(b["ip"] == ip for b in self.store.active_blocks()):
            return ActionResult("block_ip", "skipped", f"{ip} already blocked", ip)
        if len(self.store.active_blocks()) >= self.max_blocks:
            return ActionResult("block_ip", "blocked", f"block list full ({self.max_blocks})", ip)
        if self.dry_run:
            return ActionResult("block_ip", "dry_run", f"dry-run: would block {ip} via {firewall.backend_name()}", ip)
        if automated:
            ok, why = self.guard.consume_action_budget()
            if not ok:
                return ActionResult("block_ip", "blocked", why, ip, {"breaker": True})
        backend, ok, msg = firewall.apply(ip)
        if not ok:
            # firewall failed - still enforce at app level so the response is not lost
            self.store.add_block(ip, self._ttl(ttl_hours), reason, alert_id, "app-level")
            return ActionResult("block_ip", "success", f"firewall error ({msg}); enforced at app level", ip,
                                {"backend": "app-level", "firewall_error": msg})
        self.store.add_block(ip, self._ttl(ttl_hours), reason, alert_id, backend)
        conns = []
        try:
            conns = [c.pid for c in psutil.net_connections("inet") if c.raddr and c.raddr.ip == ip and c.pid]
        except (psutil.Error, OSError):
            pass
        return ActionResult("block_ip", "success", f"blocked {ip} ({backend}): {msg}", ip,
                            {"backend": backend, "ttl_hours": self._ttl(ttl_hours) / 3600,
                             "processes_connected": conns})

    def _ttl(self, hours: Optional[float]) -> float:
        return float(hours) * 3600 if hours is not None else self.block_ttl

    def unblock_ip(self, ip: str) -> ActionResult:
        rows = [b for b in self.store.active_blocks() if b["ip"] == ip]
        if not rows:
            return ActionResult("unblock_ip", "skipped", f"{ip} is not blocked", ip)
        msg = "removed from app-level block list"
        if rows[0]["backend"] != "app-level":
            _, ok, msg = firewall.apply(ip, remove=True)
        self.store.deactivate_block(ip)
        return ActionResult("unblock_ip", "success", msg, ip)

    def expire_blocks(self) -> List[ActionResult]:
        now = time.time()
        return [self.unblock_ip(b["ip"]) for b in self.store.active_blocks() if b["expires"] and b["expires"] < now]

    # ------------------------------------------------------------------ forensics
    def collect_forensics(self, alert: Dict[str, Any]) -> ActionResult:
        proc = alert.get("process") or {}
        evidence: Dict[str, Any] = {"collected_at": time.time(), "alert": alert}
        if proc.get("pid"):
            p, why = self.guard.live_process(proc)
            if p is None:
                evidence["live_process"] = {"error": why}
            else:
                attrs = ["pid", "ppid", "name", "exe", "cmdline", "cwd", "username", "create_time", "status",
                         "num_threads", "memory_info", "cpu_times", "open_files", "nice"]
                try:
                    with p.oneshot():
                        d = p.as_dict(attrs, ad_value=None)
                    d["memory_info"] = d["memory_info"]._asdict() if d.get("memory_info") else None
                    d["cpu_times"] = d["cpu_times"]._asdict() if d.get("cpu_times") else None
                    d["open_files"] = [f.path for f in (d.get("open_files") or [])][:200]
                    try:
                        d["connections"] = [{"laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                             "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                                             "status": c.status} for c in p.net_connections("inet")]
                    except (psutil.Error, OSError):
                        d["connections"] = "access denied"
                    d["parents"] = [{"pid": a.pid, "name": a.name()} for a in p.parents()]
                    d["children"] = [{"pid": c.pid, "name": c.name()} for c in p.children(recursive=True)][:200]
                    if IS_LINUX:
                        try:
                            with open(f"/proc/{p.pid}/maps", "r") as fh:
                                d["mapped_files"] = sorted({ln.split()[-1] for ln in fh if "/" in ln})[:300]
                        except OSError:
                            pass
                    evidence["live_process"] = d
                except (psutil.Error, OSError) as exc:
                    evidence["live_process"] = {"error": str(exc)}
        path = subdir("evidence") / f"{alert.get('id', 'manual')}_{proc.get('pid', 'na')}.json"
        path.write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)
        return ActionResult("collect_forensics", "success", f"evidence saved to {path}", str(proc.get("pid", "")),
                            {"path": str(path)})
