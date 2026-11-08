"""Reports for the registered administrators (e-mail), with a persistent outbox.

Recipients are the e-mail addresses of the *registered* El Doctor administrators (role ``admin``, active,
account record intact - a row added to the database behind the agent's back is never a recipient), plus
``activity.report.extra_recipients``.  They are resolved when the mail is sent.

SMTP settings: ``activity.report.smtp`` or, when empty, the first ``email`` notification channel.

Every report is written to the ``outbox`` table *before* anything is sent, and retried with back-off
until it is delivered - across agent restarts and reboots.  Queued and delivered reports are both
recorded in the signed audit trail (``admin_report_queued`` / ``admin_report_sent``).
"""
from __future__ import annotations

import base64
import io
import json
import threading
import time
import zipfile
from typing import Any, Dict, List, Optional

from eldoctor.activity.wipe import CSV_FIELDS, human_bytes, rows_csv
from eldoctor.models import HOSTNAME

ATTRIBUTION_HELP = {
    "kernel": "recorded by the operating system (auditd / Sysmon / Security log) - authoritative",
    "handle": "the process had the file open",
    "cmdline": "the process command line named the file or a parent folder",
    "self": "El Doctor itself (quarantine)",
    "inferred": "no process evidence - the home-folder owner / only logged-in user (a lead, not proof)",
    "unknown": "no evidence of who did it",
}


def _t(ts: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError):
        return "?"


class AdminReporter:
    def __init__(self, cfg: Dict[str, Any], store, errors: Optional[Any] = None) -> None:
        rc = ((cfg.get("activity") or {}).get("report") or {})
        self.cfg = cfg
        self.store = store
        self.enabled = bool(rc.get("email_admins", True))
        self.extra = [str(x) for x in rc.get("extra_recipients") or [] if x]
        self.smtp_conf = dict(rc.get("smtp") or {})
        self.max_attachment = float(rc.get("max_attachment_mb", 10)) * 1024 * 1024
        self.retry_max = float(rc.get("retry_max_seconds", 6 * 3600))
        self.body_rows = int(rc.get("body_rows", 100))
        self.errors = errors if errors is not None else []
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.sent = 0

    # ------------------------------------------------------------------ configuration
    def smtp(self) -> Optional[Dict[str, Any]]:
        if self.smtp_conf.get("smtp_host"):
            return self.smtp_conf
        for ch in (self.cfg.get("notifications") or {}).get("channels") or []:
            if ch.get("type") == "email" and ch.get("enabled", True) and ch.get("smtp_host"):
                return ch
        return None

    def recipients(self) -> List[str]:
        out: List[str] = []
        for r in self.store.query("SELECT * FROM users WHERE role = 'admin' AND active = 1 ORDER BY id"):
            if r.get("email") and self.store.user_row_ok(r):
                out.append(str(r["email"]))
        out += self.extra
        seen, uniq = set(), []
        for e in out:
            if e.lower() not in seen:
                seen.add(e.lower())
                uniq.append(e)
        return uniq

    # ------------------------------------------------------------------ queue / deliver
    def queue(self, kind: str, subject: str, body: str, attachments: Optional[List[Dict[str, Any]]] = None,
              ref: str = "") -> Optional[str]:
        if not self.enabled:
            return None
        enc = [{"name": a["name"], "mime": a.get("mime", "application/octet-stream"),
                "data": base64.b64encode(a["data"]).decode()} for a in attachments or []]
        oid = self.store.outbox_add(kind, subject, body, enc, ref)
        self._wake.set()
        return oid

    def deliver(self, now: Optional[float] = None, force: bool = False) -> List[Dict[str, Any]]:
        """Try every due report once.  Returns [{id, status, error}]."""
        from eldoctor.notify.channels import ChannelError, send_email
        now = now or time.time()
        rows = self.store.query("SELECT * FROM outbox WHERE status = 'pending' ORDER BY ts") if force \
            else self.store.outbox_due(now)
        results = []
        for r in rows:
            conf = self.smtp()
            to = self.recipients()
            err = ""
            if conf is None:
                err = "no SMTP server configured (activity.report.smtp or an e-mail notification channel)"
            elif not to:
                err = "no registered administrator with an e-mail address"
            else:
                try:
                    atts = [{"name": a["name"], "mime": a.get("mime"), "data": base64.b64decode(a["data"])}
                            for a in json.loads(r["attachments"] or "[]")]
                    send_email(conf, to, r["subject"], r["body"], atts)
                except ChannelError as exc:
                    err = str(exc)
                except Exception as exc:             # never let a report crash the agent
                    err = f"{type(exc).__name__}: {exc}"
            attempts = int(r["attempts"] or 0) + 1
            if err:
                delay = min(self.retry_max, 60.0 * (2 ** min(attempts - 1, 12)))
                self.store.outbox_update(r["id"], attempts=attempts, next_try=now + delay, last_error=err[:500])
                msg = f"{time.strftime('%H:%M:%S')} admin report {r['id']}: {err}"
                if not self.errors or self.errors[-1] != msg:
                    self.errors.append(msg)
                if attempts == 1:
                    self.store.audit("agent", "admin_report_failed", {"id": r["id"], "error": err[:300]})
            else:
                self.store.outbox_update(r["id"], status="sent", attempts=attempts, sent_ts=time.time(),
                                         last_error="", recipients=", ".join(to))
                self.store.audit("agent", "admin_report_sent", {"id": r["id"], "kind": r["kind"], "recipients": to,
                                                                "subject": r["subject"]})
                self.sent += 1
            results.append({"id": r["id"], "status": "failed" if err else "sent", "error": err})
        return results

    def start(self) -> None:
        if self._thread or not self.enabled:
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.deliver()
                except Exception as exc:
                    self.errors.append(f"admin reports: {exc}")
                self._wake.wait(30)
                self._wake.clear()
        self._thread = threading.Thread(target=loop, daemon=True, name="eldoctor-reports")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    # ------------------------------------------------------------------ report contents
    def deletion_attachment(self, inc_summary: Dict[str, Any], rows: Optional[List[Dict[str, Any]]] = None
                            ) -> Dict[str, Any]:
        """Zipped CSV of every deleted file/folder of the incident (read back from the activity record)."""
        buf = io.BytesIO()
        written, truncated = 0, False
        name = f"eldoctor-deleted-{HOSTNAME}-{inc_summary['id']}.csv"
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            with zf.open(name, "w") as fh:
                fh.write(rows_csv([]).encode())       # header
                budget = self.max_attachment * 8      # paths compress ~8-10x
                size = 0
                for chunk in self._deletion_rows(inc_summary, rows):
                    data = rows_csv(chunk).split("\n", 1)[1].encode()
                    if size + len(data) > budget:
                        truncated = True
                        break
                    fh.write(data)
                    size += len(data)
                    written += len(chunk)
        return {"name": name + ".zip", "mime": "application/zip", "data": buf.getvalue(), "rows": written,
                "truncated": truncated}

    def _deletion_rows(self, s: Dict[str, Any], rows: Optional[List[Dict[str, Any]]]):
        if rows is not None:
            for i in range(0, len(rows), 5000):
                yield rows[i:i + 5000]
            return
        after = int(s.get("first_id") or 0) - 1
        last = int(s.get("last_id") or 0)
        while after < last:
            chunk = self.store.query("SELECT * FROM activity WHERE id > ? AND id <= ? AND kind = 'file_deleted' "
                                     "ORDER BY id LIMIT 5000", (after, last))
            if not chunk:
                return
            for r in chunk:
                try:
                    r["details"] = json.loads(r["details"]) if r.get("details") else {}
                except ValueError:
                    r["details"] = {}
            yield chunk
            after = int(chunk[-1]["id"])

    def wipe_report(self, s: Dict[str, Any], alert: Dict[str, Any], sessions: List[Dict[str, Any]],
                    sample: List[Dict[str, Any]], attachment: Dict[str, Any]) -> Dict[str, str]:
        offline = s.get("source") == "offline"
        actors = s.get("actors") or []
        main = actors[0][0] if actors else "unknown"
        procs = s.get("processes") or []
        p0 = procs[0] if procs else None
        sev = str(alert.get("severity", "critical")).upper()
        what = f"{s['total']:,} files/folders deleted"
        who = (" (actor not identified)" if main == "unknown" else f" by {main}") + \
            (f" ({p0['process']}, pid {p0['pid']})" if p0 else "")
        subject = (f"[El Doctor][{sev}] {'Files deleted while El Doctor was not running' if offline else 'Data wipe'}"
                   f" on {HOSTNAME}: {what}{'' if offline and main == 'unknown' else who}")
        L: List[str] = []
        if offline:
            g = s.get("gap") or [s["started"], s["last"]]
            L += [f"El Doctor found {s['total']:,} files and folders missing when it started on {HOSTNAME}.",
                  f"They were deleted while El Doctor was not running, between {_t(g[0])} and {_t(g[1])}",
                  "(system shut down / rebooted, agent stopped, or the disk was accessed from another system).", ""]
        else:
            L += [f"El Doctor detected a mass deletion of files (possible data wipe) on {HOSTNAME}.", ""]
        L += ["WHO"]
        for name, n in actors[:10]:
            L.append(f"  {name:<40} {n:>8,} item(s)")
        for p in procs[:10]:
            L.append(f"  process {p['process']} (pid {p['pid']}) {p.get('exe') or ''} - user {p.get('user') or '?'}"
                     + (f", login user {p['login_user']}" if p.get("login_user") else "") + f" - {p['count']:,} item(s)")
            if p.get("cmdline"):
                L.append(f"    command line: {str(p['cmdline'])[:300]}")
        L.append("  How each deletion was attributed:")
        for how, n in sorted((s.get("attribution") or {}).items(), key=lambda x: -x[1]):
            L.append(f"    {how:<9} {n:>8,}  - {ATTRIBUTION_HELP.get(how, '')}")
        L.append("  Logged-in users " + ("before El Doctor stopped:" if offline else "at the time:"))
        for x in sessions or []:
            L.append(f"    {x.get('user')} ({x.get('type', '')} {x.get('terminal') or ''}"
                     + (f" from {x['host']}" if x.get("host") else "") + f", since {_t(x.get('started'))})")
        if not sessions:
            L.append("    (none recorded)")
        L += ["", "WHEN", f"  {_t(s['started'])}  ->  {_t(s['last'])}   ({s['duration_s']} s)"
              + ("" if offline or s.get("closed") else "   (incident still open)"), "",
              "WHAT",
              f"  {s['files']:,} file(s) ({human_bytes(s['bytes'])}) and {s['folders']:,} folder(s); "
              f"{s['permanent']:,} permanently deleted, {s['trashed']:,} moved to the Trash"]
        if s.get("top_folders"):
            L.append("  Folders most affected:")
            for folder, n in s["top_folders"]:
                L.append(f"    {n:>8,}  {folder}")
        if s.get("deleted_folders"):
            L.append("  Deleted folders:")
            for f in s["deleted_folders"]:
                L.append(f"    {f}")
        L += ["", f"  First {min(len(sample), self.body_rows)} of {s['total']:,} deleted items "
                  f"(complete list attached: {attachment['name']}, {attachment['rows']:,} rows"
                  + (", TRUNCATED - run `eldoctor activity export` for everything" if attachment.get("truncated")
                     else "") + "):"]
        for d in sample[: self.body_rows]:
            det = d.get("details") if isinstance(d.get("details"), dict) else {}
            who_ = d.get("user") or "?"
            if d.get("process"):
                who_ += f"/{d['process']}[{d.get('pid') or '?'}]"
            L.append(f"    {_t(d.get('ts'), '%H:%M:%S')}  {'folder' if d.get('is_dir') else 'file  '}  {d.get('path')}"
                     + ("" if d.get("is_dir") or d.get("size") is None else f"  ({human_bytes(d.get('size'))})")
                     + f"  by {who_}" + ("  [Trash]" if det.get("trashed") else ""))
        L += ["", "RESPONSE / INVESTIGATION",
              f"  Alert {alert.get('id')} - {alert.get('rule_id')} {alert.get('title')}",
              f"  Timeline:  eldoctor activity list --since {int(s['started']) - 300} --kind file_deleted",
              f"  Export:    eldoctor activity export --since {int(s['started']) - 300} --out triage.csv",
              "  Response actions taken by playbooks: eldoctor actions",
              "", "These records are kept in El Doctor's tamper-evident activity log (eldoctor audit verify).",
              f"CSV columns: {', '.join(CSV_FIELDS)}"]
        return {"subject": subject, "body": "\n".join(L)}

    def simple_report(self, title: str, lines: List[str], alert: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        sev = str((alert or {}).get("severity", "high")).upper()
        body = "\n".join(lines + (["", f"Alert {alert.get('id')} - {alert.get('rule_id')}"] if alert else []))
        return {"subject": f"[El Doctor][{sev}] {title} on {HOSTNAME}", "body": body}
