"""Presentation helpers shared by the CLI and the GUI: one-line descriptions of activity records and the paged
export (the agent audits every export)."""
from __future__ import annotations

import csv
import json
import time
from typing import Any, Callable, Dict, Optional

from eldoctor.activity.wipe import csv_safe

EXPORT_COLUMNS = ["id", "time", "ts", "kind", "category", "user", "login_user", "pid", "process", "exe", "path",
                  "target", "is_dir", "size", "attribution", "source", "boot_id", "details"]


def _ts(t: Optional[float]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""


def describe(r: Dict[str, Any]) -> Dict[str, Any]:
    """{id, time, kind, user, process, what, how, source} - a readable line for tables."""
    det = r.get("details") if isinstance(r.get("details"), dict) else {}
    who = r.get("user") or ""
    if r.get("login_user") and r.get("login_user") != who:
        who += f" (login {r['login_user']})"
    proc = f"{r.get('process') or ''}[{r['pid']}]" if r.get("pid") else (r.get("process") or "")
    what = r.get("path") or ""
    if r.get("target"):
        what += f" -> {r['target']}"
    cat = r.get("category")
    if cat == "session":
        what = " ".join(str(x) for x in (det.get("type"), det.get("terminal"), det.get("host"),
                                         det.get("command")) if x)
    elif cat == "process":
        what = (det.get("cmdline") or r.get("exe") or "")[:200]
    elif cat in ("system", "incident") and not what:
        what = ", ".join(f"{k}={v}" for k, v in det.items() if k in ("clean", "seconds", "deleted_total", "counts",
                                                                       "note", "reason"))[:200]
    if det.get("trashed"):
        what += "  [moved to Trash]"
    if det.get("url"):
        what += f"  <- {det['url']}"
    return {"id": r.get("id"), "time": _ts(r.get("ts")), "kind": r.get("kind", ""), "user": who, "process": proc,
            "what": what, "how": r.get("attribution") or "", "source": r.get("source") or ""}


def export(call: Callable[..., Any], path: str, params: Dict[str, Any], fmt: str = "csv") -> int:
    """Page through ``activity.list`` (oldest first) and write CSV or JSON lines to ``path`` (written by the
    client, as the person running it).  Returns the number of records."""
    n, after = 0, 0
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = None
        while True:
            rows = call("activity.list", limit=5000, order="asc", after_id=after, export=True, format=fmt, **params)
            if not rows:
                break
            for r in rows:
                if fmt == "jsonl":
                    fh.write(json.dumps(r, default=str) + "\n")
                    continue
                if w is None:
                    w = csv.writer(fh)
                    w.writerow(EXPORT_COLUMNS)
                w.writerow([csv_safe(x) for x in (
                    r["id"], _ts(r["ts"]), r["ts"], r["kind"], r["category"], r["user"], r["login_user"],
                    r["pid"] or "", r["process"], r["exe"], r["path"], r["target"], r["is_dir"],
                    "" if r["size"] is None else r["size"], r["attribution"], r["source"], r["boot_id"],
                    json.dumps(r["details"], default=str))])
            n += len(rows)
            after = rows[-1]["id"]
        if w is None and fmt != "jsonl":
            csv.writer(fh).writerow(EXPORT_COLUMNS)
    return n
