"""Real-time forwarding of the hash-chained audit trail to a SIEM.

Every audit record is pushed the moment it is committed (the store wakes the forwarder), in order, to
every configured destination:

* ``syslog`` - UDP, TCP or TLS (RFC 5425) to Wazuh, Graylog, QRadar, Splunk, Elastic, Sentinel (AMA/CEF)...
  Formats: ``cef`` (ArcSight CEF), ``rfc5424`` (structured data + JSON body) or ``json``.
* ``webhook`` - HTTPS POST of JSON batches (HMAC-SHA256 signed with ``secret_env``): Splunk HEC, Elastic,
  Logstash/Vector/Fluent Bit HTTP inputs, SOAR.
* ``jsonl`` - a local append-only JSON-lines copy for Filebeat / Vector / the Splunk UF.

Delivery is ordered and at-least-once: each destination has a cursor (last forwarded ``seq``) that is
persisted, so an outage or an agent restart resumes exactly where it stopped, with exponential back-off
while the destination is down.  (UDP syslog cannot confirm delivery: use ``protocol: tcp`` or ``tls``
when completeness matters.)

Every record carries ``seq``, ``prev_hash``, ``hash`` and ``mac``.  The SIEM copy is out of reach of a
local attacker, and ``verify_export`` (CLI: ``eldoctor audit verify-export FILE``) checks the chain of an
exported copy without any secret: a record that differs between the SIEM and the host, or a gap in
``seq``, pinpoints tampering.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from eldoctor import __version__
from eldoctor.config import home_dir, safe_url
from eldoctor.integrity import GENESIS, audit_hash, fingerprint, verify_signature

CRITICAL_EVENTS = {"integrity_violation", "audit_chain_broken", "data_wipe_reported"}
HIGH_EVENTS = {"api_denied", "token_peer_mismatch", "login_failed", "approval_decided", "role_changed",
               "user_disabled", "user_enabled", "user_registered", "mode_changed", "quarantine_restore",
               "unblock_ip", "service_key_rotated", "sessions_revoked", "approval_executed", "response_action",
               "offline_changes_found", "monitoring_gap", "system_restarted", "admin_report_failed",
               "user_privilege_use", "user_remote_login", "activity_exported"}


def event_severity(event: str) -> int:
    """CEF severity 0-10."""
    if event in CRITICAL_EVENTS:
        return 10
    if event in HIGH_EVENTS or event.startswith("manual_"):
        return 7 if event != "login_failed" else 5
    return 3


def _details(rec: Dict[str, Any]) -> Any:
    try:
        return json.loads(rec.get("details") or "null")
    except ValueError:
        return rec.get("details")


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int((ts % 1) * 1000):03d}Z"


def as_json(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Self-contained record: everything needed to re-verify the chain (``details_raw`` + float ``ts``)."""
    return {"@timestamp": _iso(float(rec["ts"])), "source": "eldoctor", "type": "audit", "version": __version__,
            "seq": int(rec["seq"]), "ts": float(rec["ts"]), "host": rec.get("host", ""), "actor": rec["actor"],
            "event": rec["event"], "severity": event_severity(rec["event"]), "details": _details(rec),
            "details_raw": rec.get("details") or "", "os_user": rec.get("os_user", ""),
            "os_uid": rec.get("os_uid", ""), "os_pid": int(rec.get("os_pid") or 0), "client": rec.get("client", ""),
            "prev_hash": rec.get("prev_hash", ""), "hash": rec.get("hash", ""), "mac": rec.get("mac", ""),
            "v": int(rec.get("v") or 1), "pub": rec.get("pub") or "", "next_pub": rec.get("next_pub") or "",
            "sig": rec.get("sig") or "", "ref_kind": rec.get("ref_kind") or "", "ref_id": rec.get("ref_id") or "",
            "ref_digest": rec.get("ref_digest") or ""}


def _cef_h(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_v(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def as_cef(rec: Dict[str, Any]) -> str:
    hdr = "|".join(["CEF:0", "ElDoctor", "ElDoctor", _cef_h(__version__), _cef_h(f"audit:{rec['event']}"),
                    _cef_h(rec["event"]), str(event_severity(rec["event"]))])
    ext = [("rt", int(float(rec["ts"]) * 1000)), ("dvchost", rec.get("host", "")), ("suser", rec["actor"]),
           ("spid", rec.get("os_pid") or ""), ("suid", rec.get("os_uid", "")), ("act", rec["event"]),
           ("externalId", rec["seq"]), ("cn1Label", "seq"), ("cn1", rec["seq"]),
           ("cs1Label", "hash"), ("cs1", rec.get("hash", "")), ("cs2Label", "prevHash"), ("cs2", rec.get("prev_hash", "")),
           ("cs3Label", "osUser"), ("cs3", rec.get("os_user", "")), ("cs4Label", "client"), ("cs4", rec.get("client", "")),
           ("cs5Label", "details"), ("cs5", rec.get("details") or ""), ("cs6Label", "mac"), ("cs6", rec.get("mac", "")),
           ("flexString1Label", "ts"), ("flexString1", repr(float(rec["ts"]))),
           ("edV", int(rec.get("v") or 1)), ("edPub", rec.get("pub") or ""), ("edNextPub", rec.get("next_pub") or ""),
           ("edSig", rec.get("sig") or ""), ("edRefKind", rec.get("ref_kind") or ""),
           ("edRefId", rec.get("ref_id") or ""), ("edRefDigest", rec.get("ref_digest") or "")]
    return hdr + "|" + " ".join(f"{k}={_cef_v(v)}" for k, v in ext if v != "")


def _sd(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def as_rfc5424(rec: Dict[str, Any], facility: int = 13) -> str:
    sev = {10: 1, 7: 4, 5: 4}.get(event_severity(rec["event"]), 5)        # alert / warning / notice
    pri = facility * 8 + sev
    sd = (f'[eldoctor-audit@32473 seq="{rec["seq"]}" event="{_sd(rec["event"])}" actor="{_sd(rec["actor"])}" '
          f'osUser="{_sd(rec.get("os_user", ""))}" osUid="{_sd(rec.get("os_uid", ""))}" '
          f'osPid="{rec.get("os_pid") or 0}" client="{_sd(rec.get("client", ""))}" ts="{float(rec["ts"])!r}" '
          f'prevHash="{rec.get("prev_hash", "")}" hash="{rec.get("hash", "")}" mac="{rec.get("mac", "")}" '
          f'v="{int(rec.get("v") or 1)}" pub="{rec.get("pub") or ""}" nextPub="{rec.get("next_pub") or ""}" '
          f'sig="{rec.get("sig") or ""}" refKind="{_sd(rec.get("ref_kind") or "")}" '
          f'refId="{_sd(rec.get("ref_id") or "")}" refDigest="{rec.get("ref_digest") or ""}"]')
    return (f"<{pri}>1 {_iso(float(rec['ts']))} {rec.get('host') or '-'} eldoctor-audit {rec.get('os_pid') or '-'} "
            f"AUDIT {sd} {rec.get('details') or ''}")


# --------------------------------------------------------------------------- sinks
class SinkError(Exception):
    pass


class Sink:
    type = "base"

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.conf = conf
        self.id = conf.get("name") or self.default_id()
        self.failures = 0
        self.retry_at = 0.0
        self.last_error = ""
        self.sent = 0

    def default_id(self) -> str:
        return self.type

    def send(self, records: List[Dict[str, Any]]) -> None:   # pragma: no cover - abstract
        raise NotImplementedError

    def close(self) -> None:
        pass


class SyslogSink(Sink):
    type = "syslog"

    def default_id(self) -> str:
        c = self.conf
        return f"syslog:{c.get('host', '127.0.0.1')}:{c.get('port', 514)}/{c.get('protocol', 'udp')}/{c.get('format', 'cef')}"

    def __init__(self, conf: Dict[str, Any]) -> None:
        super().__init__(conf)
        self._sock: Optional[socket.socket] = None

    def _line(self, rec: Dict[str, Any]) -> str:
        fmt = self.conf.get("format", "cef")
        if fmt == "json":
            return json.dumps(as_json(rec), separators=(",", ":"))
        if fmt == "rfc5424":
            return as_rfc5424(rec, int(self.conf.get("facility", 13)))
        body = as_cef(rec)
        return f"<{13 * 8 + (1 if event_severity(rec['event']) == 10 else 5)}>1 {_iso(float(rec['ts']))} " \
               f"{rec.get('host') or '-'} eldoctor-audit - AUDIT - {body}"

    def _connect(self) -> socket.socket:
        c = self.conf
        host, port = c.get("host", "127.0.0.1"), int(c.get("port", 514))
        s = socket.create_connection((host, port), timeout=float(c.get("timeout", 5)))
        if c.get("protocol") == "tls":
            ctx = ssl.create_default_context(cafile=c.get("ca_file") or None)
            if c.get("insecure_skip_verify"):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        return s

    def send(self, records: List[Dict[str, Any]]) -> None:
        c = self.conf
        host, port, proto = c.get("host", "127.0.0.1"), int(c.get("port", 514)), c.get("protocol", "udp")
        try:
            if proto == "udp":
                with socket.socket(socket.AF_INET6 if ":" in str(host) else socket.AF_INET, socket.SOCK_DGRAM) as s:
                    for r in records:
                        s.sendto(self._line(r).encode("utf-8")[:65000], (host, port))
                        self.sent += 1
                return
            data = b""
            for r in records:
                line = self._line(r).encode("utf-8")
                data += (str(len(line)).encode() + b" " + line) if c.get("framing") == "octet" else line + b"\n"
            if self._sock is None:
                self._sock = self._connect()
            self._sock.sendall(data)
            self.sent += len(records)
        except OSError as exc:
            self.close()
            raise SinkError(f"{host}:{port}/{proto}: {exc}") from exc

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class WebhookSink(Sink):
    type = "webhook"

    def default_id(self) -> str:
        return f"webhook:{self.conf.get('name') or self.conf.get('url_env') or self.conf.get('url', '')}"

    def send(self, records: List[Dict[str, Any]]) -> None:
        import os
        import urllib.error
        import urllib.request
        c = self.conf
        url = os.environ.get(c["url_env"], "") if c.get("url_env") else str(c.get("url") or "")
        if not url:
            raise SinkError(f"webhook url not set ({c.get('url_env') or 'url'})")
        body = json.dumps({"source": "eldoctor", "type": "audit", "records": [as_json(r) for r in records]},
                          separators=(",", ":")).encode()
        req = urllib.request.Request(safe_url(url), data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", f"ElDoctor/{__version__}")
        secret = os.environ.get(c["secret_env"], "") if c.get("secret_env") else ""
        if secret:
            req.add_header("X-ElDoctor-Signature", "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest())
        if c.get("token_env") and os.environ.get(c["token_env"]):
            req.add_header("Authorization", f"{c.get('auth_scheme', 'Bearer')} {os.environ[c['token_env']]}")
        try:
            with urllib.request.urlopen(req, timeout=float(c.get("timeout", 10))) as resp:  # noqa: S310
                if resp.status >= 300:
                    raise SinkError(f"HTTP {resp.status}")
        except (urllib.error.URLError, OSError) as exc:
            raise SinkError(str(exc)) from exc
        self.sent += len(records)


class JsonlSink(Sink):
    type = "jsonl"

    def default_id(self) -> str:
        return f"jsonl:{self.conf.get('path', 'audit.jsonl')}"

    def send(self, records: List[Dict[str, Any]]) -> None:
        p = Path(self.conf.get("path", "audit.jsonl"))
        if not p.is_absolute():
            p = home_dir() / p
        try:
            with open(p, "a", encoding="utf-8") as fh:
                for r in records:
                    fh.write(json.dumps(as_json(r), separators=(",", ":")) + "\n")
        except OSError as exc:
            raise SinkError(str(exc)) from exc
        self.sent += len(records)


SINKS = {"syslog": SyslogSink, "webhook": WebhookSink, "jsonl": JsonlSink}


def build_sinks(cfg: Dict[str, Any]) -> List[Sink]:
    ac = cfg.get("audit", {}) or {}
    confs: List[Dict[str, Any]] = [dict(c) for c in ac.get("forward") or [] if c.get("enabled", True)]
    if ac.get("forward_to_notification_syslog", True):
        # the SIEM already configured for alerts gets the audit trail too
        for ch in (cfg.get("notifications", {}) or {}).get("channels", []) or []:
            if ch.get("type") == "syslog" and ch.get("enabled", True):
                confs.append({"type": "syslog", "host": ch.get("host", "127.0.0.1"), "port": ch.get("port", 514),
                              "protocol": ch.get("protocol", "udp"),
                              "format": ch.get("format", "cef") if ch.get("format") in ("cef", "rfc5424", "json")
                              else "cef"})
    if ac.get("jsonl", "audit.jsonl"):
        confs.append({"type": "jsonl", "path": ac.get("jsonl", "audit.jsonl")})
    sinks, seen = [], set()
    for c in confs:
        t = c.get("type")
        if t not in SINKS:
            raise ValueError(f"unknown audit.forward type {t!r} (choose from {sorted(SINKS)})")
        s = SINKS[t](c)
        if s.id not in seen:
            seen.add(s.id)
            sinks.append(s)
    return sinks


class AuditForwarder:
    BATCH = 200

    def __init__(self, cfg: Dict[str, Any], store) -> None:
        self.store = store
        self.sinks = build_sinks(cfg)
        self.backfill = bool((cfg.get("audit", {}) or {}).get("backfill", True))
        self.state_path = Path(store.path).parent / "audit-forward.json"
        self.cursors: Dict[str, int] = self._load()
        head = int(store.audit_head().get("seq") or 0)
        for s in self.sinks:
            if s.id not in self.cursors:
                self.cursors[s.id] = 0 if self.backfill else head
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        store.audit_listeners.append(lambda rec: self._wake.set())

    def _load(self) -> Dict[str, int]:
        try:
            return {k: int(v) for k, v in json.loads(self.state_path.read_text(encoding="utf-8")).items()}
        except (OSError, ValueError, AttributeError):
            return {}

    def _save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self.cursors), encoding="utf-8")
            tmp.replace(self.state_path)
        except OSError:
            pass

    def pump(self) -> bool:
        """Forward whatever is pending. Returns True when every destination is caught up."""
        with self._lock:
            caught_up = True
            now = time.time()
            for s in self.sinks:
                if s.retry_at > now:
                    caught_up = False
                    continue
                while True:
                    rows = self.store.audit_after(self.cursors.get(s.id, 0), self.BATCH)
                    if not rows:
                        break
                    try:
                        s.send(rows)
                    except Exception as exc:       # SinkError or anything unexpected: retry later, never crash
                        s.failures += 1
                        s.retry_at = time.time() + min(60.0, 2.0 ** min(s.failures, 6))
                        s.last_error = f"{time.strftime('%H:%M:%S')} {exc}"
                        caught_up = False
                        break
                    s.failures, s.retry_at, s.last_error = 0, 0.0, ""
                    self.cursors[s.id] = int(rows[-1]["seq"])
                    self._save()
                    if len(rows) < self.BATCH:
                        break
            return caught_up

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=2.0)
            self._wake.clear()
            if self._stop.is_set():
                break
            self.pump()

    def start(self) -> None:
        if self.sinks and not self._thread:
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="eldoctor-siem")
            self._thread.start()
            self._wake.set()

    def flush(self, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while True:
            if self.pump():
                return True
            if time.time() >= end:
                return False
            time.sleep(0.1)

    def stop(self, timeout: float = 3.0) -> None:
        self.flush(timeout)
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        for s in self.sinks:
            s.close()

    def status(self) -> List[Dict[str, Any]]:
        head = int(self.store.audit_head().get("seq") or 0)
        return [{"destination": s.id, "type": s.type, "forwarded_seq": self.cursors.get(s.id, 0),
                 "lag": max(0, head - self.cursors.get(s.id, 0)), "sent": s.sent, "last_error": s.last_error}
                for s in self.sinks]


# --------------------------------------------------------------------------- offline verification
def verify_export(records: List[Dict[str, Any]], genesis_pin: str = "") -> Dict[str, Any]:
    """Verify an exported / SIEM copy of the chain with public information only - no agent key needed.

    Checks record hashes, seq gaps, prev_hash links, the Ed25519 signature of every v2 record and the
    continuity of the one-time signing keys, and reports the genesis key fingerprint (compare it with
    the one you recorded, or pass ``genesis_pin``).  The HMAC ``mac`` needs the agent key and is checked
    by ``eldoctor audit verify``."""
    recs = sorted(records, key=lambda r: int(r["seq"]))
    problems: List[Dict[str, Any]] = []
    prev_seq, prev_hash, next_pub, genesis = None, None, None, None
    for r in recs:
        rec = {"seq": int(r["seq"]), "ts": float(r["ts"]), "actor": r["actor"], "event": r["event"],
               "details": r.get("details_raw", r.get("details") if isinstance(r.get("details"), str) else ""),
               "os_user": r.get("os_user", ""), "os_uid": r.get("os_uid", ""), "os_pid": int(r.get("os_pid") or 0),
               "client": r.get("client", ""), "host": r.get("host", ""), "v": int(r.get("v") or 1),
               "pub": r.get("pub", ""), "next_pub": r.get("next_pub", ""), "ref_kind": r.get("ref_kind", ""),
               "ref_id": r.get("ref_id", ""), "ref_digest": r.get("ref_digest", "")}
        h = audit_hash(rec, r.get("prev_hash", ""))
        if h != r.get("hash"):
            problems.append({"seq": rec["seq"], "problem": "content does not match its hash (modified)"})
        if prev_seq is not None:
            if rec["seq"] != prev_seq + 1:
                problems.append({"seq": rec["seq"], "problem": f"gap after seq {prev_seq} (records missing)"})
            elif r.get("prev_hash") != prev_hash:
                problems.append({"seq": rec["seq"], "problem": "does not link to the previous record"})
        elif rec["seq"] == 1 and r.get("prev_hash") != GENESIS:
            problems.append({"seq": 1, "problem": "first record does not start from the genesis hash"})
        if rec["v"] >= 2:
            if not verify_signature(rec["pub"], h, r.get("sig", "")):
                problems.append({"seq": rec["seq"], "problem": "signature invalid (forged or re-signed)"})
            if next_pub and rec["pub"] != next_pub:
                problems.append({"seq": rec["seq"], "problem": "signing key does not continue the chain"})
            if genesis is None:
                genesis = rec["pub"]          # first signing key in this export (the genesis if it starts the chain)
            next_pub = rec["next_pub"]
        elif next_pub:
            problems.append({"seq": rec["seq"], "problem": "unsigned record after signed records (downgrade)"})
        prev_seq, prev_hash = rec["seq"], r.get("hash")
    gfp = fingerprint(genesis) if genesis else ""
    if genesis_pin and gfp != genesis_pin and recs and int(recs[0]["seq"]) <= 1:
        problems.append({"seq": None, "problem": f"chain starts from {gfp or 'no signed record'}, not from the pinned "
                                                 f"{genesis_pin}"})
    return {"ok": not problems, "checked": len(recs), "first_seq": recs[0]["seq"] if recs else None,
            "last_seq": prev_seq, "genesis": gfp, "problems": problems}
