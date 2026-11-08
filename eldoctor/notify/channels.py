"""Notification channels.

console | jsonl | email | slack | teams | discord | webhook (Shuffle, n8n, Tines,
generic SOAR) | thehive | syslog (RFC5424 or CEF).

Secrets come from environment variables (``*_env`` keys) - never from the
config file.  Webhook payloads can be HMAC-SHA256 signed (X-ElDoctor-Signature)
so the receiving SOAR workflow can verify they really came from El Doctor.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import socket
import ssl
import sys
import time
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional

from eldoctor import __version__
from eldoctor.config import home_dir, safe_url
from eldoctor.models import HOSTNAME, severity_rank

SEV_COLOR = {"info": "#6c757d", "low": "#17a2b8", "medium": "#ffc107", "high": "#fd7e14", "critical": "#dc3545"}
SEV_EMOJI = {"info": "ℹ️", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


class ChannelError(Exception):
    pass


def _secret(conf: Dict[str, Any], key: str) -> str:
    """Return conf[key] or the env var named in conf[key + '_env']."""
    env = conf.get(f"{key}_env")
    if env:
        val = os.environ.get(env, "")
        if not val:
            raise ChannelError(f"environment variable {env} is not set")
        return val
    return str(conf.get(key) or "")


def _post_json(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None,
               timeout: float = 10, body: Optional[bytes] = None) -> int:
    data = body if body is not None else json.dumps(payload, default=str).encode()
    try:
        safe_url(url)
    except ValueError as exc:
        raise ChannelError(str(exc)) from exc
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", f"ElDoctor/{__version__}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured endpoint
            return resp.status
    except urllib.error.HTTPError as exc:
        raise ChannelError(f"HTTP {exc.code} from {url.split('?')[0]}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ChannelError(f"cannot reach {url.split('?')[0]}: {exc}") from exc


# --------------------------------------------------------------------------- message model
def build_message(alert: Dict[str, Any], actions: List[Dict[str, Any]], kind: str = "alert",
                  note: str = "") -> Dict[str, Any]:
    proc = alert.get("process") or {}
    sev = alert.get("severity", "medium")
    who = f"{proc.get('name')} (pid {proc.get('pid')}, user {proc.get('username') or '?'})" if proc else ""
    title = f"[El Doctor][{sev.upper()}] {alert.get('title')}" + (f" - {proc.get('name')}" if proc else "") + \
        (f" - {alert.get('remote_ip')}" if alert.get("remote_ip") and not proc else "")
    if kind == "approval":
        title = f"[El Doctor][APPROVAL NEEDED] {alert.get('title')}"
    lines = [f"Host: {alert.get('host', HOSTNAME)}", f"Rule: {alert.get('rule_id')} ({alert.get('source')})",
             f"Severity: {sev}", f"Time: {alert.get('time_iso', '')}"]
    if who:
        lines.append(f"Process: {who}")
        if proc.get("exe"):
            lines.append(f"Executable: {proc.get('exe')}")
        if proc.get("cmdline"):
            lines.append(f"Command line: {str(proc.get('cmdline'))[:300]}")
    if alert.get("remote_ip"):
        lines.append(f"Remote IP: {alert['remote_ip']}")
    mitre = alert.get("mitre_details") or []
    if mitre:
        lines.append("MITRE ATT&CK: " + "; ".join(f"{m['id']} {m['name']}" for m in mitre))
    if alert.get("description"):
        lines.append(f"Why: {alert['description']}")
    ev = alert.get("evidence") or {}
    if ev:
        lines.append("Evidence: " + json.dumps(ev, default=str)[:600])
    if actions:
        lines.append("Response:")
        for a in actions:
            lines.append(f"  - {a.get('action')}: {a.get('status')} - {a.get('message')}")
    if note:
        lines.append(note)
    return {"title": title, "text": "\n".join(lines), "severity": sev, "alert": alert, "actions": actions,
            "kind": kind}


# --------------------------------------------------------------------------- channels
class Channel:
    type = "base"

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.conf = conf
        self.name = conf.get("name") or self.type
        self.min_severity = conf.get("min_severity")

    def wants(self, severity: str, global_min: str) -> bool:
        return severity_rank(severity) >= severity_rank(self.min_severity or global_min)

    def send(self, msg: Dict[str, Any]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class ConsoleChannel(Channel):
    type = "console"
    COLORS = {"info": "\033[37m", "low": "\033[36m", "medium": "\033[33m", "high": "\033[35m", "critical": "\033[31m"}

    def send(self, msg: Dict[str, Any]) -> None:
        stream = sys.stdout
        color = self.COLORS.get(msg["severity"], "") if stream.isatty() else ""
        reset = "\033[0m" if color else ""
        ts = time.strftime("%H:%M:%S")
        stream.write(f"{color}{ts} {msg['title']}{reset}\n")
        for a in msg.get("actions") or []:
            stream.write(f"         -> {a.get('action')}: {a.get('status')} - {a.get('message')}\n")
        stream.flush()


class JsonlChannel(Channel):
    """Append-only JSON lines file - easy to ship with Filebeat/Wazuh/Splunk UF/Vector."""
    type = "jsonl"

    def send(self, msg: Dict[str, Any]) -> None:
        path = Path(self.conf.get("path", "alerts.jsonl"))
        if not path.is_absolute():
            path = home_dir() / path
        rec = {"kind": msg["kind"], "alert": msg["alert"], "actions": msg["actions"], "ts": time.time()}
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")


class EmailChannel(Channel):
    type = "email"

    def send(self, msg: Dict[str, Any]) -> None:
        c = self.conf
        to = c.get("to") or []
        if isinstance(to, str):
            to = [to]
        if not to:
            raise ChannelError("email: no recipients")
        em = EmailMessage()
        em["Subject"] = msg["title"]
        em["From"] = c.get("from") or c.get("username") or f"eldoctor@{HOSTNAME}"
        em["To"] = ", ".join(to)
        em.set_content(msg["text"])
        host, port = c.get("smtp_host", "localhost"), int(c.get("smtp_port", 587))
        timeout = float(c.get("timeout", 15))
        try:
            if c.get("ssl"):
                server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)
            with server:
                if c.get("starttls", True) and not c.get("ssl"):
                    server.starttls(context=ssl.create_default_context())
                if c.get("username"):
                    server.login(c["username"], _secret(c, "password"))
                server.send_message(em)
        except (smtplib.SMTPException, OSError) as exc:
            raise ChannelError(f"email: {exc}") from exc


class SlackChannel(Channel):
    type = "slack"

    def send(self, msg: Dict[str, Any]) -> None:
        payload = {"text": f"{SEV_EMOJI.get(msg['severity'], '')} {msg['title']}",
                   "attachments": [{"color": SEV_COLOR.get(msg["severity"]), "text": msg["text"],
                                    "footer": f"El Doctor {__version__}", "ts": int(time.time())}]}
        _post_json(_secret(self.conf, "url"), payload)


class TeamsChannel(Channel):
    """Microsoft Teams Workflows / incoming webhook using an Adaptive Card."""
    type = "teams"

    def send(self, msg: Dict[str, Any]) -> None:
        facts = [{"title": k, "value": v} for k, v in (ln.split(": ", 1) for ln in msg["text"].splitlines()
                                                        if ": " in ln and not ln.startswith("  "))][:12]
        card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4", "body": [
                    {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": msg["title"], "wrap": True,
                     "color": "Attention" if msg["severity"] in ("high", "critical") else "Default"},
                    {"type": "FactSet", "facts": facts}]}
        acts = msg.get("actions") or []
        if acts:
            card["body"].append({"type": "TextBlock", "wrap": True, "text": "\n".join(
                f"- {a.get('action')}: {a.get('status')} - {a.get('message')}" for a in acts)})
        payload = {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}
        _post_json(_secret(self.conf, "url"), payload)


class DiscordChannel(Channel):
    type = "discord"

    def send(self, msg: Dict[str, Any]) -> None:
        color = int(SEV_COLOR.get(msg["severity"], "#6c757d")[1:], 16)
        payload = {"username": "El Doctor", "content": msg["title"][:1900],
                   "embeds": [{"title": msg["alert"].get("title", "")[:250], "description": msg["text"][:4000],
                               "color": color}]}
        _post_json(_secret(self.conf, "url"), payload)


class WebhookChannel(Channel):
    """Generic JSON webhook: Shuffle, n8n, Tines, Cortex XSOAR, custom SOAR."""
    type = "webhook"

    def send(self, msg: Dict[str, Any]) -> None:
        payload = {"source": "eldoctor", "version": __version__, "kind": msg["kind"], "title": msg["title"],
                   "severity": msg["severity"], "host": HOSTNAME, "alert": msg["alert"], "actions": msg["actions"],
                   "summary": msg["text"]}
        body = json.dumps(payload, default=str).encode()
        headers = dict(self.conf.get("headers") or {})
        if self.conf.get("secret_env") or self.conf.get("secret"):
            sig = hmac.new(_secret(self.conf, "secret").encode(), body, hashlib.sha256).hexdigest()
            headers["X-ElDoctor-Signature"] = f"sha256={sig}"
        if self.conf.get("token_env"):
            headers["Authorization"] = f"Bearer {_secret(self.conf, 'token')}"
        _post_json(_secret(self.conf, "url"), payload, headers=headers, body=body)


class TheHiveChannel(Channel):
    """Create an alert in TheHive (v5 /api/v1/alert, v4 /api/alert) with observables."""
    type = "thehive"
    SEV = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def send(self, msg: Dict[str, Any]) -> None:
        a = msg["alert"]
        proc = a.get("process") or {}
        observables = []
        if a.get("remote_ip"):
            observables.append({"dataType": "ip", "data": a["remote_ip"], "ioc": True})
        if proc.get("sha256"):
            observables.append({"dataType": "hash", "data": proc["sha256"], "ioc": True})
        if proc.get("exe"):
            observables.append({"dataType": "filename", "data": proc["exe"]})
        observables.append({"dataType": "hostname", "data": a.get("host", HOSTNAME)})
        tags = ["eldoctor", a.get("rule_id", "")] + [f"mitre:{m}" for m in a.get("mitre", [])]
        version = int(self.conf.get("version", 5))
        body: Dict[str, Any] = {"type": "eldoctor", "source": f"eldoctor@{a.get('host', HOSTNAME)}",
                                "sourceRef": a.get("id"), "title": a.get("title"), "description": msg["text"],
                                "severity": self.SEV.get(msg["severity"], 2), "tags": tags, "tlp": 2, "pap": 2}
        if version >= 5:
            body["observables"] = observables
            path = "/api/v1/alert"
        else:
            body["artifacts"] = observables
            path = "/api/alert"
        url = str(self.conf.get("url", "")).rstrip("/") + path
        _post_json(url, body, headers={"Authorization": f"Bearer {_secret(self.conf, 'api_key')}"})


class SyslogChannel(Channel):
    """Forward to a SIEM (Wazuh, Graylog, QRadar, Splunk, Elastic) via syslog, RFC5424 or CEF."""
    type = "syslog"
    CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}

    @staticmethod
    def _cef_escape(v: Any) -> str:
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")

    def format(self, msg: Dict[str, Any]) -> str:
        a = msg["alert"]
        proc = a.get("process") or {}
        sev = msg["severity"]
        pri = 8 * 4 + {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}.get(sev, 4)  # facility auth(4)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        if self.conf.get("format", "rfc5424") == "cef":
            hdr = "|".join(x.replace("|", "\\|") for x in [
                "CEF:0", "ElDoctor", "ElDoctor", __version__, a.get("rule_id", ""), a.get("title", ""),
                str(self.CEF_SEV.get(sev, 5))])
            ext = {"rt": int(a.get("timestamp", time.time()) * 1000), "dhost": a.get("host", HOSTNAME),
                   "src": a.get("remote_ip", ""), "dproc": proc.get("name", ""), "dpid": proc.get("pid", ""),
                   "duser": proc.get("username", ""), "filePath": proc.get("exe", ""),
                   "fileHash": proc.get("sha256", ""), "cs1Label": "mitre", "cs1": ",".join(a.get("mitre", [])),
                   "cs2Label": "actions", "cs2": ";".join(f"{x.get('action')}={x.get('status')}"
                                                          for x in msg.get("actions") or []),
                   "externalId": a.get("id", "")}
            body = hdr + "|" + " ".join(f"{k}={self._cef_escape(v)}" for k, v in ext.items() if v != "")
            return f"<{pri}>1 {ts} {HOSTNAME} eldoctor - - - {body}"
        sd = f'[eldoctor@32473 rule="{a.get("rule_id")}" severity="{sev}" mitre="{",".join(a.get("mitre", []))}"]'
        return f"<{pri}>1 {ts} {HOSTNAME} eldoctor {os.getpid()} ALERT {sd} {msg['title']}"

    def send(self, msg: Dict[str, Any]) -> None:
        line = self.format(msg)
        host, port = self.conf.get("host", "127.0.0.1"), int(self.conf.get("port", 514))
        try:
            if self.conf.get("protocol", "udp") == "tcp":
                with socket.create_connection((host, port), timeout=5) as s:
                    s.sendall(line.encode() + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(line.encode()[:8192], (host, port))
        except OSError as exc:
            raise ChannelError(f"syslog {host}:{port}: {exc}") from exc


CHANNEL_TYPES = {c.type: c for c in (ConsoleChannel, JsonlChannel, EmailChannel, SlackChannel, TeamsChannel,
                                     DiscordChannel, WebhookChannel, TheHiveChannel, SyslogChannel)}


def build_channel(conf: Dict[str, Any]) -> Channel:
    t = conf.get("type")
    if t not in CHANNEL_TYPES:
        raise ValueError(f"unknown notification channel type {t!r} (choose from {sorted(CHANNEL_TYPES)})")
    return CHANNEL_TYPES[t](conf)
