"""Log collection and normalisation.

Sources
  * files   - tail -f semantics with rotation handling (auth.log, secure, syslog ...)
  * journald- `journalctl -f -o json` (Linux/systemd)
  * syslog  - built-in UDP/TCP receiver (RFC3164 / RFC5424) for remote devices
  * windows - Windows Event Log through wevtutil (Security, System, Sysmon, PowerShell)

Every source produces the same normalised *log event* dict consumed by the
detection engine (stateful log rules + Sigma rules).
"""
from __future__ import annotations

import json
import os
import queue
import re
import socketserver
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from eldoctor.config import system_tool

# --------------------------------------------------------------------------- parsing
RE_5424 = re.compile(r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
                     r"(?P<sd>-|(?:\[.*?\])+) ?(?P<msg>.*)$")
RE_3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?:(?P<host>\S+) )?"
                     r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
RE_ISO = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>\d{4}-\d\d-\d\dT\S+) (?P<host>\S+) (?P<prog>[^\s:\[]+)"
                    r"(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")

IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:.]*)"
AUTH_PATTERNS = [
    ("ssh_failed", re.compile(r"Failed (?P<method>password|publickey|none|keyboard-interactive/pam) for "
                              r"(?:invalid user )?(?P<user>\S+) from " + IP + r"(?: port (?P<port>\d+))?")),
    ("ssh_failed", re.compile(r"Invalid user (?P<user>\S*) from " + IP)),
    ("ssh_failed", re.compile(r"Connection closed by authenticating user (?P<user>\S+) " + IP)),
    ("ssh_success", re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP + r"(?: port (?P<port>\d+))?")),
    ("sudo_failed", re.compile(r"(?P<user>\S+) : (?:\d+ )?incorrect password attempts?")),
    ("sudo_failed", re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?user=(?P<user>\S+)")),
    ("sudo_command", re.compile(r"(?P<user>\S+) : .*?TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)")),
    ("su_failed", re.compile(r"(?:FAILED SU|pam_unix\(su(?:-l)?:auth\): authentication failure).*?(?:user=|for )(?P<user>\S+)")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("user_deleted", re.compile(r"delete user '(?P<user>[^']+)'")),
]


def parse_auth_message(program: str, message: str) -> Dict[str, Any]:
    for etype, rx in AUTH_PATTERNS:
        m = rx.search(message)
        if m:
            fields = {k: v for k, v in m.groupdict().items() if v is not None}
            if "ip" in fields:
                fields["src_ip"] = fields.pop("ip")
            return {"event_type": etype, "fields": fields}
    return {"event_type": "", "fields": {}}


def parse_syslog_line(line: str, source: str = "") -> Dict[str, Any]:
    line = line.rstrip("\r\n")
    ev: Dict[str, Any] = {"kind": "log", "source": source, "product": "linux", "raw": line,
                          "message": line, "program": "", "host": "", "pid": None, "ts": time.time()}
    m = RE_5424.match(line)
    if m:
        ev.update(program=m.group("app") if m.group("app") != "-" else "", host=m.group("host"),
                  message=m.group("msg"), pid=None if m.group("procid") == "-" else m.group("procid"))
    else:
        m = RE_ISO.match(line) or RE_3164.match(line)
        if m:
            ev.update(program=m.group("prog"), host=m.group("host") or "", message=m.group("msg"), pid=m.group("pid"))
    prog = (ev["program"] or "").lower()
    ev["service"] = "sshd" if prog.startswith("sshd") else prog
    ev.update(parse_auth_message(prog, ev["message"]))
    return ev


# --------------------------------------------------------------------------- file tailer
class FileTailer:
    def __init__(self, paths: List[str], read_existing: bool = False, parser=None) -> None:
        self.state: Dict[str, Dict[str, int]] = {}
        self.paths = [p for p in paths]
        self.parser = parser or parse_syslog_line
        for p in self.paths:
            self._init(p, read_existing)

    def _init(self, path: str, read_existing: bool) -> None:
        try:
            st = os.stat(path)
            self.state[path] = {"ino": st.st_ino, "pos": 0 if read_existing else st.st_size}
        except OSError:
            self.state[path] = {"ino": -1, "pos": 0}

    @property
    def readable(self) -> List[str]:
        return [p for p in self.paths if os.access(p, os.R_OK)]

    def poll(self, max_lines: int = 5000) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for path in self.paths:
            st_ = self.state[path]
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_ino != st_["ino"] or st.st_size < st_["pos"]:  # rotated / truncated / created
                st_["ino"], st_["pos"] = st.st_ino, 0
            if st.st_size == st_["pos"]:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(st_["pos"])
                    while len(out) < max_lines:
                        line = fh.readline()
                        if not line:
                            break
                        if not line.endswith("\n"):   # partial line - wait for the rest
                            break
                        st_["pos"] = fh.tell()
                        if line.strip():
                            out.append(self.parser(line, f"file:{path}"))
            except OSError:
                continue
        return out


# --------------------------------------------------------------------------- auditd
RE_AUDIT = re.compile(r"type=(?P<type>\w+) msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\): ?(?P<body>.*)")
RE_KV = re.compile(r'([\w\[\]]+)=("(?:[^"\\]|\\.)*"|\S+)')
RE_HEX = re.compile(r"^[0-9A-Fa-f]+$")
EXEC_SYSCALLS = {"59", "322", "11", "358"}   # execve/execveat on x86_64, execve/execveat on i386


def _audit_value(v: str) -> str:
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    if v != "(null)" and len(v) % 2 == 0 and len(v) >= 2 and RE_HEX.match(v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ").strip()
        except ValueError:
            return v
    return v


def _uid_name(uid: str) -> str:
    try:
        import pwd
        return pwd.getpwuid(int(uid)).pw_name
    except (ImportError, KeyError, ValueError):
        return uid


class AuditParser:
    """Turns Linux audit EXECVE/SYSCALL/CWD/PROCTITLE records into process_creation events.

    Needs an audit rule such as (installed by the Linux deployment bundle):
        -a always,exit -F arch=b64 -S execve -k eldoctor_exec
    This sees *every* exec, including processes that live for milliseconds,
    which /proc polling can miss.
    """

    def __init__(self, max_age: float = 2.0) -> None:
        self.buf: Dict[str, Dict[str, Any]] = {}
        self.max_age = max_age

    def feed(self, line: str) -> List[Dict[str, Any]]:
        m = RE_AUDIT.search(line)
        if not m:
            return []
        serial, rtype = m.group("serial"), m.group("type")
        out: List[Dict[str, Any]] = []
        if rtype == "EOE":
            ev = self._build(serial)
            return [ev] if ev else []
        ent = self.buf.setdefault(serial, {"ts": float(m.group("ts")), "seen": time.time(), "rec": {}})
        kv = {k: v for k, v in RE_KV.findall(m.group("body"))}
        ent["rec"].setdefault(rtype, {}).update(kv)
        out.extend(self.flush(older_than=self.max_age, keep=serial))
        return out

    def flush(self, older_than: float = 0.0, keep: str = "") -> List[Dict[str, Any]]:
        now = time.time()
        out = []
        for serial in [s for s, e in self.buf.items() if s != keep and now - e["seen"] >= older_than]:
            ev = self._build(serial)
            if ev:
                out.append(ev)
        return out

    def _build(self, serial: str) -> Optional[Dict[str, Any]]:
        ent = self.buf.pop(serial, None)
        if not ent:
            return None
        rec = ent["rec"]
        sc, ex = rec.get("SYSCALL", {}), rec.get("EXECVE")
        if not ex and sc.get("syscall") not in EXEC_SYSCALLS:
            return None
        if sc.get("success") == "no":
            return None
        args: List[str] = []
        if ex:
            argc = int(ex.get("argc", "0") or 0)
            for i in range(argc):
                if f"a{i}" in ex:
                    args.append(_audit_value(ex[f"a{i}"]))
                else:   # long argument split as a1[0]=.. a1[1]=..
                    parts = [_audit_value(v) for k, v in sorted(
                        ((k, v) for k, v in ex.items() if k.startswith(f"a{i}[")),
                        key=lambda kv: int(kv[0].split("[")[1].rstrip("]")))]
                    args.append("".join(parts))
        elif rec.get("PROCTITLE", {}).get("proctitle"):
            args = _audit_value(rec["PROCTITLE"]["proctitle"]).split(" ")
        exe = _audit_value(sc.get("exe", "")) if sc.get("exe") else ""
        cmd = " ".join(args)
        cwd = _audit_value(rec.get("CWD", {}).get("cwd", "")) if rec.get("CWD") else ""
        pid = int(sc.get("pid", "0") or 0)
        ppid = int(sc.get("ppid", "0") or 0)
        user = _uid_name(sc.get("uid", "")) if sc.get("uid") else ""
        name = _audit_value(sc.get("comm", "")) if sc.get("comm") else exe.rsplit("/", 1)[-1]
        fields = {"Image": exe, "CommandLine": cmd, "ProcessId": pid, "ParentProcessId": ppid, "User": user,
                  "CurrentDirectory": cwd, "auid": _uid_name(sc.get("auid", "")) if sc.get("auid") else "",
                  "key": _audit_value(sc.get("key", "")) if sc.get("key") else ""}
        return {"kind": "log", "source": "auditd", "product": "linux", "service": "auditd",
                "category": "process_creation", "event_type": "process_creation", "ts": ent["ts"],
                "raw": cmd, "message": f"execve pid={pid} ppid={ppid} exe={exe} cmd={cmd}", "program": name,
                "host": "", "pid": pid, "fields": fields,
                "process": {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": args,
                            "username": user, "cwd": cwd, "create_time": 0.0}}


class AuditdCollector:
    def __init__(self, path: str = "/var/log/audit/audit.log", read_existing: bool = False) -> None:
        self.parser = AuditParser()
        self.tailer = FileTailer([path], read_existing, parser=lambda line, src: {"raw": line})
        self.path = path

    @staticmethod
    def available(path: str = "/var/log/audit/audit.log") -> bool:
        return os.access(path, os.R_OK)

    def poll(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for rec in self.tailer.poll():
            out.extend(self.parser.feed(rec["raw"]))
        out.extend(self.parser.flush(older_than=self.parser.max_age))
        return out


# --------------------------------------------------------------------------- journald
class JournaldTailer(threading.Thread):
    def __init__(self, q: "queue.Queue[Dict[str, Any]]") -> None:
        super().__init__(daemon=True, name="journald")
        self.q = q
        self.proc: Optional[subprocess.Popen] = None
        self._stop = threading.Event()

    @staticmethod
    def available() -> bool:
        if not system_tool("journalctl"):
            return False
        try:
            out = subprocess.run([system_tool("journalctl"), "-n", "1", "-o", "json", "--no-pager"], capture_output=True,
                                 text=True, timeout=5)
            return out.returncode == 0 and out.stdout.strip().startswith("{")
        except (OSError, subprocess.SubprocessError):
            return False

    def run(self) -> None:
        try:
            self.proc = subprocess.Popen([system_tool("journalctl"), "-f", "-n", "0", "-o", "json", "--no-pager"],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return
        assert self.proc.stdout
        for line in self.proc.stdout:
            if self._stop.is_set():
                break
            try:
                j = json.loads(line)
            except ValueError:
                continue
            msg = j.get("MESSAGE") or ""
            if isinstance(msg, list):
                msg = bytes(msg).decode("utf-8", "replace")
            prog = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ""
            ev = {"kind": "log", "source": "journald", "product": "linux", "raw": msg, "message": msg,
                  "program": prog, "host": j.get("_HOSTNAME", ""), "pid": j.get("_PID"), "ts": time.time(),
                  "service": "sshd" if prog.startswith("sshd") else prog.lower()}
            ev.update(parse_auth_message(prog, msg))
            self.q.put(ev)

    def stop(self) -> None:
        self._stop.set()
        if self.proc:
            self.proc.terminate()


# --------------------------------------------------------------------------- syslog receiver
class SyslogListener:
    """Minimal syslog server so firewalls/servers/other agents can forward logs."""

    def __init__(self, q: "queue.Queue[Dict[str, Any]]", host: str = "127.0.0.1", port: int = 5514,
                 protocol: str = "udp") -> None:
        self.q, self.host, self.port, self.protocol = q, host, port, protocol.lower()
        self.server: Optional[socketserver.BaseServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        outer = self

        class UDPHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request[0]
                for line in data.decode("utf-8", "replace").splitlines():
                    if line.strip():
                        ev = parse_syslog_line(line, f"syslog:{self.client_address[0]}")
                        ev["sender"] = self.client_address[0]
                        outer.q.put(ev)

        class TCPHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                for raw in self.rfile:
                    line = raw.decode("utf-8", "replace").strip()
                    if line:
                        ev = parse_syslog_line(line, f"syslog:{self.client_address[0]}")
                        ev["sender"] = self.client_address[0]
                        outer.q.put(ev)

        if self.protocol == "tcp":
            socketserver.ThreadingTCPServer.allow_reuse_address = True
            self.server = socketserver.ThreadingTCPServer((self.host, self.port), TCPHandler)
        else:
            self.server = socketserver.ThreadingUDPServer((self.host, self.port), UDPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="syslog")
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


# --------------------------------------------------------------------------- windows event log
EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
WIN_EVENT_TYPES = {
    4625: "logon_failed", 4624: "logon_success", 4720: "user_created", 4732: "group_member_added",
    1102: "log_cleared", 104: "log_cleared", 7045: "service_installed", 4688: "process_creation",
    4104: "powershell_scriptblock",
}


def parse_windows_events_xml(xml_text: str, channel: str = "") -> List[Dict[str, Any]]:
    xml_text = xml_text.strip()
    if not xml_text or "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return []          # never let a DTD reach the parser (entity-expansion / XXE style abuse)
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError:
        return []
    out = []
    for ev in root.findall(f"{EVT_NS}Event"):
        sysn = ev.find(f"{EVT_NS}System")
        if sysn is None:
            continue
        eid_txt = (sysn.findtext(f"{EVT_NS}EventID") or "0").strip()
        eid = int(eid_txt) if eid_txt.isdigit() else 0
        prov = sysn.find(f"{EVT_NS}Provider")
        provider = prov.get("Name", "") if prov is not None else ""
        chan = sysn.findtext(f"{EVT_NS}Channel") or channel
        rec = int((sysn.findtext(f"{EVT_NS}EventRecordID") or "0").strip() or 0)
        fields: Dict[str, Any] = {"EventID": eid, "Channel": chan, "Provider_Name": provider,
                                  "Computer": sysn.findtext(f"{EVT_NS}Computer") or ""}
        for d in ev.iter(f"{EVT_NS}Data"):
            name = d.get("Name")
            if name:
                fields[name] = d.text or ""
        e: Dict[str, Any] = {"kind": "log", "source": f"wineventlog:{chan}", "product": "windows",
                             "service": _win_service(chan, provider), "raw": "", "program": provider,
                             "host": fields["Computer"], "pid": None, "ts": time.time(), "record_id": rec,
                             "event_id": eid, "fields": fields, "event_type": "", "message": ""}
        is_sysmon = "sysmon" in chan.lower()
        if is_sysmon and eid == 1:
            e["category"], e["event_type"] = "process_creation", "process_creation"
            e["process"] = _win_process(fields.get("ProcessId"), fields.get("Image", ""), fields.get("CommandLine", ""),
                                        fields.get("User", ""), fields.get("ParentProcessId"))
        elif is_sysmon and eid == 3:
            e["category"], e["event_type"] = "network_connection", "network_connection"
        elif eid == 4688 and chan.lower() == "security":
            e["category"], e["event_type"] = "process_creation", "process_creation"
            fields.setdefault("Image", fields.get("NewProcessName", ""))
            fields.setdefault("ParentImage", fields.get("ParentProcessName", ""))
            e["process"] = _win_process(fields.get("NewProcessId"), fields.get("Image", ""),
                                        fields.get("CommandLine", ""), fields.get("SubjectUserName", ""),
                                        fields.get("ProcessId"))
        else:
            e["event_type"] = WIN_EVENT_TYPES.get(eid, "")
        # common normalised names used by log rules
        if fields.get("IpAddress") and fields["IpAddress"] not in ("-", "::1", "127.0.0.1"):
            fields["src_ip"] = fields["IpAddress"]
        if fields.get("TargetUserName"):
            fields["user"] = fields["TargetUserName"]
        e["message"] = " ".join(f"{k}={v}" for k, v in fields.items() if v)[:2000]
        e["raw"] = e["message"]
        out.append(e)
    return out


def _pid(v: Any) -> int:
    try:
        v = str(v or "0").strip()
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return 0


def _win_process(pid: Any, image: str, cmdline: str, user: str, ppid: Any) -> Dict[str, Any]:
    return {"pid": _pid(pid), "ppid": _pid(ppid), "name": image.replace("/", "\\").rsplit("\\", 1)[-1],
            "exe": image, "cmdline": cmdline.split(" ") if cmdline else [], "username": user, "create_time": 0.0}


def _win_service(channel: str, provider: str) -> str:
    c = channel.lower()
    if "sysmon" in c:
        return "sysmon"
    if "powershell" in c:
        return "powershell"
    return c


class WindowsEventCollector:
    def __init__(self, channels: List[str]) -> None:
        self.channels = channels
        self.last: Dict[str, int] = {}
        self.wevtutil = system_tool("wevtutil")
        for ch in channels:
            self.last[ch] = self._latest(ch)

    @staticmethod
    def available() -> bool:
        return sys.platform.startswith("win") and bool(system_tool("wevtutil"))

    def _run(self, args: List[str]) -> str:
        try:
            if not self.wevtutil:
                return ""
            r = subprocess.run([self.wevtutil] + args, capture_output=True, text=True, timeout=15)
            return r.stdout if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    def _latest(self, channel: str) -> int:
        evs = parse_windows_events_xml(self._run(["qe", channel, "/rd:true", "/c:1", "/f:xml"]), channel)
        return evs[0]["record_id"] if evs else 0

    def poll(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for ch in self.channels:
            q = f"*[System[EventRecordID>{self.last.get(ch, 0)}]]"
            evs = parse_windows_events_xml(self._run(["qe", ch, f"/q:{q}", "/c:500", "/f:xml"]), ch)
            for e in evs:
                self.last[ch] = max(self.last.get(ch, 0), e["record_id"])
            out.extend(evs)
        return out


# --------------------------------------------------------------------------- manager
class LogManager:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        lc = cfg.get("logs", {})
        self.q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=100000)
        self.file_tailer = FileTailer(lc.get("files", []), bool(lc.get("read_existing")))
        self.sources: List[str] = [f"file:{p}" for p in self.file_tailer.readable]
        self.journald: Optional[JournaldTailer] = None
        self.syslog: Optional[SyslogListener] = None
        self.windows: Optional[WindowsEventCollector] = None
        jd = lc.get("journald", "auto")
        if jd is True or (jd == "auto" and JournaldTailer.available()):
            self.journald = JournaldTailer(self.q)
            self.sources.append("journald")
        sl = lc.get("syslog_listener", {}) or {}
        if sl.get("enabled"):
            self.syslog = SyslogListener(self.q, sl.get("host", "127.0.0.1"), int(sl.get("port", 5514)),
                                         sl.get("protocol", "udp"))
            self.sources.append(f"syslog:{sl.get('protocol', 'udp')}/{sl.get('host')}:{sl.get('port')}")
        self.auditd: Optional[AuditdCollector] = None
        ad, ad_path = lc.get("auditd", "auto"), lc.get("auditd_path", "/var/log/audit/audit.log")
        if ad is True or (ad == "auto" and AuditdCollector.available(ad_path)):
            self.auditd = AuditdCollector(ad_path, bool(lc.get("read_existing")))
            self.sources.append(f"auditd:{ad_path}")
        we = lc.get("windows_eventlog", "auto")
        if we is True or (we == "auto" and WindowsEventCollector.available()):
            self.windows = WindowsEventCollector(lc.get("windows_channels", []))
            self.sources.append("windows-eventlog")

    def start(self) -> List[str]:
        """Start threaded sources. A source that fails (e.g. port in use) is disabled, never fatal."""
        problems = []
        if self.journald:
            self.journald.start()
        if self.syslog:
            try:
                self.syslog.start()
            except OSError as exc:
                problems.append(f"syslog listener {self.syslog.host}:{self.syslog.port} disabled: {exc}")
                self.sources = [s for s in self.sources if not s.startswith("syslog:")]
                self.syslog = None
        return problems

    def stop(self) -> None:
        if self.journald:
            self.journald.stop()
        if self.syslog:
            self.syslog.stop()

    def poll(self) -> List[Dict[str, Any]]:
        events = self.file_tailer.poll()
        if self.auditd:
            events.extend(self.auditd.poll())
        if self.windows:
            events.extend(self.windows.poll())
        while True:
            try:
                events.append(self.q.get_nowait())
            except queue.Empty:
                break
        return events
