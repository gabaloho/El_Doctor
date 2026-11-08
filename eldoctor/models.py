"""Core data structures shared across El Doctor components."""
from __future__ import annotations

import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get(str(sev).lower(), 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


HOSTNAME = socket.gethostname()


@dataclass
class ProcessInfo:
    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    username: str = ""
    create_time: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    rss: int = 0
    status: str = ""
    parent_name: str = ""
    parent_exe: str = ""
    parent_cmdline: str = ""
    cwd: str = ""
    sha256: str = ""
    exe_deleted: bool = False
    num_threads: int = 0

    @property
    def key(self) -> str:
        """Unique identity (pid + start time) that survives PID reuse."""
        return f"{self.pid}:{self.create_time:.2f}"

    @property
    def cmdline_str(self) -> str:
        return " ".join(self.cmdline)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cmdline"] = self.cmdline_str
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProcessInfo":
        d = dict(d or {})
        cmd = d.get("cmdline", [])
        if isinstance(cmd, str):
            cmd = cmd.split(" ") if cmd else []
        d["cmdline"] = cmd
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str = "medium"
    description: str = ""
    source: str = "heuristic"          # heuristic | sigma | ioc | yara | log | system
    mitre: List[str] = field(default_factory=list)
    process: Optional[Dict[str, Any]] = None
    remote_ip: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    dedup_key: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    host: str = HOSTNAME

    def __post_init__(self) -> None:
        if not self.dedup_key:
            ent = ""
            if self.process:
                ent = f"{self.process.get('pid')}:{float(self.process.get('create_time') or 0):.2f}"
            elif self.remote_ip:
                ent = self.remote_ip
            self.dedup_key = f"{self.rule_id}|{ent}"

    @property
    def pid(self) -> Optional[int]:
        return int(self.process["pid"]) if self.process and "pid" in self.process else None

    def to_dict(self) -> Dict[str, Any]:
        from eldoctor.mitre import describe  # local import to avoid cycles

        d = asdict(self)
        d["mitre_details"] = describe(self.mitre)
        d["time_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.timestamp))
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Alert":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def short(self) -> str:
        who = ""
        if self.process:
            who = f" {self.process.get('name')}[{self.process.get('pid')}]"
        elif self.remote_ip:
            who = f" {self.remote_ip}"
        mitre = f" ({','.join(self.mitre)})" if self.mitre else ""
        return f"[{self.severity.upper()}] {self.rule_id} {self.title}{who}{mitre}"


@dataclass
class ActionResult:
    action: str
    status: str            # success | failed | skipped | blocked | dry_run | pending_approval | would_run
    message: str = ""
    target: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.status in ("success", "dry_run", "would_run", "skipped")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
