"""Threat-intelligence IOC store and open-feed updater.

IOC types: ip, cidr, domain, sha256, sha1, md5, filename.
Sources  : bundled CSV, user CSV/TXT files, cached feed downloads
           (abuse.ch Feodo Tracker / MalwareBazaar / URLhaus, Emerging Threats ...).

CSV format (header required):  type,value,severity,description,mitre,source
TXT format: one value per line, '#' comments; the type comes from the feed config.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from eldoctor.config import package_data, safe_url, subdir

HEX = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RX = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
URL_HOST_RX = re.compile(r"(?:https?|ftp|stratum\+tcp|stratum\+ssl)://([^/:\s'\"]+)", re.I)


@dataclass
class Indicator:
    type: str
    value: str
    severity: str = "high"
    description: str = ""
    mitre: List[str] = field(default_factory=list)
    source: str = "local"


def normalize(ioc_type: str, value: str) -> Optional[str]:
    t, v = ioc_type.lower().strip(), value.strip()
    if not v:
        return None
    if t == "ip":
        try:
            return str(ipaddress.ip_address(v.split(":")[0] if v.count(":") == 1 else v))
        except ValueError:
            return None
    if t == "cidr":
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            return None
    if t in ("sha256", "sha1", "md5"):
        ln = {"sha256": 64, "sha1": 40, "md5": 32}[t]
        return v.lower() if len(v) == ln and HEX.match(v) else None
    if t == "domain":
        v = v.lower().rstrip(".")
        return v if DOMAIN_RX.match(v) else None
    if t == "filename":
        return v.lower()
    return None


class IOCStore:
    def __init__(self) -> None:
        self.by_type: Dict[str, Dict[str, Indicator]] = {t: {} for t in
                                                         ("ip", "cidr", "domain", "sha256", "sha1", "md5", "filename")}
        self.networks: List[Tuple[ipaddress._BaseNetwork, Indicator]] = []
        self.sources: Dict[str, int] = {}

    def __len__(self) -> int:
        return sum(len(v) for v in self.by_type.values())

    def add(self, ind: Indicator) -> bool:
        norm = normalize(ind.type, ind.value)
        if norm is None:
            return False
        ind.value = norm
        t = ind.type.lower()
        ind.type = t
        self.by_type[t][norm] = ind
        if t == "cidr":
            self.networks.append((ipaddress.ip_network(norm), ind))
        self.sources[ind.source] = self.sources.get(ind.source, 0) + 1
        return True

    # ------------------------------------------------------------------ loading
    def load_csv(self, path: Path, source: Optional[str] = None) -> int:
        n = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            rows = (r for r in fh if r.strip() and not r.lstrip().startswith("#"))
            for row in csv.DictReader(rows):
                mitre = [m.strip() for m in (row.get("mitre") or "").replace(";", ",").split(",") if m.strip()]
                ok = self.add(Indicator(type=row.get("type", ""), value=row.get("value", ""),
                                        severity=(row.get("severity") or "high").lower(),
                                        description=row.get("description", ""), mitre=mitre,
                                        source=source or row.get("source") or path.name))
                n += int(ok)
        return n

    def load_text(self, text: str, ioc_type: str, source: str, severity: str = "high", description: str = "",
                  fmt: str = "text") -> int:
        n = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if fmt == "hosts":   # "127.0.0.1 evil.example"
                parts = line.split()
                if len(parts) < 2:
                    continue
                line = parts[1]
            else:
                line = line.split()[0].split(",")[0]
            n += int(self.add(Indicator(ioc_type, line, severity, description, source=source)))
        return n

    def load_file(self, path: Path) -> int:
        path = Path(path)
        if path.suffix.lower() == ".csv":
            return self.load_csv(path)
        meta_path = path.with_suffix(path.suffix + ".meta.json")
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        return self.load_text(path.read_text(encoding="utf-8", errors="replace"), meta.get("type", "ip"),
                              meta.get("name", path.stem), meta.get("severity", "high"),
                              meta.get("description", ""), meta.get("format", "text"))

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "IOCStore":
        store = cls()
        for f in sorted(package_data("iocs").glob("*.csv")):
            store.load_csv(f)
        for f in (cfg.get("intel", {}).get("ioc_files") or []):
            p = Path(f).expanduser()
            if p.exists():
                store.load_file(p)
        feed_dir = subdir("intel")
        for f in sorted(feed_dir.glob("*.txt")):
            store.load_file(f)
        return store

    # ------------------------------------------------------------------ lookups
    def match_ip(self, ip: str) -> Optional[Indicator]:
        if not ip:
            return None
        hit = self.by_type["ip"].get(ip)
        if hit:
            return hit
        if self.networks:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, ind in self.networks:
                if addr.version == net.version and addr in net:
                    return ind
        return None

    def match_hash(self, digest: str) -> Optional[Indicator]:
        if not digest:
            return None
        d = digest.lower()
        for t in ("sha256", "sha1", "md5"):
            if d in self.by_type[t]:
                return self.by_type[t][d]
        return None

    def match_filename(self, name: str) -> Optional[Indicator]:
        if not name:
            return None
        n = name.lower()
        return self.by_type["filename"].get(n) or (self.by_type["filename"].get(n[:-4]) if n.endswith(".exe") else None)

    def match_domains_in(self, text: str) -> Optional[Indicator]:
        if not text or not self.by_type["domain"]:
            return None
        for host in URL_HOST_RX.findall(text):
            host = host.lower()
            parts = host.split(".")
            for i in range(len(parts) - 1):          # evil.com also matches a.b.evil.com
                hit = self.by_type["domain"].get(".".join(parts[i:]))
                if hit:
                    return hit
        return None

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self), "by_type": {t: len(v) for t, v in self.by_type.items()},
                "sources": dict(self.sources)}


# ---------------------------------------------------------------------- feed updater
def update_feeds(cfg: Dict[str, Any], timeout: int = 30, only: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Download configured open feeds into $ELDOCTOR_HOME/intel/<name>.txt."""
    results = []
    feed_dir = subdir("intel")
    for feed in cfg.get("intel", {}).get("feeds", []) or []:
        name = feed.get("name")
        if only and name not in only:
            continue
        res: Dict[str, Any] = {"name": name, "url": feed.get("url"), "ok": False}
        try:
            headers = {"User-Agent": "ElDoctor-ThreatIntel/2.0"}
            for hk, hv in (feed.get("headers") or {}).items():
                headers[hk] = hv
            req = urllib.request.Request(safe_url(feed["url"]), headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (configured URL)
                raw = resp.read(50 * 1024 * 1024)
            text = raw.decode("utf-8", "replace")
            probe = IOCStore()
            count = probe.load_text(text, feed.get("type", "ip"), name, feed.get("severity", "high"),
                                    feed.get("description", ""), feed.get("format", "text"))
            if count == 0:
                raise ValueError("feed returned no valid indicators")
            (feed_dir / f"{name}.txt").write_text(text, encoding="utf-8")
            (feed_dir / f"{name}.txt.meta.json").write_text(json.dumps({
                "name": name, "type": feed.get("type", "ip"), "severity": feed.get("severity", "high"),
                "description": feed.get("description", ""), "format": feed.get("format", "text"),
                "url": feed.get("url"), "updated": time.time(), "count": count}), encoding="utf-8")
            res.update(ok=True, count=count)
        except Exception as exc:  # network errors, HTTP errors, parse errors
            res["error"] = f"{type(exc).__name__}: {exc}"
        results.append(res)
    return results


def feed_status() -> List[Dict[str, Any]]:
    out = []
    for meta in sorted(subdir("intel").glob("*.meta.json")):
        try:
            out.append(json.loads(meta.read_text()))
        except ValueError:
            pass
    return out


def add_local_ioc(ioc_type: str, value: str, severity: str = "high", description: str = "",
                  mitre: str = "") -> Path:
    if normalize(ioc_type, value) is None:
        raise ValueError(f"invalid {ioc_type}: {value}")
    path = subdir("intel") / "local_iocs.csv"
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["type", "value", "severity", "description", "mitre", "source"])
        w.writerow([ioc_type, value, severity, description, mitre, "local"])
    return path
