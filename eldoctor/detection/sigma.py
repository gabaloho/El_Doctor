"""Native Sigma rule evaluator (https://github.com/SigmaHQ/sigma).

Supports the parts of the Sigma specification that matter for host telemetry:

* detection maps (AND), lists of maps (OR), value lists (OR), keyword lists
* modifiers: contains, startswith, endswith, all, re (+ i/m/s), cidr, windash,
  base64, base64offset, exists, cased, gt/gte/lt/lte, wide/utf16le (with base64)
* wildcards ``*`` / ``?`` and escapes in plain values, case-insensitive by default
* conditions: and / or / not / parentheses / ``1 of x*`` / ``all of x*`` /
  ``any of them`` / ``all of them`` and condition lists
* logsource matching on category / product / service

Rules using aggregations (``| count() by ...``) or correlation meta-rules are
reported as unsupported and skipped rather than mis-evaluated.

You can point ``detection.sigma_dirs`` at a SigmaHQ checkout (e.g.
``rules/linux/process_creation`` or ``rules/windows/process_creation``).
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import yaml

from eldoctor.mitre import from_sigma_tags

LEVEL_TO_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high",
                     "critical": "critical"}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "windash",
                       "base64", "base64offset", "exists", "cased", "gt", "gte", "lt", "lte", "wide",
                       "utf16le", "utf16", "utf16be", "expand"}


class SigmaError(Exception):
    pass


# --------------------------------------------------------------------------- value matchers
def _wildcard_to_regex(value: str) -> str:
    """Sigma wildcard string -> regex.  '*' any, '?' one char, '\\*' literal."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _b64_variants(s: bytes, offset: bool) -> List[str]:
    if not offset:
        return [base64.b64encode(s).decode()]
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + s).decode()
        start = (0, 2, 3)[i]
        end_trim = (0, 3, 2)[(len(s) + i) % 3]
        out.append(enc[start: len(enc) - end_trim] if end_trim else enc[start:])
    return out


def _windash_variants(s: str) -> List[str]:
    if "-" not in s and "/" not in s:
        return [s]
    variants = {s}
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        variants.add(re.sub(r"(^|\s)[-/](?=\w)", lambda m, d=dash: m.group(1) + d, s))
    return list(variants)


class FieldMatcher:
    """Compiled ``Field|mod1|mod2: value(s)`` item."""

    def __init__(self, field_spec: Optional[str], values: Any) -> None:
        parts = field_spec.split("|") if field_spec else [None]
        self.field = parts[0]
        self.mods = [m.lower() for m in parts[1:]]
        unknown = set(self.mods) - SUPPORTED_MODIFIERS
        if unknown:
            raise SigmaError(f"unsupported modifier(s): {sorted(unknown)}")
        if not isinstance(values, list):
            values = [values]
        self.require_all = "all" in self.mods
        self.cased = "cased" in self.mods
        self.checks: List[Callable[[Any], bool]] = []
        self.null_check: Optional[bool] = None
        self.exists: Optional[bool] = None
        for v in values:
            self._compile(v)

    def _compile(self, v: Any) -> None:
        mods = self.mods
        if "exists" in mods:
            self.exists = bool(v) if not isinstance(v, str) else v.lower() == "true"
            return
        if v is None:
            self.null_check = True
            return
        for cmp_op in ("gt", "gte", "lt", "lte"):
            if cmp_op in mods:
                num = float(v)
                ops = {"gt": lambda x, n=num: x > n, "gte": lambda x, n=num: x >= n,
                       "lt": lambda x, n=num: x < n, "lte": lambda x, n=num: x <= n}
                f = ops[cmp_op]
                self.checks.append(lambda x, f=f: _num(x) is not None and f(_num(x)))
                return
        if "cidr" in mods:
            net = ipaddress.ip_network(str(v), strict=False)

            def chk(x: Any, net=net) -> bool:
                try:
                    return ipaddress.ip_address(str(x)) in net
                except ValueError:
                    return False
            self.checks.append(chk)
            return
        flags = 0 if self.cased else re.IGNORECASE
        if "re" in mods:
            rflags = 0
            if "i" in mods:
                rflags |= re.IGNORECASE
            if "m" in mods:
                rflags |= re.MULTILINE
            if "s" in mods:
                rflags |= re.DOTALL
            rx = re.compile(str(v), rflags)
            self.checks.append(lambda x, rx=rx: rx.search(str(x)) is not None)
            return
        if isinstance(v, (int, float)) and not isinstance(v, bool) and not any(
                m in mods for m in ("contains", "startswith", "endswith")):
            self.checks.append(lambda x, v=v: str(x) == str(v))
            return
        s = str(v)
        candidates = [s]
        if "windash" in mods:
            candidates = _windash_variants(s)
        if "base64" in mods or "base64offset" in mods:
            enc = "utf-16-le" if ("wide" in mods or "utf16le" in mods or "utf16" in mods) else (
                "utf-16-be" if "utf16be" in mods else "utf-8")
            candidates = [c for cand in candidates for c in _b64_variants(cand.encode(enc), "base64offset" in mods)]
            # base64 output is literal - escape wildcard characters
            candidates = [c.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?") for c in candidates]
        regs = []
        for cand in candidates:
            body = _wildcard_to_regex(cand)
            if "contains" in mods or (self.field is None and not ({"startswith", "endswith"} & set(mods))):
                pattern = body  # keywords are unbound (substring) matches
            elif "startswith" in mods:
                pattern = "^" + body
            elif "endswith" in mods:
                pattern = body + "$"
            else:
                pattern = "^" + body + "$"
            regs.append(re.compile(pattern, flags | re.DOTALL))
        self.checks.append(lambda x, regs=regs: any(r.search(str(x)) for r in regs))

    def match(self, event: Dict[str, Any], keyword_fields: Iterable[str]) -> bool:
        if self.field is None:   # keyword search over message-like fields
            texts = [str(event.get(f, "")) for f in keyword_fields if event.get(f)]
            if not texts:
                return False
            results = [any(chk(t) for t in texts) for chk in self.checks]
            return all(results) if self.require_all else any(results)
        present = self.field in event and event[self.field] not in (None, "")
        if self.exists is not None:
            return present == self.exists
        if self.null_check and not self.checks:
            return not present
        if not present:
            return bool(self.null_check)
        value = event[self.field]
        vals = value if isinstance(value, list) else [value]
        results = [any(chk(x) for x in vals) for chk in self.checks]
        if not results:
            return False
        return all(results) if self.require_all else any(results)


def _num(x: Any) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- search identifiers
class Search:
    """A named detection item (e.g. ``selection``)."""

    def __init__(self, name: str, body: Any) -> None:
        self.name = name
        # list of alternatives; each alternative is a list of FieldMatchers that must all match
        self.alternatives: List[List[FieldMatcher]] = []
        if isinstance(body, dict):
            self.alternatives.append([FieldMatcher(k, v) for k, v in body.items()])
        elif isinstance(body, list):
            if all(isinstance(x, dict) for x in body):
                for m in body:
                    self.alternatives.append([FieldMatcher(k, v) for k, v in m.items()])
            elif all(not isinstance(x, (dict, list)) for x in body):
                self.alternatives.append([FieldMatcher(None, body)])
            else:
                raise SigmaError(f"mixed list in search '{name}'")
        elif isinstance(body, str):
            self.alternatives.append([FieldMatcher(None, [body])])
        else:
            raise SigmaError(f"unsupported search body in '{name}'")

    def match(self, event: Dict[str, Any], keyword_fields: Iterable[str]) -> bool:
        return any(all(fm.match(event, keyword_fields) for fm in alt) for alt in self.alternatives)


# --------------------------------------------------------------------------- condition parser
TOKEN_RX = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+)")


def _tokenize(cond: str) -> List[str]:
    if "|" in cond:
        raise SigmaError("aggregation conditions ('|') are not supported")
    pos, toks = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = TOKEN_RX.match(cond, pos)
        if not m:
            raise SigmaError(f"bad condition near: {cond[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
    return toks


class ConditionParser:
    def __init__(self, cond: str, names: List[str]) -> None:
        self.toks = _tokenize(cond)
        self.i = 0
        self.names = names

    def peek(self) -> Optional[str]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise SigmaError("unexpected end of condition")
        self.i += 1
        return t

    def parse(self) -> Callable[[Dict[str, bool]], bool]:
        node = self._or()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token {self.peek()!r}")
        return node

    def _or(self):
        left = self._and()
        while self.peek() and self.peek().lower() == "or":
            self.take()
            right = self._and()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def _and(self):
        left = self._not()
        while self.peek() and self.peek().lower() == "and":
            self.take()
            right = self._not()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def _not(self):
        if self.peek() and self.peek().lower() == "not":
            self.take()
            inner = self._not()
            return lambda r: not inner(r)
        return self._atom()

    def _atom(self):
        t = self.take()
        if t == "(":
            node = self._or()
            if self.take() != ")":
                raise SigmaError("missing ')'")
            return node
        low = t.lower()
        if low in ("1", "any", "all") and self.peek() and self.peek().lower() == "of":
            self.take()
            target = self.take()
            if target.lower() == "them":
                names = [n for n in self.names if not n.startswith("_")]
            else:
                names = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise SigmaError(f"'{target}' matches no search identifier")
            if low == "all":
                return lambda r, names=names: all(r[n] for n in names)
            return lambda r, names=names: any(r[n] for n in names)
        if t not in self.names:
            raise SigmaError(f"unknown search identifier {t!r}")
        return lambda r, t=t: r[t]


# --------------------------------------------------------------------------- rule
@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    logsource: Dict[str, str]
    tags: List[str]
    searches: Dict[str, Search]
    conditions: List[Callable[[Dict[str, bool]], bool]]
    path: str = ""
    falsepositives: List[str] = field(default_factory=list)
    status: str = ""

    @property
    def severity(self) -> str:
        return LEVEL_TO_SEVERITY.get(self.level.lower(), "medium")

    @property
    def mitre(self) -> List[str]:
        return from_sigma_tags(self.tags)

    def applies_to(self, event: Dict[str, Any], platform: str) -> bool:
        ls = self.logsource
        cat, prod, svc = ls.get("category"), ls.get("product"), ls.get("service")
        ev_prod = event.get("product") or platform
        if prod and prod.lower() != str(ev_prod).lower():
            return False
        if cat and cat.lower() != str(event.get("category", "")).lower():
            return False
        if svc:
            ev_svc = str(event.get("service", "")).lower()
            svc = svc.lower()
            aliases = {"auth": {"sshd", "sudo", "su", "login", "auth", "useradd", "passwd", "pam"},
                       "syslog": {"*"}}
            if svc in aliases:
                if "*" not in aliases[svc] and ev_svc not in aliases[svc]:
                    return False
            elif svc != ev_svc:
                return False
        if not cat and not svc and event.get("category"):
            return False   # keyword/log rules don't run on structured process events
        return True

    def match(self, event: Dict[str, Any], keyword_fields: Iterable[str] = ("message", "raw", "CommandLine")) -> bool:
        results = {name: s.match(event, keyword_fields) for name, s in self.searches.items()}
        return any(c(results) for c in self.conditions)


def parse_rule(doc: Dict[str, Any], path: str = "") -> SigmaRule:
    if not isinstance(doc, dict) or "detection" not in doc:
        raise SigmaError("not a Sigma detection rule")
    if "correlation" in doc:
        raise SigmaError("correlation rules are not supported")
    det = dict(doc["detection"])
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if cond is None:
        raise SigmaError("missing condition")
    searches = {name: Search(name, body) for name, body in det.items()}
    conds = cond if isinstance(cond, list) else [cond]
    compiled = [ConditionParser(str(c), list(searches)).parse() for c in conds]
    return SigmaRule(
        id=str(doc.get("id") or Path(path).stem),
        title=str(doc.get("title", "Sigma rule")),
        level=str(doc.get("level", "medium")),
        description=str(doc.get("description", "")).strip(),
        logsource={k: str(v) for k, v in (doc.get("logsource") or {}).items() if isinstance(v, (str, int))},
        tags=[str(t) for t in doc.get("tags") or []],
        searches=searches,
        conditions=compiled,
        path=path,
        falsepositives=[str(x) for x in (doc.get("falsepositives") or [])],
        status=str(doc.get("status", "")),
    )


def load_rules(dirs: Iterable[Path]) -> Tuple[List[SigmaRule], List[Tuple[str, str]]]:
    rules, errors = [], []
    for d in dirs:
        d = Path(d)
        files = [d] if d.is_file() else sorted(list(d.rglob("*.yml")) + list(d.rglob("*.yaml")))
        for f in files:
            try:
                docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                errors.append((str(f), f"yaml: {exc}"))
                continue
            for doc in docs:
                if not doc:
                    continue
                try:
                    rules.append(parse_rule(doc, str(f)))
                except (SigmaError, re.error, ValueError, TypeError) as exc:
                    errors.append((str(f), str(exc)))
    return rules, errors


# --------------------------------------------------------------------------- event adapters
def process_event(proc, platform: str) -> Dict[str, Any]:
    """Map an El Doctor ProcessInfo to Sigma process_creation field names."""
    return {
        "category": "process_creation", "product": platform,
        "Image": proc.exe or proc.name, "CommandLine": proc.cmdline_str, "ProcessId": proc.pid,
        "ParentImage": proc.parent_exe or proc.parent_name, "ParentCommandLine": proc.parent_cmdline,
        "ParentProcessId": proc.ppid, "User": proc.username, "CurrentDirectory": proc.cwd,
        "OriginalFileName": proc.name, "Hashes": f"SHA256={proc.sha256}" if proc.sha256 else "",
    }


def network_event(proc, conn: Dict[str, Any], platform: str) -> Dict[str, Any]:
    return {
        "category": "network_connection", "product": platform,
        "Image": (proc.exe or proc.name) if proc else "", "DestinationIp": conn.get("rip", ""),
        "DestinationPort": conn.get("rport", 0), "SourcePort": conn.get("lport", 0),
        "Initiated": "true", "Protocol": conn.get("type", "tcp"), "User": proc.username if proc else "",
    }


def log_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    flat = {k: v for k, v in ev.items() if k != "fields"}
    flat.update(ev.get("fields") or {})
    return flat
