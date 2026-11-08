"""Optional YARA scanning of suspicious executables (requires `pip install yara-python`)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from eldoctor.config import package_data

try:  # pragma: no cover - availability depends on the host
    import yara  # type: ignore
except Exception:  # ImportError or broken libyara
    yara = None


class YaraScanner:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        ycfg = cfg.get("detection", {}).get("yara", {}) or {}
        enabled = ycfg.get("enabled", "auto")
        self.max_bytes = int(ycfg.get("max_file_mb", 50)) * 1024 * 1024
        self.scan_all = ycfg.get("scan", "suspicious") == "all"
        self.rules = None
        self.error = ""
        self.rule_count = 0
        if enabled is False or (enabled == "auto" and yara is None):
            self.error = "yara-python not installed" if yara is None else "disabled"
            return
        if yara is None:
            self.error = "yara-python not installed"
            return
        files: Dict[str, str] = {}
        dirs = [package_data("rules", "yara")] + [Path(d).expanduser() for d in ycfg.get("rules_dirs", []) or []]
        for d in dirs:
            for f in list(Path(d).glob("*.yar")) + list(Path(d).glob("*.yara")):
                files[f"{d.name}_{f.stem}"] = str(f)
        if not files:
            self.error = "no YARA rules found"
            return
        try:
            self.rules = yara.compile(filepaths=files)
            self.rule_count = len(files)
        except Exception as exc:  # yara.SyntaxError etc.
            self.error = f"compile error: {exc}"

    @property
    def enabled(self) -> bool:
        return self.rules is not None

    def scan_file(self, path: str) -> List[Dict[str, Any]]:
        if not self.rules or not path:
            return []
        try:
            if os.path.getsize(path) > self.max_bytes:
                return []
            matches = self.rules.match(path, timeout=10)
        except Exception:
            return []
        out = []
        for m in matches:
            meta = dict(getattr(m, "meta", {}) or {})
            out.append({"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "meta": meta})
        return out
