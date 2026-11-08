#!/usr/bin/env python3
"""Print the CHANGELOG.md section of a version (GitHub release notes).   release_notes.py 2.1.0 [repo]"""
import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(version: str, text: str) -> str:
    m = re.search(r"^## \[?" + re.escape(version) + r"\]?[^\n]*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else "See CHANGELOG.md."


if __name__ == "__main__":
    notes = section(sys.argv[1], CHANGELOG.read_text(encoding="utf-8"))
    repo = sys.argv[2] if len(sys.argv) > 2 else "<owner>/<repo>"
    print(notes + "\n\n---\n**Verify your download:** `sha256sum -c SHA256SUMS.txt --ignore-missing` "
                  f"(Windows: `Get-FileHash <file>`); build provenance: `gh attestation verify <file> --repo {repo}`.")
