"""Linux installer packages for people who do not use a terminal: double-click the .deb (Ubuntu, Debian, Mint) or
the .rpm (Fedora, RHEL, openSUSE) and the software centre installs El Doctor with a menu entry and an icon.

* .deb - written in pure Python (an ``ar`` archive of control.tar.gz + data.tar.gz), so it is identical wherever it is
  built; checked with ``dpkg-deb`` when available.
* .rpm - ``rpmbuild`` (the release workflow builds it in AlmaLinux 8).

Both install the standalone executable to /opt/eldoctor, ``eldoctor`` on the PATH, the menu entry and icons.  They
do **not** start the whole-computer service on their own: the administrator turns it on with
``sudo eldoctor install-service`` (it asks who manages El Doctor).  Upgrades restart that service if it is on;
removing the package removes the service; only ``apt purge`` deletes the records.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "packaging" / "assets"
DESKTOP = ROOT / "packaging" / "linux" / "eldoctor.desktop"
DOCS = ["README.md", "INSTALL.md", "CHANGELOG.md", "SECURITY.md"]
ICON_SIZES = [48, 64, 128, 256, 512]
SUMMARY = "Endpoint security monitor with threat detection, response and a user-activity record"
DESCRIPTION = """El Doctor watches this computer for threats (cryptominers, reverse shells, droppers,
 ransomware-style mass deletion...), maps them to MITRE ATT&CK, responds with safe,
 reversible playbooks, and records who logged in, which applications ran and which
 files were created, edited, deleted, opened or downloaded. Data-wipe incidents are
 e-mailed to the registered administrators."""

POSTINST = """#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true; fi
# upgrade: the whole-computer service (if the administrator turned it on) continues on the new version
if [ -f /etc/systemd/system/eldoctor.service ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl try-restart eldoctor.service || true
fi
if [ "${1:-}" = "configure" ] && [ -z "${2:-}" ]; then
  echo "El Doctor is installed: open it from the applications menu (or run 'eldoctor')."
  echo "To protect the whole computer around the clock: sudo eldoctor install-service"
fi
exit 0
"""
PRERM = """#!/bin/sh
set -e
# removal (not upgrade): stop and remove the whole-computer service; its records stay until purge
if [ "${1:-}" = "remove" ] && [ -f /etc/systemd/system/eldoctor.service ]; then
  /opt/eldoctor/eldoctor uninstall-service --quiet || true
fi
exit 0
"""
POSTRM = """#!/bin/sh
set -e
if [ "${1:-}" = "purge" ]; then
  rm -rf /var/lib/eldoctor /etc/eldoctor
fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
exit 0
"""


def deb_arch(machine: str) -> str:
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)


def rpm_arch(machine: str) -> str:
    return {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(machine, machine)


def layout(binary: Path) -> List[Tuple[str, Optional[Path], int, Optional[str]]]:
    """(path in the package, source file | None for directories/links, mode, symlink target)."""
    items: List[Tuple[str, Optional[Path], int, Optional[str]]] = [
        ("opt/eldoctor/eldoctor", binary, 0o755, None),
        ("usr/bin/eldoctor", None, 0o777, "/opt/eldoctor/eldoctor"),
        ("usr/share/applications/eldoctor.desktop", DESKTOP, 0o644, None),
        ("usr/share/doc/eldoctor/copyright", ROOT / "LICENSE", 0o644, None),
    ]
    for s in ICON_SIZES:
        items.append((f"usr/share/icons/hicolor/{s}x{s}/apps/eldoctor.png", ASSETS / f"eldoctor-{s}.png", 0o644, None))
    for d in DOCS:
        if (ROOT / d).exists():
            items.append((f"usr/share/doc/eldoctor/{d}", ROOT / d, 0o644, None))
    return items


def _tar(entries: List[Tuple[str, Optional[bytes], int, Optional[str]]], mtime: int) -> bytes:
    """gzip'd tar, owned by root, parent directories listed first (what dpkg expects)."""
    buf = io.BytesIO()
    dirs: List[str] = []
    for name, _, _, _ in entries:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            d = "/".join(parts[:i])
            if d and d not in dirs:
                dirs.append(d)
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=mtime) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            def info(n: str) -> tarfile.TarInfo:
                ti = tarfile.TarInfo("./" + n if n else ".")
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                ti.mtime = mtime
                return ti
            root = info("")
            root.type, root.mode = tarfile.DIRTYPE, 0o755
            tf.addfile(root)
            for d in dirs:
                ti = info(d + "/")
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(ti)
            for name, data, mode, link in entries:
                ti = info(name)
                ti.mode = mode
                if link:
                    ti.type, ti.linkname = tarfile.SYMTYPE, link
                    tf.addfile(ti)
                else:
                    ti.size = len(data or b"")
                    tf.addfile(ti, io.BytesIO(data or b""))
    return buf.getvalue()


def _ar(members: List[Tuple[str, bytes]], mtime: int) -> bytes:
    out = [b"!<arch>\n"]
    for name, data in members:
        hdr = (f"{name:<16}{mtime:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n").encode("ascii")
        assert len(hdr) == 60
        out += [hdr, data, b"\n" if len(data) % 2 else b""]
    return b"".join(out)


def build_deb(binary: Path, out_dir: Path, version: str, machine: str) -> Path:
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    files = layout(binary)
    data_entries = []
    md5 = []
    size = 0
    for name, src, mode, link in files:
        if link:
            data_entries.append((name, None, mode, link))
            continue
        data = src.read_bytes()
        size += len(data)
        data_entries.append((name, data, mode, None))
        md5.append(f"{hashlib.md5(data).hexdigest()}  {name}")        # noqa: S324 - dpkg's integrity list format
    arch = deb_arch(machine)
    control = (f"Package: eldoctor\nVersion: {version}\nArchitecture: {arch}\n"
               f"Maintainer: El Doctor contributors <security@eldoctor.invalid>\n"
               f"Installed-Size: {max(1, size // 1024)}\nDepends: libc6 (>= 2.28)\nSection: admin\n"
               f"Priority: optional\nHomepage: https://github.com/\nDescription: {SUMMARY}\n {DESCRIPTION}\n")
    ctl = [("control", control.encode(), 0o644, None), ("md5sums", ("\n".join(md5) + "\n").encode(), 0o644, None),
           ("postinst", POSTINST.encode(), 0o755, None), ("prerm", PRERM.encode(), 0o755, None),
           ("postrm", POSTRM.encode(), 0o755, None)]
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", _tar(ctl, mtime)),
               ("data.tar.gz", _tar(data_entries, mtime))], mtime)
    out = out_dir / f"eldoctor_{version}_{arch}.deb"
    out.write_bytes(deb)
    return out


RPM_SPEC = """%global __os_install_post %{{nil}}
%global debug_package %{{nil}}
%define _build_id_links none
Name:           eldoctor
Version:        {version}
Release:        1
Summary:        {summary}
License:        MIT
URL:            https://github.com/
BuildArch:      {arch}
AutoReqProv:    no
Requires:       glibc >= 2.28

%description
{description}

%install
cp -a {staging}/. %{{buildroot}}/

%files
%dir /opt/eldoctor
%attr(0755,root,root) /opt/eldoctor/eldoctor
/usr/bin/eldoctor
/usr/share/applications/eldoctor.desktop
/usr/share/icons/hicolor/*/apps/eldoctor.png
%dir /usr/share/doc/eldoctor
/usr/share/doc/eldoctor/*

%post
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || :
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || :
if [ "$1" = "1" ]; then
  echo "El Doctor is installed: open it from the applications menu (or run 'eldoctor')."
  echo "To protect the whole computer around the clock: sudo eldoctor install-service"
fi

%preun
if [ "$1" = "0" ] && [ -f /etc/systemd/system/eldoctor.service ]; then
  /opt/eldoctor/eldoctor uninstall-service --quiet || :
fi

%postun
if [ "$1" -ge "1" ] && [ -f /etc/systemd/system/eldoctor.service ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || :
  systemctl try-restart eldoctor.service || :
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || :
"""


def build_rpm(binary: Path, out_dir: Path, version: str, machine: str) -> Optional[Path]:
    if not shutil.which("rpmbuild"):
        return None
    arch = rpm_arch(machine)
    work = Path(tempfile.mkdtemp(prefix="eldoctor-rpm-"))
    try:
        staging = work / "staging"
        for name, src, mode, link in layout(binary):
            dest = staging / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if link:
                os.symlink(link, dest)
            else:
                shutil.copy2(src, dest)
                os.chmod(dest, mode)
        spec = work / "eldoctor.spec"
        spec.write_text(RPM_SPEC.format(version=version, arch=arch, summary=SUMMARY,
                                        description=DESCRIPTION.replace("\n ", "\n"), staging=staging),
                        encoding="utf-8")
        subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {work / 'top'}", "--define",
                        f"_rpmdir {work / 'rpms'}", str(spec)], check=True)
        built = next((work / "rpms").rglob("*.rpm"))
        out = out_dir / built.name
        shutil.copy2(built, out)
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_deb(deb: Path) -> Dict[str, str]:
    """dpkg-deb's view of the package + the extracted executable runs (when dpkg-deb exists)."""
    if not shutil.which("dpkg-deb"):
        return {}
    info = subprocess.run(["dpkg-deb", "--info", str(deb)], capture_output=True, text=True, check=True).stdout
    contents = subprocess.run(["dpkg-deb", "--contents", str(deb)], capture_output=True, text=True, check=True).stdout
    tmp = Path(tempfile.mkdtemp(prefix="eldoctor-deb-"))
    try:
        subprocess.run(["dpkg-deb", "-x", str(deb), str(tmp)], check=True)
        ver = subprocess.run([str(tmp / "opt/eldoctor/eldoctor"), "--version"], capture_output=True, text=True,
                             check=True, env=dict(os.environ, ELDOCTOR_HOME=str(tmp / "home"))).stdout.strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"info": info, "contents": contents, "version": ver}
