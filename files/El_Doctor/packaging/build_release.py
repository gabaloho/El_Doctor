#!/usr/bin/env python3
"""Build the El Doctor release for *this* platform - what users download and run.

    python -m pip install --require-hashes -r requirements.lock
    python -m pip install -r packaging/requirements-build.txt
    python packaging/build_release.py                 # tests -> binary -> smoke test -> archive -> checksums

Output (release/):
    eldoctor-<version>-<os>-<arch>.tar.gz | .zip      standalone executable(s) + service installer + docs
    ElDoctor-Setup-<version>.exe                       Windows setup wizard (Inno Setup)
    ElDoctor-<version>.dmg                             macOS disk image with "El Doctor.app"
    eldoctor_<version>_<arch>.deb / eldoctor-<version>-1.<arch>.rpm   Linux packages (menu entry + icon)
    eldoctor-<version>-py3-none-any.whl, .tar.gz      for `pipx install` / pip      (--python-dist)
    eldoctor-<version>-sbom.cdx.json                  CycloneDX SBOM of the bundled dependencies
    SHA256SUMS-<os>-<arch>.txt

The smoke test runs the *built* executable the way a user would: version, doctor, registration, rules and
playbooks present, a headless agent with the activity recorder, the audit chain verified, and a deployment
bundle generated from the standalone build.  A failure stops the build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eldoctor import __version__  # noqa: E402

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
EXE = ".exe" if IS_WIN else ""
DOCS = ["README.md", "INSTALL.md", "LICENSE", "CHANGELOG.md", "SECURITY.md"]
GUI_EXE = "El Doctor.exe"         # windowed GUI; not "ElDoctor.exe": Windows ignores case -> same name as eldoctor.exe


def plat_tag() -> str:
    osname = "windows" if IS_WIN else "macos" if IS_MAC else "linux"
    arch = platform.machine().lower()
    arch = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(arch, arch)
    return f"{osname}-{arch}"


def step(msg: str) -> None:
    print(f"\n==> {msg}", flush=True)


def run(cmd: List[str], **kw) -> subprocess.CompletedProcess:
    print("   $ " + " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


# ------------------------------------------------------------------------------------------- build
def write_version_info(dest: Path) -> None:
    """Windows version resource (file properties -> Details)."""
    nums = tuple(int(x) for x in (__version__.split(".") + ["0", "0", "0"])[:4] if x.isdigit())
    nums = (nums + (0, 0, 0, 0))[:4]
    dest.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'El Doctor contributors'),
      StringStruct('FileDescription', 'El Doctor endpoint monitoring, detection and response'),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('InternalName', 'eldoctor'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'eldoctor.exe'),
      StringStruct('ProductName', 'El Doctor'),
      StringStruct('ProductVersion', '{__version__}')])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
""", encoding="utf-8")


def build_binary(work: Path) -> List[Path]:
    """PyInstaller -> [console executable, windowed "El Doctor.exe" (Windows)]; also dist/El Doctor.app on macOS."""
    step("PyInstaller: standalone executable(s)")
    write_version_info(ROOT / "packaging" / "version_info.txt")
    dist = work / "dist"
    run([sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "--distpath", str(dist),
         "--workpath", str(work / "build"), str(ROOT / "packaging" / "eldoctor.spec")], cwd=str(ROOT))
    out = [dist / f"eldoctor{EXE}"]
    if (dist / GUI_EXE).exists():
        out.append(dist / GUI_EXE)
    sign = os.environ.get("ELDOCTOR_SIGN_CMD", "")
    for b in out:
        if sign:                              # e.g. signtool sign /fd sha256 /tr <tsa> /td sha256 /f cert.pfx {file}
            import shlex
            run([a.replace("{file}", str(b)) for a in shlex.split(sign, posix=not IS_WIN)])
        print(f"   built {b} ({b.stat().st_size / 1048576:.1f} MB){' - signed' if sign else ''}")
    return out


def glibc_requirement(binary: Path) -> Optional[tuple]:
    """Highest GLIBC_x.y symbol version any bundled library needs = the oldest Linux it runs on."""
    if not sys.platform.startswith("linux") or not shutil.which("objdump"):
        return None
    import re
    from PyInstaller.archive.readers import CArchiveReader
    worst = (0, 0)
    tmp = Path(tempfile.mkdtemp())
    try:
        arch = CArchiveReader(str(binary))
        libs = [n for n in arch.toc if ".so" in n]
        for i, name in enumerate(libs):
            f = tmp / f"lib{i}.so"
            f.write_bytes(arch.extract(name))
            out = subprocess.run(["objdump", "-T", str(f)], capture_output=True, text=True).stdout
            for v in re.findall(r"GLIBC_(\d+)\.(\d+)", out):
                worst = max(worst, (int(v[0]), int(v[1])))
        out = subprocess.run(["objdump", "-T", str(binary)], capture_output=True, text=True).stdout
        for v in re.findall(r"GLIBC_(\d+)\.(\d+)", out):
            worst = max(worst, (int(v[0]), int(v[1])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return worst


def build_info(binary: Path, glibc: Optional[tuple]) -> str:
    from importlib.metadata import version
    deps = {d: version(d) for d in ("psutil", "PyYAML", "cryptography", "PyInstaller")}
    commit = ""
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                                cwd=str(ROOT)).stdout.strip()
    except OSError:
        pass
    lines = [f"El Doctor {__version__}", f"platform: {plat_tag()}",
             f"built: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} with Python {platform.python_version()}",
             f"commit: {commit or 'unknown'}", "bundled: " + ", ".join(f"{k} {v}" for k, v in deps.items()),
             f"sha256 ({binary.name}): {hashlib.sha256(binary.read_bytes()).hexdigest()}"]
    if glibc:
        lines.append(f"requires glibc >= {glibc[0]}.{glibc[1]} (check yours: ldd --version)")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------------------- smoke test
def smoke_test(binary: Path, require_gui: bool = False) -> Dict[str, str]:
    """Run the built executable like a user would; raise on any failure."""
    step(f"smoke test of {binary.name}")
    tmp = Path(tempfile.mkdtemp(prefix="eldoctor-smoke-"))
    env = dict(os.environ, ELDOCTOR_HOME=str(tmp / "data"), ELDOCTOR_CLIENT_DIR=str(tmp / "client"),
               SMOKE_PW="Sm0ke!Test-Passw0rd")
    for k in ("ELDOCTOR_SOCKET", "ELDOCTOR_API_KEY", "ELDOCTOR_MODE"):
        env.pop(k, None)
    watched = tmp / "watched"
    (watched / "Documents").mkdir(parents=True)
    results: Dict[str, str] = {}

    def ed(*args: str, timeout: float = 120, check: bool = True) -> subprocess.CompletedProcess:
        r = subprocess.run([str(binary), *args], env=env, capture_output=True, text=True, timeout=timeout,
                           cwd=str(tmp))
        if check and r.returncode != 0:
            raise SystemExit(f"SMOKE TEST FAILED: eldoctor {' '.join(args)} -> {r.returncode}\n"
                             f"stdout: {r.stdout[-2000:]}\nstderr: {r.stderr[-2000:]}")
        return r

    def expect(cond: bool, what: str) -> None:
        if not cond:
            raise SystemExit(f"SMOKE TEST FAILED: {what}")
        results[what] = "ok"
        print(f"   ok  {what}")

    try:
        expect(__version__ in ed("--version").stdout, f"--version reports {__version__}")
        checks = json.loads(ed("doctor", "--json").stdout)
        expect(not any(c["status"] == "fail" for c in checks), "doctor: no failing check")
        gui = next((c for c in checks if c["area"] == "desktop GUI"), {})
        if require_gui:                       # bundled Tk (a CI runner has no display, so 'available' is not expected)
            expect("without the desktop GUI" not in gui.get("summary", ""), "desktop GUI bundled")
        expect(not (tmp / "data").exists(), "doctor is read-only (creates nothing)")
        key = json.loads(ed("register", "--non-interactive", "--username", "smoke_admin", "--email",
                            "smoke@example.invalid", "--password-env", "SMOKE_PW", "--json").stdout)["api_key"]
        expect(key.startswith("edk_"), "registration (first user = admin)")
        (tmp / "data" / "config.yaml").write_text(
            "agent: {interval: 1.0, mode: monitor}\n"
            "logs: {files: [], journald: false, auditd: false, windows_eventlog: false}\n"
            "notifications: {channels: [{type: jsonl, path: alerts.jsonl}]}\n"
            f"activity: {{files: {{paths: [{json.dumps(str(watched))}], open_handles_interval: 0, poll_interval: 2}}, "
            "wtmp: ''}\n",
            encoding="utf-8")
        expect("SIGMA:" in ed("--api-key", key, "rules").stdout, "bundled Sigma rules load")
        expect("pb-data-destruction" in ed("--api-key", key, "playbooks", "list").stdout, "bundled playbooks load")
        agent = subprocess.Popen([str(binary), "--api-key", key, "run", "--headless", "--duration", "14"], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(tmp))
        try:
            time.sleep(6)
            (watched / "Documents" / "smoke.txt").write_text("hello", encoding="utf-8")
            ok = False
            for _ in range(20):
                time.sleep(0.5)
                r = ed("--api-key", key, "activity", "list", "--json", check=False)
                if r.returncode == 0 and "smoke.txt" in r.stdout:
                    ok = True
                    break
            expect(ok, "running agent records file activity")
            expect("OK" in ed("--api-key", key, "audit", "verify").stdout, "audit chain verifies")
        finally:
            try:
                out, _ = agent.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                agent.kill()
                out, _ = agent.communicate()
        expect(agent.returncode == 0, f"headless agent exits cleanly (rc {agent.returncode})")
        expect((tmp / "data" / "logs" / "eldoctor.log").exists(), "log file written")
        # El Doctor Hub from the same executable: a hub, a token, this agent enrolled and reporting over mutual TLS
        import socket as _s
        ports = []
        for _ in range(2):
            so = _s.socket()
            so.bind(("127.0.0.1", 0))
            ports.append(so.getsockname()[1])
            so.close()
        henv = dict(env, ELDOCTOR_HUB_HOME=str(tmp / "hub"))
        r = subprocess.run([str(binary), "hub", "init", "--name", "127.0.0.1", "--port", str(ports[0]),
                            "--console-port", str(ports[1]), "--admin-username", "smoke_soc", "--admin-email",
                            "soc@example.invalid", "--password-env", "SMOKE_PW"], env=henv, capture_output=True,
                           text=True, timeout=120)
        expect(r.returncode == 0, "hub: created (CA, certificates, administrator)")
        hub = subprocess.Popen([str(binary), "hub", "serve"], env=henv, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
        agent2 = None
        try:
            time.sleep(4)
            tok = subprocess.run([str(binary), "hub", "token"], env=henv, capture_output=True, text=True,
                                 timeout=60).stdout.split()[4]
            expect(tok.startswith("EDH1-"), "hub: enrollment token")
            expect("Enrolled as" in ed("enroll", tok).stdout, "agent enrolled (CA pinned from the token)")
            agent2 = subprocess.Popen([str(binary), "--api-key", key, "run", "--headless", "--duration", "30"],
                                      env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                      cwd=str(tmp))
            online = False
            for _ in range(40):
                time.sleep(1)
                out = subprocess.run([str(binary), "hub", "agents", "--json"], env=henv, capture_output=True,
                                     text=True, timeout=60).stdout
                if '"state": "online"' in out:
                    online = True
                    break
            expect(online, "agent reports to the hub over mutual TLS")
        finally:
            for pr in (agent2, hub):
                if pr is not None and pr.poll() is None:
                    pr.terminate()
                    try:
                        pr.wait(40)
                    except subprocess.TimeoutExpired:
                        pr.kill()
        target = "windows" if IS_WIN else "linux" if sys.platform.startswith("linux") else ""
        if target:
            bundle = tmp / "bundle"
            ed("--api-key", key, "deploy", "--target", target, "--out", str(bundle))
            expect((bundle / f"eldoctor{EXE}").exists(), "deployment bundle carries the standalone executable")
            expect(any(p.name.endswith("-src.zip") for p in bundle.iterdir()), "deployment bundle carries the sources")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return results


# ------------------------------------------------------------------------------------------- installers
def _sign(path: Path) -> None:
    sign = os.environ.get("ELDOCTOR_SIGN_CMD", "")
    if sign:
        import shlex
        run([a.replace("{file}", str(path)) for a in shlex.split(sign, posix=not IS_WIN)])


def find_iscc() -> Optional[str]:
    for cand in [shutil.which("ISCC"), shutil.which("iscc"),
                 os.path.expandvars(r"%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"),
                 os.path.expandvars(r"%ProgramFiles%\Inno Setup 6\ISCC.exe"),
                 os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe")]:
        if cand and os.path.isfile(cand):
            return cand
    return None


def windows_installer(binaries: List[Path], work: Path, out_dir: Path) -> Optional[Path]:
    iscc = find_iscc()
    if not iscc:
        print("   Inno Setup (ISCC) not found - no setup wizard (choco install innosetup)")
        return None
    stage = work / "setup-files"
    stage.mkdir()
    for b in binaries:
        shutil.copy2(b, stage / b.name)
    if not (stage / GUI_EXE).exists():
        raise SystemExit(f"the setup wizard needs the windowed {GUI_EXE} (build with a Python that has Tk)")
    shutil.copy2(ROOT / "packaging" / "assets" / "eldoctor.ico", stage / "eldoctor.ico")
    for d in DOCS:
        shutil.copy2(ROOT / d, stage / d)
    run([iscc, "/Q", f"/DAppVersion={__version__}", f"/DSourceDir={stage}", f"/DOutputDir={out_dir}",
         str(ROOT / "packaging" / "windows" / "eldoctor.iss")])
    setup = out_dir / f"ElDoctor-Setup-{__version__}.exe"
    _sign(setup)
    return setup


def _wait_gone(path: Path, timeout: float = 90) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not path.exists():
            return True
        time.sleep(1)
    return False


def smoke_windows_installer(setup: Path, service_test: bool) -> None:
    """Install and uninstall the setup silently, the way an IT department would."""
    step(f"installer test: {setup.name} (personal installation)")
    tmp = Path(tempfile.mkdtemp(prefix="eldoctor-setup-"))
    inst = tmp / "personal"
    run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", f"/DIR={inst}", "/TASKS=",
         f"/LOG={tmp / 'setup-personal.log'}"])
    for exe in ("eldoctor.exe", GUI_EXE):
        if not (inst / exe).exists():
            raise SystemExit(f"INSTALLER TEST FAILED: {exe} not installed")
    out = subprocess.run([str(inst / "eldoctor.exe"), "--version"], capture_output=True, text=True, timeout=120).stdout
    if __version__ not in out:
        raise SystemExit(f"INSTALLER TEST FAILED: installed eldoctor.exe --version -> {out!r}")
    print("   ok  installed for the current user, runs")
    run([str(inst / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
    if not _wait_gone(inst / "eldoctor.exe"):
        raise SystemExit("INSTALLER TEST FAILED: uninstaller did not remove the program")
    print("   ok  uninstalled")
    if not service_test:
        return
    step(f"installer test: {setup.name} (all users + protection service)")
    inst = tmp / "allusers"
    pw = "C1-Setup!Test-pw"
    env = dict(os.environ, ELDOCTOR_ADMIN_PASSWORD=pw, CI_PW=pw)
    env.pop("ELDOCTOR_HOME", None)
    run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/ALLUSERS", f"/DIR={inst}",
         "/TASKS=service", "/ADMINUSER=ci_admin", "/ADMINEMAIL=ci@example.invalid", "/ADMINNAME=CI Admin",
         f"/LOG={tmp / 'setup-service.log'}"], env=env)
    log = inst / "install-service.log"
    print(log.read_text(encoding="utf-8", errors="replace") if log.exists() else "   (no install-service.log)")
    q = subprocess.run(["schtasks", "/Query", "/TN", "ElDoctor Agent"], capture_output=True, text=True)
    if q.returncode != 0:
        raise SystemExit("INSTALLER TEST FAILED: scheduled task not registered")
    print("   ok  scheduled task 'ElDoctor Agent' registered")
    env.pop("ELDOCTOR_ADMIN_PASSWORD")
    client = dict(env, ELDOCTOR_CLIENT_DIR=str(tmp / "client"))
    ok = False
    for _ in range(60):                               # the service starts, then answers on its named pipe
        r = subprocess.run([str(inst / "eldoctor.exe"), "login", "--username", "ci_admin", "--password-env", "CI_PW"],
                           capture_output=True, text=True, env=client, timeout=120)
        if r.returncode == 0:
            ok = True
            break
        time.sleep(2)
    if not ok:
        raise SystemExit(f"INSTALLER TEST FAILED: cannot log in to the service: {r.stdout} {r.stderr}")
    who = subprocess.run([str(inst / "eldoctor.exe"), "whoami"], capture_output=True, text=True, env=client).stdout
    if "service" not in who:
        raise SystemExit(f"INSTALLER TEST FAILED: not connected to the service: {who}")
    print("   ok  the administrator created by the wizard logs in to the running service")
    run([str(inst / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])
    if not _wait_gone(inst / "eldoctor.exe"):
        raise SystemExit("INSTALLER TEST FAILED: uninstaller did not remove the program")
    if subprocess.run(["schtasks", "/Query", "/TN", "ElDoctor Agent"], capture_output=True).returncode == 0:
        raise SystemExit("INSTALLER TEST FAILED: the scheduled task survived the uninstall")
    print("   ok  uninstalled: program and service removed (records kept)")


def macos_dmg(dist: Path, out_dir: Path) -> Optional[Path]:
    app = dist / "El Doctor.app"
    if not app.exists():
        print("   no El Doctor.app (built without Tk?) - no disk image")
        return None
    _sign(app)
    exe = app / "Contents" / "MacOS" / "ElDoctor"
    r = subprocess.run([str(exe), "--help"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or "usage" not in r.stdout.lower():
        raise SystemExit(f"SMOKE TEST FAILED: El Doctor.app does not start: {r.stdout} {r.stderr}")
    print("   ok  El Doctor.app starts")
    stage = dist.parent / "dmg"
    stage.mkdir()
    shutil.copytree(app, stage / "El Doctor.app", symlinks=True)
    os.symlink("/Applications", stage / "Applications")
    shutil.copy2(ROOT / "INSTALL.md", stage / "INSTALL.md")
    dmg = out_dir / f"ElDoctor-{__version__}.dmg"
    if dmg.exists():
        dmg.unlink()
    run(["hdiutil", "create", "-volname", f"El Doctor {__version__}", "-srcfolder", str(stage), "-ov",
         "-format", "UDZO", str(dmg)])
    run(["hdiutil", "verify", str(dmg)])
    _sign(dmg)
    return dmg


def has_gui(binary: Path) -> bool:
    r = subprocess.run([str(binary), "doctor", "--json"], capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, ELDOCTOR_HOME=tempfile.mkdtemp(prefix="eldoctor-gui-check-")))
    try:
        gui = next(c for c in json.loads(r.stdout) if c["area"] == "desktop GUI")
    except (ValueError, StopIteration):
        return False
    return "without the desktop GUI" not in gui.get("summary", "")


def linux_packages(binary: Path, out_dir: Path, allow_no_gui: bool = False) -> List[Path]:
    if not has_gui(binary):
        if not allow_no_gui:
            print("   this executable has no desktop GUI (built with a Python without Tk): no .deb / .rpm - their "
                  "menu entry would open nothing. Build with Tk, or --packages-without-gui for testing only.")
            return []
        print("   WARNING: packages WITHOUT the desktop GUI - for testing only, do not publish")
    sys.path.insert(0, str(ROOT / "packaging"))
    import linux_packages as lp
    out = [lp.build_deb(binary, out_dir, __version__, platform.machine())]
    chk = lp.check_deb(out[0])
    if chk:
        if chk["version"] != f"El Doctor {__version__}":
            raise SystemExit(f"PACKAGE TEST FAILED: {out[0].name}: {chk['version']!r}")
        print(f"   ok  {out[0].name}: dpkg-deb accepts it, the packaged executable runs")
    rpm = lp.build_rpm(binary, out_dir, __version__, platform.machine())
    if rpm:
        out.append(rpm)
        if os.geteuid() == 0 and shutil.which("rpm"):
            run(["rpm", "-i", str(rpm)])
            v = subprocess.run(["/usr/bin/eldoctor", "--version"], capture_output=True, text=True).stdout
            if __version__ not in v or not Path("/usr/share/applications/eldoctor.desktop").exists():
                raise SystemExit(f"PACKAGE TEST FAILED: {rpm.name} installed but eldoctor --version -> {v!r}")
            run(["rpm", "-e", "eldoctor"])
            if Path("/opt/eldoctor/eldoctor").exists():
                raise SystemExit(f"PACKAGE TEST FAILED: {rpm.name} did not uninstall cleanly")
            print(f"   ok  {rpm.name}: installed, runs, menu entry present, uninstalled")
    else:
        print("   rpmbuild not found - no .rpm (dnf install rpm-build)")
    return out


# ------------------------------------------------------------------------------------------- assemble
def make_installer_files(folder: Path, binaries: List[Path]) -> None:
    """The service installer + docs next to the executable(s): extract and run, or install as a service."""
    from eldoctor.deploy.generator import generate
    target = "windows" if IS_WIN else "linux" if sys.platform.startswith("linux") else ""
    if target:
        generate(target, folder, {"username": "admin", "email": "admin@example.invalid"})
        for p in folder.glob("eldoctor-*-src.zip"):        # the standalone executable replaces the source package
            p.unlink()
    for b in binaries:
        shutil.copy2(b, folder / b.name)
        os.chmod(folder / b.name, 0o755)
    for d in DOCS:
        if (ROOT / d).exists():
            shutil.copy2(ROOT / d, folder / d)


def archive(folder: Path, out_dir: Path) -> Path:
    if IS_WIN:
        dest = out_dir / f"{folder.name}.zip"
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(folder.rglob("*")):
                if p.is_file():
                    zf.write(p, f"{folder.name}/{p.relative_to(folder).as_posix()}")
    else:
        dest = out_dir / f"{folder.name}.tar.gz"
        with tarfile.open(dest, "w:gz") as tf:
            tf.add(folder, arcname=folder.name)
    return dest


def python_dists(out_dir: Path) -> List[Path]:
    step("wheel + source distribution")
    before = set(out_dir.iterdir())
    try:
        run([sys.executable, "-m", "build", "--outdir", str(out_dir), str(ROOT)])
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("   'build' not available - wheel only")
        run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out_dir), str(ROOT)])
    return sorted(set(out_dir.iterdir()) - before)


def sbom(out_dir: Path) -> Optional[Path]:
    dest = out_dir / f"eldoctor-{__version__}-sbom.cdx.json"
    try:
        run([sys.executable, "-m", "cyclonedx_py", "requirements", str(ROOT / "requirements.lock"),
             "--output-format", "JSON", "--output-file", str(dest)])
        return dest
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("   cyclonedx-bom not installed - no SBOM (pip install cyclonedx-bom)")
        return None


def checksums(files: List[Path], out_dir: Path) -> Path:
    dest = out_dir / f"SHA256SUMS-{plat_tag()}.txt"
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        for f in sorted(files):
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            fh.write(f"{h}  {f.name}\n")
    return dest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "release"))
    ap.add_argument("--skip-tests", action="store_true", help="do not run the test suite first")
    ap.add_argument("--python-dist", action="store_true", help="also build the wheel + sdist")
    ap.add_argument("--require-gui", action="store_true", help="fail unless the desktop GUI is bundled")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument("--max-glibc", help="Linux: fail if the binary needs a newer glibc than this (e.g. 2.28)")
    ap.add_argument("--no-installers", action="store_true", help="skip the setup wizard / disk image / packages")
    ap.add_argument("--packages-without-gui", action="store_true", help="Linux: build .deb/.rpm even without Tk "
                                                                        "(testing only)")
    ap.add_argument("--installer-service-test", action="store_true",
                    help="Windows (administrator, CI): also install with the protection service and remove it again")
    args = ap.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"El Doctor {__version__} release build for {plat_tag()} with Python {platform.python_version()}")
    if not args.skip_tests:
        step("test suite")
        run([sys.executable, "-m", "pytest", "-q", "-x"], cwd=str(ROOT))
    work = Path(tempfile.mkdtemp(prefix="eldoctor-build-"))
    try:
        binaries = build_binary(work)
        glibc = glibc_requirement(binaries[0])
        if glibc:
            print(f"   needs glibc >= {glibc[0]}.{glibc[1]}")
            if args.max_glibc and glibc > tuple(int(x) for x in args.max_glibc.split(".")):
                raise SystemExit(f"the binary needs glibc {glibc[0]}.{glibc[1]} > {args.max_glibc}: build it on an "
                                 f"older distribution (see .github/workflows/release.yml)")
        smoke_test(binaries[0], require_gui=args.require_gui)
        step("release archive")
        folder = work / f"eldoctor-{__version__}-{plat_tag()}"
        folder.mkdir()
        make_installer_files(folder, binaries)
        (folder / "BUILDINFO.txt").write_text(build_info(binaries[0], glibc), encoding="utf-8")
        artefacts = [archive(folder, out_dir)]
        if not args.no_installers:
            step("installers")
            if IS_WIN:
                setup = windows_installer(binaries, work, out_dir)
                if setup:
                    smoke_windows_installer(setup, args.installer_service_test)
                    artefacts.append(setup)
            elif IS_MAC:
                dmg = macos_dmg(binaries[0].parent, out_dir)
                if dmg:
                    artefacts.append(dmg)
            else:
                artefacts += linux_packages(binaries[0], out_dir, args.packages_without_gui)
        if args.python_dist:
            artefacts += python_dists(out_dir)
        s = sbom(out_dir)
        if s:
            artefacts.append(s)
        sums = checksums(artefacts, out_dir)
        step("done")
        for a in artefacts + [sums]:
            print(f"   {a}  ({a.stat().st_size / 1048576:.1f} MB)")
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        vi = ROOT / "packaging" / "version_info.txt"
        if vi.exists():
            vi.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
