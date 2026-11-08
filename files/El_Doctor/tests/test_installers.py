"""Installers for non-developers: the shared 'protect this computer' logic (Windows + Linux), the clean stop used by
upgrades, the Windows setup wizard script, the Linux packages and the app icon.

Windows tools (icacls, schtasks, the registry) do not exist here: the Windows installation *logic* runs with those
calls recorded; the wizard itself and the service are exercised for real by the release workflow on Windows.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from eldoctor import installer

ROOT = Path(__file__).resolve().parents[1]
PW = "Str0ng!Passw0rd"
NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


class Recorder:
    def __init__(self, fail=()):
        self.calls = []
        self.fail = set(fail)

    def __call__(self, cmd, check=True, log=None):
        self.calls.append(list(cmd))
        rc = 1 if cmd[0] in self.fail else 0
        if check and rc:
            raise installer.InstallError(f"{cmd[0]} failed")
        return subprocess.CompletedProcess(cmd, rc, "", "")

    def names(self):
        return [" ".join(c[:2]) for c in self.calls]


# ------------------------------------------------------------------ Windows: task definition + installation logic
def test_task_xml_is_valid_and_runs_as_system_at_boot():
    xml = installer.task_xml([r"C:\Program Files\El Doctor\eldoctor.exe"], Path(r"C:\ProgramData\ElDoctor\config.yaml"),
                             Path(r"C:\ProgramData\ElDoctor"))
    root = ET.fromstring(xml.replace('encoding="UTF-16"', ""))          # parsed the way schtasks reads it
    assert root.find(f"{NS}Principals/{NS}Principal/{NS}UserId").text == "S-1-5-18"          # LocalSystem
    assert root.find(f"{NS}Triggers/{NS}BootTrigger/{NS}Enabled").text == "true"
    s = root.find(f"{NS}Settings")
    assert s.find(f"{NS}ExecutionTimeLimit").text == "PT0S" and s.find(f"{NS}RestartOnFailure/{NS}Count").text == "999"
    assert s.find(f"{NS}DisallowStartIfOnBatteries").text == "false"
    ex = root.find(f"{NS}Actions/{NS}Exec")
    assert ex.find(f"{NS}Command").text == r'"C:\Program Files\El Doctor\eldoctor.exe"'       # quoted: has spaces
    assert ex.find(f"{NS}Arguments").text == r"--config C:\ProgramData\ElDoctor\config.yaml service"
    # a pip installation runs python -m eldoctor
    xml2 = installer.task_xml([r"C:\Python312\python.exe", "-m", "eldoctor"], Path(r"C:\D\config.yaml"), Path(r"C:\D"))
    assert "<Arguments>-m eldoctor --config C:\\D\\config.yaml service</Arguments>" in xml2
    xml.encode("utf-16")                                                 # written as UTF-16 for schtasks


@pytest.fixture
def fake_windows(monkeypatch, tmp_path):
    data = tmp_path / "ProgramData" / "ElDoctor"
    rec = Recorder()
    state = {"marker": None, "env": {}}
    monkeypatch.setattr(installer, "IS_WINDOWS", True)
    monkeypatch.setattr(installer, "IS_LINUX", False)
    monkeypatch.setattr(installer, "is_privileged", lambda: True)
    monkeypatch.setattr(installer, "windows_data_dir", lambda: data)
    monkeypatch.setattr(installer, "_run", rec)
    monkeypatch.setattr(installer, "_win_marker",
                        lambda d, installed=True: state.update(marker=None if d is None else (str(d), installed)))
    monkeypatch.setattr(installer, "_win_machine_env", lambda n, v: state["env"].update({n: v}))
    monkeypatch.setattr(installer, "windows_previous_data_dir",
                        lambda: Path(state["marker"][0]) if state["marker"] else None)
    monkeypatch.setattr(installer, "windows_installed_data_dir",
                        lambda: Path(state["marker"][0]) if state["marker"] and state["marker"][1] else None)
    monkeypatch.setattr(installer, "request_clean_stop", lambda log=None, timeout=20: True)
    monkeypatch.setattr(installer, "agent_command", lambda: [r"C:\Program Files\El Doctor\eldoctor.exe"])
    return data, rec, state


def test_windows_install_registers_the_admin_then_upgrades_in_place(fake_windows, monkeypatch, cfg):
    data, rec, state = fake_windows
    monkeypatch.delenv("ELDOCTOR_HOME", raising=False)
    admin = {"username": "alice", "email": "alice@corp.example", "full_name": "Alice", "password": PW}
    res = installer.install_service(admin)
    assert res["upgraded"] is False and Path(res["data_dir"]) == data
    assert rec.calls[0][:2] == ["schtasks", "/End"]
    icacls = next(c for c in rec.calls if c[0] == "icacls")
    assert "*S-1-5-18:(OI)(CI)F" in icacls and "/inheritance:r" in icacls
    assert [c[1] for c in rec.calls if c[0] == "schtasks"][-2:] == ["/Create", "/Run"]
    assert state["env"] == {"ELDOCTOR_HOME": str(data)} and state["marker"] == (str(data), True)
    assert (data / "config.yaml").exists() and (data / "service.key").exists()
    from eldoctor.auth.users import UserManager
    from eldoctor.storage import Store
    os.environ["ELDOCTOR_HOME"] = str(data)
    s = Store()
    um = UserManager(s, cfg)
    assert um.get("alice").role == "admin" and um.authenticate("alice", PW)
    s.close()
    assert "windows_eventlog: true" in (data / "config.yaml").read_text()
    # upgrade: the locked data folder is not touched, nobody is registered, the task is re-created and started
    rec.calls.clear()
    res = installer.install_service({})
    assert res["upgraded"] is True
    assert not any(c[0] == "icacls" for c in rec.calls)
    assert [c[1] for c in rec.calls if c[0] == "schtasks"] == ["/End", "/Create", "/Run"]


def test_windows_uninstall_keeps_records_and_a_reinstall_finds_them(fake_windows, monkeypatch):
    data, rec, state = fake_windows
    monkeypatch.delenv("ELDOCTOR_HOME", raising=False)
    installer.install_service({"username": "alice", "email": "a@corp.example", "password": PW})
    rec.calls.clear()
    res = installer.uninstall_service()
    assert res["removed"] and not res["purged"]
    assert [c[1] for c in rec.calls if c[0] == "schtasks"] == ["/Query", "/End", "/Delete"]
    assert state["env"]["ELDOCTOR_HOME"] is None and state["marker"] == (str(data), False)
    assert (data / "eldoctor.db").exists()
    res = installer.install_service({})                 # reinstall: no account asked, records reused
    assert res["upgraded"] is True and state["marker"] == (str(data), True)
    res = installer.uninstall_service(purge=True)
    assert res["purged"] and state["marker"] is None and not data.exists()
    assert any(c[0] == "takeown" for c in rec.calls)


def test_windows_first_install_without_an_account_fails_clearly(fake_windows, monkeypatch):
    monkeypatch.delenv("ELDOCTOR_HOME", raising=False)
    with pytest.raises(installer.InstallError) as e:
        installer.install_service({"username": "alice"})
    assert "administrator account" in str(e.value)
    with pytest.raises(installer.InstallError) as e:
        installer.install_service({"username": "alice", "email": "a@corp.example", "password": "weak"})
    assert "weak password" in str(e.value)


# ------------------------------------------------------------------ Linux: systemd service
@pytest.fixture
def fake_linux(monkeypatch, tmp_path):
    rec = Recorder()
    monkeypatch.setattr(installer, "IS_WINDOWS", False)
    monkeypatch.setattr(installer, "IS_LINUX", True)
    monkeypatch.setattr(installer, "is_privileged", lambda: True)
    monkeypatch.setattr(installer, "_run", rec)
    monkeypatch.setattr(installer, "LINUX_DATA", tmp_path / "var-lib-eldoctor")
    monkeypatch.setattr(installer, "LINUX_ETC", tmp_path / "etc-eldoctor")
    monkeypatch.setattr(installer, "LINUX_UNIT_PATH", tmp_path / "eldoctor.service")
    monkeypatch.setattr(installer.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(installer, "agent_command", lambda: ["/opt/eldoctor/eldoctor"])
    return tmp_path, rec


def test_linux_install_and_remove(fake_linux, monkeypatch):
    tmp, rec = fake_linux
    monkeypatch.delenv("ELDOCTOR_HOME", raising=False)
    res = installer.install_service({"username": "bob", "email": "bob@corp.example", "password": PW})
    unit = (tmp / "eldoctor.service").read_text()
    assert f"ExecStart=/opt/eldoctor/eldoctor --config {tmp / 'etc-eldoctor' / 'config.yaml'} service --bootstrap" in unit
    assert "Documentation=file:///usr/share/doc/eldoctor/INSTALL.md" in unit and "CAP_KILL" in unit
    assert rec.names()[-3:] == ["systemctl daemon-reload", "systemctl enable", "systemctl restart"]
    assert (tmp / "var-lib-eldoctor" / "service.key").exists() and oct((tmp / "var-lib-eldoctor").stat().st_mode)[-3:] == "700"
    assert oct((tmp / "etc-eldoctor" / "config.yaml").stat().st_mode)[-3:] == "600"
    assert res["upgraded"] is False
    assert installer.install_service({})["upgraded"] is True              # upgrade: accounts untouched
    res = installer.uninstall_service()
    assert res["removed"] and not (tmp / "eldoctor.service").exists() and (tmp / "var-lib-eldoctor").exists()
    assert installer.uninstall_service() == {"removed": False, "note": "no El Doctor service installed"}


def test_not_elevated_is_refused_and_nothing_installed_is_fine(monkeypatch):
    monkeypatch.setattr(installer, "is_privileged", lambda: False)
    with pytest.raises(installer.InstallError) as e:
        installer.install_service({})
    assert "administrator / root" in str(e.value)
    r = subprocess.run([sys.executable, "-m", "eldoctor", "uninstall-service"], capture_output=True, text=True,
                       cwd=str(ROOT))
    assert r.returncode == 0                                            # uninstallers rely on this


# ------------------------------------------------------------------ clean stop (upgrades must not look like attacks)
def test_agent_shutdown_only_for_the_agents_account(cfg):
    from eldoctor.api.client import ApiClient, ApiError
    from eldoctor.api.peercred import Peer, own_identity
    from eldoctor.api.server import AgentService
    from eldoctor.api.transport import InProcessTransport
    svc = AgentService(cfg)
    try:
        c = ApiClient(InProcessTransport(svc.handle, own_identity(), "t"), "cli")
        c.call("auth.register", username="admin1", password=PW, email="a@example.invalid")
        user = svc.um.get("admin1")
        agent = svc.start_agent(user, "monitor")
        stranger = ApiClient(InProcessTransport(svc.handle, Peer(1, "4242", "mallory", [], "unix"), "t"), "cli")
        with pytest.raises(ApiError) as e:
            stranger.call("agent.shutdown")
        assert e.value.code == "forbidden"
        assert c.call("agent.shutdown") == {"stopping": True}
        agent._thread.join(15)
        assert not agent._thread.is_alive()
        assert [r for r in svc.store.list_audit(200) if r["event"] == "agent_shutdown_requested"]
    finally:
        svc.close()


def test_installer_stops_a_running_agent_cleanly(tmp_path):
    """A real agent process, stopped the way the installers do before replacing its files: clean, so its next
    start records no monitoring-gap alert."""
    env = dict(os.environ, P=PW)
    run = lambda *a: subprocess.run([sys.executable, "-m", "eldoctor", *a], capture_output=True, text=True,
                                    env=env, cwd=str(ROOT), timeout=120)
    key = json.loads(run("register", "--non-interactive", "--username", "owner", "--email", "o@example.invalid",
                         "--password-env", "P", "--json").stdout)["api_key"]
    agent = subprocess.Popen([sys.executable, "-m", "eldoctor", "--api-key", key, "run", "--headless", "--duration",
                              "120", "--interval", "0.5"], env=env, cwd=str(ROOT), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    try:
        from eldoctor.config import home_dir
        end = time.time() + 60
        while not (home_dir() / "agent.lock").exists() and time.time() < end:
            time.sleep(0.3)
        time.sleep(2)
        t0 = time.time()
        assert installer.request_clean_stop(timeout=30)
        assert agent.wait(30) == 0 and time.time() - t0 < 30
    finally:
        if agent.poll() is None:
            agent.kill()
    from eldoctor.storage import Store
    s = Store()
    try:
        assert s.meta_get("activity_state")["clean_stop"] is True
        assert [r for r in s.list_audit(300) if r["event"] == "agent_stopped"]
    finally:
        s.close()


# ------------------------------------------------------------------ Windows setup wizard script (static checks)
def test_setup_wizard_script_is_consistent():
    iss = (ROOT / "packaging" / "windows" / "eldoctor.iss").read_text()
    code = iss.split("[Code]", 1)[1]
    words = re.findall(r"\b(begin|end)\b", re.sub(r"\{[^}]*\}|'[^']*'", "", code), re.I)
    assert words.count("begin") == sum(1 for w in words if w.lower() == "end"), "begin/end do not balance"
    for n, line in enumerate(re.sub(r"\{[^}]*\}", "", code).splitlines(), 1):        # comments removed
        assert line.count("'") % 2 == 0, f"[Code] line {n}: unbalanced quote: {line}"
    for fn in re.findall(r"^(?:function|procedure) (\w+)", code, re.M):
        assert re.search(rf"\b{fn}\b", code.split(fn, 1)[1]) or fn in (
            "InitializeWizard", "ShouldSkipPage", "NextButtonClick", "PrepareToInstall", "CurStepChanged",
            "InitializeUninstall", "CurUninstallStepChanged", "SetEnvironmentVariable"), fn
    # every file the wizard packs is staged by the release builder
    staged = {"El Doctor.exe", "eldoctor.exe", "eldoctor.ico", "LICENSE", "README.md", "INSTALL.md", "CHANGELOG.md",
              "SECURITY.md"}
    sources = set(re.findall(r'Source: "\{#SourceDir\}\\([^"]+)"', iss))
    assert sources == staged, sources ^ staged
    build = (ROOT / "packaging" / "build_release.py").read_text()
    assert 'DOCS = ["README.md", "INSTALL.md", "LICENSE", "CHANGELOG.md", "SECURITY.md"]' in build
    # the CLI commands the wizard calls exist, with the options it passes
    from eldoctor.cli import build_parser
    p = build_parser()
    for argv in (["install-service", "--quiet", "--log", "x.log"], ["uninstall-service", "--quiet", "--purge"],
                 ["uninstall-service", "--stop-only", "--quiet"]):
        p.parse_args(argv)
    assert re.search(r"^AppId=\{\{[0-9A-F-]{36}\}", iss, re.M)        # constant AppId = upgrades find the install
    assert "PrivilegesRequiredOverridesAllowed=dialog" in iss             # 'all users' or 'just me'
    assert "ELDOCTOR_ADMIN_PASSWORD" in iss and "--password" not in iss   # the password never on a command line


# ------------------------------------------------------------------ Linux packages and icons
def test_deb_package_is_accepted_by_dpkg(tmp_path):
    sys.path.insert(0, str(ROOT / "packaging"))
    import linux_packages as lp
    fake = tmp_path / "eldoctor"
    fake.write_text("#!/bin/sh\necho 'El Doctor 9.9.9'\n")
    fake.chmod(0o755)
    deb = lp.build_deb(fake, tmp_path, "9.9.9", "x86_64")
    assert deb.name == "eldoctor_9.9.9_amd64.deb" and deb.read_bytes().startswith(b"!<arch>\ndebian-binary   ")
    for script in (lp.POSTINST, lp.PRERM, lp.POSTRM):
        assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0
    if not shutil.which("dpkg-deb"):
        pytest.skip("dpkg-deb not installed")
    chk = lp.check_deb(deb)
    assert chk["version"] == "El Doctor 9.9.9"
    assert "Package: eldoctor" in chk["info"] and "Depends: libc6 (>= 2.28)" in chk["info"]
    for path in ("./opt/eldoctor/eldoctor", "./usr/bin/eldoctor -> /opt/eldoctor/eldoctor",
                 "./usr/share/applications/eldoctor.desktop", "./usr/share/icons/hicolor/256x256/apps/eldoctor.png"):
        assert path in chk["contents"], path
    assert "root/root" in chk["contents"]


def test_desktop_entry_and_icons():
    desk = (ROOT / "packaging" / "linux" / "eldoctor.desktop").read_text()
    entries = dict(line.split("=", 1) for line in desk.splitlines()[1:] if "=" in line)
    assert desk.startswith("[Desktop Entry]") and entries["Exec"] == "eldoctor gui" and entries["Icon"] == "eldoctor"
    assert entries["Type"] == "Application" and entries["Terminal"] == "false" and entries["StartupWMClass"] == "ElDoctor"
    import struct                                     # header checks: no imaging library needed
    assets = ROOT / "packaging" / "assets"
    ico = (assets / "eldoctor.ico").read_bytes()
    reserved, kind, count = struct.unpack("<HHH", ico[:6])
    widths = {ico[6 + 16 * i] or 256 for i in range(count)}
    assert (reserved, kind) == (0, 1) and {16, 32, 48, 256} <= widths
    assert (assets / "eldoctor.icns").read_bytes()[:4] == b"icns"
    for s in (48, 64, 128, 256, 512):
        png = (assets / f"eldoctor-{s}.png").read_bytes()
        assert png[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", png[16:24]) == (s, s)
    from eldoctor.config import package_data
    assert package_data("icons", "eldoctor-256.png").exists()
    assert "data/icons/*.png" in (ROOT / "pyproject.toml").read_text()


def test_spec_builds_icons_and_the_mac_app():
    spec = (ROOT / "packaging" / "eldoctor.spec").read_text()
    assert 'ICO = os.path.join(SPECPATH, "assets", "eldoctor.ico")' in spec
    assert 'BUNDLE(' in spec and 'name="El Doctor.app"' in spec and "icon=ICNS" in spec
    # everything PyInstaller writes into dist/ must differ when case is ignored (Windows and macOS file systems):
    # "ElDoctor.exe" next to "eldoctor.exe" would silently overwrite it
    outputs = re.findall(r'(?:EXE|COLLECT)\([^)]*?name="([^"]+)"', spec, re.S)
    dist = [n for n in outputs if n != "ElDoctor"]        # the mac EXE lives inside the bundle, not in dist/
    assert len({n.lower() for n in dist}) == len(dist), dist
    assert 'name="El Doctor"' in spec and 'name="eldoctor"' in spec
