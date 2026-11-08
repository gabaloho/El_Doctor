import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from eldoctor.auth.users import AuthError, UserManager, hash_password, verify_password
from eldoctor.cli import main
from eldoctor.deploy.generator import TARGETS, generate

PW = "Str0ng!Passw0rd"


def test_password_hashing():
    h = hash_password("Secret!123x")
    assert h.startswith("pbkdf2_sha256$") and verify_password("Secret!123x", h)
    assert not verify_password("secret!123x", h) and not verify_password("x", "garbage")


def test_registration_rules_and_roles(store, cfg):
    um = UserManager(store, cfg)
    with pytest.raises(AuthError):
        um.register("al", PW, "a@example.invalid")                          # username too short
    with pytest.raises(AuthError):
        um.register("admin_user", "password123", "a@example.invalid")            # weak
    with pytest.raises(AuthError):
        um.register("admin_user", PW, "not-an-email")
    with pytest.raises(AuthError):
        um.register("admin_user", PW, "a@example.invalid", use_case="mining")
    admin, key = um.register("admin_user", PW, "a@example.invalid", use_case="soc", deployment_target="kubernetes")
    assert admin.role == "admin" and key.startswith("edk_")
    user_two, _ = um.register("user_two", "B0b!Passw0rd", "b@example.invalid", role="admin")      # self-registration: role ignored
    assert user_two.role == "viewer" and not user_two.can("run")
    analyst_user, _ = um.register("analyst_user", "C4rol!Passw0rd", "c@example.invalid", role="analyst", created_by=admin)
    assert analyst_user.role == "analyst" and analyst_user.can("approve") and not analyst_user.can("enforce")
    with pytest.raises(AuthError):
        um.register("analyst_user", "C4rol!Passw0rd", "c@example.invalid")
    with pytest.raises(AuthError):
        um.set_role(user_two, "analyst_user", "admin")                       # viewer cannot manage users
    with pytest.raises(AuthError):
        um.set_role(admin, "admin_user", "viewer")                    # last admin cannot demote itself
    assert um.user_for_api_key(key).username == "admin_user"
    row = store.query("SELECT password_hash, api_key_hash FROM users WHERE username='admin_user'")[0]
    assert PW not in row["password_hash"] and key not in row["api_key_hash"]


def test_login_lockout_and_sessions(store, cfg):
    """Lockout in the user manager; sessions are agent-issued JWTs (see tests/test_api.py for the API side)."""
    from eldoctor.api.client import ApiClient, ApiError
    from eldoctor.api.peercred import own_identity
    from eldoctor.api.server import AgentService
    from eldoctor.api.transport import InProcessTransport
    cfg["registration"]["lockout_attempts"] = 3
    um = UserManager(store, cfg)
    um.register("admin_user", PW, "a@example.invalid")
    for _ in range(3):
        with pytest.raises(AuthError):
            um.authenticate("admin_user", "Wrong!Passw0rd")
    with pytest.raises(AuthError, match="locked"):
        um.authenticate("admin_user", PW)
    store.execute("UPDATE users SET locked_until = 0")
    svc = AgentService(cfg, store=store)
    c = ApiClient(InProcessTransport(svc.handle, own_identity(), "test-endpoint"))
    assert c.whoami() is None
    res = c.login("admin_user", PW)
    assert res["token"].count(".") == 2 and c.whoami()["username"] == "admin_user"
    assert ApiClient(InProcessTransport(svc.handle, own_identity(), "test-endpoint")).whoami()["username"] == "admin_user"
    c.logout()                                                   # jti denylisted by the agent
    assert c.whoami() is None
    with pytest.raises(ApiError) as e:
        c.call("alerts.list")
    assert e.value.code == "unauthenticated"


def test_registration_share_is_opt_in(store, cfg, monkeypatch):
    sent = []
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=5: sent.append(req) or open(os.devnull))
    cfg["registration"]["webhook_url"] = "http://collector.example/register"
    um = UserManager(store, cfg)
    um.register("admin_user", PW, "a@example.invalid", consent_share=False)
    assert sent == []
    um.register("bobby", "B0b!Passw0rd", "b@example.invalid", consent_share=True)
    body = json.loads(sent[0].data)
    assert body["username"] == "bobby" and "password" not in json.dumps(body).lower()


@pytest.mark.parametrize("target", TARGETS)
def test_deploy_bundles(tmp_path, target):
    files = generate(target, tmp_path / target, {"username": "admin_user", "email": "a@example.invalid", "use_case": "soc"})
    names = {f.name for f in files}
    assert "README-DEPLOY.md" in names
    for f in files:
        if f.suffix in (".yaml", ".yml"):
            if f.name == "cloud-init.yaml":
                assert f.read_text().startswith("#cloud-config")
            list(yaml.safe_load_all(f.read_text()))              # must be valid YAML
    if target == "windows":
        ps1 = (tmp_path / target / "install.ps1").read_bytes()
        assert b"\r\n" in ps1 and b"Register-ScheduledTask" in ps1 and b"register" in ps1
    if target == "linux":
        unit = (tmp_path / target / "eldoctor.service").read_text()
        assert "service --bootstrap" in unit and "CAP_KILL" in unit
        assert "execve" in (tmp_path / target / "eldoctor-audit.rules").read_text()
        assert subprocess.run(["bash", "-n", str(tmp_path / target / "install.sh")]).returncode == 0
    if target == "kubernetes":
        ds = list(yaml.safe_load_all((tmp_path / target / "30-daemonset.yaml").read_text()))
        spec = ds[1]["spec"]["template"]["spec"]
        assert spec["hostPID"] and "KILL" in spec["containers"][0]["securityContext"]["capabilities"]["add"]
        cfg = yaml.safe_load(yaml.safe_load((tmp_path / target / "10-configmap.yaml").read_text())["data"]["config.yaml"])
        assert "169.254.169.254" in cfg["safety"]["never_block_ips"]
    if target in ("windows", "linux", "docker"):
        z = zipfile.ZipFile(next(f for f in files if f.suffix == ".zip"))
        zn = z.namelist()
        assert any(n.endswith("pyproject.toml") for n in zn) and any(n.endswith("default_config.yaml") for n in zn)
        assert any("rules/sigma/linux" in n for n in zn) and not any("__pycache__" in n for n in zn)


def run_cli(*args, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run([sys.executable, "-m", "eldoctor", *args], capture_output=True, text=True, env=env,
                          cwd=str(Path(__file__).resolve().parents[1]), timeout=120)


def test_cli_requires_registration_then_login(tmp_path):
    r = run_cli("alerts")
    assert r.returncode == 2 and "registration" in r.stderr
    r = run_cli("register", "--non-interactive", "--username", "admin_user", "--email", "a@example.invalid", "--password-env", "P",
                "--use-case", "soc", "--deploy-target", "docker", "--json", env_extra={"P": PW})
    assert r.returncode == 0, r.stderr
    key = json.loads(r.stdout)["api_key"]
    r = run_cli("alerts")
    assert r.returncode == 2 and "log" in r.stderr.lower()
    assert run_cli("--api-key", key, "whoami").returncode == 0
    assert run_cli("login", "--username", "admin_user", "--password-env", "P", env_extra={"P": PW}).returncode == 0
    r = run_cli("whoami")
    assert "role=admin" in r.stdout and "deploy_target=docker" in r.stdout
    r = run_cli("deploy", "--target", "kubernetes", "--out", str(tmp_path / "k8s-out"))
    assert r.returncode == 0 and "30-daemonset.yaml" in r.stdout
    assert run_cli("playbooks", "list").returncode == 0
    assert "SIGMA:" in run_cli("rules").stdout


def test_cli_service_bootstrap(tmp_path):
    env = {"ELDOCTOR_ADMIN_USER": "owner", "ELDOCTOR_ADMIN_EMAIL": "o@example.invalid", "ELDOCTOR_ADMIN_USE_CASE": "cloud",
           "ELDOCTOR_ADMIN_DEPLOY_TARGET": "aws"}
    r = run_cli("service", "--bootstrap", "--duration", "2", "--mode", "monitor", env_extra=env)
    assert r.returncode == 0, r.stderr
    assert "registered admin 'owner'" in r.stdout and "service identity" in r.stdout
    home = Path(os.environ["ELDOCTOR_HOME"])
    assert (home / "service.key").exists() and oct((home / "admin-password").stat().st_mode & 0o777) == "0o600"
    r = run_cli("service", "--duration", "1", "--mode", "monitor")          # second start re-uses the key
    assert r.returncode == 0 and "registered admin" not in r.stdout
