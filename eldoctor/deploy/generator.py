"""Deployment artefact generator.

    eldoctor deploy generate --target windows|linux|docker|kubernetes|aws|azure|gcp --out DIR

Every bundle contains a tuned config.yaml, a README with exact steps and the
El Doctor source archive so the target does not need internet access to PyPI
for El Doctor itself (dependencies: psutil, PyYAML).

Identity: registration is mandatory everywhere.  Interactive installs run
`eldoctor register`; unattended installs (containers, cloud-init) use
`eldoctor service --bootstrap`, which registers the owner from environment
variables and creates a dedicated service API key.

Trust model of every bundle: the service owns the data folder (locked to the
service account at each start) and serves the local API (Unix socket
/run/eldoctor/api.sock, or a named pipe on Windows).  Consoles - CLI, TUI, GUI -
run as ordinary users and are clients of that API; no sudo / "Run as
administrator" is needed to approve or respond.
"""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from eldoctor import __version__
from eldoctor.config import DEFAULT_CONFIG, PACKAGE_DIR

TARGETS = ["windows", "linux", "docker", "kubernetes", "aws", "azure", "gcp"]
SERVER_TARGETS = {"linux", "docker", "kubernetes", "aws", "azure", "gcp"}
SRC_ZIP = f"eldoctor-{__version__}-src.zip"


def default_mode(target: str) -> str:
    return "interactive" if target == "windows" else "enforce"


def build_source_zip(dest: Path) -> Path:
    """Zip the installable project (pyproject + package) - pip can install the zip directly."""
    project = PACKAGE_DIR.parent
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        root = f"eldoctor-{__version__}"
        for extra in ("pyproject.toml", "README.md", "LICENSE", "requirements.txt"):
            if (project / extra).exists():
                zf.write(project / extra, f"{root}/{extra}")
        for path in sorted(PACKAGE_DIR.rglob("*")):
            if "__pycache__" in path.parts or path.suffix == ".pyc" or path.is_dir():
                continue
            zf.write(path, f"{root}/eldoctor/{path.relative_to(PACKAGE_DIR).as_posix()}")
    out = dest / SRC_ZIP
    out.write_bytes(buf.getvalue())
    return out


def tuned_config(target: str, mode: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    cfg = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    cfg["agent"]["mode"] = mode
    chans: List[Dict[str, Any]] = [{"type": "jsonl", "path": "alerts.jsonl"}]
    if target == "windows":
        cfg["logs"]["windows_eventlog"] = True
        cfg["logs"]["files"] = []
        cfg["logs"]["journald"] = False
        chans.insert(0, {"type": "console"})
    elif target in ("docker", "kubernetes"):
        cfg["logs"]["files"] = ["/host/var/log/auth.log", "/host/var/log/secure", "/host/var/log/syslog",
                                "/host/var/log/messages"]
        cfg["logs"]["journald"] = False
        cfg["logs"]["auditd_path"] = "/host/var/log/audit/audit.log"
        chans.insert(0, {"type": "console"})
    else:
        cfg["logs"]["journald"] = "auto"
        chans.insert(0, {"type": "console"})
    if target in ("aws", "azure", "gcp", "kubernetes"):
        # never cut the VM off its metadata / control plane
        cfg["safety"]["never_block_ips"] = sorted(set(cfg["safety"]["never_block_ips"] + ["169.254.169.254",
                                                                                          "168.63.129.16",
                                                                                          "169.254.169.253"]))
    chans += [
        {"type": "email", "enabled": False, "smtp_host": "smtp.example.com", "smtp_port": 587, "starttls": True,
         "username": profile.get("email", "alerts@example.com"), "password_env": "ELDOCTOR_SMTP_PASSWORD",
         "from": profile.get("email", "alerts@example.com"), "to": [profile.get("email", "soc@example.com")],
         "min_severity": "high"},
        {"type": "slack", "enabled": False, "url_env": "ELDOCTOR_SLACK_WEBHOOK"},
        {"type": "teams", "enabled": False, "url_env": "ELDOCTOR_TEAMS_WEBHOOK"},
        {"type": "discord", "enabled": False, "url_env": "ELDOCTOR_DISCORD_WEBHOOK"},
        {"type": "webhook", "name": "shuffle", "enabled": False, "url_env": "ELDOCTOR_SHUFFLE_WEBHOOK",
         "secret_env": "ELDOCTOR_WEBHOOK_SECRET"},
        {"type": "thehive", "enabled": False, "url": "http://thehive.example.com:9000",
         "api_key_env": "ELDOCTOR_THEHIVE_KEY", "version": 5},
        {"type": "syslog", "enabled": False, "host": "siem.example.com", "port": 514, "protocol": "udp",
         "format": "cef"},
    ]
    cfg["notifications"]["channels"] = chans
    # tamper-evident audit trail: also forwarded to any enabled syslog channel above; dedicated SIEM input here
    cfg.setdefault("audit", {})["forward"] = [
        {"type": "syslog", "enabled": False, "host": "siem.example.com", "port": 6514, "protocol": "tls",
         "format": "cef"},
        {"type": "webhook", "enabled": False, "url_env": "ELDOCTOR_AUDIT_WEBHOOK", "secret_env": "ELDOCTOR_WEBHOOK_SECRET"},
    ]
    return cfg


# --------------------------------------------------------------------------- templates
ENV_EXAMPLE = """# El Doctor secrets - keep this file readable by root/SYSTEM only.
# Owner used by `eldoctor service --bootstrap` for unattended registration:
ELDOCTOR_ADMIN_USER={username}
ELDOCTOR_ADMIN_EMAIL={email}
ELDOCTOR_ADMIN_NAME={full_name}
ELDOCTOR_ADMIN_ORG={organization}
ELDOCTOR_ADMIN_USE_CASE={use_case}
ELDOCTOR_ADMIN_DEPLOY_TARGET={target}
# ELDOCTOR_ADMIN_PASSWORD=   # leave empty: a random one is generated and stored 0600 in ELDOCTOR_HOME
# Notification secrets (referenced by *_env keys in config.yaml)
ELDOCTOR_SMTP_PASSWORD=
ELDOCTOR_SLACK_WEBHOOK=
ELDOCTOR_TEAMS_WEBHOOK=
ELDOCTOR_DISCORD_WEBHOOK=
ELDOCTOR_SHUFFLE_WEBHOOK=
ELDOCTOR_WEBHOOK_SECRET=
ELDOCTOR_THEHIVE_KEY=
"""

LINUX_UNIT = """[Unit]
Description=El Doctor endpoint monitoring & response agent
Documentation=file:///opt/eldoctor/README-DEPLOY.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/eldoctor/eldoctor.env
Environment=ELDOCTOR_HOME=/var/lib/eldoctor
# Local API for the CLI / TUI / GUI of every user (token + kernel peer credentials, RBAC inside the agent)
Environment=ELDOCTOR_SOCKET=/run/eldoctor/api.sock
RuntimeDirectory=eldoctor
RuntimeDirectoryMode=0755
# Data folder (DB, keys, evidence, quarantine): root only - re-checked and repaired at every start
StateDirectory=eldoctor
StateDirectoryMode=0700
ExecStart=/opt/eldoctor/venv/bin/eldoctor --config /etc/eldoctor/config.yaml service --bootstrap
Restart=on-failure
RestartSec=5
# Response actions need: kill/suspend (CAP_KILL), read other processes (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH),
# renice (CAP_SYS_NICE), firewall (CAP_NET_ADMIN), quarantine moves (CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_CHOWN)
CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN CAP_SYS_NICE CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
PrivateTmp=no
UMask=0077
Nice=-5

[Install]
WantedBy=multi-user.target
"""

LINUX_INSTALL = """#!/usr/bin/env bash
# El Doctor installer for Linux hosts / cloud VMs (systemd).
set -euo pipefail
HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
[[ $EUID -eq 0 ]] || {{ echo "run as root (sudo $0)"; exit 1; }}

if ! command -v python3 >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update -y && apt-get install -y python3 python3-venv python3-pip
  elif command -v dnf >/dev/null; then dnf install -y python3 python3-pip
  elif command -v yum >/dev/null; then yum install -y python3 python3-pip
  else echo "install python3 (>=3.9) first"; exit 1; fi
fi
python3 -m venv --help >/dev/null 2>&1 || {{ command -v apt-get >/dev/null && apt-get install -y python3-venv; }}

install -d -m 0755 /opt/eldoctor
install -d -m 0700 /etc/eldoctor /var/lib/eldoctor
python3 -m venv /opt/eldoctor/venv
/opt/eldoctor/venv/bin/pip install --upgrade pip >/dev/null
PKG="${{ELDOCTOR_PACKAGE:-$HERE/{src_zip}}}"
/opt/eldoctor/venv/bin/pip install "$PKG"
ln -sf /opt/eldoctor/venv/bin/eldoctor /usr/local/bin/eldoctor

[[ -f /etc/eldoctor/config.yaml ]] || install -m 0600 "$HERE/config.yaml" /etc/eldoctor/config.yaml
[[ -f /etc/eldoctor/eldoctor.env ]] || install -m 0600 "$HERE/eldoctor.env.example" /etc/eldoctor/eldoctor.env
cp "$HERE/README-DEPLOY.md" /opt/eldoctor/ 2>/dev/null || true
# Full exec telemetry via auditd (recommended): catches processes that live only milliseconds
if command -v auditctl >/dev/null || {{ command -v apt-get >/dev/null && apt-get install -y auditd >/dev/null; }}; then
  install -m 0640 "$HERE/eldoctor-audit.rules" /etc/audit/rules.d/eldoctor.rules
  (augenrules --load || auditctl -R /etc/audit/rules.d/eldoctor.rules) >/dev/null 2>&1 || true
  systemctl enable --now auditd >/dev/null 2>&1 || true
fi
install -m 0644 "$HERE/eldoctor.service" /etc/systemd/system/eldoctor.service

export ELDOCTOR_HOME=/var/lib/eldoctor
if [[ -t 0 && "${{ELDOCTOR_UNATTENDED:-0}}" != "1" ]]; then
  echo "== Registration is required before El Doctor can run =="
  eldoctor --config /etc/eldoctor/config.yaml register || true
  echo "== Log in to create the service identity =="
  eldoctor --config /etc/eldoctor/config.yaml login && eldoctor --config /etc/eldoctor/config.yaml service-key
fi

systemctl daemon-reload
systemctl enable --now eldoctor.service
systemctl --no-pager status eldoctor.service | head -5 || true
echo "Installed. Logs: journalctl -u eldoctor -f   Alerts: /var/lib/eldoctor/alerts.jsonl"
echo "Console (any user, no sudo - talks to the service over /run/eldoctor/api.sock): eldoctor login && eldoctor tui"
echo "Audit trail: eldoctor audit verify  (admins; configure audit.forward in /etc/eldoctor/config.yaml for your SIEM)"
"""

AUDIT_RULES = """## El Doctor: record every program execution (feeds Sigma/IOC/YARA with short-lived processes too)
-a always,exit -F arch=b64 -S execve,execveat -F key=eldoctor_exec
-a always,exit -F arch=b32 -S execve,execveat -F key=eldoctor_exec
"""

LINUX_UNINSTALL = """#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
systemctl disable --now eldoctor.service 2>/dev/null || true
rm -f /etc/systemd/system/eldoctor.service /usr/local/bin/eldoctor
systemctl daemon-reload
rm -rf /opt/eldoctor
echo "Removed binaries. Data kept in /var/lib/eldoctor and config in /etc/eldoctor (delete manually)."
"""

WIN_INSTALL = r"""#Requires -RunAsAdministrator
<#
  El Doctor installer for Windows 10/11 and Windows Server.
    -Mode Service : unattended agent (Scheduled Task as SYSTEM at boot) - recommended for servers
    -Mode Desktop : Start-menu / desktop shortcut that opens the interactive console (approval prompts)
  Tip: install Sysmon (https://learn.microsoft.com/sysinternals/downloads/sysmon) so El Doctor's
  Sigma rules see full process-creation and network events.
#>
param(
  [ValidateSet("Service", "Desktop", "Both")] [string]$Mode = "{win_mode}",
  [string]$InstallDir = "$env:ProgramFiles\ElDoctor",
  [string]$DataDir = "$env:ProgramData\ElDoctor"
)
$ErrorActionPreference = "Stop"
$py = Get-Command py -ErrorAction SilentlyContinue
$pyArgs = @("-3")
if (-not $py) {{ $py = Get-Command python -ErrorAction SilentlyContinue; $pyArgs = @() }}
if (-not $py) {{ throw "Python 3.9+ is required. Install it with: winget install Python.Python.3.12" }}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
& $py.Source @pyArgs -m venv "$InstallDir\venv"
$vpy = "$InstallDir\venv\Scripts\python.exe"
& $vpy -m pip install --upgrade pip | Out-Null
& $vpy -m pip install "$PSScriptRoot\{src_zip}" windows-curses
if (-not (Test-Path "$DataDir\config.yaml")) {{ Copy-Item "$PSScriptRoot\config.yaml" "$DataDir\config.yaml" }}

# Data directory: SYSTEM + Administrators during installation (registration below). The service then locks it
# to SYSTEM only at every start; analysts and admins use the agent's named-pipe API, not the files.
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
[Environment]::SetEnvironmentVariable("ELDOCTOR_HOME", $DataDir, "Machine")
$env:ELDOCTOR_HOME = $DataDir
$exe = "$InstallDir\venv\Scripts\eldoctor.exe"
$cfg = "$DataDir\config.yaml"

Write-Host "== Registration is required before El Doctor can run ==" -ForegroundColor Cyan
& $exe --config $cfg register
Write-Host "== Log in ==" -ForegroundColor Cyan
& $exe --config $cfg login

if ($Mode -in @("Service", "Both")) {{
  & $exe --config $cfg service-key
  $action = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$cfg`" service"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName "ElDoctor Agent" -Action $action -Trigger $trigger -Principal $principal `
              -Settings $settings -Description "El Doctor endpoint monitoring & response" -Force | Out-Null
  Start-ScheduledTask -TaskName "ElDoctor Agent"
  Write-Host "Service mode: Scheduled Task 'ElDoctor Agent' running as SYSTEM (data folder: SYSTEM only)." -ForegroundColor Green
}}
if ($Mode -in @("Desktop", "Both")) {{
  # Desktop GUI (windowed - no console) + the terminal console as a second shortcut.
  # With the service installed they run as the normal user: they are clients of the service's API and the
  # service (SYSTEM) performs kill/suspend/quarantine after checking the user's role. Desktop-only installs
  # host the agent inside the GUI, so those shortcuts are flagged "Run as administrator".
  $elevate = ($Mode -eq "Desktop")
  $gui = "$InstallDir\venv\Scripts\eldoctor-gui.exe"
  $ws = New-Object -ComObject WScript.Shell
  foreach ($dir in @([Environment]::GetFolderPath("CommonDesktopDirectory"), "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")) {{
    $lnk = $ws.CreateShortcut("$dir\El Doctor.lnk")
    $lnk.TargetPath = $gui
    $lnk.Arguments = "--config `"$cfg`""
    $lnk.WorkingDirectory = $DataDir
    $lnk.Description = "El Doctor security console (GUI)"
    $lnk.Save()
    $con = $ws.CreateShortcut("$dir\El Doctor (terminal).lnk")
    $con.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $con.Arguments = "-NoExit -Command `"`$env:ELDOCTOR_HOME='$DataDir'; & '$exe' --config '$cfg' tui`""
    $con.Description = "El Doctor terminal console"
    $con.Save()
    if ($elevate) {{
      foreach ($p in @("$dir\El Doctor.lnk", "$dir\El Doctor (terminal).lnk")) {{
        $bytes = [IO.File]::ReadAllBytes($p); $bytes[0x15] = $bytes[0x15] -bor 0x20; [IO.File]::WriteAllBytes($p, $bytes)
      }}
    }}
  }}
  Write-Host "Desktop mode: 'El Doctor' (GUI) and 'El Doctor (terminal)' shortcuts created." -ForegroundColor Green
}}
Write-Host "Alerts: $DataDir\alerts.jsonl   Evidence: $DataDir\evidence   Quarantine: $DataDir\quarantine"
"""

WIN_UNINSTALL = r"""#Requires -RunAsAdministrator
param([string]$InstallDir = "$env:ProgramFiles\ElDoctor")
Unregister-ScheduledTask -TaskName "ElDoctor Agent" -Confirm:$false -ErrorAction SilentlyContinue
Get-Process eldoctor -ErrorAction SilentlyContinue | Stop-Process -Force
foreach ($dir in @([Environment]::GetFolderPath("CommonDesktopDirectory"), "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")) {
  Remove-Item "$dir\El Doctor.lnk", "$dir\El Doctor (terminal).lnk" -ErrorAction SilentlyContinue }
Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
Write-Host "Removed. Data kept in $env:ProgramData\ElDoctor (delete manually)."
"""

DOCKERFILE = """FROM python:3.12-slim
LABEL org.opencontainers.image.title="El Doctor" org.opencontainers.image.version="{version}"
RUN apt-get update && apt-get install -y --no-install-recommends iptables procps && rm -rf /var/lib/apt/lists/*
COPY {src_zip} /tmp/
RUN pip install --no-cache-dir /tmp/{src_zip} && rm /tmp/{src_zip}
COPY config.yaml /etc/eldoctor/config.yaml
ENV ELDOCTOR_HOME=/var/lib/eldoctor ELDOCTOR_CLIENT_DIR=/tmp/eldoctor-client PYTHONUNBUFFERED=1
VOLUME ["/var/lib/eldoctor"]
# Root inside the container is required to act on *host* processes (pid: host) - capabilities are
# restricted in docker-compose.yml / the DaemonSet instead of granting --privileged.
ENTRYPOINT ["eldoctor", "--config", "/etc/eldoctor/config.yaml"]
CMD ["service", "--bootstrap"]
"""

COMPOSE = """services:
  eldoctor:
    build: .
    image: {image}
    container_name: eldoctor
    restart: unless-stopped
    pid: host                 # see and respond to host processes
    network_mode: host        # see host connections, manage host firewall
    cap_drop: [ALL]
    cap_add: [KILL, SYS_PTRACE, DAC_READ_SEARCH, DAC_OVERRIDE, FOWNER, CHOWN, SYS_NICE, NET_ADMIN, NET_RAW]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    env_file: [.env]
    volumes:
      - eldoctor-data:/var/lib/eldoctor
      - /var/log:/host/var/log:ro
      # Uncomment to allow quarantine of host files (exe paths are host paths):
      # - /:/host:rw
    stdin_open: true
    tty: true                 # `docker attach eldoctor` / `docker exec -it eldoctor eldoctor tui`
volumes:
  eldoctor-data:
"""

K8S_NS = """apiVersion: v1
kind: Namespace
metadata:
  name: eldoctor
  labels:
    pod-security.kubernetes.io/enforce: privileged   # hostPID/hostNetwork DaemonSet
"""

K8S_DS = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: eldoctor
  namespace: eldoctor
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: eldoctor
  namespace: eldoctor
  labels: {{app.kubernetes.io/name: eldoctor, app.kubernetes.io/version: "{version}"}}
spec:
  selector:
    matchLabels: {{app.kubernetes.io/name: eldoctor}}
  updateStrategy: {{type: RollingUpdate}}
  template:
    metadata:
      labels: {{app.kubernetes.io/name: eldoctor}}
    spec:
      serviceAccountName: eldoctor
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      priorityClassName: system-node-critical
      tolerations:
        - operator: Exists            # run on every node, including control plane
      containers:
        - name: eldoctor
          image: {image}
          imagePullPolicy: IfNotPresent
          args: ["service", "--bootstrap"]
          envFrom:
            - secretRef: {{name: eldoctor-secrets}}
          env:
            - {{name: ELDOCTOR_HOME, value: /var/lib/eldoctor}}
            - {{name: ELDOCTOR_CLIENT_DIR, value: /tmp/eldoctor-client}}
            - name: NODE_NAME
              valueFrom: {{fieldRef: {{fieldPath: spec.nodeName}}}}
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
              add: [KILL, SYS_PTRACE, DAC_READ_SEARCH, DAC_OVERRIDE, FOWNER, CHOWN, SYS_NICE, NET_ADMIN, NET_RAW]
          resources:
            requests: {{cpu: 50m, memory: 96Mi}}
            limits: {{cpu: 500m, memory: 384Mi}}
          volumeMounts:
            - {{name: config, mountPath: /etc/eldoctor, readOnly: true}}
            - {{name: data, mountPath: /var/lib/eldoctor}}
            - {{name: varlog, mountPath: /host/var/log, readOnly: true}}
            - {{name: tmp, mountPath: /tmp}}
      volumes:
        - name: config
          configMap: {{name: eldoctor-config}}
        - name: data
          hostPath: {{path: /var/lib/eldoctor, type: DirectoryOrCreate}}
        - name: varlog
          hostPath: {{path: /var/log}}
        - name: tmp
          emptyDir: {{}}
"""

K8S_SECRET = """apiVersion: v1
kind: Secret
metadata:
  name: eldoctor-secrets
  namespace: eldoctor
type: Opaque
stringData:
  ELDOCTOR_ADMIN_USER: "{username}"
  ELDOCTOR_ADMIN_EMAIL: "{email}"
  ELDOCTOR_ADMIN_NAME: "{full_name}"
  ELDOCTOR_ADMIN_ORG: "{organization}"
  ELDOCTOR_ADMIN_USE_CASE: "{use_case}"
  ELDOCTOR_ADMIN_DEPLOY_TARGET: "kubernetes"
  ELDOCTOR_SLACK_WEBHOOK: ""
  ELDOCTOR_SHUFFLE_WEBHOOK: ""
  ELDOCTOR_WEBHOOK_SECRET: ""
  ELDOCTOR_THEHIVE_KEY: ""
"""

CLOUD_INIT = """#cloud-config
# El Doctor bootstrap for {cloud_name} VMs (Ubuntu/Debian/RHEL-family images with cloud-init).
package_update: true
packages: [python3, python3-venv, python3-pip, curl, unzip, auditd]
write_files:
  - path: /etc/audit/rules.d/eldoctor.rules
    permissions: "0640"
    content: |
      -a always,exit -F arch=b64 -S execve,execveat -F key=eldoctor_exec
      -a always,exit -F arch=b32 -S execve,execveat -F key=eldoctor_exec
  - path: /etc/eldoctor/config.yaml
    permissions: "0600"
    encoding: b64
    content: {config_b64}
  - path: /etc/eldoctor/eldoctor.env
    permissions: "0600"
    content: |
      ELDOCTOR_ADMIN_USER={username}
      ELDOCTOR_ADMIN_EMAIL={email}
      ELDOCTOR_ADMIN_NAME={full_name}
      ELDOCTOR_ADMIN_ORG={organization}
      ELDOCTOR_ADMIN_USE_CASE={use_case}
      ELDOCTOR_ADMIN_DEPLOY_TARGET={target}
  - path: /etc/systemd/system/eldoctor.service
    permissions: "0644"
    encoding: b64
    content: {unit_b64}
runcmd:
  - augenrules --load || true
  - install -d -m 0700 /var/lib/eldoctor
  - python3 -m venv /opt/eldoctor/venv
  - /opt/eldoctor/venv/bin/pip install --upgrade pip
  # Host the source zip somewhere the VM can reach (S3/Blob/GCS bucket, release page, git):
  - /opt/eldoctor/venv/bin/pip install "{package_url}"
  - ln -sf /opt/eldoctor/venv/bin/eldoctor /usr/local/bin/eldoctor
  - systemctl daemon-reload
  - systemctl enable --now eldoctor.service
"""

TERRAFORM_AWS = """# Minimal example - adapt AMI / subnet / key pair to your environment.
terraform {{
  required_providers {{ aws = {{ source = "hashicorp/aws", version = ">= 5.0" }} }}
}}
provider "aws" {{ region = var.region }}
variable "region" {{ default = "us-east-1" }}
variable "instance_type" {{ default = "t3.small" }}

data "aws_ami" "ubuntu" {{
  most_recent = true
  owners      = ["099720109477"]
  filter {{
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }}
}}

resource "aws_instance" "eldoctor_host" {{
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  user_data     = file("${{path.module}}/cloud-init.yaml")
  metadata_options {{
    http_tokens = "required"   # IMDSv2 only
  }}
  tags = {{ Name = "eldoctor-protected", ManagedBy = "eldoctor" }}
}}
"""

GCP_STARTUP = """#!/bin/bash
# GCE startup-script: installs El Doctor once, then keeps the systemd service running.
set -euo pipefail
if [[ -x /opt/eldoctor/venv/bin/eldoctor ]]; then systemctl start eldoctor.service; exit 0; fi
apt-get update -y && apt-get install -y python3 python3-venv python3-pip auditd
printf -- '-a always,exit -F arch=b64 -S execve,execveat -F key=eldoctor_exec\n' > /etc/audit/rules.d/eldoctor.rules
augenrules --load || true
install -d -m 0700 /etc/eldoctor /var/lib/eldoctor
echo '{config_b64}' | base64 -d > /etc/eldoctor/config.yaml && chmod 600 /etc/eldoctor/config.yaml
cat > /etc/eldoctor/eldoctor.env <<'ENV'
ELDOCTOR_ADMIN_USER={username}
ELDOCTOR_ADMIN_EMAIL={email}
ELDOCTOR_ADMIN_NAME={full_name}
ELDOCTOR_ADMIN_ORG={organization}
ELDOCTOR_ADMIN_USE_CASE={use_case}
ELDOCTOR_ADMIN_DEPLOY_TARGET=gcp
ENV
chmod 600 /etc/eldoctor/eldoctor.env
echo '{unit_b64}' | base64 -d > /etc/systemd/system/eldoctor.service
python3 -m venv /opt/eldoctor/venv
/opt/eldoctor/venv/bin/pip install --upgrade pip
/opt/eldoctor/venv/bin/pip install "{package_url}"
ln -sf /opt/eldoctor/venv/bin/eldoctor /usr/local/bin/eldoctor
systemctl daemon-reload && systemctl enable --now eldoctor.service
"""

README_COMMON = """
## After installation

* Desktop GUI:        `eldoctor gui`  (Windows: `eldoctor-gui`, no console window)
* Console (TUI):      `eldoctor login && eldoctor tui`   - as a normal user: consoles are clients of the service API
* Pending approvals:  `eldoctor approvals list` / `eldoctor approvals approve <id>`
* Alerts / actions:   `eldoctor alerts`, `eldoctor actions`
* Threat intel:       `eldoctor intel update` (abuse.ch, Emerging Threats ... needs outbound HTTPS)
* Change mode:        edit `agent.mode` in config.yaml (monitor | interactive | enforce) and restart
* Notifications:      enable channels in config.yaml and put secrets in the env file / secret
* Audit trail:        `eldoctor audit` / `eldoctor audit verify` (admin). Hash-chained and signed with forward-secure
                      one-time keys, forwarded in real time to `audit.forward` destinations and to enabled syslog
                      channels - point it at your SIEM. Right after installation run `eldoctor audit verify` and
                      record the printed *genesis signing key* off-host (or pin it in audit.genesis_fingerprint).

Security model: only the service account can read or write the data folder; every request from the CLI / TUI /
GUI is authenticated by the agent (session token bound to the OS account, or API key) and checked against the
user's role inside the agent. Approvals, roles and the audit trail are sealed with the agent's key - editing the
database does not approve anything, it raises a critical ED-INT-001 incident.

Response mode of this bundle: **{mode}**.
- monitor: alerts only, destructive actions recorded as "would run"
- interactive: suspend/renice automatically, kill/quarantine/block after approval
- enforce: playbooks act automatically (safety guards + circuit breaker still apply)
"""


def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()


def generate(target: str, out_dir: Path, profile: Optional[Dict[str, Any]] = None, mode: Optional[str] = None,
             image: str = "eldoctor:latest", package_url: str = "", win_mode: str = "Both") -> List[Path]:
    if target not in TARGETS:
        raise ValueError(f"target must be one of {TARGETS}")
    profile = dict(profile or {})
    profile.setdefault("username", "admin")
    profile.setdefault("email", "admin@example.com")
    profile.setdefault("full_name", "")
    profile.setdefault("organization", "")
    profile.setdefault("use_case", "cloud" if target in SERVER_TARGETS else "personal")
    mode = mode or default_mode(target)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files: List[Path] = []

    def write(name: str, text: str, executable: bool = False) -> None:
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\r\n" if name.endswith((".ps1", ".bat")) else "\n")
        if executable:
            os.chmod(p, 0o755)
        files.append(p)

    cfg = tuned_config(target, mode, profile)
    cfg_text = f"# El Doctor configuration generated for target '{target}'\n" + yaml.safe_dump(cfg, sort_keys=False)
    fmt = dict(profile, target=target, version=__version__, src_zip=SRC_ZIP, image=image, mode=mode,
               win_mode=win_mode)
    pkg_url = package_url or f"https://YOUR-BUCKET.example.com/{SRC_ZIP}"

    if target != "kubernetes":
        write("config.yaml", cfg_text)
    if target in ("windows", "linux", "docker"):
        files.append(build_source_zip(out))

    if target == "linux":
        write("install.sh", LINUX_INSTALL.format(**fmt), executable=True)
        write("uninstall.sh", LINUX_UNINSTALL, executable=True)
        write("eldoctor.service", LINUX_UNIT)
        write("eldoctor-audit.rules", AUDIT_RULES)
        write("eldoctor.env.example", ENV_EXAMPLE.format(**fmt))
        steps = ("1. Copy this folder to the host.\n2. `sudo ./install.sh` - installs to /opt/eldoctor, asks you to "
                 "register + log in, creates the service identity and starts `eldoctor.service`.\n"
                 "   Unattended: `sudo ELDOCTOR_UNATTENDED=1 ./install.sh` (owner details from /etc/eldoctor/eldoctor.env).")
    elif target == "windows":
        write("install.ps1", WIN_INSTALL.format(**fmt))
        write("uninstall.ps1", WIN_UNINSTALL)
        write("run-console.bat", "@echo off\r\nset ELDOCTOR_HOME=%ProgramData%\\ElDoctor\r\n"
                                 "\"%ProgramFiles%\\ElDoctor\\venv\\Scripts\\eldoctor.exe\" --config "
                                 "\"%ProgramData%\\ElDoctor\\config.yaml\" tui\r\n")
        steps = ("1. Install Python 3.9+ (`winget install Python.Python.3.12`). Optional but recommended: Sysmon.\n"
                 "2. Open **PowerShell as Administrator** in this folder.\n"
                 "3. `Set-ExecutionPolicy -Scope Process Bypass; .\\install.ps1 -Mode Desktop|Service|Both`\n"
                 "   - Desktop: 'El Doctor' desktop/Start-menu shortcut opens the GUI (dashboard, alerts, approvals,\n"
                 "     one-click response). A terminal-console shortcut is created too.\n"
                 "   - Service: Scheduled Task as SYSTEM at boot, headless, protects the machine without anyone logged in.\n"
                 "   - Both (recommended): the shortcuts run as the normal user and attach to the service through its\n"
                 "     named-pipe API; the service checks every permission and holds the only copy of the data.")
    elif target == "docker":
        write("Dockerfile", DOCKERFILE.format(**fmt))
        write("docker-compose.yml", COMPOSE.format(**fmt))
        write(".env.example", ENV_EXAMPLE.format(**fmt))
        write(".dockerignore", "*.md\n.env\n")
        steps = ("1. `cp .env.example .env` and fill in owner + notification secrets.\n"
                 "2. `docker compose up -d --build`\n"
                 "3. Console: `docker exec -it eldoctor eldoctor tui` (log in with the generated admin password from "
                 "`docker exec eldoctor cat /var/lib/eldoctor/admin-password`).\n"
                 "Host processes are visible via `pid: host`; host firewall via `network_mode: host` + NET_ADMIN.")
    elif target == "kubernetes":
        write("00-namespace.yaml", K8S_NS)
        write("10-configmap.yaml", yaml.safe_dump({"apiVersion": "v1", "kind": "ConfigMap",
                                                   "metadata": {"name": "eldoctor-config", "namespace": "eldoctor"},
                                                   "data": {"config.yaml": cfg_text}}, sort_keys=False))
        write("20-secret.example.yaml", K8S_SECRET.format(**fmt))
        write("30-daemonset.yaml", K8S_DS.format(**fmt))
        write("kustomization.yaml", "resources:\n  - 00-namespace.yaml\n  - 10-configmap.yaml\n"
                                    "  - 20-secret.example.yaml\n  - 30-daemonset.yaml\n")
        steps = ("1. Build & push the image: `eldoctor deploy generate --target docker --out img && "
                 f"docker build -t {image} img && docker push {image}`\n"
                 "2. Edit `20-secret.example.yaml` (owner + webhook secrets).\n"
                 "3. `kubectl apply -k .`  -> one agent per node (hostPID/hostNetwork, minimal capabilities).\n"
                 "4. Alerts: `kubectl -n eldoctor logs ds/eldoctor -f`; ship `/var/lib/eldoctor/alerts.jsonl` "
                 "to your SIEM or enable the webhook/syslog channels.")
    else:  # cloud VMs
        unit = LINUX_UNIT
        cfmt = dict(fmt, config_b64=_b64(cfg_text), unit_b64=_b64(unit), package_url=pkg_url,
                    cloud_name={"aws": "AWS EC2", "azure": "Azure", "gcp": "Google Cloud"}[target])
        files.append(build_source_zip(out))
        if target == "gcp":
            write("startup-script.sh", GCP_STARTUP.format(**cfmt), executable=True)
            steps = (f"1. Upload `{SRC_ZIP}` to a bucket the VM can read and set its URL (regenerate with "
                     "`--package-url`).\n2. `gcloud compute instances create eldoctor-vm --image-family=ubuntu-2404-lts-amd64 "
                     "--image-project=ubuntu-os-cloud --metadata-from-file startup-script=startup-script.sh`")
        else:
            write("cloud-init.yaml", CLOUD_INIT.format(**cfmt))
            if target == "aws":
                write("main.tf", TERRAFORM_AWS.format(**cfmt))
                steps = (f"1. Upload `{SRC_ZIP}` to S3 (pre-signed URL) or a release page; regenerate with "
                         "`--package-url URL`.\n2. `aws ec2 run-instances --image-id <ubuntu-ami> --instance-type t3.small "
                         "--user-data file://cloud-init.yaml --metadata-options HttpTokens=required`\n"
                         "   or `terraform init && terraform apply` with the included main.tf.")
            else:
                steps = (f"1. Upload `{SRC_ZIP}` to Blob Storage (SAS URL); regenerate with `--package-url URL`.\n"
                         "2. `az vm create -g <rg> -n eldoctor-vm --image Ubuntu2404 --custom-data cloud-init.yaml "
                         "--generate-ssh-keys`")
        steps += ("\n3. Registration happens unattended from the owner details embedded here; the admin password is "
                  "generated on the VM: `sudo cat /var/lib/eldoctor/admin-password`.\n"
                  "4. Cloud metadata endpoints (169.254.169.254, 168.63.129.16) are on the never-block list.")
    readme = (f"# El Doctor deployment bundle - {target}\n\nGenerated for **{profile['username']}** "
              f"({profile['email']}), use case: {profile['use_case']}.\n\n## Install\n\n{steps}\n"
              + README_COMMON.format(mode=mode))
    write("README-DEPLOY.md", readme)
    return files
