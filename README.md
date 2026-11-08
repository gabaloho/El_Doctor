# El Doctor 2.0 — monitoring, threat detection & automated response

El Doctor started as a curses tool that showed CPU / memory / disk / network, logged them to CSV and
e-mailed when a threshold was crossed. Version 2 rebuilds it as a Python package (`eldoctor/`) that
turns it into a small **endpoint security tool with SOAR-style playbooks**:

* **detects** resource abuse, cryptominers, reverse shells, droppers, fileless/deleted binaries,
  masquerading, threat-intel hits (hash / C2 IP / domain), brute force and log tampering, using
  heuristics, **Sigma** rules, **IOC feeds** (abuse.ch, Emerging Threats) and **YARA**. Every alert is
  mapped to **MITRE ATT&CK**.
* **responds** through YAML playbooks: renice, suspend, collect forensics, quarantine, kill (process
  tree), block IP. There are three modes (**monitor / interactive approval / enforce**), and safety
  guards and a circuit breaker sit in front of every action.
* **notifies** through e-mail, Slack, Microsoft Teams, Discord, webhooks for **Shuffle / n8n / Tines**
  (HMAC-signed), **TheHive**, syslog (RFC 5424 / **CEF**) and JSONL.
* **requires registration** before use, with roles (admin / analyst / viewer), stateless session
  tokens (JWT) bound to the OS account, API keys and login lockout.
* **keeps the agent as the only trust anchor**: the CLI, TUI and GUI are clients of a local
  authenticated API (Unix socket / Windows named pipe with OS peer credentials). Every permission is
  checked *inside the agent*; approvals, roles and the **hash-chained audit trail** are sealed with a
  key only the agent holds, and the audit trail is forwarded to your SIEM in real time (section 6b).
* **records user activity for forensics and triage** (section 5b): who is logged in, which
  applications each person runs, and which files they create, edit, delete, rename, open or download,
  with *who did it* and *how we know*. The record survives shutdowns and reboots, finds files deleted
  while El Doctor was not running, and **e-mails every data-wipe incident — the user responsible and
  every affected file and folder — to the registered administrators**.
* **generates deployments** for Windows desktop/server, Linux (systemd), Docker, Kubernetes
  (DaemonSet), AWS, Azure and GCP VMs.

The original features (live metrics, CSV log, threshold e-mails, `q` to quit) are still there.
`python3 el_doctor.py` still works and starts the new console.

---

## 1. Quick start

Requires Python 3.9 or newer (tested on 3.12 and 3.14). From the `El_Doctor` folder:

```bash
python -m pip install -r requirements.txt   # psutil, PyYAML, cryptography (+ windows-curses on Windows)
python eldoctor                              # first run: registration wizard -> login -> live console
```

Any of these start the same program:

| Command | When |
|---|---|
| `python eldoctor`, `python -m eldoctor` | from the `El_Doctor` folder, no install needed |
| `python el_doctor.py` | the old El Doctor 1 command, still works |
| `eldoctor` | after `python -m pip install -e .` (adds the `eldoctor` command) |
| `python eldoctor gui` | **desktop GUI** (see section 1b) |
| `eldoctor-gui`, or double-click `el_doctor_gui.pyw` | desktop GUI with no console window (Windows) |

On Windows use `py` or `python` instead of `python3`. Open the terminal **as Administrator** if you
want El Doctor to be able to kill or suspend other users' processes. If a required package is
missing, El Doctor prints the exact `pip install` command for the Python you are using.

Optional: `python -m pip install yara-python` enables YARA scanning. At the time of writing it has no
ready-made package for Python 3.14 (pip tries to compile it), so on 3.14 El Doctor simply runs with
YARA off.

Registration is mandatory. The wizard asks for name, e-mail, organisation, **use case** and **where you
will deploy** (Windows, Linux, Docker, Kubernetes, AWS, Azure, GCP), and can generate the deployment
bundle for that target straight away. The first user becomes `admin`.

In the commands below, `eldoctor` can be replaced with `python eldoctor` or `python -m eldoctor`:

```bash
eldoctor run --headless --mode interactive   # agent with console output
eldoctor tui                                 # curses console (approvals, manual response)
eldoctor scan                                # one-shot scan of running processes/connections
eldoctor approvals list | approve ID | deny ID
eldoctor alerts | actions | rules | playbooks list | blocks list | quarantine list
eldoctor audit | audit verify                # tamper-evident, signed audit trail + row ledger (admin)
eldoctor audit verify-export audit.jsonl     # verify a SIEM / exported copy offline, no secret needed
eldoctor whoami                              # your role + the OS identity the agent sees
eldoctor activity now                        # who is logged in right now and what they are running
eldoctor activity list --since 2h            # timeline: sessions, apps, files created/edited/deleted/opened/downloaded
eldoctor activity export --out triage.csv    # forensic export (CSV or --format jsonl)
eldoctor intel update                        # pull abuse.ch / Emerging Threats feeds
eldoctor deploy                              # deployment wizard (or --target linux --out DIR)
eldoctor notify-test                         # send a test alert to every channel
```

Data lives in `$ELDOCTOR_HOME` (default `~/.eldoctor`, mode 0700; the Linux service uses
`/var/lib/eldoctor`, root only). It holds the SQLite DB (alerts, actions, approvals, users, audit
trail), the agent's integrity key (`keys/`), `alerts.jsonl`, `audit.jsonl`, `metrics.csv`,
`evidence/`, `quarantine/` and `intel/`. **Only the agent opens it.** Every command above is a
request to the agent's local API. When no agent is running and the folder belongs to you (personal
install), the command hosts the agent in its own process for its duration, through the same API
code. Your session token and GUI preferences live in your own client folder (`~/.config/eldoctor`,
`%APPDATA%\ElDoctor`, or `$ELDOCTOR_CLIENT_DIR`).

## 1b. Desktop GUI

```bash
python eldoctor gui                       # or: eldoctor gui / eldoctor-gui / double-click el_doctor_gui.pyw
python eldoctor gui --mode monitor        # start in a given response mode
```

This is a Tkinter window, and Tkinter ships with Python on Windows and macOS.

**No tkinter and no sudo?** (Common with Linux system Pythons that lack `python3-tk`.) Just run
`python3 eldoctor gui` anyway. El Doctor finds another Python on the machine that has Tk (uv,
pyenv, conda, python.org, the Windows `py` launcher, Homebrew…). It builds a private runtime from it
once, in `~/.cache/eldoctor/gui-runtime` (a virtual environment with psutil and PyYAML, about 40 s),
and starts the GUI there. The GUI runs the same El Doctor code with the same users and data, and
later starts take about 3 s. If the machine has no Tk-capable Python, it tries
`uv python install 3.12` (no root needed), and otherwise prints the no-sudo steps:
`python3 -m pip install --user uv && ~/.local/bin/uv python install 3.12`. To force a particular
interpreter, set `ELDOCTOR_GUI_PYTHON=/path/to/python`; to turn this off, use `--no-auto-runtime`.

* **Sign-in first.** On first start the GUI shows the registration form: name, e-mail, organisation,
  use case, where you'll deploy, and password (the first user becomes admin). It then shows your
  one-time API key, with a button to generate the deployment bundle, followed by the sign-in screen.
* **Dashboard**: CPU / memory / disk / network cards, a 3-minute chart, 24-hour counts by severity,
  containment actions, blocked IPs, quarantined files and the latest detections. A **red banner**
  pops up on every high or critical detection, showing what El Doctor did about it.
* **Processes**: live, sortable and filterable table. Kill, Kill tree, Suspend, Resume, Lower
  priority, Quarantine executable and Forensics, each with a confirmation dialog, from the buttons or
  the right-click menu. The same safety guards apply as for playbooks.
* **Alerts**: filter by severity or search text. The investigation pane explains why it matters, the
  MITRE ATT&CK techniques (with links), the process and its command line, every automated response
  step, and the evidence. You can kill the process or block its IP from there.
* **Response log**, **Approvals** (Approve / Deny with expiry countdown; the tab title shows how many
  are waiting), **Threat intel & rules** (update abuse.ch / Emerging Threats feeds, add your own
  indicators, browse rules and playbooks), **Blocks & quarantine** (unblock, restore), **User activity**
  (who is logged in now; timeline of sessions, applications and files created / edited / deleted /
  opened / downloaded with the user and *how we know*; filters; CSV export - analysts and admins), **Deploy**
  (pick Windows / Linux / Docker / Kubernetes / AWS / Azure / GCP and generate the bundle), **Users &
  settings** (roles, enable/disable users, test notifications, audit trail).
* **Modes**: switch between monitor, interactive and enforce from the header (enforce needs admin).
* **Roles**: viewers get a read-only window; analysts can respond and approve; admins can do
  everything. Greyed-out buttons are only a convenience: the agent refuses the request anyway.
* **Attach mode**: if the El Doctor service is already running (e.g. the Windows Scheduled Task), the
  GUI does not start a second agent. It connects to the service's API, shows its detections live and
  sends your approvals, denials and responses to it. The service checks your role before acting,
  so the GUI needs no administrator rights. This is the recommended setup: service for 24/7
  protection, plus the GUI shortcut (`install.ps1 -Mode Both`). Without a service, the GUI hosts the
  agent itself and serves the API, so `eldoctor approvals approve ID` works from another terminal.
* **Appearance: light, dark or system.** The default follows the operating system (the Windows app
  setting, macOS Dark Mode, or the GNOME/GTK colour scheme). Switch with the **Light mode / Dark mode**
  button in the header or on the sign-in screen, with **Ctrl+T**, or under *Users & settings →
  Appearance*. Switching is instant, monitoring keeps running, and the current tab, selection and
  filters are kept. Your choice is remembered per user. You can also pass `--theme light|dark|system`
  or set `gui.theme` in config.yaml. Both palettes meet WCAG AA contrast (at least 4.5:1) for all
  text, and a test enforces this.
* **Keyboard**: Ctrl+1…9 and Ctrl+0 switch tabs, F5 refresh, Delete kills the selected process, Alt+A / Alt+D
  approve or deny, Ctrl+T light/dark, Ctrl+Q quit.

Screenshots are omitted from the repository to avoid publishing demo account details.

## 2. Architecture

```
 collectors/                 detection/                     playbooks/            response/ + notify/
 ───────────                 ──────────                     ──────────            ───────────────────
 metrics (CPU/mem/disk/net)─┐ heuristics (resource, fork    YAML playbooks  ───►  renice · suspend · kill(tree)
 processes (psutil, hashes) ├► storm, memfd, deleted exe,   trigger → conditions   quarantine · block_ip
 network connections        │  masquerade, reverse shell)   → steps                collect_forensics
 logs: files, journald,     │ IOC store (feeds, CSV)        modes + approvals  ───► email · Slack · Teams ·
   auditd EXECVE, syslog    ├► Sigma engine (native)        safety guards          Discord · Shuffle/n8n/Tines
   receiver, Windows Event  │ YARA (optional)               circuit breaker        TheHive · syslog/CEF · JSONL
   Log (Sysmon, 4688, 4625) ┘ → Alert (+MITRE) → correlation (1 incident per entity)
```

* **Correlation**: several detections on the same process or IP in the same cycle become *one
  incident*. The most specific playbook runs once, MITRE techniques are merged, and the other
  detections are attached as evidence.
* **One agent per data directory** (lock file). SIGTERM/SIGHUP shut down gracefully, which is what
  systemd, Docker and Task Scheduler send.
* **One door in**: `eldoctor/api/` (section 6b). The CLI, TUI and GUI never open the database. The
  agent (`AgentService`) is the only component that reads or writes it, holds the keys, runs
  responses and decides permissions.

## 3. Detection

| Source | What |
|---|---|
| Heuristics | `ED-RES-001` sustained CPU · `ED-RES-002` sustained memory · `ED-RES-003` spawn storm / fork bomb · `ED-SYS-00x` legacy host thresholds · `ED-PROC-001` exec from temp dirs · `ED-PROC-002` deleted binary · `ED-PROC-003` kernel-thread / daemon masquerading · `ED-PROC-004` web server → shell · `ED-PROC-005` fileless `memfd` execution · `ED-NET-001` shell holding a TCP socket · `ED-NET-002` miner/C2 ports · `ED-NET-003` connection to an IP El Doctor blocked |
| Threat intel | `ED-IOC-001` exe SHA-256 · `ED-IOC-002` remote IP / CIDR · `ED-IOC-003` known tool names (xmrig, kinsing, mimikatz…) · `ED-IOC-004` malicious domain on the command line. Feeds: abuse.ch Feodo Tracker, MalwareBazaar, URLhaus, Emerging Threats (`eldoctor intel update`, or `intel.auto_update: true`) plus your own CSV (`eldoctor intel add`) |
| Logs | `ED-LOG-001` SSH/login brute force · `ED-LOG-002` success after brute force · `ED-LOG-003` sudo/su failures · `ED-LOG-004` account created · `ED-LOG-005` Windows 4625 brute force |
| Sigma | 18 bundled rules (Linux + Windows): reverse shells, download-and-execute, base64→shell, miners, history/log tampering, disabling defences, `/etc/shadow` access, cron/systemd persistence, encoded PowerShell, Office spawning shells, shadow-copy deletion, LOLBins, Defender tampering, 1102 log cleared, 7045 suspicious service, root SSH password login |
| YARA | EICAR, XMRig strings, reverse-shell scripts. Add YARA-Forge / signature-base via `detection.yara.rules_dirs` |

**The Sigma engine is native** (no backend or SIEM needed). It supports value lists, keyword lists,
`contains / startswith / endswith / all / re / cidr / windash / base64 / base64offset / exists / cased /
gt…`, wildcards, and conditions with `and / or / not / () / 1 of x* / all of them`. It also handles
logsource matching. Rules with aggregations or correlations are reported as unsupported and skipped,
never mis-evaluated. To load more rules, point `detection.sigma_dirs` at a SigmaHQ checkout (e.g.
`rules/linux/process_creation`, `rules/windows/process_creation`).

**Exec telemetry.** By default El Doctor polls processes every `agent.interval` seconds. That misses
commands that live for milliseconds (for example `bash -c "a; b"`, which `exec`s away). For full
coverage, enable the kernel-level sources. On Linux that's **auditd EXECVE** (the Linux/cloud bundles
install `-a always,exit -S execve -k eldoctor_exec`). On Windows it's **Sysmon Event 1** or
**Security 4688**. These events go through the same heuristics, IOC, Sigma and YARA pipeline.

## 4. Response: playbooks, modes, safety

Bundled playbooks (`eldoctor playbooks list`):

| Playbook | Trigger | Steps |
|---|---|---|
| `pb-cryptominer` | miner name / Sigma / YARA (T1496) | suspend (auto) → forensics → quarantine → kill tree → block pool IP → notify |
| `pb-reverse-shell` | `ED-NET-001`, reverse-shell Sigma | suspend (auto) → forensics → **force** kill tree → block IP → notify |
| `pb-threat-intel-hit` | IOC hash / IP / name / domain, YARA | suspend → forensics → quarantine → kill → block C2 → notify |
| `pb-fork-bomb` | `ED-RES-003` | freeze tree → force kill tree → notify |
| `pb-resource-hog` | `ED-RES-001/002` | **renice** (graduated, automatic) → forensics → kill → notify |
| `pb-brute-force` | `ED-LOG-001/002/005` | block source IP for 24 h → notify |
| `pb-blocked-connection` | `ED-NET-003` | kill → notify |
| `pb-malicious-execution` | high/critical Sigma or heuristic on a process | forensics → kill tree → notify |
| `pb-notify-only` | everything else ≥ low | notify (legacy threshold e-mails) |

**Modes** (`agent.mode`, `--mode`, or the `m` key in the TUI):

* **monitor**: detect and notify only. Actions that would touch a process are recorded as
  `would_run`, or `blocked` if a guard would refuse them.
* **interactive**: reversible steps (`renice`, steps marked `auto: true` such as `suspend`) run
  immediately. The first destructive step pauses the playbook and opens an **approval** (TUI keys
  `a`/`d`, or `eldoctor approvals approve ID`). Approve resumes the playbook. Deny, or expiry, resumes
  any suspended process (`approval_timeout_action: keep` leaves a suspected miner frozen instead).
* **enforce**: everything runs automatically. Needs the admin role.

**Safety guards** (every destructive action passes through them; dry-run available):

* never PID 0/1, kernel threads, El Doctor itself or **its parent chain**
* protected names (systemd, sshd, dockerd, kubelet, lsass.exe, csrss.exe, svchost.exe…) and users
* allow-lists by name, path, SHA-256 and IP
* **PID-reuse check**: the live process's start time must match the alert
* quarantine never touches system paths (`/usr`, `C:\Windows`…); python-based malware is killed, not
  the interpreter quarantined
* block-IP never blocks loopback, RFC 1918, link-local, or **cloud metadata** (169.254.169.254,
  168.63.129.16)
* **circuit breaker**: more than 10 destructive actions in 60 s trips it, and El Doctor drops to
  approval mode (protects the host from a bad rule or a detection storm)
* approvals are never requested for actions the guards would refuse anyway

**Actions**:

* `kill` freezes the whole tree first, then SIGTERM, then SIGKILL (`force: true` for shells and
  fork bombs).
* `quarantine` copies the binary to a 0400 vault with SHA-256 and metadata, recovers *deleted*
  binaries from `/proc/PID/exe`, and can be undone with `eldoctor quarantine restore ID`.
* `block_ip` uses iptables/nftables or the Windows Firewall when privileged. Otherwise it uses
  **app-level enforcement**: any process that connects to the IP gets killed.
* `collect_forensics` writes a JSON snapshot (cmdline, parents, children, connections, open files,
  mapped files).

Writing your own playbook (put it in a directory listed in `playbooks.dirs`; files with the same `id`
override bundled ones):

```yaml
id: pb-webshell
name: Web shell containment
priority: 15
exclusive: true
max_mode: enforce            # cap; the effective mode is min(global, max_mode)
trigger:
  rule_ids: [ED-PROC-004, "SIGMA:*"]
  mitre: [T1505.003]
  min_severity: high
conditions:
  - {field: alert.process.parent_name, op: in, value: [nginx, apache2, php-fpm]}
steps:
  - {action: suspend, auto: true}
  - {action: collect_forensics}
  - {action: kill, tree: true, force: true}
  - {action: block_ip, ip: "{{ alert.remote_ip }}", when: [{field: alert.remote_ip, op: exists}]}
  - {action: notify, channels: [slack, thehive], message: "Web shell contained"}
```

Validate with `eldoctor playbooks validate my.yml`. When running as root, El Doctor refuses
world-writable playbooks and config files (that would be a privilege-escalation path).

## 5. Notifications

Configure `notifications.channels` in `$ELDOCTOR_HOME/config.yaml` (`eldoctor config init` writes a
commented template). **Secrets are read from environment variables** (`*_env` keys). The old
hard-coded Gmail password is gone.

```yaml
notifications:
  min_severity: medium
  channels:
    - {type: email, smtp_host: smtp.gmail.com, smtp_port: 587, username: me@example.invalid,
       password_env: ELDOCTOR_SMTP_PASSWORD, to: [soc@example.invalid], min_severity: high}
    - {type: slack,   url_env: ELDOCTOR_SLACK_WEBHOOK}
    - {type: teams,   url_env: ELDOCTOR_TEAMS_WEBHOOK}        # Workflows webhook, Adaptive Card
    - {type: discord, url_env: ELDOCTOR_DISCORD_WEBHOOK}
    - {type: webhook, name: shuffle, url_env: ELDOCTOR_SHUFFLE_WEBHOOK, secret_env: ELDOCTOR_WEBHOOK_SECRET}
    - {type: webhook, name: n8n,     url_env: ELDOCTOR_N8N_WEBHOOK}
    - {type: webhook, name: tines,   url_env: ELDOCTOR_TINES_WEBHOOK}
    - {type: thehive, url: http://thehive:9000, api_key_env: ELDOCTOR_THEHIVE_KEY, version: 5}
    - {type: syslog,  host: wazuh.example.com, port: 514, protocol: udp, format: cef}
```

Webhook bodies are signed as `X-ElDoctor-Signature: sha256=<HMAC>`, so the receiving workflow can
verify them. TheHive alerts carry observables (IP, hash, filename, host) and `mitre:Txxxx` tags.
Delivery is asynchronous, with retries and per-channel rate limiting, so a slow webhook never delays
containment. Playbook steps can target specific channels (`channels: [shuffle]`), which is how you
hand incidents to an external SOAR.

## 5b. User activity record (forensics & triage)

While the agent runs it keeps a timeline of what people do on the machine. Investigators use it to answer
*who was logged in, what did they run, which files did they touch, and who deleted what*.

| Category | Recorded (`kind`) | Source |
|---|---|---|
| session | `session_start` / `session_end` (console, terminal, remote), `remote_login` (sshd), `privilege_use` (sudo + command) | OS session table (utmp / WTS), auth log, Windows 4624/4634, wtmp for logins while El Doctor was off |
| process | `app_start` / `app_stop` (command line, parent, SHA-256, working folder, terminal, run time), `app_running` (inventory at start-up) | process poller, auditd / Sysmon exec events |
| file | `file_created`, `file_modified` (edited), `file_deleted` (incl. **moved to the Trash**), `file_renamed` / moved, `file_opened`, `file_downloaded` (+ source URL and SHA-256), `bulk_access` | inotify (Linux, real time), folder scans (Windows / macOS, and at every start), auditd, Sysmon 11/23/26/15, Security 4663, GTK recently-used |
| system | `system_boot`, `system_shutdown` (clean or not), `monitoring_gap`, `offline_changes`, `events_lost` | boot id + heartbeat kept in the database |
| incident | `wipe_incident`, `evidence_deleted` | see below |

**Who did it — and how we know.** inotify and folder scans say *what* changed, never *who*. Every file
record therefore carries an `attribution`:

| attribution | meaning |
|---|---|
| `kernel` | auditd (Linux) / Sysmon or the Security log (Windows) recorded the process and the user — including the **login user** (auid) behind `sudo` / `su`. Authoritative. |
| `handle` | the process had the file open (open-files sample taken right after the event) |
| `cmdline` | a running process named the file or a parent folder on its command line (`rm -rf ~/Documents`, `shred`, `curl -o`, `find . -delete`, `bash -c "…"`) |
| `inferred` | no process evidence: the owner of the home folder who was logged in, or the only logged-in user — a lead, not proof |
| `unknown` | nothing to go on (typically changes made while El Doctor was not running) |

For authoritative attribution of deletions install the bundled auditd rules (the Linux installer does it:
deletions and renames below `/home` and `/root`) or Sysmon with file events on Windows.

**Survives shutdowns and reboots.** Records are committed to the SQLite database as they happen. They are
sealed in the signed audit chain immediately for deletions, sessions, boots, incidents and downloads, and
otherwise once a minute (`seal_interval`), which keeps the chain small. `eldoctor audit verify` reports any
record that was edited, deleted or inserted behind the agent's back. Rows left unsealed by a crash are sealed
at the next start and marked `recovered`. The last known state of the watched folders is also kept. At every start the
folders are compared with it, so files **deleted while El Doctor was not running** (machine off, agent killed,
disk mounted from another OS) are still found. They are recorded with `source: offline` and the time window in
which it happened. Boots, clean and unclean shutdowns and monitoring gaps are recorded (an unclean gap in the same
boot raises ED-ACT-005: the agent may have been killed). Logins during the gap are read back from wtmp.
Sessions, privilege use, wipe reports, restarts and gaps also go to the audit trail, which is forwarded to your
SIEM in real time. A copy survives even if the host is wiped.

**Data wipes → e-mail to the registered admins.** When `activity.wipe.threshold` files or folders (default 50)
disappear within `window` seconds (default 60), El Doctor

1. raises **ED-ACT-001** (critical, T1485 / T1070.004) at once, naming the user and the process. When the process
   is still running, playbook `pb-data-destruction` collects evidence and suspends it: *monitor* = recorded only,
   *interactive* = after approval, *enforce* = immediately. Resume it if the deletion was legitimate.
2. sends a short "wipe in progress" e-mail, then a **complete report** once the deletions stop. The report says
   who (user, login user, process, command line, how each deletion was attributed), who was logged in, when,
   how much (files, folders, bytes, Trash vs permanent) and the folders most affected. It has a **zipped CSV of
   every deleted file and folder** attached.
3. does the same at start-up for deletions found while it was off (**ED-ACT-002**). Deleting El Doctor's own
   database, keys or logs raises **ED-ACT-003**. A downloaded file whose hash or name is in threat intel raises
   **ED-ACT-004**.

Recipients are the e-mail addresses of the **registered administrators** (active `admin` users whose account
record passes the integrity check; a user row injected into the database is never a recipient), plus
`activity.report.extra_recipients`. SMTP comes from `activity.report.smtp` or, if that is empty, from the first
`email` channel under `notifications.channels`. Reports are written to a persistent outbox *before* sending and
retried with back-off until delivered, across restarts and reboots. Check them with `eldoctor activity reports`;
`--retry` sends pending ones now.

```bash
eldoctor activity now                                   # logged-in users + the applications each one runs
eldoctor activity list --since 2h --user alice          # timeline (filters: --kind --category --path --search --pid)
eldoctor activity list --kind file_deleted,file_downloaded --path /home/alice/Documents
eldoctor activity sessions                              # current sessions + login/logout history
eldoctor activity status                                # watched folders, backend, kernel telemetry, outbox
eldoctor activity export --since 2025-06-01 --out triage.csv   # or --format jsonl (exports are audited)
```

Viewing or exporting the record needs the `forensics` permission (analyst, admin). Viewers cannot see
people's file activity.

Configuration: the `activity:` section of `config.yaml`. Defaults:

* watched folders: every home folder when the agent is privileged (`/home`, `/root`, `C:\Users`), otherwise your own.
* excluded: caches, browser profiles, `node_modules`, VCS metadata, `AppData`. The Trash is watched, because moving
  a file there is a deletion by the user.
* opens are de-duplicated (10 min) and rate-limited (300 per minute, then one `bulk_access` summary).
* `retention_days: 0` keeps everything (when set, whole sealed batches are pruned).
* `jsonl: activity.jsonl` writes a JSON-lines copy for Filebeat / Vector.

Recording people's activity is monitoring. Deploy it under your organisation's acceptable-use /
monitoring policy.

## 6. Users and roles

| Role | Can |
|---|---|
| viewer | view alerts / actions / rules (default for self-registration) |
| analyst | + run the agent (monitor/interactive), approve, manual response, intel updates, user-activity record |
| admin | + enforce mode, user management, deployment bundles, quarantine restore, unblock, audit trail; receives data-wipe reports by e-mail |

* Passwords use PBKDF2-SHA256 (600k iterations), need at least 10 characters from 3 character
  classes, and 5 failures lock the account for 5 minutes.
* Sessions are stateless JWTs issued by the agent, bound to your OS account, and expire
  (`registration.session_hours`, 12 h). Logout, a role change or disabling the account revokes them
  immediately. Services use API keys, which are stored hashed.
* Roles are enforced by the agent (section 6b), never by the front ends.
* `registration.webhook_url` (opt-in, with consent) sends the registration profile — never the
  password — to your endpoint, so you know who uses El Doctor and for what.


## 6b. Trust boundary: agent API, RBAC in the agent, tamper-evident audit

The front ends used to check roles themselves while the agent trusted the database, so anyone who
could edit `eldoctor.db` could forge an approval "by admin1" and then rewrite the audit trail
(`docs/PRODUCTION_READINESS.md`, P0-1). The architecture is now:

```
 eldoctor CLI / TUI / GUI              local API (JSON lines)            AgentService (service account)
 as any OS user         ── Unix socket /run/eldoctor/api.sock ──►   1 peer credentials from the kernel
 token in ~/.config/eldoctor   or named pipe \\.\pipe\eldoctor-api-*  2 OS-account policy
                                                                    3 JWT (bound to that OS uid) / API key
                                                                    4 RBAC on the *current* sealed role
                                                                    5 action -> hash-chained audit -> SIEM
```

**Local authenticated API** (`eldoctor/api/`).
* Linux/macOS: AF_UNIX socket. The agent reads `SO_PEERCRED` / `LOCAL_PEERCRED` (pid, uid, groups)
  on every connection. The client checks the same for the server and only talks to root, itself, or
  the owner of a non-writable socket folder, so a fake socket can't collect passwords.
* Windows: named pipe with an explicit DACL (no network logons; SYSTEM, Administrators, the agent;
  Authenticated Users read/write for the service), `FILE_FLAG_FIRST_PIPE_INSTANCE`, and peer identity
  via `GetNamedPipeClientProcessId`.
* Peer credentials are used to refuse OS accounts you don't allow (`api.allowed_os_users/groups`). They
  **bind session tokens** to the OS account that logged in, so a copied token is useless to another
  user. They restrict creating the first admin to the agent's own account or root, and can require OS
  group membership for admin operations (`api.admin_os_groups: [sudo]`). They also put the real OS
  user/uid/pid in every audit record.

**Stateless sessions.** HS256 JWTs (`eldoctor/auth/tokens.py`) are signed with a key derived from the
agent's master key. Claims are `sub`, `uid`, `tv` (token version), `ouid` (OS uid), `jti` and `exp`.
There is no session table. Logout denylists the `jti`; a role change, disabling an account or
`auth.logout_all` bump the user's token version. The role is always re-read from the sealed user
record, never from the token.

**RBAC in the agent.** `eldoctor/api/server.py` has one table mapping each API method to its
permission. It is the only place roles are checked. Refused calls return exit code 3 in the CLI and
are written to the audit trail as `api_denied`. Response requests carry only a PID and start time; the
agent resolves the process itself, so a client can't make it quarantine `/etc/passwd`.

**Integrity of what the agent acts on** (`eldoctor/integrity.py`, `eldoctor/storage.py`):
* approval requests and decisions, user records (role, active flag, credentials, token version), IP
  blocks and quarantine records carry HMAC seals made with the agent's key (a fast first check);
* **the signed ledger is the authority.** Every write to alerts, actions, users, IP blocks,
  quarantine records and approval requests appends the row's SHA-256 digest to the signed audit
  chain. Before acting, the agent compares the row with its last recorded digest. A long-running
  agent uses an index it built by verifying the whole chain at start, kept up to date incrementally.
  So someone who *recomputes an HMAC seal* with a stolen master key still can't promote a user, plant
  an IP block, retarget a quarantine restore or edit an approval request;
* before executing an approval, the agent verifies the request seal and the decision seal. It checks
  that the matching chained audit record exists and that the approver **currently** holds the approve
  permission, and that the approval was not already executed (replay);
* anything else is refused, marked `rejected` and raised as a critical **ED-INT-001** incident
  (alert and forced notification). A role edited in the DB makes that account unusable instead of
  admin. An emptied user table does not hand out a new admin.

**Tamper-evident audit trail.** It records who did what:
* logins and sessions;
* registrations and role changes;
* every approval decision and its execution;
* every executed containment action, automated or approved (`response_action`), with the approver
  as actor;
* manual responses, denied API calls and integrity incidents.

Each record carries the El Doctor user and the OS user/uid/pid, plus:
* `seq`, `prev_hash`, and `hash = SHA-256(record + prev_hash)`, verifiable by anyone;
* `mac = HMAC(agent key, hash)`;
* a **forward-secure Ed25519 signature**. Every record is signed with a *one-time* key, commits to the
  public key of the key that will sign the next record (`next_pub`), and the used private key is
  overwritten and deleted after the commit. Only the key for the *next* record exists on disk. Even
  with every file of the data folder (root, the service account), nobody can change or re-sign a
  record written before the theft: the key that signed it no longer exists, and key continuity breaks.
  Rebuilding the whole chain from a new first key changes the **genesis fingerprint**, which
  `eldoctor audit verify` prints. Record it off-host or pin it (`audit.genesis_fingerprint`).

A sealed head pointer catches truncation, even if the agent has written new records since.
`eldoctor audit verify` walks the chain and checks every alert, action, user, block, quarantine and
approval-request row against the ledger, so edited, planted and deleted rows are all reported
(`eldoctor alerts` / `actions` and the GUI show a per-row integrity flag). The agent also verifies the
chain at start and every `audit.verify_interval_minutes`.

**Real-time SIEM forwarding** (`eldoctor/siem.py`). Every record is pushed the moment it is
committed, in order and at least once. Each destination has a persisted cursor, with back-off while
it is down. Destinations: syslog over UDP, TCP or TLS in CEF, RFC 5424 or JSON; a signed webhook
(Splunk HEC, Elastic, Logstash, Vector); and a local `audit.jsonl`. By default the audit trail also
goes to every syslog channel already in `notifications.channels`. `eldoctor audit verify-export
FILE [--genesis ed25519:...]` verifies an exported or SIEM copy with public information only: hash
chain, every signature, key continuity and the genesis key.

```yaml
audit:
  forward:
    - {type: syslog, host: siem.example.com, port: 6514, protocol: tls, format: cef, ca_file: /etc/ssl/siem-ca.pem}
    - {type: webhook, url_env: ELDOCTOR_AUDIT_WEBHOOK, secret_env: ELDOCTOR_WEBHOOK_SECRET}
api:
  socket_group: eldoctor        # optional: only members of this group can even connect
  admin_os_groups: [sudo]       # optional: admin operations also need OS admin group membership
```

**Data folder locked to the service account.** `eldoctor service` runs this at every start
(`eldoctor/lockdown.py`):
* POSIX: folder 0700 and files 0600, owned by the service account (root), no symlinks, umask 0077.
* Windows: `icacls`, SYSTEM only (`api.windows_admins_access: true` keeps Administrators).
* Anything found loosened is fixed and reported.

The systemd unit serves the API on `/run/eldoctor/api.sock`, so analysts use `eldoctor tui` and
`eldoctor approvals approve` **without sudo**.

**See it yourself:**
* `LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && python3 scripts/tamper_demo.py` replays the
  original finding against a live agent and checks that every step is refused.
  Steps 6–8 give the attacker every key file and show that history still can't be rewritten.
* `python3 scripts/verify_requirements.py` runs checks R7.1–R7.7 and R8.1–R8.3.
* Tests: `tests/test_api.py`, `tests/test_integrity.py` and `tests/test_forward_secure.py`.
* Reviewer checklist: [`docs/REVIEW_GUIDE.md`](docs/REVIEW_GUIDE.md).
* GUI walkthroughs can be run locally with the commands in [`docs/REVIEW_GUIDE.md`](docs/REVIEW_GUIDE.md).

**What no on-host design can prevent, and what happens instead:**
* An attacker who controls the machine **while the agent runs** (root, the service account) can
  append *new* records with the current one-time key, just as they could run the agent themselves or
  kill processes without El Doctor. They can't change, re-sign or delete anything already written.
  Everything they append is chained after the real history and forwarded to the SIEM in real time.
* Used keys are overwritten and deleted. On copy-on-write filesystems or SSDs, remnants may survive
  until the blocks are reused; full-disk encryption covers that.
* The Windows named-pipe and ACL code has not been run in this sandbox (see P0-2).

## 7. Deployment

`eldoctor deploy --target <t> --out DIR` (admin) writes a self-contained bundle: tuned `config.yaml`,
the source archive, and a README with exact steps.

| Target | Bundle |
|---|---|
| `windows` | `install.ps1 -Mode Desktop\|Service\|Both`: venv in Program Files, data in ProgramData (locked to SYSTEM by the service), registration, SYSTEM Scheduled Task and/or desktop console shortcut (a plain-user client of the service's named pipe); Event Log + Sysmon collection |
| `linux` | `install.sh` + hardened systemd unit (capability bounding set, `RuntimeDirectory` for the API socket, `StateDirectory` 0700) + auditd exec rule + env file for secrets |
| `docker` | Dockerfile + compose (`pid: host`, `network_mode: host`, `cap_drop: ALL` + minimal caps, read-only rootfs) |
| `kubernetes` | namespace, ConfigMap, Secret, DaemonSet (hostPID/hostNetwork, minimal caps, tolerations for every node) |
| `aws` / `azure` / `gcp` | cloud-init / startup-script + Terraform (AWS, IMDSv2); unattended registration of the owner; metadata IPs protected |

Unattended hosts run `eldoctor service --bootstrap`. It registers the owner from `ELDOCTOR_ADMIN_*`
env vars (with a random admin password stored 0600) and creates a dedicated service identity.

## 8. Open-source security tools El Doctor uses or can be enriched with

Already integrated:

* **Sigma** (detection rules)
* **abuse.ch** Feodo Tracker / MalwareBazaar / URLhaus and **Emerging Threats** (threat intel)
* **YARA** (file signatures)
* **MITRE ATT&CK** (mapping)
* **TheHive** (case management)
* **Shuffle / n8n / Tines** (SOAR workflows)
* **Sysmon** and **auditd** (exec telemetry)
* Any syslog/CEF SIEM: **Wazuh**, Graylog, Elastic, Splunk

Good next candidates:

* **osquery** (inventory and scheduled hunts)
* **Falco / Tetragon** (eBPF runtime events for Kubernetes)
* **Velociraptor** (deep forensics on demand)
* **MISP / OpenCTI** (richer intel with sightings)
* **YARA-Forge** (curated YARA packs)
* **CrowdSec** (shared IP reputation)
* **Suricata / Zeek** (network IDS)

## 9. Testing — what was verified in the sandbox

**Check every requirement yourself (one command):**

```bash
python3 scripts/verify_requirements.py          # 29 behavioural checks, ~4 min, isolated temp folders
python3 scripts/verify_requirements.py --full   # + full test suite + live 15-attack lab (Linux, ~10 min)
```

Requirement → code → test mapping: [`docs/REQUIREMENTS_TRACEABILITY.md`](docs/REQUIREMENTS_TRACEABILITY.md).
Production-readiness review and roadmap: [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).


```bash
python -m pytest             # 230 tests (39 for the user-activity record; 2 GUI tests skip without Tk) incl. GUI, appearance + GUI-runtime tests (Python 3.14; GUI tests skip without Tk): Sigma engine, detections, guards, real kill/suspend/quarantine,
                             # playbook modes & approvals, notifications over real HTTP/SMTP/UDP,
                             # auth/RBAC, deployment bundles, CLI gate, agent end-to-end, TUI in a pty,
                             # agent API (RBAC per method and role, JWT binding/revocation, Unix socket peer
                             # credentials, CLI against a running service), tamper detection, SIEM forwarding,
                             # forward-secure signatures vs. an attacker holding every key file, row ledger
scripts/lab.sh enforce       # live purple-team lab (PYTHON=python3.14 scripts/lab.sh ... to pick a Python): 15 harmless attack simulations vs the running agent
                             # (responses are scoped to the lab's own process tree; LAB_SCOPE_PID=none = whole host)
LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && python3 scripts/interactive_demo.py   # approval flow via the API
LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && python3 scripts/tamper_demo.py       # P0-1: forging is refused
scripts/lab.sh monitor cpu_hog,cryptominer,c2_beacon                     # nothing is touched
```

Lab results (enforce mode, unprivileged user, 1 s polling): **15/15 detected and contained**.

| Scenario | Detected by | Time | Outcome |
|---|---|---|---|
| CPU busy loop | ED-RES-001 (T1496) | 7.2 s (6 s threshold) | reniced → forensics → killed |
| memory leak | ED-RES-002 (T1499) | 18 s | reniced → killed |
| XMRig-style miner in /tmp | IOC name + domain, Sigma miner, temp-dir (merged into 1 incident) | 0.6 s | suspended → quarantined → killed |
| bash / python reverse shells | Sigma + ED-NET-001 | ≤ 0.9 s | force-killed tree (loopback block refused by guard) |
| `curl \| bash` dropper | Sigma download-exec | 0.8 s | killed with children |
| fork storm (45 children) | ED-RES-003 | 0.8 s | frozen + killed 46 processes |
| deleted binary / kernel-thread masquerade | ED-PROC-002 / ED-PROC-003 | < 1 s | killed |
| binary in MalwareBazaar-format feed | ED-IOC-001 | 0.9 s | suspended → quarantined → killed |
| beacon to Feodo-listed C2 | ED-IOC-002 | 0.9 s | killed, C2 blocked (app-level) |
| history tampering script | Sigma | 0.9 s | killed |
| SSH brute force via real syslog (`logger`) + root login | ED-LOG-001/002 + Sigma | 1.0 s | source IP blocked |
| auth.log tail: sudo failures, new user | ED-LOG-003/004 | 0.3 s | notified |
| later connection to the blocked IP | ED-NET-003 | 0.3 s | killed |

It also caught something real in the sandbox itself: the sandbox's tool runner executes from a
`memfd` (fileless), which raised ED-PROC-005. The kill was **refused** because that process is the
agent's own parent. Agent overhead was about 6% of one core and 45 MB RSS.

## 10. Known limitations

See [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) for the full, prioritised list.
P0-1 (authorization enforced by the UIs, forgeable approvals and audit trail) is **resolved** (section 6b).
The remaining P0 blockers are Windows and privileged paths never executed, and the false-positive risk
of automatic kills. In short:

* Only **Linux** was exercised live. The Windows code paths (Event Log via wevtutil, Sysmon/4688
  mapping, netsh firewall, installer, **the named-pipe API transport and the SYSTEM-only ACL
  lockdown**) are syntax-checked only.
* The sandbox has a single unprivileged OS account. Cross-account API behaviour (another user's token,
  unknown peers, OS groups) is tested by passing kernel-style peer identities to the same request
  handler. The real socket path was only run with one account, and the root service's `0666` socket with
  non-root clients was not run.
* The sandbox had no root, no internet, no sshd and no journald. So firewall blocking fell back to
  app-level enforcement. Threat-intel feeds were served locally in the real abuse.ch formats. The
  notification endpoints were local mocks speaking the real protocols (HTTP, SMTP, UDP syslog).
* Process polling can miss very short-lived commands. Enable auditd (Linux) or Sysmon (Windows) for
  full exec coverage. The auditd parser is unit-tested, not run live (needs root).
* The Sigma engine was tested with the bundled rules and the spec constructs, not yet against the
  full SigmaHQ repository.
* User activity record: inotify, the start-up folder comparison, `cmdline` / `handle` attribution, wipe
  incidents and the admin e-mail (over a real SMTP conversation) were run live on Linux. The auditd file
  records and the Sysmon / 4663 file events are parsed from real-format samples in tests, not captured live
  (no root / no Windows here). The Windows polling backend and the Mark-of-the-Web reader were not run on Windows.
* Without auditd / Sysmon, a command that lives for milliseconds (`rm file`) can finish between two process
  samples. Its deletion is then recorded as `inferred` or `unknown`, never silently attributed.
  `rm -rf` of a large folder, `shred`, and any `sh -c "..."` wrapper are long enough to be caught.
* A folder moved *out* of the watched folders is one `file_deleted` record (`moved_out`,
  `contained_entries`), not one per file. Files created and deleted again within a second are not recorded.

## License

MIT — see [LICENSE](LICENSE). Bundled Sigma/YARA rules are original El Doctor content.
